"""
Phase 1 - Live capture + core metrics (no storage yet)
========================================================

Purpose
-------
This is the foundation of the whole project. Before we touch SQLite,
FastAPI, Prometheus, or anomaly detection, we need to prove that we can:

  1. Capture live packets off a real interface (via Npcap on Windows,
     libpcap on Linux later).
  2. Parse each packet into the fields we care about: src/dst IP,
     src/dst port, protocol, size.
  3. Compute a first slice of metrics over a rolling time window:
        - packet count / packet rate (packets per second)
        - bandwidth usage (bits per second)
        - protocol distribution (TCP vs UDP vs ICMP vs other)
        - top talkers (which IPs are generating the most traffic)
        - Shannon entropy of the source-IP and destination-port
          distributions (our first anomaly-detection signal)

Everything here runs in memory. Nothing is persisted yet - that's
Phase 2. Keeping this phase storage-free lets us validate the capture
and metrics logic in isolation, which makes bugs much easier to find
than if capture + storage + metrics all landed at once.

Requirements
------------
    pip install scapy

On Windows you also need Npcap installed (https://npcap.com/) with
"Install Npcap in WinPcap API-compatible Mode" checked during setup -
this is what lets Scapy's libpcap bindings find the driver.

Usage
-----
    # List available interfaces (run this first to find your interface name)
    python capture_metrics.py --list-interfaces

    # Capture on a specific interface, report every 5 seconds
    python capture_metrics.py --iface "Wi-Fi" --window 5

    # Optional: restrict capture with a BPF filter (same syntax as tcpdump)
    python capture_metrics.py --iface "Wi-Fi" --filter "tcp or udp"

Run as Administrator on Windows - Npcap requires elevated privileges
to open the adapter in promiscuous/capture mode.
"""

import argparse
import math
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, get_if_list

from network_utils import get_active_interface, InterfaceNotFoundError


# ---------------------------------------------------------------------------
# Data model for one measurement window
# ---------------------------------------------------------------------------

@dataclass
class WindowStats:
    """Accumulates everything we observe during one reporting window.

    A 'window' is just a fixed number of seconds (default 5). At the end
    of each window we compute metrics from what we've accumulated, print
    a report, and reset for the next window. This is the same rolling-
    window approach flow monitoring tools like nfcapd or Argus use -
    it keeps memory bounded regardless of how long the process runs.
    """
    packet_count: int = 0
    byte_count: int = 0
    protocol_counter: Counter = field(default_factory=Counter)
    src_ip_counter: Counter = field(default_factory=Counter)
    dst_ip_counter: Counter = field(default_factory=Counter)
    dst_port_counter: Counter = field(default_factory=Counter)
    # bytes sent per source IP -> lets us compute "top talkers" by volume,
    # not just by packet count (a few huge packets matter as much as many
    # small ones for bandwidth purposes)
    bytes_by_src_ip: Counter = field(default_factory=Counter)


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def shannon_entropy(counter: Counter) -> float:
    """Compute Shannon entropy (in bits) of a categorical distribution.

    H(X) = -sum( p(x) * log2(p(x)) )  for each distinct value x

    Intuition: entropy measures how "spread out" or unpredictable a
    distribution is.
      - High entropy  -> traffic is talking to many different IPs/ports
                         roughly evenly (normal, diverse office traffic).
      - Low entropy   -> traffic is concentrated on very few values
                         (e.g. one destination IP getting flooded, or
                         one source scanning many ports in sequence -
                         both collapse a distribution towards a single
                         dominant value or a tight cluster).

    We compute this per-window over categorical counters (source IPs,
    destination ports, etc). A sudden drop or spike in entropy between
    consecutive windows is a classic early indicator of scans, floods,
    or exfiltration - this is the same principle used in flow-based
    anomaly detection research (see references in the write-up).
    """
    total = sum(counter.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def max_possible_entropy(counter: Counter) -> float:
    """Upper bound on entropy for N distinct values: log2(N).

    Useful for normalizing: entropy / max_entropy gives a 0-1 score
    that's comparable across windows even as the number of distinct
    values (N) changes.
    """
    n = len(counter)
    if n <= 1:
        return 0.0
    return math.log2(n)


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def classify_protocol(pkt) -> str:
    """Return a short protocol label for a parsed Scapy packet.

    Scapy packets are layered objects (Ether / IP / TCP / ...). We check
    from the transport layer down, since that's usually more useful for
    monitoring than the raw IP protocol number.
    """
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return f"IP-proto-{pkt[IP].proto}"
    return "non-IP"


def process_packet(pkt, stats: WindowStats) -> None:
    """Callback invoked by Scapy for every captured packet.

    This is intentionally cheap - it only accumulates counters. Anything
    expensive (entropy math, sorting for top talkers) happens once per
    window in generate_report(), not per packet. On a busy interface
    this callback can be invoked thousands of times per second, so
    per-packet cost matters a lot more than per-window cost.
    """
    if not pkt.haslayer(IP):
        return  # Phase 1 focuses on IP traffic; non-IP frames are skipped

    ip_layer = pkt[IP]
    size = len(pkt)

    stats.packet_count += 1
    stats.byte_count += size
    stats.protocol_counter[classify_protocol(pkt)] += 1
    stats.src_ip_counter[ip_layer.src] += 1
    stats.dst_ip_counter[ip_layer.dst] += 1
    stats.bytes_by_src_ip[ip_layer.src] += size

    if pkt.haslayer(TCP):
        stats.dst_port_counter[pkt[TCP].dport] += 1
    elif pkt.haslayer(UDP):
        stats.dst_port_counter[pkt[UDP].dport] += 1


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def generate_report(stats: WindowStats, window_seconds: float) -> str:
    """Turn accumulated WindowStats into a human-readable report."""
    pps = stats.packet_count / window_seconds
    bps = (stats.byte_count * 8) / window_seconds  # bits per second
    mbps = bps / 1_000_000

    src_entropy = shannon_entropy(stats.src_ip_counter)
    port_entropy = shannon_entropy(stats.dst_port_counter)

    top_talkers = stats.bytes_by_src_ip.most_common(5)
    protocol_breakdown = stats.protocol_counter.most_common()

    lines = []
    lines.append("=" * 60)
    lines.append(f"Window report ({window_seconds:.0f}s)")
    lines.append("=" * 60)
    lines.append(f"Packets: {stats.packet_count}   Rate: {pps:.1f} pkt/s")
    lines.append(f"Bandwidth: {mbps:.3f} Mbps ({stats.byte_count} bytes)")
    lines.append("")
    lines.append("Protocol distribution:")
    for proto, count in protocol_breakdown:
        pct = 100 * count / stats.packet_count if stats.packet_count else 0
        lines.append(f"  {proto:<14} {count:>6} pkts  ({pct:5.1f}%)")
    lines.append("")
    lines.append("Top talkers (by bytes sent):")
    for ip, byte_total in top_talkers:
        lines.append(f"  {ip:<16} {byte_total:>8} bytes")
    lines.append("")
    lines.append("Entropy (higher = more spread out / diverse):")
    lines.append(f"  Source IP entropy:        {src_entropy:.3f} bits "
                  f"(max possible: {max_possible_entropy(stats.src_ip_counter):.3f})")
    lines.append(f"  Destination port entropy: {port_entropy:.3f} bits "
                  f"(max possible: {max_possible_entropy(stats.dst_port_counter):.3f})")
    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------------

def run(interface: str, window_seconds: float, bpf_filter: str | None) -> None:
    stats = WindowStats()

    def on_packet(pkt):
        process_packet(pkt, stats)

    print(f"Starting capture on interface: {interface!r}")
    if bpf_filter:
        print(f"BPF filter: {bpf_filter!r}")
    print(f"Reporting every {window_seconds:.0f} seconds. Press Ctrl+C to stop.\n")

    # AsyncSniffer runs capture on a background thread so our main thread
    # is free to sleep/report on a timer. This is what makes the windowed
    # reporting model possible without hand-rolling our own threading.
    sniffer = AsyncSniffer(
        iface=interface,
        filter=bpf_filter,
        prn=on_packet,
        store=False,  # don't keep packets in memory - we only need the
                      # aggregated counters, so this keeps memory flat
                      # even over long capture runs
    )
    sniffer.start()

    try:
        while True:
            time.sleep(window_seconds)
            print(generate_report(stats, window_seconds))
            stats = WindowStats()  # reset counters for the next window
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        sniffer.stop()


def list_interfaces() -> None:
    print("Available interfaces:")
    for iface in get_if_list():
        print(f"  {iface}")


def parse_args():
    parser = argparse.ArgumentParser(description="Phase 1 network capture + metrics")
    parser.add_argument("--iface", type=str, help="Interface name to capture on. If omitted, auto-detects the active interface.")
    parser.add_argument("--window", type=float, default=5.0,
                         help="Reporting window in seconds (default: 5)")
    parser.add_argument("--filter", type=str, default=None,
                         help="Optional BPF filter, e.g. 'tcp or udp'")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="List available capture interfaces and exit")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    iface = args.iface
    if not iface:
        try:
            iface = get_active_interface()
            print(f"No --iface given - auto-detected active interface: {iface!r}")
        except InterfaceNotFoundError as e:
            print(f"Error: --iface was not provided and auto-detection failed: {e}")
            sys.exit(1)

    run(interface=iface, window_seconds=args.window, bpf_filter=args.filter)
