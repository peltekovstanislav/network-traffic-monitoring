"""
Phase 6 (alternative) - Pure-Python throughput generator, no iperf3 required
================================================================================

Why this exists
-----------------
iperf3 requires a separate download and install. This script does the
same essential job using nothing but Python's built-in socket library.

Design: outbound-only UDP, no local listener
-----------------------------------------------
An earlier version of this script ran a local TCP client AND server on
the same machine. That approach hit two real problems in practice:
    1. Over loopback (127.0.0.1), Npcap's loopback capture adapter is
       known to be considerably less reliable than capturing on a real
       NIC, and dropped the vast majority of packets under load -
       observed directly during testing (only ~5-10% of sent traffic
       was captured).
    2. Switching to a real interface IP required the local server to
       *listen* for inbound connections, which triggers a Windows
       Firewall permission prompt (or silent block) - not something
       appropriate to require on a machine that isn't the developer's own.

This version sends UDP packets outbound to an existing real host (the
local network gateway, by default) instead. Outbound connections do
not require any firewall exception on Windows - only listening does.
The destination does not need to be listening on the target port
either; it will simply discard the packets (or reply with an ICMP
port-unreachable message, which is harmless background noise). The
packets still traverse the real network interface exactly like any
other outbound traffic, so the capture engine sees them exactly as it
would see any other real traffic - the same interface and code path
already validated throughout this project via the Nmap scan tests.

Output format
---------------
Writes a JSON file in the same shape iperf3's -J output uses, so
throughput_compare.py works unchanged against either this tool's
output or real iperf3 output.

Usage
-----
    python loadgen.py --dest 192.168.88.1 --port 5301 --duration 30 --interval 5 --target-mbps 50 --output loadgen_result.json

Then:
    python throughput_compare.py --json loadgen_result.json --db netmon.db

No administrator privileges and no firewall changes are required.
"""

import argparse
import json
import socket
import sys
import time

from network_utils import get_default_gateway, GatewayNotFoundError

PACKET_SIZE = 1400  # bytes per UDP datagram - stays under typical 1500-byte MTU to avoid IP fragmentation


def run_sender(dest_ip: str, dest_port: int, duration: float, interval: float,
               target_mbps: float | None) -> tuple[float, list[dict]]:
    """Sends UDP datagrams to (dest_ip, dest_port) continuously for
    `duration` seconds, measuring real bytes sent per `interval`-second
    bucket. No response from the destination is expected or required -
    this is intentionally a one-way, outbound-only send so no local
    listening socket (and therefore no firewall prompt) is needed.

    If target_mbps is set, sending is paced via short sleeps to stay
    close to that rate rather than sending as fast as possible."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\x00" * PACKET_SIZE
    target_bytes_per_sec = (target_mbps * 1_000_000 / 8) if target_mbps else None

    test_start = time.time()
    intervals = []

    bucket_start_rel = 0.0
    while bucket_start_rel < duration:
        bucket_end_rel = min(bucket_start_rel + interval, duration)
        bucket_duration = bucket_end_rel - bucket_start_rel
        bytes_sent_this_bucket = 0
        bucket_wall_start = time.time()

        bucket_deadline = test_start + bucket_end_rel
        while time.time() < bucket_deadline:
            try:
                sent = sock.sendto(payload, (dest_ip, dest_port))
                bytes_sent_this_bucket += sent
            except OSError:
                # A destination that actively replies with ICMP port-unreachable
                # can occasionally surface as a transient send error on Windows;
                # harmless here - just skip this one datagram and keep going.
                pass

            if target_bytes_per_sec is not None:
                elapsed = time.time() - bucket_wall_start
                expected_bytes_by_now = target_bytes_per_sec * elapsed
                if bytes_sent_this_bucket > expected_bytes_by_now:
                    ahead_seconds = (bytes_sent_this_bucket - expected_bytes_by_now) / target_bytes_per_sec
                    if ahead_seconds > 0:
                        time.sleep(min(ahead_seconds, 0.05))

        bits_per_second = (bytes_sent_this_bucket * 8) / bucket_duration
        intervals.append({
            "sum": {
                "start": bucket_start_rel,
                "end": bucket_end_rel,
                "bits_per_second": bits_per_second,
            }
        })
        print(f"[{bucket_start_rel:5.1f}-{bucket_end_rel:5.1f}s] "
              f"sent {bytes_sent_this_bucket:>10,} bytes  "
              f"({bits_per_second / 1_000_000:.3f} Mbps)")

        bucket_start_rel = bucket_end_rel

    sock.close()
    return test_start, intervals


def parse_args():
    parser = argparse.ArgumentParser(description="Pure-Python outbound-only UDP throughput generator (no iperf3, no firewall changes required)")
    parser.add_argument("--dest", default=None,
                         help="Destination IP to send UDP traffic to - typically your network "
                              "gateway (e.g. 192.168.88.1). It does not need to be listening on "
                              "the target port; packets are simply discarded or ICMP-rejected, "
                              "which is fine since only outbound sending is being measured. "
                              "If omitted, the default gateway is auto-detected.")
    parser.add_argument("--port", type=int, default=5301,
                         help="Destination UDP port. Pick an unusual/unused port to avoid "
                              "accidentally hitting a real service.")
    parser.add_argument("--duration", type=float, default=30.0, help="Total test duration in seconds")
    parser.add_argument("--interval", type=float, default=5.0, help="Reporting interval in seconds")
    parser.add_argument("--output", default="loadgen_result.json")
    parser.add_argument("--target-mbps", type=float, default=None,
                         help="Pace sending to approximately this Mbps rate. Omit for unthrottled.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    dest = args.dest
    if dest is None:
        try:
            dest = get_default_gateway()
            print(f"No --dest given - auto-detected default gateway: {dest}")
        except GatewayNotFoundError as e:
            print(f"Error: --dest was not provided and gateway auto-detection failed: {e}")
            sys.exit(1)

    print(f"Sending UDP to {dest}:{args.port} for {args.duration:.0f}s, "
          f"reporting every {args.interval:.0f}s"
          + (f", paced to ~{args.target_mbps:.0f} Mbps..." if args.target_mbps else " (unthrottled)...") + "\n")
    test_start, intervals = run_sender(dest, args.port, args.duration, args.interval, args.target_mbps)

    output = {
        "start": {"timestamp": {"timesecs": test_start}},
        "intervals": intervals,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote {args.output} - compare it with:")
    print(f"    python throughput_compare.py --json {args.output} --db netmon.db")