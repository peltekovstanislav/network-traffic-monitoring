"""
Phase 3 - Live capture + SQLite storage + Prometheus exporter
================================================================

What's new versus Phase 2
--------------------------
Phase 2 persisted window and flow data into SQLite. Phase 3 adds a
Prometheus exporter alongside it: an HTTP endpoint (/metrics) that
Prometheus scrapes on a timer, exposing the same window-level numbers
as Prometheus Gauges/Counters. Grafana then queries Prometheus (not
SQLite) for the live dashboard, since Prometheus's time-series storage
is purpose-built for exactly this kind of "value over time" querying
and charting, which SQLite doesn't do natively.

Division of labour (kept deliberately separate, see project docs):
    - SQLite  -> detailed flow records, for arbitrary later queries
    - Prometheus/Grafana -> aggregated time-series metrics, for live
      and historical dashboards and threshold-based alerting

Requirements
------------
    pip install scapy prometheus_client

Usage
-----
    python capture_exporter.py --iface "Ethernet" --window 5 --db netmon.db --exporter-port 8000

Once running, http://localhost:8000/metrics will show the current
Prometheus-formatted metrics - open it in a browser to sanity check
before wiring up Prometheus itself.
"""

import argparse
import math
import sqlite3
import sys
import time
from collections import Counter
from dataclasses import dataclass, field

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, get_if_list

from network_utils import get_active_interface, InterfaceNotFoundError
from prometheus_client import start_http_server, Gauge, Counter as PromCounter

FLOW_TIMEOUT_SECONDS = 30

# ---------------------------------------------------------------------------
# Prometheus metric definitions
# ---------------------------------------------------------------------------
# Gauges: a value that can go up or down, representing "right now" -
# perfect for rates, bandwidth, entropy, active flow count.
# Counters: a value that only ever increases (Prometheus/Grafana compute
# rates from these themselves) - used for cumulative totals.
#
# Every metric gets a short, self-describing name prefixed with
# "netmon_" - this namespacing convention avoids collisions if this
# Prometheus instance ever scrapes more than one application.

METRIC_PACKET_RATE     = Gauge("netmon_packet_rate", "Packets per second in the last window")
METRIC_BANDWIDTH_MBPS  = Gauge("netmon_bandwidth_mbps", "Bandwidth in Mbps in the last window")
METRIC_SRC_IP_ENTROPY  = Gauge("netmon_src_ip_entropy_bits", "Shannon entropy of source IP distribution")
METRIC_DST_PORT_ENTROPY = Gauge("netmon_dst_port_entropy_bits", "Shannon entropy of destination port distribution")
METRIC_ACTIVE_FLOWS    = Gauge("netmon_active_flows", "Number of currently active flows")
METRIC_PACKETS_TOTAL   = PromCounter("netmon_packets_total", "Cumulative packets captured since process start")
METRIC_BYTES_TOTAL     = PromCounter("netmon_bytes_total", "Cumulative bytes captured since process start")
METRIC_SYN_TOTAL       = PromCounter("netmon_syn_total", "Cumulative TCP SYN packets observed since process start")


# ---------------------------------------------------------------------------
# SQLite schema (identical to Phase 2)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    flow_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip        TEXT NOT NULL,
    dst_ip        TEXT NOT NULL,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    packet_count  INTEGER NOT NULL DEFAULT 0,
    byte_count    INTEGER NOT NULL DEFAULT 0,
    syn_count     INTEGER NOT NULL DEFAULT 0,
    rst_count     INTEGER NOT NULL DEFAULT 0,
    fin_count     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen);

CREATE TABLE IF NOT EXISTS window_metrics (
    window_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start    REAL NOT NULL,
    window_end      REAL NOT NULL,
    packet_count    INTEGER,
    byte_count      INTEGER,
    packet_rate     REAL,
    bandwidth_mbps  REAL,
    src_ip_entropy  REAL,
    dst_port_entropy REAL
);

CREATE TABLE IF NOT EXISTS protocol_stats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id     INTEGER NOT NULL REFERENCES window_metrics(window_id),
    protocol      TEXT NOT NULL,
    packet_count  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS top_talkers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id     INTEGER NOT NULL REFERENCES window_metrics(window_id),
    ip            TEXT NOT NULL,
    bytes         INTEGER NOT NULL
);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# In-memory flow tracking (identical to Phase 2)
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    flow_id: int | None = None


def flow_key(pkt):
    if not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    if pkt.haslayer(TCP):
        return (ip_layer.src, ip_layer.dst, pkt[TCP].sport, pkt[TCP].dport, "TCP")
    if pkt.haslayer(UDP):
        return (ip_layer.src, ip_layer.dst, pkt[UDP].sport, pkt[UDP].dport, "UDP")
    return None


def update_flow(active_flows: dict, pkt, now: float) -> None:
    key = flow_key(pkt)
    if key is None:
        return
    size = len(pkt)
    record = active_flows.get(key)
    if record is None:
        src_ip, dst_ip, src_port, dst_port, proto = key
        record = FlowRecord(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                             dst_port=dst_port, protocol=proto, first_seen=now, last_seen=now)
        active_flows[key] = record
    record.last_seen = now
    record.packet_count += 1
    record.byte_count += size

    if pkt.haslayer(TCP):
        flags = int(pkt[TCP].flags)
        if flags & 0x02:
            record.syn_count += 1
            METRIC_SYN_TOTAL.inc()  # cumulative SYN counter, updated live per packet
        if flags & 0x04:
            record.rst_count += 1
        if flags & 0x01:
            record.fin_count += 1


def flush_flows(conn: sqlite3.Connection, active_flows: dict, now: float) -> int:
    cur = conn.cursor()
    # Snapshot with list(...) before iterating: process_packet() runs on
    # Scapy's background sniffer thread and can insert new flows into
    # active_flows at any moment, including while this loop is running.
    # Iterating the live dict directly races with that thread and raises
    # "RuntimeError: dictionary changed size during iteration" whenever a
    # new flow arrives mid-flush. Iterating a snapshot copy instead avoids
    # this without needing a lock, since we only ever read here.
    for record in list(active_flows.values()):
        if record.flow_id is None:
            cur.execute(
                """INSERT INTO flows
                   (src_ip, dst_ip, src_port, dst_port, protocol,
                    first_seen, last_seen, packet_count, byte_count,
                    syn_count, rst_count, fin_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record.src_ip, record.dst_ip, record.src_port, record.dst_port,
                 record.protocol, record.first_seen, record.last_seen,
                 record.packet_count, record.byte_count,
                 record.syn_count, record.rst_count, record.fin_count),
            )
            record.flow_id = cur.lastrowid
        else:
            cur.execute(
                """UPDATE flows SET last_seen=?, packet_count=?, byte_count=?,
                   syn_count=?, rst_count=?, fin_count=? WHERE flow_id=?""",
                (record.last_seen, record.packet_count, record.byte_count,
                 record.syn_count, record.rst_count, record.fin_count, record.flow_id),
            )
    conn.commit()

    finished_keys = [k for k, r in list(active_flows.items()) if now - r.last_seen > FLOW_TIMEOUT_SECONDS]
    for k in finished_keys:
        del active_flows[k]

    METRIC_ACTIVE_FLOWS.set(len(active_flows))  # snapshot gauge, not cumulative
    return len(finished_keys)


# ---------------------------------------------------------------------------
# Window-level stats
# ---------------------------------------------------------------------------

@dataclass
class WindowStats:
    packet_count: int = 0
    byte_count: int = 0
    protocol_counter: Counter = field(default_factory=Counter)
    src_ip_counter: Counter = field(default_factory=Counter)
    dst_port_counter: Counter = field(default_factory=Counter)
    bytes_by_src_ip: Counter = field(default_factory=Counter)


def shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return entropy


def classify_protocol(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return f"IP-proto-{pkt[IP].proto}"
    return "non-IP"


def process_packet(pkt, stats: WindowStats, active_flows: dict) -> None:
    now = time.time()
    update_flow(active_flows, pkt, now)

    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    size = len(pkt)
    stats.packet_count += 1
    stats.byte_count += size
    stats.protocol_counter[classify_protocol(pkt)] += 1
    stats.src_ip_counter[ip_layer.src] += 1
    stats.bytes_by_src_ip[ip_layer.src] += size

    if pkt.haslayer(TCP):
        stats.dst_port_counter[pkt[TCP].dport] += 1
    elif pkt.haslayer(UDP):
        stats.dst_port_counter[pkt[UDP].dport] += 1

    # Cumulative Prometheus counters - updated live, per packet
    METRIC_PACKETS_TOTAL.inc()
    METRIC_BYTES_TOTAL.inc(size)


# ---------------------------------------------------------------------------
# Persisting + exporting a completed window
# ---------------------------------------------------------------------------

def persist_window(conn: sqlite3.Connection, stats: WindowStats,
                    window_start: float, window_end: float) -> int:
    duration = window_end - window_start
    pps = stats.packet_count / duration if duration > 0 else 0
    mbps = (stats.byte_count * 8) / duration / 1_000_000 if duration > 0 else 0
    src_entropy = shannon_entropy(stats.src_ip_counter)
    port_entropy = shannon_entropy(stats.dst_port_counter)

    # Update the Prometheus gauges - this is what Grafana will actually
    # be reading, via Prometheus, the next time it scrapes /metrics.
    METRIC_PACKET_RATE.set(pps)
    METRIC_BANDWIDTH_MBPS.set(mbps)
    METRIC_SRC_IP_ENTROPY.set(src_entropy)
    METRIC_DST_PORT_ENTROPY.set(port_entropy)

    cur = conn.cursor()
    cur.execute(
        """INSERT INTO window_metrics
           (window_start, window_end, packet_count, byte_count,
            packet_rate, bandwidth_mbps, src_ip_entropy, dst_port_entropy)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (window_start, window_end, stats.packet_count, stats.byte_count,
         pps, mbps, src_entropy, port_entropy),
    )
    window_id = cur.lastrowid

    for proto, count in stats.protocol_counter.items():
        cur.execute(
            "INSERT INTO protocol_stats (window_id, protocol, packet_count) VALUES (?, ?, ?)",
            (window_id, proto, count),
        )
    for ip, byte_total in stats.bytes_by_src_ip.most_common(5):
        cur.execute(
            "INSERT INTO top_talkers (window_id, ip, bytes) VALUES (?, ?, ?)",
            (window_id, ip, byte_total),
        )
    conn.commit()

    print(f"[window {window_id}] {stats.packet_count} pkts, {mbps:.3f} Mbps, "
          f"src-entropy={src_entropy:.3f}, port-entropy={port_entropy:.3f}")
    return window_id


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(interface: str, window_seconds: float, db_path: str,
        bpf_filter: str | None, exporter_port: int) -> None:
    conn = init_db(db_path)
    stats = WindowStats()
    active_flows: dict = {}

    def on_packet(pkt):
        process_packet(pkt, stats, active_flows)

    # Starts a tiny built-in HTTP server, in a background thread, serving
    # Prometheus-formatted text at http://localhost:<port>/metrics
    start_http_server(exporter_port)
    print(f"Prometheus metrics exposed at: http://localhost:{exporter_port}/metrics")
    print(f"Storing data in: {db_path}")
    print(f"Starting capture on interface: {interface!r}")
    print(f"Reporting/persisting every {window_seconds:.0f} seconds. Press Ctrl+C to stop.\n")

    sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=on_packet, store=False)
    sniffer.start()
    window_start = time.time()

    try:
        while True:
            time.sleep(window_seconds)
            window_end = time.time()
            persist_window(conn, stats, window_start, window_end)
            finished = flush_flows(conn, active_flows, window_end)
            if finished:
                print(f"    ({finished} flow(s) timed out; {len(active_flows)} still active)")
            stats = WindowStats()
            window_start = window_end
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        sniffer.stop()
        conn.close()


def list_interfaces() -> None:
    print("Available interfaces:")
    for iface in get_if_list():
        print(f"  {iface}")


def parse_args():
    parser = argparse.ArgumentParser(description="Phase 3 capture + SQLite + Prometheus exporter")
    parser.add_argument("--iface", type=str, help="Interface name to capture on. If omitted, auto-detects the active interface.")
    parser.add_argument("--window", type=float, default=5.0)
    parser.add_argument("--db", type=str, default="netmon.db")
    parser.add_argument("--filter", type=str, default=None)
    parser.add_argument("--exporter-port", type=int, default=8000)
    parser.add_argument("--list-interfaces", action="store_true")
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
    run(interface=iface, window_seconds=args.window, db_path=args.db,
        bpf_filter=args.filter, exporter_port=args.exporter_port)