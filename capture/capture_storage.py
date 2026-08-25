"""
Phase 2 - Live capture + SQLite storage (flow-level and window-level)
========================================================================

What's new versus Phase 1
--------------------------
Phase 1 computed metrics in memory and printed them - nothing survived
past the console. Phase 2 adds persistent storage with a two-tier model:

  1. FLOWS (primary, source-of-truth table)
     One row per 5-tuple session (src ip, dst ip, src port, dst port,
     protocol). Updated (upserted) every window while the flow is
     active. This is what lets you answer questions you didn't
     specifically design a dashboard for later - e.g. "show me every
     flow from 10.0.0.5 yesterday" is just a WHERE clause against this
     table, not a feature you have to have pre-built.

  2. WINDOW_METRICS / PROTOCOL_STATS / TOP_TALKERS (rollup tables)
     One row per reporting window (default 5s), storing the aggregated
     numbers we already computed in Phase 1 (packet rate, bandwidth,
     entropy). These are kept as a *separate* rollup rather than
     computed live from the flows table every time, because entropy
     and rate are cheap to compute once per window but expensive to
     recompute from raw flow history on every dashboard refresh.

Design principle: flows = detail you can query anything from later,
window_metrics = pre-computed numbers for fast dashboarding. Don't
conflate the two into one table - it's a very common mistake that
makes both slow.

Flow lifecycle
---------------
A flow is identified by its 5-tuple (src_ip, dst_ip, src_port,
dst_port, protocol). It's tracked in memory in `active_flows` while
packets keep arriving for it. Each window:
    - every active flow is upserted into SQLite (insert if new,
      update if it already has a flow_id from a previous window)
    - flows that have been silent for longer than FLOW_TIMEOUT_SECONDS
      are considered finished and dropped from memory (their last
      state is already persisted, so nothing is lost)

Usage
-----
    python capture_storage.py --iface "Wi-Fi" --window 5 --db netmon.db

Run as Administrator on Windows (same Npcap requirement as Phase 1).
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

FLOW_TIMEOUT_SECONDS = 30  # a flow with no packets for this long is considered finished


# ---------------------------------------------------------------------------
# SQLite schema
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
    conn.execute("PRAGMA journal_mode=WAL")  # allows reads while we're writing
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# In-memory flow tracking
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    """In-memory state for one active flow (5-tuple session)."""
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
    flow_id: int | None = None  # set once this flow has been inserted into SQLite


def flow_key(pkt) -> tuple | None:
    """Return the 5-tuple identifying this packet's flow, or None if not TCP/UDP."""
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
        record = FlowRecord(
            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
            protocol=proto, first_seen=now, last_seen=now,
        )
        active_flows[key] = record

    record.last_seen = now
    record.packet_count += 1
    record.byte_count += size

    if pkt.haslayer(TCP):
        flags = int(pkt[TCP].flags)
        if flags & 0x02:  # SYN
            record.syn_count += 1
        if flags & 0x04:  # RST
            record.rst_count += 1
        if flags & 0x01:  # FIN
            record.fin_count += 1


def flush_flows(conn: sqlite3.Connection, active_flows: dict, now: float) -> int:
    """Upsert every active flow into SQLite, then drop flows that timed out.

    Returns the number of flows removed (finished) this call, for reporting.
    """
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
                 record.syn_count, record.rst_count, record.fin_count,
                 record.flow_id),
            )
    conn.commit()

    # Evict flows that have been silent longer than the timeout - their
    # latest state is already persisted above, so this is safe.
    finished_keys = [
        key for key, record in list(active_flows.items())
        if now - record.last_seen > FLOW_TIMEOUT_SECONDS
    ]
    for key in finished_keys:
        del active_flows[key]
    return len(finished_keys)


# ---------------------------------------------------------------------------
# Window-level stats (same as Phase 1)
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


# ---------------------------------------------------------------------------
# Persisting + reporting a completed window
# ---------------------------------------------------------------------------

def persist_window(conn: sqlite3.Connection, stats: WindowStats,
                    window_start: float, window_end: float) -> int:
    duration = window_end - window_start
    pps = stats.packet_count / duration if duration > 0 else 0
    mbps = (stats.byte_count * 8) / duration / 1_000_000 if duration > 0 else 0
    src_entropy = shannon_entropy(stats.src_ip_counter)
    port_entropy = shannon_entropy(stats.dst_port_counter)

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

def run(interface: str, window_seconds: float, db_path: str, bpf_filter: str | None) -> None:
    conn = init_db(db_path)
    stats = WindowStats()
    active_flows: dict = {}

    def on_packet(pkt):
        process_packet(pkt, stats, active_flows)

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
                print(f"    ({finished} flow(s) timed out and were finalized; "
                      f"{len(active_flows)} still active)")
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
    parser = argparse.ArgumentParser(description="Phase 2 capture + SQLite storage")
    parser.add_argument("--iface", type=str, help="Interface name to capture on. If omitted, auto-detects the active interface.")
    parser.add_argument("--window", type=float, default=5.0, help="Window size in seconds")
    parser.add_argument("--db", type=str, default="netmon.db", help="SQLite database file path")
    parser.add_argument("--filter", type=str, default=None, help="Optional BPF filter")
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
    run(interface=iface, window_seconds=args.window, db_path=args.db, bpf_filter=args.filter)