"""
Phase 4 - Active probing: RTT, jitter, and packet loss
=========================================================

Why this phase exists
-----------------------
Phases 1-3 are all *passive* - they only observe traffic that happens
to occur. This is fine for throughput, protocol mix, entropy, and flow
analysis, but it cannot honestly answer three questions a network
engineer cares about:

    - What is the real round-trip time to a given host?
    - What is real packet loss to that host?
    - What is jitter (variation in RTT over time)?

Passive capture has no way to measure these for arbitrary traffic,
because it isn't the one sending the probe - at best it can infer
approximate TCP handshake timing for flows that happen to occur. This
module instead *actively* probes a small, fixed set of targets on a
schedule (the same approach used by tools like NetworkPing / classic
smokeping), which is the only way to get real, honest RTT/jitter/loss
numbers on demand rather than opportunistically.

Design notes
-------------
- Uses Scapy's ICMP Echo Request/Reply (ping) directly, rather than
  shelling out to the system `ping` command, to stay consistent with
  the rest of the project and avoid parsing OS-specific ping text
  output. Requires the same Npcap/admin privileges as capture.
- Jitter is defined here the same way as NetworkPing: the absolute
  difference between this cycle's average RTT and the previous
  cycle's average RTT for the same target. This is a simplification of
  "true" jitter (RFC 3550 defines it via consecutive packet arrival
  deltas) but is simple, reproducible, and documented as such.
- The target pool is small and fixed (a handful of hosts), not one
  entry per arbitrary flow - this deliberately avoids the Prometheus
  high-cardinality-label problem noted in the Phase 3 documentation.
- Kept as a separate process/script from the passive capture engine
  (capture_exporter.py), since it is a different monitoring mechanism
  with a different failure mode; it has its own SQLite table and its
  own Prometheus exporter port so it can run independently.

Usage
-----
    python active_probe.py --targets targets.txt --interval 30 --count 4 --db netmon.db --exporter-port 8001

targets.txt: one host/IP per line, '#' for comments, blank lines ignored.

Run as Administrator on Windows (ICMP raw sockets require it, same as capture).
"""

import argparse
import sqlite3
import sys
import time
from dataclasses import dataclass

from scapy.all import IP, ICMP, sr1
from prometheus_client import start_http_server, Gauge

from network_utils import get_default_gateway, GatewayNotFoundError

# ---------------------------------------------------------------------------
# Prometheus metrics - labeled by target, which is safe here because the
# target set is small and fixed (unlike per-flow IPs in Phase 3).
# ---------------------------------------------------------------------------

METRIC_RTT_MIN   = Gauge("netmon_probe_rtt_min_ms", "Minimum RTT in the last probe cycle", ["target"])
METRIC_RTT_AVG   = Gauge("netmon_probe_rtt_avg_ms", "Average RTT in the last probe cycle", ["target"])
METRIC_RTT_MAX   = Gauge("netmon_probe_rtt_max_ms", "Maximum RTT in the last probe cycle", ["target"])
METRIC_JITTER    = Gauge("netmon_probe_jitter_ms", "abs(this cycle avg RTT - previous cycle avg RTT)", ["target"])
METRIC_LOSS_PCT  = Gauge("netmon_probe_packet_loss_pct", "Packet loss percentage in the last probe cycle", ["target"])
METRIC_UP        = Gauge("netmon_probe_up", "1 if at least one probe in the cycle got a reply, else 0", ["target"])


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL NOT NULL,
    target          TEXT NOT NULL,
    status          TEXT NOT NULL,     -- 'UP' or 'DOWN'
    rtt_min_ms      REAL,
    rtt_avg_ms      REAL,
    rtt_max_ms      REAL,
    jitter_ms       REAL,
    packet_loss_pct REAL
);
CREATE INDEX IF NOT EXISTS idx_probe_target ON probe_results(target);
CREATE INDEX IF NOT EXISTS idx_probe_timestamp ON probe_results(timestamp);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Target pool parsing (same conventions as NetworkPing's pool.txt, minus
# the URL-to-host reduction since this project targets IPs/hostnames)
# ---------------------------------------------------------------------------

def load_targets(path: str) -> list[str]:
    """Load the target pool file. A line containing exactly the literal
    placeholder GATEWAY is resolved at load time to this machine's
    actual default gateway IP, so targets.txt does not need to hardcode
    a specific network's gateway address and stays portable across
    machines/networks without manual editing."""
    targets = []
    gateway_ip = None  # resolved lazily, only if the placeholder is actually used

    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or " " in line or line.endswith(":"):
                continue
            if line == "GATEWAY":
                if gateway_ip is None:
                    try:
                        gateway_ip = get_default_gateway()
                        print(f"Resolved GATEWAY placeholder to: {gateway_ip}")
                    except GatewayNotFoundError as e:
                        raise ValueError(
                            f"targets.txt contains the GATEWAY placeholder, but "
                            f"auto-detection failed: {e}. Replace GATEWAY with an "
                            f"explicit IP address instead."
                        ) from e
                targets.append(gateway_ip)
            else:
                targets.append(line)

    if not targets:
        raise ValueError(f"No targets found in {path}")
    return targets


# ---------------------------------------------------------------------------
# Probing a single target for one cycle
# ---------------------------------------------------------------------------

@dataclass
class CycleResult:
    target: str
    status: str
    rtt_min_ms: float | None
    rtt_avg_ms: float | None
    rtt_max_ms: float | None
    packet_loss_pct: float


def probe_target(target: str, count: int, timeout: float) -> CycleResult:
    """Send `count` ICMP echo requests to target, one at a time, and
    summarize the round-trip times observed."""
    rtts_ms = []
    for _ in range(count):
        pkt = IP(dst=target) / ICMP()
        sent_at = time.time()
        # sr1 sends one packet and waits for exactly one matching reply,
        # or returns None on timeout. verbose=0 suppresses Scapy's own
        # console output so it doesn't interleave with our reporting.
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is not None:
            rtt_ms = (time.time() - sent_at) * 1000
            rtts_ms.append(rtt_ms)

    loss_pct = 100.0 * (count - len(rtts_ms)) / count

    if not rtts_ms:
        return CycleResult(target, "DOWN", None, None, None, loss_pct)

    return CycleResult(
        target=target,
        status="UP",
        rtt_min_ms=min(rtts_ms),
        rtt_avg_ms=sum(rtts_ms) / len(rtts_ms),
        rtt_max_ms=max(rtts_ms),
        packet_loss_pct=loss_pct,
    )


# ---------------------------------------------------------------------------
# Persist + export one cycle's results
# ---------------------------------------------------------------------------

def persist_and_export(conn: sqlite3.Connection, result: CycleResult,
                        previous_avg: dict, timestamp: float) -> None:
    prev = previous_avg.get(result.target)
    jitter_ms = None
    if prev is not None and result.rtt_avg_ms is not None:
        jitter_ms = abs(result.rtt_avg_ms - prev)
    if result.rtt_avg_ms is not None:
        previous_avg[result.target] = result.rtt_avg_ms

    conn.execute(
        """INSERT INTO probe_results
           (timestamp, target, status, rtt_min_ms, rtt_avg_ms, rtt_max_ms,
            jitter_ms, packet_loss_pct)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, result.target, result.status, result.rtt_min_ms,
         result.rtt_avg_ms, result.rtt_max_ms, jitter_ms, result.packet_loss_pct),
    )
    conn.commit()

    METRIC_UP.labels(target=result.target).set(1 if result.status == "UP" else 0)
    METRIC_LOSS_PCT.labels(target=result.target).set(result.packet_loss_pct)
    if result.rtt_avg_ms is not None:
        METRIC_RTT_MIN.labels(target=result.target).set(result.rtt_min_ms)
        METRIC_RTT_AVG.labels(target=result.target).set(result.rtt_avg_ms)
        METRIC_RTT_MAX.labels(target=result.target).set(result.rtt_max_ms)
    if jitter_ms is not None:
        METRIC_JITTER.labels(target=result.target).set(jitter_ms)

    rtt_str = f"{result.rtt_avg_ms:.1f}ms" if result.rtt_avg_ms is not None else "N/A"
    jitter_str = f"{jitter_ms:.1f}ms" if jitter_ms is not None else "N/A"
    print(f"[{result.target:20s}] {result.status:4s} rtt_avg={rtt_str:>8s} "
          f"jitter={jitter_str:>8s} loss={result.packet_loss_pct:5.1f}%")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(targets_path: str, interval: float, count: int, timeout: float,
        db_path: str, exporter_port: int) -> None:
    targets = load_targets(targets_path)
    conn = init_db(db_path)
    previous_avg: dict = {}

    start_http_server(exporter_port)
    print(f"Prometheus metrics exposed at: http://localhost:{exporter_port}/metrics")
    print(f"Probing {len(targets)} target(s): {', '.join(targets)}")
    print(f"Cycle interval: {interval:.0f}s, {count} probes per target per cycle\n")

    try:
        while True:
            cycle_start = time.time()
            for target in targets:
                result = probe_target(target, count=count, timeout=timeout)
                persist_and_export(conn, result, previous_avg, timestamp=time.time())
            elapsed = time.time() - cycle_start
            sleep_for = max(0.0, interval - elapsed)
            print()
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        print("\nStopping probes...")
    finally:
        conn.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Phase 4 active probing: RTT, jitter, packet loss")
    parser.add_argument("--targets", type=str, default="targets.txt", help="Path to target list file")
    parser.add_argument("--interval", type=float, default=30.0, help="Seconds between probe cycles")
    parser.add_argument("--count", type=int, default=4, help="Probes per target per cycle")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-probe timeout in seconds")
    parser.add_argument("--db", type=str, default="netmon.db", help="SQLite database file path")
    parser.add_argument("--exporter-port", type=int, default=8001, help="Prometheus exporter port")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(targets_path=args.targets, interval=args.interval, count=args.count,
        timeout=args.timeout, db_path=args.db, exporter_port=args.exporter_port)