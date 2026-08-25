"""
Phase 7 - Backend query logic
================================

This module contains all the actual data-fetching logic, kept
deliberately separate from the FastAPI route definitions in api.py.

Why separated this way
-------------------------
Every function here takes a plain sqlite3.Connection and returns plain
Python data (dicts/lists) - no FastAPI, no HTTP, no async. This means
the actual query logic (which is the part most likely to have a real
bug - a wrong JOIN, an off-by-one time window, wrong sort order) can be
tested directly with a synthetic SQLite database, without needing a
running web server or an HTTP client. api.py then just wraps each of
these functions in a thin route handler.

Design note: everything here reads from SQLite only, not Prometheus,
even for values (like active flow count) that are also exposed as a
live Prometheus gauge elsewhere in the project. This keeps the backend
consistent with this project's established architecture (SQLite is the
detailed, queryable source of truth; Prometheus is for time-series
dashboarding) and avoids adding an HTTP round-trip to Prometheus as a
second dependency for the same information - "active flows in the last
30 seconds" is computable directly and just as accurately from the
flows table itself.
"""

import sqlite3
import time


def get_snapshot(conn: sqlite3.Connection) -> dict:
    """Current point-in-time readout: latest window's metrics, plus
    live-computed active flow count and SYN rate derived directly from
    the flows table (not stored precomputed anywhere)."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        """SELECT window_id, window_start, window_end, packet_rate, bandwidth_mbps,
                  src_ip_entropy, dst_port_entropy
           FROM window_metrics ORDER BY window_id DESC LIMIT 1"""
    )
    latest = cur.fetchone()
    if latest is None:
        return {"available": False}

    now = time.time()
    cur.execute("SELECT COUNT(*) AS n FROM flows WHERE last_seen > ?", (now - 30,))
    active_flows = cur.fetchone()["n"]

    cur.execute(
        "SELECT COALESCE(SUM(syn_count), 0) AS total_syn FROM flows WHERE last_seen > ?",
        (now - 60,),
    )
    syn_rate = cur.fetchone()["total_syn"] / 60.0

    cur.execute(
        """SELECT anomaly_score, is_anomaly FROM anomalies
           ORDER BY window_id DESC LIMIT 1"""
    )
    anomaly_row = cur.fetchone()

    return {
        "available": True,
        "window_id": latest["window_id"],
        "timestamp": latest["window_end"],
        "packet_rate": round(latest["packet_rate"], 2),
        "bandwidth_mbps": round(latest["bandwidth_mbps"], 4),
        "src_ip_entropy": round(latest["src_ip_entropy"], 3),
        "dst_port_entropy": round(latest["dst_port_entropy"], 3),
        "entropy_divergence": round(latest["dst_port_entropy"] - latest["src_ip_entropy"], 3),
        "active_flows": active_flows,
        "syn_rate": round(syn_rate, 3),
        "anomaly_score": round(anomaly_row["anomaly_score"], 4) if anomaly_row else None,
        "is_anomaly": bool(anomaly_row["is_anomaly"]) if anomaly_row else False,
    }


def get_entropy_history(conn: sqlite3.Connection, limit: int = 40) -> list[dict]:
    """Recent window-by-window entropy values, oldest first, for the
    dashboard's live scope chart."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """SELECT window_id, window_end, src_ip_entropy, dst_port_entropy, packet_rate
           FROM window_metrics ORDER BY window_id DESC LIMIT ?""",
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    rows.reverse()  # chronological order for a left-to-right chart
    return rows


def get_top_talkers(conn: sqlite3.Connection, minutes: int = 10, limit: int = 5) -> list[dict]:
    """Top talkers by byte volume across recent windows, using the
    per-window top_talkers table populated by the capture engine."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cutoff_window_start = time.time() - (minutes * 60)
    cur.execute(
        """SELECT t.ip, SUM(t.bytes) AS total_bytes
           FROM top_talkers t
           JOIN window_metrics w ON w.window_id = t.window_id
           WHERE w.window_start > ?
           GROUP BY t.ip
           ORDER BY total_bytes DESC
           LIMIT ?""",
        (cutoff_window_start, limit),
    )
    return [dict(r) for r in cur.fetchall()]


def get_anomalies(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    """Recent anomaly-flagged windows, most recent first, joined back to
    window_metrics for context (what the traffic actually looked like)."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """SELECT a.window_id, a.anomaly_score, a.computed_at,
                  w.window_end, w.packet_rate, w.src_ip_entropy, w.dst_port_entropy
           FROM anomalies a
           JOIN window_metrics w ON w.window_id = a.window_id
           WHERE a.is_anomaly = 1
           ORDER BY a.window_id DESC
           LIMIT ?""",
        (limit,),
    )
    return [dict(r) for r in cur.fetchall()]


def get_probe_status(conn: sqlite3.Connection) -> list[dict]:
    """Latest result per probe target (Phase 4 data)."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """SELECT p.target, p.status, p.rtt_avg_ms, p.jitter_ms, p.packet_loss_pct, p.timestamp
           FROM probe_results p
           INNER JOIN (
               SELECT target, MAX(id) AS max_id FROM probe_results GROUP BY target
           ) latest ON p.id = latest.max_id
           ORDER BY p.target"""
    )
    return [dict(r) for r in cur.fetchall()]


def get_period_stats(conn: sqlite3.Connection, minutes: int) -> dict:
    """Aggregated summary statistics over a trailing time period - the
    core numbers a periodic report needs (unlike get_snapshot, which is
    a single point-in-time reading)."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cutoff = time.time() - (minutes * 60)
    cur.execute(
        """SELECT COUNT(*) AS window_count,
                  AVG(packet_rate) AS avg_packet_rate, MAX(packet_rate) AS max_packet_rate,
                  AVG(bandwidth_mbps) AS avg_bandwidth_mbps, MAX(bandwidth_mbps) AS max_bandwidth_mbps,
                  AVG(src_ip_entropy) AS avg_src_entropy, AVG(dst_port_entropy) AS avg_dst_entropy
           FROM window_metrics WHERE window_start > ?""",
        (cutoff,),
    )
    row = dict(cur.fetchone())
    row["period_minutes"] = minutes
    row["period_start"] = cutoff
    row["period_end"] = time.time()
    return row


def get_anomalies_in_period(conn: sqlite3.Connection, minutes: int) -> list[dict]:
    """Anomaly-flagged windows within a trailing time period specifically
    (unlike get_anomalies, which returns the most recent N regardless of
    how long ago they occurred) - what a periodic report needs: 'what
    happened during this reporting period', not 'what are the most
    recent anomalies overall'."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cutoff = time.time() - (minutes * 60)
    cur.execute(
        """SELECT a.window_id, a.anomaly_score, a.computed_at,
                  w.window_end, w.packet_rate, w.src_ip_entropy, w.dst_port_entropy
           FROM anomalies a
           JOIN window_metrics w ON w.window_id = a.window_id
           WHERE a.is_anomaly = 1 AND w.window_start > ?
           ORDER BY a.window_id DESC""",
        (cutoff,),
    )
    return [dict(r) for r in cur.fetchall()]


def get_flows(conn: sqlite3.Connection, minutes: int = 10, limit: int = 100) -> list[dict]:
    """Recent flow records, for a drill-down / raw-data view."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cutoff = time.time() - (minutes * 60)
    cur.execute(
        """SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                  packet_count, byte_count, syn_count, rst_count, last_seen
           FROM flows
           WHERE last_seen > ?
           ORDER BY byte_count DESC
           LIMIT ?""",
        (cutoff, limit),
    )
    return [dict(r) for r in cur.fetchall()]