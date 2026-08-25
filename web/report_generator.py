"""
Phase 7 - Automated periodic report generator
==================================================

Runs continuously alongside the rest of the system and, every
--interval-seconds (default 1800 = 30 minutes), writes a self-contained
HTML summary report of the preceding period to the reports/ folder,
which api.py's /api/reports endpoint already lists (and, with the
addition of a file-serving route in this same update, can actually
download).

Design: each report waits for the FULL interval to elapse before being
generated, so the period it covers ([now - interval, now]) is exactly
one complete, non-overlapping reporting window - not a partial one
generated mid-cycle.

Report content
----------------
Reuses queries.py exclusively - the same, already-tested functions the
live API endpoints use - rather than writing separate one-off SQL for
the report. This guarantees the report's numbers are computed exactly
the same way as the numbers shown live on the dashboard; a report
disagreeing with what the dashboard showed during that period would be
a serious credibility problem for a monitoring tool.

Usage
-----
    python report_generator.py --db netmon.db --interval-seconds 1800

    # For quick testing without waiting 30 real minutes:
    python report_generator.py --db netmon.db --interval-seconds 120
"""

import argparse
import html
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

import queries as q


def render_report_html(stats: dict, talkers: list[dict], anomalies: list[dict],
                        probes: list[dict], generated_at: float) -> str:
    period_start_str = datetime.fromtimestamp(stats["period_start"]).strftime("%Y-%m-%d %H:%M:%S")
    period_end_str = datetime.fromtimestamp(stats["period_end"]).strftime("%Y-%m-%d %H:%M:%S")

    def esc(x):
        return html.escape(str(x))

    talker_rows = "".join(
        f"<tr><td>{esc(t['ip'])}</td><td>{t['total_bytes']:,} bytes</td></tr>"
        for t in talkers
    ) or "<tr><td colspan='2' class='empty'>No talker data for this period</td></tr>"

    if anomalies:
        anomaly_rows = "".join(
            f"<tr><td>{a['window_id']}</td>"
            f"<td>{datetime.fromtimestamp(a['window_end']).strftime('%H:%M:%S')}</td>"
            f"<td>{a['anomaly_score']:.4f}</td>"
            f"<td>{a['packet_rate']:.1f}</td>"
            f"<td>{(a['dst_port_entropy'] - a['src_ip_entropy']):.2f}</td></tr>"
            for a in anomalies
        )
    else:
        anomaly_rows = "<tr><td colspan='5' class='empty'>No anomalies detected during this period</td></tr>"

    probe_rows = "".join(
        f"<tr><td>{esc(p['target'])}</td><td>{esc(p['status'])}</td>"
        f"<td>{p['rtt_avg_ms']:.1f} ms</td><td>{p['jitter_ms']:.2f} ms</td>"
        f"<td>{p['packet_loss_pct']}%</td></tr>"
        for p in probes
    ) or "<tr><td colspan='5' class='empty'>No probe data available</td></tr>"

    status_flag = "ANOMALIES DETECTED" if anomalies else "NORMAL"
    status_color = "#FF5A5A" if anomalies else "#34D399"

    avg_rate = stats["avg_packet_rate"] or 0
    max_rate = stats["max_packet_rate"] or 0
    avg_bw = stats["avg_bandwidth_mbps"] or 0
    max_bw = stats["max_bandwidth_mbps"] or 0

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Netmon Report {esc(period_end_str)}</title>
<style>
  body {{ background:#0B0D0E; color:#E8E6E1; font-family: 'Segoe UI', Arial, sans-serif; padding: 32px; }}
  .mono {{ font-family: Consolas, monospace; }}
  h1 {{ font-size: 20px; margin-bottom: 4px; }}
  .subtitle {{ color:#8B9198; font-size: 13px; margin-bottom: 20px; }}
  .status {{ display:inline-block; padding: 4px 12px; border-radius: 999px; font-family: monospace;
             font-size: 12px; border: 1px solid {status_color}66; background: {status_color}1A; color: {status_color}; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 28px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #ffffff10; }}
  th {{ font-family: monospace; font-size: 10px; letter-spacing: 1px; text-transform: uppercase; color: #5C6470; }}
  td {{ font-family: monospace; color: #D4D4D8; }}
  .empty {{ color: #4B5158; text-align: center; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }}
  .stat-tile {{ background: #14171A; border: 1px solid #ffffff10; border-radius: 8px; padding: 14px; }}
  .stat-label {{ font-family: monospace; font-size: 10px; color: #5C6470; text-transform: uppercase; letter-spacing: 1px; }}
  .stat-value {{ font-family: monospace; font-size: 22px; font-weight: 600; margin-top: 8px; color: #FFB020; }}
  h2 {{ font-family: monospace; font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase; color: #8B9198; margin-bottom: 10px; }}
</style></head>
<body>
  <h1>Network Monitoring Report</h1>
  <div class="subtitle">Period: {esc(period_start_str)} &ndash; {esc(period_end_str)} ({stats['period_minutes']} minutes, {stats['window_count']} capture windows) &middot; generated {esc(datetime.fromtimestamp(generated_at).strftime('%Y-%m-%d %H:%M:%S'))}</div>
  <div class="status">{status_flag}</div>

  <div class="stat-grid">
    <div class="stat-tile"><div class="stat-label">Avg Packet Rate</div><div class="stat-value">{avg_rate:.1f} <span style="font-size:12px;color:#5C6470;">pkt/s</span></div></div>
    <div class="stat-tile"><div class="stat-label">Max Packet Rate</div><div class="stat-value">{max_rate:.1f} <span style="font-size:12px;color:#5C6470;">pkt/s</span></div></div>
    <div class="stat-tile"><div class="stat-label">Avg Bandwidth</div><div class="stat-value">{avg_bw:.3f} <span style="font-size:12px;color:#5C6470;">Mbps</span></div></div>
    <div class="stat-tile"><div class="stat-label">Max Bandwidth</div><div class="stat-value">{max_bw:.3f} <span style="font-size:12px;color:#5C6470;">Mbps</span></div></div>
  </div>

  <h2>Top Talkers This Period</h2>
  <table><tr><th>IP Address</th><th>Bytes</th></tr>{talker_rows}</table>

  <h2>Anomalies Detected This Period</h2>
  <table><tr><th>Window</th><th>Time</th><th>Score</th><th>Pkt Rate</th><th>Divergence</th></tr>{anomaly_rows}</table>

  <h2>Probe Status (at report generation time)</h2>
  <table><tr><th>Target</th><th>Status</th><th>RTT</th><th>Jitter</th><th>Loss</th></tr>{probe_rows}</table>
</body></html>"""


def generate_report(db_path: str, output_dir: Path, period_minutes: int) -> Path:
    """Builds one report. Each data section is fetched independently -
    if one table doesn't exist yet (e.g. probe_results, before
    active_probe.py has ever run against this database), that section
    degrades to an empty result rather than crashing the entire report.
    A report missing its Probe Status section is far more useful than
    no report existing at all; the failure of one optional subsystem
    should never silently prevent every other section from being
    generated and written to disk."""
    conn = sqlite3.connect(db_path)
    try:
        # get_period_stats reads window_metrics, this project's most
        # fundamental table - if this specific query fails, something
        # is genuinely wrong (not just "one optional table missing"),
        # so this one is allowed to propagate and stop report
        # generation rather than being silently swallowed.
        stats = q.get_period_stats(conn, minutes=period_minutes)

        try:
            talkers = q.get_top_talkers(conn, minutes=period_minutes, limit=10)
        except sqlite3.OperationalError as e:
            print(f"Warning: top talkers unavailable this cycle ({e}); continuing without them.")
            talkers = []

        try:
            anomalies = q.get_anomalies_in_period(conn, minutes=period_minutes)
        except sqlite3.OperationalError as e:
            print(f"Warning: anomalies unavailable this cycle ({e}); continuing without them.")
            anomalies = []

        try:
            probes = q.get_probe_status(conn)
        except sqlite3.OperationalError as e:
            print(f"Warning: probe status unavailable this cycle ({e}); continuing without it.")
            probes = []
    finally:
        conn.close()

    generated_at = time.time()
    html_content = render_report_html(stats, talkers, anomalies, probes, generated_at)

    output_dir.mkdir(exist_ok=True)
    filename = datetime.fromtimestamp(generated_at).strftime("report_%Y-%m-%d_%H-%M.html")
    filepath = output_dir / filename
    filepath.write_text(html_content, encoding="utf-8")
    return filepath


def parse_args():
    parser = argparse.ArgumentParser(description="Automated periodic network monitoring report generator")
    parser.add_argument("--db", type=str, default="netmon.db")
    parser.add_argument("--output-dir", type=str, default="reports")
    parser.add_argument("--interval-seconds", type=int, default=1800,
                         help="Seconds between reports (default 1800 = 30 minutes)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    output_dir = Path(args.output_dir)
    period_minutes = args.interval_seconds / 60

    print(f"Report generator started. Writing to: {output_dir.resolve()}")
    print(f"Generating a report every {args.interval_seconds}s ({period_minutes:.1f} min). Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(args.interval_seconds)
            if not Path(args.db).exists():
                print(f"Warning: database {args.db!r} not found, skipping this cycle.")
                continue
            path = generate_report(args.db, output_dir, period_minutes)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Report written: {path}")
    except KeyboardInterrupt:
        print("\nStopping report generator...")
        sys.exit(0)