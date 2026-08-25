"""
Phase 5 - Anomaly detection using scikit-learn's Isolation Forest
=====================================================================

What this phase does
----------------------
Phases 1-4 produced a rich set of independently-validated signals:
entropy (source-IP and destination-port), packet rate, bandwidth, and
(from Phase 4, kept separate) active-probing RTT/jitter/loss. Each of
these was shown, on its own, to move in a predictable direction during
a real attack (the Nmap scan validated throughout Phases 1-3). This
phase combines several of those signals into a single unsupervised
anomaly detector, rather than relying on any one fixed threshold.

Why Isolation Forest specifically
-----------------------------------
Isolation Forest works by building an ensemble of random decision
trees that each try to isolate individual data points via random
feature splits. Points that are "normal" (similar to the bulk of the
data) require many splits to isolate, since they're surrounded by
similar points. Points that are anomalous are, on average, isolated in
far fewer splits, because a small number of random splits is enough to
separate them from everything else. This makes it well suited to this
project's use case: it does not require labeled attack data (this
project has none, and generating enough labeled attack traffic to
train a supervised classifier is impractical), and it degrades
gracefully to a "no bad news" baseline on ordinary traffic, which is
what the vast majority of any real deployment's data will look like.

Feature set
------------
Loaded directly from the window_metrics table already populated by
Phase 2/3 - no schema changes to existing tables were required:

    - packet_rate        (packets/second)
    - bandwidth_mbps      (Mbps)
    - src_ip_entropy       (bits)
    - dst_port_entropy      (bits)
    - entropy_divergence      (dst_port_entropy - src_ip_entropy)

The fifth feature is engineered, not stored directly: it is exactly
the diagnostic signature identified in the Phase 1 analysis - during a
scan, destination-port entropy rises while source-IP entropy
simultaneously falls, so their *difference* spikes far more sharply
than either value alone. Isolation Forest can in principle learn
interactions between raw features on its own, but making this
particular interaction an explicit input feature gives the model a
strong, theoretically-motivated head start rather than relying on it
to rediscover a relationship already established analytically.

Feature scaling is deliberately NOT applied. Unlike distance-based
methods (e.g. k-means, kNN), Isolation Forest's splits are chosen
per-feature independently and are invariant to monotonic per-feature
rescaling, so standardization would add complexity without changing
the model's behaviour.

Usage
-----
    # Train on all historical window_metrics data, save the model,
    # and report which historical windows the model flags as anomalous
    # (useful for sanity-checking against known events, e.g. the Nmap
    # scan windows documented in Phase 1).
    python anomaly_detector.py --mode train --db netmon.db --model model.joblib

    # Continuously score newly-arriving windows (run alongside the
    # capture engine), writing results to the 'anomalies' table and
    # optionally exposing a Prometheus gauge.
    python anomaly_detector.py --mode watch --db netmon.db --model model.joblib --exporter-port 8002
"""

import argparse
import sqlite3
import sys
import time

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_COLUMNS = [
    "packet_rate", "bandwidth_mbps", "src_ip_entropy", "dst_port_entropy",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS anomalies (
    window_id     INTEGER PRIMARY KEY,
    anomaly_score REAL NOT NULL,
    is_anomaly    INTEGER NOT NULL,
    computed_at   REAL NOT NULL
);
"""


def init_anomalies_table(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def build_feature_matrix(rows: list[dict]) -> np.ndarray:
    """Turn a list of window_metrics rows into a feature matrix, adding
    the engineered entropy_divergence feature described above."""
    X = []
    for row in rows:
        divergence = row["dst_port_entropy"] - row["src_ip_entropy"]
        X.append([
            row["packet_rate"],
            row["bandwidth_mbps"],
            row["src_ip_entropy"],
            row["dst_port_entropy"],
            divergence,
        ])
    return np.array(X, dtype=float)


def load_window_rows(conn: sqlite3.Connection, since_window_id: int = 0) -> list[dict]:
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        f"""SELECT window_id, {", ".join(FEATURE_COLUMNS)}
            FROM window_metrics
            WHERE window_id > ?
            ORDER BY window_id""",
        (since_window_id,),
    )
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_model(X: np.ndarray, contamination) -> IsolationForest:
    """Fit an Isolation Forest on the given feature matrix.

    contamination is the expected proportion of anomalies in the
    training data - it controls where the model draws its decision
    boundary between "normal" and "anomalous". 'auto' lets scikit-learn
    pick a data-driven default; a small explicit fraction (e.g. 0.02-0.05)
    is more appropriate once there is a rough sense of how rare real
    anomalies are expected to be in a given deployment's baseline traffic.

    random_state is fixed for reproducibility - without it, which exact
    points get flagged can vary slightly between runs on the same data,
    which would make this project's validation results non-reproducible.
    """
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)
    return model


def score(model: IsolationForest, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Return (anomaly_scores, is_anomaly) for each row in X.

    decision_function: higher = more normal, lower (more negative) =
    more anomalous. predict: -1 = anomaly, 1 = normal - converted here
    to a plain 0/1 int for storage.
    """
    scores = model.decision_function(X)
    predictions = model.predict(X)
    is_anomaly = (predictions == -1).astype(int)
    return scores, is_anomaly


# ---------------------------------------------------------------------------
# Train mode: fit on full history, report + persist results
# ---------------------------------------------------------------------------

def run_train(db_path: str, model_path: str, contamination) -> None:
    conn = sqlite3.connect(db_path)
    init_anomalies_table(conn)

    rows = load_window_rows(conn)
    if len(rows) < 10:
        print(f"Error: only {len(rows)} window_metrics rows available; "
              f"need at least 10 to train a meaningful model. "
              f"Run the capture engine longer first.")
        sys.exit(1)

    X = build_feature_matrix(rows)
    model = train_model(X, contamination)
    joblib.dump(model, model_path)
    print(f"Trained on {len(rows)} windows. Model saved to: {model_path}")

    scores, is_anomaly = score(model, X)
    cur = conn.cursor()
    now = time.time()
    for row, s, a in zip(rows, scores, is_anomaly):
        cur.execute(
            """INSERT INTO anomalies (window_id, anomaly_score, is_anomaly, computed_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(window_id) DO UPDATE SET
                   anomaly_score=excluded.anomaly_score,
                   is_anomaly=excluded.is_anomaly,
                   computed_at=excluded.computed_at""",
            (row["window_id"], float(s), int(a), now),
        )
    conn.commit()

    flagged = [(row, s) for row, s, a in zip(rows, scores, is_anomaly) if a == 1]
    flagged.sort(key=lambda pair: pair[1])  # most anomalous (lowest score) first
    print(f"\n{len(flagged)} of {len(rows)} windows flagged as anomalous "
          f"({100 * len(flagged) / len(rows):.1f}%).")
    if flagged:
        print("\nMost anomalous windows (lowest score = most anomalous):")
        print(f"{'window_id':>10} {'score':>8}  {'pkt_rate':>9} {'bw_mbps':>9} "
              f"{'src_ent':>8} {'dst_ent':>8}")
        for row, s in flagged[:15]:
            print(f"{row['window_id']:>10} {s:>8.4f}  {row['packet_rate']:>9.1f} "
                  f"{row['bandwidth_mbps']:>9.3f} {row['src_ip_entropy']:>8.3f} "
                  f"{row['dst_port_entropy']:>8.3f}")
    conn.close()


# ---------------------------------------------------------------------------
# Watch mode: continuously score newly-arriving windows
# ---------------------------------------------------------------------------

def run_watch(db_path: str, model_path: str, poll_interval: float, exporter_port: int | None) -> None:
    try:
        model = joblib.load(model_path)
    except FileNotFoundError:
        print(f"Error: model file not found at {model_path!r}. "
              f"Run with --mode train first.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    init_anomalies_table(conn)

    metric_score = metric_flag = None
    if exporter_port:
        from prometheus_client import start_http_server, Gauge
        metric_score = Gauge("netmon_anomaly_score", "Isolation Forest decision_function score for the latest window (lower = more anomalous)")
        metric_flag = Gauge("netmon_is_anomaly", "1 if the latest window was flagged anomalous, else 0")
        start_http_server(exporter_port)
        print(f"Prometheus metrics exposed at: http://localhost:{exporter_port}/metrics")

    cur = conn.cursor()
    cur.execute("SELECT COALESCE(MAX(window_id), 0) FROM anomalies")
    last_scored = cur.fetchone()[0]
    print(f"Watching for new windows after window_id={last_scored}. "
          f"Polling every {poll_interval:.0f}s. Press Ctrl+C to stop.\n")

    try:
        while True:
            rows = load_window_rows(conn, since_window_id=last_scored)
            if rows:
                X = build_feature_matrix(rows)
                scores, is_anomaly = score(model, X)
                now = time.time()
                for row, s, a in zip(rows, scores, is_anomaly):
                    cur.execute(
                        """INSERT INTO anomalies (window_id, anomaly_score, is_anomaly, computed_at)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(window_id) DO UPDATE SET
                               anomaly_score=excluded.anomaly_score,
                               is_anomaly=excluded.is_anomaly,
                               computed_at=excluded.computed_at""",
                        (row["window_id"], float(s), int(a), now),
                    )
                    flag = "  ANOMALY" if a == 1 else ""
                    print(f"[window {row['window_id']}] score={s:.4f}{flag}")
                    if metric_score is not None:
                        metric_score.set(float(s))
                        metric_flag.set(int(a))
                conn.commit()
                last_scored = rows[-1]["window_id"]
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        conn.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Phase 5 anomaly detection (Isolation Forest)")
    parser.add_argument("--mode", choices=["train", "watch"], required=True)
    parser.add_argument("--db", type=str, default="netmon.db")
    parser.add_argument("--model", type=str, default="model.joblib")
    parser.add_argument("--contamination", type=str, default="auto",
                         help="'auto' or a float like 0.05 (expected anomaly fraction)")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--exporter-port", type=int, default=None,
                         help="If set, expose Prometheus metrics on this port in --mode watch")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    contamination = args.contamination
    if contamination != "auto":
        contamination = float(contamination)

    if args.mode == "train":
        run_train(args.db, args.model, contamination)
    else:
        run_watch(args.db, args.model, args.poll_interval, args.exporter_port)