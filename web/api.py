"""
Phase 7 - FastAPI backend
============================

Thin HTTP layer over queries.py. Every route here does the minimum
possible: open a connection, call one already-tested function from
queries.py, return its result as JSON. All the actual logic (and all
the actual testing) lives in queries.py - see that file's docstring
for why it's structured this way.

Requirements
------------
    pip install fastapi uvicorn

Usage
-----
    python api.py --db netmon.db --port 8080

Then, for example:
    http://127.0.0.1:8080/api/snapshot
    http://127.0.0.1:8080/docs   (FastAPI's automatic interactive API docs)

Note: run this as "python api.py ...", not "uvicorn api:app ..." - the
--db argument is only parsed in the __main__ block below, which the
plain "uvicorn api:app" invocation skips entirely (uvicorn imports the
module rather than executing it as a script), silently leaving DB_PATH
at its default instead of the path you intended.

CORS is enabled for local development so a frontend served from a
different port (e.g. a Vite dev server, or the static console.html
opened directly as a file) can fetch from this API without being
blocked by the browser's same-origin policy.
"""

import argparse
import sqlite3
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

import queries as q

DB_PATH = "netmon.db"  # overridden by --db at startup, see bottom of file

app = FastAPI(title="Netmon API", description="Read-only API over the network monitoring project's data")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local dev/demo tool - not intended for production/public exposure as-is
    allow_methods=["GET"],
    allow_headers=["*"],
)


def get_connection() -> sqlite3.Connection:
    if not Path(DB_PATH).exists():
        raise HTTPException(status_code=503, detail=f"Database not found at {DB_PATH!r}. Is the capture engine running?")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA query_only = TRUE")  # this API is read-only by design; refuse to ever write
    return conn


@app.get("/api/snapshot")
def snapshot():
    conn = get_connection()
    try:
        return q.get_snapshot(conn)
    finally:
        conn.close()


@app.get("/api/entropy-history")
def entropy_history(limit: int = 40):
    conn = get_connection()
    try:
        return q.get_entropy_history(conn, limit=limit)
    finally:
        conn.close()


@app.get("/api/top-talkers")
def top_talkers(minutes: int = 10, limit: int = 5):
    conn = get_connection()
    try:
        return q.get_top_talkers(conn, minutes=minutes, limit=limit)
    finally:
        conn.close()


@app.get("/api/anomalies")
def anomalies(limit: int = 10):
    conn = get_connection()
    try:
        return q.get_anomalies(conn, limit=limit)
    finally:
        conn.close()


@app.get("/api/probes")
def probes():
    conn = get_connection()
    try:
        return q.get_probe_status(conn)
    finally:
        conn.close()


@app.get("/api/flows")
def flows(minutes: int = 10, limit: int = 100):
    conn = get_connection()
    try:
        return q.get_flows(conn, minutes=minutes, limit=limit)
    finally:
        conn.close()


@app.get("/api/reports")
def reports():
    """Lists generated report files (written by report_generator.py).
    Returns an empty list gracefully if the reports/ folder doesn't
    exist yet, rather than erroring, so the frontend's Reports panel
    doesn't break before report_generator.py has run for the first time."""
    reports_dir = Path("reports")
    if not reports_dir.exists():
        return []
    files = sorted(reports_dir.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [
        {"name": f.name, "size_kb": round(f.stat().st_size / 1024, 1), "modified": f.stat().st_mtime}
        for f in files
    ]


@app.get("/api/reports/{filename}")
def download_report(filename: str):
    """Serves an individual report file's actual HTML content, so the
    frontend's download/view links have something real to point at."""
    # Reject any path traversal attempt outright - filename must be a
    # bare filename, not something like '../../etc/passwd'.
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    filepath = Path("reports") / filename
    if not filepath.exists() or filepath.suffix != ".html":
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(filepath, media_type="text/html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Netmon FastAPI backend")
    parser.add_argument("--db", type=str, default="netmon.db")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    DB_PATH = args.db

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)