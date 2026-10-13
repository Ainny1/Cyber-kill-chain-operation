#!/usr/bin/env python3
"""Run a safe loopback HTTP telemetry lab and write observed evidence.

Only binds to 127.0.0.1; no external targets or dependencies.
"""
import argparse
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_lab(output_dir, count=5, interval=0.25):
    if count < 1 or count > 100 or interval < 0:
        raise ValueError("count must be 1..100 and interval nonnegative")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    events = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status = 200 if self.path == "/health" else 404
            with lock:
                events.append({"timestamp_utc": utc_now(), "source": "127.0.0.1",
                               "path": self.path, "status": status})
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"ok" if status == 200 else b"not found")

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = utc_now()
    responses = []
    try:
        for i in range(count):
            with urlopen(f"http://127.0.0.1:{server.server_port}/health", timeout=3) as response:
                response.read()
                responses.append(response.status)
            if i + 1 < count:
                time.sleep(interval)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    ended = utc_now()
    log_path = output_dir / "events.jsonl"
    log_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    successful = sum(e["status"] == 200 for e in events)
    report = f"""# Observed Local Telemetry Lab Results

| Field | Observed finding |
| --- | --- |
| Lab date (UTC) | {started} to {ended} |
| Authorized scope | Loopback only (127.0.0.1), ephemeral port |
| Hypothesis | Repeated benign HTTP requests should appear in server access telemetry |
| Telemetry source | Python local HTTP server request handler |
| Expected events | {count} HTTP GET requests to /health |
| Observed events | {len(events)} server log entries, {successful} HTTP 200 responses |
| Client responses | {len(responses)} successful HTTP 200 responses |
| Outcome | {"PASS: expected requests observed" if len(events) == count and successful == count and len(responses) == count else "REVIEW: counts differ"} |
| Limitations | Loopback HTTP telemetry only; no EDR, SIEM, C2 detection, or production alerts tested |

The events are **genuine observations from this script's local execution**, not simulated SOC alerts.
The report is generated at runtime and is not evidence of any earlier run.
"""
    report_path = output_dir / "evidence.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path, log_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="lab-output")
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--interval", type=float, default=0.25)
    args = parser.parse_args()
    report, events = run_lab(args.output_dir, args.count, args.interval)
    print(f"Evidence: {report}\nEvents: {events}")
