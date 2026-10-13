# Case Study: Windows Local HTTP Telemetry Validation

## Summary

A local Windows test of the repository's `scripts/local_telemetry_lab.py` was **completed successfully by the project owner** on October 13, 2026. The owner supplied a screenshot of the generated `evidence.md` report showing **five expected requests, five server-observed events, and five successful HTTP 200 responses**.

**Evidence provenance:** This case study transcribes the user-provided screenshot of a local run. The repository maintainer's machine was used; this PR did **not** independently execute the script or inspect the raw `events.jsonl` file. The screenshot itself is not embedded here to avoid publishing incidental personal details.

## Environment and scope

| Field | Recorded observation |
| --- | --- |
| Operating system | Windows (PowerShell workflow) |
| Python | Python 3.13.4 reported in an earlier Windows terminal screenshot |
| Lab script | `scripts/local_telemetry_lab.py` |
| Test destination | Loopback `127.0.0.1`, temporary local port |
| Date | October 13, 2026 |
| UTC run time | Approximately 14:27:46–14:27:48 UTC, as displayed in the generated report |
| Telemetry source | Python local HTTP server request handler |
| Expected | 5 HTTP GET requests to `/health` |
| Observed | 5 server log entries and 5 HTTP 200 responses |
| Client responses | 5 successful HTTP 200 responses |
| Reported outcome | **PASS: expected requests observed** |

## Reproduce on an authorized computer

From the repository root, with Python 3.9+ installed:

```powershell
py -3 scripts\local_telemetry_lab.py
Get-Content lab-output\evidence.md
Get-Content lab-output\events.jsonl
```

The program listens on localhost only. It creates a timestamped local evidence report and JSONL request log. Generated `lab-output/` files are excluded from version control; **do not upload logs without reviewing and redacting them**.

## What the evidence establishes

The screenshot supports that this specific local run recorded the expected number of benign HTTP requests and responses. This is a **successful telemetry capture and validation exercise**.

## What the evidence does not establish

This was **not** a real cyberattack, network intrusion, Splunk/Sentinel ingestion, endpoint detection, C2 detection, or production alert validation. The local loopback address is a standard address, **not the owner's public IP**. No personal public IP is included in this case study.

## Suggested next validation

On the same authorized machine, inspect the raw JSONL events, note the Python version and UTC execution time, and optionally write a separate case study when a SIEM ingests those events and a query produces independently observed results. Keep any new claims strictly aligned with the evidence.
