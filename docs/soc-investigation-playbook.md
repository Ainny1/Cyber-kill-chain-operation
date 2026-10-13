# SOC Investigation Playbook — Kill Chain Signals

## Objective

Investigate an unusual outbound connection alert in an **authorized lab** without assuming malicious intent. This is a reproducible **exercise design**, not a report of a completed investigation.

## Data to collect

- Endpoint: host identifier, process path, parent process, process start time, and signed-binary status (if available).
- Network: destination, port, DNS name, connection frequency, and time window.
- Context: asset owner, expected software, known maintenance activity, and relevant change tickets.
- Security tools: EDR alerts, DNS/proxy/firewall logs, and asset inventory where configured.

## Triage procedure

1. Record the alert's UTC timestamp and originating data source.
2. Confirm the event is present in raw telemetry; note missing fields.
3. Identify the originating process and whether the destination is expected.
4. Compare connection intervals with normal activity; regular timing alone does **not** prove command-and-control.
5. Review related endpoint and identity events in the same time window.
6. Classify as expected, suspicious, or inconclusive, documenting evidence and uncertainty.
7. If suspicious, follow the organization's approved escalation and containment process. Do not perform disruptive actions in production as part of this exercise.

## Safe validation option

Generate benign periodic requests from an owned lab VM to a **local service you control**; do not simulate remote malware or stealth behavior. Record whether your own logging captures the connections, then compare expected and observed events.

## Evidence template

| Field | Finding |
| --- | --- |
| Lab date and scope | Not yet recorded |
| Hypothesis | Repeated outbound connections merit contextual review |
| Telemetry source | Not yet configured / verified |
| Expected events | Not yet recorded |
| Observed events | Not tested |
| False positives | Software update checks, monitoring agents, scheduled jobs |
| Outcome | Not determined |
| Next action | Collect and review authorized lab evidence |

## Limitations

Network indicators are context-dependent. ATT&CK tactic mappings are illustrative and do not prove attribution, intrusion, or impact. Never publish personal data, internal hostnames, credentials, or unredacted logs.
