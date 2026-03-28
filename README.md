# Log Anomaly Detection

A small Python implementation for detecting suspicious log activity in DevOps and cybersecurity workflows.

## What it does

- Parses JSON Lines or common plaintext log formats.
- Builds a baseline from historical logs.
- Flags anomalies such as:
  - event types never seen before
  - severe spikes per source IP or actor
  - unusual status codes
  - activity outside typical hours
  - high-risk keywords in messages
- Produces a ranked report in the terminal.

## Quick start

```bash
python3 -m log_anomaly_detector.main \
  --baseline sample_data/baseline.jsonl \
  --input sample_data/current.jsonl
```

## Test

```bash
python3 -m unittest discover -s tests
```
