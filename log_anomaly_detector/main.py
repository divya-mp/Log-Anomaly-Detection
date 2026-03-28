import argparse
import json

from .detector import build_baseline, detect_anomalies, format_report, load_events, summarize_by_reason


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect anomalies in operational and security logs.")
    parser.add_argument("--baseline", required=True, help="Path to baseline historical log file")
    parser.add_argument("--input", required=True, help="Path to the current log file to analyze")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args()

    baseline_events = load_events(args.baseline)
    current_events = load_events(args.input)
    baseline = build_baseline(baseline_events)
    anomalies = detect_anomalies(current_events, baseline)

    if args.json:
        payload = {
            "anomaly_count": len(anomalies),
            "summary": summarize_by_reason(anomalies),
            "anomalies": [
                {
                    "score": anomaly.score,
                    "timestamp": anomaly.event.timestamp.isoformat(),
                    "source_ip": anomaly.event.source_ip,
                    "actor": anomaly.event.actor,
                    "event_type": anomaly.event.event_type,
                    "severity": anomaly.event.severity,
                    "status": anomaly.event.status,
                    "message": anomaly.event.message,
                    "reasons": anomaly.reasons,
                }
                for anomaly in anomalies
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    print((anomalies))


if __name__ == "__main__":
    main()
