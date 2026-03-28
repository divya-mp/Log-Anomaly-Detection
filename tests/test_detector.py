import unittest

from log_anomaly_detector.detector import build_baseline, detect_anomalies, load_events, parse_line, summarize_by_reason


class DetectorTests(unittest.TestCase):
    def test_parse_json_line(self) -> None:
        event = parse_line(
            '{"timestamp":"2026-03-24T09:00:00+00:00","source_ip":"1.2.3.4","actor":"alice","event_type":"login","severity":"info","status":200,"message":"ok"}'
        )
        self.assertEqual(event.source_ip, "1.2.3.4")
        self.assertEqual(event.status, 200)
        self.assertEqual(event.timestamp.hour, 9)

    def test_parse_common_log_line(self) -> None:
        event = parse_line('192.168.0.5 - - [24/Mar/2026:09:00:00 +0000] "POST /admin HTTP/1.1" 403 123')
        self.assertEqual(event.event_type, "http_post")
        self.assertEqual(event.status, 403)
        self.assertEqual(event.severity, "medium")

    def test_detect_anomalies(self) -> None:
        baseline = build_baseline(load_events("sample_data/baseline.jsonl"))
        current = load_events("sample_data/current.jsonl")
        anomalies = detect_anomalies(current, baseline)
        self.assertGreaterEqual(len(anomalies), 3)
        self.assertEqual(anomalies[0].event.event_type, "privilege_change")
        summary = summarize_by_reason(anomalies)
        self.assertIn("new event type", summary)


if __name__ == "__main__":
    unittest.main()
