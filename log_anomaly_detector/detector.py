import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable


SUSPICIOUS_KEYWORDS = {
    "sudo",
    "failed password",
    "unauthorized",
    "forbidden",
    "privilege escalation",
    "data exfiltration",
    "reverse shell",
    "malware",
    "ransomware",
    "sql injection",
}


COMMON_LOG_RE = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})'
)


@dataclass
class LogEvent:
    timestamp: datetime
    source_ip: str
    actor: str
    event_type: str
    severity: str
    status: int | None
    message: str
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class Baseline:
    event_types: Counter[str]
    ip_counts: Counter[str]
    actor_counts: Counter[str]
    status_counts: Counter[int]
    hour_counts: Counter[int]
    total_events: int


@dataclass
class Anomaly:
    event: LogEvent
    score: float
    reasons: list[str]


def load_events(path: str | Path) -> list[LogEvent]:
    events: list[LogEvent] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            events.append(parse_line(line))
    return events


def parse_line(line: str) -> LogEvent:
    if line.startswith("{"):
        payload = json.loads(line)
        timestamp = _parse_timestamp(payload.get("timestamp"))
        return LogEvent(
            timestamp=timestamp,
            source_ip=payload.get("source_ip", "unknown"),
            actor=payload.get("actor", "unknown"),
            event_type=payload.get("event_type", "unknown"),
            severity=payload.get("severity", "info").lower(),
            status=_safe_int(payload.get("status")),
            message=payload.get("message", ""),
            raw={k: str(v) for k, v in payload.items()},
        )

    match = COMMON_LOG_RE.search(line)
    if match:
        status = _safe_int(match.group("status"))
        method = match.group("method")
        path = match.group("path")
        return LogEvent(
            timestamp=_parse_timestamp(match.group("timestamp")),
            source_ip=match.group("ip"),
            actor="unknown",
            event_type=f"http_{method.lower()}",
            severity=_severity_from_status(status),
            status=status,
            message=f"{method} {path}",
            raw={"raw_line": line},
        )

    raise ValueError(f"Unsupported log format: {line}")


def build_baseline(events: Iterable[LogEvent]) -> Baseline:
    event_types: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    actor_counts: Counter[str] = Counter()
    status_counts: Counter[int] = Counter()
    hour_counts: Counter[int] = Counter()
    total = 0

    for event in events:
        total += 1
        event_types[event.event_type] += 1
        ip_counts[event.source_ip] += 1
        actor_counts[event.actor] += 1
        hour_counts[event.timestamp.hour] += 1
        if event.status is not None:
            status_counts[event.status] += 1

    return Baseline(
        event_types=event_types,
        ip_counts=ip_counts,
        actor_counts=actor_counts,
        status_counts=status_counts,
        hour_counts=hour_counts,
        total_events=total,
    )


def detect_anomalies(current_events: Iterable[LogEvent], baseline: Baseline) -> list[Anomaly]:
    events = list(current_events)
    ip_burst = Counter(event.source_ip for event in events)
    actor_burst = Counter(event.actor for event in events)
    anomalies: list[Anomaly] = []

    for event in events:
        score = 0.0
        reasons: list[str] = []

        if baseline.event_types[event.event_type] == 0:
            score += 4.0
            reasons.append("new event type")

        if event.status is not None and baseline.status_counts[event.status] == 0 and event.status >= 400:
            score += 3.0
            reasons.append(f"unseen error status {event.status}")

        if baseline.hour_counts[event.timestamp.hour] == 0:
            score += 2.5
            reasons.append("activity at an unseen hour")

        if _is_burst(
            observed=ip_burst[event.source_ip],
            historical=baseline.ip_counts[event.source_ip],
            baseline_total=baseline.total_events,
            current_total=len(events),
        ):
            score += 2.5
            reasons.append(f"source IP spike from {event.source_ip}")

        if event.actor != "unknown" and _is_burst(
            observed=actor_burst[event.actor],
            historical=baseline.actor_counts[event.actor],
            baseline_total=baseline.total_events,
            current_total=len(events),
        ):
            score += 2.0
            reasons.append(f"actor spike for {event.actor}")

        if event.severity in {"critical", "high"}:
            score += 2.0
            reasons.append(f"high severity {event.severity}")

        matched_keywords = _matched_keywords(event.message)
        if matched_keywords:
            score += 1.5 + 0.5 * len(matched_keywords)
            reasons.append("suspicious terms: " + ", ".join(sorted(matched_keywords)))

        if score >= 3.0:
            anomalies.append(Anomaly(event=event, score=round(score, 2), reasons=reasons))

    return sorted(anomalies, key=lambda item: item.score, reverse=True)


def format_report(anomalies: Iterable[Anomaly]) -> str:
    anomalies = list(anomalies)
    if not anomalies:
        return "No anomalies detected."

    lines = [f"Detected {len(anomalies)} anomalies:"]
    for index, anomaly in enumerate(anomalies, start=1):
        event = anomaly.event
        lines.append(
            f"{index}. score={anomaly.score:.2f} time={event.timestamp.isoformat()} "
            f"ip={event.source_ip} actor={event.actor} type={event.event_type} "
            f"status={event.status if event.status is not None else '-'}"
        )
        lines.append(f"   reasons: {', '.join(anomaly.reasons)}")
        lines.append(f"   message: {event.message}")
    return "\n".join(lines)


def summarize_by_reason(anomalies: Iterable[Anomaly]) -> dict[str, int]:
    summary: dict[str, int] = defaultdict(int)
    for anomaly in anomalies:
        for reason in anomaly.reasons:
            summary[reason] += 1
    return dict(sorted(summary.items(), key=lambda item: (-item[1], item[0])))


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        raise ValueError("Missing timestamp")

    if "/" in value and ":" in value and " " not in value[:3]:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")

    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _safe_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _severity_from_status(status: int | None) -> str:
    if status is None:
        return "info"
    if status >= 500:
        return "high"
    if status >= 400:
        return "medium"
    return "info"


def _matched_keywords(message: str) -> set[str]:
    lowered = message.lower()
    return {keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered}


def _is_burst(observed: int, historical: int, baseline_total: int, current_total: int) -> bool:
    if observed < 3 or current_total == 0:
        return False

    historical_rate = (historical + 1) / max(baseline_total, 1)
    expected = historical_rate * current_total
    threshold = expected + max(2.0, 2.0 * math.sqrt(max(expected, 1.0)))
    return observed > threshold
