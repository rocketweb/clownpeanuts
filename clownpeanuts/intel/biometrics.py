"""Behavioral biometrics and interaction style heuristics."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import math
from statistics import pstdev
from typing import Any


def summarize_session_biometrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {
            "automation_score": 0.0,
            "interaction_style": "unknown",
            "service_diversity": 0,
            "action_diversity": 0,
            "command_reuse_ratio": 0.0,
            "command_entropy_avg": 0.0,
            "interval_cv": 0.0,
        }

    services = [str(item.get("service", "")).strip() for item in events if str(item.get("service", "")).strip()]
    actions = [str(item.get("action", "")).strip() for item in events if str(item.get("action", "")).strip()]
    commands = [command for command in (_extract_command_text(item) for item in events) if command]
    unique_commands = len(set(commands))
    command_reuse_ratio = 0.0
    if commands:
        command_reuse_ratio = round(1.0 - (unique_commands / max(1, len(commands))), 3)

    entropy_values = [_shannon_entropy(command) for command in commands if command]
    command_entropy_avg = round(sum(entropy_values) / len(entropy_values), 3) if entropy_values else 0.0

    timestamps = [_parse_timestamp(str(item.get("timestamp", ""))) for item in events]
    parsed = sorted(item for item in timestamps if item is not None)
    intervals: list[float] = []
    for idx in range(1, len(parsed)):
        delta = float((parsed[idx] - parsed[idx - 1]).total_seconds())
        if delta >= 0:
            intervals.append(delta)
    interval_cv = 0.0
    if intervals:
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval > 0:
            interval_cv = round(float(pstdev(intervals)) / mean_interval, 3)

    event_rate = _events_per_minute(parsed, len(events))
    score = _automation_score(
        event_rate=event_rate,
        reuse_ratio=command_reuse_ratio,
        interval_cv=interval_cv,
        entropy_avg=command_entropy_avg,
        command_count=len(commands),
    )
    if score >= 70.0:
        style = "automated"
    elif score >= 40.0:
        style = "hybrid"
    else:
        style = "hands-on"

    return {
        "automation_score": round(score, 3),
        "interaction_style": style,
        "service_diversity": len(set(services)),
        "action_diversity": len(set(actions)),
        "command_reuse_ratio": command_reuse_ratio,
        "command_entropy_avg": command_entropy_avg,
        "interval_cv": interval_cv,
    }


def summarize_biometrics(items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        return {
            "average_automation_score": 0.0,
            "styles": [],
            "automated_sessions": 0,
        }
    counter: Counter[str] = Counter()
    total_score = 0.0
    automated_sessions = 0
    for item in items:
        style = str(item.get("interaction_style", "unknown")).strip() or "unknown"
        counter[style] += 1
        score = float(item.get("automation_score", 0.0) or 0.0)
        total_score += score
        if style == "automated":
            automated_sessions += 1
    styles = [{"style": style, "count": count} for style, count in counter.most_common()]
    return {
        "average_automation_score": round(total_score / len(items), 3),
        "styles": styles,
        "automated_sessions": automated_sessions,
    }


def _extract_command_text(event: dict[str, Any]) -> str:
    payload = event.get("payload", {})
    if not isinstance(payload, dict):
        return ""
    for key in ("command", "query", "request", "path", "message"):
        value = payload.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Counter[str] = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _parse_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _events_per_minute(timestamps: list[datetime], event_count: int) -> float:
    if not timestamps:
        return 0.0
    duration_seconds = max(0.0, float((timestamps[-1] - timestamps[0]).total_seconds()))
    minutes = max(duration_seconds / 60.0, 1.0 / 60.0)
    return event_count / minutes


def _automation_score(
    *,
    event_rate: float,
    reuse_ratio: float,
    interval_cv: float,
    entropy_avg: float,
    command_count: int,
) -> float:
    score = 0.0
    if event_rate >= 30.0:
        score += 30.0
    elif event_rate >= 10.0:
        score += 20.0
    elif event_rate >= 3.0:
        score += 10.0

    if reuse_ratio >= 0.7:
        score += 25.0
    elif reuse_ratio >= 0.4:
        score += 15.0

    if interval_cv <= 0.25:
        score += 25.0
    elif interval_cv <= 0.6:
        score += 10.0

    if command_count >= 3 and entropy_avg <= 2.5:
        score += 20.0
    elif command_count >= 3 and entropy_avg <= 3.5:
        score += 10.0
    return min(100.0, score)
