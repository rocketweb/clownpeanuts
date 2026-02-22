"""Simple attacker classification heuristics."""

from __future__ import annotations

from typing import Any


def classify_session(session: dict[str, Any]) -> dict[str, Any]:
    events = session.get("events", [])
    if not isinstance(events, list):
        events = []
    event_count = int(session.get("event_count", len(events)) or 0)
    auth_attempts = sum(1 for item in events if isinstance(item, dict) and item.get("action") == "auth_attempt")
    commands = sum(1 for item in events if isinstance(item, dict) and item.get("action") == "command")

    if event_count <= 3 and commands == 0:
        level = 1
        label = "Automated Scanner"
    elif event_count <= 12:
        level = 2
        label = "Script Kiddie"
    elif event_count <= 30:
        level = 3
        label = "Intermediate Attacker"
    else:
        level = 4
        label = "Advanced/APT"

    confidence = min(0.95, 0.4 + (event_count / 100.0) + (commands / 50.0))
    return {
        "level": level,
        "label": label,
        "confidence": round(confidence, 3),
        "signals": {
            "event_count": event_count,
            "auth_attempts": auth_attempts,
            "commands": commands,
        },
    }
