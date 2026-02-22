"""Credential reuse summarization helpers."""

from __future__ import annotations

import hashlib
from typing import Any


_USER_KEYS = ("username", "user", "login", "account", "email")
_PASSWORD_KEYS = ("password", "pass", "passwd", "pwd")


def summarize_credential_reuse(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    observed: dict[str, dict[str, Any]] = {}
    sessions_seen: set[str] = set()

    for session in sessions:
        session_id = str(session.get("session_id", "")).strip()
        events = session.get("events", [])
        if not session_id or not isinstance(events, list):
            continue
        sessions_seen.add(session_id)
        for event in events:
            if not isinstance(event, dict):
                continue
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                continue
            username = _first_non_empty(payload, _USER_KEYS)
            password = _first_non_empty(payload, _PASSWORD_KEYS)
            if not username or not password:
                continue

            credential_id = hashlib.sha1(
                f"{username.lower()}:{password}".encode("utf-8"),
                usedforsecurity=False,
            ).hexdigest()
            record = observed.setdefault(
                credential_id,
                {
                    "credential_id": credential_id,
                    "username": username,
                    "password_mask": _mask_secret(password),
                    "sessions": set(),
                    "events": 0,
                },
            )
            record["events"] = int(record["events"]) + 1
            record_sessions = record["sessions"]
            if isinstance(record_sessions, set):
                record_sessions.add(session_id)

    patterns: list[dict[str, Any]] = []
    impacted_sessions: set[str] = set()
    for record in observed.values():
        record_sessions = record.get("sessions")
        if not isinstance(record_sessions, set):
            continue
        if len(record_sessions) < 2:
            continue
        impacted_sessions.update(record_sessions)
        patterns.append(
            {
                "credential_id": str(record.get("credential_id", "")),
                "username": str(record.get("username", "")),
                "password_mask": str(record.get("password_mask", "")),
                "sessions": sorted(record_sessions),
                "session_count": len(record_sessions),
                "events": int(record.get("events", 0) or 0),
            }
        )

    patterns.sort(
        key=lambda item: (
            -int(item.get("session_count", 0)),
            -int(item.get("events", 0)),
            str(item.get("username", "")),
        )
    )
    return {
        "patterns": patterns,
        "total_reused_credentials": len(patterns),
        "impacted_sessions": len(impacted_sessions),
        "observed_sessions": len(sessions_seen),
    }


def _first_non_empty(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _mask_secret(secret: str) -> str:
    if len(secret) <= 2:
        return "*" * len(secret)
    return f"{secret[0]}{'*' * (len(secret) - 2)}{secret[-1]}"
