"""Slack alert adapter."""

from __future__ import annotations

import re
from typing import Any

from clownpeanuts.alerts.webhook import send_webhook


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_slack_text(value: Any) -> str:
    text = _CONTROL_CHARS.sub("", str(value))
    text = text.replace("@everyone", "@\u200beveryone").replace("@here", "@\u200bhere").replace(
        "@channel", "@\u200bchannel"
    )
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text[:3000]


def send_slack(*, endpoint: str, payload: dict[str, Any], timeout_seconds: float = 2.0) -> None:
    title = _sanitize_slack_text(payload.get("title", "ClownPeanuts Alert"))
    severity = _sanitize_slack_text(payload.get("severity", "unknown"))
    summary = _sanitize_slack_text(payload.get("summary", ""))
    message = {
        "text": title,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{title or 'Alert'}*\n"
                        f"Severity: `{severity}`\n"
                        f"{summary}"
                    ),
                },
            }
        ],
        "metadata": {"event_type": "clownpeanuts_alert", "event_payload": payload},
    }
    send_webhook(endpoint=endpoint, payload=message, timeout_seconds=timeout_seconds)
