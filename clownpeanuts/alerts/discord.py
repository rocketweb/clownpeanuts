"""Discord alert adapter."""

from __future__ import annotations

import re
from typing import Any

from clownpeanuts.alerts.webhook import send_webhook


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_discord_text(value: Any) -> str:
    text = _CONTROL_CHARS.sub("", str(value))
    text = text.replace("@everyone", "@\u200beveryone").replace("@here", "@\u200bhere")
    text = text.replace("<@", "<@\u200b").replace("<#", "<#\u200b")
    return text[:2000]


def send_discord(*, endpoint: str, payload: dict[str, Any], timeout_seconds: float = 2.0) -> None:
    title = _sanitize_discord_text(payload.get("title", "ClownPeanuts Alert"))
    severity = _sanitize_discord_text(payload.get("severity", "unknown"))
    summary = _sanitize_discord_text(payload.get("summary", ""))
    message = {
        "content": (
            f"**{title}**\n"
            f"Severity: `{severity}`\n"
            f"{summary}"
        ),
        "embeds": [
            {
                "title": title or "Alert",
                "description": summary,
                "color": 15158332,
            }
        ],
    }
    send_webhook(endpoint=endpoint, payload=message, timeout_seconds=timeout_seconds)
