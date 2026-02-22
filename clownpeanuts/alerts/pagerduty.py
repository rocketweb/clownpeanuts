"""PagerDuty Events API delivery adapter."""

from __future__ import annotations

import json
from typing import Any
from urllib import request


def send_pagerduty(
    *,
    endpoint: str,
    payload: dict[str, Any],
    token: str,
    metadata: dict[str, str] | None = None,
) -> None:
    metadata = metadata or {}
    routing_key = metadata.get("routing_key", "") or token
    if not routing_key:
        raise RuntimeError("pagerduty destination requires routing key (token or metadata.routing_key)")

    severity = str(payload.get("severity", "info")).lower()
    mapped = "warning"
    if severity == "critical":
        mapped = "critical"
    elif severity == "high":
        mapped = "error"
    elif severity == "medium":
        mapped = "warning"
    elif severity == "low":
        mapped = "info"

    body = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"clownpeanuts-{payload.get('title', 'alert')}",
        "payload": {
            "summary": str(payload.get("summary", "clownpeanuts alert"))[:1024],
            "source": metadata.get("source", "clownpeanuts"),
            "severity": mapped,
            "timestamp": payload.get("timestamp"),
            "component": payload.get("service"),
            "group": "honeypot",
            "class": payload.get("action"),
            "custom_details": payload.get("payload", {}),
        },
    }

    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    target = endpoint.strip() or "https://events.pagerduty.com/v2/enqueue"
    req = request.Request(
        target,
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=4.0) as response:
        status = int(getattr(response, "status", 0) or 0)
        if status and status >= 300:
            raise RuntimeError(f"pagerduty returned HTTP {status}")
