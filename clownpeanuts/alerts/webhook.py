"""Webhook alert delivery."""

from __future__ import annotations

import json
from typing import Any
from urllib import request

MAX_PAYLOAD_BYTES = 256 * 1024


def send_webhook(*, endpoint: str, payload: dict[str, Any], timeout_seconds: float = 2.0) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"webhook payload exceeds {MAX_PAYLOAD_BYTES} bytes "
            f"(size={len(body)} bytes)"
        )
    req = request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout_seconds):
        return
