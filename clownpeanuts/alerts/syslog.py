"""Syslog alert adapter (UDP)."""

from __future__ import annotations

import re
import socket
from typing import Any


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_syslog_text(value: Any) -> str:
    return _CONTROL_CHARS.sub("", str(value))[:1024]


def send_syslog(*, endpoint: str, payload: dict[str, Any], facility: int = 16, severity: int = 4) -> None:
    host, _, port_raw = endpoint.rpartition(":")
    if not host or not port_raw:
        raise ValueError("syslog endpoint must be host:port")
    pri = facility * 8 + severity
    service = _sanitize_syslog_text(payload.get("service", "core"))
    title = _sanitize_syslog_text(payload.get("title", "Alert"))
    level = _sanitize_syslog_text(payload.get("severity", "unknown"))
    summary = _sanitize_syslog_text(payload.get("summary", ""))
    message = (
        f"<{pri}>clownpeanuts[{service}]: "
        f"{title} severity={level} "
        f"summary={summary}"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode("utf-8", errors="replace"), (host, int(port_raw)))
    finally:
        sock.close()
