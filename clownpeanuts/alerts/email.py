"""SMTP email alert delivery adapter."""

from __future__ import annotations

from email.message import EmailMessage
import smtplib
from typing import Any
from urllib.parse import urlparse


def send_email(
    *,
    endpoint: str,
    payload: dict[str, Any],
    metadata: dict[str, str] | None = None,
) -> None:
    metadata = metadata or {}
    parsed = urlparse(endpoint if "://" in endpoint else f"smtp://{endpoint}")
    if parsed.scheme not in {"smtp", "smtps"}:
        raise RuntimeError("email endpoint must use smtp:// or smtps://")
    host = parsed.hostname or ""
    if not host:
        raise RuntimeError("email endpoint missing SMTP host")
    port = int(parsed.port or (465 if parsed.scheme == "smtps" else 25))
    username = parsed.username or metadata.get("username", "")
    password = parsed.password or metadata.get("password", "")
    from_addr = metadata.get("from", "clownpeanuts@localhost")
    to_list = [item.strip() for item in metadata.get("to", "").split(",") if item.strip()]
    if not to_list:
        raise RuntimeError("email metadata requires non-empty 'to' recipients")

    subject_prefix = metadata.get("subject_prefix", "[clownpeanuts]")
    subject = f"{subject_prefix} {payload.get('severity', 'info').upper()} {payload.get('title', 'alert')}".strip()
    body_lines = [
        f"timestamp: {payload.get('timestamp', '')}",
        f"severity: {payload.get('severity', '')}",
        f"service: {payload.get('service', '')}",
        f"action: {payload.get('action', '')}",
        f"summary: {payload.get('summary', '')}",
        "",
        str(payload.get("payload", {})),
    ]

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_addr
    message["To"] = ", ".join(to_list)
    message.set_content("\n".join(body_lines))

    starttls = metadata.get("starttls", "true").lower() in {"1", "true", "yes", "on"}
    if parsed.scheme == "smtps":
        with smtplib.SMTP_SSL(host, port, timeout=4.0) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
        return

    with smtplib.SMTP(host, port, timeout=4.0) as smtp:
        smtp.ehlo()
        if starttls:
            smtp.starttls()
            smtp.ehlo()
        if username:
            smtp.login(username, password)
        smtp.send_message(message)
