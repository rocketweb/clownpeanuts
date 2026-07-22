"""Validation helpers for Redis connection URLs."""

from __future__ import annotations

from urllib.parse import urlparse


def validate_redis_url(redis_url: str, *, field_name: str = "redis_url") -> str:
    """Return a normalized Redis URL or raise for ambiguous/invalid targets."""

    normalized = str(redis_url).strip()
    parsed = urlparse(normalized)
    if parsed.scheme not in {"redis", "rediss"}:
        raise ValueError(f"{field_name} scheme must be redis or rediss")
    if not parsed.hostname:
        raise ValueError(f"{field_name} must include a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} port must be between 1 and 65535") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{field_name} port must be between 1 and 65535")
    return normalized
