"""Deterministic engagement map helpers for dashboard visualization."""

from __future__ import annotations

import hashlib
from typing import Any


def build_engagement_map(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    points: list[dict[str, Any]] = []
    for session in sessions:
        source_ip = str(session.get("source_ip", "")).strip()
        if not source_ip:
            continue
        lat, lon = _derive_coordinates(source_ip)
        points.append(
            {
                "session_id": str(session.get("session_id", "")),
                "source_ip": source_ip,
                "lat": lat,
                "lon": lon,
                "event_count": int(session.get("event_count", 0) or 0),
            }
        )
    return {
        "points": points,
        "count": len(points),
        "note": "Coordinates are deterministic pseudo-geo values derived from source IP for safe visualization.",
    }


def _derive_coordinates(source_ip: str) -> tuple[float, float]:
    digest = hashlib.sha1(source_ip.encode("utf-8"), usedforsecurity=False).digest()
    lat_raw = int.from_bytes(digest[0:2], "big")
    lon_raw = int.from_bytes(digest[2:4], "big")
    lat = round((lat_raw / 65535.0) * 140.0 - 70.0, 5)
    lon = round((lon_raw / 65535.0) * 340.0 - 170.0, 5)
    return (lat, lon)
