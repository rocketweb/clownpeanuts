"""Tracking hit registry for optional toxic-data callback workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any
from uuid import uuid4


@dataclass(slots=True)
class TrackingHit:
    hit_id: str
    fingerprint_id: str
    source_ip: str
    user_agent: str
    headers: dict[str, str]
    metadata: dict[str, Any]
    created_at: str


class TrackingRegistry:
    """Tracking-hit registry with optional SQLite-backed persistence."""

    def __init__(self, *, store_path: str = "") -> None:
        self._lock = threading.RLock()
        self._hits: list[TrackingHit] = []
        self._conn: sqlite3.Connection | None = None
        if store_path.strip():
            path = Path(store_path.strip()).expanduser()
            if not path.is_absolute():
                path = (Path.cwd() / path).resolve()
            else:
                path = path.resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path), timeout=5.0, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._ensure_schema_locked()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __del__(self) -> None:  # pragma: no cover - defensive cleanup
        try:
            self.close()
        except Exception:
            return

    def _ensure_schema_locked(self) -> None:
        if self._conn is None:
            return
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pripyatsprings_tracking_hits (
                    hit_id TEXT PRIMARY KEY,
                    fingerprint_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    headers_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS pripyatsprings_tracking_hits_created_idx
                    ON pripyatsprings_tracking_hits(created_at DESC);
                """
            )

    def register_hit(
        self,
        *,
        fingerprint_id: str,
        source_ip: str,
        user_agent: str = "",
        headers: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TrackingHit:
        hit = TrackingHit(
            hit_id=uuid4().hex[:12],
            fingerprint_id=fingerprint_id.strip(),
            source_ip=source_ip.strip(),
            user_agent=user_agent.strip(),
            headers={str(key): str(value) for key, value in dict(headers or {}).items()},
            metadata=dict(metadata or {}),
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        with self._lock:
            if self._conn is None:
                self._hits.append(hit)
                return hit
            self._conn.execute(
                """
                INSERT INTO pripyatsprings_tracking_hits (
                    hit_id,
                    fingerprint_id,
                    source_ip,
                    user_agent,
                    headers_json,
                    metadata_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hit.hit_id,
                    hit.fingerprint_id,
                    hit.source_ip,
                    hit.user_agent,
                    json.dumps(hit.headers, separators=(",", ":"), ensure_ascii=True),
                    json.dumps(hit.metadata, separators=(",", ":"), ensure_ascii=True),
                    hit.created_at,
                ),
            )
            self._conn.commit()
            return hit

    def list_hits(self, *, limit: int = 200) -> list[TrackingHit]:
        safe_limit = max(1, min(2000, int(limit)))
        with self._lock:
            if self._conn is None:
                return list(reversed(self._hits[-safe_limit:]))
            query_rows = self._conn.execute(
                """
                SELECT hit_id, fingerprint_id, source_ip, user_agent, headers_json, metadata_json, created_at
                FROM pripyatsprings_tracking_hits
                ORDER BY created_at DESC, hit_id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
            return [self._row_to_record(row) for row in query_rows]

    def summary(self) -> dict[str, Any]:
        hits = self.list_hits(limit=20000)
        latest_hit_at = hits[0].created_at if hits else None
        return {
            "count": len(hits),
            "latest_hit_at": latest_hit_at,
            "tracked_fingerprints": len({hit.fingerprint_id for hit in hits if hit.fingerprint_id}),
        }

    def _row_to_record(self, row: sqlite3.Row) -> TrackingHit:
        raw_headers = str(row["headers_json"])
        raw_metadata = str(row["metadata_json"])
        try:
            parsed_headers = json.loads(raw_headers)
        except json.JSONDecodeError:
            parsed_headers = {}
        if not isinstance(parsed_headers, dict):
            parsed_headers = {}
        try:
            parsed_metadata = json.loads(raw_metadata)
        except json.JSONDecodeError:
            parsed_metadata = {}
        if not isinstance(parsed_metadata, dict):
            parsed_metadata = {}
        headers = {str(key): str(value) for key, value in parsed_headers.items()}
        metadata = {str(key): value for key, value in parsed_metadata.items()}
        return TrackingHit(
            hit_id=str(row["hit_id"]),
            fingerprint_id=str(row["fingerprint_id"]),
            source_ip=str(row["source_ip"]),
            user_agent=str(row["user_agent"]),
            headers=headers,
            metadata=metadata,
            created_at=str(row["created_at"]),
        )
