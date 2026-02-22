"""Fingerprint registry for data export attribution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any


@dataclass(slots=True)
class FingerprintRecord:
    fingerprint_id: str
    session_id: str
    deployment_id: str
    created_at: str
    metadata: dict[str, Any]


class FingerprintRegistry:
    """Fingerprint index with optional SQLite-backed persistence."""

    def __init__(self, *, store_path: str = "") -> None:
        self._lock = threading.RLock()
        self._records: dict[str, FingerprintRecord] = {}
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
                CREATE TABLE IF NOT EXISTS pripyatsprings_fingerprints (
                    fingerprint_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    deployment_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS pripyatsprings_fingerprints_created_idx
                    ON pripyatsprings_fingerprints(created_at DESC);
                """
            )

    @staticmethod
    def build_fingerprint_id(*, payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    def register(
        self,
        *,
        payload: str,
        session_id: str,
        deployment_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> FingerprintRecord:
        fingerprint_id = self.build_fingerprint_id(payload=payload)
        record = FingerprintRecord(
            fingerprint_id=fingerprint_id,
            session_id=session_id.strip(),
            deployment_id=deployment_id.strip(),
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            metadata=dict(metadata or {}),
        )
        with self._lock:
            if self._conn is None:
                self._records[fingerprint_id] = record
                return record
            self._conn.execute(
                """
                INSERT OR REPLACE INTO pripyatsprings_fingerprints (
                    fingerprint_id,
                    session_id,
                    deployment_id,
                    created_at,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.fingerprint_id,
                    record.session_id,
                    record.deployment_id,
                    record.created_at,
                    json.dumps(record.metadata, separators=(",", ":"), ensure_ascii=True),
                ),
            )
            self._conn.commit()
            return record

    def get(self, fingerprint_id: str) -> FingerprintRecord | None:
        normalized = fingerprint_id.strip()
        if not normalized:
            return None
        with self._lock:
            if self._conn is None:
                return self._records.get(normalized)
            row = self._conn.execute(
                """
                SELECT fingerprint_id, session_id, deployment_id, created_at, metadata_json
                FROM pripyatsprings_fingerprints
                WHERE fingerprint_id = ?
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_record(row)

    def list(self, *, limit: int = 200) -> list[FingerprintRecord]:
        safe_limit = max(1, min(2000, int(limit)))
        with self._lock:
            if self._conn is None:
                rows = list(self._records.values())
                rows.sort(key=lambda item: item.created_at, reverse=True)
                return rows[:safe_limit]
            query_rows = self._conn.execute(
                """
                SELECT fingerprint_id, session_id, deployment_id, created_at, metadata_json
                FROM pripyatsprings_fingerprints
                ORDER BY created_at DESC, fingerprint_id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
            return [self._row_to_record(row) for row in query_rows]

    def _row_to_record(self, row: sqlite3.Row) -> FingerprintRecord:
        raw_metadata = str(row["metadata_json"])
        try:
            parsed = json.loads(raw_metadata)
        except json.JSONDecodeError:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        metadata = {str(key): value for key, value in parsed.items()}
        return FingerprintRecord(
            fingerprint_id=str(row["fingerprint_id"]),
            session_id=str(row["session_id"]),
            deployment_id=str(row["deployment_id"]),
            created_at=str(row["created_at"]),
            metadata=metadata,
        )
