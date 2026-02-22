"""Event trip tracking for optional AD deception workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class ADEventDefinition:
    event_id: str
    event_type: str
    description: str


@dataclass(slots=True)
class ADTripRecord:
    trip_id: str
    object_id: str
    event_type: str
    source_host: str
    source_user: str
    created_at: str
    metadata: dict[str, Any]


class ADEventMonitor:
    """Trip history store with optional SQLite-backed persistence."""

    _EVENT_DEFINITIONS: tuple[ADEventDefinition, ...] = (
        ADEventDefinition(
            event_id="4624",
            event_type="logon_attempt",
            description="Interactive or network logon using seeded credentials.",
        ),
        ADEventDefinition(
            event_id="4768",
            event_type="kerberos_tgt_request",
            description="Kerberos TGT request for a seeded account.",
        ),
        ADEventDefinition(
            event_id="4769",
            event_type="kerberos_service_ticket",
            description="Kerberos service ticket request for a seeded SPN/account.",
        ),
        ADEventDefinition(
            event_id="4662",
            event_type="directory_object_read",
            description="Directory object read or enumeration on seeded objects.",
        ),
        ADEventDefinition(
            event_id="5136",
            event_type="directory_object_modified",
            description="Directory object modification attempt on seeded objects.",
        ),
        ADEventDefinition(
            event_id="4738",
            event_type="account_changed",
            description="Account change event touching a seeded user.",
        ),
    )
    _EVENT_TYPE_BY_ID: dict[str, str] = {item.event_id: item.event_type for item in _EVENT_DEFINITIONS}

    def __init__(self, *, store_path: str = "") -> None:
        self._lock = threading.RLock()
        self._trips: list[ADTripRecord] = []
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
                CREATE TABLE IF NOT EXISTS adlibs_trips (
                    trip_id TEXT PRIMARY KEY,
                    object_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    source_user TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS adlibs_trips_created_idx
                    ON adlibs_trips(created_at DESC);
                """
            )

    def record_trip(
        self,
        *,
        object_id: str,
        event_type: str,
        source_host: str = "",
        source_user: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ADTripRecord:
        record = ADTripRecord(
            trip_id=uuid4().hex[:12],
            object_id=object_id.strip(),
            event_type=event_type.strip() or "unknown",
            source_host=source_host.strip(),
            source_user=source_user.strip(),
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            metadata=dict(metadata or {}),
        )
        with self._lock:
            if self._conn is None:
                self._trips.append(record)
                return record
            self._conn.execute(
                """
                INSERT INTO adlibs_trips (
                    trip_id,
                    object_id,
                    event_type,
                    source_host,
                    source_user,
                    created_at,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.trip_id,
                    record.object_id,
                    record.event_type,
                    record.source_host,
                    record.source_user,
                    record.created_at,
                    json.dumps(record.metadata, separators=(",", ":"), ensure_ascii=True),
                ),
            )
            self._conn.commit()
            return record

    def list_trips(self, *, limit: int = 200) -> list[dict[str, Any]]:
        safe_limit = max(1, min(2000, int(limit)))
        with self._lock:
            if self._conn is None:
                rows = list(reversed(self._trips[-safe_limit:]))
                return [self._serialize(row) for row in rows]
            query_rows = self._conn.execute(
                """
                SELECT trip_id, object_id, event_type, source_host, source_user, created_at, metadata_json
                FROM adlibs_trips
                ORDER BY created_at DESC, trip_id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
            return [self._serialize(self._row_to_record(row)) for row in query_rows]

    def _row_to_record(self, row: sqlite3.Row) -> ADTripRecord:
        raw_metadata = str(row["metadata_json"])
        try:
            parsed = json.loads(raw_metadata)
        except json.JSONDecodeError:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        metadata = {str(key): value for key, value in parsed.items()}
        return ADTripRecord(
            trip_id=str(row["trip_id"]),
            object_id=str(row["object_id"]),
            event_type=str(row["event_type"]),
            source_host=str(row["source_host"]),
            source_user=str(row["source_user"]),
            created_at=str(row["created_at"]),
            metadata=metadata,
        )

    @staticmethod
    def _serialize(record: ADTripRecord) -> dict[str, Any]:
        return {
            "trip_id": record.trip_id,
            "object_id": record.object_id,
            "event_type": record.event_type,
            "source_host": record.source_host,
            "source_user": record.source_user,
            "created_at": record.created_at,
            "metadata": dict(record.metadata),
        }

    @classmethod
    def normalize_event_id(cls, value: str | int | None) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        digits = "".join(ch for ch in text if ch.isdigit())
        if digits:
            return digits
        return text

    @classmethod
    def classify_event_type(cls, event_id: str | int | None) -> str:
        normalized = cls.normalize_event_id(event_id)
        if not normalized:
            return "unknown_event"
        return cls._EVENT_TYPE_BY_ID.get(normalized, f"event_{normalized}")

    @classmethod
    def event_catalog(cls) -> list[dict[str, str]]:
        return [
            {
                "event_id": item.event_id,
                "event_type": item.event_type,
                "description": item.description,
            }
            for item in cls._EVENT_DEFINITIONS
        ]
