"""Deterministic object seeding scaffolding for optional AD deception."""

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
class ADObjectRecord:
    object_id: str
    object_type: str
    name: str
    distinguished_name: str
    attributes: dict[str, Any]
    created_at: str


class ADObjectSeeder:
    """Object planner/seeder with optional SQLite-backed persistence."""

    def __init__(self, *, target_ou: str, store_path: str = "") -> None:
        self._target_ou = target_ou.strip()
        self._lock = threading.RLock()
        self._records: dict[str, ADObjectRecord] = {}
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
                CREATE TABLE IF NOT EXISTS adlibs_objects (
                    object_id TEXT PRIMARY KEY,
                    object_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    distinguished_name TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS adlibs_objects_created_idx
                    ON adlibs_objects(created_at DESC);
                """
            )

    def validate_plan(
        self,
        *,
        fake_users: int,
        fake_service_accounts: int,
        fake_groups: int,
    ) -> dict[str, Any]:
        normalized_users = max(0, int(fake_users))
        normalized_service_accounts = max(0, int(fake_service_accounts))
        normalized_groups = max(0, int(fake_groups))
        issues: list[str] = []
        for field_name, value in (
            ("fake_users", fake_users),
            ("fake_service_accounts", fake_service_accounts),
            ("fake_groups", fake_groups),
        ):
            if int(value) < 0:
                issues.append(f"{field_name} must be >= 0")
        if not self._target_ou:
            issues.append("target_ou is required")
        return {
            "ready": not issues,
            "issues": issues,
            "requested": {
                "fake_users": normalized_users,
                "fake_service_accounts": normalized_service_accounts,
                "fake_groups": normalized_groups,
            },
            "projected_total": normalized_users + normalized_service_accounts + normalized_groups,
            "preview": {
                "users": self._preview_objects("user", "usr-decoy", normalized_users),
                "service_accounts": self._preview_objects(
                    "service_account",
                    "svc-decoy",
                    normalized_service_accounts,
                ),
                "groups": self._preview_objects("group", "grp-decoy", normalized_groups),
            },
            "target_ou": self._target_ou,
        }

    def seed(
        self,
        *,
        fake_users: int,
        fake_service_accounts: int,
        fake_groups: int,
    ) -> dict[str, Any]:
        plan = self.validate_plan(
            fake_users=fake_users,
            fake_service_accounts=fake_service_accounts,
            fake_groups=fake_groups,
        )
        if not bool(plan["ready"]):
            return {
                "status": "rejected",
                "issues": list(plan["issues"]),
                "objects": [],
                "count": 0,
            }

        created: list[ADObjectRecord] = []
        created.extend(self._create_objects("user", "usr-decoy", fake_users))
        created.extend(self._create_objects("service_account", "svc-decoy", fake_service_accounts))
        created.extend(self._create_objects("group", "grp-decoy", fake_groups))
        with self._lock:
            for record in created:
                self._save_record_locked(record)
        return {
            "status": "seeded",
            "count": len(created),
            "objects": [self._serialize(record) for record in created],
        }

    def list_objects(self, *, limit: int = 200) -> list[dict[str, Any]]:
        safe_limit = max(1, min(2000, int(limit)))
        with self._lock:
            if self._conn is None:
                rows = list(self._records.values())
                rows.sort(key=lambda item: item.created_at, reverse=True)
                return [self._serialize(row) for row in rows[:safe_limit]]
            query_rows = self._conn.execute(
                """
                SELECT object_id, object_type, name, distinguished_name, attributes_json, created_at
                FROM adlibs_objects
                ORDER BY created_at DESC, object_id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
            return [self._serialize(self._row_to_record(row)) for row in query_rows]

    def delete_object(self, object_id: str) -> bool:
        normalized = object_id.strip()
        if not normalized:
            return False
        with self._lock:
            if self._conn is None:
                return self._records.pop(normalized, None) is not None
            cursor = self._conn.execute(
                "DELETE FROM adlibs_objects WHERE object_id = ?",
                (normalized,),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def _create_objects(self, object_type: str, prefix: str, count: int) -> list[ADObjectRecord]:
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        records: list[ADObjectRecord] = []
        for index in range(1, int(count) + 1):
            name = f"{prefix}-{index:02d}"
            object_id = uuid4().hex[:14]
            records.append(
                ADObjectRecord(
                    object_id=object_id,
                    object_type=object_type,
                    name=name,
                    distinguished_name=f"CN={name},{self._target_ou}",
                    attributes={"seed_index": index, "managed_by": "adlibs"},
                    created_at=created_at,
                )
            )
        return records

    def _save_record_locked(self, record: ADObjectRecord) -> None:
        if self._conn is None:
            self._records[record.object_id] = record
            return
        self._conn.execute(
            """
            INSERT OR REPLACE INTO adlibs_objects (
                object_id,
                object_type,
                name,
                distinguished_name,
                attributes_json,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record.object_id,
                record.object_type,
                record.name,
                record.distinguished_name,
                json.dumps(record.attributes, separators=(",", ":"), ensure_ascii=True),
                record.created_at,
            ),
        )
        self._conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> ADObjectRecord:
        raw_attributes = str(row["attributes_json"])
        try:
            parsed = json.loads(raw_attributes)
        except json.JSONDecodeError:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        attributes = {str(key): value for key, value in parsed.items()}
        return ADObjectRecord(
            object_id=str(row["object_id"]),
            object_type=str(row["object_type"]),
            name=str(row["name"]),
            distinguished_name=str(row["distinguished_name"]),
            attributes=attributes,
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _serialize(record: ADObjectRecord) -> dict[str, Any]:
        return {
            "object_id": record.object_id,
            "object_type": record.object_type,
            "name": record.name,
            "distinguished_name": record.distinguished_name,
            "attributes": dict(record.attributes),
            "created_at": record.created_at,
        }

    def _preview_objects(self, object_type: str, prefix: str, count: int, *, max_items: int = 5) -> dict[str, Any]:
        safe_count = max(0, int(count))
        limit = max(1, int(max_items))
        rows: list[dict[str, Any]] = []
        for index in range(1, min(safe_count, limit) + 1):
            name = f"{prefix}-{index:02d}"
            rows.append(
                {
                    "object_type": object_type,
                    "name": name,
                    "distinguished_name": f"CN={name},{self._target_ou}",
                }
            )
        return {
            "count": safe_count,
            "preview_count": len(rows),
            "truncated": safe_count > len(rows),
            "rows": rows,
        }
