"""Profile storage primitives for optional adversary attribution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any
from uuid import uuid4


@dataclass(slots=True)
class AdversaryProfile:
    profile_id: str
    skill: str
    created_at: str
    last_seen_at: str
    sessions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)


class ProfileStore:
    """SQLite-backed profile store with deterministic bounded retention."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        max_profiles: int = 10000,
        max_sessions_per_profile: int = 500,
        max_notes_per_profile: int = 200,
    ) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._db_path: Path | None = None
        self._max_profiles = max(1, int(max_profiles))
        self._max_sessions_per_profile = max(1, int(max_sessions_per_profile))
        self._max_notes_per_profile = max(1, int(max_notes_per_profile))
        if db_path and str(db_path).strip():
            path = Path(str(db_path).strip()).expanduser()
            if not path.is_absolute():
                path = (Path.cwd() / path).resolve()
            else:
                path = path.resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = path
            self._conn = sqlite3.connect(str(path), timeout=5.0, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        else:
            self._conn = sqlite3.connect(":memory:", timeout=5.0, check_same_thread=False)
            self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    @property
    def db_path(self) -> str | None:
        if self._db_path is None:
            return None
        return str(self._db_path)

    @property
    def max_profiles(self) -> int:
        return self._max_profiles

    @property
    def max_sessions_per_profile(self) -> int:
        return self._max_sessions_per_profile

    @property
    def max_notes_per_profile(self) -> int:
        return self._max_notes_per_profile

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._conn.close()
            self._closed = True

    def __del__(self) -> None:  # pragma: no cover - defensive cleanup
        try:
            self.close()
        except Exception:
            return

    def _ensure_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dirtylaundry_profiles (
                    profile_id TEXT PRIMARY KEY,
                    skill TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    metrics_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dirtylaundry_profile_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES dirtylaundry_profiles(profile_id) ON DELETE CASCADE
                );
                CREATE UNIQUE INDEX IF NOT EXISTS dirtylaundry_profile_sessions_unique
                    ON dirtylaundry_profile_sessions(profile_id, session_id);
                CREATE TABLE IF NOT EXISTS dirtylaundry_profile_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES dirtylaundry_profiles(profile_id) ON DELETE CASCADE
                );
                """
            )

    @staticmethod
    def _timestamp_now() -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")

    @staticmethod
    def _normalize_skill(value: str) -> str:
        normalized = value.strip() or "intermediate"
        if len(normalized) > 64:
            return normalized[:64]
        return normalized

    @staticmethod
    def _normalize_metrics(metrics: dict[str, float]) -> dict[str, float]:
        normalized: dict[str, float] = {}
        for key, value in metrics.items():
            metric_name = str(key).strip()
            if not metric_name:
                continue
            try:
                metric_value = float(value)
            except (TypeError, ValueError):
                continue
            normalized[metric_name] = max(0.0, min(1.0, metric_value))
        return normalized

    @staticmethod
    def _timestamp_max(left: str, right: str) -> str:
        return right if right > left else left

    def _build_profile_locked(self, row: sqlite3.Row) -> AdversaryProfile:
        profile_id = str(row["profile_id"])
        sessions_rows = self._conn.execute(
            """
            SELECT session_id
            FROM dirtylaundry_profile_sessions
            WHERE profile_id = ?
            ORDER BY id ASC
            """,
            (profile_id,),
        ).fetchall()
        notes_rows = self._conn.execute(
            """
            SELECT note
            FROM dirtylaundry_profile_notes
            WHERE profile_id = ?
            ORDER BY id ASC
            """,
            (profile_id,),
        ).fetchall()
        raw_metrics = str(row["metrics_json"])
        try:
            parsed_metrics = json.loads(raw_metrics)
        except json.JSONDecodeError:
            parsed_metrics = {}
        if not isinstance(parsed_metrics, dict):
            parsed_metrics = {}
        metrics = self._normalize_metrics(parsed_metrics)
        return AdversaryProfile(
            profile_id=profile_id,
            skill=str(row["skill"]),
            created_at=str(row["created_at"]),
            last_seen_at=str(row["last_seen_at"]),
            sessions=[str(item["session_id"]) for item in sessions_rows],
            notes=[str(item["note"]) for item in notes_rows],
            metrics=metrics,
        )

    def _profile_by_id_locked(self, profile_id: str) -> AdversaryProfile | None:
        row = self._conn.execute(
            """
            SELECT profile_id, skill, created_at, last_seen_at, metrics_json
            FROM dirtylaundry_profiles
            WHERE profile_id = ?
            LIMIT 1
            """,
            (profile_id,),
        ).fetchone()
        if row is None:
            return None
        return self._build_profile_locked(row)

    def _trim_profile_sessions_locked(self, profile_id: str) -> None:
        row = self._conn.execute(
            "SELECT COUNT(1) AS count FROM dirtylaundry_profile_sessions WHERE profile_id = ?",
            (profile_id,),
        ).fetchone()
        total = int(row["count"]) if row is not None else 0
        overflow = total - self._max_sessions_per_profile
        if overflow <= 0:
            return
        self._conn.execute(
            """
            DELETE FROM dirtylaundry_profile_sessions
            WHERE id IN (
                SELECT id
                FROM dirtylaundry_profile_sessions
                WHERE profile_id = ?
                ORDER BY id ASC
                LIMIT ?
            )
            """,
            (profile_id, overflow),
        )

    def _trim_profile_notes_locked(self, profile_id: str) -> None:
        row = self._conn.execute(
            "SELECT COUNT(1) AS count FROM dirtylaundry_profile_notes WHERE profile_id = ?",
            (profile_id,),
        ).fetchone()
        total = int(row["count"]) if row is not None else 0
        overflow = total - self._max_notes_per_profile
        if overflow <= 0:
            return
        self._conn.execute(
            """
            DELETE FROM dirtylaundry_profile_notes
            WHERE id IN (
                SELECT id
                FROM dirtylaundry_profile_notes
                WHERE profile_id = ?
                ORDER BY id ASC
                LIMIT ?
            )
            """,
            (profile_id, overflow),
        )

    def _evict_profiles_locked(self) -> None:
        row = self._conn.execute("SELECT COUNT(1) AS count FROM dirtylaundry_profiles").fetchone()
        total = int(row["count"]) if row is not None else 0
        overflow = total - self._max_profiles
        if overflow <= 0:
            return
        rows = self._conn.execute(
            """
            SELECT profile_id
            FROM dirtylaundry_profiles
            ORDER BY last_seen_at ASC, profile_id ASC
            LIMIT ?
            """,
            (overflow,),
        ).fetchall()
        for row_item in rows:
            self._conn.execute(
                "DELETE FROM dirtylaundry_profiles WHERE profile_id = ?",
                (str(row_item["profile_id"]),),
            )

    def create_profile(
        self,
        *,
        skill: str,
        session_id: str,
        metrics: dict[str, float],
        profile_id: str | None = None,
        created_at: str | None = None,
        last_seen_at: str | None = None,
    ) -> AdversaryProfile:
        normalized_profile_id = (profile_id or "").strip() or uuid4().hex[:14]
        normalized_skill = self._normalize_skill(skill)
        normalized_metrics = self._normalize_metrics(metrics)
        created = (created_at or "").strip() or self._timestamp_now()
        last_seen = (last_seen_at or "").strip() or created
        session = session_id.strip()
        with self._lock:
            while True:
                try:
                    self._conn.execute(
                        """
                        INSERT INTO dirtylaundry_profiles (
                            profile_id,
                            skill,
                            created_at,
                            last_seen_at,
                            metrics_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            normalized_profile_id,
                            normalized_skill,
                            created,
                            last_seen,
                            json.dumps(normalized_metrics, separators=(",", ":"), ensure_ascii=True),
                        ),
                    )
                    break
                except sqlite3.IntegrityError:
                    if profile_id and profile_id.strip():
                        raise ValueError(f"profile_id '{normalized_profile_id}' already exists")
                    normalized_profile_id = uuid4().hex[:14]
            if session:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO dirtylaundry_profile_sessions (
                        profile_id,
                        session_id,
                        created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (normalized_profile_id, session, self._timestamp_now()),
                )
            self._trim_profile_sessions_locked(normalized_profile_id)
            self._evict_profiles_locked()
            self._conn.commit()
            profile = self._profile_by_id_locked(normalized_profile_id)
            if profile is None:  # pragma: no cover - defensive
                raise RuntimeError("failed to load newly created profile")
            return profile

    def get_profile(self, profile_id: str) -> AdversaryProfile | None:
        normalized_profile_id = profile_id.strip()
        if not normalized_profile_id:
            return None
        with self._lock:
            return self._profile_by_id_locked(normalized_profile_id)

    def list_profiles(self, *, limit: int = 200) -> list[AdversaryProfile]:
        safe_limit = max(1, min(2000, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT profile_id, skill, created_at, last_seen_at, metrics_json
                FROM dirtylaundry_profiles
                ORDER BY last_seen_at DESC, profile_id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
            return [self._build_profile_locked(row) for row in rows]

    def add_session(self, *, profile_id: str, session_id: str) -> AdversaryProfile | None:
        normalized_profile_id = profile_id.strip()
        normalized_session_id = session_id.strip()
        if not normalized_profile_id:
            return None
        with self._lock:
            existing = self._profile_by_id_locked(normalized_profile_id)
            if existing is None:
                return None
            if normalized_session_id:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO dirtylaundry_profile_sessions (
                        profile_id,
                        session_id,
                        created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (normalized_profile_id, normalized_session_id, self._timestamp_now()),
                )
            self._trim_profile_sessions_locked(normalized_profile_id)
            self._conn.execute(
                """
                UPDATE dirtylaundry_profiles
                SET last_seen_at = ?
                WHERE profile_id = ?
                """,
                (self._timestamp_now(), normalized_profile_id),
            )
            self._conn.commit()
            return self._profile_by_id_locked(normalized_profile_id)

    def add_note(self, *, profile_id: str, note: str) -> AdversaryProfile | None:
        normalized_profile_id = profile_id.strip()
        normalized_note = note.strip()
        if not normalized_profile_id:
            return None
        with self._lock:
            existing = self._profile_by_id_locked(normalized_profile_id)
            if existing is None:
                return None
            if normalized_note:
                self._conn.execute(
                    """
                    INSERT INTO dirtylaundry_profile_notes (
                        profile_id,
                        note,
                        created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (normalized_profile_id, normalized_note, self._timestamp_now()),
                )
            self._trim_profile_notes_locked(normalized_profile_id)
            self._conn.execute(
                """
                UPDATE dirtylaundry_profiles
                SET last_seen_at = ?
                WHERE profile_id = ?
                """,
                (self._timestamp_now(), normalized_profile_id),
            )
            self._conn.commit()
            return self._profile_by_id_locked(normalized_profile_id)

    def upsert_profile(
        self,
        *,
        profile_id: str,
        skill: str,
        metrics: dict[str, float],
        created_at: str = "",
        last_seen_at: str = "",
    ) -> AdversaryProfile:
        normalized_profile_id = profile_id.strip() or uuid4().hex[:14]
        normalized_skill = self._normalize_skill(skill)
        normalized_metrics = self._normalize_metrics(metrics)
        created = created_at.strip() or self._timestamp_now()
        observed_last_seen = last_seen_at.strip() or created
        with self._lock:
            existing = self._conn.execute(
                """
                SELECT created_at, last_seen_at
                FROM dirtylaundry_profiles
                WHERE profile_id = ?
                LIMIT 1
                """,
                (normalized_profile_id,),
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    """
                    INSERT INTO dirtylaundry_profiles (
                        profile_id,
                        skill,
                        created_at,
                        last_seen_at,
                        metrics_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_profile_id,
                        normalized_skill,
                        created,
                        observed_last_seen,
                        json.dumps(normalized_metrics, separators=(",", ":"), ensure_ascii=True),
                    ),
                )
            else:
                effective_last_seen = self._timestamp_max(str(existing["last_seen_at"]), observed_last_seen)
                self._conn.execute(
                    """
                    UPDATE dirtylaundry_profiles
                    SET skill = ?, last_seen_at = ?, metrics_json = ?
                    WHERE profile_id = ?
                    """,
                    (
                        normalized_skill,
                        effective_last_seen,
                        json.dumps(normalized_metrics, separators=(",", ":"), ensure_ascii=True),
                        normalized_profile_id,
                    ),
                )
            self._evict_profiles_locked()
            self._conn.commit()
            profile = self._profile_by_id_locked(normalized_profile_id)
            if profile is None:  # pragma: no cover - defensive
                raise RuntimeError("failed to load upserted profile")
            return profile

    @staticmethod
    def as_payload(profile: AdversaryProfile) -> dict[str, Any]:
        return {
            "profile_id": profile.profile_id,
            "skill": profile.skill,
            "created_at": profile.created_at,
            "last_seen_at": profile.last_seen_at,
            "sessions": list(profile.sessions),
            "session_count": len(profile.sessions),
            "notes": list(profile.notes),
            "metrics": dict(profile.metrics),
        }
