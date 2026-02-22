"""Structured intelligence snapshot persistence."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
from typing import Any

from clownpeanuts.core.logging import get_logger
from clownpeanuts.intel.canary import token_identifier


class _ReadWriteLock:
    """Allow concurrent readers while preserving single-writer semantics."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._readers = 0
        self._writer = False
        self._writer_waiters = 0

    @contextmanager
    def read_lock(self) -> Any:
        with self._condition:
            while self._writer or self._writer_waiters > 0:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers = max(0, self._readers - 1)
                if self._readers == 0:
                    self._condition.notify_all()

    @contextmanager
    def write_lock(self) -> Any:
        with self._condition:
            self._writer_waiters += 1
            while self._writer or self._readers > 0:
                self._condition.wait()
            self._writer_waiters = max(0, self._writer_waiters - 1)
            self._writer = True
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


class IntelligenceStore:
    _SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    _SQL_DDL_DISALLOWED_TOKENS = (";", "--", "/*", "*/")

    def __init__(self, db_path: str | Path | None = None) -> None:
        configured = db_path or os.getenv("CLOWNPEANUTS_INTEL_DB")
        if configured:
            self._db_path = Path(configured).expanduser().resolve()
        else:
            self._db_path = Path(tempfile.gettempdir()) / "clownpeanuts-intel.sqlite3"
        self._lock = _ReadWriteLock()
        self._schema_lock = threading.Lock()
        self._ready = False
        self._enabled = True
        self.logger = get_logger("clownpeanuts.intel.store")

    @property
    def db_path(self) -> str:
        return str(self._db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def record_report(self, report: dict[str, Any]) -> int | None:
        if not self._enabled:
            return None
        payload_json = json.dumps(report, separators=(",", ":"), ensure_ascii=True)
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        totals = report.get("totals", {})
        if not isinstance(totals, dict):
            totals = {}
        sessions = int(totals.get("sessions", 0) or 0)
        events = int(totals.get("events", 0) or 0)
        engagement_score_avg = float(totals.get("engagement_score_avg", 0.0) or 0.0)
        coherence_score_avg = float(totals.get("coherence_score_avg", 0.0) or 0.0)
        bandit_reward_avg = float(totals.get("bandit_reward_avg", 0.0) or 0.0)

        session_rows: list[tuple[str, str, str, float, int, float, float, str, float]] = []
        raw_sessions = report.get("sessions", [])
        if isinstance(raw_sessions, list):
            for session in raw_sessions:
                if not isinstance(session, dict):
                    continue
                timing = session.get("timing", {})
                if not isinstance(timing, dict):
                    timing = {}
                classification = session.get("classification", {})
                if not isinstance(classification, dict):
                    classification = {}
                engagement_score = session.get("engagement_score", {})
                if not isinstance(engagement_score, dict):
                    engagement_score = {}
                coherence_violations = self._normalize_violation_list(session.get("coherence_violations", []))
                session_rows.append(
                    (
                        str(session.get("session_id", "")),
                        str(session.get("source_ip", "")),
                        str(classification.get("label", "")),
                        float(engagement_score.get("score", 0.0) or 0.0),
                        int(session.get("event_count", 0) or 0),
                        float(timing.get("duration_seconds", 0.0) or 0.0),
                        float(session.get("coherence_score", 0.0) or 0.0),
                        json.dumps(coherence_violations, separators=(",", ":"), ensure_ascii=True),
                        float(session.get("bandit_reward", 0.0) or 0.0),
                    )
                )

        with self._lock.write_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO intelligence_reports (
                            created_at,
                            sessions,
                            events,
                            engagement_score_avg,
                            coherence_score_avg,
                            bandit_reward_avg,
                            payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            created_at,
                            sessions,
                            events,
                            engagement_score_avg,
                            coherence_score_avg,
                            bandit_reward_avg,
                            payload_json,
                        ),
                    )
                    report_id = int(cursor.lastrowid)
                    if session_rows:
                        cursor.executemany(
                            """
                            INSERT INTO intelligence_sessions (
                                report_id,
                                session_id,
                                source_ip,
                                classification_label,
                                engagement_score,
                                event_count,
                                duration_seconds,
                                coherence_score,
                                coherence_violations_json,
                                bandit_reward
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            [(report_id, *row) for row in session_rows],
                        )
                    conn.commit()
                    return report_id
            except Exception as exc:
                self._enabled = False
                self.logger.error(
                    "failed to persist intelligence report",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return None

    def recent_reports(self, *, limit: int = 20) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        """
                        SELECT
                            report_id,
                            created_at,
                            sessions,
                            events,
                            engagement_score_avg,
                            coherence_score_avg,
                            bandit_reward_avg,
                            payload_json
                        FROM intelligence_reports
                        ORDER BY report_id DESC
                        LIMIT ?
                        """,
                        (max(1, int(limit)),),
                    ).fetchall()
                payload: list[dict[str, Any]] = []
                for row in rows:
                    item = {
                        "report_id": int(row["report_id"]),
                        "created_at": str(row["created_at"]),
                        "sessions": int(row["sessions"]),
                        "events": int(row["events"]),
                        "engagement_score_avg": float(row["engagement_score_avg"]),
                        "coherence_score_avg": float(row["coherence_score_avg"]),
                        "bandit_reward_avg": float(row["bandit_reward_avg"]),
                    }
                    raw_payload = str(row["payload_json"])
                    try:
                        parsed = json.loads(raw_payload)
                        if isinstance(parsed, dict):
                            item["report"] = parsed
                    except json.JSONDecodeError:
                        item["report"] = {}
                    payload.append(item)
                return payload
            except Exception as exc:
                self.logger.warning(
                    "failed to read intelligence report history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def get_report(self, *, report_id: int) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    row = conn.execute(
                        """
                        SELECT
                            report_id,
                            created_at,
                            sessions,
                            events,
                            engagement_score_avg,
                            coherence_score_avg,
                            bandit_reward_avg,
                            payload_json
                        FROM intelligence_reports
                        WHERE report_id = ?
                        LIMIT 1
                        """,
                        (int(report_id),),
                    ).fetchone()
                if row is None:
                    return None
                item = {
                    "report_id": int(row["report_id"]),
                    "created_at": str(row["created_at"]),
                    "sessions": int(row["sessions"]),
                    "events": int(row["events"]),
                    "engagement_score_avg": float(row["engagement_score_avg"]),
                    "coherence_score_avg": float(row["coherence_score_avg"]),
                    "bandit_reward_avg": float(row["bandit_reward_avg"]),
                }
                raw_payload = str(row["payload_json"])
                try:
                    parsed = json.loads(raw_payload)
                    if isinstance(parsed, dict):
                        item["report"] = parsed
                except json.JSONDecodeError:
                    item["report"] = {}
                return item
            except Exception as exc:
                self.logger.warning(
                    "failed to read intelligence report detail",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "report_id": int(report_id), "error": str(exc)},
                    },
                )
                return None

    def recent_sessions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        """
                        SELECT
                            id,
                            report_id,
                            session_id,
                            source_ip,
                            classification_label,
                            engagement_score,
                            event_count,
                            duration_seconds,
                            coherence_score,
                            coherence_violations_json,
                            bandit_reward
                        FROM intelligence_sessions
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (max(1, int(limit)),),
                    ).fetchall()
                return [
                    {
                        "row_id": int(row["id"]),
                        "report_id": int(row["report_id"]),
                        "session_id": str(row["session_id"]),
                        "source_ip": str(row["source_ip"]),
                        "classification_label": str(row["classification_label"]),
                        "engagement_score": float(row["engagement_score"]),
                        "event_count": int(row["event_count"]),
                        "duration_seconds": float(row["duration_seconds"]),
                        "coherence_score": float(row["coherence_score"]),
                        "coherence_violations": self._parse_json_string_list(row["coherence_violations_json"]),
                        "bandit_reward": float(row["bandit_reward"]),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read intelligence session history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def report_sessions(self, *, report_id: int, limit: int = 1000) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        """
                        SELECT
                            id,
                            report_id,
                            session_id,
                            source_ip,
                            classification_label,
                            engagement_score,
                            event_count,
                            duration_seconds,
                            coherence_score,
                            coherence_violations_json,
                            bandit_reward
                        FROM intelligence_sessions
                        WHERE report_id = ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (int(report_id), max(1, int(limit))),
                    ).fetchall()
                return [
                    {
                        "row_id": int(row["id"]),
                        "report_id": int(row["report_id"]),
                        "session_id": str(row["session_id"]),
                        "source_ip": str(row["source_ip"]),
                        "classification_label": str(row["classification_label"]),
                        "engagement_score": float(row["engagement_score"]),
                        "event_count": int(row["event_count"]),
                        "duration_seconds": float(row["duration_seconds"]),
                        "coherence_score": float(row["coherence_score"]),
                        "coherence_violations": self._parse_json_string_list(row["coherence_violations_json"]),
                        "bandit_reward": float(row["bandit_reward"]),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read report-specific session history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "report_id": int(report_id), "error": str(exc)},
                    },
                )
                return []

    def record_canary_token(
        self,
        *,
        token_id: str,
        token: str,
        token_type: str,
        namespace: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_token = token.strip()
        if not normalized_token:
            return None
        normalized_token_id = token_id.strip() or token_identifier(token=normalized_token)
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=True)

        try:
            with self._lock.write_lock():
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute(
                        """
                        INSERT INTO canary_tokens (
                            token_id,
                            token,
                            token_type,
                            namespace,
                            created_at,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(token_id) DO UPDATE SET
                            token = excluded.token,
                            token_type = excluded.token_type,
                            namespace = excluded.namespace,
                            metadata_json = excluded.metadata_json
                        """,
                        (
                            normalized_token_id,
                            normalized_token,
                            token_type.strip() or "unknown",
                            namespace.strip() or "cp",
                            created_at,
                            metadata_json,
                        ),
                    )
                    conn.commit()
        except Exception as exc:
            self.logger.warning(
                "failed to persist canary token",
                extra={
                    "service": "intel_store",
                    "payload": {"db_path": str(self._db_path), "token_id": normalized_token_id, "error": str(exc)},
                },
            )
            return None
        return self.canary_token(token_id=normalized_token_id)

    def canary_token(self, *, token_id: str) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_token_id = token_id.strip()
        if not normalized_token_id:
            return None
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    row = conn.execute(
                        """
                        SELECT
                            t.token_id,
                            t.token,
                            t.token_type,
                            t.namespace,
                            t.created_at,
                            t.metadata_json,
                            COUNT(h.id) AS hit_count,
                            MAX(h.created_at) AS last_hit_at
                        FROM canary_tokens AS t
                        LEFT JOIN canary_hits AS h ON h.token_id = t.token_id
                        WHERE t.token_id = ?
                        GROUP BY t.token_id, t.token, t.token_type, t.namespace, t.created_at, t.metadata_json
                        LIMIT 1
                        """,
                        (normalized_token_id,),
                    ).fetchone()
                if row is None:
                    return None
                return {
                    "token_id": str(row["token_id"]),
                    "token": str(row["token"]),
                    "token_type": str(row["token_type"]),
                    "namespace": str(row["namespace"]),
                    "created_at": str(row["created_at"]),
                    "metadata": self._parse_json_object(row["metadata_json"]),
                    "hit_count": int(row["hit_count"] or 0),
                    "last_hit_at": str(row["last_hit_at"] or ""),
                }
            except Exception as exc:
                self.logger.warning(
                    "failed to read canary token detail",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "token_id": normalized_token_id, "error": str(exc)},
                    },
                )
                return None

    def recent_canary_tokens(
        self,
        *,
        limit: int = 100,
        namespace: str | None = None,
        token_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        normalized_namespace = namespace.strip() if namespace else ""
        normalized_type = token_type.strip() if token_type else ""
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                query = """
                    SELECT
                        t.token_id,
                        t.token,
                        t.token_type,
                        t.namespace,
                        t.created_at,
                        t.metadata_json,
                        COUNT(h.id) AS hit_count,
                        MAX(h.created_at) AS last_hit_at
                    FROM canary_tokens AS t
                    LEFT JOIN canary_hits AS h ON h.token_id = t.token_id
                """
                where_clauses: list[str] = []
                params: list[object] = []
                if normalized_namespace:
                    where_clauses.append("t.namespace = ?")
                    params.append(normalized_namespace)
                if normalized_type:
                    where_clauses.append("t.token_type = ?")
                    params.append(normalized_type)
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
                query += """
                    GROUP BY t.token_id, t.token, t.token_type, t.namespace, t.created_at, t.metadata_json
                    ORDER BY t.created_at DESC
                    LIMIT ?
                """
                params.append(max(1, int(limit)))

                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    {
                        "token_id": str(row["token_id"]),
                        "token": str(row["token"]),
                        "token_type": str(row["token_type"]),
                        "namespace": str(row["namespace"]),
                        "created_at": str(row["created_at"]),
                        "metadata": self._parse_json_object(row["metadata_json"]),
                        "hit_count": int(row["hit_count"] or 0),
                        "last_hit_at": str(row["last_hit_at"] or ""),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read canary token inventory",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def record_canary_hit(
        self,
        *,
        token: str,
        source_ip: str,
        service: str,
        session_id: str,
        tenant_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_token = token.strip()
        if not normalized_token:
            return None
        normalized_token_id = token_identifier(token=normalized_token)
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=True)
        hit_row_id: int | None = None
        try:
            with self._lock.write_lock():
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute(
                        """
                        INSERT INTO canary_tokens (
                            token_id,
                            token,
                            token_type,
                            namespace,
                            created_at,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(token_id) DO UPDATE SET
                            token = excluded.token
                        """,
                        (normalized_token_id, normalized_token, "unknown", "external", created_at, "{}"),
                    )
                    cursor = conn.execute(
                        """
                        INSERT INTO canary_hits (
                            token_id,
                            token,
                            source_ip,
                            service,
                            session_id,
                            tenant_id,
                            created_at,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            normalized_token_id,
                            normalized_token,
                            source_ip.strip(),
                            service.strip(),
                            session_id.strip(),
                            tenant_id.strip(),
                            created_at,
                            metadata_json,
                        ),
                    )
                    hit_row_id = int(cursor.lastrowid)
                    conn.commit()
        except Exception as exc:
            self.logger.warning(
                "failed to persist canary hit",
                extra={
                    "service": "intel_store",
                    "payload": {"db_path": str(self._db_path), "token_id": normalized_token_id, "error": str(exc)},
                },
            )
            return None
        if hit_row_id is None:
            return None
        rows = self.recent_canary_hits(limit=1, row_id=hit_row_id)
        return rows[0] if rows else None

    def recent_canary_hits(
        self,
        *,
        limit: int = 200,
        token_id: str | None = None,
        row_id: int | None = None,
    ) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        normalized_token_id = token_id.strip() if token_id else ""
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                query = """
                    SELECT
                        h.id,
                        h.token_id,
                        h.token,
                        h.source_ip,
                        h.service,
                        h.session_id,
                        h.tenant_id,
                        h.created_at,
                        h.metadata_json,
                        t.namespace,
                        t.token_type
                    FROM canary_hits AS h
                    LEFT JOIN canary_tokens AS t ON t.token_id = h.token_id
                """
                where_clauses: list[str] = []
                params: list[object] = []
                if row_id is not None:
                    where_clauses.append("h.id = ?")
                    params.append(int(row_id))
                if normalized_token_id:
                    where_clauses.append("h.token_id = ?")
                    params.append(normalized_token_id)
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
                query += " ORDER BY h.id DESC LIMIT ?"
                params.append(max(1, int(limit)))

                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    {
                        "row_id": int(row["id"]),
                        "token_id": str(row["token_id"]),
                        "token": str(row["token"]),
                        "token_type": str(row["token_type"] or ""),
                        "namespace": str(row["namespace"] or ""),
                        "source_ip": str(row["source_ip"]),
                        "service": str(row["service"]),
                        "session_id": str(row["session_id"]),
                        "tenant_id": str(row["tenant_id"]),
                        "created_at": str(row["created_at"]),
                        "metadata": self._parse_json_object(row["metadata_json"]),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read canary hit history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def record_bandit_decision(
        self,
        *,
        context_key: str,
        selected_arm: str | None,
        algorithm: str,
        candidates: list[str],
        exploration_applied: bool = False,
        blocked_arms: dict[str, str] | None = None,
        arm_scores: dict[str, float] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_context = context_key.strip() or "default"
        timestamp = created_at or datetime.now(UTC).isoformat(timespec="seconds")
        candidates_json = json.dumps([str(item).strip() for item in candidates if str(item).strip()], separators=(",", ":"), ensure_ascii=True)
        blocked_json = json.dumps(blocked_arms or {}, separators=(",", ":"), ensure_ascii=True)
        scores_json = json.dumps(arm_scores or {}, separators=(",", ":"), ensure_ascii=True)
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=True)
        decision_id: int | None = None
        try:
            with self._lock.write_lock():
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(
                        """
                        INSERT INTO bandit_decisions (
                            created_at,
                            context_key,
                            selected_arm,
                            algorithm,
                            exploration_applied,
                            candidates_json,
                            blocked_arms_json,
                            arm_scores_json,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            timestamp,
                            normalized_context,
                            (selected_arm or "").strip(),
                            algorithm.strip() or "thompson",
                            1 if exploration_applied else 0,
                            candidates_json,
                            blocked_json,
                            scores_json,
                            metadata_json,
                        ),
                    )
                    decision_id = int(cursor.lastrowid)
                    conn.commit()
        except Exception as exc:
            self.logger.warning(
                "failed to persist bandit decision",
                extra={
                    "service": "intel_store",
                    "payload": {"db_path": str(self._db_path), "context_key": normalized_context, "error": str(exc)},
                },
            )
            return None
        if decision_id is None:
            return None
        rows = self.recent_bandit_decisions(limit=1, decision_id=decision_id)
        return rows[0] if rows else None

    def recent_bandit_decisions(self, *, limit: int = 200, decision_id: int | None = None) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                query = """
                    SELECT
                        decision_id,
                        created_at,
                        context_key,
                        selected_arm,
                        algorithm,
                        exploration_applied,
                        candidates_json,
                        blocked_arms_json,
                        arm_scores_json,
                        metadata_json
                    FROM bandit_decisions
                """
                params: list[object] = []
                if decision_id is not None:
                    query += " WHERE decision_id = ?"
                    params.append(int(decision_id))
                query += " ORDER BY decision_id DESC LIMIT ?"
                params.append(max(1, int(limit)))

                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    {
                        "decision_id": int(row["decision_id"]),
                        "created_at": str(row["created_at"]),
                        "context_key": str(row["context_key"]),
                        "selected_arm": str(row["selected_arm"]),
                        "algorithm": str(row["algorithm"]),
                        "exploration_applied": bool(int(row["exploration_applied"] or 0)),
                        "candidates": self._parse_json_string_list(row["candidates_json"]),
                        "blocked_arms": self._parse_json_object(row["blocked_arms_json"]),
                        "arm_scores": self._parse_json_float_map(row["arm_scores_json"]),
                        "metadata": self._parse_json_object(row["metadata_json"]),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read bandit decision history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def record_bandit_reward(
        self,
        *,
        decision_id: int,
        reward: float,
        signals: dict[str, float | int] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        reward_value = max(0.0, min(1.0, float(reward)))
        timestamp = created_at or datetime.now(UTC).isoformat(timespec="seconds")
        signals_json = json.dumps(signals or {}, separators=(",", ":"), ensure_ascii=True)
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=True)
        row_id: int | None = None
        try:
            with self._lock.write_lock():
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    decision_row = conn.execute(
                        "SELECT decision_id, created_at FROM bandit_decisions WHERE decision_id = ? LIMIT 1",
                        (int(decision_id),),
                    ).fetchone()
                    if decision_row is None:
                        return None
                    delay_seconds = self._delay_seconds(
                        decision_created_at=str(decision_row["created_at"]),
                        reward_created_at=timestamp,
                    )
                    cursor = conn.execute(
                        """
                        INSERT INTO bandit_rewards (
                            decision_id,
                            created_at,
                            reward,
                            delay_seconds,
                            signals_json,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            int(decision_id),
                            timestamp,
                            reward_value,
                            delay_seconds,
                            signals_json,
                            metadata_json,
                        ),
                    )
                    row_id = int(cursor.lastrowid)
                    conn.commit()
        except Exception as exc:
            self.logger.warning(
                "failed to persist bandit reward",
                extra={
                    "service": "intel_store",
                    "payload": {"db_path": str(self._db_path), "decision_id": int(decision_id), "error": str(exc)},
                },
            )
            return None
        if row_id is None:
            return None
        rows = self.recent_bandit_rewards(limit=1, row_id=row_id)
        return rows[0] if rows else None

    def recent_bandit_rewards(
        self,
        *,
        limit: int = 200,
        decision_id: int | None = None,
        row_id: int | None = None,
    ) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                query = """
                    SELECT
                        id,
                        decision_id,
                        created_at,
                        reward,
                        delay_seconds,
                        signals_json,
                        metadata_json
                    FROM bandit_rewards
                """
                where_clauses: list[str] = []
                params: list[object] = []
                if row_id is not None:
                    where_clauses.append("id = ?")
                    params.append(int(row_id))
                if decision_id is not None:
                    where_clauses.append("decision_id = ?")
                    params.append(int(decision_id))
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
                query += " ORDER BY id DESC LIMIT ?"
                params.append(max(1, int(limit)))

                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    {
                        "row_id": int(row["id"]),
                        "decision_id": int(row["decision_id"]),
                        "created_at": str(row["created_at"]),
                        "reward": float(row["reward"]),
                        "delay_seconds": float(row["delay_seconds"]),
                        "signals": self._parse_json_float_map(row["signals_json"]),
                        "metadata": self._parse_json_object(row["metadata_json"]),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read bandit reward history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def record_theater_action(
        self,
        *,
        action_type: str,
        session_id: str,
        actor: str,
        recommendation_id: str | None = None,
        payload: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_action = action_type.strip().lower().replace("-", "_").replace(" ", "_")
        normalized_session = session_id.strip()
        if not normalized_action or not normalized_session:
            return None
        timestamp = created_at or datetime.now(UTC).isoformat(timespec="seconds")
        payload_json = json.dumps(payload or {}, separators=(",", ":"), ensure_ascii=True)
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=True)
        normalized_actor = actor.strip() or "operator"
        normalized_recommendation_id = (recommendation_id or "").strip()
        row_id: int | None = None
        try:
            with self._lock.write_lock():
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(
                        """
                        INSERT INTO theater_actions (
                            created_at,
                            action_type,
                            session_id,
                            recommendation_id,
                            actor,
                            payload_json,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            timestamp,
                            normalized_action,
                            normalized_session,
                            normalized_recommendation_id,
                            normalized_actor,
                            payload_json,
                            metadata_json,
                        ),
                    )
                    row_id = int(cursor.lastrowid)
                    conn.commit()
        except Exception as exc:
            self.logger.warning(
                "failed to persist theater action",
                extra={
                    "service": "intel_store",
                    "payload": {
                        "db_path": str(self._db_path),
                        "action_type": normalized_action,
                        "session_id": normalized_session,
                        "error": str(exc),
                    },
                },
            )
            return None
        if row_id is None:
            return None
        rows = self.recent_theater_actions(limit=1, row_id=row_id)
        return rows[0] if rows else None

    def recent_theater_actions(
        self,
        *,
        limit: int = 200,
        session_id: str | None = None,
        action_type: str | None = None,
        row_id: int | None = None,
    ) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        normalized_session_id = session_id.strip() if session_id else ""
        normalized_action_type = action_type.strip().lower().replace("-", "_").replace(" ", "_") if action_type else ""
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                query = """
                    SELECT
                        id,
                        created_at,
                        action_type,
                        session_id,
                        recommendation_id,
                        actor,
                        payload_json,
                        metadata_json
                    FROM theater_actions
                """
                where_clauses: list[str] = []
                params: list[object] = []
                if row_id is not None:
                    where_clauses.append("id = ?")
                    params.append(int(row_id))
                if normalized_session_id:
                    where_clauses.append("session_id = ?")
                    params.append(normalized_session_id)
                if normalized_action_type:
                    where_clauses.append("action_type = ?")
                    params.append(normalized_action_type)
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
                query += " ORDER BY id DESC LIMIT ?"
                params.append(max(1, int(limit)))
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    {
                        "row_id": int(row["id"]),
                        "created_at": str(row["created_at"]),
                        "action_type": str(row["action_type"]),
                        "session_id": str(row["session_id"]),
                        "recommendation_id": str(row["recommendation_id"]),
                        "actor": str(row["actor"]),
                        "payload": self._parse_json_object(row["payload_json"]),
                        "metadata": self._parse_json_object(row["metadata_json"]),
                    }
                    for row in rows
                ]
            except Exception as exc:
                self.logger.warning(
                    "failed to read theater action history",
                    extra={
                        "service": "intel_store",
                        "payload": {"db_path": str(self._db_path), "error": str(exc)},
                    },
                )
                return []

    def upsert_campaign_graph(
        self,
        *,
        campaign_id: str,
        name: str,
        status: str = "draft",
        nodes: list[dict[str, Any]] | None = None,
        edges: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
        event_type: str = "upsert",
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_campaign_id = campaign_id.strip()
        normalized_name = name.strip()
        if not normalized_campaign_id or not normalized_name:
            return None
        normalized_status = status.strip().lower() or "draft"
        if normalized_status not in {"draft", "active", "paused", "archived"}:
            normalized_status = "draft"
        timestamp = created_at or datetime.now(UTC).isoformat(timespec="seconds")
        normalized_nodes = self._normalize_json_object_list(nodes)
        normalized_edges = self._normalize_json_object_list(edges)
        graph_json = json.dumps(
            {"nodes": normalized_nodes, "edges": normalized_edges},
            separators=(",", ":"),
            ensure_ascii=True,
        )
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=True)
        normalized_event_type = event_type.strip().lower() or "upsert"
        with self._lock.write_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    existing = self._select_campaign_graph_row(conn=conn, campaign_id=normalized_campaign_id)
                    if existing is None:
                        created_at_value = timestamp
                        next_version = 1
                    else:
                        created_at_value = str(existing["created_at"])
                        next_version = max(1, int(existing["version"] or 0) + 1)
                    conn.execute(
                        """
                        INSERT INTO campaign_graphs (
                            campaign_id,
                            name,
                            status,
                            created_at,
                            updated_at,
                            version,
                            graph_json,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(campaign_id) DO UPDATE SET
                            name = excluded.name,
                            status = excluded.status,
                            updated_at = excluded.updated_at,
                            version = excluded.version,
                            graph_json = excluded.graph_json,
                            metadata_json = excluded.metadata_json
                        """,
                        (
                            normalized_campaign_id,
                            normalized_name,
                            normalized_status,
                            created_at_value,
                            timestamp,
                            next_version,
                            graph_json,
                            metadata_json,
                        ),
                    )
                    current = self._select_campaign_graph_row(conn=conn, campaign_id=normalized_campaign_id)
                    self._record_campaign_graph_version(
                        conn=conn,
                        campaign_row=current,
                        event_type=normalized_event_type,
                    )
                    conn.commit()
                    return self._campaign_graph_row_payload(current)
            except Exception as exc:
                self.logger.warning(
                    "failed to persist campaign graph",
                    extra={
                        "service": "intel_store",
                        "payload": {
                            "db_path": str(self._db_path),
                            "campaign_id": normalized_campaign_id,
                            "error": str(exc),
                        },
                    },
                )
                return None

    def set_campaign_graph_status(
        self,
        *,
        campaign_id: str,
        status: str,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_campaign_id = campaign_id.strip()
        if not normalized_campaign_id:
            return None
        normalized_status = status.strip().lower()
        if normalized_status not in {"draft", "active", "paused", "archived"}:
            return None
        timestamp = created_at or datetime.now(UTC).isoformat(timespec="seconds")
        with self._lock.write_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    existing = self._select_campaign_graph_row(conn=conn, campaign_id=normalized_campaign_id)
                    if existing is None:
                        return None
                    current_status = str(existing["status"]).strip().lower()
                    current_metadata = self._parse_json_object(existing["metadata_json"])
                    if metadata:
                        current_metadata.update(metadata)
                    metadata_json = json.dumps(current_metadata, separators=(",", ":"), ensure_ascii=True)
                    if current_status != normalized_status:
                        next_version = max(1, int(existing["version"] or 0) + 1)
                        conn.execute(
                            """
                            UPDATE campaign_graphs
                            SET status = ?,
                                updated_at = ?,
                                version = ?,
                                metadata_json = ?
                            WHERE campaign_id = ?
                            """,
                            (
                                normalized_status,
                                timestamp,
                                next_version,
                                metadata_json,
                                normalized_campaign_id,
                            ),
                        )
                        current = self._select_campaign_graph_row(conn=conn, campaign_id=normalized_campaign_id)
                        self._record_campaign_graph_version(
                            conn=conn,
                            campaign_row=current,
                            event_type="status_change",
                        )
                        conn.commit()
                        return self._campaign_graph_row_payload(current)

                    if metadata:
                        conn.execute(
                            """
                            UPDATE campaign_graphs
                            SET updated_at = ?,
                                metadata_json = ?
                            WHERE campaign_id = ?
                            """,
                            (
                                timestamp,
                                metadata_json,
                                normalized_campaign_id,
                            ),
                        )
                        conn.commit()
                        current = self._select_campaign_graph_row(conn=conn, campaign_id=normalized_campaign_id)
                        return self._campaign_graph_row_payload(current)
                    return self._campaign_graph_row_payload(existing)
            except Exception as exc:
                self.logger.warning(
                    "failed to update campaign graph status",
                    extra={
                        "service": "intel_store",
                        "payload": {
                            "db_path": str(self._db_path),
                            "campaign_id": normalized_campaign_id,
                            "status": normalized_status,
                            "error": str(exc),
                        },
                    },
                )
                return None

    def campaign_graph(self, *, campaign_id: str) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        normalized_campaign_id = campaign_id.strip()
        if not normalized_campaign_id:
            return None
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    row = self._select_campaign_graph_row(conn=conn, campaign_id=normalized_campaign_id)
                return self._campaign_graph_row_payload(row)
            except Exception as exc:
                self.logger.warning(
                    "failed to read campaign graph detail",
                    extra={
                        "service": "intel_store",
                        "payload": {
                            "db_path": str(self._db_path),
                            "campaign_id": normalized_campaign_id,
                            "error": str(exc),
                        },
                    },
                )
                return None

    def recent_campaign_graphs(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        normalized_status = str(status or "").strip().lower()
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                query = """
                    SELECT
                        campaign_id,
                        name,
                        status,
                        created_at,
                        updated_at,
                        version,
                        graph_json,
                        metadata_json
                    FROM campaign_graphs
                """
                params: list[object] = []
                if normalized_status:
                    query += " WHERE status = ?"
                    params.append(normalized_status)
                query += " ORDER BY updated_at DESC, campaign_id ASC LIMIT ?"
                params.append(max(1, int(limit)))
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(query, tuple(params)).fetchall()
                payload: list[dict[str, Any]] = []
                for row in rows:
                    parsed = self._campaign_graph_row_payload(row)
                    if parsed is not None:
                        payload.append(parsed)
                return payload
            except Exception as exc:
                self.logger.warning(
                    "failed to read campaign graph inventory",
                    extra={
                        "service": "intel_store",
                        "payload": {
                            "db_path": str(self._db_path),
                            "status": normalized_status,
                            "error": str(exc),
                        },
                    },
                )
                return []

    def campaign_graph_versions(
        self,
        *,
        campaign_id: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        normalized_campaign_id = campaign_id.strip()
        if not normalized_campaign_id:
            return []
        with self._lock.read_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        """
                        SELECT
                            campaign_id,
                            version,
                            status,
                            created_at,
                            event_type,
                            graph_json,
                            metadata_json
                        FROM campaign_graph_versions
                        WHERE campaign_id = ?
                        ORDER BY version DESC, id DESC
                        LIMIT ?
                        """,
                        (normalized_campaign_id, max(1, int(limit))),
                    ).fetchall()
                payload: list[dict[str, Any]] = []
                for row in rows:
                    parsed = self._campaign_graph_version_row_payload(row)
                    if parsed is not None:
                        payload.append(parsed)
                return payload
            except Exception as exc:
                self.logger.warning(
                    "failed to read campaign graph version history",
                    extra={
                        "service": "intel_store",
                        "payload": {
                            "db_path": str(self._db_path),
                            "campaign_id": normalized_campaign_id,
                            "error": str(exc),
                        },
                    },
                )
                return []

    def delete_campaign_graph(self, *, campaign_id: str) -> bool:
        if not self._enabled:
            return False
        normalized_campaign_id = campaign_id.strip()
        if not normalized_campaign_id:
            return False
        with self._lock.write_lock():
            try:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.execute(
                        "DELETE FROM campaign_graph_versions WHERE campaign_id = ?",
                        (normalized_campaign_id,),
                    )
                    cursor = conn.execute(
                        "DELETE FROM campaign_graphs WHERE campaign_id = ?",
                        (normalized_campaign_id,),
                    )
                    conn.commit()
                return int(cursor.rowcount or 0) > 0
            except Exception as exc:
                self.logger.warning(
                    "failed to delete campaign graph",
                    extra={
                        "service": "intel_store",
                        "payload": {
                            "db_path": str(self._db_path),
                            "campaign_id": normalized_campaign_id,
                            "error": str(exc),
                        },
                    },
                )
                return False

    def snapshot(self) -> dict[str, Any]:
        return {"enabled": self._enabled, "db_path": str(self._db_path)}

    def _ensure_schema(self) -> None:
        if self._ready:
            return
        with self._schema_lock:
            if self._ready:
                return
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS intelligence_reports (
                        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        sessions INTEGER NOT NULL,
                        events INTEGER NOT NULL,
                        engagement_score_avg REAL NOT NULL,
                        coherence_score_avg REAL NOT NULL DEFAULT 0.0,
                        bandit_reward_avg REAL NOT NULL DEFAULT 0.0,
                        payload_json TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS intelligence_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        report_id INTEGER NOT NULL,
                        session_id TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        classification_label TEXT NOT NULL,
                        engagement_score REAL NOT NULL,
                        event_count INTEGER NOT NULL,
                        duration_seconds REAL NOT NULL,
                        coherence_score REAL NOT NULL DEFAULT 0.0,
                        coherence_violations_json TEXT NOT NULL DEFAULT '[]',
                        bandit_reward REAL NOT NULL DEFAULT 0.0,
                        FOREIGN KEY(report_id) REFERENCES intelligence_reports(report_id)
                    )
                    """
                )
                self._ensure_column(
                    conn=conn,
                    table="intelligence_reports",
                    column="coherence_score_avg",
                    definition="REAL NOT NULL DEFAULT 0.0",
                )
                self._ensure_column(
                    conn=conn,
                    table="intelligence_reports",
                    column="bandit_reward_avg",
                    definition="REAL NOT NULL DEFAULT 0.0",
                )
                self._ensure_column(
                    conn=conn,
                    table="intelligence_sessions",
                    column="coherence_score",
                    definition="REAL NOT NULL DEFAULT 0.0",
                )
                self._ensure_column(
                    conn=conn,
                    table="intelligence_sessions",
                    column="coherence_violations_json",
                    definition="TEXT NOT NULL DEFAULT '[]'",
                )
                self._ensure_column(
                    conn=conn,
                    table="intelligence_sessions",
                    column="bandit_reward",
                    definition="REAL NOT NULL DEFAULT 0.0",
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_intel_reports_created_at ON intelligence_reports(created_at)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_intel_sessions_report_id ON intelligence_sessions(report_id)"
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS canary_tokens (
                        token_id TEXT PRIMARY KEY,
                        token TEXT NOT NULL,
                        token_type TEXT NOT NULL,
                        namespace TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        metadata_json TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS canary_hits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token_id TEXT NOT NULL,
                        token TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        service TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        tenant_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        FOREIGN KEY(token_id) REFERENCES canary_tokens(token_id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS bandit_decisions (
                        decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        context_key TEXT NOT NULL,
                        selected_arm TEXT NOT NULL,
                        algorithm TEXT NOT NULL,
                        exploration_applied INTEGER NOT NULL,
                        candidates_json TEXT NOT NULL,
                        blocked_arms_json TEXT NOT NULL,
                        arm_scores_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS bandit_rewards (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        decision_id INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        reward REAL NOT NULL,
                        delay_seconds REAL NOT NULL,
                        signals_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        FOREIGN KEY(decision_id) REFERENCES bandit_decisions(decision_id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS theater_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        recommendation_id TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS campaign_graphs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        campaign_id TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        version INTEGER NOT NULL DEFAULT 1,
                        graph_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL
                    )
                    """
                )
                self._ensure_column(
                    conn=conn,
                    table="campaign_graphs",
                    column="version",
                    definition="INTEGER NOT NULL DEFAULT 1",
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS campaign_graph_versions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        campaign_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        graph_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_canary_tokens_created_at ON canary_tokens(created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_canary_hits_token_id ON canary_hits(token_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_canary_hits_created_at ON canary_hits(created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_bandit_decisions_created_at ON bandit_decisions(created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_bandit_rewards_decision_id ON bandit_rewards(decision_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_bandit_rewards_created_at ON bandit_rewards(created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_theater_actions_created_at ON theater_actions(created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_theater_actions_session_id ON theater_actions(session_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_theater_actions_action_type ON theater_actions(action_type)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_graphs_status ON campaign_graphs(status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_graphs_updated_at ON campaign_graphs(updated_at)")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_campaign_graph_versions_campaign_id ON campaign_graph_versions(campaign_id)"
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_graph_versions_version ON campaign_graph_versions(version)")
                conn.commit()
            self._ready = True

    @staticmethod
    def _parse_json_object(raw_value: object) -> dict[str, Any]:
        text = str(raw_value or "").strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {}
        return {}

    @staticmethod
    def _parse_json_object_list(raw_value: object) -> list[dict[str, Any]]:
        text = str(raw_value or "").strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, list):
            return []
        return IntelligenceStore._normalize_json_object_list(parsed)

    @staticmethod
    def _normalize_json_object_list(raw_value: object) -> list[dict[str, Any]]:
        if not isinstance(raw_value, list):
            return []
        normalized: list[dict[str, Any]] = []
        for item in raw_value:
            if isinstance(item, dict):
                normalized.append(dict(item))
            if len(normalized) >= 4000:
                break
        return normalized

    @staticmethod
    def _parse_json_string_list(raw_value: object) -> list[str]:
        text = str(raw_value or "").strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, list):
            return []
        values: list[str] = []
        for item in parsed:
            normalized = str(item).strip()
            if normalized:
                values.append(normalized)
        return values

    @staticmethod
    def _parse_json_float_map(raw_value: object) -> dict[str, float]:
        parsed = IntelligenceStore._parse_json_object(raw_value)
        payload: dict[str, float] = {}
        for key, value in parsed.items():
            normalized_key = str(key).strip()
            if not normalized_key:
                continue
            try:
                payload[normalized_key] = float(value)
            except (TypeError, ValueError):
                payload[normalized_key] = 0.0
        return payload

    @staticmethod
    def _delay_seconds(*, decision_created_at: str, reward_created_at: str) -> float:
        try:
            decision_time = datetime.fromisoformat(decision_created_at.replace("Z", "+00:00"))
            reward_time = datetime.fromisoformat(reward_created_at.replace("Z", "+00:00"))
            if decision_time.tzinfo is None:
                decision_time = decision_time.replace(tzinfo=UTC)
            if reward_time.tzinfo is None:
                reward_time = reward_time.replace(tzinfo=UTC)
            delta = (reward_time - decision_time).total_seconds()
            return max(0.0, float(delta))
        except Exception:
            return 0.0

    @staticmethod
    def _campaign_graph_row_payload(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        graph = IntelligenceStore._parse_json_object(row["graph_json"])
        nodes = IntelligenceStore._normalize_json_object_list(graph.get("nodes", []))
        edges = IntelligenceStore._normalize_json_object_list(graph.get("edges", []))
        return {
            "campaign_id": str(row["campaign_id"]),
            "name": str(row["name"]),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "version": max(1, int(row["version"] or 1)),
            "nodes": nodes,
            "edges": edges,
            "metadata": IntelligenceStore._parse_json_object(row["metadata_json"]),
        }

    @staticmethod
    def _campaign_graph_version_row_payload(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        graph = IntelligenceStore._parse_json_object(row["graph_json"])
        nodes = IntelligenceStore._normalize_json_object_list(graph.get("nodes", []))
        edges = IntelligenceStore._normalize_json_object_list(graph.get("edges", []))
        return {
            "campaign_id": str(row["campaign_id"]),
            "version": max(1, int(row["version"] or 1)),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "event_type": str(row["event_type"]),
            "nodes": nodes,
            "edges": edges,
            "metadata": IntelligenceStore._parse_json_object(row["metadata_json"]),
        }

    def _select_campaign_graph_row(
        self,
        *,
        conn: sqlite3.Connection,
        campaign_id: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT
                campaign_id,
                name,
                status,
                created_at,
                updated_at,
                version,
                graph_json,
                metadata_json
            FROM campaign_graphs
            WHERE campaign_id = ?
            LIMIT 1
            """,
            (campaign_id,),
        ).fetchone()

    def _record_campaign_graph_version(
        self,
        *,
        conn: sqlite3.Connection,
        campaign_row: sqlite3.Row | None,
        event_type: str,
    ) -> None:
        if campaign_row is None:
            return
        conn.execute(
            """
            INSERT INTO campaign_graph_versions (
                campaign_id,
                version,
                status,
                created_at,
                event_type,
                graph_json,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(campaign_row["campaign_id"]),
                max(1, int(campaign_row["version"] or 1)),
                str(campaign_row["status"]),
                str(campaign_row["updated_at"]),
                str(event_type).strip().lower() or "upsert",
                str(campaign_row["graph_json"]),
                str(campaign_row["metadata_json"]),
            ),
        )

    @staticmethod
    def _normalize_violation_list(raw_value: object) -> list[str]:
        if not isinstance(raw_value, list):
            return []
        values: list[str] = []
        for item in raw_value:
            normalized = str(item).strip()
            if not normalized:
                continue
            values.append(normalized[:120])
            if len(values) >= 200:
                break
        return values

    @staticmethod
    def _ensure_column(*, conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        if IntelligenceStore._SQL_IDENTIFIER_RE.fullmatch(table) is None:
            raise ValueError(f"invalid sql table identifier: {table!r}")
        if IntelligenceStore._SQL_IDENTIFIER_RE.fullmatch(column) is None:
            raise ValueError(f"invalid sql column identifier: {column!r}")
        normalized_definition = str(definition).strip()
        if not normalized_definition:
            raise ValueError("invalid sql column definition: empty")
        for token in IntelligenceStore._SQL_DDL_DISALLOWED_TOKENS:
            if token in normalized_definition:
                raise ValueError(f"invalid sql column definition: contains disallowed token {token!r}")
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {str(row[1]) for row in rows}
        if column in names:
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {normalized_definition}")
