"""Adversary Theater aggregation service."""

from __future__ import annotations

from datetime import UTC, datetime
import secrets
import time
from typing import Any

from clownpeanuts.config.schema import TheaterConfig
from clownpeanuts.intel.behavior import infer_kill_chain, map_event_to_stage, predict_next_action


_LATENCY_BUDGET_MS = 500.0
_EXPLANATION_WEIGHTS = {
    "kill_chain": 0.45,
    "narrative": 0.25,
    "bandit": 0.30,
}
_STAGE_LURE_MAP = {
    "reconnaissance": "http-query-bait",
    "initial_access": "ssh-credential-bait",
    "credential_access": "ssh-credential-bait",
    "discovery": "generic-pivot-bait",
    "lateral_movement": "multi-protocol-bait",
    "collection": "mysql-query-bait",
    "exfiltration": "http-backup-bait",
    "execution": "generic-baseline",
}


class TheaterService:
    """Builds operator-focused live views from active session telemetry."""

    def __init__(self, config: TheaterConfig) -> None:
        self.config = config

    def snapshot(self) -> dict[str, object]:
        return {
            "enabled": self.config.enabled,
            "rollout_mode": self.config.rollout_mode,
            "max_live_sessions": self.config.max_live_sessions,
            "recommendation_cooldown_seconds": self.config.recommendation_cooldown_seconds,
            "latency_budget_ms": _LATENCY_BUDGET_MS,
        }

    def build_live_view(
        self,
        *,
        sessions: list[dict[str, Any]],
        bandit_metrics: dict[str, Any] | None = None,
    ) -> dict[str, object]:
        started = time.perf_counter()
        session_views: list[dict[str, object]] = []
        for session in sessions[: self.config.max_live_sessions]:
            if not isinstance(session, dict):
                continue
            session_views.append(self.build_session_view(session=session, bandit_metrics=bandit_metrics))
        recommendations = self._recommendations_from_views(session_views)
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        return {
            "enabled": self.config.enabled,
            "mode": self.config.rollout_mode,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "count": len(session_views),
            "sessions": session_views,
            "recommendations": recommendations,
            "bandit_metrics": self._bandit_summary(bandit_metrics),
            "latency_ms": latency_ms,
            "within_latency_budget": latency_ms <= _LATENCY_BUDGET_MS,
        }

    def build_recommendations(
        self,
        *,
        sessions: list[dict[str, Any]],
        limit: int = 20,
        bandit_metrics: dict[str, Any] | None = None,
    ) -> dict[str, object]:
        live_view = self.build_live_view(sessions=sessions, bandit_metrics=bandit_metrics)
        recommendations = live_view.get("recommendations", [])
        if not isinstance(recommendations, list):
            recommendations = []
        capped = recommendations[: max(1, int(limit))]
        return {
            "enabled": self.config.enabled,
            "mode": self.config.rollout_mode,
            "count": len(capped),
            "recommendations": capped,
            "bandit_metrics": live_view.get("bandit_metrics", {}),
            "generated_at": live_view.get("generated_at", ""),
            "latency_ms": live_view.get("latency_ms", 0.0),
            "within_latency_budget": live_view.get("within_latency_budget", True),
        }

    def build_session_view(
        self,
        *,
        session: dict[str, Any],
        bandit_metrics: dict[str, Any] | None = None,
    ) -> dict[str, object]:
        raw_events = session.get("events", [])
        events: list[dict[str, Any]] = []
        if isinstance(raw_events, list):
            for event in raw_events:
                if isinstance(event, dict):
                    events.append(event)
        kill_chain = infer_kill_chain(events)
        prediction = predict_next_action(events=events, kill_chain=kill_chain)
        recommendation = self._recommendation_for_session(
            session=session,
            prediction=prediction,
            events=events,
            kill_chain=kill_chain,
            bandit_metrics=bandit_metrics,
        )
        timeline = self._timeline(events)

        narrative = session.get("narrative", {})
        if not isinstance(narrative, dict):
            narrative = {}
        touched_services = narrative.get("touched_services", [])
        if not isinstance(touched_services, list):
            touched_services = []

        return {
            "session_id": str(session.get("session_id", "")),
            "source_ip": str(session.get("source_ip", "")),
            "created_at": str(session.get("created_at", "")),
            "event_count": int(session.get("event_count", len(events)) or len(events)),
            "kill_chain": kill_chain,
            "current_stage": str(prediction.get("current_stage", "reconnaissance")),
            "prediction": prediction,
            "timeline": timeline,
            "recommendation": recommendation,
            "narrative": {
                "context_id": str(narrative.get("context_id", "")),
                "world_id": str(narrative.get("world_id", "")),
                "discovery_depth": int(narrative.get("discovery_depth", 0) or 0),
                "touched_services": [str(item) for item in touched_services if str(item).strip()],
            },
        }

    def _timeline(self, events: list[dict[str, Any]]) -> list[dict[str, object]]:
        timeline: list[dict[str, object]] = []
        for event in events[-50:]:
            stage = map_event_to_stage(event)
            timeline.append(
                {
                    "timestamp": str(event.get("timestamp", "")),
                    "service": str(event.get("service", "")),
                    "action": str(event.get("action", "")),
                    "stage": stage or "unknown",
                }
            )
        return timeline

    def _recommendation_for_session(
        self,
        *,
        session: dict[str, Any],
        prediction: dict[str, Any],
        events: list[dict[str, Any]],
        kill_chain: list[str],
        bandit_metrics: dict[str, Any] | None,
    ) -> dict[str, object]:
        session_id = str(session.get("session_id", ""))
        predicted_stage = str(prediction.get("predicted_stage", "discovery"))
        predicted_action = str(prediction.get("predicted_action", "command"))
        prediction_confidence = max(0.0, min(1.0, float(prediction.get("confidence", 0.5) or 0.5)))
        primary_service = self._primary_service(events)
        context_key = f"{primary_service}:{str(prediction.get('current_stage', 'reconnaissance'))}"
        candidate_arm = _STAGE_LURE_MAP.get(predicted_stage, "generic-baseline")

        narrative = session.get("narrative", {})
        if not isinstance(narrative, dict):
            narrative = {}
        discovery_depth = int(narrative.get("discovery_depth", 0) or 0)
        kill_chain_score = min(1.0, float(len(kill_chain)) / 6.0)
        narrative_score = min(1.0, float(discovery_depth) / 8.0)

        metrics = bandit_metrics if isinstance(bandit_metrics, dict) else {}
        bandit_reward_avg = max(0.0, min(1.0, float(metrics.get("reward_avg", 0.0) or 0.0)))
        bandit_exploration_ratio = max(0.0, min(1.0, float(metrics.get("exploration_ratio", 0.0) or 0.0)))
        bandit_score = max(0.0, min(1.0, bandit_reward_avg - (bandit_exploration_ratio * 0.2)))

        composite = (
            kill_chain_score * _EXPLANATION_WEIGHTS["kill_chain"]
            + narrative_score * _EXPLANATION_WEIGHTS["narrative"]
            + bandit_score * _EXPLANATION_WEIGHTS["bandit"]
        )
        recommendation_confidence = max(
            0.1,
            min(0.99, (prediction_confidence * 0.7) + (composite * 0.3)),
        )

        fallback_applied = False
        fallback_reason = ""
        lure_arm = candidate_arm
        if predicted_stage not in _STAGE_LURE_MAP:
            lure_arm = "generic-baseline"
            fallback_applied = True
            fallback_reason = "unknown_predicted_stage"
        elif bandit_exploration_ratio >= 0.8 and candidate_arm != "generic-baseline":
            lure_arm = "generic-baseline"
            fallback_applied = True
            fallback_reason = "high_exploration_ratio"
        if fallback_applied:
            recommendation_confidence = max(0.1, min(0.95, recommendation_confidence * 0.8))

        explanation = {
            "version": "v1",
            "weights": dict(_EXPLANATION_WEIGHTS),
            "signals": {
                "kill_chain_depth": len(kill_chain),
                "narrative_discovery_depth": discovery_depth,
                "bandit_reward_avg": round(bandit_reward_avg, 6),
                "bandit_exploration_ratio": round(bandit_exploration_ratio, 6),
                "predicted_stage": predicted_stage,
                "predicted_action": predicted_action,
            },
            "components": {
                "kill_chain_score": round(kill_chain_score, 6),
                "narrative_score": round(narrative_score, 6),
                "bandit_score": round(bandit_score, 6),
                "composite_score": round(composite, 6),
            },
            "fallback": {
                "applied": fallback_applied,
                "reason": fallback_reason,
                "candidate_arm": candidate_arm,
                "selected_arm": lure_arm,
            },
        }
        recommendation_id = self._recommendation_id(session_id=session_id, predicted_stage=predicted_stage)
        explanation_digest = self._explanation_digest(
            predicted_stage=predicted_stage,
            primary_service=primary_service,
            recommendation_confidence=recommendation_confidence,
            kill_chain_depth=len(kill_chain),
            discovery_depth=discovery_depth,
            fallback_applied=fallback_applied,
            fallback_reason=fallback_reason,
        )

        return {
            "recommendation_id": recommendation_id,
            "session_id": session_id,
            "context_key": context_key,
            "recommended_lure_arm": lure_arm,
            "predicted_stage": predicted_stage,
            "predicted_action": predicted_action,
            "confidence": round(recommendation_confidence, 3),
            "prediction_confidence": round(prediction_confidence, 3),
            "apply_allowed": self.config.rollout_mode == "apply-enabled",
            "rationale": (
                f"predicted_next_stage={predicted_stage}; "
                f"primary_service={primary_service}; "
                f"mode={self.config.rollout_mode}"
            ),
            "explanation_digest": explanation_digest,
            "explanation": explanation,
        }

    @staticmethod
    def _recommendation_id(*, session_id: str, predicted_stage: str) -> str:
        session_hint = "".join(ch for ch in session_id.strip().lower() if ch.isalnum())[:8] or "session"
        stage_hint = "".join(ch for ch in predicted_stage.strip().lower() if ch.isalnum())[:12] or "stage"
        nonce = secrets.token_hex(8)
        return f"rec-{session_hint}-{stage_hint}-{nonce}"

    def _recommendations_from_views(self, session_views: list[dict[str, object]]) -> list[dict[str, object]]:
        recommendations: list[dict[str, object]] = []
        for view in session_views:
            recommendation = view.get("recommendation")
            if isinstance(recommendation, dict):
                recommendations.append(dict(recommendation))
        recommendations.sort(
            key=lambda item: (
                -float(item.get("confidence", 0.0) or 0.0),
                str(item.get("session_id", "")),
            )
        )
        for index, recommendation in enumerate(recommendations, start=1):
            recommendation["queue_position"] = index
        return recommendations

    @staticmethod
    def _primary_service(events: list[dict[str, Any]]) -> str:
        for event in reversed(events):
            service = str(event.get("service", "")).strip().lower()
            if service:
                return service
        return "generic"

    @staticmethod
    def _bandit_summary(raw: dict[str, Any] | None) -> dict[str, float]:
        if not isinstance(raw, dict):
            return {"reward_avg": 0.0, "exploration_ratio": 0.0}
        reward_avg = max(0.0, min(1.0, float(raw.get("reward_avg", 0.0) or 0.0)))
        exploration_ratio = max(0.0, min(1.0, float(raw.get("exploration_ratio", 0.0) or 0.0)))
        return {
            "reward_avg": round(reward_avg, 6),
            "exploration_ratio": round(exploration_ratio, 6),
        }

    @staticmethod
    def _explanation_digest(
        *,
        predicted_stage: str,
        primary_service: str,
        recommendation_confidence: float,
        kill_chain_depth: int,
        discovery_depth: int,
        fallback_applied: bool,
        fallback_reason: str,
    ) -> str:
        summary = (
            f"stage={predicted_stage}; service={primary_service}; "
            f"confidence={recommendation_confidence:.2f}; "
            f"kill_chain_depth={kill_chain_depth}; discovery_depth={discovery_depth}"
        )
        if fallback_applied:
            reason = fallback_reason or "policy_fallback"
            return f"{summary}; fallback={reason}"
        return summary
