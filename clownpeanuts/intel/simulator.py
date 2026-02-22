"""Offline counterfactual simulator for bandit policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from clownpeanuts.config.schema import BanditConfig, BanditRewardWeightsConfig, BanditSafetyCapsConfig
from clownpeanuts.intel.lure_bandit import LureBandit
from clownpeanuts.intel.reward import compute_bandit_reward, normalize_reward_signals


@dataclass(slots=True)
class SimulationPolicy:
    name: str
    algorithm: str
    exploration_floor: float


def simulate_bandit_counterfactual(
    *,
    report_rows: list[dict[str, Any]],
    window_hours: float,
    baseline_policy: SimulationPolicy,
    candidate_policy: SimulationPolicy,
    reward_weights: BanditRewardWeightsConfig,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    now = now_utc or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    sessions = _window_sessions(report_rows=report_rows, window_hours=window_hours, now_utc=now)

    baseline = _simulate_policy(sessions=sessions, policy=baseline_policy, reward_weights=reward_weights)
    candidate = _simulate_policy(sessions=sessions, policy=candidate_policy, reward_weights=reward_weights)

    baseline_avg = float(baseline.get("reward_avg", 0.0) or 0.0)
    candidate_avg = float(candidate.get("reward_avg", 0.0) or 0.0)
    baseline_total = float(baseline.get("reward_total", 0.0) or 0.0)
    candidate_total = float(candidate.get("reward_total", 0.0) or 0.0)
    reward_delta_total = round(candidate_total - baseline_total, 6)
    reward_delta_avg = round(candidate_avg - baseline_avg, 6)
    reward_delta_pct = 0.0
    if baseline_avg > 0:
        reward_delta_pct = round((reward_delta_avg / baseline_avg) * 100.0, 3)

    return {
        "window_hours": float(max(0.1, window_hours)),
        "window_start": (now - timedelta(hours=max(0.1, window_hours))).isoformat(timespec="seconds"),
        "window_end": now.isoformat(timespec="seconds"),
        "session_count": len(sessions),
        "baseline": baseline,
        "candidate": candidate,
        "delta": {
            "reward_total": reward_delta_total,
            "reward_avg": reward_delta_avg,
            "reward_avg_percent": reward_delta_pct,
        },
    }


def _simulate_policy(
    *,
    sessions: list[dict[str, Any]],
    policy: SimulationPolicy,
    reward_weights: BanditRewardWeightsConfig,
) -> dict[str, Any]:
    config = BanditConfig(
        enabled=True,
        algorithm=policy.algorithm,
        exploration_floor=max(0.0, min(1.0, float(policy.exploration_floor))),
        reward_weights=reward_weights,
        safety_caps=BanditSafetyCapsConfig(max_arm_exposure_percent=1.0, cooldown_seconds=0.0, denylist=[]),
    )
    bandit = LureBandit(config)

    reward_total = 0.0
    selection_count = 0
    exploration_count = 0
    trace_rows: list[dict[str, Any]] = []

    for index, session in enumerate(sessions):
        context_key, candidates = _context_for_session(session)
        decision = bandit.select_arm(context_key=context_key, candidates=candidates, now_epoch=float(index + 1))
        selected_arm = str(decision.selected_arm or "")
        if selected_arm:
            selection_count += 1
        if bool(decision.exploration_applied):
            exploration_count += 1

        signals = _reward_signals_for_session(session)
        observed_reward = _observed_reward(session=session, signals=signals, reward_weights=reward_weights)
        counterfactual_reward = _counterfactual_reward(
            arm=selected_arm,
            observed_reward=observed_reward,
            signals=signals,
        )
        if selected_arm:
            bandit.record_reward(
                context_key=context_key,
                arm=selected_arm,
                reward=counterfactual_reward,
                now_epoch=float(index + 1),
            )
        reward_total += counterfactual_reward

        trace_rows.append(
            {
                "session_id": str(session.get("session_id", "")),
                "context_key": context_key,
                "selected_arm": selected_arm,
                "observed_reward": round(observed_reward, 6),
                "counterfactual_reward": round(counterfactual_reward, 6),
                "exploration_applied": bool(decision.exploration_applied),
            }
        )

    reward_avg = round((reward_total / len(sessions)), 6) if sessions else 0.0
    exploration_ratio = round((float(exploration_count) / float(selection_count)), 6) if selection_count > 0 else 0.0
    snapshot = bandit.snapshot()
    arms = snapshot.get("arms", [])
    if not isinstance(arms, list):
        arms = []
    return {
        "policy": {
            "name": policy.name,
            "algorithm": policy.algorithm,
            "exploration_floor": max(0.0, min(1.0, float(policy.exploration_floor))),
        },
        "session_count": len(sessions),
        "selection_count": selection_count,
        "exploration_ratio": exploration_ratio,
        "reward_total": round(reward_total, 6),
        "reward_avg": reward_avg,
        "arms": arms,
        "trace": trace_rows[:50],
    }


def _window_sessions(
    *,
    report_rows: list[dict[str, Any]],
    window_hours: float,
    now_utc: datetime,
) -> list[dict[str, Any]]:
    cutoff = now_utc - timedelta(hours=max(0.1, float(window_hours)))
    by_session: dict[str, tuple[datetime, dict[str, Any]]] = {}

    for row in report_rows:
        if not isinstance(row, dict):
            continue
        row_created_at = _parse_iso_utc(row.get("created_at"))
        if row_created_at < cutoff:
            continue
        report = row.get("report")
        if not isinstance(report, dict):
            continue
        raw_sessions = report.get("sessions", [])
        if not isinstance(raw_sessions, list):
            continue
        for session in raw_sessions:
            if not isinstance(session, dict):
                continue
            session_id = str(session.get("session_id", "")).strip()
            if not session_id:
                continue
            session_created = _parse_iso_utc(session.get("created_at"))
            effective_created = session_created if session_created > datetime.min.replace(tzinfo=UTC) else row_created_at
            if effective_created < cutoff:
                continue
            existing = by_session.get(session_id)
            if existing is None or effective_created >= existing[0]:
                merged = dict(session)
                merged["_report_id"] = int(row.get("report_id", 0) or 0)
                by_session[session_id] = (effective_created, merged)

    ordered = sorted(by_session.values(), key=lambda item: item[0])
    return [item[1] for item in ordered]


def _context_for_session(session: dict[str, Any]) -> tuple[str, list[str]]:
    coherence_signals = session.get("coherence_signals", {})
    if not isinstance(coherence_signals, dict):
        coherence_signals = {}
    observed_services = coherence_signals.get("observed_services", [])
    services: list[str] = []
    if isinstance(observed_services, list):
        for item in observed_services:
            normalized = str(item).strip().lower()
            if normalized and normalized not in services:
                services.append(normalized)
    primary = services[0] if services else "generic"
    stage = _kill_chain_stage(session.get("kill_chain"))
    context_key = f"{primary}:{stage}"
    candidates = _candidates_for_primary(primary=primary, service_count=len(services))
    return (context_key, candidates)


def _candidates_for_primary(*, primary: str, service_count: int) -> list[str]:
    if primary.startswith("ssh"):
        candidates = ["ssh-baseline", "ssh-credential-bait", "ssh-lateral-bait"]
    elif primary.startswith("http"):
        candidates = ["http-baseline", "http-query-bait", "http-backup-bait"]
    elif "mysql" in primary:
        candidates = ["mysql-baseline", "mysql-query-bait", "mysql-credential-bait"]
    elif "postgres" in primary:
        candidates = ["postgres-baseline", "postgres-query-bait", "postgres-credential-bait"]
    else:
        candidates = ["generic-baseline", "generic-credential-bait", "generic-pivot-bait"]
    if service_count >= 2:
        candidates.append("multi-protocol-bait")
    return candidates


def _kill_chain_stage(raw: Any) -> str:
    if not isinstance(raw, list) or not raw:
        return "unknown"
    return str(raw[-1]).strip().lower().replace(" ", "_")[:40] or "unknown"


def _reward_signals_for_session(session: dict[str, Any]) -> dict[str, float]:
    existing = session.get("bandit_reward_signals", {})
    if isinstance(existing, dict) and existing:
        return normalize_reward_signals(existing)

    timing = session.get("timing", {})
    if not isinstance(timing, dict):
        timing = {}
    duration_seconds = max(0.0, float(timing.get("duration_seconds", 0.0) or 0.0))
    dwell_time = min(1.0, duration_seconds / 900.0)

    coherence_signals = session.get("coherence_signals", {})
    if not isinstance(coherence_signals, dict):
        coherence_signals = {}
    observed_services = coherence_signals.get("observed_services", [])
    service_count = len(observed_services) if isinstance(observed_services, list) else 0
    cross_protocol_pivot = 1.0 if service_count >= 2 else 0.0

    technique_novelty = 0.2
    tool_fingerprints = session.get("tool_fingerprints", [])
    if isinstance(tool_fingerprints, list):
        technique_novelty = min(1.0, max(0.0, float(len(tool_fingerprints)) / 5.0))

    engagement = session.get("engagement_score", {})
    if not isinstance(engagement, dict):
        engagement = {}
    alert_quality = min(1.0, max(0.0, float(engagement.get("score", 0.0) or 0.0) / 100.0))

    kill_chain = session.get("kill_chain", [])
    analyst_feedback = 0.0
    if isinstance(kill_chain, list):
        analyst_feedback = min(1.0, max(0.0, float(len(kill_chain)) / 6.0))

    return normalize_reward_signals(
        {
            "dwell_time": dwell_time,
            "cross_protocol_pivot": cross_protocol_pivot,
            "technique_novelty": technique_novelty,
            "alert_quality": alert_quality,
            "analyst_feedback": analyst_feedback,
        }
    )


def _observed_reward(
    *,
    session: dict[str, Any],
    signals: dict[str, float],
    reward_weights: BanditRewardWeightsConfig,
) -> float:
    raw = session.get("bandit_reward")
    if raw is not None:
        try:
            return max(0.0, min(1.0, float(raw)))
        except (TypeError, ValueError):
            pass
    return compute_bandit_reward(weights=reward_weights, signals=signals)


def _counterfactual_reward(*, arm: str, observed_reward: float, signals: dict[str, float]) -> float:
    normalized_arm = arm.strip().lower()
    multiplier = 1.0
    if "credential" in normalized_arm:
        multiplier += (signals.get("alert_quality", 0.0) * 0.18) + (signals.get("analyst_feedback", 0.0) * 0.07)
    if any(token in normalized_arm for token in ("lateral", "pivot", "multi-protocol")):
        multiplier += (signals.get("cross_protocol_pivot", 0.0) * 0.25) + (signals.get("technique_novelty", 0.0) * 0.08)
    if "query" in normalized_arm:
        multiplier += (signals.get("technique_novelty", 0.0) * 0.15)
    if "backup" in normalized_arm:
        multiplier += (signals.get("dwell_time", 0.0) * 0.12)
    if "baseline" in normalized_arm:
        multiplier += 0.0
    multiplier = max(0.7, min(1.45, multiplier))
    return max(0.0, min(1.0, observed_reward * multiplier))


def _parse_iso_utc(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime.min.replace(tzinfo=UTC)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
