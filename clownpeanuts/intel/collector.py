"""Session-to-intelligence collector pipeline."""

from __future__ import annotations

from typing import Any

from clownpeanuts.config.schema import BanditRewardWeightsConfig
from clownpeanuts.intel.behavior import infer_kill_chain, summarize_kill_chain, summarize_kill_chain_graph, summarize_timing
from clownpeanuts.intel.biometrics import summarize_biometrics, summarize_session_biometrics
from clownpeanuts.intel.canary import summarize_canary_hits
from clownpeanuts.intel.classifier import classify_session
from clownpeanuts.intel.credentials import summarize_credential_reuse
from clownpeanuts.intel.fingerprints import fingerprint_events, summarize_fingerprints
from clownpeanuts.intel.mitre import summarize_coverage, summarize_techniques
from clownpeanuts.intel.reward import compute_bandit_reward, normalize_reward_signals
from clownpeanuts.intel.scoring import score_narrative_coherence, score_session
from clownpeanuts.intel.source import enrich_source_ip, summarize_sources


def build_intelligence_report(
    sessions: list[dict[str, Any]],
    *,
    bandit_reward_weights: BanditRewardWeightsConfig | None = None,
) -> dict[str, Any]:
    session_reports: list[dict[str, Any]] = []
    flattened_events: list[dict[str, Any]] = []
    kill_chain_sequences: list[list[str]] = []
    session_fingerprints: list[list[dict[str, Any]]] = []
    source_contexts: list[dict[str, Any]] = []
    session_biometrics: list[dict[str, Any]] = []
    total_score = 0.0
    total_coherence = 0.0
    total_coherence_violations = 0
    total_bandit_reward = 0.0
    total_duration_seconds = 0.0
    profile_counts: dict[str, int] = {}
    reward_weights = bandit_reward_weights or BanditRewardWeightsConfig()

    for session in sessions:
        events: list[dict[str, Any]] = []
        raw_events = session.get("events", [])
        if isinstance(raw_events, list):
            for event in raw_events:
                if isinstance(event, dict):
                    events.append(event)
                    flattened_events.append(event)
        score = score_session(session)
        total_score += float(score.get("score", 0.0) or 0.0)
        coherence = score_narrative_coherence(session)
        coherence_score = float(coherence.get("score", 0.0) or 0.0)
        coherence_violations = coherence.get("violations", [])
        if not isinstance(coherence_violations, list):
            coherence_violations = []
        total_coherence += coherence_score
        total_coherence_violations += len(coherence_violations)
        classification = classify_session(session)
        timing = summarize_timing(events)
        total_duration_seconds += float(timing.get("duration_seconds", 0.0) or 0.0)
        kill_chain = infer_kill_chain(events)
        kill_chain_sequences.append(kill_chain)
        fingerprints = fingerprint_events(events)
        session_fingerprints.append(fingerprints)
        source_context = enrich_source_ip(str(session.get("source_ip", "")))
        source_contexts.append(source_context)
        biometrics = summarize_session_biometrics(events)
        session_biometrics.append(biometrics)
        reward_signals = _session_reward_signals(
            session=session,
            events=events,
            timing=timing,
            engagement_score=score,
            kill_chain=kill_chain,
        )
        bandit_reward = compute_bandit_reward(weights=reward_weights, signals=reward_signals)
        total_bandit_reward += bandit_reward
        label = str(classification.get("label", "Unknown"))
        profile_counts[label] = profile_counts.get(label, 0) + 1
        session_reports.append(
            {
                "session_id": session.get("session_id", ""),
                "source_ip": session.get("source_ip", ""),
                "created_at": session.get("created_at", ""),
                "event_count": session.get("event_count", 0),
                "source_context": source_context,
                "classification": classification,
                "engagement_score": score,
                "coherence_score": round(coherence_score, 3),
                "coherence_violations": [str(item) for item in coherence_violations if str(item).strip()],
                "coherence_signals": coherence.get("signals", {}),
                "bandit_reward": round(bandit_reward, 6),
                "bandit_reward_signals": reward_signals,
                "biometrics": biometrics,
                "timing": timing,
                "kill_chain": kill_chain,
                "tool_fingerprints": fingerprints,
            }
        )

    profiles = [{"label": label, "count": count} for label, count in sorted(profile_counts.items())]
    techniques_summary = summarize_techniques(flattened_events)
    coverage_summary = summarize_coverage(techniques_summary)
    canary_summary = summarize_canary_hits(flattened_events)
    fingerprint_summary = summarize_fingerprints(session_fingerprints)
    kill_chain_summary = summarize_kill_chain(kill_chain_sequences)
    kill_chain_graph = summarize_kill_chain_graph(kill_chain_sequences)
    credential_reuse = summarize_credential_reuse(sessions)
    source_summary = summarize_sources(source_contexts)
    biometrics_summary = summarize_biometrics(session_biometrics)
    fingerprinted_sessions = sum(1 for item in session_fingerprints if item)

    return {
        "sessions": session_reports,
        "techniques": techniques_summary,
        "coverage": coverage_summary,
        "profiles": profiles,
        "canaries": canary_summary,
        "fingerprints": fingerprint_summary,
        "kill_chain": kill_chain_summary,
        "kill_chain_graph": kill_chain_graph,
        "credential_reuse": credential_reuse,
        "geography": source_summary,
        "biometrics": biometrics_summary,
        "totals": {
            "sessions": len(sessions),
            "events": sum(int(item.get("event_count", 0) or 0) for item in sessions),
            "engagement_score_avg": round(total_score / len(sessions), 2) if sessions else 0.0,
            "coherence_score_avg": round(total_coherence / len(sessions), 3) if sessions else 0.0,
            "coherence_violations": total_coherence_violations,
            "bandit_reward_avg": round(total_bandit_reward / len(sessions), 6) if sessions else 0.0,
            "canary_hits": int(canary_summary.get("total_hits", 0)),
            "fingerprinted_sessions": fingerprinted_sessions,
            "avg_session_duration_seconds": round(total_duration_seconds / len(sessions), 3) if sessions else 0.0,
            "kill_chain_progressed_sessions": int(kill_chain_summary.get("sessions_with_progression", 0)),
            "unique_asns": int(source_summary.get("unique_asns", 0)),
            "unique_countries": int(source_summary.get("unique_countries", 0)),
            "automated_sessions": int(biometrics_summary.get("automated_sessions", 0)),
            "mitre_coverage_percent": float(coverage_summary.get("coverage_percent", 0.0) or 0.0),
        },
    }


def _session_reward_signals(
    *,
    session: dict[str, Any],
    events: list[dict[str, Any]],
    timing: dict[str, Any],
    engagement_score: dict[str, Any],
    kill_chain: list[str],
) -> dict[str, float]:
    duration_seconds = max(0.0, float(timing.get("duration_seconds", 0.0) or 0.0))
    dwell_time = min(1.0, duration_seconds / 900.0)

    unique_services = {
        str(event.get("service", "")).strip().lower()
        for event in events
        if isinstance(event, dict) and str(event.get("service", "")).strip()
    }
    cross_protocol_pivot = 1.0 if len(unique_services) >= 2 else 0.0

    technique_summary = summarize_techniques(events)
    technique_novelty = min(1.0, float(len(technique_summary)) / 6.0)

    alert_quality = min(1.0, max(0.0, float(engagement_score.get("score", 0.0) or 0.0) / 100.0))

    analyst_feedback = 0.0
    feedback_raw = session.get("analyst_feedback", 0.0)
    try:
        analyst_feedback = float(feedback_raw or 0.0)
    except (TypeError, ValueError):
        analyst_feedback = 0.0
    if kill_chain:
        analyst_feedback = max(analyst_feedback, min(1.0, float(len(kill_chain)) / 6.0))

    return normalize_reward_signals(
        {
            "dwell_time": dwell_time,
            "cross_protocol_pivot": cross_protocol_pivot,
            "technique_novelty": technique_novelty,
            "alert_quality": alert_quality,
            "analyst_feedback": analyst_feedback,
        }
    )
