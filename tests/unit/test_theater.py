from clownpeanuts.config.schema import TheaterConfig
from clownpeanuts.dashboard.theater import TheaterService


def _session_fixture() -> dict[str, object]:
    return {
        "session_id": "theater-s1",
        "source_ip": "203.0.113.44",
        "created_at": "2026-02-01T00:00:00+00:00",
        "event_count": 3,
        "narrative": {
            "context_id": "ctx-1",
            "world_id": "world-1",
            "discovery_depth": 2,
            "touched_services": ["ssh", "http_admin"],
        },
        "events": [
            {
                "timestamp": "2026-02-01T00:00:01+00:00",
                "service": "ssh",
                "action": "command",
                "payload": {"command": "whoami"},
            },
            {
                "timestamp": "2026-02-01T00:00:02+00:00",
                "service": "ssh",
                "action": "command",
                "payload": {"command": "ip a"},
            },
            {
                "timestamp": "2026-02-01T00:00:03+00:00",
                "service": "http_admin",
                "action": "http_request",
                "payload": {"path": "/admin"},
            },
        ],
    }


def test_theater_live_view_includes_prediction_confidence_and_latency_budget() -> None:
    service = TheaterService(
        TheaterConfig(
            enabled=True,
            rollout_mode="recommend-only",
            max_live_sessions=10,
            recommendation_cooldown_seconds=5.0,
        )
    )
    payload = service.build_live_view(
        sessions=[_session_fixture()],
        bandit_metrics={"reward_avg": 0.72, "exploration_ratio": 0.2},
    )

    assert payload["enabled"] is True
    assert payload["count"] == 1
    assert payload["within_latency_budget"] is True
    assert payload["bandit_metrics"]["reward_avg"] == 0.72
    session = payload["sessions"][0]
    prediction = session["prediction"]
    assert prediction["predicted_action"]
    assert 0.0 <= float(prediction["confidence"]) <= 1.0
    recommendation = session["recommendation"]
    assert "explanation" in recommendation
    assert "explanation_digest" in recommendation
    assert "components" in recommendation["explanation"]
    assert "fallback" in recommendation["explanation"]


def test_theater_recommendations_allow_apply_when_mode_is_apply_enabled() -> None:
    service = TheaterService(
        TheaterConfig(
            enabled=True,
            rollout_mode="apply-enabled",
            max_live_sessions=10,
            recommendation_cooldown_seconds=5.0,
        )
    )
    payload = service.build_recommendations(
        sessions=[_session_fixture()],
        limit=5,
        bandit_metrics={"reward_avg": 0.65, "exploration_ratio": 0.15},
    )
    assert payload["count"] == 1
    assert payload["recommendations"][0]["apply_allowed"] is True


def test_theater_recommendations_apply_fallback_when_bandit_exploration_is_high() -> None:
    service = TheaterService(
        TheaterConfig(
            enabled=True,
            rollout_mode="recommend-only",
            max_live_sessions=10,
            recommendation_cooldown_seconds=5.0,
        )
    )
    payload = service.build_recommendations(
        sessions=[_session_fixture()],
        limit=5,
        bandit_metrics={"reward_avg": 0.4, "exploration_ratio": 0.95},
    )
    recommendation = payload["recommendations"][0]
    assert recommendation["explanation"]["fallback"]["applied"] is True
    assert recommendation["recommended_lure_arm"] == "generic-baseline"


def test_theater_recommendation_ids_are_not_predictable() -> None:
    service = TheaterService(
        TheaterConfig(
            enabled=True,
            rollout_mode="recommend-only",
            max_live_sessions=10,
            recommendation_cooldown_seconds=5.0,
        )
    )
    first = service.build_recommendations(
        sessions=[_session_fixture()],
        limit=5,
        bandit_metrics={"reward_avg": 0.65, "exploration_ratio": 0.2},
    )["recommendations"][0]["recommendation_id"]
    second = service.build_recommendations(
        sessions=[_session_fixture()],
        limit=5,
        bandit_metrics={"reward_avg": 0.65, "exploration_ratio": 0.2},
    )["recommendations"][0]["recommendation_id"]

    assert isinstance(first, str)
    assert isinstance(second, str)
    assert first.startswith("rec-")
    assert second.startswith("rec-")
    assert first != second
