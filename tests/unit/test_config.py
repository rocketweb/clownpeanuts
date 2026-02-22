import pytest

from pathlib import Path

from clownpeanuts.config.loader import load_config
from clownpeanuts.config.schema import parse_config
from clownpeanuts.core.event_bus import EventBus
from clownpeanuts.core.session import SessionManager


def test_load_defaults() -> None:
    config = load_config(Path("clownpeanuts/config/defaults.yml"))
    assert config.environment == "development"
    assert config.services
    assert config.services[0].name == "ssh"
    assert config.logging.fmt == "ecs_json"
    assert config.network.require_segmentation is True
    assert config.network.verify_host_firewall is False
    assert config.network.verify_docker_network is False
    assert config.session.backend == "redis"
    assert SessionManager._redis_url_has_credentials(config.session.redis_url)
    assert config.session.max_events_per_session == 2000
    assert config.event_bus.backend == "redis"
    assert EventBus._redis_url_has_credentials(config.event_bus.redis_url)
    assert config.api.docs_enabled is False
    assert config.api.cors_allow_origins == [
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:3001",
        "http://localhost:3001",
    ]
    assert config.api.cors_allow_credentials is False
    assert config.api.intel_report_cache_ttl_seconds == 1.5
    assert config.api.trusted_hosts == ["*"]
    assert config.api.auth_enabled is False
    assert config.api.auth_operator_tokens == []
    assert config.api.auth_viewer_tokens == []
    assert config.api.allow_unauthenticated_health is True
    assert config.api.rate_limit_enabled is False
    assert config.api.rate_limit_requests_per_minute == 240
    assert config.api.rate_limit_burst == 60
    assert config.api.rate_limit_exempt_paths == ["/health"]
    assert config.api.max_request_body_bytes == 262144
    assert config.engine.backend == "rule-based"
    assert config.engine.local_llm.enabled is False
    assert config.engine.local_llm.provider == "lmstudio"
    assert config.engine.local_llm.endpoint == "http://masoc:1234/v1/chat/completions"
    assert config.engine.local_llm.failure_threshold == 3
    assert config.engine.local_llm.cooldown_seconds == 15.0
    assert config.narrative.enabled is False
    assert config.narrative.world_seed == "clownpeanuts"
    assert config.narrative.entity_count == 120
    assert config.bandit.enabled is False
    assert config.bandit.algorithm == "thompson"
    assert config.bandit.exploration_floor == 0.1
    assert config.theater.enabled is False
    assert config.theater.rollout_mode == "observe-only"
    assert config.ecosystem.enabled is False
    assert config.ecosystem.drift_alert_threshold == 0.7
    assert config.ecosystem.witchbait_credentials == []
    assert config.ecosystem.jit.enabled is False
    assert config.ecosystem.jit.pool_size == 10
    assert config.ecosystem.jit.ttl_idle_seconds == 14400
    assert config.ecosystem.jit.ttl_max_seconds == 86400
    assert config.agents.pripyatsprings.enabled is False
    assert config.agents.pripyatsprings.backend == ""
    assert config.agents.pripyatsprings.default_toxicity == 2
    assert config.agents.pripyatsprings.store_path == ""
    assert config.agents.adlibs.enabled is False
    assert config.agents.adlibs.backend == ""
    assert config.agents.adlibs.event_log_source == "wef"
    assert config.agents.adlibs.store_path == ""
    assert config.agents.dirtylaundry.enabled is False
    assert config.agents.dirtylaundry.backend == ""
    assert config.agents.dirtylaundry.match_threshold == 0.75
    assert config.agents.dirtylaundry.profile_store_path == ""
    assert config.agents.dirtylaundry.max_profiles == 10000
    assert config.agents.dirtylaundry.max_sessions_per_profile == 500
    assert config.agents.dirtylaundry.max_notes_per_profile == 200
    assert config.agents.dirtylaundry.sharing.request_timeout_seconds == 5.0
    assert config.agents.dirtylaundry.sharing.headers == {}
    assert config.logging.siem.batch_size == 50
    assert any(service.name == "memcached-db" for service in config.services)
    assert any(destination.destination_type == "email" for destination in config.alerts.destinations)
    assert any(destination.destination_type == "pagerduty" for destination in config.alerts.destinations)


def test_load_production_hardened_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CP_REDIS_PASSWORD", "unit-test-redis-password")
    monkeypatch.setenv("CP_API_OPERATOR_TOKEN", "unit-test-operator-token-0123456789")
    monkeypatch.setenv("CP_API_VIEWER_TOKEN", "unit-test-viewer-token-0123456789")
    config = load_config(Path("config/production-hardened.yml"))
    assert config.environment == "production"
    assert config.network.require_segmentation is True
    assert config.network.verify_host_firewall is True
    assert config.network.verify_docker_network is True
    assert config.session.backend == "redis"
    assert config.session.required is True
    assert SessionManager._redis_url_has_credentials(config.session.redis_url)
    assert config.event_bus.backend == "redis"
    assert config.event_bus.required is True
    assert EventBus._redis_url_has_credentials(config.event_bus.redis_url)
    assert config.api.docs_enabled is False
    assert config.api.auth_enabled is True
    assert config.api.allow_unauthenticated_health is False
    assert config.api.rate_limit_enabled is True
    assert config.api.rate_limit_requests_per_minute == 600
    assert config.api.rate_limit_burst == 120
    assert config.api.rate_limit_exempt_paths == ["/health"]
    assert config.api.max_request_body_bytes == 131072
    assert config.api.cors_allow_origins == ["https://soc.example"]
    assert config.api.trusted_hosts == ["api.soc.example"]
    assert config.alerts.enabled is False
    assert len(config.services) >= 5


def test_load_production_reverse_proxy_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CP_REDIS_PASSWORD", "unit-test-redis-password")
    monkeypatch.setenv("CP_API_OPERATOR_TOKEN", "unit-test-operator-token-0123456789")
    monkeypatch.setenv("CP_API_VIEWER_TOKEN", "unit-test-viewer-token-0123456789")
    config = load_config(Path("config/production-reverse-proxy.yml"))
    assert config.environment == "production"
    assert config.network.require_segmentation is True
    assert config.session.backend == "redis"
    assert config.session.required is True
    assert SessionManager._redis_url_has_credentials(config.session.redis_url)
    assert config.event_bus.backend == "redis"
    assert config.event_bus.required is True
    assert EventBus._redis_url_has_credentials(config.event_bus.redis_url)
    assert config.api.docs_enabled is False
    assert config.api.auth_enabled is True
    assert config.api.allow_unauthenticated_health is False
    assert config.api.rate_limit_enabled is True
    assert config.api.rate_limit_requests_per_minute == 600
    assert config.api.rate_limit_burst == 120
    assert config.api.rate_limit_exempt_paths == ["/health"]
    assert config.api.max_request_body_bytes == 131072
    assert config.api.cors_allow_origins == ["https://soc.example", "https://dashboard.soc.example"]
    assert config.api.trusted_hosts == ["127.0.0.1", "localhost", "api.soc.example"]
    assert config.alerts.enabled is False
    assert len(config.services) >= 5


def test_load_sample_config_uses_credentialed_redis_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CP_REDIS_PASSWORD", "unit-test-redis-password")
    config = load_config(Path("config/clownpeanuts.yml"))
    assert config.session.backend == "redis"
    assert SessionManager._redis_url_has_credentials(config.session.redis_url)
    assert config.event_bus.backend == "redis"
    assert EventBus._redis_url_has_credentials(config.event_bus.redis_url)


def test_load_sample_config_requires_redis_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CP_REDIS_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="missing required environment variable 'CP_REDIS_PASSWORD'"):
        load_config(Path("config/clownpeanuts.yml"))


def test_load_production_hardened_requires_env_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CP_REDIS_PASSWORD", raising=False)
    monkeypatch.delenv("CP_API_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("CP_API_VIEWER_TOKEN", raising=False)
    with pytest.raises(ValueError, match="missing required environment variable 'CP_REDIS_PASSWORD'"):
        load_config(Path("config/production-hardened.yml"))

    monkeypatch.setenv("CP_REDIS_PASSWORD", "unit-test-redis-password")
    with pytest.raises(ValueError, match="missing required environment variable 'CP_API_OPERATOR_TOKEN'"):
        load_config(Path("config/production-hardened.yml"))

def test_parse_config_rejects_invalid_local_llm_provider() -> None:
    with pytest.raises(ValueError, match="invalid engine.local_llm provider"):
        parse_config(
            {
                "engine": {
                    "backend": "local-llm",
                    "local_llm": {
                        "enabled": True,
                        "provider": "invalid-provider",
                    },
                },
                "services": [],
            }
        )


def test_parse_config_sets_ollama_default_endpoint_when_provider_selected() -> None:
    config = parse_config(
        {
            "engine": {
                "backend": "local-llm",
                "local_llm": {
                    "enabled": True,
                    "provider": "ollama",
                    "model": "tiny-llm",
                },
            },
            "services": [],
        }
    )
    assert config.engine.local_llm.provider == "ollama"
    assert config.engine.local_llm.endpoint == "http://127.0.0.1:11434/api/generate"


def test_parse_config_rejects_invalid_local_llm_failure_threshold() -> None:
    with pytest.raises(ValueError, match="engine.local_llm failure_threshold"):
        parse_config(
            {
                "engine": {
                    "backend": "local-llm",
                    "local_llm": {
                        "enabled": True,
                        "provider": "lmstudio",
                        "failure_threshold": 0,
                    },
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_session_max_events() -> None:
    with pytest.raises(ValueError, match="session max_events_per_session"):
        parse_config(
            {
                "session": {
                    "max_events_per_session": 0,
                },
                "services": [],
            }
        )


def test_parse_config_accepts_api_hardening_section() -> None:
    config = parse_config(
        {
            "api": {
                "docs_enabled": False,
                "cors_allow_origins": ["https://soc.example"],
                "cors_allow_credentials": False,
                "intel_report_cache_ttl_seconds": 2.5,
                "trusted_hosts": ["soc.example", "127.0.0.1"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 180,
                "rate_limit_burst": 20,
                "rate_limit_exempt_paths": ["/health", "doctor"],
                "max_request_body_bytes": 65536,
            },
            "services": [],
        }
    )
    assert config.api.docs_enabled is False
    assert config.api.cors_allow_origins == ["https://soc.example"]
    assert config.api.cors_allow_credentials is False
    assert config.api.intel_report_cache_ttl_seconds == 2.5
    assert config.api.trusted_hosts == ["soc.example", "127.0.0.1"]
    assert config.api.rate_limit_enabled is True
    assert config.api.rate_limit_requests_per_minute == 180
    assert config.api.rate_limit_burst == 20
    assert config.api.rate_limit_exempt_paths == ["/health", "/doctor"]
    assert config.api.max_request_body_bytes == 65536


def test_parse_config_accepts_api_auth_section() -> None:
    config = parse_config(
        {
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": [
                    "operator-token-0123456789abcdef",
                    "operator-token-0123456789abcdef",
                    "  ",
                ],
                "auth_viewer_tokens": ["viewer-token-0123456789abcdef"],
                "allow_unauthenticated_health": False,
            },
            "services": [],
        }
    )
    assert config.api.auth_enabled is True
    assert config.api.auth_operator_tokens == ["operator-token-0123456789abcdef"]
    assert config.api.auth_viewer_tokens == ["viewer-token-0123456789abcdef"]
    assert config.api.allow_unauthenticated_health is False


def test_parse_config_rejects_api_auth_without_tokens() -> None:
    with pytest.raises(ValueError, match="api auth_enabled requires at least one token"):
        parse_config(
            {
                "api": {
                    "auth_enabled": True,
                },
                "services": [],
            }
        )


def test_parse_config_rejects_short_api_auth_tokens() -> None:
    with pytest.raises(ValueError, match="api auth tokens must be at least 16 characters"):
        parse_config(
            {
                "api": {
                    "auth_enabled": True,
                    "auth_operator_tokens": ["too-short"],
                },
                "services": [],
            }
        )


def test_parse_config_rejects_wildcard_origin_with_credentials() -> None:
    with pytest.raises(ValueError, match="api.cors_allow_credentials cannot be true"):
        parse_config(
            {
                "api": {
                    "cors_allow_origins": ["*"],
                    "cors_allow_credentials": True,
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_api_cors_allow_origins() -> None:
    with pytest.raises(ValueError, match="api.cors_allow_origins"):
        parse_config(
            {
                "api": {
                    "cors_allow_origins": "https://soc.example",
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_api_intel_report_cache_ttl_seconds() -> None:
    with pytest.raises(ValueError, match="api intel_report_cache_ttl_seconds"):
        parse_config(
            {
                "api": {
                    "intel_report_cache_ttl_seconds": -1,
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_api_rate_limit_requests_per_minute() -> None:
    with pytest.raises(ValueError, match="api rate_limit_requests_per_minute"):
        parse_config(
            {
                "api": {
                    "rate_limit_requests_per_minute": 0,
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_api_rate_limit_exempt_paths() -> None:
    with pytest.raises(ValueError, match="api.rate_limit_exempt_paths"):
        parse_config(
            {
                "api": {
                    "rate_limit_exempt_paths": "health",
                },
                "services": [],
            }
        )


def test_parse_config_rejects_wildcard_api_rate_limit_exempt_paths() -> None:
    with pytest.raises(ValueError, match="cannot include wildcard"):
        parse_config(
            {
                "api": {
                    "rate_limit_exempt_paths": ["/health", "*"],
                },
                "services": [],
            }
        )


def test_parse_config_rejects_too_many_api_rate_limit_exempt_paths() -> None:
    with pytest.raises(ValueError, match="at most 16 entries"):
        parse_config(
            {
                "api": {
                    "rate_limit_exempt_paths": [f"/path-{index}" for index in range(17)],
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_api_max_request_body_bytes() -> None:
    with pytest.raises(ValueError, match="api max_request_body_bytes"):
        parse_config(
            {
                "api": {
                    "max_request_body_bytes": 512,
                },
                "services": [],
            }
        )


def test_parse_config_accepts_narrative_bandit_theater_sections() -> None:
    config = parse_config(
        {
            "narrative": {
                "enabled": True,
                "world_seed": "acme-world",
                "entity_count": 250,
                "per_tenant_worlds": False,
            },
            "bandit": {
                "enabled": True,
                "algorithm": "ucb",
                "exploration_floor": 0.2,
                "reward_weights": {
                    "dwell_time": 2.0,
                    "cross_protocol_pivot": 1.5,
                    "technique_novelty": 1.1,
                    "alert_quality": 0.7,
                    "analyst_feedback": 1.4,
                },
                "safety_caps": {
                    "max_arm_exposure_percent": 0.6,
                    "cooldown_seconds": 45.0,
                    "denylist": ["aggressive_exfil", "aggressive_exfil", " "],
                },
            },
            "theater": {
                "enabled": True,
                "rollout_mode": "recommend-only",
                "max_live_sessions": 120,
                "recommendation_cooldown_seconds": 12.5,
            },
            "services": [],
        }
    )
    assert config.narrative.enabled is True
    assert config.narrative.world_seed == "acme-world"
    assert config.narrative.entity_count == 250
    assert config.narrative.per_tenant_worlds is False
    assert config.bandit.enabled is True
    assert config.bandit.algorithm == "ucb"
    assert config.bandit.exploration_floor == 0.2
    assert config.bandit.reward_weights.dwell_time == 2.0
    assert config.bandit.safety_caps.max_arm_exposure_percent == 0.6
    assert config.bandit.safety_caps.cooldown_seconds == 45.0
    assert config.bandit.safety_caps.denylist == ["aggressive_exfil"]
    assert config.theater.enabled is True
    assert config.theater.rollout_mode == "recommend-only"
    assert config.theater.max_live_sessions == 120
    assert config.theater.recommendation_cooldown_seconds == 12.5


def test_parse_config_accepts_ecosystem_section() -> None:
    config = parse_config(
        {
            "ecosystem": {
                "enabled": True,
                "drift_alert_threshold": 0.8,
                "witchbait_credentials": [
                    {
                        "credential_id": "seed-1",
                        "credential_value": "secret-value-1",
                        "credential_type": "password",
                    }
                ],
                "jit": {
                    "enabled": True,
                    "pool_size": 3,
                    "ttl_idle_seconds": 600,
                    "ttl_max_seconds": 1800,
                },
            },
            "services": [],
        }
    )
    assert config.ecosystem.enabled is True
    assert config.ecosystem.drift_alert_threshold == 0.8
    assert len(config.ecosystem.witchbait_credentials) == 1
    assert config.ecosystem.jit.enabled is True
    assert config.ecosystem.jit.pool_size == 3
    assert config.ecosystem.jit.ttl_idle_seconds == 600
    assert config.ecosystem.jit.ttl_max_seconds == 1800


def test_parse_config_rejects_invalid_ecosystem_section() -> None:
    with pytest.raises(ValueError, match="'ecosystem' must be an object"):
        parse_config(
            {
                "ecosystem": "enabled",
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_ecosystem_drift_alert_threshold() -> None:
    with pytest.raises(ValueError, match="ecosystem.drift_alert_threshold"):
        parse_config(
            {
                "ecosystem": {"enabled": True, "drift_alert_threshold": 1.5},
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_ecosystem_jit_section() -> None:
    with pytest.raises(ValueError, match="ecosystem.jit.pool_size"):
        parse_config(
            {
                "ecosystem": {
                    "enabled": True,
                    "jit": {"enabled": True, "pool_size": 0},
                },
                "services": [],
            }
        )


def test_parse_config_accepts_agents_section() -> None:
    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "pripyatsprings": {
                    "enabled": True,
                    "backend": "private.pripyatsprings.runtime:Backend",
                    "default_toxicity": 3,
                    "tracking_domain": "t.example.com",
                    "canary_dns_domain": "c.example.com",
                    "tracking_server_port": 9443,
                    "level3_acknowledgment": "matt-2026-02-21",
                    "per_emulator_overrides": {"ssh": 2},
                    "store_path": "data/pripyatsprings.sqlite3",
                },
                "adlibs": {
                    "enabled": True,
                    "backend": "private.adlibs.runtime:Backend",
                    "event_log_source": "sysmon",
                    "fake_users": 4,
                    "fake_service_accounts": 2,
                    "fake_groups": 1,
                    "store_path": "data/adlibs.sqlite3",
                },
                "dirtylaundry": {
                    "enabled": True,
                    "backend": "private.dirtylaundry.runtime:Backend",
                    "matching_window_seconds": 120,
                    "match_threshold": 0.8,
                    "profile_store_path": "data/dirtylaundry.sqlite3",
                    "max_profiles": 4000,
                    "max_sessions_per_profile": 250,
                    "max_notes_per_profile": 150,
                    "sharing": {
                        "enabled": True,
                        "endpoint": "https://sharing.example",
                        "export_interval_hours": 12,
                        "request_timeout_seconds": 8.5,
                        "headers": {
                            "Authorization": "Bearer shared-token",
                            "X-Route": "cluster-a",
                        },
                    },
                },
            },
            "services": [],
        }
    )
    assert config.agents.pripyatsprings.enabled is True
    assert config.agents.pripyatsprings.backend == "private.pripyatsprings.runtime:Backend"
    assert config.agents.pripyatsprings.default_toxicity == 3
    assert config.agents.pripyatsprings.tracking_server_port == 9443
    assert config.agents.pripyatsprings.per_emulator_overrides == {"ssh": 2}
    assert config.agents.pripyatsprings.store_path == "data/pripyatsprings.sqlite3"
    assert config.agents.adlibs.enabled is True
    assert config.agents.adlibs.backend == "private.adlibs.runtime:Backend"
    assert config.agents.adlibs.event_log_source == "sysmon"
    assert config.agents.adlibs.store_path == "data/adlibs.sqlite3"
    assert config.agents.dirtylaundry.enabled is True
    assert config.agents.dirtylaundry.backend == "private.dirtylaundry.runtime:Backend"
    assert config.agents.dirtylaundry.matching_window_seconds == 120
    assert config.agents.dirtylaundry.profile_store_path == "data/dirtylaundry.sqlite3"
    assert config.agents.dirtylaundry.max_profiles == 4000
    assert config.agents.dirtylaundry.max_sessions_per_profile == 250
    assert config.agents.dirtylaundry.max_notes_per_profile == 150
    assert config.agents.dirtylaundry.sharing.enabled is True
    assert config.agents.dirtylaundry.sharing.endpoint == "https://sharing.example"
    assert config.agents.dirtylaundry.sharing.request_timeout_seconds == 8.5
    assert config.agents.dirtylaundry.sharing.headers == {
        "Authorization": "Bearer shared-token",
        "X-Route": "cluster-a",
    }


def test_parse_config_rejects_invalid_agents_adlibs_event_log_source() -> None:
    with pytest.raises(ValueError, match="agents.adlibs.event_log_source"):
        parse_config(
            {
                "agents": {
                    "adlibs": {
                        "enabled": True,
                        "event_log_source": "invalid",
                    }
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_agents_dirtylaundry_caps() -> None:
    with pytest.raises(ValueError, match="agents.dirtylaundry.max_profiles"):
        parse_config(
            {
                "agents": {
                    "dirtylaundry": {
                        "enabled": True,
                        "max_profiles": 0,
                    }
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_agents_dirtylaundry_sharing_timeout() -> None:
    with pytest.raises(ValueError, match="agents.dirtylaundry.sharing.request_timeout_seconds"):
        parse_config(
            {
                "agents": {
                    "dirtylaundry": {
                        "enabled": True,
                        "sharing": {
                            "enabled": True,
                            "request_timeout_seconds": 0.1,
                        },
                    }
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_agents_dirtylaundry_sharing_headers_type() -> None:
    with pytest.raises(ValueError, match="agents.dirtylaundry.sharing.headers"):
        parse_config(
            {
                "agents": {
                    "dirtylaundry": {
                        "enabled": True,
                        "sharing": {
                            "enabled": True,
                            "headers": ["bad"],
                        },
                    }
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_narrative_entity_count() -> None:
    with pytest.raises(ValueError, match="narrative entity_count"):
        parse_config(
            {
                "narrative": {"entity_count": 0},
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_bandit_algorithm() -> None:
    with pytest.raises(ValueError, match="invalid bandit algorithm"):
        parse_config(
            {
                "bandit": {"algorithm": "epsilon-greedy"},
                "services": [],
            }
        )


def test_parse_config_rejects_template_relative_path_escape() -> None:
    with pytest.raises(ValueError, match="templates.paths relative entries must stay within the current workspace root"):
        parse_config(
            {
                "templates": {
                    "enabled": True,
                    "paths": ["../../etc/passwd"],
                },
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_bandit_exploration_floor() -> None:
    with pytest.raises(ValueError, match="bandit exploration_floor"):
        parse_config(
            {
                "bandit": {"exploration_floor": 1.5},
                "services": [],
            }
        )


def test_parse_config_rejects_invalid_theater_rollout_mode() -> None:
    with pytest.raises(ValueError, match="invalid theater rollout_mode"):
        parse_config(
            {
                "theater": {"rollout_mode": "fully-auto"},
                "services": [],
            }
        )


def test_load_config_interpolates_local_llm_env_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LM_STUDIO_API_KEY", "secret-token")
    monkeypatch.delenv("LM_HOST", raising=False)

    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "\n".join(
            [
                "engine:",
                "  backend: local-llm",
                "  local_llm:",
                "    enabled: true",
                "    provider: lmstudio",
                "    endpoint: \"http://${LM_HOST:-masoc}:1234/v1/chat/completions\"",
                "    api_key: \"${LM_STUDIO_API_KEY}\"",
                "services: []",
                "",
            ]
        ),
        encoding="utf-8",
    )

    config = load_config(config_path)
    assert config.engine.local_llm.endpoint == "http://masoc:1234/v1/chat/completions"
    assert config.engine.local_llm.api_key == "secret-token"


def test_load_config_raises_when_required_env_var_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LM_STUDIO_API_KEY", raising=False)

    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "\n".join(
            [
                "engine:",
                "  backend: local-llm",
                "  local_llm:",
                "    enabled: true",
                "    provider: lmstudio",
                "    api_key: \"${LM_STUDIO_API_KEY}\"",
                "services: []",
                "",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing required environment variable 'LM_STUDIO_API_KEY'"):
        load_config(config_path)
