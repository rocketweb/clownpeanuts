from clownpeanuts.config.schema import LocalLLMConfig, parse_config
from clownpeanuts.core.doctor import probe_local_llm_endpoint, run_diagnostics


class _FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


def test_run_diagnostics_passes_for_default_minimal_config() -> None:
    config = parse_config({"services": []})
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is True
    assert any(item["name"] == "network_policy" for item in report["checks"])
    assert any(item["name"] == "template_validation" for item in report["checks"])
    assert any(item["name"] == "alerts_config" for item in report["checks"])
    assert any(item["name"] == "session_backend_auth" for item in report["checks"])
    assert any(item["name"] == "event_bus_backend_auth" for item in report["checks"])
    assert report["templates"]["ok"] is True
    assert report["alerts"]["ok"] is True


def test_run_diagnostics_fails_when_redis_backends_lack_auth_credentials() -> None:
    config = parse_config(
        {
            "session": {
                "backend": "redis",
                "redis_url": "redis://redis:6379/0",
            },
            "event_bus": {
                "backend": "redis",
                "redis_url": "redis://redis:6379/1",
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is False
    session_check = next(item for item in report["checks"] if item["name"] == "session_backend_auth")
    event_bus_check = next(item for item in report["checks"] if item["name"] == "event_bus_backend_auth")
    assert session_check["ok"] is False
    assert event_bus_check["ok"] is False
    assert "missing URL credentials" in session_check["detail"]
    assert "missing URL credentials" in event_bus_check["detail"]


def test_run_diagnostics_accepts_credentialed_redis_backends() -> None:
    config = parse_config(
        {
            "session": {
                "backend": "redis",
                "redis_url": "redis://:strong-password@redis:6379/0",
            },
            "event_bus": {
                "backend": "redis",
                "redis_url": "redis://:strong-password@redis:6379/1",
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is True
    session_check = next(item for item in report["checks"] if item["name"] == "session_backend_auth")
    event_bus_check = next(item for item in report["checks"] if item["name"] == "event_bus_backend_auth")
    assert session_check["ok"] is True
    assert event_bus_check["ok"] is True


def test_run_diagnostics_flags_known_default_credentials_outside_development() -> None:
    config = parse_config(
        {
            "environment": "staging",
            "session": {
                "backend": "redis",
                "redis_url": "redis://:clownpeanuts-dev-redis@redis:6379/0",
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    default_check = next(item for item in report["checks"] if item["name"] == "default_credentials")
    assert default_check["ok"] is False
    assert "known default credential" in default_check["detail"]


def test_run_diagnostics_allows_known_default_credentials_in_development() -> None:
    config = parse_config(
        {
            "environment": "development",
            "session": {
                "backend": "redis",
                "redis_url": "redis://:clownpeanuts-dev-redis@redis:6379/0",
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    default_check = next(item for item in report["checks"] if item["name"] == "default_credentials")
    assert default_check["ok"] is True
    assert "development profile" in default_check["detail"]


def test_run_diagnostics_flags_weak_production_api_hardening() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": False,
                "docs_enabled": True,
                "cors_allow_origins": ["*"],
                "trusted_hosts": ["*"],
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "api.auth_enabled=true" in hardening_check["detail"]


def test_run_diagnostics_flags_missing_production_operator_tokens() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": [],
                "auth_viewer_tokens": ["viewer-token-0123456789abcdef"],
                "cors_allow_origins": ["https://soc.example"],
                "trusted_hosts": ["api.soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "auth_operator_tokens" in hardening_check["detail"]


def test_run_diagnostics_flags_overlapping_production_operator_viewer_tokens() -> None:
    shared = "shared-token-0123456789abcdef"
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": [shared],
                "auth_viewer_tokens": [shared],
                "cors_allow_origins": ["https://soc.example"],
                "trusted_hosts": ["api.soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "distinct" in hardening_check["detail"]


def test_run_diagnostics_flags_placeholder_production_api_tokens() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["replace-with-long-operator-token-0123456789"],
                "auth_viewer_tokens": ["viewer-token-0123456789abcdef"],
                "allow_unauthenticated_health": False,
                "cors_allow_origins": ["https://soc.example"],
                "trusted_hosts": ["api.soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "rate_limit_exempt_paths": ["/health"],
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "non-placeholder api.auth_operator_tokens" in hardening_check["detail"]


def test_run_diagnostics_flags_short_production_operator_tokens() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["1234567890abcdef"],
                "auth_viewer_tokens": ["viewer-token-0123456789abcdef"],
                "allow_unauthenticated_health": False,
                "cors_allow_origins": ["https://soc.example"],
                "trusted_hosts": ["api.soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "rate_limit_exempt_paths": ["/health"],
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "at least 24 characters" in hardening_check["detail"]


def test_run_diagnostics_flags_unauthenticated_health_in_production() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "auth_viewer_tokens": ["viewer-token-0123456789abcdef"],
                "allow_unauthenticated_health": True,
                "cors_allow_origins": ["https://soc.example"],
                "trusted_hosts": ["api.soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "rate_limit_exempt_paths": ["/health"],
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "allow_unauthenticated_health" in hardening_check["detail"]


def test_run_diagnostics_accepts_strict_production_api_hardening() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "auth_viewer_tokens": ["viewer-token-0123456789abcdef"],
                "allow_unauthenticated_health": False,
                "cors_allow_origins": ["https://soc.example"],
                "trusted_hosts": ["api.soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is True
    assert "auth enabled" in hardening_check["detail"]
    assert "body_limit=131072" in hardening_check["detail"]


def test_run_diagnostics_flags_missing_production_rate_limit() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "trusted_hosts": ["api.soc.example"],
                "cors_allow_origins": ["https://soc.example"],
                "rate_limit_enabled": False,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "rate_limit_enabled" in hardening_check["detail"]


def test_run_diagnostics_flags_excessive_production_request_body_limit() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "trusted_hosts": ["api.soc.example"],
                "cors_allow_origins": ["https://soc.example"],
                "allow_unauthenticated_health": False,
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "max_request_body_bytes": 2_000_000,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "max_request_body_bytes" in hardening_check["detail"]


def test_run_diagnostics_flags_unsafe_production_rate_limit_exempt_paths() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "trusted_hosts": ["api.soc.example"],
                "cors_allow_origins": ["https://soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 600,
                "rate_limit_exempt_paths": ["/health", "/status"],
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "rate_limit_exempt_paths" in hardening_check["detail"]


def test_run_diagnostics_flags_excessive_production_rate_limit_burst() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "trusted_hosts": ["api.soc.example"],
                "cors_allow_origins": ["https://soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 120,
                "rate_limit_burst": 500,
                "rate_limit_exempt_paths": ["/health"],
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "rate_limit_burst" in hardening_check["detail"]


def test_run_diagnostics_flags_excessive_production_rate_limit_requests() -> None:
    config = parse_config(
        {
            "environment": "production",
            "api": {
                "auth_enabled": True,
                "docs_enabled": False,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "trusted_hosts": ["api.soc.example"],
                "cors_allow_origins": ["https://soc.example"],
                "rate_limit_enabled": True,
                "rate_limit_requests_per_minute": 20000,
                "rate_limit_burst": 120,
                "rate_limit_exempt_paths": ["/health"],
                "max_request_body_bytes": 131072,
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    hardening_check = next(item for item in report["checks"] if item["name"] == "api_hardening_profile")
    assert hardening_check["ok"] is False
    assert "rate_limit_requests_per_minute" in hardening_check["detail"]


def test_run_diagnostics_fails_when_template_validation_fails(tmp_path) -> None:
    template_path = tmp_path / "template-invalid.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [\"bad\"]\n",
        encoding="utf-8",
    )
    config = parse_config(
        {
            "templates": {"enabled": True, "paths": [str(template_path)]},
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is False
    template_check = next(item for item in report["checks"] if item["name"] == "template_validation")
    assert template_check["ok"] is False
    assert report["templates"]["error_count"] >= 1


def test_run_diagnostics_validates_all_enabled_tenants(tmp_path) -> None:
    template_path = tmp_path / "template.yml"
    template_path.write_text(
        "templates:\n"
        "  - service: ssh\n"
        "    ports: [2222]\n",
        encoding="utf-8",
    )
    config = parse_config(
        {
            "templates": {"enabled": True, "paths": [str(template_path)]},
            "multi_tenant": {
                "enabled": True,
                "default_tenant": "tenant-a",
                "tenants": [
                    {"id": "tenant-a", "enabled": True},
                    {"id": "tenant-b", "enabled": True},
                ],
            },
            "services": [{"name": "ssh", "module": "clownpeanuts.services.ssh.emulator", "ports": [2222], "config": {}}],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is True
    assert report["templates"]["all_tenants"] is True
    assert report["templates"]["tenant_count"] == 2
    tenant_ids = {item["tenant"] for item in report["templates"]["tenants"]}
    assert tenant_ids == {"tenant-a", "tenant-b"}


def test_run_diagnostics_fails_with_invalid_alert_configuration() -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [
                    {"name": "bad-webhook", "type": "webhook", "enabled": True, "endpoint": "not-a-url"}
                ],
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is False
    alerts_check = next(item for item in report["checks"] if item["name"] == "alerts_config")
    assert alerts_check["ok"] is False
    assert report["alerts"]["ok"] is False
    assert report["alerts"]["invalid_destinations"]


def test_run_diagnostics_fails_when_alerts_enabled_without_destinations() -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [],
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is False
    alerts_check = next(item for item in report["checks"] if item["name"] == "alerts_config")
    assert alerts_check["ok"] is False


def test_run_diagnostics_fails_when_alert_action_filters_overlap() -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [
                    {
                        "name": "overlap",
                        "type": "webhook",
                        "enabled": True,
                        "endpoint": "https://example.test/webhook",
                        "include_actions": ["command"],
                        "exclude_actions": ["command"],
                    }
                ],
            },
            "services": [],
        }
    )
    report = run_diagnostics(config, check_llm=False)
    assert report["ok"] is False
    assert report["alerts"]["policy_destination_count"] == 1
    assert report["alerts"]["invalid_destinations"]
    assert "overlap" in report["alerts"]["invalid_destinations"][0]["reason"]


def test_probe_local_llm_endpoint_maps_lmstudio_models(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called = {"url": ""}

    def _urlopen(req, timeout):  # type: ignore[no-untyped-def]
        called["url"] = req.full_url
        assert timeout > 0
        return _FakeResponse(status=200)

    monkeypatch.setattr("clownpeanuts.core.doctor.request.urlopen", _urlopen)
    ok, detail = probe_local_llm_endpoint(
        LocalLLMConfig(
            enabled=True,
            provider="lmstudio",
            endpoint="http://masoc:1234/v1/chat/completions",
        )
    )
    assert ok is True
    assert "reachable" in detail
    assert called["url"] == "http://masoc:1234/v1/models"


def test_probe_local_llm_endpoint_maps_ollama_tags(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called = {"url": ""}

    def _urlopen(req, timeout):  # type: ignore[no-untyped-def]
        called["url"] = req.full_url
        assert timeout > 0
        return _FakeResponse(status=200)

    monkeypatch.setattr("clownpeanuts.core.doctor.request.urlopen", _urlopen)
    ok, _detail = probe_local_llm_endpoint(
        LocalLLMConfig(
            enabled=True,
            provider="ollama",
            endpoint="http://127.0.0.1:11434/api/generate",
        )
    )
    assert ok is True
    assert called["url"] == "http://127.0.0.1:11434/api/tags"
