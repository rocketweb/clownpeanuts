"""Operational diagnostics for local config/runtime readiness."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
from urllib import request

from clownpeanuts.config.schema import AppConfig, LocalLLMConfig
from clownpeanuts.core.network import NetworkIsolationManager
from clownpeanuts.core.tenant import TenantManager
from clownpeanuts.templates.deception import DeceptionTemplateLoader


@dataclass(slots=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


def run_diagnostics(
    config: AppConfig,
    *,
    check_llm: bool = False,
) -> dict[str, Any]:
    checks: list[DoctorCheck] = []

    network_report = NetworkIsolationManager().validate(config.network)
    checks.append(
        DoctorCheck(
            name="network_policy",
            ok=network_report.compliant,
            detail="; ".join(network_report.violations) if network_report.violations else "network policy valid",
        )
    )

    checks.append(
        DoctorCheck(
            name="session_backend",
            ok=config.session.backend in {"memory", "redis"},
            detail=f"session backend={config.session.backend}",
        )
    )
    checks.append(
        DoctorCheck(
            name="session_backend_auth",
            ok=(
                config.session.backend != "redis"
                or _redis_url_has_credentials(config.session.redis_url)
            ),
            detail=(
                "session redis auth configured"
                if config.session.backend == "redis" and _redis_url_has_credentials(config.session.redis_url)
                else (
                    "session backend is memory"
                    if config.session.backend != "redis"
                    else "session redis backend missing URL credentials"
                )
            ),
        )
    )
    checks.append(
        DoctorCheck(
            name="event_bus_backend",
            ok=config.event_bus.backend in {"memory", "redis"},
            detail=f"event bus backend={config.event_bus.backend}",
        )
    )
    checks.append(
        DoctorCheck(
            name="event_bus_backend_auth",
            ok=(
                config.event_bus.backend != "redis"
                or _redis_url_has_credentials(config.event_bus.redis_url)
            ),
            detail=(
                "event bus redis auth configured"
                if config.event_bus.backend == "redis" and _redis_url_has_credentials(config.event_bus.redis_url)
                else (
                    "event bus backend is memory"
                    if config.event_bus.backend != "redis"
                    else "event bus redis backend missing URL credentials"
                )
            ),
        )
    )
    default_credentials_ok, default_credentials_detail = _default_credentials_check(config)
    checks.append(
        DoctorCheck(
            name="default_credentials",
            ok=default_credentials_ok,
            detail=default_credentials_detail,
        )
    )
    api_hardening_ok, api_hardening_detail = _api_hardening_check(config)
    checks.append(
        DoctorCheck(
            name="api_hardening_profile",
            ok=api_hardening_ok,
            detail=api_hardening_detail,
        )
    )

    alerts_report = _alerts_diagnostics(config)
    checks.append(
        DoctorCheck(
            name="alerts_config",
            ok=bool(alerts_report.get("ok")),
            detail=str(alerts_report.get("detail", "alerts config check")),
        )
    )

    llm_enabled = config.engine.backend == "local-llm" and config.engine.local_llm.enabled
    checks.append(
        DoctorCheck(
            name="local_llm_config",
            ok=(config.engine.backend == "rule-based") or llm_enabled,
            detail=(
                "rule-based backend configured"
                if config.engine.backend == "rule-based"
                else (
                    f"provider={config.engine.local_llm.provider} endpoint={config.engine.local_llm.endpoint}"
                    if llm_enabled
                    else "local-llm backend selected but local_llm.enabled is false"
                )
            ),
        )
    )

    tenant_manager = TenantManager(config.multi_tenant)
    template_loader = DeceptionTemplateLoader(config.templates)
    tenant_targets: list[str] = []
    if config.multi_tenant.enabled:
        tenant_targets.extend([tenant.tenant_id for tenant in config.multi_tenant.tenants if tenant.enabled and tenant.tenant_id])
        default_tenant = config.multi_tenant.default_tenant.strip()
        if default_tenant:
            tenant_targets.append(default_tenant)
    if not tenant_targets:
        tenant_targets.append(config.multi_tenant.default_tenant)

    unique_targets: list[str] = []
    seen_targets: set[str] = set()
    for target in tenant_targets:
        normalized = target.strip()
        if not normalized or normalized in seen_targets:
            continue
        seen_targets.add(normalized)
        unique_targets.append(normalized)

    tenant_reports: list[dict[str, Any]] = []
    for target in unique_targets:
        tenant = tenant_manager.resolve_tenant(target)
        tenant_services = tenant_manager.apply_service_overrides(config.services, tenant)
        report = template_loader.validate(tenant_services)
        report["tenant"] = tenant.tenant_id
        report["service_count"] = len(tenant_services)
        tenant_reports.append(report)

    template_error_count = sum(max(0, int(item.get("error_count", 0))) for item in tenant_reports)
    template_warning_count = sum(max(0, int(item.get("warning_count", 0))) for item in tenant_reports)
    template_report = {
        "all_tenants": len(tenant_reports) > 1,
        "enabled": config.templates.enabled,
        "paths": [str(path) for path in config.templates.paths],
        "tenant_count": len(tenant_reports),
        "tenants": tenant_reports,
        "error_count": template_error_count,
        "warning_count": template_warning_count,
        "ok": all(bool(item.get("ok")) for item in tenant_reports),
    }
    checks.append(
        DoctorCheck(
            name="template_validation",
            ok=bool(template_report.get("ok")),
            detail=(
                f"errors={int(template_report.get('error_count', 0))} "
                f"warnings={int(template_report.get('warning_count', 0))}"
            ),
        )
    )

    if check_llm and llm_enabled:
        ok, detail = probe_local_llm_endpoint(config.engine.local_llm)
        checks.append(DoctorCheck(name="local_llm_probe", ok=ok, detail=detail))
    elif check_llm:
        checks.append(
            DoctorCheck(
                name="local_llm_probe",
                ok=True,
                detail="probe skipped (local llm backend not enabled)",
            )
        )

    return {
        "ok": all(item.ok for item in checks),
        "checks": [
            {
                "name": item.name,
                "ok": item.ok,
                "detail": item.detail,
            }
            for item in checks
        ],
        "network": {
            "compliant": network_report.compliant,
            "warnings": network_report.warnings,
            "violations": network_report.violations,
        },
        "alerts": alerts_report,
        "templates": template_report,
    }


def probe_local_llm_endpoint(config: LocalLLMConfig) -> tuple[bool, str]:
    if config.provider == "ollama":
        endpoint = _ollama_probe_endpoint(config.endpoint)
    else:
        endpoint = _lmstudio_probe_endpoint(config.endpoint)

    headers = {}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    req = request.Request(endpoint, headers=headers, method="GET")
    timeout_seconds = max(0.5, min(5.0, float(config.timeout_seconds)))
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            status_code = int(getattr(response, "status", 200))
        if 200 <= status_code < 500:
            return (True, f"reachable ({endpoint}) status={status_code}")
        return (False, f"unexpected status {status_code} from {endpoint}")
    except Exception as exc:
        return (False, f"unreachable ({endpoint}): {exc}")


def _lmstudio_probe_endpoint(endpoint: str) -> str:
    needle = "/v1/chat/completions"
    if endpoint.endswith(needle):
        return f"{endpoint[: -len(needle)]}/v1/models"
    return endpoint


def _ollama_probe_endpoint(endpoint: str) -> str:
    needle = "/api/generate"
    if endpoint.endswith(needle):
        return f"{endpoint[: -len(needle)]}/api/tags"
    return endpoint


def _alerts_diagnostics(config: AppConfig) -> dict[str, Any]:
    enabled_destinations = [destination for destination in config.alerts.destinations if destination.enabled]
    policy_destinations = [
        destination
        for destination in enabled_destinations
        if destination.min_severity
        or destination.include_services
        or destination.include_actions
        or destination.exclude_actions
    ]
    if not config.alerts.enabled:
        return {
            "ok": True,
            "enabled": False,
            "enabled_destination_count": len(enabled_destinations),
            "destination_count": len(config.alerts.destinations),
            "policy_destination_count": len(policy_destinations),
            "invalid_destinations": [],
            "detail": "alerts disabled",
        }
    if not enabled_destinations:
        return {
            "ok": False,
            "enabled": True,
            "enabled_destination_count": 0,
            "destination_count": len(config.alerts.destinations),
            "policy_destination_count": len(policy_destinations),
            "invalid_destinations": [],
            "detail": "alerts enabled but no destinations are enabled",
        }

    invalid: list[dict[str, str]] = []
    for destination in enabled_destinations:
        endpoint = destination.endpoint.strip()
        kind = destination.destination_type
        if kind in {"webhook", "slack", "discord"}:
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                invalid.append(
                    {
                        "name": destination.name,
                        "type": kind,
                        "reason": "endpoint must be http(s) URL",
                    }
                )
        elif kind == "syslog":
            host, _, port_raw = endpoint.rpartition(":")
            if not host or not port_raw.isdigit():
                invalid.append(
                    {
                        "name": destination.name,
                        "type": kind,
                        "reason": "endpoint must be host:port",
                    }
                )
        elif kind == "email":
            parsed = urlparse(endpoint if "://" in endpoint else f"smtp://{endpoint}")
            if parsed.scheme not in {"smtp", "smtps"} or not parsed.hostname:
                invalid.append(
                    {
                        "name": destination.name,
                        "type": kind,
                        "reason": "endpoint must be smtp:// or smtps:// with host",
                    }
                )
            recipients = destination.metadata.get("to", "").strip()
            if not recipients:
                invalid.append(
                    {
                        "name": destination.name,
                        "type": kind,
                        "reason": "metadata.to recipients required",
                    }
                )
        elif kind == "pagerduty":
            routing_key = destination.metadata.get("routing_key", "").strip() or destination.token.strip()
            if not routing_key:
                invalid.append(
                    {
                        "name": destination.name,
                        "type": kind,
                        "reason": "token or metadata.routing_key required",
                    }
                )

        overlap = sorted(set(destination.include_actions) & set(destination.exclude_actions))
        if overlap:
            invalid.append(
                {
                    "name": destination.name,
                    "type": kind,
                    "reason": f"include_actions/exclude_actions overlap ({', '.join(overlap)})",
                }
            )

    if invalid:
        names = ", ".join(item["name"] for item in invalid)
        detail = f"invalid alert destinations: {names}"
    else:
        detail = f"alerts enabled with {len(enabled_destinations)} enabled destinations"
    return {
        "ok": not bool(invalid),
        "enabled": True,
        "enabled_destination_count": len(enabled_destinations),
        "destination_count": len(config.alerts.destinations),
        "policy_destination_count": len(policy_destinations),
        "invalid_destinations": invalid,
        "detail": detail,
    }


def _api_hardening_check(config: AppConfig) -> tuple[bool, str]:
    minimum_token_length = 24

    def _is_placeholder_token(value: str) -> bool:
        normalized = value.strip().lower()
        if not normalized:
            return True
        if "replace-with-" in normalized:
            return True
        return normalized in {"replace-me", "change-me", "changeme", "replace_this"}

    environment = str(getattr(config, "environment", "")).strip().lower()
    if environment != "production":
        return (True, "api hardening check skipped outside production profiles")
    if not config.api.auth_enabled:
        return (False, "production profile requires api.auth_enabled=true")
    operator_tokens = [str(token).strip() for token in getattr(config.api, "auth_operator_tokens", []) if str(token).strip()]
    if not operator_tokens:
        return (False, "production profile requires at least one api.auth_operator_tokens entry")
    if any(len(token) < minimum_token_length for token in operator_tokens):
        return (
            False,
            f"production profile requires api.auth_operator_tokens values at least {minimum_token_length} characters",
        )
    if any(_is_placeholder_token(token) for token in operator_tokens):
        return (False, "production profile requires non-placeholder api.auth_operator_tokens values")
    viewer_tokens = [str(token).strip() for token in getattr(config.api, "auth_viewer_tokens", []) if str(token).strip()]
    if any(len(token) < minimum_token_length for token in viewer_tokens):
        return (
            False,
            f"production profile requires api.auth_viewer_tokens values at least {minimum_token_length} characters",
        )
    if any(_is_placeholder_token(token) for token in viewer_tokens):
        return (False, "production profile requires non-placeholder api.auth_viewer_tokens values")
    overlapping_tokens = sorted(set(operator_tokens) & set(viewer_tokens))
    if overlapping_tokens:
        return (False, "production profile requires distinct api.auth_operator_tokens and api.auth_viewer_tokens")
    if config.api.docs_enabled:
        return (False, "production profile requires docs/openapi disabled")
    if "*" in config.api.trusted_hosts:
        return (False, "production profile should not use wildcard api.trusted_hosts")
    if "*" in config.api.cors_allow_origins:
        return (False, "production profile should not use wildcard api.cors_allow_origins")
    if not bool(getattr(config.api, "rate_limit_enabled", False)):
        return (False, "production profile requires api.rate_limit_enabled=true")
    rate_limit_requests = int(getattr(config.api, "rate_limit_requests_per_minute", 0) or 0)
    if rate_limit_requests < 60:
        return (False, "production profile requires api.rate_limit_requests_per_minute >= 60")
    if rate_limit_requests > 5000:
        return (False, "production profile should cap api.rate_limit_requests_per_minute to 5000 or lower")
    rate_limit_burst = int(getattr(config.api, "rate_limit_burst", 0) or 0)
    if rate_limit_burst > rate_limit_requests:
        return (
            False,
            "production profile should keep api.rate_limit_burst <= api.rate_limit_requests_per_minute",
        )
    exempt_paths_raw = getattr(config.api, "rate_limit_exempt_paths", ["/health"]) or ["/health"]
    exempt_paths = {f"/{str(path).strip().lstrip('/')}".rstrip("/") or "/" for path in exempt_paths_raw}
    if not exempt_paths:
        exempt_paths = {"/health"}
    disallowed_exempt_paths = sorted(path for path in exempt_paths if path != "/health")
    if disallowed_exempt_paths:
        joined = ", ".join(disallowed_exempt_paths)
        return (False, f"production profile should restrict api.rate_limit_exempt_paths to /health (found: {joined})")
    if bool(getattr(config.api, "allow_unauthenticated_health", True)):
        return (False, "production profile should set api.allow_unauthenticated_health=false")
    max_request_body_bytes = int(getattr(config.api, "max_request_body_bytes", 0) or 0)
    if max_request_body_bytes > 1_048_576:
        return (False, "production profile should cap api.max_request_body_bytes to 1048576 or lower")
    return (
        True,
        (
            f"auth enabled; docs disabled; trusted_hosts={len(config.api.trusted_hosts)} "
            f"cors_origins={len(config.api.cors_allow_origins)} "
            f"rate_limit={rate_limit_requests}/min burst={rate_limit_burst} "
            f"exempt_paths={len(exempt_paths)} "
            f"body_limit={max_request_body_bytes}"
        ),
    )


def _default_credentials_check(config: AppConfig) -> tuple[bool, str]:
    environment = str(getattr(config, "environment", "")).strip().lower()
    if environment == "development":
        return (True, "default credential check skipped for development profile")

    disallowed_redis_passwords = {
        "clownpeanuts-dev-redis",
        "replace-with-strong-redis-password",
    }
    disallowed_api_tokens = {
        "clownpeanuts-ops-operator-token-2026",
        "replace-with-long-operator-token-0123456789",
    }
    violations: list[str] = []

    if config.session.backend == "redis":
        password = str(urlparse(config.session.redis_url).password or "").strip()
        if password in disallowed_redis_passwords:
            violations.append("session.redis_url uses a known default credential")
    if config.event_bus.backend == "redis":
        password = str(urlparse(config.event_bus.redis_url).password or "").strip()
        if password in disallowed_redis_passwords:
            violations.append("event_bus.redis_url uses a known default credential")
    if config.api.auth_enabled:
        tokens = [*config.api.auth_operator_tokens, *config.api.auth_viewer_tokens]
        if any(str(token).strip() in disallowed_api_tokens for token in tokens):
            violations.append("api auth token uses a known default credential")

    if violations:
        return (False, "; ".join(violations))
    return (True, "no known default credentials detected")


def _redis_url_has_credentials(redis_url: str) -> bool:
    parsed = urlparse(redis_url)
    if parsed.scheme not in {"redis", "rediss"}:
        return False
    password = (parsed.password or "").strip()
    return bool(password)
