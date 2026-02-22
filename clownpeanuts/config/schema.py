"""Dataclasses for top-level application config."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
from typing import Any


DEFAULT_API_CORS_ALLOW_ORIGINS = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3001",
    "http://localhost:3001",
]
DEFAULT_API_RATE_LIMIT_EXEMPT_PATHS = ["/health"]


@dataclass(slots=True)
class ServiceConfig:
    name: str
    module: str
    enabled: bool = True
    listen_host: str = "0.0.0.0"
    ports: list[int] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NetworkConfig:
    segmentation_mode: str = "vxlan"
    allow_outbound: bool = False
    allowed_egress: list[str] = field(default_factory=list)
    enforce_runtime: bool = True
    require_segmentation: bool = True
    verify_host_firewall: bool = False
    verify_docker_network: bool = False
    required_docker_network: str = "clownpeanuts"
    apply_firewall_rules: bool = False
    firewall_dry_run: bool = True


@dataclass(slots=True)
class SessionConfig:
    backend: str = "memory"
    redis_url: str = "redis://redis:6379/0"
    key_prefix: str = "clownpeanuts"
    ttl_seconds: int = 86400
    connect_timeout_seconds: float = 1.0
    max_events_per_session: int = 2000
    required: bool = False


@dataclass(slots=True)
class EventBusConfig:
    backend: str = "memory"
    redis_url: str = "redis://redis:6379/1"
    channel_prefix: str = "clownpeanuts"
    connect_timeout_seconds: float = 1.0
    required: bool = False


@dataclass(slots=True)
class APIConfig:
    docs_enabled: bool = False
    cors_allow_origins: list[str] = field(
        default_factory=lambda: list(DEFAULT_API_CORS_ALLOW_ORIGINS)
    )
    cors_allow_credentials: bool = False
    intel_report_cache_ttl_seconds: float = 1.5
    trusted_hosts: list[str] = field(default_factory=lambda: ["*"])
    auth_enabled: bool = False
    auth_operator_tokens: list[str] = field(default_factory=list)
    auth_viewer_tokens: list[str] = field(default_factory=list)
    allow_unauthenticated_health: bool = True
    rate_limit_enabled: bool = False
    rate_limit_requests_per_minute: int = 240
    rate_limit_burst: int = 60
    rate_limit_exempt_paths: list[str] = field(default_factory=lambda: list(DEFAULT_API_RATE_LIMIT_EXEMPT_PATHS))
    max_request_body_bytes: int = 262144


@dataclass(slots=True)
class SIEMConfig:
    enabled: bool = False
    transport: str = "http"
    endpoint: str = ""
    timeout_seconds: float = 2.0
    headers: dict[str, str] = field(default_factory=dict)
    batch_size: int = 50
    flush_interval_seconds: float = 1.0
    max_retries: int = 3
    retry_backoff_seconds: float = 0.5
    max_queue_size: int = 5000
    dead_letter_path: str = "logs/siem-dead-letter.ndjson"


@dataclass(slots=True)
class LocalLLMConfig:
    enabled: bool = False
    provider: str = "lmstudio"
    endpoint: str = "http://masoc:1234/v1/chat/completions"
    model: str = "llama3.2:3b"
    api_key: str = ""
    timeout_seconds: float = 1.2
    max_response_chars: int = 700
    temperature: float = 0.2
    failure_threshold: int = 3
    cooldown_seconds: float = 15.0


@dataclass(slots=True)
class EngineConfig:
    enabled: bool = True
    backend: str = "rule-based"
    model: str = "rule-based"
    template_fast_path: bool = True
    context_seed: str = "clownpeanuts"
    local_llm: LocalLLMConfig = field(default_factory=LocalLLMConfig)


@dataclass(slots=True)
class NarrativeConfig:
    enabled: bool = False
    world_seed: str = "clownpeanuts"
    entity_count: int = 120
    per_tenant_worlds: bool = True


@dataclass(slots=True)
class BanditRewardWeightsConfig:
    dwell_time: float = 1.0
    cross_protocol_pivot: float = 1.2
    technique_novelty: float = 1.3
    alert_quality: float = 0.8
    analyst_feedback: float = 1.0


@dataclass(slots=True)
class BanditSafetyCapsConfig:
    max_arm_exposure_percent: float = 0.7
    cooldown_seconds: float = 30.0
    denylist: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BanditConfig:
    enabled: bool = False
    algorithm: str = "thompson"
    exploration_floor: float = 0.1
    reward_weights: BanditRewardWeightsConfig = field(default_factory=BanditRewardWeightsConfig)
    safety_caps: BanditSafetyCapsConfig = field(default_factory=BanditSafetyCapsConfig)


@dataclass(slots=True)
class TheaterConfig:
    enabled: bool = False
    rollout_mode: str = "observe-only"
    max_live_sessions: int = 75
    recommendation_cooldown_seconds: float = 8.0


@dataclass(slots=True)
class AlertDestinationConfig:
    name: str
    destination_type: str = "webhook"
    enabled: bool = True
    endpoint: str = ""
    token: str = ""
    channel: str = ""
    min_severity: str = ""
    include_services: list[str] = field(default_factory=list)
    include_actions: list[str] = field(default_factory=list)
    exclude_actions: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AlertsConfig:
    enabled: bool = False
    min_severity: str = "medium"
    throttle_seconds: int = 60
    destinations: list[AlertDestinationConfig] = field(default_factory=list)


@dataclass(slots=True)
class ThreatIntelConfig:
    enabled: bool = False
    feed_urls: list[str] = field(default_factory=list)
    rotation_interval_seconds: int = 3600
    strategy: str = "balanced"
    seasonal_month_override: int | None = None


@dataclass(slots=True)
class TenantConfig:
    tenant_id: str
    display_name: str = ""
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    service_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class MultiTenantConfig:
    enabled: bool = False
    default_tenant: str = "default"
    tenants: list[TenantConfig] = field(default_factory=list)


@dataclass(slots=True)
class TemplateConfig:
    enabled: bool = False
    paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RedTeamConfig:
    enabled: bool = False
    label: str = "red_team"
    internal_cidrs: list[str] = field(default_factory=list)
    suppress_external_alerts: bool = False


@dataclass(slots=True)
class EcosystemJITConfig:
    enabled: bool = False
    pool_size: int = 10
    ttl_idle_seconds: int = 14_400
    ttl_max_seconds: int = 86_400


@dataclass(slots=True)
class EcosystemConfig:
    enabled: bool = False
    drift_alert_threshold: float = 0.7
    witchbait_credentials: list[dict[str, Any]] = field(default_factory=list)
    jit: EcosystemJITConfig = field(default_factory=EcosystemJITConfig)


@dataclass(slots=True)
class PripyatSpringsConfig:
    enabled: bool = False
    backend: str = ""
    default_toxicity: int = 2
    tracking_domain: str = ""
    canary_dns_domain: str = ""
    tracking_server_port: int = 8443
    level3_acknowledgment: str = ""
    per_emulator_overrides: dict[str, int] = field(default_factory=dict)
    store_path: str = ""


@dataclass(slots=True)
class ADLibsConfig:
    enabled: bool = False
    backend: str = ""
    ldap_uri: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password_env: str = ""
    base_dn: str = ""
    target_ou: str = ""
    fake_users: int = 8
    fake_service_accounts: int = 5
    fake_groups: int = 3
    bloodhound_paths: bool = True
    event_log_source: str = "wef"
    witchbait_integration: bool = True
    store_path: str = ""


@dataclass(slots=True)
class DirtyLaundrySharingConfig:
    enabled: bool = False
    endpoint: str = ""
    export_interval_hours: int = 24
    request_timeout_seconds: float = 5.0
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DirtyLaundryConfig:
    enabled: bool = False
    backend: str = ""
    matching_window_seconds: int = 90
    match_threshold: float = 0.75
    skill_adaptive: bool = True
    auto_theater_on_apt: bool = True
    profile_store_path: str = ""
    max_profiles: int = 10000
    max_sessions_per_profile: int = 500
    max_notes_per_profile: int = 200
    sharing: DirtyLaundrySharingConfig = field(default_factory=DirtyLaundrySharingConfig)


@dataclass(slots=True)
class AgentsConfig:
    pripyatsprings: PripyatSpringsConfig = field(default_factory=PripyatSpringsConfig)
    adlibs: ADLibsConfig = field(default_factory=ADLibsConfig)
    dirtylaundry: DirtyLaundryConfig = field(default_factory=DirtyLaundryConfig)


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    fmt: str = "ecs_json"
    sink: str = "stdout"
    file_path: str | None = None
    service_name: str = "clownpeanuts"
    siem: SIEMConfig = field(default_factory=SIEMConfig)


@dataclass(slots=True)
class AppConfig:
    environment: str
    network: NetworkConfig
    session: SessionConfig
    event_bus: EventBusConfig
    api: APIConfig
    logging: LoggingConfig
    engine: EngineConfig
    narrative: NarrativeConfig
    bandit: BanditConfig
    theater: TheaterConfig
    alerts: AlertsConfig
    threat_intel: ThreatIntelConfig
    multi_tenant: MultiTenantConfig
    templates: TemplateConfig
    red_team: RedTeamConfig
    ecosystem: EcosystemConfig
    agents: AgentsConfig
    services: list[ServiceConfig]


VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
VALID_SEGMENTATION_MODES = {"vxlan", "wireguard", "none"}
VALID_SIEM_TRANSPORTS = {"http", "udp"}
VALID_LOG_FORMATS = {"json", "ecs_json"}
VALID_LOG_SINKS = {"stdout", "file"}
VALID_SESSION_BACKENDS = {"memory", "redis"}
VALID_EVENT_BUS_BACKENDS = {"memory", "redis"}
VALID_ENGINE_BACKENDS = {"rule-based", "local-llm"}
VALID_LOCAL_LLM_PROVIDERS = {"lmstudio", "ollama"}
VALID_BANDIT_ALGORITHMS = {"thompson", "ucb"}
VALID_THEATER_ROLLOUT_MODES = {"observe-only", "recommend-only", "apply-enabled"}
VALID_ALERT_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_ALERT_DESTINATION_TYPES = {"webhook", "slack", "discord", "syslog", "email", "pagerduty"}
VALID_FEED_STRATEGIES = {"balanced", "aggressive", "conservative", "seasonal"}


def _parse_services(items: list[dict[str, Any]]) -> list[ServiceConfig]:
    services: list[ServiceConfig] = []
    for item in items:
        name = item.get("name")
        module = item.get("module")
        ports = item.get("ports", [])
        service_config = item.get("config", {}) or {}
        if not name or not module:
            raise ValueError("service requires non-empty 'name' and 'module'")
        if not isinstance(ports, list) or any(not isinstance(p, int) for p in ports):
            raise ValueError(f"service '{name}' has invalid ports list")
        if not isinstance(service_config, dict):
            raise ValueError(f"service '{name}' has invalid config payload")
        services.append(
            ServiceConfig(
                name=name,
                module=module,
                enabled=bool(item.get("enabled", True)),
                listen_host=str(item.get("listen_host", "0.0.0.0")),
                ports=ports,
                config=dict(service_config),
            )
        )
    return services


def _validate_egress_targets(targets: list[str]) -> None:
    for target in targets:
        if target == "redis":
            continue
        try:
            ipaddress.ip_network(target, strict=False)
            continue
        except ValueError:
            pass
        if "." in target and " " not in target:
            continue
        raise ValueError(f"invalid egress target '{target}'")


def _normalize_alert_filter(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    return "_".join(part for part in normalized.split("_") if part)


def _parse_alert_filter_list(
    raw: Any,
    *,
    field_name: str,
    destination_name: str,
) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"alerts destination '{destination_name}' {field_name} must be a list")
    values: list[str] = []
    seen: set[str] = set()
    for item in raw:
        normalized = _normalize_alert_filter(str(item))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
    return values


def _parse_non_empty_string_list(raw: Any, *, field_name: str, default: list[str]) -> list[str]:
    source = default if raw is None else raw
    if not isinstance(source, list):
        raise ValueError(f"'{field_name}' must be a list")
    values: list[str] = []
    seen: set[str] = set()
    for item in source:
        normalized = str(item).strip()
        if not normalized:
            continue
        if " " in normalized:
            raise ValueError(f"'{field_name}' entries must not include spaces")
        if normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
    if not values:
        raise ValueError(f"'{field_name}' must contain at least one non-empty value")
    return values


def _parse_token_list(raw: Any, *, field_name: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"'{field_name}' must be a list")
    values: list[str] = []
    seen: set[str] = set()
    for item in raw:
        token = str(item).strip()
        if not token:
            continue
        if " " in token:
            raise ValueError(f"'{field_name}' entries must not include spaces")
        if token in seen:
            continue
        seen.add(token)
        values.append(token)
    return values


def _parse_bool_value(raw: Any, *, field_name: str, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError(f"'{field_name}' must be a boolean")


def _parse_path_list(raw: Any, *, field_name: str, default: list[str]) -> list[str]:
    source = default if raw is None else raw
    if not isinstance(source, list):
        raise ValueError(f"'{field_name}' must be a list")
    values: list[str] = []
    seen: set[str] = set()
    for item in source:
        normalized = str(item).strip()
        if not normalized:
            continue
        if " " in normalized:
            raise ValueError(f"'{field_name}' entries must not include spaces")
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
    return values


def _validate_template_paths(raw: Any, *, field_name: str) -> list[str]:
    if not isinstance(raw, list):
        raise ValueError(f"'{field_name}' must be a list")
    workspace_root = Path.cwd().resolve()
    paths: list[str] = []
    for item in raw:
        token = str(item).strip()
        if not token:
            continue
        candidate = Path(token).expanduser()
        if not candidate.is_absolute():
            resolved = (workspace_root / candidate).resolve()
            try:
                resolved.relative_to(workspace_root)
            except ValueError as exc:
                raise ValueError(
                    f"{field_name} relative entries must stay within the current workspace root"
                ) from exc
        paths.append(token)
    return paths


def parse_config(data: dict[str, Any]) -> AppConfig:
    environment = str(data.get("environment", "development"))

    network_raw = data.get("network", {})
    if not isinstance(network_raw, dict):
        raise ValueError("'network' must be an object")
    segmentation_mode = str(network_raw.get("segmentation_mode", "vxlan"))
    if segmentation_mode not in VALID_SEGMENTATION_MODES:
        raise ValueError(f"invalid segmentation mode '{segmentation_mode}'")
    allowed_egress_raw = network_raw.get("allowed_egress", [])
    if not isinstance(allowed_egress_raw, list):
        raise ValueError("'network.allowed_egress' must be a list")
    allowed_egress = [str(item) for item in allowed_egress_raw]
    _validate_egress_targets(allowed_egress)
    network = NetworkConfig(
        segmentation_mode=segmentation_mode,
        allow_outbound=bool(network_raw.get("allow_outbound", False)),
        allowed_egress=allowed_egress,
        enforce_runtime=bool(network_raw.get("enforce_runtime", True)),
        require_segmentation=bool(network_raw.get("require_segmentation", True)),
        verify_host_firewall=bool(network_raw.get("verify_host_firewall", False)),
        verify_docker_network=bool(network_raw.get("verify_docker_network", False)),
        required_docker_network=str(network_raw.get("required_docker_network", "clownpeanuts")).strip()
        or "clownpeanuts",
        apply_firewall_rules=bool(network_raw.get("apply_firewall_rules", False)),
        firewall_dry_run=bool(network_raw.get("firewall_dry_run", True)),
    )

    session_raw = data.get("session", {})
    if not isinstance(session_raw, dict):
        raise ValueError("'session' must be an object")
    session_backend = str(session_raw.get("backend", "memory")).lower()
    if session_backend not in VALID_SESSION_BACKENDS:
        raise ValueError(f"invalid session backend '{session_backend}'")
    session_ttl = int(session_raw.get("ttl_seconds", 86400))
    if session_ttl <= 0:
        raise ValueError("session ttl_seconds must be greater than zero")
    session_connect_timeout = float(session_raw.get("connect_timeout_seconds", 1.0))
    if session_connect_timeout <= 0:
        raise ValueError("session connect_timeout_seconds must be greater than zero")
    session_max_events = int(session_raw.get("max_events_per_session", 2000))
    if session_max_events <= 0:
        raise ValueError("session max_events_per_session must be greater than zero")
    session_config = SessionConfig(
        backend=session_backend,
        redis_url=str(session_raw.get("redis_url", "redis://redis:6379/0")),
        key_prefix=str(session_raw.get("key_prefix", "clownpeanuts")),
        ttl_seconds=session_ttl,
        connect_timeout_seconds=session_connect_timeout,
        max_events_per_session=session_max_events,
        required=bool(session_raw.get("required", False)),
    )

    event_bus_raw = data.get("event_bus", {})
    if not isinstance(event_bus_raw, dict):
        raise ValueError("'event_bus' must be an object")
    event_bus_backend = str(event_bus_raw.get("backend", "memory")).lower()
    if event_bus_backend not in VALID_EVENT_BUS_BACKENDS:
        raise ValueError(f"invalid event_bus backend '{event_bus_backend}'")
    event_bus_connect_timeout = float(event_bus_raw.get("connect_timeout_seconds", 1.0))
    if event_bus_connect_timeout <= 0:
        raise ValueError("event_bus connect_timeout_seconds must be greater than zero")
    event_bus_config = EventBusConfig(
        backend=event_bus_backend,
        redis_url=str(event_bus_raw.get("redis_url", "redis://redis:6379/1")),
        channel_prefix=str(event_bus_raw.get("channel_prefix", "clownpeanuts")),
        connect_timeout_seconds=event_bus_connect_timeout,
        required=bool(event_bus_raw.get("required", False)),
    )

    api_raw = data.get("api", {})
    if not isinstance(api_raw, dict):
        raise ValueError("'api' must be an object")
    auth_enabled = _parse_bool_value(
        api_raw.get("auth_enabled"),
        field_name="api.auth_enabled",
        default=False,
    )
    auth_operator_tokens = _parse_token_list(
        api_raw.get("auth_operator_tokens"),
        field_name="api.auth_operator_tokens",
    )
    auth_viewer_tokens = _parse_token_list(
        api_raw.get("auth_viewer_tokens"),
        field_name="api.auth_viewer_tokens",
    )
    for token in [*auth_operator_tokens, *auth_viewer_tokens]:
        if len(token) < 16:
            raise ValueError("api auth tokens must be at least 16 characters")
    if auth_enabled and not auth_operator_tokens and not auth_viewer_tokens:
        raise ValueError(
            "api auth_enabled requires at least one token in api.auth_operator_tokens or api.auth_viewer_tokens"
        )
    cors_allow_origins = _parse_non_empty_string_list(
        api_raw.get("cors_allow_origins"),
        field_name="api.cors_allow_origins",
        default=DEFAULT_API_CORS_ALLOW_ORIGINS,
    )
    cors_allow_credentials = _parse_bool_value(
        api_raw.get("cors_allow_credentials"),
        field_name="api.cors_allow_credentials",
        default=False,
    )
    if cors_allow_credentials and "*" in cors_allow_origins:
        raise ValueError("api.cors_allow_credentials cannot be true when api.cors_allow_origins includes '*'")
    intel_report_cache_ttl_seconds = float(api_raw.get("intel_report_cache_ttl_seconds", 1.5))
    if intel_report_cache_ttl_seconds < 0 or intel_report_cache_ttl_seconds > 60:
        raise ValueError("api intel_report_cache_ttl_seconds must be between 0 and 60 seconds")
    rate_limit_requests_per_minute = int(api_raw.get("rate_limit_requests_per_minute", 240))
    if rate_limit_requests_per_minute < 1 or rate_limit_requests_per_minute > 100000:
        raise ValueError("api rate_limit_requests_per_minute must be between 1 and 100000")
    rate_limit_burst = int(api_raw.get("rate_limit_burst", 60))
    if rate_limit_burst < 0 or rate_limit_burst > 100000:
        raise ValueError("api rate_limit_burst must be between 0 and 100000")
    max_request_body_bytes = int(api_raw.get("max_request_body_bytes", 262144))
    if max_request_body_bytes < 1024 or max_request_body_bytes > 50_000_000:
        raise ValueError("api max_request_body_bytes must be between 1024 and 50000000")
    rate_limit_exempt_paths = _parse_path_list(
        api_raw.get("rate_limit_exempt_paths"),
        field_name="api.rate_limit_exempt_paths",
        default=DEFAULT_API_RATE_LIMIT_EXEMPT_PATHS,
    )
    if any("*" in item for item in rate_limit_exempt_paths):
        raise ValueError("api.rate_limit_exempt_paths cannot include wildcard patterns")
    if len(rate_limit_exempt_paths) > 16:
        raise ValueError("api.rate_limit_exempt_paths must include at most 16 entries")
    api_config = APIConfig(
        docs_enabled=_parse_bool_value(
            api_raw.get("docs_enabled"),
            field_name="api.docs_enabled",
            default=False,
        ),
        cors_allow_origins=cors_allow_origins,
        cors_allow_credentials=cors_allow_credentials,
        intel_report_cache_ttl_seconds=intel_report_cache_ttl_seconds,
        trusted_hosts=_parse_non_empty_string_list(
            api_raw.get("trusted_hosts"),
            field_name="api.trusted_hosts",
            default=["*"],
        ),
        auth_enabled=auth_enabled,
        auth_operator_tokens=auth_operator_tokens,
        auth_viewer_tokens=auth_viewer_tokens,
        allow_unauthenticated_health=_parse_bool_value(
            api_raw.get("allow_unauthenticated_health"),
            field_name="api.allow_unauthenticated_health",
            default=True,
        ),
        rate_limit_enabled=_parse_bool_value(
            api_raw.get("rate_limit_enabled"),
            field_name="api.rate_limit_enabled",
            default=False,
        ),
        rate_limit_requests_per_minute=rate_limit_requests_per_minute,
        rate_limit_burst=rate_limit_burst,
        rate_limit_exempt_paths=rate_limit_exempt_paths,
        max_request_body_bytes=max_request_body_bytes,
    )

    logging_raw = data.get("logging", {})
    if not isinstance(logging_raw, dict):
        raise ValueError("'logging' must be an object")
    level = str(logging_raw.get("level", "INFO")).upper()
    if level not in VALID_LOG_LEVELS:
        raise ValueError(f"invalid log level '{level}'")
    log_format = str(logging_raw.get("format", "ecs_json"))
    if log_format not in VALID_LOG_FORMATS:
        raise ValueError(f"invalid log format '{log_format}'")
    sink = str(logging_raw.get("sink", "stdout"))
    if sink not in VALID_LOG_SINKS:
        raise ValueError(f"invalid log sink '{sink}'")

    siem_raw = logging_raw.get("siem", {})
    if not isinstance(siem_raw, dict):
        raise ValueError("'logging.siem' must be an object")
    transport = str(siem_raw.get("transport", "http")).lower()
    if transport not in VALID_SIEM_TRANSPORTS:
        raise ValueError(f"invalid SIEM transport '{transport}'")
    timeout_seconds = float(siem_raw.get("timeout_seconds", 2.0))
    if timeout_seconds <= 0:
        raise ValueError("SIEM timeout must be greater than zero")
    batch_size = int(siem_raw.get("batch_size", 50))
    if batch_size <= 0:
        raise ValueError("SIEM batch_size must be greater than zero")
    flush_interval = float(siem_raw.get("flush_interval_seconds", 1.0))
    if flush_interval <= 0:
        raise ValueError("SIEM flush_interval_seconds must be greater than zero")
    max_retries = int(siem_raw.get("max_retries", 3))
    if max_retries < 0:
        raise ValueError("SIEM max_retries must be greater than or equal to zero")
    retry_backoff = float(siem_raw.get("retry_backoff_seconds", 0.5))
    if retry_backoff <= 0:
        raise ValueError("SIEM retry_backoff_seconds must be greater than zero")
    max_queue_size = int(siem_raw.get("max_queue_size", 5000))
    if max_queue_size <= 0:
        raise ValueError("SIEM max_queue_size must be greater than zero")
    headers_raw = siem_raw.get("headers", {})
    if not isinstance(headers_raw, dict):
        raise ValueError("'logging.siem.headers' must be an object")
    headers = {str(key): str(value) for key, value in headers_raw.items()}

    logging_config = LoggingConfig(
        level=level,
        fmt=log_format,
        sink=sink,
        file_path=logging_raw.get("file_path"),
        service_name=str(logging_raw.get("service_name", "clownpeanuts")),
        siem=SIEMConfig(
            enabled=bool(siem_raw.get("enabled", False)),
            transport=transport,
            endpoint=str(siem_raw.get("endpoint", "")),
            timeout_seconds=timeout_seconds,
            headers=headers,
            batch_size=batch_size,
            flush_interval_seconds=flush_interval,
            max_retries=max_retries,
            retry_backoff_seconds=retry_backoff,
            max_queue_size=max_queue_size,
            dead_letter_path=str(siem_raw.get("dead_letter_path", "logs/siem-dead-letter.ndjson")),
        ),
    )

    engine_raw = data.get("engine", {})
    if not isinstance(engine_raw, dict):
        raise ValueError("'engine' must be an object")
    engine_backend = str(engine_raw.get("backend", "rule-based")).lower()
    if engine_backend not in VALID_ENGINE_BACKENDS:
        raise ValueError(f"invalid engine backend '{engine_backend}'")
    local_llm_raw = engine_raw.get("local_llm", {})
    if not isinstance(local_llm_raw, dict):
        raise ValueError("'engine.local_llm' must be an object")
    local_llm_provider = str(local_llm_raw.get("provider", "lmstudio")).lower()
    if local_llm_provider not in VALID_LOCAL_LLM_PROVIDERS:
        raise ValueError(f"invalid engine.local_llm provider '{local_llm_provider}'")
    default_local_llm_endpoint = (
        "http://127.0.0.1:11434/api/generate"
        if local_llm_provider == "ollama"
        else "http://masoc:1234/v1/chat/completions"
    )
    local_llm_timeout_seconds = float(local_llm_raw.get("timeout_seconds", 1.2))
    if local_llm_timeout_seconds <= 0:
        raise ValueError("engine.local_llm timeout_seconds must be greater than zero")
    local_llm_max_response_chars = int(local_llm_raw.get("max_response_chars", 700))
    if local_llm_max_response_chars <= 0:
        raise ValueError("engine.local_llm max_response_chars must be greater than zero")
    local_llm_temperature = float(local_llm_raw.get("temperature", 0.2))
    if local_llm_temperature < 0 or local_llm_temperature > 2:
        raise ValueError("engine.local_llm temperature must be between 0 and 2")
    local_llm_failure_threshold = int(local_llm_raw.get("failure_threshold", 3))
    if local_llm_failure_threshold <= 0:
        raise ValueError("engine.local_llm failure_threshold must be greater than zero")
    local_llm_cooldown_seconds = float(local_llm_raw.get("cooldown_seconds", 15.0))
    if local_llm_cooldown_seconds < 0:
        raise ValueError("engine.local_llm cooldown_seconds must be greater than or equal to zero")
    local_llm_enabled_default = engine_backend == "local-llm"
    local_llm_config = LocalLLMConfig(
        enabled=bool(local_llm_raw.get("enabled", local_llm_enabled_default)),
        provider=local_llm_provider,
        endpoint=str(local_llm_raw.get("endpoint", default_local_llm_endpoint)).strip() or default_local_llm_endpoint,
        model=str(local_llm_raw.get("model", "llama3.2:3b")).strip() or "llama3.2:3b",
        api_key=str(local_llm_raw.get("api_key", "")).strip(),
        timeout_seconds=local_llm_timeout_seconds,
        max_response_chars=local_llm_max_response_chars,
        temperature=local_llm_temperature,
        failure_threshold=local_llm_failure_threshold,
        cooldown_seconds=local_llm_cooldown_seconds,
    )
    engine_config = EngineConfig(
        enabled=bool(engine_raw.get("enabled", True)),
        backend=engine_backend,
        model=str(engine_raw.get("model", "rule-based")),
        template_fast_path=bool(engine_raw.get("template_fast_path", True)),
        context_seed=str(engine_raw.get("context_seed", "clownpeanuts")),
        local_llm=local_llm_config,
    )

    narrative_raw = data.get("narrative", {})
    if not isinstance(narrative_raw, dict):
        raise ValueError("'narrative' must be an object")
    narrative_world_seed = str(narrative_raw.get("world_seed", "clownpeanuts")).strip() or "clownpeanuts"
    narrative_entity_count = int(narrative_raw.get("entity_count", 120))
    if narrative_entity_count <= 0:
        raise ValueError("narrative entity_count must be greater than zero")
    if narrative_entity_count > 10000:
        raise ValueError("narrative entity_count must be less than or equal to 10000")
    narrative_config = NarrativeConfig(
        enabled=bool(narrative_raw.get("enabled", False)),
        world_seed=narrative_world_seed,
        entity_count=narrative_entity_count,
        per_tenant_worlds=bool(narrative_raw.get("per_tenant_worlds", True)),
    )

    bandit_raw = data.get("bandit", {})
    if not isinstance(bandit_raw, dict):
        raise ValueError("'bandit' must be an object")
    bandit_algorithm = str(bandit_raw.get("algorithm", "thompson")).strip().lower() or "thompson"
    if bandit_algorithm not in VALID_BANDIT_ALGORITHMS:
        raise ValueError(f"invalid bandit algorithm '{bandit_algorithm}'")
    bandit_exploration_floor = float(bandit_raw.get("exploration_floor", 0.1))
    if bandit_exploration_floor < 0 or bandit_exploration_floor > 1:
        raise ValueError("bandit exploration_floor must be between 0 and 1")

    reward_weights_raw = bandit_raw.get("reward_weights", {})
    if not isinstance(reward_weights_raw, dict):
        raise ValueError("'bandit.reward_weights' must be an object")
    bandit_reward_weights = BanditRewardWeightsConfig(
        dwell_time=float(reward_weights_raw.get("dwell_time", 1.0)),
        cross_protocol_pivot=float(reward_weights_raw.get("cross_protocol_pivot", 1.2)),
        technique_novelty=float(reward_weights_raw.get("technique_novelty", 1.3)),
        alert_quality=float(reward_weights_raw.get("alert_quality", 0.8)),
        analyst_feedback=float(reward_weights_raw.get("analyst_feedback", 1.0)),
    )
    for field_name, value in (
        ("dwell_time", bandit_reward_weights.dwell_time),
        ("cross_protocol_pivot", bandit_reward_weights.cross_protocol_pivot),
        ("technique_novelty", bandit_reward_weights.technique_novelty),
        ("alert_quality", bandit_reward_weights.alert_quality),
        ("analyst_feedback", bandit_reward_weights.analyst_feedback),
    ):
        if value < 0:
            raise ValueError(f"bandit.reward_weights.{field_name} must be greater than or equal to zero")

    safety_caps_raw = bandit_raw.get("safety_caps", {})
    if not isinstance(safety_caps_raw, dict):
        raise ValueError("'bandit.safety_caps' must be an object")
    bandit_max_arm_exposure_percent = float(safety_caps_raw.get("max_arm_exposure_percent", 0.7))
    if bandit_max_arm_exposure_percent <= 0 or bandit_max_arm_exposure_percent > 1:
        raise ValueError("bandit.safety_caps.max_arm_exposure_percent must be between 0 and 1")
    bandit_cooldown_seconds = float(safety_caps_raw.get("cooldown_seconds", 30.0))
    if bandit_cooldown_seconds < 0:
        raise ValueError("bandit.safety_caps.cooldown_seconds must be greater than or equal to zero")
    denylist_raw = safety_caps_raw.get("denylist", [])
    if not isinstance(denylist_raw, list):
        raise ValueError("'bandit.safety_caps.denylist' must be a list")
    bandit_denylist: list[str] = []
    seen_denylist: set[str] = set()
    for item in denylist_raw:
        normalized = str(item).strip()
        if not normalized or normalized in seen_denylist:
            continue
        seen_denylist.add(normalized)
        bandit_denylist.append(normalized)
    bandit_config = BanditConfig(
        enabled=bool(bandit_raw.get("enabled", False)),
        algorithm=bandit_algorithm,
        exploration_floor=bandit_exploration_floor,
        reward_weights=bandit_reward_weights,
        safety_caps=BanditSafetyCapsConfig(
            max_arm_exposure_percent=bandit_max_arm_exposure_percent,
            cooldown_seconds=bandit_cooldown_seconds,
            denylist=bandit_denylist,
        ),
    )

    theater_raw = data.get("theater", {})
    if not isinstance(theater_raw, dict):
        raise ValueError("'theater' must be an object")
    theater_rollout_mode = str(theater_raw.get("rollout_mode", "observe-only")).strip().lower() or "observe-only"
    if theater_rollout_mode not in VALID_THEATER_ROLLOUT_MODES:
        raise ValueError(f"invalid theater rollout_mode '{theater_rollout_mode}'")
    theater_max_live_sessions = int(theater_raw.get("max_live_sessions", 75))
    if theater_max_live_sessions <= 0:
        raise ValueError("theater max_live_sessions must be greater than zero")
    theater_recommendation_cooldown_seconds = float(theater_raw.get("recommendation_cooldown_seconds", 8.0))
    if theater_recommendation_cooldown_seconds < 0:
        raise ValueError("theater recommendation_cooldown_seconds must be greater than or equal to zero")
    theater_config = TheaterConfig(
        enabled=bool(theater_raw.get("enabled", False)),
        rollout_mode=theater_rollout_mode,
        max_live_sessions=theater_max_live_sessions,
        recommendation_cooldown_seconds=theater_recommendation_cooldown_seconds,
    )

    alerts_raw = data.get("alerts", {})
    if not isinstance(alerts_raw, dict):
        raise ValueError("'alerts' must be an object")
    min_severity = str(alerts_raw.get("min_severity", "medium")).lower()
    if min_severity not in VALID_ALERT_SEVERITIES:
        raise ValueError(f"invalid alerts min_severity '{min_severity}'")
    throttle_seconds = int(alerts_raw.get("throttle_seconds", 60))
    if throttle_seconds < 0:
        raise ValueError("alerts throttle_seconds must be greater than or equal to zero")
    destinations_raw = alerts_raw.get("destinations", [])
    if not isinstance(destinations_raw, list):
        raise ValueError("'alerts.destinations' must be a list")
    destinations: list[AlertDestinationConfig] = []
    for index, item in enumerate(destinations_raw):
        if not isinstance(item, dict):
            raise ValueError(f"alerts destination #{index} must be an object")
        destination_name = str(item.get("name", f"destination-{index + 1}")).strip() or f"destination-{index + 1}"
        destination_type = str(item.get("type", "webhook")).lower()
        if destination_type not in VALID_ALERT_DESTINATION_TYPES:
            raise ValueError(f"invalid alerts destination type '{destination_type}'")
        destination_min_severity = str(item.get("min_severity", "")).strip().lower()
        if destination_min_severity and destination_min_severity not in VALID_ALERT_SEVERITIES:
            raise ValueError(
                f"alerts destination '{destination_name}' has invalid min_severity '{destination_min_severity}'"
            )
        include_services = _parse_alert_filter_list(
            item.get("include_services", []),
            field_name="include_services",
            destination_name=destination_name,
        )
        include_actions = _parse_alert_filter_list(
            item.get("include_actions", []),
            field_name="include_actions",
            destination_name=destination_name,
        )
        exclude_actions = _parse_alert_filter_list(
            item.get("exclude_actions", []),
            field_name="exclude_actions",
            destination_name=destination_name,
        )
        metadata_raw = item.get("metadata", {}) or {}
        if not isinstance(metadata_raw, dict):
            raise ValueError(f"alerts destination '{destination_name}' metadata must be an object")
        destinations.append(
            AlertDestinationConfig(
                name=destination_name,
                destination_type=destination_type,
                enabled=bool(item.get("enabled", True)),
                endpoint=str(item.get("endpoint", "")),
                token=str(item.get("token", "")),
                channel=str(item.get("channel", "")),
                min_severity=destination_min_severity,
                include_services=include_services,
                include_actions=include_actions,
                exclude_actions=exclude_actions,
                metadata={
                    str(key): str(value)
                    for key, value in metadata_raw.items()
                    if str(key).strip()
                },
            )
        )
    alerts_config = AlertsConfig(
        enabled=bool(alerts_raw.get("enabled", False)),
        min_severity=min_severity,
        throttle_seconds=throttle_seconds,
        destinations=destinations,
    )

    threat_intel_raw = data.get("threat_intel", {})
    if not isinstance(threat_intel_raw, dict):
        raise ValueError("'threat_intel' must be an object")
    strategy = str(threat_intel_raw.get("strategy", "balanced")).lower()
    if strategy not in VALID_FEED_STRATEGIES:
        raise ValueError(f"invalid threat_intel strategy '{strategy}'")
    feed_urls_raw = threat_intel_raw.get("feed_urls", [])
    if not isinstance(feed_urls_raw, list):
        raise ValueError("'threat_intel.feed_urls' must be a list")
    rotation_interval_seconds = int(threat_intel_raw.get("rotation_interval_seconds", 3600))
    if rotation_interval_seconds <= 0:
        raise ValueError("threat_intel rotation_interval_seconds must be greater than zero")
    seasonal_month_override_raw = threat_intel_raw.get("seasonal_month_override")
    seasonal_month_override: int | None = None
    if seasonal_month_override_raw is not None:
        seasonal_month_override = int(seasonal_month_override_raw)
        if seasonal_month_override < 1 or seasonal_month_override > 12:
            raise ValueError("threat_intel seasonal_month_override must be between 1 and 12")
    threat_intel_config = ThreatIntelConfig(
        enabled=bool(threat_intel_raw.get("enabled", False)),
        feed_urls=[str(url) for url in feed_urls_raw if str(url).strip()],
        rotation_interval_seconds=rotation_interval_seconds,
        strategy=strategy,
        seasonal_month_override=seasonal_month_override,
    )

    multi_tenant_raw = data.get("multi_tenant", {})
    if not isinstance(multi_tenant_raw, dict):
        raise ValueError("'multi_tenant' must be an object")
    tenants_raw = multi_tenant_raw.get("tenants", [])
    if not isinstance(tenants_raw, list):
        raise ValueError("'multi_tenant.tenants' must be a list")
    tenants: list[TenantConfig] = []
    for index, item in enumerate(tenants_raw):
        if not isinstance(item, dict):
            raise ValueError(f"tenant #{index} must be an object")
        tenant_id = str(item.get("id", "")).strip()
        if not tenant_id:
            raise ValueError(f"tenant #{index} requires non-empty 'id'")
        overrides_raw = item.get("service_overrides", {}) or {}
        if not isinstance(overrides_raw, dict):
            raise ValueError(f"tenant '{tenant_id}' has invalid service_overrides")
        overrides: dict[str, dict[str, Any]] = {}
        for service_name, override in overrides_raw.items():
            if not isinstance(override, dict):
                raise ValueError(f"tenant '{tenant_id}' override for '{service_name}' must be an object")
            overrides[str(service_name)] = dict(override)
        tags_raw = item.get("tags", [])
        if not isinstance(tags_raw, list):
            raise ValueError(f"tenant '{tenant_id}' tags must be a list")
        tenants.append(
            TenantConfig(
                tenant_id=tenant_id,
                display_name=str(item.get("display_name", tenant_id)),
                enabled=bool(item.get("enabled", True)),
                tags=[str(tag) for tag in tags_raw],
                service_overrides=overrides,
            )
        )
    multi_tenant_config = MultiTenantConfig(
        enabled=bool(multi_tenant_raw.get("enabled", False)),
        default_tenant=str(multi_tenant_raw.get("default_tenant", "default")).strip() or "default",
        tenants=tenants,
    )

    templates_raw = data.get("templates", {})
    if not isinstance(templates_raw, dict):
        raise ValueError("'templates' must be an object")
    template_paths_raw = templates_raw.get("paths", [])
    template_paths = _validate_template_paths(template_paths_raw, field_name="templates.paths")
    templates_config = TemplateConfig(
        enabled=bool(templates_raw.get("enabled", False)),
        paths=template_paths,
    )

    red_team_raw = data.get("red_team", {})
    if not isinstance(red_team_raw, dict):
        raise ValueError("'red_team' must be an object")
    internal_cidrs_raw = red_team_raw.get("internal_cidrs", [])
    if not isinstance(internal_cidrs_raw, list):
        raise ValueError("'red_team.internal_cidrs' must be a list")
    internal_cidrs = [str(cidr) for cidr in internal_cidrs_raw]
    for cidr in internal_cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid red_team internal cidr '{cidr}'") from exc
    red_team_config = RedTeamConfig(
        enabled=bool(red_team_raw.get("enabled", False)),
        label=str(red_team_raw.get("label", "red_team")).strip() or "red_team",
        internal_cidrs=internal_cidrs,
        suppress_external_alerts=bool(red_team_raw.get("suppress_external_alerts", False)),
    )

    ecosystem_raw = data.get("ecosystem", {})
    if not isinstance(ecosystem_raw, dict):
        raise ValueError("'ecosystem' must be an object")
    drift_alert_threshold = float(ecosystem_raw.get("drift_alert_threshold", 0.7))
    if drift_alert_threshold < 0 or drift_alert_threshold > 1:
        raise ValueError("ecosystem.drift_alert_threshold must be between 0 and 1")
    witchbait_credentials_raw = ecosystem_raw.get("witchbait_credentials", [])
    if not isinstance(witchbait_credentials_raw, list):
        raise ValueError("ecosystem.witchbait_credentials must be a list")
    witchbait_credentials: list[dict[str, Any]] = []
    for index, item in enumerate(witchbait_credentials_raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"ecosystem.witchbait_credentials[{index}] must be an object")
        witchbait_credentials.append(dict(item))
    jit_raw = ecosystem_raw.get("jit", {})
    if not isinstance(jit_raw, dict):
        raise ValueError("ecosystem.jit must be an object")
    jit_pool_size = int(jit_raw.get("pool_size", 10))
    if jit_pool_size < 1 or jit_pool_size > 1000:
        raise ValueError("ecosystem.jit.pool_size must be between 1 and 1000")
    jit_ttl_idle_seconds = int(jit_raw.get("ttl_idle_seconds", 14_400))
    if jit_ttl_idle_seconds < 60:
        raise ValueError("ecosystem.jit.ttl_idle_seconds must be >= 60")
    jit_ttl_max_seconds = int(jit_raw.get("ttl_max_seconds", 86_400))
    if jit_ttl_max_seconds < jit_ttl_idle_seconds:
        raise ValueError("ecosystem.jit.ttl_max_seconds must be >= ecosystem.jit.ttl_idle_seconds")
    jit_config = EcosystemJITConfig(
        enabled=_parse_bool_value(
            jit_raw.get("enabled"),
            field_name="ecosystem.jit.enabled",
            default=False,
        ),
        pool_size=jit_pool_size,
        ttl_idle_seconds=jit_ttl_idle_seconds,
        ttl_max_seconds=jit_ttl_max_seconds,
    )
    ecosystem_config = EcosystemConfig(
        enabled=_parse_bool_value(
            ecosystem_raw.get("enabled"),
            field_name="ecosystem.enabled",
            default=False,
        ),
        drift_alert_threshold=drift_alert_threshold,
        witchbait_credentials=witchbait_credentials,
        jit=jit_config,
    )

    agents_raw = data.get("agents", {})
    if not isinstance(agents_raw, dict):
        raise ValueError("'agents' must be an object")

    pripyatsprings_raw = agents_raw.get("pripyatsprings", {})
    if not isinstance(pripyatsprings_raw, dict):
        raise ValueError("'agents.pripyatsprings' must be an object")
    default_toxicity = int(pripyatsprings_raw.get("default_toxicity", 2))
    if default_toxicity < 1 or default_toxicity > 3:
        raise ValueError("agents.pripyatsprings.default_toxicity must be between 1 and 3")
    tracking_server_port = int(pripyatsprings_raw.get("tracking_server_port", 8443))
    if tracking_server_port < 1 or tracking_server_port > 65535:
        raise ValueError("agents.pripyatsprings.tracking_server_port must be between 1 and 65535")
    overrides_raw = pripyatsprings_raw.get("per_emulator_overrides", {})
    if not isinstance(overrides_raw, dict):
        raise ValueError("agents.pripyatsprings.per_emulator_overrides must be an object")
    per_emulator_overrides: dict[str, int] = {}
    for key, value in overrides_raw.items():
        normalized_key = str(key).strip()
        if not normalized_key:
            continue
        toxicity_value = int(value)
        if toxicity_value < 1 or toxicity_value > 3:
            raise ValueError(
                "agents.pripyatsprings.per_emulator_overrides values must be between 1 and 3"
            )
        per_emulator_overrides[normalized_key] = toxicity_value
    pripyatsprings_config = PripyatSpringsConfig(
        enabled=_parse_bool_value(
            pripyatsprings_raw.get("enabled"),
            field_name="agents.pripyatsprings.enabled",
            default=False,
        ),
        backend=str(pripyatsprings_raw.get("backend", "")).strip(),
        default_toxicity=default_toxicity,
        tracking_domain=str(pripyatsprings_raw.get("tracking_domain", "")).strip(),
        canary_dns_domain=str(pripyatsprings_raw.get("canary_dns_domain", "")).strip(),
        tracking_server_port=tracking_server_port,
        level3_acknowledgment=str(pripyatsprings_raw.get("level3_acknowledgment", "")).strip(),
        per_emulator_overrides=per_emulator_overrides,
        store_path=str(pripyatsprings_raw.get("store_path", "")).strip(),
    )

    adlibs_raw = agents_raw.get("adlibs", {})
    if not isinstance(adlibs_raw, dict):
        raise ValueError("'agents.adlibs' must be an object")
    fake_users = int(adlibs_raw.get("fake_users", 8))
    fake_service_accounts = int(adlibs_raw.get("fake_service_accounts", 5))
    fake_groups = int(adlibs_raw.get("fake_groups", 3))
    if fake_users < 0 or fake_service_accounts < 0 or fake_groups < 0:
        raise ValueError("agents.adlibs fake object counts must be >= 0")
    adlibs_config = ADLibsConfig(
        enabled=_parse_bool_value(
            adlibs_raw.get("enabled"),
            field_name="agents.adlibs.enabled",
            default=False,
        ),
        backend=str(adlibs_raw.get("backend", "")).strip(),
        ldap_uri=str(adlibs_raw.get("ldap_uri", "")).strip(),
        ldap_bind_dn=str(adlibs_raw.get("ldap_bind_dn", "")).strip(),
        ldap_bind_password_env=str(adlibs_raw.get("ldap_bind_password_env", "")).strip(),
        base_dn=str(adlibs_raw.get("base_dn", "")).strip(),
        target_ou=str(adlibs_raw.get("target_ou", "")).strip(),
        fake_users=fake_users,
        fake_service_accounts=fake_service_accounts,
        fake_groups=fake_groups,
        bloodhound_paths=_parse_bool_value(
            adlibs_raw.get("bloodhound_paths"),
            field_name="agents.adlibs.bloodhound_paths",
            default=True,
        ),
        event_log_source=str(adlibs_raw.get("event_log_source", "wef")).strip().lower() or "wef",
        witchbait_integration=_parse_bool_value(
            adlibs_raw.get("witchbait_integration"),
            field_name="agents.adlibs.witchbait_integration",
            default=True,
        ),
        store_path=str(adlibs_raw.get("store_path", "")).strip(),
    )
    if adlibs_config.event_log_source not in {"wef", "wmi", "sysmon"}:
        raise ValueError("agents.adlibs.event_log_source must be one of: wef, wmi, sysmon")

    dirtylaundry_raw = agents_raw.get("dirtylaundry", {})
    if not isinstance(dirtylaundry_raw, dict):
        raise ValueError("'agents.dirtylaundry' must be an object")
    matching_window_seconds = int(dirtylaundry_raw.get("matching_window_seconds", 90))
    if matching_window_seconds < 1:
        raise ValueError("agents.dirtylaundry.matching_window_seconds must be >= 1")
    match_threshold = float(dirtylaundry_raw.get("match_threshold", 0.75))
    if match_threshold < 0.0 or match_threshold > 1.0:
        raise ValueError("agents.dirtylaundry.match_threshold must be between 0 and 1")
    max_profiles = int(dirtylaundry_raw.get("max_profiles", 10000))
    if max_profiles < 1:
        raise ValueError("agents.dirtylaundry.max_profiles must be >= 1")
    max_sessions_per_profile = int(dirtylaundry_raw.get("max_sessions_per_profile", 500))
    if max_sessions_per_profile < 1:
        raise ValueError("agents.dirtylaundry.max_sessions_per_profile must be >= 1")
    max_notes_per_profile = int(dirtylaundry_raw.get("max_notes_per_profile", 200))
    if max_notes_per_profile < 1:
        raise ValueError("agents.dirtylaundry.max_notes_per_profile must be >= 1")
    sharing_raw = dirtylaundry_raw.get("sharing", {})
    if not isinstance(sharing_raw, dict):
        raise ValueError("agents.dirtylaundry.sharing must be an object")
    export_interval_hours = int(sharing_raw.get("export_interval_hours", 24))
    if export_interval_hours < 1:
        raise ValueError("agents.dirtylaundry.sharing.export_interval_hours must be >= 1")
    request_timeout_seconds = float(sharing_raw.get("request_timeout_seconds", 5.0))
    if request_timeout_seconds < 0.5 or request_timeout_seconds > 120.0:
        raise ValueError("agents.dirtylaundry.sharing.request_timeout_seconds must be between 0.5 and 120")
    headers_raw = sharing_raw.get("headers", {})
    if not isinstance(headers_raw, dict):
        raise ValueError("agents.dirtylaundry.sharing.headers must be an object")
    sharing_headers: dict[str, str] = {}
    for key, value in headers_raw.items():
        header_name = str(key).strip()
        if not header_name:
            continue
        sharing_headers[header_name] = str(value).strip()
    dirtylaundry_sharing = DirtyLaundrySharingConfig(
        enabled=_parse_bool_value(
            sharing_raw.get("enabled"),
            field_name="agents.dirtylaundry.sharing.enabled",
            default=False,
        ),
        endpoint=str(sharing_raw.get("endpoint", "")).strip(),
        export_interval_hours=export_interval_hours,
        request_timeout_seconds=request_timeout_seconds,
        headers=sharing_headers,
    )
    dirtylaundry_config = DirtyLaundryConfig(
        enabled=_parse_bool_value(
            dirtylaundry_raw.get("enabled"),
            field_name="agents.dirtylaundry.enabled",
            default=False,
        ),
        backend=str(dirtylaundry_raw.get("backend", "")).strip(),
        matching_window_seconds=matching_window_seconds,
        match_threshold=match_threshold,
        skill_adaptive=_parse_bool_value(
            dirtylaundry_raw.get("skill_adaptive"),
            field_name="agents.dirtylaundry.skill_adaptive",
            default=True,
        ),
        auto_theater_on_apt=_parse_bool_value(
            dirtylaundry_raw.get("auto_theater_on_apt"),
            field_name="agents.dirtylaundry.auto_theater_on_apt",
            default=True,
        ),
        profile_store_path=str(dirtylaundry_raw.get("profile_store_path", "")).strip(),
        max_profiles=max_profiles,
        max_sessions_per_profile=max_sessions_per_profile,
        max_notes_per_profile=max_notes_per_profile,
        sharing=dirtylaundry_sharing,
    )
    agents_config = AgentsConfig(
        pripyatsprings=pripyatsprings_config,
        adlibs=adlibs_config,
        dirtylaundry=dirtylaundry_config,
    )

    services_raw = data.get("services", [])
    if not isinstance(services_raw, list):
        raise ValueError("'services' must be a list")

    services = _parse_services(services_raw)

    return AppConfig(
        environment=environment,
        network=network,
        session=session_config,
        event_bus=event_bus_config,
        api=api_config,
        logging=logging_config,
        engine=engine_config,
        narrative=narrative_config,
        bandit=bandit_config,
        theater=theater_config,
        alerts=alerts_config,
        threat_intel=threat_intel_config,
        multi_tenant=multi_tenant_config,
        templates=templates_config,
        red_team=red_team_config,
        ecosystem=ecosystem_config,
        agents=agents_config,
        services=services,
    )
