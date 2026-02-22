import json

from clownpeanuts.config.schema import LoggingConfig, SIEMConfig
from clownpeanuts.core.logging import ECSJsonFormatter, SIEMHandler, EventLogger, configure_logging, emit_metric, get_logger


def test_ecs_log_output_to_file(tmp_path) -> None:
    log_file = tmp_path / "events.log"
    config = LoggingConfig(
        level="INFO",
        fmt="ecs_json",
        sink="file",
        file_path=str(log_file),
        service_name="clownpeanuts-test",
        siem=SIEMConfig(),
    )
    configure_logging(config, force=True)
    emitter = EventLogger(
        logger=get_logger("clownpeanuts.test.logging"),
        service_name="clownpeanuts-test",
    )
    emitter.emit(
        message="captured auth event",
        service="ssh",
        action="auth_attempt",
        session_id="sess-1",
        source_ip="10.0.0.5",
        source_port=55670,
        outcome="failure",
        event_type="authentication",
        payload={"username": "root", "password": "guessme"},
    )

    record = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert record["@timestamp"]
    assert record["service"]["name"] == "clownpeanuts-test"
    assert record["event"]["action"] == "auth_attempt"
    assert record["session"]["id"] == "sess-1"
    assert record["source"]["ip"] == "10.0.0.5"


def test_emit_metric_logs_metric_category(tmp_path) -> None:
    log_file = tmp_path / "metrics.log"
    config = LoggingConfig(
        level="INFO",
        fmt="ecs_json",
        sink="file",
        file_path=str(log_file),
        service_name="clownpeanuts-test",
        siem=SIEMConfig(),
    )
    configure_logging(config, force=True)
    logger = get_logger("clownpeanuts.test.metrics")
    emit_metric(
        logger,
        name="bandit_reward_avg",
        value=0.42,
        service="intel",
        payload={"window": "5m"},
    )

    lines = [line for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    record = json.loads(lines[-1])
    assert record["event"]["category"] == "metric"
    assert record["event"]["action"] == "bandit_reward_avg"
    assert record["clownpeanuts"]["payload"]["metric_value"] == 0.42


def test_siem_http_validation_rejects_dns_drift(monkeypatch) -> None:
    class _Resolver:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                return [(0, 0, 0, "", ("93.184.216.34", 443))]
            return [(0, 0, 0, "", ("151.101.1.69", 443))]

    resolver = _Resolver()
    monkeypatch.setattr("clownpeanuts.core.logging.socket.getaddrinfo", resolver)
    handler = SIEMHandler(
        SIEMConfig(
            enabled=True,
            transport="http",
            endpoint="https://siem.example.local/ingest",
            flush_interval_seconds=0.05,
        ),
        ECSJsonFormatter(),
    )
    try:
        handler._validate_http_endpoint()
        handler._http_endpoint_validation_expires_at_monotonic = 0.0
        try:
            handler._validate_http_endpoint()
        except ValueError as exc:
            assert "drift" in str(exc)
        else:
            raise AssertionError("expected ValueError for DNS resolution drift")
    finally:
        handler.close()


def test_siem_http_validation_accepts_subset_re_resolution(monkeypatch) -> None:
    class _Resolver:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                return [
                    (0, 0, 0, "", ("93.184.216.34", 443)),
                    (0, 0, 0, "", ("151.101.1.69", 443)),
                ]
            return [(0, 0, 0, "", ("151.101.1.69", 443))]

    monkeypatch.setattr("clownpeanuts.core.logging.socket.getaddrinfo", _Resolver())
    handler = SIEMHandler(
        SIEMConfig(
            enabled=True,
            transport="http",
            endpoint="https://siem.example.local/ingest",
            flush_interval_seconds=0.05,
        ),
        ECSJsonFormatter(),
    )
    try:
        handler._validate_http_endpoint()
        handler._http_endpoint_validation_expires_at_monotonic = 0.0
        handler._validate_http_endpoint()
    finally:
        handler.close()
