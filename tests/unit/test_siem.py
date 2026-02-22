import logging
import time

from clownpeanuts.config.schema import SIEMConfig
from clownpeanuts.core.logging import ECSJsonFormatter, SIEMHandler


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="clownpeanuts.test.siem",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_siem_handler_writes_dead_letter_on_failure(tmp_path, monkeypatch) -> None:
    dead_letter = tmp_path / "siem-dead.ndjson"
    config = SIEMConfig(
        enabled=True,
        transport="http",
        endpoint="http://example.local/ingest",
        timeout_seconds=0.05,
        batch_size=1,
        flush_interval_seconds=0.02,
        max_retries=1,
        retry_backoff_seconds=0.01,
        max_queue_size=10,
        dead_letter_path=str(dead_letter),
    )

    def _fail(*_args, **_kwargs):
        raise RuntimeError("ingest failed")

    monkeypatch.setattr("clownpeanuts.core.logging.SIEMHandler._validate_http_endpoint", lambda self: None)
    monkeypatch.setattr("clownpeanuts.core.logging.request.urlopen", _fail)

    handler = SIEMHandler(config, ECSJsonFormatter(service_name="test"))
    handler.emit(_record("first-event"))
    time.sleep(0.15)
    handler.close()

    payload = dead_letter.read_text(encoding="utf-8")
    assert "ingest failed" in payload
    assert "first-event" in payload


def test_siem_handler_batches_events(tmp_path, monkeypatch) -> None:
    sent_batches: list[str] = []
    dead_letter = tmp_path / "siem-dead.ndjson"
    config = SIEMConfig(
        enabled=True,
        transport="http",
        endpoint="http://example.local/ingest",
        timeout_seconds=0.05,
        batch_size=2,
        flush_interval_seconds=0.5,
        max_retries=0,
        retry_backoff_seconds=0.01,
        max_queue_size=10,
        dead_letter_path=str(dead_letter),
    )

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    def _ok(req, timeout):  # noqa: ARG001
        sent_batches.append(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr("clownpeanuts.core.logging.SIEMHandler._validate_http_endpoint", lambda self: None)
    monkeypatch.setattr("clownpeanuts.core.logging.request.urlopen", _ok)

    handler = SIEMHandler(config, ECSJsonFormatter(service_name="test"))
    handler.emit(_record("batch-event-1"))
    handler.emit(_record("batch-event-2"))
    time.sleep(0.15)
    handler.close()

    assert sent_batches
    assert "batch-event-1" in sent_batches[0]
    assert "batch-event-2" in sent_batches[0]
    assert dead_letter.exists() is False


def test_siem_handler_blocks_private_http_endpoint(tmp_path) -> None:
    dead_letter = tmp_path / "siem-dead.ndjson"
    config = SIEMConfig(
        enabled=True,
        transport="http",
        endpoint="http://127.0.0.1:9200/ingest",
        timeout_seconds=0.05,
        batch_size=1,
        flush_interval_seconds=0.02,
        max_retries=0,
        retry_backoff_seconds=0.01,
        max_queue_size=10,
        dead_letter_path=str(dead_letter),
    )

    handler = SIEMHandler(config, ECSJsonFormatter(service_name="test"))
    handler.emit(_record("blocked-private-endpoint"))
    time.sleep(0.1)
    handler.close()

    payload = dead_letter.read_text(encoding="utf-8")
    assert "private or non-routable address" in payload
    assert "blocked-private-endpoint" in payload


def test_siem_dead_letter_rotates_when_size_limit_exceeded(tmp_path) -> None:
    dead_letter = tmp_path / "siem-dead.ndjson"
    config = SIEMConfig(
        enabled=False,
        transport="http",
        endpoint="",
        dead_letter_path=str(dead_letter),
    )
    handler = SIEMHandler(config, ECSJsonFormatter(service_name="test"))
    handler._DEAD_LETTER_MAX_BYTES = 120
    handler._DEAD_LETTER_MAX_FILES = 2
    handler._write_dead_letter(payloads=["x" * 200], error_message="first")
    handler._write_dead_letter(payloads=["y" * 200], error_message="second")
    handler.close()

    assert dead_letter.exists()
    rotated = dead_letter.with_name(f"{dead_letter.name}.1")
    assert rotated.exists()
    assert "first" in rotated.read_text(encoding="utf-8")
    assert "second" in dead_letter.read_text(encoding="utf-8")
