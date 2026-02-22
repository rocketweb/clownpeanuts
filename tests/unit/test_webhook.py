import pytest

from clownpeanuts.alerts.webhook import MAX_PAYLOAD_BYTES, send_webhook


class _Response:
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        return False


def test_send_webhook_rejects_oversized_payload() -> None:
    payload = {"blob": "x" * (MAX_PAYLOAD_BYTES + 128)}
    with pytest.raises(ValueError):
        send_webhook(endpoint="https://example.test/hook", payload=payload)


def test_send_webhook_posts_bounded_payload(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    observed: dict[str, object] = {}

    def _ok(req, timeout):  # type: ignore[no-untyped-def]
        observed["url"] = req.full_url
        observed["timeout"] = timeout
        observed["size"] = len(req.data or b"")
        return _Response()

    monkeypatch.setattr("clownpeanuts.alerts.webhook.request.urlopen", _ok)
    send_webhook(endpoint="https://example.test/hook", payload={"event": "ok"}, timeout_seconds=1.25)
    assert observed["url"] == "https://example.test/hook"
    assert observed["timeout"] == 1.25
    assert int(observed["size"]) <= MAX_PAYLOAD_BYTES
