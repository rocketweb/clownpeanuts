"""Tests for the SSRF-resistant outbound fetch helper."""

from __future__ import annotations

import pytest

from clownpeanuts.core import safe_fetch
from clownpeanuts.core.safe_fetch import SafeFetchError, safe_fetch as do_fetch, validate_public_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/resource",
        "data:text/plain,hello",
        "gopher://example.com/",
        "//example.com/no-scheme",
    ],
)
def test_rejects_non_http_schemes(url: str) -> None:
    with pytest.raises(SafeFetchError):
        validate_public_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost.localdomain.invalid./",  # unresolvable -> blocked
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://10.0.0.5/",
        "http://192.168.1.10:6379/",
        "http://0.0.0.0/",
    ],
)
def test_rejects_private_and_metadata_targets(url: str) -> None:
    with pytest.raises(SafeFetchError):
        validate_public_url(url)


def test_rejects_embedded_credentials() -> None:
    with pytest.raises(SafeFetchError):
        validate_public_url("http://user:pass@93.184.216.34/")


def test_rejects_non_ascii_host() -> None:
    with pytest.raises(SafeFetchError):
        validate_public_url("http://exámple.com/")


def test_allow_private_opt_in_permits_literal_loopback() -> None:
    host, port, resolved = validate_public_url("http://127.0.0.1:8099/peer", allow_private=True)
    assert host == "127.0.0.1"
    assert port == 8099
    assert resolved == frozenset()


def test_literal_public_ip_is_allowed() -> None:
    host, port, resolved = validate_public_url("https://93.184.216.34/")
    assert host == "93.184.216.34"
    assert port == 443
    assert resolved == frozenset()


def test_safe_fetch_blocks_loopback_before_any_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    # If validation is bypassed, the opener must never be opened.
    def _boom(*args: object, **kwargs: object) -> None:  # pragma: no cover - must not run
        raise AssertionError("opener should not be reached for a blocked target")

    monkeypatch.setattr(safe_fetch._OPENER, "open", _boom)
    with pytest.raises(SafeFetchError):
        do_fetch("http://127.0.0.1/")
    with pytest.raises(SafeFetchError):
        do_fetch("file:///etc/passwd")


def test_safe_fetch_enforces_byte_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self, n: int) -> bytes:
            return b"x" * n  # always returns the full requested count -> over cap

    monkeypatch.setattr(safe_fetch, "validate_public_url", lambda url, allow_private=False: ("h", 80, frozenset()))
    monkeypatch.setattr(safe_fetch._OPENER, "open", lambda req, timeout=None: _Resp())
    with pytest.raises(SafeFetchError, match="cap"):
        do_fetch("http://example.com/", max_bytes=16)
