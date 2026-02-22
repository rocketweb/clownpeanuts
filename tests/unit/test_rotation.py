from clownpeanuts.config.schema import ServiceConfig, ThreatIntelConfig, parse_config
from clownpeanuts.intel.rotation import ThreatFeedRotator


def test_parse_config_accepts_seasonal_rotation_strategy() -> None:
    config = parse_config({"threat_intel": {"strategy": "seasonal", "seasonal_month_override": 1}, "services": []})
    assert config.threat_intel.strategy == "seasonal"
    assert config.threat_intel.seasonal_month_override == 1


def test_parse_config_rejects_invalid_seasonal_month_override() -> None:
    try:
        parse_config({"threat_intel": {"strategy": "seasonal", "seasonal_month_override": 13}, "services": []})
    except ValueError as exc:
        assert "seasonal_month_override" in str(exc)
        return
    raise AssertionError("expected ValueError for invalid seasonal month override")


def test_threat_feed_rotator_uses_seasonal_profile_when_signal_is_low() -> None:
    rotator = ThreatFeedRotator(
        ThreatIntelConfig(
            enabled=True,
            strategy="seasonal",
            feed_urls=[],
            seasonal_month_override=1,
        )
    )
    services = [ServiceConfig(name="ssh", module="clownpeanuts.services.ssh.emulator", config={}, ports=[2222])]
    rotated = rotator.apply(services)
    assert rotator.last_profile == "ssh-heavy"
    assert rotated[0].config.get("auth_failures_before_success") == 2


def test_threat_feed_rotator_allows_signal_override_in_seasonal_mode(monkeypatch) -> None:
    monkeypatch.setattr(
        ThreatFeedRotator,
        "_read_source",
        staticmethod(lambda _source: "http wordpress admin panel http wordpress phpmyadmin http\n"),
    )
    rotator = ThreatFeedRotator(
        ThreatIntelConfig(
            enabled=True,
            strategy="seasonal",
            feed_urls=["https://feeds.example.test/threat.txt"],
            seasonal_month_override=1,
        )
    )
    services = [ServiceConfig(name="http-admin", module="clownpeanuts.services.http.emulator", config={}, ports=[8080])]
    rotated = rotator.apply(services)
    assert rotator.last_profile == "web-heavy"
    assert rotated[0].config.get("server_name") == "nginx/1.22.1"


def test_threat_feed_rotator_read_source_rejects_non_https_and_files(tmp_path) -> None:
    feed_path = tmp_path / "feed.txt"
    feed_path.write_text("wordpress", encoding="utf-8")

    assert ThreatFeedRotator._read_source(str(feed_path)) == ""
    assert ThreatFeedRotator._read_source("http://feeds.example.test/threat.txt") == ""


def test_threat_feed_rotator_read_source_accepts_public_https(monkeypatch) -> None:
    class _FakeResponse:
        def read(self, _size: int = -1) -> bytes:
            return b"ssh wordpress mysql"

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    monkeypatch.setattr(
        "clownpeanuts.intel.rotation.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr("clownpeanuts.intel.rotation.request.urlopen", lambda *_args, **_kwargs: _FakeResponse())
    payload = ThreatFeedRotator._read_source("https://feeds.example.test/threat.txt")
    assert "wordpress" in payload


def test_threat_feed_rotator_read_source_rejects_private_https_target(monkeypatch) -> None:
    monkeypatch.setattr(
        "clownpeanuts.intel.rotation.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", ("10.0.0.12", 443))],
    )
    payload = ThreatFeedRotator._read_source("https://feeds.example.test/threat.txt")
    assert payload == ""


def test_threat_feed_rotator_read_source_rejects_dns_rebind_between_checks(monkeypatch) -> None:
    class _Resolver:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                return [(0, 0, 0, "", ("93.184.216.34", 443))]
            return [(0, 0, 0, "", ("151.101.1.69", 443))]

    called = {"urlopen": False}

    resolver = _Resolver()
    monkeypatch.setattr("clownpeanuts.intel.rotation.socket.getaddrinfo", resolver)

    def _urlopen(*_args, **_kwargs):
        called["urlopen"] = True
        raise AssertionError("urlopen should not run when DNS resolution drifts")

    monkeypatch.setattr("clownpeanuts.intel.rotation.request.urlopen", _urlopen)
    payload = ThreatFeedRotator._read_source("https://feeds.example.test/threat.txt")
    assert payload == ""
    assert called["urlopen"] is False


def test_threat_feed_rotator_read_source_accepts_subset_re_resolution(monkeypatch) -> None:
    class _FakeResponse:
        def read(self, _size: int = -1) -> bytes:
            return b"redis ssh"

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

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

    monkeypatch.setattr("clownpeanuts.intel.rotation.socket.getaddrinfo", _Resolver())
    monkeypatch.setattr("clownpeanuts.intel.rotation.request.urlopen", lambda *_args, **_kwargs: _FakeResponse())
    payload = ThreatFeedRotator._read_source("https://feeds.example.test/threat.txt")
    assert "redis" in payload
