from typing import Any

from clownpeanuts.alerts.discord import send_discord
from clownpeanuts.alerts.router import AlertRouter
from clownpeanuts.alerts.slack import send_slack
from clownpeanuts.alerts.syslog import send_syslog
from clownpeanuts.config.schema import parse_config


def test_parse_alert_destinations_supports_email_and_pagerduty() -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "destinations": [
                    {
                        "name": "email-dest",
                        "type": "email",
                        "endpoint": "smtp://localhost:25",
                        "metadata": {"to": "soc@example.local", "from": "honeypot@example.local"},
                    },
                    {
                        "name": "pagerduty-dest",
                        "type": "pagerduty",
                        "token": "routing-key",
                        "endpoint": "https://events.pagerduty.com/v2/enqueue",
                        "metadata": {"source": "clownpeanuts"},
                    },
                ],
            },
            "services": [],
        }
    )
    assert len(config.alerts.destinations) == 2
    assert config.alerts.destinations[0].destination_type == "email"
    assert config.alerts.destinations[1].destination_type == "pagerduty"
    assert config.alerts.destinations[0].metadata["to"] == "soc@example.local"


def test_parse_alert_destinations_supports_routing_policy_filters() -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "destinations": [
                    {
                        "name": "ssh-critical",
                        "type": "webhook",
                        "endpoint": "https://example.test/webhook",
                        "min_severity": "high",
                        "include_services": ["ssh", "http-admin"],
                        "include_actions": ["credential_capture", "http-request"],
                        "exclude_actions": ["banner_grab"],
                    }
                ],
            },
            "services": [],
        }
    )
    destination = config.alerts.destinations[0]
    assert destination.min_severity == "high"
    assert destination.include_services == ["ssh", "http_admin"]
    assert destination.include_actions == ["credential_capture", "http_request"]
    assert destination.exclude_actions == ["banner_grab"]


def test_alert_router_delivers_to_supported_destinations(monkeypatch: Any) -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [
                    {"name": "webhook", "type": "webhook", "endpoint": "https://example.test/webhook"},
                    {"name": "email", "type": "email", "endpoint": "smtp://localhost:25", "metadata": {"to": "soc@test"}},
                    {"name": "pagerduty", "type": "pagerduty", "token": "rk"},
                ],
            },
            "services": [],
        }
    )
    calls: list[str] = []

    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", lambda **_: calls.append("webhook"))
    monkeypatch.setattr("clownpeanuts.alerts.router.send_email", lambda **_: calls.append("email"))
    monkeypatch.setattr("clownpeanuts.alerts.router.send_pagerduty", lambda **_: calls.append("pagerduty"))

    router = AlertRouter(config.alerts, config.red_team)
    router.send_alert(
        severity="high",
        title="ssh:credential_capture",
        summary="captured creds",
        service="ssh",
        action="credential_capture",
        payload={"service": "ssh", "action": "credential_capture"},
    )
    assert sorted(calls) == ["email", "pagerduty", "webhook"]
    snapshot = router.snapshot()
    assert snapshot["recent"][0]["sent_to"] == ["webhook", "email", "pagerduty"]


def test_alert_router_applies_destination_filters(monkeypatch: Any) -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [
                    {
                        "name": "critical-only",
                        "type": "webhook",
                        "endpoint": "https://example.test/critical",
                        "min_severity": "critical",
                    },
                    {
                        "name": "ssh-commands",
                        "type": "webhook",
                        "endpoint": "https://example.test/ssh",
                        "include_services": ["ssh"],
                        "include_actions": ["command"],
                    },
                    {
                        "name": "exclude-command",
                        "type": "webhook",
                        "endpoint": "https://example.test/exclude",
                        "exclude_actions": ["command"],
                    },
                ],
            },
            "services": [],
        }
    )
    calls: list[str] = []
    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", lambda **_: calls.append("webhook"))

    router = AlertRouter(config.alerts, config.red_team)
    event = router.send_alert(
        severity="high",
        title="ssh:command",
        summary="command observed",
        service="ssh",
        action="command",
        payload={"service": "ssh", "action": "command"},
    )
    assert event is not None
    assert calls == ["webhook"]
    assert event.sent_to == ["ssh-commands"]


def test_alert_router_route_preview_reports_routing_reasons() -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "medium",
                "throttle_seconds": 0,
                "destinations": [
                    {
                        "name": "medium-webhook",
                        "type": "webhook",
                        "endpoint": "https://example.test/webhook",
                    },
                    {
                        "name": "high-only",
                        "type": "webhook",
                        "endpoint": "https://example.test/high",
                        "min_severity": "high",
                    },
                    {
                        "name": "ops-only",
                        "type": "webhook",
                        "endpoint": "https://example.test/ops",
                        "include_services": ["ops"],
                    },
                ],
            },
            "services": [],
        }
    )
    router = AlertRouter(config.alerts, config.red_team)
    preview = router.route_preview(severity="medium", service="ssh", action="command")
    assert preview["deliver_count"] == 1
    reasons = {route["name"]: route["reason"] for route in preview["routes"]}
    assert reasons["high-only"] == "severity_below_high"
    assert reasons["ops-only"] == "service_not_included"


def test_alert_router_suppresses_red_team_payload(monkeypatch: Any) -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [{"name": "webhook", "type": "webhook", "endpoint": "https://example.test/webhook"}],
            },
            "red_team": {"enabled": True, "label": "red_team", "suppress_external_alerts": True},
            "services": [],
        }
    )
    called = {"value": False}

    def _send(**_: Any) -> None:
        called["value"] = True

    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", _send)

    router = AlertRouter(config.alerts, config.red_team)
    router.send_alert(
        severity="critical",
        title="ssh:command",
        summary="red team test",
        service="ssh",
        action="command",
        payload={"service": "ssh", "red_team": True},
    )
    assert called["value"] is False


def test_alert_router_suppresses_internal_cidr_payload(monkeypatch: Any) -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [{"name": "webhook", "type": "webhook", "endpoint": "https://example.test/webhook"}],
            },
            "red_team": {
                "enabled": True,
                "label": "red_team",
                "suppress_external_alerts": True,
                "internal_cidrs": ["203.0.113.0/24"],
            },
            "services": [],
        }
    )
    called = {"value": False}

    def _send(**_: Any) -> None:
        called["value"] = True

    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", _send)

    router = AlertRouter(config.alerts, config.red_team)
    router.send_alert(
        severity="high",
        title="ssh:command",
        summary="internal replay",
        service="ssh",
        action="command",
        payload={
            "service": "ssh",
            "payload": {"source_ip": "203.0.113.44", "command": "id"},
        },
    )
    assert called["value"] is False


def test_alert_router_records_bandit_observability_metrics() -> None:
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
    router = AlertRouter(config.alerts, config.red_team)
    router.send_intel_alert(
        report={"totals": {"sessions": 1, "events": 3, "bandit_reward_avg": 0.6}, "techniques": []},
        bandit_metrics={
            "exploration_ratio": 0.3,
            "reward_avg": 0.6,
            "decision_count": 12,
            "reward_count": 8,
        },
    )
    observability = router.bandit_observability(limit=5)
    assert observability["sample_count"] == 1
    assert observability["current"]["exploration_ratio"] == 0.3
    assert observability["current"]["reward_avg"] == 0.6
    assert router.snapshot()["bandit_observability"]["sample_count"] == 1


def test_alert_router_emits_degradation_alert_for_sustained_reward_drop(monkeypatch: Any) -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 0,
                "destinations": [{"name": "webhook", "type": "webhook", "endpoint": "https://example.test/webhook"}],
            },
            "services": [],
        }
    )
    delivered: list[dict[str, Any]] = []
    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", lambda **kwargs: delivered.append(kwargs["payload"]))

    router = AlertRouter(config.alerts, config.red_team)
    rewards = [0.88, 0.7, 0.45]
    for index, reward in enumerate(rewards):
        router.send_intel_alert(
            report={"totals": {"sessions": 2, "events": 12, "bandit_reward_avg": reward}, "techniques": []},
            bandit_metrics={
                "exploration_ratio": 0.2 + (index * 0.05),
                "reward_avg": reward,
                "decision_count": 20,
                "reward_count": 20 + index,
            },
        )

    titles = [str(item.get("title", "")) for item in delivered]
    assert "bandit_reward_degradation" in titles
    observability = router.bandit_observability(limit=5)
    assert observability["current"]["sustained_degradation"] is True


def test_discord_and_slack_escape_mass_mentions(monkeypatch: Any) -> None:
    discord_payloads: list[dict[str, Any]] = []
    slack_payloads: list[dict[str, Any]] = []
    monkeypatch.setattr("clownpeanuts.alerts.discord.send_webhook", lambda **kwargs: discord_payloads.append(kwargs["payload"]))
    monkeypatch.setattr("clownpeanuts.alerts.slack.send_webhook", lambda **kwargs: slack_payloads.append(kwargs["payload"]))

    payload = {
        "title": "@everyone Incident <@1234567890> <!channel>",
        "severity": "high",
        "summary": "@here investigate immediately <#C12345> @channel",
    }
    send_discord(endpoint="https://example.test/discord", payload=payload)
    send_slack(endpoint="https://example.test/slack", payload=payload)

    assert "@everyone" not in discord_payloads[0]["content"]
    assert "@here" not in discord_payloads[0]["content"]
    assert "<@1234567890>" not in discord_payloads[0]["content"]
    assert "<#C12345>" not in discord_payloads[0]["content"]
    assert "@everyone" not in slack_payloads[0]["blocks"][0]["text"]["text"]
    assert "@here" not in slack_payloads[0]["blocks"][0]["text"]["text"]
    assert "@channel" not in slack_payloads[0]["blocks"][0]["text"]["text"]
    assert "<@1234567890>" not in slack_payloads[0]["blocks"][0]["text"]["text"]
    assert "<!channel>" not in slack_payloads[0]["blocks"][0]["text"]["text"]
    assert "<#C12345>" not in slack_payloads[0]["blocks"][0]["text"]["text"]


def test_syslog_strips_control_characters(monkeypatch: Any) -> None:
    sent: dict[str, Any] = {}

    class _FakeSocket:
        def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
            sent["data"] = data
            sent["addr"] = addr

        def close(self) -> None:
            return

    monkeypatch.setattr("clownpeanuts.alerts.syslog.socket.socket", lambda *args, **kwargs: _FakeSocket())
    send_syslog(
        endpoint="127.0.0.1:514",
        payload={"service": "ssh\nfake", "title": "alert\r\ninject", "severity": "high", "summary": "line1\nline2"},
    )
    message = sent["data"].decode("utf-8", errors="replace")
    assert "\n" not in message
    assert "\r" not in message


def test_alert_router_prunes_unbounded_throttle_cache(monkeypatch: Any) -> None:
    config = parse_config(
        {
            "alerts": {
                "enabled": True,
                "min_severity": "low",
                "throttle_seconds": 1,
                "destinations": [{"name": "webhook", "type": "webhook", "endpoint": "https://example.test/webhook"}],
            },
            "services": [],
        }
    )
    monkeypatch.setattr("clownpeanuts.alerts.router.send_webhook", lambda **_: None)
    router = AlertRouter(config.alerts, config.red_team)
    # Seed with far more than the cap and old timestamps to trigger stale eviction.
    for idx in range(7000):
        router._last_sent[f"k-{idx}"] = 0.0

    router.send_alert(
        severity="high",
        title="ssh:command",
        summary="command observed",
        service="ssh",
        action="command",
        payload={"service": "ssh", "action": "command"},
    )
    assert len(router._last_sent) <= 5000
