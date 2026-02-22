import pytest

from clownpeanuts.config.schema import parse_config
from clownpeanuts.core.network import NetworkIsolationError
from clownpeanuts.core.orchestrator import Orchestrator


def test_orchestrator_blocks_non_segmented_runtime() -> None:
    config = parse_config(
        {
            "network": {
                "segmentation_mode": "none",
                "require_segmentation": True,
                "enforce_runtime": True,
                "allow_outbound": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    with pytest.raises(NetworkIsolationError):
        orchestrator.bootstrap()


def test_orchestrator_blocks_when_firewall_verification_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._detect_firewall_backend",
        staticmethod(lambda: None),
    )
    config = parse_config(
        {
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "verify_host_firewall": True,
                "allow_outbound": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    with pytest.raises(NetworkIsolationError):
        orchestrator.bootstrap()


def test_orchestrator_blocks_when_required_docker_network_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._docker_network_exists",
        staticmethod(lambda _name: (False, "network missing")),
    )
    config = parse_config(
        {
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "verify_docker_network": True,
                "required_docker_network": "clownpeanuts",
                "allow_outbound": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    with pytest.raises(NetworkIsolationError):
        orchestrator.bootstrap()


def test_orchestrator_passes_when_runtime_network_checks_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._detect_firewall_backend",
        staticmethod(lambda: "iptables"),
    )
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._docker_network_exists",
        staticmethod(lambda _name: (True, "ok")),
    )
    config = parse_config(
        {
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "verify_host_firewall": True,
                "verify_docker_network": True,
                "required_docker_network": "clownpeanuts",
                "allow_outbound": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    status = orchestrator.status()
    assert status["network"]["compliant"] is True


def test_orchestrator_applies_nft_firewall_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._detect_firewall_backend",
        staticmethod(lambda: "nft"),
    )
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._apply_nft_policy",
        lambda _self, _config: ["nft add table inet clownpeanuts"],
    )
    config = parse_config(
        {
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "apply_firewall_rules": True,
                "firewall_dry_run": True,
                "allow_outbound": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    status = orchestrator.status()
    assert status["network"]["applied_rules"] == ["nft add table inet clownpeanuts"]
    assert status["network"]["compliant"] is True


def test_orchestrator_applies_pfctl_firewall_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._detect_firewall_backend",
        staticmethod(lambda: "pfctl"),
    )
    monkeypatch.setattr(
        "clownpeanuts.core.network.NetworkIsolationManager._apply_pfctl_policy",
        lambda _self, _config: ["pfctl -a clownpeanuts/egress -f -"],
    )
    config = parse_config(
        {
            "network": {
                "segmentation_mode": "vxlan",
                "require_segmentation": True,
                "enforce_runtime": True,
                "apply_firewall_rules": True,
                "firewall_dry_run": True,
                "allow_outbound": False,
            },
            "services": [],
        }
    )
    orchestrator = Orchestrator(config)
    orchestrator.bootstrap()
    status = orchestrator.status()
    assert status["network"]["applied_rules"] == ["pfctl -a clownpeanuts/egress -f -"]
    assert status["network"]["compliant"] is True
