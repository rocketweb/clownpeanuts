from __future__ import annotations

from pathlib import Path
import sys
import types
from typing import Any

from clownpeanuts.agents import AgentBackendLoadError
from clownpeanuts.agents.adlibs import (
    ADConnector,
    ADConnectorConfig,
    ADEventMonitor,
    ADLibsManager,
    ADObjectSeeder,
    fabricate_relationships,
)
from clownpeanuts.agents.dirtylaundry import (
    DirtyLaundryManager,
    MatchingEngine,
    ProfileStore,
    classify_skill_level,
    export_profiles,
    export_profiles_stix,
    import_profiles,
    policy_for_skill,
)
from clownpeanuts.agents.pripyatsprings import (
    FingerprintRegistry,
    PripyatSpringsManager,
    ToxicDataMiddleware,
    TrackingRegistry,
)
from clownpeanuts.agents.pripyatsprings.middleware import MiddlewareConfig
from clownpeanuts.agents.runtime import AgentRuntime
from clownpeanuts.config.schema import ADLibsConfig, PripyatSpringsConfig, parse_config


def test_pripyatsprings_middleware_levels() -> None:
    payload = {"record": "row-1"}

    disabled = ToxicDataMiddleware(MiddlewareConfig(enabled=False))
    disabled_result = disabled.transform(payload)
    assert disabled_result == payload

    enabled = ToxicDataMiddleware(MiddlewareConfig(enabled=True, default_toxicity=2))
    level2 = enabled.transform(payload)
    assert level2["tracking_enabled"] is True
    assert level2["corruption_applied"] is True
    assert "active_payload_markers_applied" not in level2

    level3 = enabled.transform(payload, toxicity_level=3)
    assert level3["active_payload_markers_applied"] is True
    assert level3["toxicity_level"] == 3


def test_pripyatsprings_fingerprint_and_tracking_registries() -> None:
    fingerprints = FingerprintRegistry()
    tracking = TrackingRegistry()

    record = fingerprints.register(
        payload="secret-row",
        session_id="session-1",
        deployment_id="deployment-1",
        metadata={"surface": "db-export"},
    )
    hit = tracking.register_hit(
        fingerprint_id=record.fingerprint_id,
        source_ip="203.0.113.7",
        user_agent="curl/8.0",
        headers={"x-test": "1"},
    )

    assert hit.fingerprint_id == record.fingerprint_id
    assert tracking.summary()["count"] == 1
    assert fingerprints.get(record.fingerprint_id) is not None


def test_pripyatsprings_runtime_manager_end_to_end() -> None:
    emitted: list[dict[str, Any]] = []
    manager = PripyatSpringsManager(
        PripyatSpringsConfig(
            enabled=True,
            default_toxicity=2,
            tracking_domain="t.example.local",
            canary_dns_domain="c.example.local",
            tracking_server_port=8443,
        ),
        emit_hook=lambda payload: emitted.append(dict(payload)),
    )
    fingerprint = manager.register_fingerprint(
        {
            "payload": "sensitive-row",
            "session_id": "session-1",
            "deployment_id": "deployment-1",
        }
    )
    assert fingerprint["fingerprint_id"]

    hit = manager.record_hit(
        {
            "fingerprint_id": fingerprint["fingerprint_id"],
            "source_ip": "203.0.113.7",
            "user_agent": "curl/8.0",
        }
    )
    assert hit["fingerprint_id"] == fingerprint["fingerprint_id"]
    assert hit["session_id"] == "session-1"
    assert hit["deployment_id"] == "deployment-1"
    assert manager.list_hits()["count"] == 1
    listed_hit = manager.list_hits()["hits"][0]
    assert listed_hit["session_id"] == "session-1"
    assert listed_hit["deployment_id"] == "deployment-1"
    summary = manager.hit_summary()
    assert summary["count"] == 1
    assert summary["by_source_ip"][0]["source_ip"] == "203.0.113.7"
    assert summary["by_session_id"][0]["session_id"] == "session-1"
    assert emitted
    assert emitted[0]["fingerprint_id"] == fingerprint["fingerprint_id"]


def test_pripyatsprings_runtime_enforces_level3_acknowledgment() -> None:
    manager = PripyatSpringsManager(
        PripyatSpringsConfig(
            enabled=True,
            default_toxicity=2,
            level3_acknowledgment="",
        )
    )
    try:
        manager.transform({"record": "row-1"}, toxicity_level=3)
        raise AssertionError("expected toxicity level 3 guard")
    except RuntimeError as exc:
        assert "level3_acknowledgment" in str(exc)


def test_pripyatsprings_runtime_persists_state_with_store_path(tmp_path: Path) -> None:
    db_path = tmp_path / "pripyatsprings.sqlite3"
    manager_a = PripyatSpringsManager(
        PripyatSpringsConfig(
            enabled=True,
            default_toxicity=2,
            level3_acknowledgment="ops-2026-02-21",
            store_path=str(db_path),
        )
    )
    fingerprint = manager_a.register_fingerprint(
        {
            "payload": "sensitive-row",
            "session_id": "session-1",
            "deployment_id": "deployment-1",
        }
    )
    manager_a.record_hit(
        {
            "fingerprint_id": fingerprint["fingerprint_id"],
            "source_ip": "203.0.113.7",
        }
    )
    manager_a.close()

    manager_b = PripyatSpringsManager(
        PripyatSpringsConfig(
            enabled=True,
            default_toxicity=2,
            level3_acknowledgment="ops-2026-02-21",
            store_path=str(db_path),
        )
    )
    assert manager_b.list_fingerprints(limit=10)["count"] == 1
    assert manager_b.list_hits(limit=10)["count"] == 1
    manager_b.close()


def test_adlibs_connector_seeder_monitor_workflows() -> None:
    connector = ADConnector(
        ADConnectorConfig(
            ldap_uri="ldaps://dc.example.local:636",
            bind_dn="CN=svc,OU=Service Accounts,DC=example,DC=local",
            bind_password_env="CP_AD_BIND_PASSWORD",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
        )
    )
    assert connector.validate() == []
    assert connector.status()["ready"] is True

    seeder = ADObjectSeeder(target_ou="OU=Deception,DC=example,DC=local")
    plan = seeder.validate_plan(fake_users=2, fake_service_accounts=1, fake_groups=1)
    assert plan["ready"] is True
    assert plan["projected_total"] == 4
    assert plan["preview"]["users"]["preview_count"] == 2
    assert plan["preview"]["service_accounts"]["preview_count"] == 1
    assert plan["preview"]["groups"]["preview_count"] == 1
    seeded = seeder.seed(fake_users=2, fake_service_accounts=1, fake_groups=1)
    assert seeded["status"] == "seeded"
    assert seeded["count"] == 4

    objects = seeder.list_objects(limit=20)
    assert len(objects) == 4
    relationships = fabricate_relationships(objects)
    assert relationships

    monitor = ADEventMonitor()
    trip = monitor.record_trip(
        object_id=objects[0]["object_id"],
        event_type="4769",
        source_host="workstation-1",
        source_user="alice",
    )
    assert trip.object_id == objects[0]["object_id"]
    assert monitor.list_trips(limit=10)[0]["event_type"] == "4769"
    catalog = monitor.event_catalog()
    assert any(row["event_id"] == "4769" for row in catalog)
    assert monitor.classify_event_type("4769") == "kerberos_service_ticket"


def test_adlibs_runtime_persists_objects_and_trips_with_store_path(tmp_path: Path) -> None:
    db_path = tmp_path / "adlibs.sqlite3"
    manager_a = ADLibsManager(
        ADLibsConfig(
            enabled=True,
            ldap_uri="ldaps://dc.example.local:636",
            ldap_bind_dn="CN=svc,OU=Service Accounts,DC=example,DC=local",
            ldap_bind_password_env="CP_AD_BIND_PASSWORD",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
            fake_users=1,
            fake_service_accounts=1,
            fake_groups=0,
            store_path=str(db_path),
        )
    )
    seeded = manager_a.seed()
    assert seeded["count"] == 2
    manager_a.record_trip(
        {
            "object_id": seeded["objects"][0]["object_id"],
            "event_type": "4769",
        }
    )
    manager_a.close()

    manager_b = ADLibsManager(
        ADLibsConfig(
            enabled=True,
            ldap_uri="ldaps://dc.example.local:636",
            ldap_bind_dn="CN=svc,OU=Service Accounts,DC=example,DC=local",
            ldap_bind_password_env="CP_AD_BIND_PASSWORD",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
            fake_users=1,
            fake_service_accounts=1,
            fake_groups=0,
            store_path=str(db_path),
        )
    )
    assert manager_b.list_objects(limit=10)["count"] == 2
    assert manager_b.list_trips(limit=10)["count"] == 1
    manager_b.close()


def test_adlibs_connector_requires_bind_credentials() -> None:
    connector = ADConnector(
        ADConnectorConfig(
            ldap_uri="ldaps://dc.example.local:636",
            bind_dn="",
            bind_password_env="",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
        )
    )
    issues = connector.validate()
    assert "ldap_bind_dn is required" in issues
    assert "ldap_bind_password_env is required" in issues


def test_adlibs_manager_trip_list_filters() -> None:
    manager = ADLibsManager(
        ADLibsConfig(
            enabled=True,
            ldap_uri="ldaps://dc.example.local:636",
            ldap_bind_dn="CN=svc,OU=Service Accounts,DC=example,DC=local",
            ldap_bind_password_env="CP_AD_BIND_PASSWORD",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
        )
    )
    manager.record_trip(
        {
            "object_id": "adlibs-user-1",
            "event_type": "4769",
            "source_host": "wkstn-01",
            "source_user": "alice",
        }
    )
    manager.record_trip(
        {
            "object_id": "adlibs-user-2",
            "event_type": "4624",
            "source_host": "adm-01",
            "source_user": "bob",
        }
    )

    kerberos_only = manager.list_trips(limit=10, event_type="4769")
    assert kerberos_only["count"] == 1
    assert kerberos_only["trips"][0]["event_type"] == "4769"

    adm_hosts = manager.list_trips(limit=10, source_host_prefix="adm")
    assert adm_hosts["count"] == 1
    assert adm_hosts["trips"][0]["source_host"] == "adm-01"
    summary = manager.trip_summary(limit=10)
    assert summary["count"] == 2
    assert summary["by_event_type"][0]["count"] == 1
    assert summary["by_source_user"][0]["count"] == 1
    manager.close()


def test_adlibs_manager_emits_trip_hook() -> None:
    emitted: list[dict[str, Any]] = []
    manager = ADLibsManager(
        ADLibsConfig(
            enabled=True,
            ldap_uri="ldaps://dc.example.local:636",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
        ),
        emit_hook=lambda payload: emitted.append(dict(payload)),
    )
    trip = manager.record_trip(
        {
            "object_id": "adlibs-user-1",
            "event_type": "4624",
            "source_host": "workstation-1",
            "source_user": "analyst-1",
            "metadata": {"channel": "wef"},
        }
    )
    assert trip["event_type"] == "4624"
    assert emitted
    assert emitted[0]["object_id"] == "adlibs-user-1"


def test_adlibs_manager_event_ingest_and_catalog() -> None:
    manager = ADLibsManager(
        ADLibsConfig(
            enabled=True,
            ldap_uri="ldaps://dc.example.local:636",
            ldap_bind_dn="CN=svc,OU=Service Accounts,DC=example,DC=local",
            ldap_bind_password_env="CP_ADLIBS_PASSWORD",
            base_dn="DC=example,DC=local",
            target_ou="OU=Deception,DC=example,DC=local",
            fake_users=1,
            fake_service_accounts=0,
            fake_groups=0,
        )
    )
    seeded = manager.seed()
    target_name = seeded["objects"][0]["name"]
    catalog = manager.event_catalog()
    assert catalog["count"] >= 6

    ingested = manager.ingest_event(
        {
            "event_id": 4769,
            "target_account": target_name,
            "source_host": "wkstn-44",
            "source_user": "attacker",
        }
    )
    assert ingested["status"] == "recorded"
    assert ingested["event_type"] == "kerberos_service_ticket"

    batch = manager.ingest_events(
        [
            {"event_id": 4624, "target_account": target_name, "source_host": "wkstn-44"},
            {"event_id": 4768, "target_account": "missing-user", "source_host": "wkstn-45"},
        ]
    )
    assert batch["recorded"] == 1
    assert batch["ignored"] == 1
    manager.close()


def test_dirtylaundry_profile_matching_and_sharing() -> None:
    store = ProfileStore()
    metrics = {
        "typing_cadence": 0.7,
        "command_vocabulary": 0.65,
        "tool_signatures": 0.8,
        "temporal_pattern": 0.5,
        "credential_reuse": 0.3,
    }
    skill = classify_skill_level(metrics)
    profile = store.create_profile(skill=skill, session_id="session-a", metrics=metrics)
    assert profile.skill in {"script_kiddie", "intermediate", "advanced", "apt"}
    assert policy_for_skill(profile.skill)["cascade_depth"] >= 2

    matcher = MatchingEngine(threshold=0.4)
    ranked = matcher.ranked_matches(current=metrics, profiles={profile.profile_id: profile.metrics}, limit=5)
    assert len(ranked) == 1
    assert ranked[0].profile_id == profile.profile_id
    match = matcher.match(current=metrics, profiles={profile.profile_id: profile.metrics})
    assert match is not None
    assert match.profile_id == profile.profile_id
    assert match.score >= 0.4
    assert "typing_cadence" in match.breakdown

    exported = export_profiles(store.list_profiles())
    imported_store = ProfileStore()
    imported = import_profiles(exported, store=imported_store)
    assert imported["status"] == "imported"
    assert imported["imported"] == 1

    stix_bundle = export_profiles_stix(store.list_profiles())
    assert stix_bundle["type"] == "bundle"
    imported_stix_store = ProfileStore()
    imported_stix = import_profiles(stix_bundle, store=imported_stix_store)
    assert imported_stix["status"] == "imported"
    assert imported_stix["format"] == "stix"
    assert imported_stix["imported"] == 1


def test_dirtylaundry_runtime_share_push_pull(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = DirtyLaundryManager(
        parse_config(
            {
                "ecosystem": {"enabled": True},
                "agents": {
                    "dirtylaundry": {
                        "enabled": True,
                        "sharing": {
                            "enabled": True,
                            "endpoint": "https://sharing.example",
                            "request_timeout_seconds": 7.0,
                            "headers": {"Authorization": "Bearer test-token"},
                        },
                    }
                },
                "services": [],
            }
        ).agents.dirtylaundry
    )
    manager.ingest_session(
        {
            "session_id": "session-1",
            "metrics": {
                "typing_cadence": 0.8,
                "command_vocabulary": 0.8,
                "tool_signatures": 0.8,
                "temporal_pattern": 0.8,
                "credential_reuse": 0.8,
            },
        }
    )

    def _fake_push(
        *,
        endpoint: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        assert endpoint == "https://sharing.example"
        assert isinstance(payload, dict)
        assert headers == {"Authorization": "Bearer test-token"}
        assert timeout_seconds == 7.0
        return {"status": "accepted"}

    def _fake_pull(
        *,
        endpoint: str,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        assert endpoint == "https://sharing.example"
        assert headers == {"Authorization": "Bearer test-token"}
        assert timeout_seconds == 7.0
        return {
            "schema": "clownpeanuts.dirtylaundry.profile_share.v1",
            "profiles": [
                {
                    "profile_id": "remote-profile-1",
                    "skill": "advanced",
                    "created_at": "2026-02-21T00:00:00+00:00",
                    "last_seen_at": "2026-02-21T01:00:00+00:00",
                    "metrics": {"typing_cadence": 0.9},
                }
            ],
        }

    monkeypatch.setattr("clownpeanuts.agents.dirtylaundry.runtime.push_share_payload", _fake_push)
    monkeypatch.setattr("clownpeanuts.agents.dirtylaundry.runtime.pull_share_payload", _fake_pull)

    pushed = manager.share_push(format_name="native")
    assert pushed["status"] == "pushed"
    assert pushed["endpoint"] == "https://sharing.example"

    pulled = manager.share_pull()
    assert pulled["status"] == "pulled"
    assert pulled["import"]["status"] == "imported"
    assert pulled["import"]["imported"] >= 1


def test_dirtylaundry_profile_list_filters_and_sorting() -> None:
    manager = DirtyLaundryManager(
        parse_config(
            {
                "ecosystem": {"enabled": True},
                "agents": {"dirtylaundry": {"enabled": True}},
                "services": [],
            }
        ).agents.dirtylaundry
    )

    manager.ingest_session(
        {
            "session_id": "dl-apt-1",
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            },
        }
    )
    manager.ingest_session(
        {
            "session_id": "dl-script-1",
            "metrics": {
                "typing_cadence": 0.1,
                "command_vocabulary": 0.1,
                "tool_signatures": 0.1,
                "temporal_pattern": 0.1,
                "credential_reuse": 0.1,
            },
        }
    )
    manager.ingest_session(
        {
            "session_id": "dl-script-2",
            "metrics": {
                "typing_cadence": 0.1,
                "command_vocabulary": 0.1,
                "tool_signatures": 0.1,
                "temporal_pattern": 0.1,
                "credential_reuse": 0.1,
            },
        }
    )

    apt_only = manager.list_profiles(limit=10, skill="apt")
    assert apt_only["count"] == 1
    assert apt_only["profiles"][0]["skill"] == "apt"

    repeated = manager.list_profiles(limit=10, min_sessions=2, sort_by="session_count", sort_order="desc")
    assert repeated["count"] == 1
    assert repeated["profiles"][0]["session_count"] == 2

    by_query = manager.list_profiles(limit=10, query="dl-script-2")
    assert by_query["count"] == 1
    assert by_query["profiles"][0]["skill"] == "script_kiddie"


def test_dirtylaundry_profile_store_persists_with_sqlite_path(tmp_path: Path) -> None:
    db_path = tmp_path / "dirtylaundry-profiles.sqlite3"
    store_a = ProfileStore(db_path=db_path)
    created = store_a.create_profile(
        skill="advanced",
        session_id="session-a",
        metrics={
            "typing_cadence": 0.8,
            "command_vocabulary": 0.7,
            "tool_signatures": 0.9,
            "temporal_pattern": 0.6,
            "credential_reuse": 0.4,
        },
    )
    store_a.add_note(profile_id=created.profile_id, note="seed-note")
    store_a.close()

    store_b = ProfileStore(db_path=db_path)
    persisted = store_b.get_profile(created.profile_id)
    assert persisted is not None
    assert persisted.profile_id == created.profile_id
    assert persisted.sessions == ["session-a"]
    assert persisted.notes == ["seed-note"]
    store_b.close()


def test_dirtylaundry_profile_share_import_upserts_by_profile_id() -> None:
    store = ProfileStore()
    payload = {
        "schema": "clownpeanuts.dirtylaundry.profile_share.v1",
        "profiles": [
            {
                "profile_id": "shared-profile-1",
                "skill": "intermediate",
                "created_at": "2026-02-21T00:00:00+00:00",
                "last_seen_at": "2026-02-21T01:00:00+00:00",
                "metrics": {"typing_cadence": 0.5},
            }
        ],
    }
    first = import_profiles(payload, store=store)
    assert first["status"] == "imported"
    assert first["imported"] == 1
    second = import_profiles(payload, store=store)
    assert second["imported"] == 1
    profiles = store.list_profiles(limit=20)
    assert len(profiles) == 1
    assert profiles[0].profile_id == "shared-profile-1"


def test_dirtylaundry_auto_theater_recommendation_for_apt_profiles() -> None:
    emitted: list[dict[str, Any]] = []
    manager = DirtyLaundryManager(
        parse_config(
            {
                "services": [],
                "agents": {
                    "dirtylaundry": {
                        "enabled": True,
                        "auto_theater_on_apt": True,
                    }
                },
            }
        ).agents.dirtylaundry,
        emit_hook=lambda item: emitted.append(dict(item)),
    )
    result = manager.ingest_session(
        {
            "session_id": "apt-session-1",
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            },
        }
    )
    assert result["profile"]["skill"] == "apt"
    assert result["auto_theater_recommended"] is True
    assert emitted


def test_dirtylaundry_evaluate_and_reclassify_session() -> None:
    manager = DirtyLaundryManager(
        parse_config(
            {
                "ecosystem": {"enabled": True},
                "agents": {"dirtylaundry": {"enabled": True}},
                "services": [],
            }
        ).agents.dirtylaundry
    )
    created = manager.ingest_session(
        {
            "session_id": "dl-reclass-1",
            "metrics": {
                "typing_cadence": 0.2,
                "command_vocabulary": 0.2,
                "tool_signatures": 0.2,
                "temporal_pattern": 0.2,
                "credential_reuse": 0.2,
            },
        }
    )
    profile_id = created["profile"]["profile_id"]
    evaluated = manager.evaluate_policy(
        {
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            }
        }
    )
    assert evaluated["skill"] == "apt"

    reclassified = manager.reclassify_session(
        {
            "session_id": "dl-reclass-1",
            "profile_id": profile_id,
            "metrics": {
                "typing_cadence": 0.95,
                "command_vocabulary": 0.95,
                "tool_signatures": 0.95,
                "temporal_pattern": 0.95,
                "credential_reuse": 0.95,
            },
        }
    )
    assert reclassified["status"] == "reclassified"
    assert reclassified["current_skill"] == "apt"
    preview = manager.preview_matches({"metrics": reclassified["metrics"], "limit": 3, "include_breakdown": True})
    assert preview["count"] >= 1
    assert preview["candidate_profile_id"] == profile_id
    assert isinstance(preview["matches"][0]["breakdown"], dict)


def test_dirtylaundry_stats_include_return_rate_and_average_sessions() -> None:
    manager = DirtyLaundryManager(
        parse_config({"ecosystem": {"enabled": True}, "agents": {"dirtylaundry": {"enabled": True}}, "services": []}).agents.dirtylaundry
    )
    metrics = {
        "typing_cadence": 0.8,
        "command_vocabulary": 0.8,
        "tool_signatures": 0.8,
        "temporal_pattern": 0.8,
        "credential_reuse": 0.8,
    }
    manager.ingest_session({"session_id": "session-1", "metrics": metrics})
    manager.ingest_session({"session_id": "session-2", "metrics": metrics})
    stats = manager.stats()
    assert stats["profile_count"] == 1
    assert stats["total_sessions"] == 2
    assert stats["average_sessions_per_profile"] == 2.0
    assert stats["return_rate"] == 1.0


def test_dirtylaundry_profile_store_caps_sessions_notes_and_profiles() -> None:
    store = ProfileStore(max_profiles=2, max_sessions_per_profile=2, max_notes_per_profile=2)
    store.create_profile(profile_id="p1", skill="intermediate", session_id="", metrics={}, created_at="2026-02-21T00:00:00+00:00", last_seen_at="2026-02-21T00:00:00+00:00")
    store.create_profile(profile_id="p2", skill="intermediate", session_id="", metrics={}, created_at="2026-02-21T00:01:00+00:00", last_seen_at="2026-02-21T00:01:00+00:00")
    store.create_profile(profile_id="p3", skill="intermediate", session_id="", metrics={}, created_at="2026-02-21T00:02:00+00:00", last_seen_at="2026-02-21T00:02:00+00:00")
    profiles = store.list_profiles(limit=10)
    assert len(profiles) == 2
    assert {row.profile_id for row in profiles} == {"p2", "p3"}

    store.add_session(profile_id="p3", session_id="s1")
    store.add_session(profile_id="p3", session_id="s2")
    store.add_session(profile_id="p3", session_id="s3")
    store.add_note(profile_id="p3", note="n1")
    store.add_note(profile_id="p3", note="n2")
    store.add_note(profile_id="p3", note="n3")
    profile = store.get_profile("p3")
    assert profile is not None
    assert profile.sessions == ["s2", "s3"]
    assert profile.notes == ["n2", "n3"]


def test_agent_runtime_reports_blockers_for_misconfigured_modules() -> None:
    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "pripyatsprings": {
                    "enabled": True,
                    "default_toxicity": 3,
                    "level3_acknowledgment": "",
                },
                "adlibs": {"enabled": True},
                "dirtylaundry": {
                    "enabled": True,
                    "sharing": {"enabled": True, "endpoint": ""},
                },
            },
            "services": [],
        }
    )
    runtime = AgentRuntime(config=config.agents, ecosystem_enabled=config.ecosystem.enabled)
    snapshot = runtime.snapshot()
    assert snapshot["blocked_count"] == 3
    by_name = {row["name"]: row for row in snapshot["modules"]}
    assert by_name["pripyatsprings"]["state"] == "blocked"
    assert by_name["adlibs"]["state"] == "blocked"
    assert by_name["dirtylaundry"]["state"] == "blocked"
    assert by_name["pripyatsprings"]["blockers"]
    assert by_name["adlibs"]["blockers"]
    assert by_name["dirtylaundry"]["blockers"]


def test_agent_runtime_blocks_pripyatsprings_level3_override_without_ack() -> None:
    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "pripyatsprings": {
                    "enabled": True,
                    "default_toxicity": 2,
                    "level3_acknowledgment": "",
                    "per_emulator_overrides": {"ssh-main": 3},
                }
            },
            "services": [],
        }
    )
    runtime = AgentRuntime(config=config.agents, ecosystem_enabled=config.ecosystem.enabled)
    snapshot = runtime.snapshot()
    by_name = {row["name"]: row for row in snapshot["modules"]}
    assert by_name["pripyatsprings"]["state"] == "blocked"
    assert by_name["pripyatsprings"]["blockers"]


def test_agent_runtime_reports_backend_configuration_flags() -> None:
    config = parse_config(
        {
            "ecosystem": {"enabled": True},
            "agents": {
                "pripyatsprings": {"enabled": True, "backend": "private.ps:Backend"},
                "adlibs": {"enabled": True},
                "dirtylaundry": {"enabled": True, "backend": "private.dl:Backend"},
            },
            "services": [],
        }
    )
    runtime = AgentRuntime(config=config.agents, ecosystem_enabled=config.ecosystem.enabled)
    snapshot = runtime.snapshot()
    by_name = {row["name"]: row for row in snapshot["modules"]}
    assert by_name["pripyatsprings"]["config"]["backend_configured"] is True
    assert by_name["adlibs"]["config"]["backend_configured"] is False
    assert by_name["dirtylaundry"]["config"]["backend_configured"] is True


def test_pripyatsprings_manager_supports_external_backend() -> None:
    module_name = "tests._pripyatsprings_backend"
    backend_module = types.ModuleType(module_name)

    class _Backend:
        def __init__(self, *, config: Any, emit_hook: Any = None) -> None:
            self._emit_hook = emit_hook

        def close(self) -> None:
            return None

        def status(self) -> dict[str, Any]:
            return {
                "enabled": True,
                "backend_mode": "external",
            }

        def resolve_toxicity_level(self, *, emulator: str = "", toxicity_level: int | None = None) -> int:
            return 2

        def register_fingerprint(self, payload: dict[str, Any]) -> dict[str, Any]:
            return {"fingerprint_id": "fp-1", "session_id": "s-1", "deployment_id": "d-1"}

        def list_fingerprints(self, *, limit: int = 200) -> dict[str, Any]:
            return {"count": 0, "fingerprints": []}

        def list_fingerprints_filtered(self, **_kwargs: Any) -> dict[str, Any]:
            return {"count": 0, "fingerprints": []}

        def record_hit(self, payload: dict[str, Any]) -> dict[str, Any]:
            if self._emit_hook is not None:
                self._emit_hook({"source_ip": payload.get("source_ip", "")})
            return {"hit_id": "hit-1"}

        def list_hits(self, *, limit: int = 200) -> dict[str, Any]:
            return {"count": 0, "hits": []}

        def list_hits_filtered(self, **_kwargs: Any) -> dict[str, Any]:
            return {"count": 0, "hits": []}

        def transform(self, payload: dict[str, Any], *, toxicity_level: int | None = None) -> dict[str, Any]:
            return {"status": "delegated", "toxicity_level": 2, "payload": payload}

    backend_module.Backend = _Backend  # type: ignore[attr-defined]
    sys.modules[module_name] = backend_module
    try:
        emitted: list[dict[str, Any]] = []
        manager = PripyatSpringsManager(
            PripyatSpringsConfig(
                enabled=True,
                backend=f"{module_name}:Backend",
            ),
            emit_hook=lambda payload: emitted.append(dict(payload)),
        )
        assert manager.status()["backend_mode"] == "external"
        transformed = manager.transform({"record": "one"})
        assert transformed["status"] == "delegated"
        manager.record_hit({"source_ip": "203.0.113.10"})
        assert emitted
    finally:
        sys.modules.pop(module_name, None)


def test_pripyatsprings_manager_rejects_invalid_external_backend_path() -> None:
    try:
        PripyatSpringsManager(PripyatSpringsConfig(enabled=True, backend="invalid-backend-path"))
        raise AssertionError("expected backend load failure")
    except AgentBackendLoadError:
        pass
