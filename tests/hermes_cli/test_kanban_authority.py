"""Scoped tests for the shared Kanban task-create authority boundary."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hermes_cli import kanban_db as kb
from hermes_cli.config import DEFAULT_CONFIG
from hermes_cli.kanban_authority import (
    authority_enforcement_enabled,
    authorize_task_create,
)
from hermes_cli.profiles import read_profile_routing_meta


ROUTES = [
    ("R01", False, "default", "drafter", True, "disabled"),
    ("R02", False, "soldier", "researcher", True, "disabled"),
    ("R03", False, "ghost", "nobody", True, "disabled"),
    ("R04", True, "default", "developer-capo", True, "router_to_lead"),
    ("R05", True, "default", "investigator", True, "router_to_lead"),
    ("R06", True, "default", "drafter", False, "router_target_not_lead"),
    ("R07", True, "enforcer", "soldier", True, "lead_to_child"),
    ("R08", True, "enforcer", "developer-capo", True, "lead_to_peer"),
    ("R09", True, "enforcer", "drafter", False, "lead_target_not_owned"),
    ("R10", True, "developer-capo", "drafter", True, "lead_to_child"),
    ("R11", True, "developer-capo", "coder", True, "lead_to_child"),
    ("R12", True, "developer-capo", "implementer", True, "lead_to_child"),
    ("R13", True, "developer-capo", "researcher", False, "lead_target_not_owned"),
    ("R14", True, "investigator", "researcher", True, "lead_to_child"),
    ("R15", True, "investigator", "bookkeeper", True, "lead_to_child"),
    ("R16", True, "investigator", "soldier", False, "lead_target_not_owned"),
    ("R17", True, "soldier", "detective", False, "actor_role_denied"),
    ("R18", True, "default", "consigliere", True, "router_to_consigliere"),
    ("R19", True, "developer-capo", "consigliere", True, "lead_to_consigliere"),
    ("R20", True, "consigliere", "developer-capo", True, "authority_to_lead"),
    ("R21", True, "consigliere", "default", True, "authority_to_router"),
    ("R22", True, "consigliere", "soldier", False, "authority_target_not_router_or_lead"),
    ("R23", True, "kharon", "default", False, "authority_actor_not_delegated"),
    ("R24", True, "underboss", "developer-capo", False, "authority_actor_not_delegated"),
    ("R25", True, "default", "kharon", False, "router_target_not_lead"),
    ("R26", True, "default", "ghost", False, "unknown_target"),
    ("R27", True, "ghost", "developer-capo", False, "unknown_actor"),
    ("R28", True, "kharon", "ghost", False, "authority_actor_not_delegated"),
]


@pytest.fixture
def roster(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "hermes"
    root.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(root))
    roles = {
        "developer-capo": ("lead", ["drafter", "coder", "implementer"]),
        "investigator": ("lead", ["researcher", "bookkeeper"]),
        "enforcer": ("lead", ["soldier"]),
        "consigliere": ("authority", []),
        "kharon": ("authority", []),
        "underboss": ("authority", []),
        "soldier": ("junior", []),
        "drafter": ("junior", []),
        "coder": ("junior", []),
        "implementer": ("junior", []),
        "researcher": ("junior", []),
        "bookkeeper": ("junior", []),
        "detective": ("junior", []),
    }
    for name, (role, children) in roles.items():
        profile = root / "profiles" / name
        profile.mkdir(parents=True)
        (profile / "profile.yaml").write_text(
            yaml.safe_dump({"routing_role": role, "routing_children": children}),
            encoding="utf-8",
        )
    return root


def test_package_default_and_missing_live_key_are_off(roster: Path) -> None:
    assert DEFAULT_CONFIG["kanban"]["authority_enforcement"]["enabled"] is False
    (roster / "config.yaml").write_text("kanban: {}\n", encoding="utf-8")
    assert authority_enforcement_enabled() is False


def test_flag_reader_uses_global_root_and_requires_boolean(
    roster: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (roster / "config.yaml").write_text(
        "kanban:\n  authority_enforcement:\n    enabled: true\n", encoding="utf-8"
    )
    named_home = roster / "profiles" / "soldier"
    (named_home / "config.yaml").write_text(
        "kanban:\n  authority_enforcement:\n    enabled: false\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(named_home))
    assert authority_enforcement_enabled() is True
    (roster / "config.yaml").write_text(
        "kanban:\n  authority_enforcement:\n    enabled: 1\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="must be boolean"):
        authority_enforcement_enabled()


def test_routing_reader_is_strict_read_only_and_normalizes(roster: Path) -> None:
    assert read_profile_routing_meta("Default") == {
        "routing_role": "router", "routing_children": []
    }
    profile = roster / "profiles" / "enforcer" / "profile.yaml"
    before = profile.read_bytes()
    profile.write_text(
        "routing_role: lead\nrouting_children: [Soldier, soldier, Developer-Capo]\n",
        encoding="utf-8",
    )
    assert read_profile_routing_meta("ENFORCER") == {
        "routing_role": "lead",
        "routing_children": ["soldier", "developer-capo"],
    }
    assert profile.read_bytes() != before
    stable = profile.read_bytes()
    read_profile_routing_meta("enforcer")
    assert profile.read_bytes() == stable


def test_routing_reader_distinguishes_missing_and_invalid_metadata(roster: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_profile_routing_meta("ghost")
    bad = roster / "profiles" / "bad"
    bad.mkdir()
    (bad / "profile.yaml").write_text(
        "routing_role: manager\nrouting_children: child\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="routing_role"):
        read_profile_routing_meta("bad")
    (bad / "profile.yaml").write_text(
        "routing_role: lead\nrouting_children: child\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="routing_children"):
        read_profile_routing_meta("bad")
    (bad / "profile.yaml").write_text("[broken", encoding="utf-8")
    with pytest.raises(ValueError, match="profile.yaml"):
        read_profile_routing_meta("bad")


@pytest.mark.parametrize("probe,enabled,actor,target,allowed,code", ROUTES)
def test_exact_frozen_route_matrix(
    roster: Path,
    probe: str,
    enabled: bool,
    actor: str,
    target: str,
    allowed: bool,
    code: str,
) -> None:
    decision = authorize_task_create(actor, target, enabled=enabled)
    assert set(decision) == {
        "allowed", "code", "actor_profile", "actor_role", "target_profile", "target_role"
    }, probe
    assert decision["allowed"] is allowed, probe
    assert decision["code"] == code, probe


def test_invalid_metadata_fails_closed_with_stable_codes(roster: Path) -> None:
    bad = roster / "profiles" / "bad"
    bad.mkdir()
    (bad / "profile.yaml").write_text("routing_role: nope\nrouting_children: []\n", encoding="utf-8")
    assert authorize_task_create("bad", "soldier", enabled=True)["code"] == "invalid_actor_metadata"
    assert authorize_task_create("default", "bad", enabled=True)["code"] == "invalid_target_metadata"


def _isolated_conn():
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    return kb.connect()


def test_create_task_denial_inserts_no_row(roster: Path) -> None:
    conn = _isolated_conn()
    try:
        before = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        with pytest.raises(ValueError, match="router_target_not_lead.*default.*drafter"):
            kb.create_task(
                conn, title="denied", assignee="drafter",
                authority_actor="default", authority_enabled=True,
            )
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before
    finally:
        conn.close()


def test_idempotency_replay_precedes_authorization(roster: Path) -> None:
    conn = _isolated_conn()
    try:
        existing = kb.create_task(
            conn, title="historical", assignee="drafter", idempotency_key="same"
        )
        replay = kb.create_task(
            conn, title="forbidden now", assignee="drafter", idempotency_key="same",
            authority_actor="default", authority_enabled=True,
        )
        assert replay == existing
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1

        with pytest.raises(ValueError, match="actor_role_denied"):
            kb.create_task(
                conn, title="new forbidden", assignee="developer-capo",
                idempotency_key="new", authority_actor="soldier", authority_enabled=True,
            )
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        conn.close()
