"""Model-tool integration tests for trusted Kanban authority identity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from hermes_cli import kanban_db as kb
from tools import kanban_tools as kt


@pytest.fixture
def authority_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "hermes"
    root.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setenv("HERMES_PROFILE", "enforcer")
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    (root / "config.yaml").write_text(
        "kanban:\n  authority_enforcement:\n    enabled: true\n", encoding="utf-8"
    )
    for name, role, children in (
        ("enforcer", "lead", ["soldier"]),
        ("developer-capo", "lead", ["drafter"]),
        ("soldier", "junior", []),
        ("drafter", "junior", []),
    ):
        directory = root / "profiles" / name
        directory.mkdir(parents=True)
        (directory / "profile.yaml").write_text(
            yaml.safe_dump({"routing_role": role, "routing_children": children}),
            encoding="utf-8",
        )
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    return root


def test_create_schema_exposes_no_actor_override() -> None:
    props = kt.KANBAN_CREATE_SCHEMA["parameters"]["properties"]
    assert "authority_actor" not in props
    assert "actor_profile" not in props


def test_tool_actor_comes_from_environment_and_denial_inserts_nothing(
    authority_home: Path,
) -> None:
    conn = kb.connect()
    try:
        before = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    finally:
        conn.close()
    result = json.loads(kt._handle_create({
        "title": "foreign child",
        "assignee": "drafter",
        "authority_actor": "default",
    }))
    assert "error" in result
    assert "lead_target_not_owned" in result["error"]
    conn = kb.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before
    finally:
        conn.close()


def test_tool_allows_declared_child_with_environment_actor(authority_home: Path) -> None:
    result = json.loads(kt._handle_create({"title": "own child", "assignee": "soldier"}))
    assert result["ok"] is True
    conn = kb.connect()
    try:
        task = kb.get_task(conn, result["task_id"])
        assert task is not None
        assert task.assignee == "soldier"
        assert task.created_by == "enforcer"
    finally:
        conn.close()


@pytest.mark.parametrize("profile_value", [None, "", "   "])
def test_tool_missing_or_blank_profile_fails_closed_when_enabled(
    authority_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile_value: str | None,
) -> None:
    if profile_value is None:
        monkeypatch.delenv("HERMES_PROFILE", raising=False)
    else:
        monkeypatch.setenv("HERMES_PROFILE", profile_value)
    conn = kb.connect()
    try:
        before = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    finally:
        conn.close()

    result = json.loads(kt._handle_create({
        "title": "impersonated router route",
        "assignee": "developer-capo",
    }))

    assert "error" in result
    assert "unknown_actor" in result["error"]
    conn = kb.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before
    finally:
        conn.close()


def test_tool_explicit_default_allows_lead_and_denies_junior(
    authority_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HERMES_PROFILE", "default")
    allowed = json.loads(kt._handle_create({
        "title": "lead route",
        "assignee": "developer-capo",
    }))
    assert allowed["ok"] is True

    denied = json.loads(kt._handle_create({
        "title": "junior route",
        "assignee": "soldier",
    }))
    assert "error" in denied
    assert "router_target_not_lead" in denied["error"]


def test_tool_flag_off_preserves_unknown_target_compatibility(
    authority_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (authority_home / "config.yaml").write_text("kanban: {}\n", encoding="utf-8")
    monkeypatch.delenv("HERMES_PROFILE", raising=False)
    result = json.loads(kt._handle_create({"title": "legacy", "assignee": "ghost"}))
    assert result["ok"] is True
