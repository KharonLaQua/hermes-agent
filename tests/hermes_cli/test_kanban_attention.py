"""Regression tests for the metadata-only Kanban attention summary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb
from hermes_cli.kanban_attention import attention_summary, project_attention_rows


@pytest.fixture
def kanban_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def test_project_attention_rows_matches_hq_attention_semantics() -> None:
    rows = [
        {
            "id": "don-only",
            "title": "Await approval",
            "status": "blocked",
            "assignee": "owner",
            "block_kind": "needs_input",
            "blocked_reason": "DON-ONLY: approve public send",
            "open_parents": 0,
        },
        {
            "id": "credential",
            "title": "Credential permission change",
            "status": "blocked",
            "assignee": "owner",
            "block_kind": "capability",
            "blocked_reason": "Need approval",
            "open_parents": 0,
        },
        {
            "id": "open-parent",
            "title": "Child task",
            "status": "todo",
            "assignee": "worker",
            "block_kind": "",
            "blocked_reason": "",
            "open_parents": 1,
        },
        {
            "id": "transient",
            "title": "Retry later",
            "status": "blocked",
            "assignee": "worker",
            "block_kind": "transient",
            "blocked_reason": "temporary harness failure",
            "open_parents": 0,
        },
        {
            "id": "review",
            "title": "Peer review",
            "status": "todo",
            "assignee": "worker",
            "block_kind": "needs_input",
            "blocked_reason": "review-required: peer evidence",
            "open_parents": 0,
        },
        {
            "id": "process-input",
            "title": "Decision needed",
            "status": "blocked",
            "assignee": "worker",
            "block_kind": "needs_input",
            "blocked_reason": "Consigliere decision pending",
            "open_parents": 0,
        },
        {
            "id": "untyped",
            "title": "Recover worker",
            "status": "blocked",
            "assignee": "worker",
            "block_kind": "",
            "blocked_reason": "worker gave up",
            "open_parents": 0,
        },
        {
            "id": "triage-process",
            "title": "Triage process",
            "status": "triage",
            "assignee": "worker",
            "block_kind": "capability",
            "blocked_reason": "local harness unavailable",
            "open_parents": 0,
        },
        {
            "id": "triage-don",
            "title": "Live trade approval",
            "status": "triage",
            "assignee": "worker",
            "block_kind": "needs_input",
            "blocked_reason": "Needs approval",
            "open_parents": 0,
        },
        {
            "id": "parked",
            "title": "PARK: device verification",
            "status": "blocked",
            "assignee": "worker",
            "block_kind": "needs_input",
            "blocked_reason": "DON-ONLY: iPhone verification",
            "open_parents": 0,
        },
        {
            "id": "done",
            "title": "Done task",
            "status": "done",
            "assignee": "worker",
            "block_kind": "needs_input",
            "blocked_reason": "DON-ONLY: irrelevant terminal state",
            "open_parents": 0,
        },
    ]

    payload = project_attention_rows(rows)

    assert [row["id"] for row in payload["blocked"]] == ["don-only", "credential", "triage-don"]
    assert [row["id"] for row in payload["waiting"]] == [
        "open-parent",
        "transient",
        "review",
        "process-input",
        "untyped",
    ]
    assert payload["counts"] == {"blocked": 3, "waiting": 5}
    assert all(set(row) == {"id", "title", "status", "assignee"} for column in ("blocked", "waiting") for row in payload[column])


def test_attention_cli_is_read_only_and_returns_metadata_only_rows(
    kanban_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with kb.connect_closing() as conn:
        task_id = kb.create_task(
            conn,
            title="Credential permission change",
            body="private task body must not leave the database",
            assignee="owner",
        )
        assert kb.claim_task(conn, task_id, claimer="owner") is not None
        assert kb.block_task(
            conn,
            task_id,
            kind="capability",
            reason="Need password for permission change",
        )

    db_path = kb.kanban_db_path(board="default")
    before = db_path.read_bytes()

    def fail_initializer() -> None:
        raise AssertionError("attention must not initialize or mutate the board")

    monkeypatch.setattr(kb, "init_db", fail_initializer)
    output = kc.run_slash("--board default attention --json")
    payload = json.loads(output)

    assert payload == attention_summary(board="default")
    assert payload["counts"] == {"blocked": 1, "waiting": 0}
    assert payload["blocked"] == [
        {
            "id": task_id,
            "title": "Credential permission change",
            "status": "blocked",
            "assignee": "owner",
        }
    ]
    assert "private task body must not leave the database" not in output
    assert db_path.read_bytes() == before


def test_attention_summary_uses_hq_bounded_active_inventory_before_projection(
    kanban_home: Path,
) -> None:
    """Only the first HQ source-inventory page can contribute attention rows."""
    with kb.connect_closing() as conn:
        for index in range(299):
            kb.create_task(conn, title=f"active-{index}", assignee="worker", priority=10)

        included = kb.create_task(conn, title="included attention", assignee="worker", priority=5)
        assert kb.claim_task(conn, included, claimer="worker") is not None
        assert kb.block_task(
            conn,
            included,
            kind="needs_input",
            reason="DON-ONLY: approve public send",
        )

        excluded = kb.create_task(conn, title="excluded attention", assignee="worker", priority=0)
        assert kb.claim_task(conn, excluded, claimer="worker") is not None
        assert kb.block_task(
            conn,
            excluded,
            kind="needs_input",
            reason="DON-ONLY: approve public send",
        )

        done = kb.create_task(conn, title="high priority done", assignee="worker", priority=100)
        conn.execute("UPDATE tasks SET status = 'done' WHERE id = ?", (done,))

    payload = attention_summary(board="default")

    assert payload["counts"] == {"blocked": 1, "waiting": 0}
    assert [row["id"] for row in payload["blocked"]] == [included]
    assert excluded not in {row["id"] for row in payload["blocked"]}
    assert all(set(row) == {"id", "title", "status", "assignee"} for row in payload["blocked"])


def test_desktop_private_reads_do_not_recompute_or_mutate_board(
    kanban_home: Path,
) -> None:
    """Every Desktop-only read stays read-only even with a promotable child."""
    with kb.connect_closing() as conn:
        parent = kb.create_task(conn, title="completed parent", assignee="owner")
        conn.execute("UPDATE tasks SET status = 'done' WHERE id = ?", (parent,))
        child = kb.create_task(conn, title="promotable child", assignee="owner")
        kb.link_tasks(conn, parent, child)
        conn.execute("UPDATE tasks SET status = 'todo' WHERE id = ?", (child,))

    db_path = kb.kanban_db_path(board="default")
    before = db_path.read_bytes()
    with kb.connect_closing() as conn:
        before_statuses = conn.execute(
            "SELECT id, status FROM tasks ORDER BY id"
        ).fetchall()
        before_events = conn.execute(
            "SELECT task_id, kind, payload FROM task_events ORDER BY id"
        ).fetchall()

    completed = kc.run_slash("--board default desktop-read completed --json")
    diagnostics = kc.run_slash(
        "--board default desktop-read diagnostics --severity error --json"
    )
    attention = kc.run_slash("--board default attention --json")

    assert json.loads(completed)[0]["id"] == parent
    assert json.loads(diagnostics) == []
    assert child not in {
        row["id"]
        for column in ("blocked", "waiting")
        for row in json.loads(attention)[column]
    }
    assert db_path.read_bytes() == before
    with kb.connect_closing() as conn:
        assert conn.execute("SELECT id, status FROM tasks ORDER BY id").fetchall() == before_statuses
        assert conn.execute(
            "SELECT task_id, kind, payload FROM task_events ORDER BY id"
        ).fetchall() == before_events


def test_desktop_private_reads_fail_without_creating_missing_board(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / ".hermes-missing"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    for command in (
        "desktop-read completed --json",
        "desktop-read diagnostics --severity error --json",
        "attention --json",
    ):
        output = kc.run_slash(f"--board default {command}")
        assert "unavailable" in output
    assert not (home / "kanban.db").exists()
