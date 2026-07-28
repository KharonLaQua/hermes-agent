"""Tests for the kanban worker turn-end stop guard."""

from __future__ import annotations

import pytest

from agent.kanban_stop import (
    build_kanban_stop_nudge,
    build_kanban_stop_nudge_for_tool_records,
    kanban_stop_nudge_enabled,
    session_called_kanban_terminal,
    tool_records_called_kanban_terminal,
)


@pytest.fixture
def clear_kanban_env(monkeypatch):
    for var in ("HERMES_KANBAN_TASK", "HERMES_KANBAN_STOP_NUDGE"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_disabled_without_kanban_task(clear_kanban_env):
    assert kanban_stop_nudge_enabled() is False
    assert build_kanban_stop_nudge(messages=[]) is None


def test_enabled_with_kanban_task(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    assert kanban_stop_nudge_enabled() is True


def test_env_can_disable(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    clear_kanban_env.setenv("HERMES_KANBAN_STOP_NUDGE", "0")
    assert kanban_stop_nudge_enabled() is False
    assert build_kanban_stop_nudge(messages=[]) is None


def test_nudge_when_no_terminal_tool(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_46be8aa5")
    messages = [
        {"role": "user", "content": "work kanban task"},
        {
            "role": "assistant",
            "content": "Let me write the comprehensive recipe.",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {"name": "kanban_heartbeat", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "name": "kanban_heartbeat", "tool_call_id": "1", "content": "ok"},
    ]
    nudge = build_kanban_stop_nudge(messages=messages, attempts=0)
    assert nudge is not None
    assert "kanban_complete" in nudge
    assert "kanban_block" in nudge
    assert "t_46be8aa5" in nudge
    assert "protocol violation" in nudge.lower() or "protocol" in nudge.lower()


def test_no_nudge_after_kanban_complete(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    messages = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {"name": "kanban_complete", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "name": "kanban_complete", "tool_call_id": "1", "content": "done"},
    ]
    assert session_called_kanban_terminal(messages) is True
    assert build_kanban_stop_nudge(messages=messages) is None


def test_no_nudge_after_kanban_block(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    messages = [
        {"role": "tool", "name": "kanban_block", "tool_call_id": "1", "content": "blocked"},
    ]
    assert build_kanban_stop_nudge(messages=messages) is None


def test_nudge_budget_exhausted(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    assert build_kanban_stop_nudge(messages=[], attempts=2) is None
    assert build_kanban_stop_nudge(messages=[], attempts=1, max_attempts=1) is None
    assert build_kanban_stop_nudge(messages=[], attempts=0, max_attempts=1) is not None


# ── Integration: agent nudge + dispatcher bounded retry ──────────────
# These tests verify the two layers compose correctly: the agent-side
# nudge fires first (up to 2 attempts), and if the worker still exits
# without a terminal call, the dispatcher's bounded retry (streak of 3)
# handles it.  See also tests/hermes_cli/test_kanban_core_functionality.py
# for the dispatcher-side streak tests.


def test_nudge_text_warns_about_blocking(clear_kanban_env):
    """The nudge should warn that repeated violations will block the task."""
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    nudge = build_kanban_stop_nudge(messages=[], attempts=0)
    assert nudge is not None
    assert "block" in nudge.lower(), (
        "nudge should warn that repeated violations will block the task"
    )


def test_nudge_and_dispatcher_budgets_are_independent(clear_kanban_env):
    """Agent-side nudge budget (2) and dispatcher-side streak (3) are
    separate budgets — the nudge counter does not affect the dispatcher's
    violation streak, and vice versa.

    This is a source-level invariant check: the nudge counter
    (``_kanban_stop_nudges``) lives on the AIAgent instance and resets
    per session, while the dispatcher streak lives in the task_runs DB
    table and persists across worker respawns.
    """
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    # Agent-side: 2 nudge attempts per session
    assert build_kanban_stop_nudge(messages=[], attempts=0) is not None
    assert build_kanban_stop_nudge(messages=[], attempts=1) is not None
    assert build_kanban_stop_nudge(messages=[], attempts=2) is None
    # Dispatcher-side streak is tracked in the DB, not in the nudge module —
    # the nudge module has no knowledge of the streak counter.
    assert not hasattr(build_kanban_stop_nudge, "_streak")


# ── Transport tool-ledger variant (claude_cli) ────────────────────────────
# claude_cli hands back a tool ledger instead of Hermes-shaped messages, and
# reports MCP-qualified tool names. Regression cover for the swarm run where
# a worker wrote its deliverable, answered in prose, and was recorded as a
# protocol violation because no guard could see the missing terminal call.


def test_tool_records_detects_mcp_qualified_name():
    ledger = [{"name": "kanban_complete", "raw_name": "mcp__hermes-tools__kanban_complete"}]
    assert tool_records_called_kanban_terminal(ledger) is True


def test_tool_records_detects_raw_name_only():
    ledger = [{"name": "", "raw_name": "mcp__hermes-tools__kanban_block"}]
    assert tool_records_called_kanban_terminal(ledger) is True


def test_tool_records_ignores_non_terminal_tools():
    ledger = [
        {"name": "write_file", "raw_name": "mcp__hermes-tools__write_file"},
        {"name": "read_file", "raw_name": "mcp__hermes-tools__read_file"},
    ]
    assert tool_records_called_kanban_terminal(ledger) is False


def test_tool_records_errored_terminal_call_does_not_count():
    """A kanban_complete that failed left the task running — still nudge."""
    ledger = [{"name": "kanban_complete", "is_error": True}]
    assert tool_records_called_kanban_terminal(ledger) is False


def test_tool_records_tolerates_junk_entries():
    assert tool_records_called_kanban_terminal([None, "x", 3]) is False
    assert tool_records_called_kanban_terminal(None) is False


def test_ledger_nudge_fires_without_terminal_call(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_d7a91b9d")
    ledger = [{"name": "write_file", "raw_name": "mcp__hermes-tools__write_file"}]
    nudge = build_kanban_stop_nudge_for_tool_records(tool_calls=ledger)
    assert nudge is not None
    assert "t_d7a91b9d" in nudge
    assert "kanban_complete" in nudge


def test_ledger_nudge_silent_after_terminal_call(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_d7a91b9d")
    ledger = [{"raw_name": "mcp__hermes-tools__kanban_complete"}]
    assert build_kanban_stop_nudge_for_tool_records(tool_calls=ledger) is None


def test_ledger_nudge_respects_attempt_budget(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_d7a91b9d")
    assert build_kanban_stop_nudge_for_tool_records(tool_calls=[], attempts=0) is not None
    assert build_kanban_stop_nudge_for_tool_records(tool_calls=[], attempts=2) is None


def test_ledger_nudge_disabled_outside_kanban(clear_kanban_env):
    assert build_kanban_stop_nudge_for_tool_records(tool_calls=[]) is None
