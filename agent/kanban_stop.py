"""Turn-end guard for kanban workers.

Kanban workers must end with ``kanban_complete`` or ``kanban_block``. Models
(especially GLM / Qwen families) sometimes narrate the next step
("Let me write the report now") and stop with ``finish_reason=stop`` and no
tool calls. Hermes treats that as a clean exit → ``rc=0`` → dispatcher
``protocol_violation``.

This module is policy-only: when a kanban worker tries to finish without a
terminal board tool, return a bounded synthetic nudge so the conversation
loop continues instead of exiting.
"""

from __future__ import annotations

import os
from typing import Any, Iterable, Optional


_TERMINAL_KANBAN_TOOLS = frozenset({"kanban_complete", "kanban_block"})

_DEFAULT_MAX_ATTEMPTS = 2

# Transports that expose Hermes tools over MCP (claude_cli, codex) report the
# fully-qualified tool name. Strip the server prefix before matching.
_MCP_TOOL_PREFIXES = ("mcp__hermes-tools__", "mcp__hermes__")


def _bare_tool_name(name: str) -> str:
    for prefix in _MCP_TOOL_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def kanban_stop_nudge_enabled() -> bool:
    """Return whether the kanban stop-guard is active for this process.

    On when ``HERMES_KANBAN_TASK`` is set (dispatcher-spawned worker), unless
    ``HERMES_KANBAN_STOP_NUDGE`` explicitly disables it.
    """
    env = os.environ.get("HERMES_KANBAN_STOP_NUDGE")
    if env is not None and env.strip().lower() in {"0", "false", "no", "off"}:
        return False
    task = (os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    return bool(task)


def _tool_call_name(tc: Any) -> str:
    if isinstance(tc, dict):
        fn = tc.get("function")
        if isinstance(fn, dict):
            return str(fn.get("name") or "")
        return str(tc.get("name") or "")
    fn = getattr(tc, "function", None)
    if fn is not None:
        return str(getattr(fn, "name", "") or "")
    return str(getattr(tc, "name", "") or "")


def session_called_kanban_terminal(messages: Iterable[dict] | None) -> bool:
    """True if this conversation already invoked a terminal kanban tool."""
    if not messages:
        return False
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role == "assistant":
            for tc in msg.get("tool_calls") or []:
                if _bare_tool_name(_tool_call_name(tc)) in _TERMINAL_KANBAN_TOOLS:
                    return True
        elif role == "tool":
            name = _bare_tool_name(str(msg.get("name") or ""))
            if name in _TERMINAL_KANBAN_TOOLS:
                return True
    return False


def tool_records_called_kanban_terminal(
    tool_calls: Iterable[dict] | None,
) -> bool:
    """True if a transport's tool-call ledger shows a terminal kanban tool.

    Used by transports that run their own agentic loop (``claude_cli``) and
    therefore never build Hermes-shaped ``messages`` with ``tool_calls``.
    Their per-turn ledger carries both the bare ``name`` and the raw MCP
    ``raw_name``; either may match.

    A call that came back as an error does NOT count — the board was not
    actually moved, so the worker still needs to be nudged.
    """
    for rec in tool_calls or []:
        if not isinstance(rec, dict):
            continue
        if rec.get("is_error"):
            continue
        for key in ("name", "raw_name"):
            name = _bare_tool_name(str(rec.get(key) or ""))
            if name in _TERMINAL_KANBAN_TOOLS:
                return True
    return False


def _nudge_text(task_id: Optional[str]) -> str:
    tid = (task_id or os.environ.get("HERMES_KANBAN_TASK") or "").strip() or "this task"
    return (
        "[System: You are a Hermes kanban worker. A plain-text reply is NOT a "
        "terminal state for the board.\n\n"
        f"Task `{tid}` is still `running`. Ending now without a board tool "
        "causes a protocol violation (clean exit with no "
        "`kanban_complete` / `kanban_block`).\n\n"
        "Do this immediately in your next response — do not narrate intent:\n"
        "1. Finish any remaining deliverable (write the required file(s) now).\n"
        "2. Call `kanban_complete(summary=..., artifacts=[...])` if the work "
        "is done, OR `kanban_block(reason=...)` if you are blocked.\n\n"
        "Never end a turn with only a promise of future action. Repeated "
        "protocol violations will block this task and require manual intervention.]"
    )


def build_kanban_stop_nudge(
    *,
    messages: Iterable[dict] | None = None,
    attempts: int = 0,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    task_id: Optional[str] = None,
) -> Optional[str]:
    """Return a synthetic follow-up when a kanban worker exits without a terminal tool.

    Returns ``None`` when the guard should not fire (not a kanban worker,
    already completed/blocked, or nudge budget exhausted).
    """
    if not kanban_stop_nudge_enabled():
        return None
    if attempts >= max_attempts:
        return None
    if session_called_kanban_terminal(messages):
        return None
    return _nudge_text(task_id)


def build_kanban_stop_nudge_for_tool_records(
    *,
    tool_calls: Iterable[dict] | None = None,
    attempts: int = 0,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    task_id: Optional[str] = None,
) -> Optional[str]:
    """``build_kanban_stop_nudge`` for transports with their own tool ledger.

    ``claude_cli`` drives Claude Code's internal agentic loop, so Hermes never
    sees per-step ``messages`` — only a final assistant text plus a tool-call
    ledger. Same policy, different evidence source.
    """
    if not kanban_stop_nudge_enabled():
        return None
    if attempts >= max_attempts:
        return None
    if tool_records_called_kanban_terminal(tool_calls):
        return None
    return _nudge_text(task_id)


__all__ = [
    "build_kanban_stop_nudge",
    "build_kanban_stop_nudge_for_tool_records",
    "kanban_stop_nudge_enabled",
    "session_called_kanban_terminal",
    "tool_records_called_kanban_terminal",
]
