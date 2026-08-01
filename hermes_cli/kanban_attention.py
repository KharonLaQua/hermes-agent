"""Read-only, metadata-only Kanban attention projection.

This module deliberately opens the board through SQLite's ``mode=ro`` URI
rather than the mutable Kanban connection helper.  It exposes only the
metadata required to mirror the HQ Blocked/Waiting projection.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Sequence

from hermes_cli import kanban_db as kb


_ATTENTION_QUERY = """
    SELECT
        t.id,
        t.title,
        t.status,
        COALESCE(t.assignee, '') AS assignee,
        COALESCE(t.block_kind, '') AS block_kind,
        COALESCE((
            SELECT CASE
                WHEN json_valid(e.payload)
                THEN COALESCE(json_extract(e.payload, '$.reason'), '')
                ELSE ''
            END
            FROM task_events e
            WHERE e.task_id = t.id AND e.kind = 'blocked'
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT 1
        ), '') AS blocked_reason,
        (
            SELECT COUNT(*)
            FROM task_links l
            JOIN tasks p ON p.id = l.parent_id
            WHERE l.child_id = t.id
              AND p.status NOT IN ('done', 'archived', 'failed', 'cancelled')
        ) AS open_parents
    FROM tasks t
    WHERE t.status != 'archived'
    ORDER BY t.priority DESC, t.created_at DESC
"""

_DON_ONLY_PREFIX = re.compile(r"^\s*DON[-_ ]ONLY\b", re.IGNORECASE)
_REVIEW_REQUIRED_PREFIX = re.compile(r"^\s*review-required\s*:", re.IGNORECASE)
_PARK_TITLE_PREFIX = re.compile(r"^\s*PARK:\s*", re.IGNORECASE)
_PARKED_REASON_PREFIX = re.compile(r"^\s*PARKED\b", re.IGNORECASE)
_DEVICE_VERIFY_TITLE_PREFIX = re.compile(r"^\s*Device verify\b", re.IGNORECASE)
_PARKED_DEVICE = re.compile(r"\bparked[- ]device\b", re.IGNORECASE)
_KITT_PHONE_CHAIN = re.compile(r"\bKITT\b[\s\S]{0,100}\bphone chain\b", re.IGNORECASE)
_DON_ONLY_PATTERNS = (
    re.compile(
        r"\b(?:wire|transfer|deposit|withdraw|spend|purchase|buy|sell)\b"
        r"[\s\S]{0,40}\b(?:fund|money|capital|cash|account|USD|\$)",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:capital|position siz\w+|allocat\w+ capital|bankroll|budget approval)\b", re.IGNORECASE),
    re.compile(r"\b(?:arm|arming|armed|go[- ]live|live trade|live bet|place (?:the )?(?:bet|trade|order))\b", re.IGNORECASE),
    re.compile(r"\b(?:publish|post(?:ing)? publicly|public send|tweet|broadcast|press release|send to (?:client|customer|public))\b", re.IGNORECASE),
    re.compile(r"\b(?:irreversible|unrecoverable|cannot be undone|no rollback|destructive)\b", re.IGNORECASE),
    re.compile(r"\b(?:legal|contract|signature|sign(?:ing)? off legally|filing|medical|diagnosis|prescription)\b", re.IGNORECASE),
    re.compile(r"\b(?:credential|password|api[- ]key|token rotation|oauth|permission change|sharing setting|acl)\b", re.IGNORECASE),
    re.compile(r"\b(?:requires? don|don must|needs? don|waiting on don|don'?s (?:iphone|phone|device|laptop))\b", re.IGNORECASE),
)


def _text(value: Any) -> str:
    """Match JavaScript's ``String(value || '')`` used by the HQ projector."""
    return str(value or "")


def _open_parents(value: Any) -> float:
    """Match the HQ projector treating malformed counts as non-actionable."""
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0


def _is_don_facing_block(block_kind: Any, title: Any, blocked_reason: Any) -> bool:
    """Port of live HQ ``hermesIsDonFacingBlock``."""
    del block_kind  # Retained for an exact-compatible call contract with HQ.
    title_text = _text(title)
    reason = _text(blocked_reason)
    blob = f"{title_text}\n{reason}"
    if _DON_ONLY_PREFIX.search(reason):
        return True
    return any(pattern.search(blob) for pattern in _DON_ONLY_PATTERNS)


def _is_parked_shelf(block_kind: Any, title: Any, blocked_reason: Any) -> bool:
    """Port of live HQ ``hermesIsParkedShelf``."""
    kind = _text(block_kind).lower()
    title_text = _text(title)
    reason = _text(blocked_reason)
    blob = f"{title_text}\n{reason}"
    return bool(
        _PARK_TITLE_PREFIX.search(title_text)
        or (kind == "needs_input" and _PARKED_REASON_PREFIX.search(reason))
        or _PARKED_DEVICE.search(blob)
        or _DEVICE_VERIFY_TITLE_PREFIX.search(title_text)
        or _KITT_PHONE_CHAIN.search(blob)
    )


def _status_to_column(status: Any, block_kind: Any, title: Any, blocked_reason: Any, open_parents: Any) -> str:
    """Exact Python port of the live HQ ``hermesStatusToCol`` classifier."""
    state = _text(status).lower()
    kind = _text(block_kind).lower()
    reason = _text(blocked_reason)
    parents = _open_parents(open_parents)

    if state in {"done", "archived", "cancelled"}:
        return "done"
    if _is_parked_shelf(kind, title, reason):
        return "parked"
    if parents > 0 and state in {"blocked", "todo", "ready"}:
        return "waiting"
    if kind == "transient" and state in {"blocked", "todo"}:
        return "waiting"
    if state in {"blocked", "todo"} and _REVIEW_REQUIRED_PREFIX.search(reason):
        return "waiting"
    if kind in {"needs_input", "capability"} and state in {"blocked", "todo", "triage"}:
        return "blocked" if _is_don_facing_block(kind, title, reason) else ("ideas" if state == "triage" else "waiting")
    if state == "blocked":
        return "blocked" if _is_don_facing_block(kind, title, reason) else "waiting"
    if state == "triage":
        return "blocked" if _is_don_facing_block(kind, title, reason) else "ideas"
    return "active"


def _public_row(row: Mapping[str, Any]) -> dict[str, str]:
    """Return the only row shape permitted outside this module."""
    return {
        "id": _text(row.get("id")),
        "title": _text(row.get("title")),
        "status": _text(row.get("status")),
        "assignee": _text(row.get("assignee")),
    }


def project_attention_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project metadata rows to the exact Blocked/Waiting attention payload."""
    blocked: list[dict[str, str]] = []
    waiting: list[dict[str, str]] = []
    for row in rows:
        column = _status_to_column(
            row.get("status"),
            row.get("block_kind"),
            row.get("title"),
            row.get("blocked_reason"),
            row.get("open_parents"),
        )
        if column == "blocked":
            blocked.append(_public_row(row))
        elif column == "waiting":
            waiting.append(_public_row(row))
    return {
        "blocked": blocked,
        "waiting": waiting,
        "counts": {"blocked": len(blocked), "waiting": len(waiting)},
    }


def _read_only_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise RuntimeError(f"attention summary unavailable: board database does not exist at {path}")
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        return conn
    except sqlite3.Error as exc:
        raise RuntimeError(f"attention summary unavailable: {exc}") from exc


def attention_summary(*, board: str | None = None) -> dict[str, Any]:
    """Read and project the attention summary without initializing or mutating a board."""
    path = kb.kanban_db_path(board=board)
    conn = _read_only_connection(path)
    try:
        rows = [dict(row) for row in conn.execute(_ATTENTION_QUERY)]
    except sqlite3.Error as exc:
        raise RuntimeError(f"attention summary unavailable: {exc}") from exc
    finally:
        conn.close()
    return project_attention_rows(rows)
