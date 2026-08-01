"""Private read-only data surfaces for the Desktop Ops Attention plugin.

This module is intentionally separate from the general Kanban ``list`` and
``diagnostics`` commands.  Those commands retain their operator-facing
semantics, including list's dependency recomputation.  Desktop polling must
never initialize, promote, or otherwise write a board.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_diagnostics as kd
from hermes_cli.config import load_config

MAX_ROWS = 8

_SAFE_DIAGNOSTIC_TITLES = {
    "hallucinated_cards": "Worker claimed unknown cards",
    "triage_aux_unavailable": "Triage auxiliary model unavailable",
    "prose_phantom_refs": "Completion summary references unknown cards",
    "repeated_failures": "Repeated worker failures",
    "repeated_crashes": "Repeated worker crashes",
    "stuck_in_blocked": "Task has been blocked for too long",
    "block_unblock_cycling": "Task is cycling between blocked and unblocked",
    "stranded_in_ready": "Task is ready without a worker",
}

_COMPLETED_QUERY = """
    SELECT id, title, status, COALESCE(assignee, '') AS assignee
    FROM tasks
    WHERE status = 'done'
    ORDER BY started_at DESC NULLS LAST, created_at DESC
    LIMIT 8
"""


def _read_only_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise RuntimeError(
            f"Desktop read unavailable: board database does not exist at {path}"
        )
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        if conn.execute("PRAGMA query_only").fetchone()[0] != 1:
            conn.close()
            raise RuntimeError("Desktop read unavailable: SQLite query_only was not enabled")
        return conn
    except sqlite3.Error as exc:
        raise RuntimeError(f"Desktop read unavailable: {exc}") from exc


def completed_rows(*, board: str | None = None) -> list[dict[str, str]]:
    """Return only the eight most recent completed-task display fields."""
    path = kb.kanban_db_path(board=board)
    conn = _read_only_connection(path)
    try:
        return [dict(row) for row in conn.execute(_COMPLETED_QUERY)]
    except sqlite3.Error as exc:
        raise RuntimeError(f"Desktop completed read unavailable: {exc}") from exc
    finally:
        conn.close()


def diagnostic_rows(
    *,
    board: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Return bounded severity/title diagnostics with no private task data."""
    if severity is not None and severity not in kd.SEVERITY_ORDER:
        raise ValueError(f"unknown diagnostic severity: {severity}")

    path = kb.kanban_db_path(board=board)
    conn = _read_only_connection(path)
    try:
        config = kd.config_from_runtime_config(load_config())
        task_rows = conn.execute(
            "SELECT * FROM tasks WHERE status != 'archived'"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in task_rows:
            task_id = row["id"]
            diagnostics = kd.compute_task_diagnostics(
                kb.Task.from_row(row),
                kb.list_events(conn, task_id),
                kb.list_runs(conn, task_id),
                config=config,
            )
            diagnostics = [
                diagnostic
                for diagnostic in diagnostics
                if kd.severity_at_or_above(diagnostic.severity, severity)
            ]
            if diagnostics:
                result.append(
                    {
                        "task_id": task_id,
                        "diagnostics": [
                            {
                                "severity": diagnostic.severity,
                                "title": _SAFE_DIAGNOSTIC_TITLES.get(
                                    diagnostic.kind, "Kanban diagnostic"
                                ),
                            }
                            for diagnostic in diagnostics
                        ],
                    }
                )
            if len(result) >= MAX_ROWS:
                break
        return result
    except sqlite3.Error as exc:
        raise RuntimeError(f"Desktop diagnostics read unavailable: {exc}") from exc
    finally:
        conn.close()
