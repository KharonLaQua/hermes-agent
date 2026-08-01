"""Pure worker-log signals and policy for the Kanban progress guard.

The parser intentionally returns only counts, typed categories, booleans, and
one-way hashes. Raw log lines and tool payloads never leave this module.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any

_ALLOWED_DECISIONS = {"disabled", "exempt", "continue", "warn", "reseat"}
_DURATION_RE = re.compile(r"\b\d+(?:\.\d+)?s\b", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")
_FAILURE_RE = re.compile(
    r"(?:^|\s)(?:failed|failure|error|exception|traceback|assertionerror|typeerror|"
    r"valueerror|runtimeerror)(?:\s|:|-|$)",
    re.IGNORECASE,
)
_TEST_BUILD_SUCCESS_RE = re.compile(
    r"(?:\b\d+\s+passed\b|\btests?\s+passed\b|\bbuild\s+succeeded\b|"
    r"\bsuccessfully\s+built\b|\bcompleted\s+successfully\b|"
    r"\bexit(?:ed)?\s+(?:code\s+)?0\b)",
    re.IGNORECASE,
)
_TOOL_RECORD_PREFIX = r"^\s*┊\s*"
_WRITE_TOOL_RE = re.compile(
    _TOOL_RECORD_PREFIX
    + r"(?:✍️?\s*|🩹\s*)?(?:write_file|write|patch|kanban_attach)\b",
    re.IGNORECASE,
)
_NONPROGRESS_TOOL_RE = re.compile(
    _TOOL_RECORD_PREFIX
    + r"(?:🔎\s*|📖\s*|⚡\s*)?(?:grep|rg|search_files|read_file|find|"
    r"browser_snapshot|browser_vision|kanban_he(?:artbeat)?)\b",
    re.IGNORECASE,
)
_TERMINAL_TOOL_RE = re.compile(
    _TOOL_RECORD_PREFIX + r"(?:💻\s*)?(?:\$|terminal\b)",
    re.IGNORECASE,
)
_COMPACTION_RE = re.compile(
    r"(?:pre-api compression|context compaction|compress(?:ing|ed)? context)",
    re.IGNORECASE,
)
_GUI_RE = re.compile(
    _TOOL_RECORD_PREFIX
    + r"(?:🖥\s*)?(?:browser_(?:click|type|press|scroll|navigate)|"
    r"computer[-_ ]control|macos[-_ ]computer[-_ ]use|gui(?:\s+control)?)",
    re.IGNORECASE,
)
_LONG_OPERATION_RE = re.compile(
    r"(?:\bpytest\b|\btest(?:s|ing)?\b|\bbuild\b|\bencode\b|\bencoding\b|"
    r"\bcrawl\b|\bcrawling\b)",
    re.IGNORECASE,
)
_HEARTBEAT_RE = re.compile(
    _TOOL_RECORD_PREFIX + r"(?:⚡\s*)?kanban_he(?:artbeat)?\b",
    re.IGNORECASE,
)


def _normalized(line: str) -> str:
    """Return a stable comparison string used only as hash input."""
    value = line.strip().lower()
    value = _DURATION_RE.sub("<duration>", value)
    value = re.sub(r"\bpid\s+\d+\b", "pid <n>", value)
    value = re.sub(r"0x[0-9a-f]+", "<hex>", value)
    return _WHITESPACE_RE.sub(" ", value)


def _signature(category: str, line: str) -> str:
    digest = hashlib.sha256(f"{category}:{_normalized(line)}".encode("utf-8")).hexdigest()
    return digest[:20]


def analyze_worker_log(text: str) -> dict[str, Any]:
    """Classify a transport-neutral per-task worker log.

    Durable progress is a successful write/patch, a completed scoped test or
    build, or a newly observed normalized failure fingerprint. Heartbeats,
    reads/searches, compaction, and GUI control remain non-progress signals.
    """
    durable: list[tuple[int, str, str]] = []
    durable_signatures: set[str] = set()
    nonprogress_signatures: Counter[str] = Counter()
    repeated_durable = 0
    compactions = 0
    gui_controls = 0
    long_operation_started_at: int | None = None
    structured_terminal_seen = False
    nonprogress_indexes: list[int] = []

    for index, raw_line in enumerate((text or "").splitlines()):
        line = raw_line.strip()
        if not line:
            continue

        is_compaction = bool(_COMPACTION_RE.search(line))
        is_gui = bool(_GUI_RE.search(line))
        is_heartbeat = bool(_HEARTBEAT_RE.search(line))
        is_nonprogress_tool = bool(_NONPROGRESS_TOOL_RE.search(line))
        is_terminal_tool = bool(_TERMINAL_TOOL_RE.search(raw_line))
        is_success = structured_terminal_seen and bool(_TEST_BUILD_SUCCESS_RE.search(line))
        is_failure = structured_terminal_seen and bool(_FAILURE_RE.search(line))
        is_write = bool(_WRITE_TOOL_RE.search(raw_line)) and not is_failure

        if is_compaction:
            compactions += 1
        if is_gui:
            gui_controls += 1

        durable_item: tuple[str, str] | None = None
        if is_write:
            durable_item = ("artifact_write", _signature("artifact_write", line))
        elif is_success:
            durable_item = (
                "test_build_success",
                _signature("test_build_success", line),
            )
            long_operation_started_at = None
        elif is_failure:
            fingerprint = _signature("failure_fingerprint", line)
            durable_item = ("changed_failure", fingerprint)
            long_operation_started_at = None

        if durable_item is not None:
            category, fingerprint = durable_item
            if fingerprint not in durable_signatures:
                durable_signatures.add(fingerprint)
                durable.append((index, category, fingerprint))
            else:
                # An unchanged repeated write/result corroborates a loop; it
                # must not manufacture a newer durable-progress observation.
                repeated_durable += 1
                nonprogress_indexes.append(index)

        # A command/tool record that names a recognized bounded long operation
        # is explicit enough; a generic terminal or heartbeat is not.
        if (
            is_terminal_tool
            and _LONG_OPERATION_RE.search(line)
            and not is_success
            and not is_failure
        ):
            long_operation_started_at = index

        if is_terminal_tool:
            structured_terminal_seen = True

        if is_nonprogress_tool or is_compaction or is_gui:
            normalized = _normalized(line)
            # Tool arguments may contain private text. Persist only a hash.
            nonprogress_signatures[_signature("nonprogress", normalized)] += 1
            nonprogress_indexes.append(index)
        elif is_heartbeat:
            nonprogress_indexes.append(index)

    last_progress_index = durable[-1][0] if durable else -1
    post_evidence_nonprogress = sum(
        1 for index in nonprogress_indexes if index > last_progress_index
    ) if durable else 0
    repeated_nonprogress = sum(
        count - 1 for count in nonprogress_signatures.values() if count > 1
    ) + repeated_durable
    category = durable[-1][1] if durable else None
    signature = durable[-1][2] if durable else None

    return {
        "durable_progress_count": len(durable),
        "durable_progress_category": category,
        "durable_progress_signature": signature,
        "repeated_nonprogress_signature_count": repeated_nonprogress,
        "context_compaction_count": compactions,
        "gui_control_count": gui_controls,
        "evidence_produced": bool(durable),
        "post_evidence_nonprogress_count": post_evidence_nonprogress,
        "long_operation_active": long_operation_started_at is not None,
    }


def decide_progress_action(
    *,
    enabled: bool,
    runtime_seconds: int,
    seconds_since_progress: int,
    nonprogress_intervals: int,
    warning_sent: bool,
    signals: dict,
    exempt_reason: str | None = None,
) -> str:
    """Return one bounded progress-guard decision.

    The first interval is baseline-only, the second emits at most one warning,
    and a later interval may reseat only after that warning. Typed exemptions
    and a recognized long operation with fresh liveness always win.
    """
    if not enabled:
        decision = "disabled"
    elif exempt_reason:
        decision = "exempt"
    elif signals.get("long_operation_active") and signals.get("fresh_liveness"):
        decision = "exempt"
    elif runtime_seconds < 0 or seconds_since_progress < 0:
        decision = "continue"
    elif seconds_since_progress == 0 and signals.get("durable_progress_count", 0):
        decision = "continue"
    elif nonprogress_intervals >= 3 and warning_sent:
        decision = "reseat"
    elif nonprogress_intervals >= 2 and not warning_sent:
        decision = "warn"
    else:
        decision = "continue"

    # Keep the public return surface closed if this function is edited later.
    if decision not in _ALLOWED_DECISIONS:  # pragma: no cover - defensive
        raise ValueError(f"invalid progress decision: {decision}")
    return decision
