"""Pure tests for the Kanban durable-progress classifier and policy."""

from __future__ import annotations

from hermes_cli.kanban_progress import analyze_worker_log, decide_progress_action


def _decide(signals, *, intervals=0, warning_sent=False, age=0, exempt=None):
    return decide_progress_action(
        enabled=True,
        runtime_seconds=3600,
        seconds_since_progress=age,
        nonprogress_intervals=intervals,
        warning_sent=warning_sent,
        signals=signals,
        exempt_reason=exempt,
    )


def test_progress_guard_disabled_is_compatible_noop():
    signals = analyze_worker_log("  ┊ ⚡ kanban_he 0.0s")
    assert decide_progress_action(
        enabled=False,
        runtime_seconds=9999,
        seconds_since_progress=9999,
        nonprogress_intervals=99,
        warning_sent=True,
        signals=signals,
    ) == "disabled"


def test_progress_guard_heartbeat_only_is_not_durable_progress():
    signals = analyze_worker_log("\n".join(["  ┊ ⚡ kanban_he 0.0s"] * 4))
    assert signals["durable_progress_count"] == 0
    assert signals["durable_progress_category"] is None


def test_progress_guard_baseline_warning_then_reseat_ceiling():
    signals = analyze_worker_log("  ┊ 🔎 grep progress 0.2s\n  ┊ 🔎 grep progress 0.2s")
    assert _decide(signals, intervals=1, age=600) == "continue"
    assert _decide(signals, intervals=2, age=1200) == "warn"
    assert _decide(signals, intervals=2, warning_sent=True, age=1200) == "continue"
    assert _decide(signals, intervals=3, warning_sent=True, age=1800) == "reseat"


def test_progress_guard_write_and_patch_are_durable_progress():
    signals = analyze_worker_log(
        "  ┊ ✍️  write /tmp/result.md 0.1s\n"
        "  ┊ 🩹 patch /tmp/result.md 0.1s"
    )
    assert signals["durable_progress_count"] == 2
    assert signals["durable_progress_category"] == "artifact_write"
    assert signals["durable_progress_signature"]
    assert _decide(signals, intervals=0, age=0) == "continue"


def test_progress_guard_deduplicates_unchanged_writes_but_counts_changed_targets():
    unchanged = analyze_worker_log(
        "  ┊ ✍️ write /tmp/result.md 0.1s\n"
        "  ┊ ✍️ write /tmp/result.md 0.2s"
    )
    changed = analyze_worker_log(
        "  ┊ ✍️ write /tmp/result.md 0.1s\n"
        "  ┊ ✍️ write /tmp/other.md 0.2s"
    )
    assert unchanged["durable_progress_count"] == 1
    assert unchanged["repeated_nonprogress_signature_count"] == 1
    assert changed["durable_progress_count"] == 2


def test_progress_guard_ignores_prose_and_source_diff_tool_mentions():
    signals = analyze_worker_log(
        "The brief says write the artifact, then patch the file.\n"
        "+ command = '$ pytest -q tests/unit/test_x.py'\n"
        "12 passed in 1.01s"
    )
    assert signals["durable_progress_count"] == 0
    assert signals["long_operation_active"] is False


def test_progress_guard_completed_structured_test_and_build_records_are_progress():
    signals = analyze_worker_log(
        "  ┊ 💻 $         python -m pytest -q tests/unit/test_x.py  1.2s\n"
        "  ┊ 💻 $         python -m build  5.4s"
    )
    assert signals["durable_progress_count"] == 2
    assert signals["durable_progress_category"] == "test_build_success"
    assert signals["long_operation_active"] is False


def test_progress_guard_unrelated_terminal_does_not_bind_later_result_prose():
    signals = analyze_worker_log(
        "  ┊ 💻 $         git status --short  0.1s\n"
        "The report later says 12 passed in 1.01s.\n"
        "It also quotes FAILED test_x.py::test_a - AssertionError."
    )
    assert signals["durable_progress_count"] == 0
    assert signals["long_operation_active"] is False


def test_progress_guard_changed_failure_fingerprint_progresses_once_per_change():
    repeated = analyze_worker_log(
        "  ┊ 💻 $         pytest -q test_x.py::test_a  1.2s [exit 1]\n"
        "  ┊ 💻 $         pytest -q test_x.py::test_a  1.3s [exit 1]"
    )
    changed = analyze_worker_log(
        "  ┊ 💻 $         pytest -q test_x.py::test_a  1.2s [exit 1]\n"
        "  ┊ 💻 $         pytest -q test_x.py::test_b  1.3s [exit 1]"
    )
    assert repeated["durable_progress_count"] == 1
    assert repeated["durable_progress_category"] == "changed_failure"
    assert repeated["long_operation_active"] is False
    assert changed["durable_progress_count"] == 2
    assert changed["durable_progress_signature"] != repeated["durable_progress_signature"]


def test_progress_guard_structured_terminal_failure_markers_are_progress():
    for marker in ("[exit 1]", "[command timed out]"):
        signals = analyze_worker_log(
            f"  ┊ 💻 $         python verify_progress_guard.py  5.5s {marker}"
        )
        assert signals["durable_progress_count"] == 1
        assert signals["durable_progress_category"] == "changed_failure"
        assert signals["long_operation_active"] is False


def test_progress_guard_repeated_read_search_only_corroborates():
    signals = analyze_worker_log(
        "  ┊ 🔎 grep heartbeat|artifact 0.2s\n"
        "  ┊ 🔎 grep heartbeat|artifact 0.3s\n"
        "  ┊ 📖 read_file kanban_db.py 0.1s"
    )
    assert signals["durable_progress_count"] == 0
    assert signals["repeated_nonprogress_signature_count"] >= 1
    assert _decide(signals, intervals=1, age=600) == "continue"


def test_progress_guard_compaction_and_gui_only_corroborate():
    signals = analyze_worker_log(
        "📦 Pre-API compression: ~234,779 tokens near the context/output limit.\n"
        "  ┊ 🖥 browser_click @e12 0.3s"
    )
    assert signals["context_compaction_count"] == 1
    assert signals["gui_control_count"] == 1
    assert signals["durable_progress_count"] == 0
    assert _decide(signals, intervals=1, age=600) == "continue"


def test_progress_guard_post_evidence_verification_churn_is_bounded():
    signals = analyze_worker_log(
        "  ┊ ✍️ write /tmp/report.md 0.1s\n"
        "  ┊ 📖 read_file report.md 0.1s\n"
        "  ┊ 🔎 grep PASS report.md 0.1s\n"
        "  ┊ 🔎 grep PASS report.md 0.1s"
    )
    assert signals["evidence_produced"] is True
    assert signals["post_evidence_nonprogress_count"] == 3
    assert _decide(signals, intervals=2, age=1200) == "warn"


def test_progress_guard_completed_long_operation_never_exempts_with_fresh_liveness():
    signals = analyze_worker_log(
        "  ┊ 💻 $         pytest -q tests/scoped/test_slow.py  45.2s"
    )
    signals["fresh_liveness"] = True
    assert signals["long_operation_active"] is False
    assert _decide(signals, intervals=3, warning_sent=True, age=1800) == "reseat"


def test_progress_guard_generic_terminal_and_heartbeat_do_not_exempt():
    signals = analyze_worker_log("  ┊ 💻 $ python worker.py\n  ┊ ⚡ kanban_he 0.0s")
    signals["fresh_liveness"] = True
    assert signals["long_operation_active"] is False
    assert _decide(signals, intervals=3, warning_sent=True, age=1800) == "reseat"


def test_progress_guard_typed_exemptions_win():
    signals = analyze_worker_log("")
    for reason in (
        "dependency_wait",
        "don_only",
        "acceptance_gate",
        "market_trading",
        "status_not_running",
        "profile_not_eligible",
        "stale_run",
        "legitimate_long_run",
    ):
        assert _decide(
            signals,
            intervals=3,
            warning_sent=True,
            age=1800,
            exempt=reason,
        ) == "exempt"


def test_progress_guard_analysis_exposes_only_minimal_signals():
    secret = "api_key=do-not-store-this"
    signals = analyze_worker_log(
        f"  ┊ 🔎 grep {secret} 0.2s\n  ┊ 🔎 grep {secret} 0.2s"
    )
    serialized = repr(signals)
    assert secret not in serialized
    assert "raw_log" not in signals
    assert "tool_payload" not in signals
    assert {
        "durable_progress_count",
        "durable_progress_category",
        "durable_progress_signature",
        "repeated_nonprogress_signature_count",
        "context_compaction_count",
        "gui_control_count",
        "evidence_produced",
        "post_evidence_nonprogress_count",
        "long_operation_active",
    } <= signals.keys()
