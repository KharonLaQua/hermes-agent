"""Phase 2c aux handling for claude_cli — compression skip + title skip.

Confirms:
  * Hermes HTTP context compression is skipped for api_mode=claude_cli
    (Claude owns native compaction via --resume)
  * Title generation skips the failing Anthropic HTTP aux path
  * Failures do not error the main turn (skip returns cleanly)

No live network / claude calls.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from agent import conversation_compression as cc
from agent import title_generator as tg


class _AgentStub:
    api_mode = "claude_cli"
    model = "claude-opus-4-8"
    provider = "anthropic"
    session_id = "sess-test"
    _cached_system_prompt = "sys-prompt"
    compression_enabled = False
    context_compressor = SimpleNamespace(
        should_compress=lambda *_a, **_k: True,
        threshold_tokens=1000,
        context_length=200_000,
        compression_count=0,
    )

    def _build_system_prompt(self, system_message=None):
        return system_message or self._cached_system_prompt


def test_compress_context_skips_for_claude_cli(caplog):
    agent = _AgentStub()
    messages = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
        {"role": "user", "content": "more context " * 50},
    ]
    with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
        out_msgs, out_prompt = cc.compress_context(
            agent, messages, system_message="sys"
        )
    assert out_msgs is messages  # unchanged identity
    assert out_prompt == "sys-prompt"
    assert any(
        "skipping Hermes HTTP context compression" in r.message for r in caplog.records
    )


def test_compress_context_skip_is_api_mode_gated(caplog):
    """claude_cli skip only fires when api_mode is claude_cli."""
    agent = _AgentStub()
    agent.api_mode = "claude_cli"
    with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
        cc.compress_context(agent, [{"role": "user", "content": "x"}], None)
    assert any("claude_cli" in r.message for r in caplog.records)

    # Different api_mode must not emit the claude_cli skip line.
    caplog.clear()
    agent.api_mode = "anthropic_messages"
    # Intercept before any aux work: replace compress_context body after the
    # claude_cli guard by short-circuiting on a custom compressor that
    # raises if entered — we only need the skip log absence.
    class _BoomCompressor:
        @staticmethod
        def _automatic_compression_blocked(_self):
            # Returning True makes compress_context return early without aux.
            return True

    agent.context_compressor = _BoomCompressor()
    with caplog.at_level(logging.INFO, logger="agent.conversation_compression"):
        out_msgs, _ = cc.compress_context(
            agent, [{"role": "user", "content": "x"}], None
        )
    assert len(out_msgs) == 1
    assert not any(
        "skipping Hermes HTTP context compression" in r.message for r in caplog.records
    )


def test_generate_title_skips_claude_cli_runtime(caplog, monkeypatch):
    # If skip fails, call_llm would be invoked — make it explode.
    def _boom(**_kw):
        raise AssertionError("call_llm must not run for claude_cli title")

    monkeypatch.setattr(tg, "call_llm", _boom)
    monkeypatch.setattr(tg, "_auto_title_enabled", lambda: True)

    with caplog.at_level(logging.INFO, logger="agent.title_generator"):
        title = tg.generate_title(
            "user hello",
            "assistant world",
            main_runtime={
                "model": "claude-opus-4-8",
                "provider": "anthropic",
                "api_mode": "claude_cli",
            },
        )
    assert title is None
    assert any("claude_cli runtime" in r.message for r in caplog.records)


def test_generate_title_still_calls_llm_for_other_modes(monkeypatch):
    class _Resp:
        class choices:
            pass

    class _Choice:
        class message:
            content = "My Title"

    _Resp.choices = [type("C", (), {"message": type("M", (), {"content": "My Title"})()})()]

    called = {}

    def _fake_call_llm(**kw):
        called["yes"] = True
        return _Resp()

    monkeypatch.setattr(tg, "call_llm", _fake_call_llm)
    monkeypatch.setattr(tg, "_auto_title_enabled", lambda: True)
    monkeypatch.setattr(
        "agent.agent_runtime_helpers.strip_think_blocks",
        lambda _self, content: content,
    )

    title = tg.generate_title(
        "user hello",
        "assistant world",
        main_runtime={
            "model": "grok-4.3",
            "provider": "xai-oauth",
            "api_mode": "chat_completions",
        },
    )
    assert called.get("yes") is True
    assert title == "My Title"


def test_claude_cli_runtime_turn_does_not_raise_on_aux_skip(tmp_path, monkeypatch):
    """Main turn completes even when title/compression would have failed.

    Integration-ish: run_claude_cli_turn with a fake session succeeds;
    generate_title skip is independent and non-fatal.
    """
    from agent import claude_runtime as cr
    from agent.transports.claude_cli import ClaudeCliSpawnConfig
    from agent.transports.claude_cli_session import ClaudeCliSession

    monkeypatch.setenv(
        "HERMES_CLAUDE_CLI_SLOT_DIR", str(tmp_path / "claude_cli_slots")
    )

    class _FakeClient:
        def __init__(self, **kw):
            pass

        def spawn(self, cfg: ClaudeCliSpawnConfig):
            return None

        def iter_stdout_lines(self, timeout=None):
            sid = "22222222-2222-2222-2222-222222222222"
            yield '{"type":"system","subtype":"init","session_id":"%s"}' % sid
            yield (
                '{"type":"result","subtype":"success","is_error":false,'
                '"result":"done","session_id":"%s",'
                '"usage":{"input_tokens":2,"output_tokens":1}}' % sid
            )

        def wait(self, timeout=None):
            return 0

        def stderr_tail(self, n=20):
            return []

        def close(self):
            pass

    real_init = ClaudeCliSession.__init__

    def _patched_init(self, *a, **k):
        k = dict(k)
        k["client_factory"] = lambda **kw: _FakeClient(**kw)
        k.setdefault("cwd", str(tmp_path))
        real_init(self, *a, **k)

    monkeypatch.setattr(ClaudeCliSession, "__init__", _patched_init)
    monkeypatch.setattr(
        "agent.transports.claude_cli_session.resolve_claude_cli_oauth_token",
        lambda **kw: "sk-ant-oat01-TEST",
    )

    agent = SimpleNamespace(
        api_mode="claude_cli",
        model="claude-opus-4-8",
        provider="anthropic",
        base_url="https://api.anthropic.com",
        api_key="sk-ant-oat01-TEST",
        session_id="s1",
        session_cwd=str(tmp_path),
        system_prompt="sys",
        show_commentary=True,
        tool_progress_callback=None,
        _session_db=None,
        _session_db_created=False,
        session_api_calls=0,
        session_prompt_tokens=0,
        session_completion_tokens=0,
        session_total_tokens=0,
        session_input_tokens=0,
        session_output_tokens=0,
        session_cache_read_tokens=0,
        session_reasoning_tokens=0,
        session_estimated_cost_usd=0.0,
        session_cost_status=None,
        session_cost_source=None,
        context_compressor=None,
        log_prefix="",
        quiet_mode=True,
    )

    def _sync(**k):
        pass

    def _spawn(**k):
        pass

    def _fire(*a, **k):
        pass

    agent._sync_external_memory_for_turn = _sync
    agent._spawn_background_review = _spawn
    agent._fire_stream_delta = _fire
    agent._emit_interim_assistant_message = _fire
    agent._flush_messages_to_session_db = _fire
    agent._ensure_db_session = _fire

    result = cr.run_claude_cli_turn(
        agent,
        user_message="hello",
        original_user_message="hello",
        messages=[{"role": "user", "content": "hello"}],
        effective_task_id="t1",
    )
    assert result["completed"] is True
    assert result["final_response"] == "done"
    assert result.get("error") is None

    # Title skip remains non-fatal.
    title = tg.generate_title(
        "hello",
        "done",
        main_runtime={"api_mode": "claude_cli", "provider": "anthropic"},
    )
    assert title is None
