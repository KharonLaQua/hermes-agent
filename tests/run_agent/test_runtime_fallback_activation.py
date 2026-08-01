"""Cross-runtime fallback activation regressions.

These tests use the real classifier and fallback activator with local fakes only.
They cover the feature-gated runtime seams that otherwise return a partial
Claude CLI turn or keep retrying an xAI OAuth quota response.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent.error_classifier import FailoverReason, classify_runtime_error
from run_agent import AIAgent


def _make_agent(fallback_model=None):
    with (
        patch("run_agent.get_tool_definitions", return_value=[]),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        agent = AIAgent(
            api_key="primary-key",
            base_url="https://primary.invalid/v1",
            provider="anthropic",
            model="claude-opus-test",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
            fallback_model=fallback_model,
        )
    agent.client = MagicMock()
    return agent


def _client(provider: str, model: str):
    client = MagicMock()
    client.api_key = f"{provider}-key"
    client.base_url = f"https://{provider}.invalid/v1"
    client.model = model
    return client


def _response(content: str):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content, tool_calls=None),
                finish_reason="stop",
            )
        ],
        model="fallback/model",
        usage=None,
    )


def _tool_response(name: str, arguments: dict, *, call_id: str = "call_test"):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=None,
                    tool_calls=[
                        SimpleNamespace(
                            id=call_id,
                            type="function",
                            function=SimpleNamespace(
                                name=name,
                                arguments=json.dumps(arguments),
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            )
        ],
        model="fallback/model",
        usage=None,
    )


class _XaiSpendingLimitError(Exception):
    status_code = 403

    def __init__(self):
        super().__init__("HTTP 403 personal-team-blocked:spending-limit")
        self.body = {"error": {"code": "personal-team-blocked:spending-limit"}}
        self.response = SimpleNamespace(headers={})


class _RateLimitedError(Exception):
    status_code = 429

    def __init__(self):
        super().__init__("HTTP 429 rate limit exceeded")
        self.response = SimpleNamespace(headers={})


class _RuntimeAgent:
    def __init__(self, *, enabled=True, provider="anthropic", model="claude-opus-test"):
        self.runtime_fallbacks_enabled = enabled
        self.provider = provider
        self.model = model
        self.base_url = f"https://{provider}.invalid/v1"
        self._fallback_chain = [{"provider": "openai-codex", "model": "gpt-test"}]
        self._fallback_index = 0
        self.statuses = []
        self.activations = []

    def _buffer_status(self, message):
        self.statuses.append(message)

    def _has_pending_fallback(self):
        return self._fallback_index < len(self._fallback_chain)

    def _try_activate_fallback(self, reason=None):
        self.activations.append(reason)
        self._fallback_index += 1
        return True


def test_claude_weekly_limit_activates_configured_fallback_once():
    from agent.conversation_loop import try_activate_runtime_fallback

    agent = _RuntimeAgent()
    result = try_activate_runtime_fallback(
        agent,
        RuntimeError("Claude weekly usage limit reached; resets next week"),
        runtime="claude_cli",
    )

    assert result is True
    assert agent.activations == [FailoverReason.rate_limit]
    assert "fallback" in agent.statuses[0].lower()


def test_partial_claude_cli_limit_turn_continues_through_fallback_transport():
    """The production runtime boundary must not return the partial CLI turn."""
    agent = _make_agent(
        [{"provider": "openai", "model": "fallback-model"}]
    )
    agent.api_mode = "claude_cli"
    agent.runtime_fallbacks_enabled = True
    agent._run_claude_cli_turn = MagicMock(return_value={
        "final_response": "Claude CLI turn failed: weekly limit",
        "messages": [],
        "api_calls": 0,
        "completed": False,
        "partial": True,
        "error": "weekly usage limit reached",
    })
    fallback_client = _client("openai", "fallback-model")
    fallback_client.chat.completions.create.return_value = _response("continued on fallback")

    with patch(
        "agent.auxiliary_client.resolve_provider_client",
        return_value=(fallback_client, "fallback-model"),
    ):
        result = agent.run_conversation("continue")

    assert result["final_response"] == "continued on fallback"
    agent._run_claude_cli_turn.assert_called_once()
    fallback_client.chat.completions.create.assert_called_once()


def test_claude_concurrency_saturation_activates_configured_fallback_once():
    from agent.conversation_loop import try_activate_runtime_fallback

    agent = _RuntimeAgent()
    result = try_activate_runtime_fallback(
        agent,
        RuntimeError("Claude CLI concurrency cap reached"),
        runtime="claude_cli",
    )

    assert result is True
    assert agent.activations == [FailoverReason.rate_limit]


def test_xai_403_spending_limit_activates_configured_fallback_once():
    from agent.conversation_loop import try_activate_runtime_fallback

    error = RuntimeError("HTTP 403 personal-team-blocked:spending-limit")
    error.status_code = 403
    error.body = {"error": {"code": "personal-team-blocked:spending-limit"}}
    agent = _RuntimeAgent(provider="xai-oauth", model="grok-test")

    result = try_activate_runtime_fallback(agent, error, runtime="xai_oauth")

    assert result is True
    assert agent.activations == [FailoverReason.billing]


def test_xai_spending_limit_turn_continues_through_fallback_transport():
    agent = _make_agent(
        [{"provider": "openai", "model": "fallback-model"}]
    )
    agent.provider = "xai-oauth"
    agent.model = "grok-test"
    agent.runtime_fallbacks_enabled = True
    agent.client.chat.completions.create.side_effect = _XaiSpendingLimitError()
    fallback_client = _client("openai", "fallback-model")
    fallback_client.chat.completions.create.return_value = _response("xai fallback continued")

    with patch(
        "agent.auxiliary_client.resolve_provider_client",
        return_value=(fallback_client, "fallback-model"),
    ):
        result = agent.run_conversation("continue")

    assert result["final_response"] == "xai fallback continued"
    assert agent.client is fallback_client
    fallback_client.chat.completions.create.assert_called_once()


def test_claude_partial_fallback_chain_advances_once_per_route():
    agent = _make_agent(
        [
            {"provider": "first", "model": "first-model"},
            {"provider": "second", "model": "second-model"},
        ]
    )
    agent.api_mode = "claude_cli"
    agent.runtime_fallbacks_enabled = True
    agent._run_claude_cli_turn = MagicMock(return_value={
        "final_response": "Claude CLI turn failed: weekly limit",
        "messages": [],
        "api_calls": 0,
        "completed": False,
        "partial": True,
        "error": "weekly usage limit reached",
    })
    first_client = _client("first", "first-model")
    first_client.chat.completions.create.side_effect = _RateLimitedError()
    second_client = _client("second", "second-model")
    second_client.chat.completions.create.return_value = _response(
        "continued on second fallback"
    )
    resolutions = []

    def resolve(provider, model=None, **_kwargs):
        resolutions.append((provider, model))
        if provider == "first":
            return first_client, model
        return second_client, model

    with patch("agent.auxiliary_client.resolve_provider_client", side_effect=resolve):
        result = agent.run_conversation("continue")

    assert result["final_response"] == "continued on second fallback"
    agent._run_claude_cli_turn.assert_called_once()
    assert resolutions == [("first", "first-model"), ("second", "second-model")]
    first_client.chat.completions.create.assert_called_once()
    second_client.chat.completions.create.assert_called_once()
    assert agent._fallback_index == 2
    assert agent.provider == "second"
    assert agent.model == "second-model"


def test_claude_partial_exhausts_fallback_chain_without_replaying_primary():
    agent = _make_agent(
        [
            {"provider": "first", "model": "first-model"},
            {"provider": "second", "model": "second-model"},
        ]
    )
    agent.api_mode = "claude_cli"
    agent.runtime_fallbacks_enabled = True
    agent._api_max_retries = 1
    agent._run_claude_cli_turn = MagicMock(return_value={
        "final_response": "Claude CLI turn failed: weekly limit",
        "messages": [],
        "api_calls": 0,
        "completed": False,
        "partial": True,
        "error": "weekly usage limit reached",
    })
    first_client = _client("first", "first-model")
    first_client.chat.completions.create.side_effect = _RateLimitedError()
    second_client = _client("second", "second-model")
    second_client.chat.completions.create.side_effect = _RateLimitedError()
    resolutions = []

    def resolve(provider, model=None, **_kwargs):
        resolutions.append((provider, model))
        if provider == "first":
            return first_client, model
        return second_client, model

    with patch("agent.auxiliary_client.resolve_provider_client", side_effect=resolve):
        result = agent.run_conversation("continue")

    assert result["completed"] is False
    assert result["failed"] is True
    assert result["error"]
    agent._run_claude_cli_turn.assert_called_once()
    assert resolutions == [("first", "first-model"), ("second", "second-model")]
    first_client.chat.completions.create.assert_called_once()
    second_client.chat.completions.create.assert_called_once()
    assert agent._fallback_index == 2
    assert agent.provider == "second"


def test_claude_partial_fallback_completes_kanban_run_without_protocol_violation(
    tmp_path, monkeypatch,
):
    """A recovered runtime turn may close its worker task through the normal tool loop."""
    from hermes_cli import kanban_db as kb
    from tools import kanban_tools  # noqa: F401 - imports the registered handler
    from tools.registry import registry

    db_path = tmp_path / "kanban.db"
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    kb.init_db(db_path)
    conn = kb.connect(db_path)
    try:
        task_id = kb.create_task(conn, title="fallback terminal handoff", assignee="worker")
        claimed = kb.claim_task(conn, task_id, claimer="test-worker")
        assert claimed is not None
        row = conn.execute(
            "SELECT current_run_id FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        run_id = int(row["current_run_id"])

        monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
        monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(run_id))

        agent = _make_agent([{"provider": "openai", "model": "fallback-model"}])
        agent.api_mode = "claude_cli"
        agent.runtime_fallbacks_enabled = True
        agent._run_claude_cli_turn = MagicMock(return_value={
            "final_response": "Claude CLI turn failed: weekly limit",
            "messages": [],
            "api_calls": 0,
            "completed": False,
            "partial": True,
            "error": "weekly usage limit reached",
        })
        entry = registry.get_entry("kanban_complete")
        assert entry is not None
        agent.tools = [{"type": "function", "function": entry.schema}]
        agent.valid_tool_names = {"kanban_complete"}

        fallback_client = _client("openai", "fallback-model")
        fallback_client.chat.completions.create.side_effect = [
            _tool_response("kanban_complete", {"summary": "fallback completed worker task"}),
            _response("terminal handoff finished"),
        ]
        with patch(
            "agent.auxiliary_client.resolve_provider_client",
            return_value=(fallback_client, "fallback-model"),
        ):
            result = agent.run_conversation("continue", task_id=task_id)

        assert result["final_response"] == "terminal handoff finished"
        agent._run_claude_cli_turn.assert_called_once()
        assert fallback_client.chat.completions.create.call_count == 2
        task = kb.get_task(conn, task_id)
        assert task.status == "done"
        run = kb.latest_run(conn, task_id)
        assert run is not None
        assert run.outcome == "completed"
        assert kb.detect_crashed_workers(conn) == []
        assert not any(
            event.kind == "protocol_violation"
            for event in kb.list_events(conn, task_id)
        )
    finally:
        conn.close()


def test_activated_fallback_re_resolves_reasoning_override():
    agent = _make_agent(
        [{"provider": "second", "model": "fallback-reasoning-model"}]
    )
    fallback_client = _client("second", "fallback-reasoning-model")

    config = {
        "agent": {
            "reasoning_effort": "medium",
            "reasoning_overrides": {"fallback-reasoning-model": "xhigh"},
        },
    }
    with (
        patch(
            "agent.auxiliary_client.resolve_provider_client",
            return_value=(fallback_client, "fallback-reasoning-model"),
        ),
        patch("hermes_cli.config.load_config", return_value=config),
    ):
        assert agent._try_activate_fallback(FailoverReason.rate_limit) is True

    assert agent.reasoning_config == {"enabled": True, "effort": "xhigh"}


def test_runtime_fallback_flag_is_off_by_default_and_does_not_activate():
    from hermes_cli.config import DEFAULT_CONFIG
    from agent.conversation_loop import try_activate_runtime_fallback

    assert DEFAULT_CONFIG["agent"]["runtime_fallbacks_enabled"] is False
    agent = _RuntimeAgent(enabled=False)
    assert try_activate_runtime_fallback(
        agent, RuntimeError("weekly usage limit reached"), runtime="claude_cli"
    ) is False
    assert agent.activations == []


def test_runtime_classifier_leaves_malformed_and_cancellation_errors_unchanged():
    malformed = classify_runtime_error(
        RuntimeError("malformed request payload"),
        runtime="claude_cli",
        provider="anthropic",
        model="claude-opus-test",
    )
    cancelled = classify_runtime_error(
        RuntimeError("request cancelled by user"),
        runtime="claude_cli",
        provider="anthropic",
        model="claude-opus-test",
    )

    assert malformed.should_fallback is False
    assert cancelled.should_fallback is False
