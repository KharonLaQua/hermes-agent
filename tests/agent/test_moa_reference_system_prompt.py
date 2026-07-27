"""Tests for the MoA reference advisor system prompt."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from agent.moa_loop import _REFERENCE_SYSTEM_PROMPT, _reference_system_prompt


def test_reference_system_prompt_prohibits_claiming_execution():
    """
    Verify that the reference system prompt contains explicit warnings
    against claiming tool execution.

    The prompt should:
    1. State that reference models cannot execute anything
    2. Warn against claiming/implying execution
    3. Provide bad/good examples

    This addresses #61452 where reference models were fabricating
    tool execution in their text output.
    """
    prompt_lower = _REFERENCE_SYSTEM_PROMPT.lower()

    # Critical constraints
    assert "you cannot call tools" in prompt_lower or "you do not execute" in prompt_lower, \
        "Prompt must explicitly state that reference models cannot execute"

    assert "never claim" in prompt_lower or "never imply" in prompt_lower, \
        "Prompt must warn against claiming/implying execution"

    # Check for examples (helps models understand what NOT to do)
    assert "bad:" in prompt_lower or "avoid:" in prompt_lower, \
        "Prompt should provide negative examples"

    # Specific action verbs that should NOT appear as claimed actions
    # (these are common patterns of hallucinated execution)
    forbidden_patterns = [
        "i ran", "i executed", "i downloaded", "i accessed",
        "i checked", "i called", "i browsed"
    ]

    # The prompt should mention these as bad examples
    # (i.e., in the context of what to avoid, not as instruction)
    has_any_forbidden = any(
        f"bad: \"{pattern}" in _REFERENCE_SYSTEM_PROMPT.lower() or
        f"avoid \"{pattern}" in _REFERENCE_SYSTEM_PROMPT.lower()
        for pattern in forbidden_patterns
    )

    # At least one bad example pattern should exist
    assert has_any_forbidden or "examples" in _REFERENCE_SYSTEM_PROMPT.lower(), \
        "Prompt should contain examples of what to avoid"


def test_reference_system_prompt_structure():
    """
    Verify the reference system prompt has a clear structure.

    A well-structured prompt helps models follow instructions better.
    """
    # Prompt should not be empty
    assert len(_REFERENCE_SYSTEM_PROMPT) > 100, \
        "Reference system prompt should be substantive"

    # Should have multiple paragraphs (structured guidance)
    assert _REFERENCE_SYSTEM_PROMPT.count("\n\n") >= 2, \
        "Prompt should be structured with multiple sections"

    # Should contain the word "advisor" (defines role)
    assert "advisor" in _REFERENCE_SYSTEM_PROMPT.lower(), \
        "Prompt should clearly define the advisor role"


def _response(text: str = "advice") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
        usage=None,
    )


def test_reference_call_composes_only_its_own_role_prompt():
    from agent.moa_loop import _run_reference

    calls: dict[str, list[dict]] = {}
    accounting: dict[str, Any] = {}
    runtime_calls: dict[str, dict[str, Any]] = {}

    def fake_call_llm(**kwargs):
        calls[kwargs["model"]] = kwargs["messages"]
        runtime_calls[kwargs["model"]] = kwargs
        return _response()

    architecture_role = "ROLE_ARCHITECTURE_MARKER: analyze boundaries and invariants."
    security_role = "ROLE_SECURITY_MARKER: analyze trust and data exposure."
    slots = [
        {
            "provider": "test",
            "model": "architecture-model",
            "role_prompt": architecture_role,
            "reasoning_effort": "low",
            "max_tokens": 321,
        },
        {
            "provider": "test",
            "model": "security-model",
            "role_prompt": security_role,
            "reasoning_effort": "high",
            "max_tokens": 654,
        },
    ]

    with (
        patch("agent.moa_loop._slot_runtime", side_effect=lambda slot: {
            "provider": slot["provider"],
            "model": slot["model"],
            "api_mode": "chat_completions",
        }),
        patch("agent.moa_loop.call_llm", side_effect=fake_call_llm),
        patch("agent.moa_loop._trim_messages_for_reference", side_effect=lambda messages, *_args, **_kwargs: messages),
        patch("agent.moa_loop._maybe_apply_moa_cache_control", side_effect=lambda messages, _runtime: messages),
    ):
        for slot in slots:
            _label, _text, ref_accounting = _run_reference(
                slot,
                [{"role": "user", "content": "Review this change."}],
            )
            accounting[str(slot["model"])] = ref_accounting

    architecture_system = calls["architecture-model"][0]
    security_system = calls["security-model"][0]
    assert architecture_system["role"] == "system"
    assert security_system["role"] == "system"
    assert architecture_system["content"].startswith(_REFERENCE_SYSTEM_PROMPT)
    assert security_system["content"].startswith(_REFERENCE_SYSTEM_PROMPT)
    assert architecture_role in architecture_system["content"]
    assert security_role not in architecture_system["content"]
    assert security_role in security_system["content"]
    assert architecture_role not in security_system["content"]
    assert runtime_calls["architecture-model"]["provider"] == "test"
    assert runtime_calls["architecture-model"]["api_mode"] == "chat_completions"
    assert runtime_calls["architecture-model"]["max_tokens"] == 321
    assert runtime_calls["architecture-model"]["reasoning_config"] == {
        "enabled": True,
        "effort": "low",
    }
    assert runtime_calls["security-model"]["max_tokens"] == 654
    assert runtime_calls["security-model"]["reasoning_config"] == {
        "enabled": True,
        "effort": "high",
    }
    assert all("role_prompt" not in kwargs for kwargs in runtime_calls.values())
    # Existing MoA traces persist accounting.messages. The specialization is
    # trusted config, not trace/output content, so only the provider request may
    # carry it; the trace copy must retain the generic system prompt instead.
    for ref_accounting in accounting.values():
        trace_system = ref_accounting.messages[0]["content"]
        assert trace_system == _REFERENCE_SYSTEM_PROMPT
        assert architecture_role not in trace_system
        assert security_role not in trace_system


def test_reference_without_role_uses_exact_generic_system_prompt():
    from agent.moa_loop import _run_reference

    captured: dict = {}

    def fake_call_llm(**kwargs):
        captured.update(kwargs)
        return _response()

    slot = {"provider": "test", "model": "generic-model"}
    with (
        patch("agent.moa_loop._slot_runtime", return_value={
            "provider": "test",
            "model": "generic-model",
            "api_mode": "chat_completions",
        }),
        patch("agent.moa_loop.call_llm", side_effect=fake_call_llm),
        patch("agent.moa_loop._trim_messages_for_reference", side_effect=lambda messages, *_args, **_kwargs: messages),
        patch("agent.moa_loop._maybe_apply_moa_cache_control", side_effect=lambda messages, _runtime: messages),
    ):
        _run_reference(slot, [{"role": "user", "content": "Review this change."}])

    assert captured["messages"][0] == {
        "role": "system",
        "content": _REFERENCE_SYSTEM_PROMPT,
    }


def test_reference_prompt_helper_omits_blank_and_non_string_roles():
    for invalid in (None, "", " \n\t ", 123, True, ["security"], {"focus": "security"}):
        assert _reference_system_prompt(invalid) is _REFERENCE_SYSTEM_PROMPT
