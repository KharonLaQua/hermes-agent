"""Feature-gated Claude CLI system-prompt delivery tests."""

from types import SimpleNamespace

from agent.claude_runtime import _extract_system_prompt


def test_enabled_uses_cached_system_prompt() -> None:
    agent = SimpleNamespace(_cached_system_prompt="BOUND SYSTEM PROMPT")
    assert _extract_system_prompt(agent, [], authority_enabled=True) == "BOUND SYSTEM PROMPT"


def test_off_preserves_legacy_fallback_order() -> None:
    cached_only = SimpleNamespace(_cached_system_prompt="CACHED")
    assert _extract_system_prompt(cached_only, [], authority_enabled=False) is None
    legacy = SimpleNamespace(
        _cached_system_prompt="CACHED",
        system_prompt="PUBLIC",
        _system_prompt="PRIVATE",
        system_message="MESSAGE",
    )
    assert _extract_system_prompt(legacy, [], authority_enabled=False) == "PUBLIC"


def test_explicit_message_keeps_precedence_when_enabled() -> None:
    agent = SimpleNamespace(
        _cached_system_prompt="CACHED",
        system_prompt="PUBLIC",
    )
    messages = [{"role": "system", "content": "EXPLICIT"}]
    assert _extract_system_prompt(agent, messages, authority_enabled=True) == "EXPLICIT"


def test_enabled_falls_through_to_legacy_when_cache_is_blank() -> None:
    agent = SimpleNamespace(_cached_system_prompt="  ", _system_prompt="PRIVATE")
    assert _extract_system_prompt(agent, [], authority_enabled=True) == "PRIVATE"
