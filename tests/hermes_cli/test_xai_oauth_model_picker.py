"""Tests for the xAI OAuth interactive model picker."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest


def test_xai_oauth_model_flow_uses_provider_model_ids(monkeypatch):
    """The picker must use live-aware provider_model_ids, not the import-time snapshot."""
    from hermes_cli import main as main_mod
    import hermes_cli.models as models_mod

    captured = {}

    def _capture_model_selection(models, *, current_model=""):
        captured["models"] = list(models)
        captured["current_model"] = current_model
        return "grok-imagine-video-1.5-preview"

    monkeypatch.setattr(models_mod, "_PROVIDER_MODELS", {"xai-oauth": ["grok-4.3"]})
    monkeypatch.setattr(
        models_mod,
        "provider_model_ids",
        lambda provider, force_refresh=False: ["grok-4.3", "grok-imagine-video-1.5-preview"],
    )

    with patch("hermes_cli.auth.get_xai_oauth_auth_status", return_value={"logged_in": True}), \
         patch("builtins.input", return_value="1"), \
         patch("hermes_cli.auth.resolve_xai_oauth_runtime_credentials", return_value={"base_url": "https://api.x.ai/v1"}), \
         patch("hermes_cli.auth._prompt_model_selection", side_effect=_capture_model_selection), \
         patch("hermes_cli.auth._save_model_choice"), \
         patch("hermes_cli.auth._update_config_for_provider"), \
         patch("builtins.print"):
        main_mod._model_flow_xai_oauth({}, current_model="")

    assert captured["models"] == ["grok-4.3", "grok-imagine-video-1.5-preview"]
    assert captured["current_model"] == "grok-4.3"


def test_xai_oauth_tty_gate_accepts_interactive_terminal(monkeypatch):
    """Clean control: an actual terminal remains eligible for intentional login."""
    from hermes_cli import auth

    monkeypatch.setattr(auth, "_stdio_is_tty", lambda: True)
    auth.require_xai_oauth_interactive_terminal()


def test_xai_oauth_tty_gate_rejects_noninteractive_before_device_flow(monkeypatch):
    """Positive control: automation cannot reach discovery, browser, or polling."""
    from hermes_cli import auth

    monkeypatch.setattr(auth, "_stdio_is_tty", lambda: False)
    monkeypatch.setattr(
        auth,
        "resolve_xai_oauth_runtime_credentials",
        lambda: (_ for _ in ()).throw(
            auth.AuthError("missing", provider="xai-oauth", code="missing")
        ),
    )
    monkeypatch.setattr(
        auth,
        "_xai_oauth_device_code_login",
        lambda **_: pytest.fail("device authorization must not start"),
    )

    with pytest.raises(auth.AuthError) as exc_info:
        auth._login_xai_oauth(
            SimpleNamespace(timeout=20, no_browser=False),
            None,
            force_new_login=True,
        )

    assert exc_info.value.code == "xai_oauth_requires_tty"
    assert exc_info.value.relogin_required is True
