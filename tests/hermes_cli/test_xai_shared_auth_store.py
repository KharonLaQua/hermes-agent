"""Canonical shared xAI OAuth store — issue #65394.

Unlike the Nous shared store (profile is source of truth + best-effort mirror),
the xAI shared store itself is authoritative: one grant family, one lock, one
serialized refresher, no per-profile forking of the rotating refresh token.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hermes_cli import auth
from hermes_cli.auth import AuthError


def _jwt(exp: int) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    )
    return f"{header}.{payload}.sig"


@pytest.fixture
def shared_env(tmp_path, monkeypatch):
    """Enable shared xAI mode with an isolated shared dir + profile auth."""
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    hermes_home = tmp_path / "profile"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("HERMES_SHARED_AUTH_DIR", str(shared_dir))
    monkeypatch.setenv("HERMES_XAI_SHARED_AUTH", "1")
    # Keep seat belts off real home.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    # Ensure gate reads as enabled.
    assert auth._xai_shared_auth_enabled() is True
    return {
        "shared_dir": shared_dir,
        "hermes_home": hermes_home,
        "store": shared_dir / "xai_oauth.json",
        "profile_auth": hermes_home / "auth.json",
    }


def _write_shared(env, *, access="at-1", refresh="rt-1", generation=1, **extra):
    payload = {
        "_schema": 1,
        "generation": generation,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "auth_mode": "oauth_device_code",
        "last_refresh": "2026-07-01T00:00:00Z",
        "discovery": {"token_endpoint": "https://auth.x.ai/oauth/token"},
        **extra,
    }
    env["store"].write_text(json.dumps(payload), encoding="utf-8")
    return payload


# ---------------------------------------------------------------------------
# Seat belt / gate / path
# ---------------------------------------------------------------------------


def test_shared_mode_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_XAI_SHARED_AUTH", raising=False)
    monkeypatch.delenv("HERMES_SHARED_AUTH_PROVIDERS", raising=False)
    monkeypatch.setenv("HERMES_SHARED_AUTH_DIR", str(tmp_path / "shared"))
    assert auth._xai_shared_auth_enabled() is False


def test_shared_mode_via_providers_list(monkeypatch):
    monkeypatch.delenv("HERMES_XAI_SHARED_AUTH", raising=False)
    monkeypatch.setenv("HERMES_SHARED_AUTH_PROVIDERS", "nous,xai-oauth")
    assert auth._xai_shared_auth_enabled() is True


def test_pytest_seat_belt_refuses_real_shared_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_XAI_SHARED_AUTH", "1")
    # Point the shared dir at the platform-native real path so the seat belt
    # has something dangerous to refuse (conftest normally isolates HERMES_HOME).
    from hermes_constants import _get_platform_default_hermes_home

    real_shared = _get_platform_default_hermes_home() / "shared"
    monkeypatch.setenv("HERMES_SHARED_AUTH_DIR", str(real_shared))
    with pytest.raises(RuntimeError, match="Refusing to touch real user shared xAI"):
        auth._xai_shared_store_path()


def test_write_shared_creates_0600_file(shared_env):
    written = auth._write_shared_xai_state(
        {
            "access_token": "at",
            "refresh_token": "rt",
            "auth_mode": "oauth_device_code",
        }
    )
    path = shared_env["store"]
    assert path.is_file()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
    assert written["generation"] == 1
    assert written["refresh_token"] == "rt"


def test_write_shared_bumps_generation(shared_env):
    auth._write_shared_xai_state(
        {"access_token": "a1", "refresh_token": "r1"}
    )
    second = auth._write_shared_xai_state(
        {"access_token": "a2", "refresh_token": "r2"}
    )
    assert second["generation"] == 2


def test_persist_failure_is_loud(shared_env, monkeypatch):
    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "open", boom)
    with pytest.raises(AuthError) as exc:
        auth._write_shared_xai_state(
            {"access_token": "a", "refresh_token": "r"}
        )
    assert exc.value.code == "xai_shared_persist_failed"


# ---------------------------------------------------------------------------
# Read / save / no profile fork
# ---------------------------------------------------------------------------


def test_read_prefers_shared_not_profile(shared_env):
    _write_shared(shared_env, access="shared-at", refresh="shared-rt")
    # Poison the profile with a different RT — must be ignored.
    shared_env["profile_auth"].write_text(
        json.dumps(
            {
                "version": 1,
                "providers": {
                    "xai-oauth": {
                        "tokens": {
                            "access_token": "profile-at",
                            "refresh_token": "profile-rt",
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    data = auth._read_xai_oauth_tokens(_lock=False)
    assert data["tokens"]["access_token"] == "shared-at"
    assert data["tokens"]["refresh_token"] == "shared-rt"
    assert data["auth_store"] == "shared"


def test_save_writes_shared_and_strips_profile_tokens(shared_env):
    auth._save_xai_oauth_tokens(
        {"access_token": "new-at", "refresh_token": "new-rt", "token_type": "Bearer"},
        discovery={"token_endpoint": "https://auth.x.ai/oauth/token"},
    )
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared["refresh_token"] == "new-rt"
    assert shared["access_token"] == "new-at"
    assert shared["generation"] >= 1

    profile = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    state = profile["providers"]["xai-oauth"]
    assert state.get("source") == auth.XAI_SHARED_SOURCE
    assert "tokens" not in state
    assert state.get("refresh_token") is None


def test_write_through_disabled_when_shared_active(shared_env, monkeypatch):
    root = shared_env["hermes_home"].parent / "root" / "auth.json"
    root.parent.mkdir(parents=True, exist_ok=True)
    root.write_text(json.dumps({"version": 1, "providers": {}}), encoding="utf-8")
    monkeypatch.setattr(auth, "_global_auth_file_path", lambda: root)
    # Should no-op entirely.
    auth._write_through_xai_oauth_to_global_root(
        {"tokens": {"access_token": "a", "refresh_token": "r"}}
    )
    root_store = json.loads(root.read_text(encoding="utf-8"))
    assert "xai-oauth" not in root_store.get("providers", {})


# ---------------------------------------------------------------------------
# Generation compare / concurrent adopt
# ---------------------------------------------------------------------------


def test_force_refresh_adopts_winner_without_second_post(shared_env, monkeypatch):
    _write_shared(
        shared_env,
        access=_jwt(int(time.time()) + 30),
        refresh="rt-stale",
        generation=3,
    )
    posts = {"n": 0}

    def fake_pure(access, refresh, **kwargs):
        posts["n"] += 1
        return {
            "access_token": "should-not-run",
            "refresh_token": "should-not-run",
            "token_type": "Bearer",
            "last_refresh": "2026-07-18T00:00:00Z",
        }

    monkeypatch.setattr(auth, "refresh_xai_oauth_pure", fake_pure)

    # Simulate: caller still holds the rejected old access token, but another
    # process already rotated the shared store to a new generation.
    _write_shared(
        shared_env,
        access="winner-at",
        refresh="winner-rt",
        generation=4,
    )
    creds = auth.resolve_xai_oauth_runtime_credentials(
        force_refresh=True,
        rejected_access_token=_jwt(int(time.time()) + 30),
        expected_generation=3,
    )
    assert posts["n"] == 0
    assert creds["api_key"] == "winner-at"
    assert creds["generation"] == 4


def test_refresh_posts_once_and_persists(shared_env, monkeypatch):
    old_at = _jwt(int(time.time()) - 10)  # expired
    _write_shared(shared_env, access=old_at, refresh="rt-1", generation=1)
    posts = []

    def fake_pure(access, refresh, **kwargs):
        posts.append(refresh)
        return {
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "token_type": "Bearer",
            "last_refresh": "2026-07-18T01:00:00Z",
        }

    monkeypatch.setattr(auth, "refresh_xai_oauth_pure", fake_pure)
    monkeypatch.setattr(
        auth,
        "_xai_oauth_discovery",
        lambda *_a, **_k: {"token_endpoint": "https://auth.x.ai/oauth/token"},
    )

    creds = auth.resolve_xai_oauth_runtime_credentials(refresh_if_expiring=True)
    assert posts == ["rt-1"]
    assert creds["api_key"] == "new-at"
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared["refresh_token"] == "new-rt"
    assert shared["generation"] == 2


def test_concurrent_waiters_second_adopts(shared_env, monkeypatch):
    old_at = _jwt(int(time.time()) - 5)
    _write_shared(shared_env, access=old_at, refresh="rt-only-once", generation=1)
    posts = []
    barrier = threading.Barrier(2)
    hold = threading.Event()

    def fake_pure(access, refresh, **kwargs):
        posts.append(refresh)
        # Hold the lock (we're inside pure only after lock acquired by resolve)
        # Simulate slow network so the second waiter queues on the flock.
        hold.wait(timeout=2.0)
        return {
            "access_token": "rotated-at",
            "refresh_token": "rotated-rt",
            "token_type": "Bearer",
            "last_refresh": "2026-07-18T02:00:00Z",
        }

    monkeypatch.setattr(auth, "refresh_xai_oauth_pure", fake_pure)
    monkeypatch.setattr(
        auth,
        "_xai_oauth_discovery",
        lambda *_a, **_k: {"token_endpoint": "https://auth.x.ai/oauth/token"},
    )

    results = [None, None]
    errors = [None, None]

    def worker(idx):
        try:
            barrier.wait(timeout=5)
            if idx == 0:
                # First through does the refresh.
                results[idx] = auth.resolve_xai_oauth_runtime_credentials(
                    force_refresh=True,
                    rejected_access_token=old_at,
                    expected_generation=1,
                )
                hold.set()
            else:
                # Give winner a head start to acquire the lock.
                time.sleep(0.05)
                results[idx] = auth.resolve_xai_oauth_runtime_credentials(
                    force_refresh=True,
                    rejected_access_token=old_at,
                    expected_generation=1,
                )
        except Exception as exc:  # pragma: no cover
            errors[idx] = exc
            hold.set()

    t0 = threading.Thread(target=worker, args=(0,))
    t1 = threading.Thread(target=worker, args=(1,))
    t0.start()
    t1.start()
    t0.join(timeout=10)
    t1.join(timeout=10)
    assert errors == [None, None]
    # Exactly one POST of the single-use RT.
    assert posts == ["rt-only-once"]
    assert results[0]["api_key"] == "rotated-at"
    assert results[1]["api_key"] == "rotated-at"


# ---------------------------------------------------------------------------
# Quarantine compare-and-clear
# ---------------------------------------------------------------------------


def test_quarantine_skips_when_generation_changed(shared_env):
    _write_shared(shared_env, access="a", refresh="rt-old", generation=5)
    # Simulate loser trying to clear with stale RT while winner already rotated.
    _write_shared(shared_env, access="a2", refresh="rt-new", generation=6)
    cleared = auth._clear_shared_xai_state(
        "test",
        terminal_error={"code": "xai_refresh_failed", "message": "nope"},
        only_if_refresh_token="rt-old",
        only_if_generation=5,
    )
    assert cleared is False
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared["refresh_token"] == "rt-new"
    assert shared["generation"] == 6


def test_quarantine_clears_when_still_canonical(shared_env):
    _write_shared(shared_env, access="a", refresh="rt-dead", generation=2)
    cleared = auth._clear_shared_xai_state(
        "test",
        terminal_error={
            "provider": "xai-oauth",
            "code": "xai_refresh_failed",
            "message": "invalid_grant",
            "relogin_required": True,
        },
        only_if_refresh_token="rt-dead",
        only_if_generation=2,
    )
    assert cleared is True
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert not shared.get("refresh_token")
    assert shared.get("last_auth_error", {}).get("code") == "xai_refresh_failed"


# ---------------------------------------------------------------------------
# Status / profile disable / migration
# ---------------------------------------------------------------------------


def test_status_points_at_shared_path(shared_env):
    _write_shared(
        shared_env,
        access=_jwt(int(time.time()) + 3600),
        refresh="rt",
        generation=1,
    )
    status = auth.get_xai_oauth_auth_status()
    assert status["logged_in"] is True
    assert status["shared_mode"] is True
    assert str(shared_env["store"]) in status["auth_store"]
    assert status["source"] == auth.XAI_SHARED_SOURCE
    # Never leak full RT in status.
    assert "refresh_token" not in status


def test_profile_disable_blocks_resolve(shared_env):
    _write_shared(shared_env, access="a", refresh="r")
    auth.disable_profile_xai_shared_auth()
    with pytest.raises(AuthError) as exc:
        auth.resolve_xai_oauth_runtime_credentials(refresh_if_expiring=False)
    assert exc.value.code == "xai_shared_profile_disabled"
    # Canonical grant remains.
    assert shared_env["store"].is_file()


def test_migrate_shared_strips_legacy(shared_env, monkeypatch):
    # Seed legacy profile tokens.
    shared_env["profile_auth"].write_text(
        json.dumps(
            {
                "version": 1,
                "providers": {
                    "xai-oauth": {
                        "tokens": {
                            "access_token": "legacy-at",
                            "refresh_token": "legacy-rt",
                        },
                        "last_refresh": "2026-06-01T00:00:00Z",
                        "auth_mode": "oauth_device_code",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    written = auth.migrate_xai_oauth_to_shared_store(source="profile", strip_legacy=True)
    assert written["refresh_token"] == "legacy-rt"
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared["refresh_token"] == "legacy-rt"
    profile = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    state = profile["providers"]["xai-oauth"]
    assert "tokens" not in state
    assert state.get("source") == auth.XAI_SHARED_SOURCE


def test_merge_shared_updates_local_dict(shared_env):
    _write_shared(shared_env, access="sa", refresh="sr", generation=9)
    local = {"access_token": "la", "refresh_token": "lr", "generation": 1}
    assert auth._merge_shared_xai_state(local) is True
    assert local["refresh_token"] == "sr"
    assert local["generation"] == 9
