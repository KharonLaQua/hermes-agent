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


# ---------------------------------------------------------------------------
# A1/A3/A4/A5 — multi-profile legacy pool strip + sole ownership
# ---------------------------------------------------------------------------


def _seed_legacy_pool_auth(path: Path, *, access: str, refresh: str, manual: bool = False):
    source = "manual:device_code" if manual else "device_code"
    payload = {
        "version": 1,
        "providers": {
            "xai-oauth": {
                "tokens": {
                    "access_token": access,
                    "refresh_token": refresh,
                },
                "auth_mode": "oauth_device_code",
            }
        },
        "credential_pool": {
            "xai-oauth": [
                {
                    "id": f"{source}-{refresh[:8]}",
                    "source": source,
                    "auth_type": "oauth",
                    "access_token": access,
                    "refresh_token": refresh,
                    "priority": 0,
                }
            ]
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_strip_covers_all_profiles_and_manuals(shared_env, tmp_path, monkeypatch):
    """A1/A4: strip removes RTs from EVERY profile + root + manual pool rows."""
    # Make default hermes root == tmp home so profile enumeration is in-sandbox.
    hermes_root = tmp_path / "home" / ".hermes"
    hermes_root.mkdir(parents=True, exist_ok=True)
    profiles_root = hermes_root / "profiles"
    profiles_root.mkdir()

    # Active profile (HERMES_HOME)
    _seed_legacy_pool_auth(
        shared_env["profile_auth"], access="p-at", refresh="p-rt", manual=False
    )
    # Second named profile with a manual RT
    other = profiles_root / "coder" / "auth.json"
    _seed_legacy_pool_auth(other, access="c-at", refresh="c-rt", manual=True)
    # Root auth.json with device_code RT
    root_auth = hermes_root / "auth.json"
    _seed_legacy_pool_auth(root_auth, access="r-at", refresh="r-rt", manual=False)

    monkeypatch.setattr(
        "hermes_cli.profiles._get_default_hermes_home", lambda: hermes_root
    )
    monkeypatch.setattr(
        "hermes_constants.get_default_hermes_root", lambda: hermes_root
    )

    audit = auth._strip_legacy_xai_oauth_secrets(include_global_root=True, fail_loud=True)
    assert audit  # something was cleaned

    for path in (shared_env["profile_auth"], other, root_auth):
        store = json.loads(path.read_text(encoding="utf-8"))
        assert not auth._auth_store_holds_durable_xai_refresh_token(store), path
        pool = store.get("credential_pool", {}).get("xai-oauth", [])
        for entry in pool:
            assert not entry.get("refresh_token")
            assert not str(entry.get("source") or "").startswith("manual")


def test_migrate_with_legacy_pools_leaves_no_fork(shared_env, tmp_path, monkeypatch):
    """Pre-populated device_code + manual RTs are gone after migrate."""
    hermes_root = tmp_path / "home" / ".hermes"
    hermes_root.mkdir(parents=True, exist_ok=True)
    (hermes_root / "profiles").mkdir()
    monkeypatch.setattr(
        "hermes_cli.profiles._get_default_hermes_home", lambda: hermes_root
    )
    monkeypatch.setattr(
        "hermes_constants.get_default_hermes_root", lambda: hermes_root
    )

    _seed_legacy_pool_auth(
        shared_env["profile_auth"], access="legacy-at", refresh="legacy-rt"
    )
    # Extra manual row in the same store
    store = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    store["credential_pool"]["xai-oauth"].append(
        {
            "id": "manual-fork",
            "source": "manual:device_code",
            "auth_type": "oauth",
            "access_token": "manual-at",
            "refresh_token": "manual-rt",
            "priority": 1,
        }
    )
    shared_env["profile_auth"].write_text(json.dumps(store), encoding="utf-8")

    written = auth.migrate_xai_oauth_to_shared_store(source="profile", strip_legacy=True)
    assert written["refresh_token"] == "legacy-rt"

    profile = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    assert not auth._auth_store_holds_durable_xai_refresh_token(profile)
    pool = profile.get("credential_pool", {}).get("xai-oauth", [])
    assert all(not e.get("refresh_token") for e in pool)
    assert all(not str(e.get("source") or "").startswith("manual") for e in pool)


def test_strip_fails_loud_when_residual_rt_remains(shared_env, monkeypatch):
    """A1: migration/login must fail if a durable RT cannot be removed."""
    _seed_legacy_pool_auth(
        shared_env["profile_auth"], access="a", refresh="rt-stuck"
    )

    real_save = auth._save_auth_store

    def save_but_restore_rt(store, target_path=None):
        # Pretend write succeeded but leave a residual RT (poisoned write).
        path = real_save(store, target_path=target_path)
        poisoned = json.loads(path.read_text(encoding="utf-8"))
        poisoned.setdefault("providers", {})["xai-oauth"] = {
            "tokens": {"access_token": "a", "refresh_token": "rt-stuck"}
        }
        path.write_text(json.dumps(poisoned), encoding="utf-8")
        return path

    monkeypatch.setattr(auth, "_save_auth_store", save_but_restore_rt)
    with pytest.raises(AuthError) as exc:
        auth._strip_legacy_xai_oauth_secrets(include_global_root=False, fail_loud=True)
    assert exc.value.code == "xai_shared_strip_incomplete"


def test_logout_preserves_disable_marker(shared_env):
    """B1: hermes logout --provider xai-oauth keeps shared_disabled marker."""
    _write_shared(shared_env, access="a", refresh="r", generation=1)
    auth._write_profile_xai_shared_reference(enabled=True, generation=1)

    # Simulate logout_command shared-mode profile path (clear then disable).
    auth.clear_provider_auth("xai-oauth")
    auth.disable_profile_xai_shared_auth()

    profile = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    state = profile["providers"]["xai-oauth"]
    assert state.get("enabled") is False
    assert state.get("shared_disabled") is True
    # Canonical grant still present.
    assert shared_env["store"].is_file()
    with pytest.raises(AuthError) as exc:
        auth.resolve_xai_oauth_runtime_credentials(refresh_if_expiring=False)
    assert exc.value.code == "xai_shared_profile_disabled"


def test_logout_command_shared_profile_path(shared_env):
    """B1 end-to-end via logout_command."""
    from types import SimpleNamespace

    _write_shared(shared_env, access="a", refresh="r")
    auth._write_profile_xai_shared_reference(enabled=True)

    args = SimpleNamespace(
        provider="xai-oauth",
        reset_config=False,
        global_logout=False,
        shared=False,
        **{"global": False},
    )
    auth.logout_command(args)

    profile = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    state = profile["providers"]["xai-oauth"]
    assert state.get("shared_disabled") is True
    assert state.get("enabled") is False
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared.get("refresh_token") == "r"


def test_load_pool_rewrites_device_code_and_manual(shared_env):
    """A3/A4: load_pool under shared mode discards local RTs."""
    from agent.credential_pool import load_pool

    _write_shared(shared_env, access="shared-at", refresh="shared-rt", generation=2)
    _seed_legacy_pool_auth(
        shared_env["profile_auth"], access="old-at", refresh="old-rt", manual=False
    )
    store = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    store["credential_pool"]["xai-oauth"].append(
        {
            "id": "manual-1",
            "source": "manual:device_code",
            "auth_type": "oauth",
            "access_token": "manual-at",
            "refresh_token": "manual-rt",
            "priority": 1,
        }
    )
    shared_env["profile_auth"].write_text(json.dumps(store), encoding="utf-8")

    pool = load_pool("xai-oauth")
    assert pool.has_credentials()
    for entry in pool.entries():
        assert not entry.refresh_token
        assert str(entry.source) == auth.XAI_SHARED_SOURCE

    # Persisted profile must not hold RTs either.
    profile = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    assert not auth._auth_store_holds_durable_xai_refresh_token(profile)


def test_manual_row_does_not_pure_refresh_under_shared(shared_env, monkeypatch):
    """A4: legacy manual entry cannot pure-refresh a local RT outside the lock."""
    from agent.credential_pool import CredentialPool, PooledCredential, AUTH_TYPE_OAUTH

    _write_shared(shared_env, access="shared-at", refresh="shared-rt", generation=1)
    pure_calls = []

    def fake_pure(access, refresh, **kwargs):
        pure_calls.append(refresh)
        return {
            "access_token": "should-not",
            "refresh_token": "should-not",
            "token_type": "Bearer",
            "last_refresh": "2026-07-18T00:00:00Z",
        }

    monkeypatch.setattr(auth, "refresh_xai_oauth_pure", fake_pure)
    monkeypatch.setattr(
        auth,
        "_xai_oauth_discovery",
        lambda *_a, **_k: {"token_endpoint": "https://auth.x.ai/oauth/token"},
    )

    entry = PooledCredential(
        id="manual-1",
        provider="xai-oauth",
        label="manual-1",
        source="manual:device_code",
        auth_type=AUTH_TYPE_OAUTH,
        access_token="manual-at",
        refresh_token="manual-rt",
        priority=0,
    )
    pool = CredentialPool("xai-oauth", [entry])
    # Force refresh path
    refreshed = pool._refresh_entry(entry, force=True)
    assert pure_calls == []  # must not pure-refresh local RT
    assert refreshed is not None
    assert refreshed.refresh_token is None
    assert refreshed.source == auth.XAI_SHARED_SOURCE


def test_write_shared_persists_id_token(shared_env):
    """D3: id_token from refresh is persisted in the canonical store."""
    written = auth._write_shared_xai_state(
        {
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "id-tok-1",
        }
    )
    assert written.get("id_token") == "id-tok-1"
    on_disk = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert on_disk.get("id_token") == "id-tok-1"


def test_save_strips_root_rt(shared_env, tmp_path, monkeypatch):
    """A5: shared save clears root providers.xai-oauth refresh_token."""
    hermes_root = tmp_path / "home" / ".hermes"
    hermes_root.mkdir(parents=True, exist_ok=True)
    root_auth = hermes_root / "auth.json"
    _seed_legacy_pool_auth(root_auth, access="root-at", refresh="root-rt")
    monkeypatch.setattr(auth, "_global_auth_file_path", lambda: root_auth)
    monkeypatch.setattr(
        "hermes_constants.get_default_hermes_root", lambda: hermes_root
    )

    auth._save_xai_oauth_tokens(
        {
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "token_type": "Bearer",
            "id_token": "id-1",
        }
    )
    root = json.loads(root_auth.read_text(encoding="utf-8"))
    assert not auth._auth_store_holds_durable_xai_refresh_token(root)
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared["refresh_token"] == "new-rt"
    assert shared.get("id_token") == "id-1"


def test_login_refuses_silent_replace_when_disabled(shared_env, monkeypatch):
    """B2: disabled profile login does not silently clobber the fleet grant."""
    from types import SimpleNamespace

    _write_shared(shared_env, access="fleet-at", refresh="fleet-rt", generation=3)
    auth.disable_profile_xai_shared_auth()

    # Non-interactive decline
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "n")
    login_called = {"n": 0}

    def boom_login(**kwargs):
        login_called["n"] += 1
        raise AssertionError("device login must not run without confirmation")

    monkeypatch.setattr(auth, "_xai_oauth_device_code_login", boom_login)
    auth._login_xai_oauth(
        SimpleNamespace(timeout=5, no_browser=True),
        auth.PROVIDER_REGISTRY["xai-oauth"],
        force_new_login=True,
    )
    assert login_called["n"] == 0
    shared = json.loads(shared_env["store"].read_text(encoding="utf-8"))
    assert shared["refresh_token"] == "fleet-rt"


def test_persistence_guard_strips_device_code_rt(shared_env):
    """A2: write_credential_pool under shared mode cannot persist a device_code RT."""
    from hermes_cli.auth import write_credential_pool

    write_credential_pool(
        "xai-oauth",
        [
            {
                "id": "dc-1",
                "source": "device_code",
                "auth_type": "oauth",
                "access_token": "at",
                "refresh_token": "rt-should-die",
                "priority": 0,
            }
        ],
    )
    store = json.loads(shared_env["profile_auth"].read_text(encoding="utf-8"))
    entries = store["credential_pool"]["xai-oauth"]
    assert len(entries) == 1
    assert not entries[0].get("refresh_token")
    assert entries[0]["source"] == auth.XAI_SHARED_SOURCE
