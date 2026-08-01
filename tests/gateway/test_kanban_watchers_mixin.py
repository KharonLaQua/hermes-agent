"""Tests for the extracted GatewayKanbanWatchersMixin (god-file Phase 3).

The kanban watcher loops were lifted out of gateway/run.py into a mixin that
GatewayRunner inherits. These tests confirm the mixin exposes the methods and
that GatewayRunner picks them up via the MRO (behavior-neutral relocation).
"""

from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace

import pytest

import gateway.kanban_watchers as watchers
import hermes_cli.scoped_terminal_permits as permits
from gateway.kanban_watchers import GatewayKanbanWatchersMixin

KANBAN_METHODS = [
    "_kanban_notifier_watcher",
    "_kanban_dispatcher_watcher",
    "_kanban_advance",
    "_kanban_unsub",
    "_kanban_rewind",
    "_deliver_kanban_artifacts",
]


def test_mixin_defines_kanban_methods():
    for m in KANBAN_METHODS:
        assert hasattr(GatewayKanbanWatchersMixin, m), f"mixin missing {m}"


def test_gateway_runner_inherits_mixin():
    # Import here so a heavy gateway import only happens if the first test passed.
    from gateway.run import GatewayRunner

    assert issubclass(GatewayRunner, GatewayKanbanWatchersMixin)
    # Each kanban method resolves to the mixin's implementation via the MRO.
    for m in KANBAN_METHODS:
        owner = next(c for c in GatewayRunner.__mro__ if m in c.__dict__)
        assert owner is GatewayKanbanWatchersMixin, (
            f"{m} resolved to {owner.__name__}, expected the mixin"
        )


def test_watcher_loops_are_coroutines():
    # The two long-running watchers are async loops.
    assert inspect.iscoroutinefunction(GatewayKanbanWatchersMixin._kanban_notifier_watcher)
    assert inspect.iscoroutinefunction(GatewayKanbanWatchersMixin._kanban_dispatcher_watcher)


def test_dispatch_owner_starts_and_stops_scoped_permit_issuer_only_when_enabled(
    monkeypatch,
):
    from hermes_cli import config as config_module

    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_DISPATCH_IN_GATEWAY", raising=False)
    monkeypatch.setattr(
        config_module,
        "load_config",
        lambda: {
            "kanban": {
                "dispatch_in_gateway": True,
                "dispatch_interval_seconds": 60,
                "scoped_terminal_permits": {
                    "enabled": True,
                    "issuer_profiles": ["default"],
                    "max_ttl_seconds": 30,
                },
            }
        },
    )
    real_sleep = asyncio.sleep

    class Runner(GatewayKanbanWatchersMixin):
        def __init__(self):
            self._running = True

        def _active_profile_name(self):
            return "default"

    for failure in (None, asyncio.CancelledError(), RuntimeError("startup failure")):
        runner = Runner()
        handle = SimpleNamespace(closed=False)
        observed = []

        monkeypatch.setattr(
            watchers, "_acquire_singleton_lock", lambda _path, h=handle: (h, "held")
        )

        def release(released_handle):
            assert permits.get_active_issuer() is None
            assert observed and observed[0].closed is True
            assert released_handle is handle
            released_handle.closed = True

        monkeypatch.setattr(watchers, "_release_singleton_lock", release)

        async def stop_or_fail(_delay):
            issuer = permits.get_active_issuer()
            assert isinstance(issuer, permits.ScopedTerminalPermitIssuer)
            assert issuer.closed is False
            observed.append(issuer)
            if failure is not None:
                raise failure
            runner._running = False

        monkeypatch.setattr(asyncio, "sleep", stop_or_fail)

        async def run_watcher():
            task = asyncio.create_task(runner._kanban_dispatcher_watcher())
            if failure is None:
                await task
            else:
                with pytest.raises(type(failure)):
                    await task
                await real_sleep(0)

        asyncio.run(run_watcher())

        assert handle.closed is True
        assert observed[0].closed is True
        assert permits.get_active_issuer() is None
        assert runner._kanban_dispatcher_lock_handle is None


def test_contended_or_unavailable_dispatch_lock_never_exposes_permit_issuer(
    monkeypatch,
):
    from hermes_cli import config as config_module
    from hermes_cli import scoped_terminal_permits as permit_module

    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_DISPATCH_IN_GATEWAY", raising=False)
    current = {
        "lock_state": "held",
        "scoped": {},
        "constructor_fails": False,
    }
    releases = []
    slept = []

    class Runner(GatewayKanbanWatchersMixin):
        def __init__(self):
            self._running = True

        def _active_profile_name(self):
            return "default"

    monkeypatch.setattr(
        config_module,
        "load_config",
        lambda: {
            "kanban": {
                "dispatch_in_gateway": True,
                "dispatch_interval_seconds": 60,
                "scoped_terminal_permits": current["scoped"],
            }
        },
    )

    def acquire(_path):
        state = current["lock_state"]
        return (SimpleNamespace(closed=False), state) if state == "held" else (None, state)

    monkeypatch.setattr(watchers, "_acquire_singleton_lock", acquire)
    monkeypatch.setattr(watchers, "_release_singleton_lock", lambda handle: releases.append(handle))

    async def stop(_delay):
        assert permits.get_active_issuer() is None
        slept.append(current["lock_state"])
        runner._running = False

    monkeypatch.setattr(asyncio, "sleep", stop)
    real_issuer = permit_module.ScopedTerminalPermitIssuer

    def issuer_factory(**kwargs):
        if current["constructor_fails"]:
            raise RuntimeError("audit setup failed")
        return real_issuer(**kwargs)

    monkeypatch.setattr(permit_module, "ScopedTerminalPermitIssuer", issuer_factory)

    cases = [
        ("contended", {"enabled": True, "issuer_profiles": ["default"], "max_ttl_seconds": 30}, False),
        ("unavailable", {"enabled": True, "issuer_profiles": ["default"], "max_ttl_seconds": 30}, False),
        ("held", {"enabled": False, "issuer_profiles": ["default"], "max_ttl_seconds": 30}, False),
        ("held", {"enabled": True, "issuer_profiles": [], "max_ttl_seconds": 30}, False),
        ("held", {"enabled": True, "issuer_profiles": ["other"], "max_ttl_seconds": 30}, False),
        ("held", {"enabled": True, "issuer_profiles": ["default"], "max_ttl_seconds": True}, False),
        ("held", {"enabled": True, "issuer_profiles": ["default"], "max_ttl_seconds": 30}, True),
    ]
    for lock_state, scoped, constructor_fails in cases:
        current.update(
            lock_state=lock_state,
            scoped=scoped,
            constructor_fails=constructor_fails,
        )
        runner = Runner()
        asyncio.run(runner._kanban_dispatcher_watcher())
        assert permits.get_active_issuer() is None

    assert slept == ["unavailable", "held", "held", "held", "held", "held"]
    assert len(releases) == 6


def test_singleton_dispatcher_lock_is_exclusive(tmp_path):
    """Only one holder of the dispatcher lock at a time — the backstop that
    stops concurrent dispatchers double reclaiming and corrupting shared
    kanban SQLite index pages under wal_autocheckpoint=0."""
    import os

    from gateway.kanban_watchers import _acquire_singleton_lock, _release_singleton_lock

    lock = tmp_path / "kanban" / ".dispatcher.lock"

    h1, st1 = _acquire_singleton_lock(lock)
    assert st1 == "held" and h1 is not None

    # A second acquire while the first is held must be refused, not granted.
    h2, st2 = _acquire_singleton_lock(lock)
    assert st2 == "contended" and h2 is None

    # Releasing the first lets a fresh acquire succeed (lock is reusable).
    _release_singleton_lock(h1)
    h3, st3 = _acquire_singleton_lock(lock)
    assert st3 == "held" and h3 is not None
    _release_singleton_lock(h3)
