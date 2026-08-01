from __future__ import annotations

import subprocess
import socket
from pathlib import Path


def _make_task(kb, *, assignee: str):
    return kb.Task(
        id="t_spawn_tools",
        title="spawn tools",
        body=None,
        assignee=assignee,
        status="running",
        priority=0,
        created_by="test",
        created_at=1,
        started_at=None,
        completed_at=None,
        workspace_kind="dir",
        workspace_path=None,
        claim_lock="lock",
        claim_expires=None,
        tenant=None,
        current_run_id=7,
    )


def test_default_spawn_pins_assignee_profile_cli_toolsets(monkeypatch, tmp_path):
    """Manual profile assignment should keep that profile's CLI tools.

    Regression guard for dispatcher-spawned workers that boot with
    HERMES_KANBAN_TASK: the worker must not collapse to only kanban lifecycle
    tools when the assigned profile's top-level ``toolsets`` is the default
    composite. The spawned CLI gets an explicit --toolsets pin resolved from
    platform_toolsets.cli; model_tools appends task-scoped kanban tools later.
    """
    root = tmp_path / ".hermes"
    profile = root / "profiles" / "elias"
    profile.mkdir(parents=True)
    profile.joinpath("config.yaml").write_text(
        """
platform_toolsets:
  cli:
    - clarify
    - code_execution
    - delegation
    - file
    - memory
    - session_search
    - skills
    - terminal
    - web
toolsets:
  - hermes-cli
agent:
  disabled_toolsets: []
""".lstrip(),
        encoding="utf-8",
    )
    root.joinpath("config.yaml").write_text("toolsets:\n  - kanban\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))

    from hermes_cli import kanban_db as kb

    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])

    captured = {}

    class FakeProc:
        pid = 4242

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        captured["cwd"] = kwargs.get("cwd")
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    pid = kb._default_spawn(_make_task(kb, assignee="elias"), str(workspace))

    assert pid == 4242
    assert captured["env"]["HERMES_HOME"] == str(profile)
    assert captured["env"]["HERMES_KANBAN_TASK"] == "t_spawn_tools"
    assert "--toolsets" in captured["cmd"]
    pinned = captured["cmd"][captured["cmd"].index("--toolsets") + 1].split(",")
    for required in ("terminal", "web", "file", "skills", "code_execution", "delegation"):
        assert required in pinned


def test_default_spawn_never_boots_the_tui(monkeypatch, tmp_path):
    """Workers are headless: an inherited HERMES_TUI=1 (or a TUI-default
    config) must not send the quiet chat run into the Ink TUI, whose no-TTY
    bail-out exits 0 without doing the task — every attempt then ends in
    "protocol violation". The spawn pins --cli (highest-precedence interface
    flag) and strips HERMES_TUI from the child env."""
    root = tmp_path / ".hermes"
    (root / "profiles" / "elias").mkdir(parents=True)
    root.joinpath("config.yaml").write_text("display:\n  interface: tui\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setenv("HERMES_TUI", "1")

    from hermes_cli import kanban_db as kb

    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])

    captured = {}

    class FakeProc:
        pid = 4243

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    kb._default_spawn(_make_task(kb, assignee="elias"), str(workspace))

    assert "--cli" in captured["cmd"]
    assert "HERMES_TUI" not in captured["env"]


def test_default_spawn_model_override_survives_real_cli_parse(monkeypatch, tmp_path):
    """The dispatcher's pre-``chat`` model flag must reach ``args.model``.

    This is an integration contract between Kanban's worker argv builder and
    the real CLI parser. A parser default once erased the explicit override,
    silently sending the worker to its profile default or fallback instead.
    """
    root = tmp_path / ".hermes"
    (root / "profiles" / "elias").mkdir(parents=True)
    root.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))

    from hermes_cli import kanban_db as kb
    from hermes_cli._parser import build_top_level_parser

    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])
    captured = {}

    class FakeProc:
        pid = 4244

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    task = _make_task(kb, assignee="elias")
    task.model_override = "gpt-5.6-sol"
    kb._default_spawn(task, str(workspace))

    parser, _subparsers, _chat_parser = build_top_level_parser()
    # Profile selection is attached by the outer CLI bootstrap rather than
    # build_top_level_parser(); remove that already-validated prefix and parse
    # the worker flags/subcommand through the real shared parser.
    assert captured["cmd"][1:3] == ["-p", "elias"]
    args = parser.parse_args(captured["cmd"][3:])

    assert args.command == "chat"
    assert args.model == "gpt-5.6-sol"
    assert args.query == "work kanban task t_spawn_tools"


def test_resolve_worker_cli_toolsets_uses_profile_home_not_parent_config(monkeypatch, tmp_path):
    root = tmp_path / ".hermes"
    profile = root / "profiles" / "elias"
    profile.mkdir(parents=True)
    root.joinpath("config.yaml").write_text("platform_toolsets:\n  cli:\n    - kanban\n", encoding="utf-8")
    profile.joinpath("config.yaml").write_text(
        """
platform_toolsets:
  cli:
    - terminal
    - web
toolsets:
  - hermes-cli
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(root))

    from hermes_cli import kanban_db as kb

    resolved = kb._resolve_worker_cli_toolsets(str(profile))

    assert resolved is not None
    assert "terminal" in resolved
    assert "web" in resolved
    assert "kanban" in resolved  # recovered worker lifecycle surface
    assert resolved != ["kanban"]


def _capture_default_spawn(monkeypatch, tmp_path, *, task=None):
    from hermes_cli import kanban_db as kb

    root = tmp_path / ".hermes"
    profile = root / "profiles" / "elias"
    profile.mkdir(parents=True, exist_ok=True)
    profile.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    root.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])

    captured = {}

    class FakeProc:
        pid = 4245

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        captured["pass_fds"] = tuple(kwargs.get("pass_fds") or ())
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    kb._default_spawn(
        task or _make_task(kb, assignee="elias"),
        str(workspace),
        board="default",
    )
    return captured, profile.resolve(), workspace.resolve()


def test_default_spawn_strips_unanswerable_approval_context(monkeypatch, tmp_path):
    inherited = {
        "HERMES_INTERACTIVE": "1",
        "HERMES_EXEC_ASK": "1",
        "HERMES_GATEWAY_SESSION": "legacy",
        "HERMES_SESSION_KEY": "parent-session",
        "HERMES_SESSION_PLATFORM": "telegram",
        "HERMES_SESSION_USER_ID": "123",
        "HERMES_KANBAN_TERMINAL_PERMIT_FD": "999",
        "HERMES_KANBAN_TERMINAL_PERMIT_STALE": "1",
    }
    for key, value in inherited.items():
        monkeypatch.setenv(key, value)

    captured, _profile, _workspace = _capture_default_spawn(monkeypatch, tmp_path)

    child_env = captured["env"]
    for key in inherited:
        assert key not in child_env
    assert child_env["HERMES_KANBAN_HEADLESS_NO_RESPONDER"] == "1"


def test_default_spawn_preserves_gateway_lifecycle_and_child_kanban_context(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("_HERMES_GATEWAY", "1")
    monkeypatch.setenv("HERMES_SESSION_PROFILE", "parent")

    captured, profile, workspace = _capture_default_spawn(monkeypatch, tmp_path)

    child_env = captured["env"]
    assert child_env["_HERMES_GATEWAY"] == "1"
    assert child_env["HERMES_KANBAN_TASK"] == "t_spawn_tools"
    assert child_env["HERMES_KANBAN_RUN_ID"] == "7"
    assert child_env["HERMES_PROFILE"] == "elias"
    assert Path(child_env["HERMES_HOME"]).resolve() == profile
    assert Path(child_env["HERMES_KANBAN_WORKSPACE"]).resolve() == workspace
    assert "HERMES_SESSION_PROFILE" not in child_env


def _permit_spawn_fixture(monkeypatch, tmp_path, *, popen):
    from hermes_cli import kanban_db as kb
    from hermes_cli import scoped_terminal_permits as permits

    root = tmp_path / ".hermes"
    profile = root / "profiles" / "elias"
    profile.mkdir(parents=True)
    profile.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    root.joinpath("config.yaml").write_text("{}\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])
    monkeypatch.setattr(subprocess, "Popen", popen)

    class Channel:
        def __init__(self):
            self.parent, self.child = socket.socketpair()
            self.permit = type("Permit", (), {"permit_id": "permit-spawn"})()
            self.sent = False
            self.released = False

        @property
        def child_fd(self):
            return self.child.fileno()

        @property
        def env_bridge(self):
            return {permits.PERMIT_FD_ENV: str(self.child_fd)}

        def send_envelope(self):
            self.sent = True

        def release_child_endpoint(self):
            self.released = True
            self.child.close()

        def close(self):
            self.released = True
            self.child.close()
            self.parent.close()

    class Issuer:
        closed = False

        def __init__(self):
            self.channel = Channel()
            self.cancelled = False
            self.activated = None

        def activate_spawn_channel(self, **kwargs):
            self.activated = kwargs
            return self.channel

        def cancel_spawn_channel(self, channel):
            self.cancelled = True
            channel.close()

        def release_spawn_child(self, channel):
            channel.release_child_endpoint()

    issuer = Issuer()
    monkeypatch.setattr(permits, "get_active_issuer", lambda: issuer)
    return kb, issuer, profile.resolve(), workspace.resolve()


def test_default_spawn_passes_exact_permit_channel_only_for_armed_next_run(
    monkeypatch, tmp_path
):
    captured = {}

    class FakeProc:
        pid = 4246

    def fake_popen(cmd, *args, **kwargs):
        captured.update(kwargs)
        return FakeProc()

    kb, issuer, profile, workspace = _permit_spawn_fixture(
        monkeypatch, tmp_path, popen=fake_popen
    )
    fd = issuer.channel.child_fd
    pid = kb._default_spawn(_make_task(kb, assignee="elias"), str(workspace), board="default")

    assert pid == 4246
    assert captured["pass_fds"] == (fd,)
    assert captured["env"]["HERMES_KANBAN_TERMINAL_PERMIT_FD"] == str(
        fd
    )
    assert issuer.channel.sent is True
    assert issuer.channel.released is True
    assert issuer.activated == {
        "board_slug": "default",
        "task_id": "t_spawn_tools",
        "run_id": 7,
        "profile": "elias",
        "profile_home": str(profile),
        "workspace": str(workspace),
    }
    assert all("payload" not in key and "signature" not in key for key in captured["env"])


def test_default_spawn_cancels_permit_when_popen_fails(monkeypatch, tmp_path):
    def failing_popen(*args, **kwargs):
        raise OSError("popen failed")

    kb, issuer, _profile, workspace = _permit_spawn_fixture(
        monkeypatch, tmp_path, popen=failing_popen
    )

    try:
        kb._default_spawn(_make_task(kb, assignee="elias"), str(workspace), board="default")
    except OSError as exc:
        assert str(exc) == "popen failed"
    else:  # pragma: no cover - assertion keeps the design node explicit
        raise AssertionError("Popen failure must propagate")

    assert issuer.cancelled is True
    assert issuer.channel.released is True
