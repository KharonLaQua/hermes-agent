"""Regression tests for terminal security and dispatch boundaries."""

import json
from types import SimpleNamespace

import pytest

import tools.terminal_tool as terminal_tool


def setup_function():
    terminal_tool._reset_cached_sudo_passwords()


def teardown_function():
    terminal_tool._reset_cached_sudo_passwords()


def _install_scoped_terminal_harness(
    monkeypatch,
    *,
    env_type="local",
    execute_effects=None,
    context_overrides=None,
):
    events = []
    effects = list(execute_effects or [{"output": "ok", "returncode": 0}])

    class FakeEnv:
        env = {}
        cwd = "/workspace"

        def execute(self, command, **kwargs):
            events.append(("execute", command, kwargs))
            effect = effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            return effect

    config = {
        "env_type": env_type,
        "cwd": "/workspace",
        "timeout": 60,
        "lifetime_seconds": 3600,
    }
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: config)
    monkeypatch.setattr(terminal_tool, "_active_environments", {"default": FakeEnv()})
    monkeypatch.setattr(terminal_tool, "_last_activity", {})
    monkeypatch.setattr(terminal_tool, "_task_env_overrides", {})
    monkeypatch.setattr(terminal_tool, "_session_cwd", {})
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(terminal_tool, "_resolve_container_task_id", lambda _value: "default")
    monkeypatch.setattr(
        terminal_tool,
        "_scoped_terminal_permit_state_present",
        lambda: True,
        raising=False,
    )

    def build_context(**kwargs):
        context = {
            "cwd": kwargs["cwd"],
            "background": kwargs["background"],
            "pty": kwargs["pty"],
            "stdin": kwargs["stdin"],
            "force": kwargs["force"],
            "notify_on_complete": kwargs["notify_on_complete"],
            "watch_patterns": kwargs["watch_patterns"],
        }
        context.update(context_overrides or {})
        events.append(("context", context.copy()))
        return context

    monkeypatch.setattr(
        terminal_tool,
        "_build_scoped_terminal_execution_context",
        build_context,
        raising=False,
    )
    return events


def _prepared_approval(ticket, events):
    def guard(command, env_type, **kwargs):
        events.append(("guard", command, env_type, kwargs.get("execution_context")))
        return {
            "approved": False,
            "status": "permit_prepared",
            "scoped_permit": True,
            "permit_prepared": True,
            "prepared_permit": ticket,
            "permit_id_digest": "a" * 64,
            "operation_index": 0,
            "message": None,
        }

    return guard


def test_scoped_permit_consumes_immediately_before_stubbed_foreground_dispatch(monkeypatch):
    events = _install_scoped_terminal_harness(monkeypatch)
    ticket = object()
    monkeypatch.setattr(terminal_tool, "_check_all_guards", _prepared_approval(ticket, events))

    def consume(received_ticket, context):
        events.append(("consume", received_ticket, context))
        return SimpleNamespace(
            allowed=True,
            failure_class=None,
            permit_id_digest="a" * 64,
        )

    monkeypatch.setattr(
        terminal_tool,
        "consume_scoped_terminal_permit",
        consume,
        raising=False,
    )

    result = json.loads(terminal_tool.terminal_tool(command="rclone copyto source target"))

    assert result["exit_code"] == 0
    assert [event[0] for event in events] == ["context", "guard", "consume", "execute"]
    assert events[2][1] is ticket
    assert events[2][2] is events[1][3]
    assert events[1][3] == {
        "cwd": "/workspace",
        "background": False,
        "pty": False,
        "stdin": False,
        "force": False,
        "notify_on_complete": False,
        "watch_patterns": None,
    }
    assert "a" * 64 in result["approval"]


def test_scoped_permit_rejection_never_calls_environment_execute(monkeypatch):
    events = _install_scoped_terminal_harness(monkeypatch)
    ticket = object()
    monkeypatch.setattr(terminal_tool, "_check_all_guards", _prepared_approval(ticket, events))
    monkeypatch.setattr(
        terminal_tool,
        "consume_scoped_terminal_permit",
        lambda *_args, **_kwargs: SimpleNamespace(
            allowed=False,
            failure_class="task_mismatch",
            permit_id_digest="a" * 64,
        ),
        raising=False,
    )

    result = json.loads(terminal_tool.terminal_tool(command="rclone copyto source target"))

    assert result["status"] == "blocked"
    assert result["exit_code"] == -1
    assert "task_mismatch" in result["error"]
    assert not any(event[0] == "execute" for event in events)


def test_scoped_permit_bootstrap_failure_never_falls_back_to_dispatch(monkeypatch):
    events = _install_scoped_terminal_harness(monkeypatch)

    def fail_context(**_kwargs):
        raise terminal_tool.ScopedTerminalPermitError("bootstrap_failure")

    def reject_guard(command, env_type, **kwargs):
        assert kwargs.get("execution_context") == {}
        return {
            "approved": False,
            "status": "scoped_permit_denied",
            "permit_failure_class": "bootstrap_failure",
            "message": (
                "BLOCKED: scoped terminal permit validation failed "
                "(bootstrap_failure)."
            ),
        }

    monkeypatch.setattr(
        terminal_tool,
        "_build_scoped_terminal_execution_context",
        fail_context,
    )
    monkeypatch.setattr(terminal_tool, "_check_all_guards", reject_guard)

    result = json.loads(terminal_tool.terminal_tool(command="rclone copyto source target"))

    assert result["status"] == "blocked"
    assert "bootstrap_failure" in result["error"]
    assert not any(event[0] == "execute" for event in events)


@pytest.mark.parametrize(
    ("terminal_kwargs", "env_type", "context_overrides", "expected_field"),
    [
        ({"force": True}, "local", None, "force"),
        ({"background": True}, "local", None, "background"),
        ({"pty": True}, "local", None, "pty"),
        ({"notify_on_complete": True}, "local", None, "notify_on_complete"),
        ({"watch_patterns": ["ready"]}, "local", None, "watch_patterns"),
        ({}, "local", {"stdin": True}, "stdin"),
        ({}, "ssh", None, "env_type"),
    ],
    ids=["force", "background", "pty", "notification", "watch", "stdin", "non-local"],
)
def test_scoped_permit_rejects_unsupported_terminal_modes_before_dispatch(
    monkeypatch, terminal_kwargs, env_type, context_overrides, expected_field
):
    events = _install_scoped_terminal_harness(
        monkeypatch,
        env_type=env_type,
        context_overrides=context_overrides,
    )
    guard_contexts = []

    def reject_guard(command, received_env_type, **kwargs):
        context = kwargs.get("execution_context")
        guard_contexts.append((received_env_type, context))
        assert context is not None
        forbidden = received_env_type != "local" or any(
            context.get(field)
            for field in (
                "force",
                "background",
                "pty",
                "stdin",
                "notify_on_complete",
                "watch_patterns",
            )
        )
        assert forbidden
        return {
            "approved": False,
            "status": "scoped_permit_denied",
            "permit_failure_class": "operation_forbidden",
            "message": "BLOCKED: scoped permit terminal mode is forbidden.",
        }

    monkeypatch.setattr(terminal_tool, "_check_all_guards", reject_guard)

    result = json.loads(
        terminal_tool.terminal_tool(
            command="rclone copyto source target",
            **terminal_kwargs,
        )
    )

    assert result["status"] == "blocked"
    assert "forbidden" in result["error"]
    assert len(guard_contexts) == 1
    if expected_field == "env_type":
        assert guard_contexts[0][0] == "ssh"
    else:
        assert guard_contexts[0][1][expected_field]
    assert not any(event[0] == "execute" for event in events)


def test_scoped_permit_never_retries_after_consumption(monkeypatch):
    events = _install_scoped_terminal_harness(
        monkeypatch,
        execute_effects=[RuntimeError("transient backend failure")],
    )
    ticket = object()
    monkeypatch.setattr(terminal_tool, "_check_all_guards", _prepared_approval(ticket, events))
    consume_calls = []

    def consume(received_ticket, context):
        consume_calls.append((received_ticket, context))
        return SimpleNamespace(
            allowed=True,
            failure_class=None,
            permit_id_digest="a" * 64,
        )

    monkeypatch.setattr(
        terminal_tool,
        "consume_scoped_terminal_permit",
        consume,
        raising=False,
    )

    result = json.loads(terminal_tool.terminal_tool(command="rclone copyto source target"))

    assert result["exit_code"] == -1
    assert "transient backend failure" in result["error"]
    assert len(consume_calls) == 1
    assert [event[0] for event in events].count("execute") == 1


def test_searching_for_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "rg --line-number --no-heading --with-filename 'sudo' . | head -n 20"
    transformed, sudo_stdin = terminal_tool._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None


def test_terminal_schema_advertises_persistent_env_state():
    description = terminal_tool.TERMINAL_TOOL_DESCRIPTION

    assert "exported environment variables persist between calls" in description
    assert "activate a virtualenv" in description
    assert "do not re-source the same environment before every command" in description


def test_printf_literal_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "printf '%s\\n' sudo"
    transformed, sudo_stdin = terminal_tool._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None


def test_non_command_argument_named_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "grep -n sudo README.md"
    transformed, sudo_stdin = terminal_tool._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None


def test_actual_sudo_command_uses_configured_password(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo apt install -y ripgrep")

    assert transformed == "sudo -S -p '' apt install -y ripgrep"
    assert sudo_stdin == "testpass\n"


def test_actual_sudo_after_leading_env_assignment_is_rewritten(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("DEBUG=1 sudo whoami")

    assert transformed == "DEBUG=1 sudo -S -p '' whoami"
    assert sudo_stdin == "testpass\n"


def test_explicit_empty_sudo_password_tries_empty_without_prompt(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    def _fail_prompt(*_args, **_kwargs):
        raise AssertionError("interactive sudo prompt should not run for explicit empty password")

    monkeypatch.setattr(terminal_tool, "_prompt_for_sudo_password", _fail_prompt)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo true")

    assert transformed == "sudo -S -p '' true"
    assert sudo_stdin == "\n"


def test_cached_sudo_password_is_used_when_env_is_unset(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    terminal_tool._set_cached_sudo_password("cached-pass")

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("echo ok && sudo whoami")

    assert transformed == "echo ok && sudo -S -p '' whoami"
    assert sudo_stdin == "cached-pass\n"


def test_registered_sudo_callback_is_used_without_interactive_env(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    monkeypatch.setattr(terminal_tool, "_sudo_nopasswd_works", lambda: False)

    calls = []

    def sudo_callback():
        calls.append("called")
        return "callback-pass"

    terminal_tool.set_sudo_password_callback(sudo_callback)
    try:
        transformed, sudo_stdin = terminal_tool._transform_sudo_command(
            "echo ok | sudo tee /tmp/hermes-test"
        )
    finally:
        terminal_tool.set_sudo_password_callback(None)

    assert calls == ["called"]
    assert transformed == "echo ok | sudo -S -p '' tee /tmp/hermes-test"
    assert sudo_stdin == "callback-pass\n"


def test_cached_sudo_password_isolated_by_session_key(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    monkeypatch.setenv("HERMES_SESSION_KEY", "session-a")
    terminal_tool._set_cached_sudo_password("alpha-pass")

    monkeypatch.setenv("HERMES_SESSION_KEY", "session-b")
    assert terminal_tool._get_cached_sudo_password() == ""

    monkeypatch.setenv("HERMES_SESSION_KEY", "session-a")
    assert terminal_tool._get_cached_sudo_password() == "alpha-pass"


def test_passwordless_sudo_skips_interactive_prompt_and_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    def _fail_prompt(*_args, **_kwargs):
        raise AssertionError(
            "interactive sudo prompt should not run when sudo -n already works"
        )

    monkeypatch.setattr(terminal_tool, "_prompt_for_sudo_password", _fail_prompt)
    monkeypatch.setattr(terminal_tool, "_sudo_nopasswd_works", lambda: True, raising=False)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo whoami")

    assert transformed == "sudo whoami"
    assert sudo_stdin is None


def test_passwordless_sudo_probe_rechecks_local_terminal(monkeypatch):
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    calls = []

    class Result:
        def __init__(self, returncode):
            self.returncode = returncode

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return Result(0 if len(calls) == 1 else 1)

    monkeypatch.setattr(terminal_tool.subprocess, "run", fake_run)

    assert terminal_tool._sudo_nopasswd_works() is True
    assert terminal_tool._sudo_nopasswd_works() is False
    assert len(calls) == 2
    assert calls[0][0] == ["sudo", "-n", "true"]
    assert calls[1][0] == ["sudo", "-n", "true"]


def test_passwordless_sudo_probe_is_disabled_for_nonlocal_terminal_env(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "docker")

    def _fail_run(*_args, **_kwargs):
        raise AssertionError("host sudo probe must not run for non-local terminal envs")

    monkeypatch.setattr(terminal_tool.subprocess, "run", _fail_run)

    assert terminal_tool._sudo_nopasswd_works() is False


def test_validate_workdir_allows_windows_drive_paths():
    assert terminal_tool._validate_workdir(r"C:\Users\Alice\project") is None
    assert terminal_tool._validate_workdir("C:/Users/Alice/project") is None


def test_validate_workdir_allows_windows_unc_paths():
    assert terminal_tool._validate_workdir(r"\\server\share\project") is None


def test_validate_workdir_blocks_shell_metacharacters_in_windows_paths():
    assert terminal_tool._validate_workdir(r"C:\Users\Alice\project; rm -rf /")
    assert terminal_tool._validate_workdir(r"C:\Users\Alice\project$(whoami)")
    assert terminal_tool._validate_workdir("C:\\Users\\Alice\\project\nwhoami")


def test_get_env_config_ignores_bad_docker_json_for_local_backend(monkeypatch):
    """Docker-only JSON env vars must not break the default local backend."""
    monkeypatch.setenv("TERMINAL_ENV", "local")
    monkeypatch.setenv("TERMINAL_DOCKER_VOLUMES", "None")
    monkeypatch.setenv("TERMINAL_DOCKER_ENV", "not-json")
    monkeypatch.setenv("TERMINAL_DOCKER_FORWARD_ENV", "not-json")
    monkeypatch.setenv("TERMINAL_DOCKER_EXTRA_ARGS", "not-json")

    config = terminal_tool._get_env_config()

    assert config["env_type"] == "local"
    assert config["docker_volumes"] == []
    assert config["docker_env"] == {}
    assert config["docker_forward_env"] == []
    assert config["docker_extra_args"] == []


def test_get_env_config_ignores_bad_docker_json_for_ssh_backend(monkeypatch):
    """Non-container remote backends should also ignore Docker-only JSON."""
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setenv("TERMINAL_DOCKER_VOLUMES", "None")
    monkeypatch.setenv("TERMINAL_DOCKER_ENV", "not-json")

    config = terminal_tool._get_env_config()

    assert config["env_type"] == "ssh"
    assert config["docker_volumes"] == []
    assert config["docker_env"] == {}


def test_get_env_config_preserves_ssh_tilde_cwd(monkeypatch):
    """SSH cwd '~' is expanded by the remote shell, not the Hermes host."""
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setenv("TERMINAL_CWD", "~")
    monkeypatch.setenv("HOME", "/opt/data")

    config = terminal_tool._get_env_config()

    assert config["env_type"] == "ssh"
    assert config["cwd"] == "~"


def test_get_env_config_preserves_ssh_tilde_child_cwd(monkeypatch):
    """SSH cwd '~/x' must not become the local/container HOME path."""
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    monkeypatch.setenv("TERMINAL_CWD", "~/project")
    monkeypatch.setenv("HOME", "/opt/data")

    config = terminal_tool._get_env_config()

    assert config["env_type"] == "ssh"
    assert config["cwd"] == "~/project"


def test_get_env_config_still_rejects_bad_docker_json_for_docker_backend(monkeypatch):
    """Selecting Docker should keep the existing actionable config error."""
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.setenv("TERMINAL_DOCKER_VOLUMES", "None")

    try:
        terminal_tool._get_env_config()
    except ValueError as exc:
        assert "TERMINAL_DOCKER_VOLUMES" in str(exc)
    else:
        raise AssertionError("Docker backend must validate TERMINAL_DOCKER_VOLUMES")


def test_sudo_wrong_password_failure_detects_rejection_output():
    output = (
        "sudo: Authentication failed, try again.\n\n"
        "sudo: maximum 3 incorrect authentication attempts\n"
    )
    assert terminal_tool._sudo_wrong_password_failure(output) is True


def test_sudo_wrong_password_failure_ignores_tty_required_message():
    output = "sudo: a terminal is required to authenticate"
    assert terminal_tool._sudo_wrong_password_failure(output) is False


def test_invalidate_cached_sudo_on_auth_failure_clears_session_cache(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    terminal_tool._set_cached_sudo_password("wrong-pass")

    cleared = terminal_tool._invalidate_cached_sudo_on_auth_failure(
        "sudo apt install fprintd",
        "sudo: Authentication failed, try again.",
    )

    assert cleared is True
    assert terminal_tool._get_cached_sudo_password() == ""


def test_invalidate_cached_sudo_on_auth_failure_keeps_env_password(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "from-env")
    terminal_tool._set_cached_sudo_password("wrong-pass")

    cleared = terminal_tool._invalidate_cached_sudo_on_auth_failure(
        "sudo true",
        "sudo: Authentication failed, try again.",
    )

    assert cleared is False
    assert terminal_tool._get_cached_sudo_password() == "wrong-pass"


def test_transform_sudo_command_pipes_one_password_line_per_invocation(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command(
        "sudo true && sudo whoami"
    )

    assert transformed == "sudo -S -p '' true && sudo -S -p '' whoami"
    assert sudo_stdin == "testpass\ntestpass\n"


def test_count_real_sudo_invocations_ignores_mentions(monkeypatch):
    assert terminal_tool._count_real_sudo_invocations("grep sudo README.md") == 0
    assert terminal_tool._count_real_sudo_invocations("sudo a; sudo b") == 2
