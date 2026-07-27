"""Direct, read-mostly Telegram operations command surface.

This module is deliberately independent of the agent/reasoner dispatch path.
It reads operator-facing status and observation files, inspects launchd/process
metadata, and exposes one confirmation-gated LaunchAgent restart.  It never
imports or calls Robber execution code.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence



def _load_alert_utilities():
    """Load the repository-owned alert helper without depending on cwd."""
    try:
        from bin import hermes_ops_alert as helper

        if Path(helper.__file__).resolve() == (Path.home() / ".hermes/bin/hermes_ops_alert.py").resolve():
            return (
                helper.TELEGRAM_MESSAGE_MAX,
                helper._truncate_with_evidence_pointer,
                helper._load_dotenv_value,
            )
    except (ImportError, AttributeError, OSError):
        pass

    helper_path = Path(__file__).resolve().parents[2] / "bin/hermes_ops_alert.py"
    spec = importlib.util.spec_from_file_location("_hermes_ops_alert_shared", helper_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load alert truncation utility at {helper_path}")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return (
        helper.TELEGRAM_MESSAGE_MAX,
        helper._truncate_with_evidence_pointer,
        helper._load_dotenv_value,
    )


(
    TELEGRAM_MESSAGE_MAX,
    _truncate_with_evidence_pointer,
    _load_dotenv_value,
) = _load_alert_utilities()


OPS_COMMANDS: tuple[tuple[str, str], ...] = (
    ("status", "Codex Manager task status"),
    ("book", "Real-route observer measurements"),
    ("flags", "Runner and reasoner process flags"),
    ("health", "Ops service and gateway health"),
    ("watcher", "Restart ops watcher with confirmation"),
    ("help", "Telegram ops command help"),
)
OPS_COMMAND_NAMES = frozenset(name for name, _description in OPS_COMMANDS)
COMMAND_RE = re.compile(
    r"^/([A-Za-z0-9_]{1,32})(?:@[A-Za-z0-9_]{5,32})?(?:\s+(.*?))?\s*$",
    re.DOTALL,
)
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FLAG_RE = re.compile(
    r"(?<!\S)([A-Z][A-Z0-9_]{1,127}_(?:ENABLED|SHADOW|MODE))=([^\s]+)"
)
CALLBACK_PREFIX = "ops:"
CONFIRM_TTL_SECONDS = 120
WATCHER_LABEL = "com.underboss.hermes-ops-watcher"

SERVICE_LABELS: tuple[tuple[str, str], ...] = (
    ("paper-exec runner", "com.underboss.robber-paper-exec-runner"),
    ("reasoner", "com.underboss.hermes-reasoner-worker"),
    ("hermes-ops-watcher", WATCHER_LABEL),
    ("hermes-dashboard", "com.underboss.hermes-dashboard"),
    ("discord-hermes-bot", "com.underboss.discord-hermes-bot"),
    ("gateway", "ai.hermes.gateway"),
)


@dataclass(frozen=True)
class ParsedCommand:
    name: str
    args: str


@dataclass
class Confirmation:
    action: str
    user_id: str
    chat_id: str
    created_monotonic: float


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str]], CommandResult]
Clock = Callable[[], float]
GatewayStateProvider = Callable[[], Mapping[str, Any]]


def parse_command(text: str) -> Optional[ParsedCommand]:
    """Parse a Telegram slash command; return None for non-ops commands."""
    match = COMMAND_RE.fullmatch(str(text or ""))
    if not match:
        return None
    name = match.group(1).lower()
    if name not in OPS_COMMAND_NAMES:
        return None
    return ParsedCommand(name=name, args=(match.group(2) or "").strip())


def merge_menu_commands(
    existing: Iterable[tuple[str, str]], *, max_commands: int
) -> list[tuple[str, str]]:
    """Put ops commands first and replace conflicting menu descriptions."""
    remainder = [item for item in existing if item[0] not in OPS_COMMAND_NAMES]
    return [*OPS_COMMANDS, *remainder][: max(0, int(max_commands))]


def allowed_user_ids_from_env(
    value: Optional[str] = None, *, dotenv_path: Optional[Path] = None
) -> frozenset[str]:
    """Derive the ops allowlist from the existing Telegram backend allowlist."""
    if value is None:
        raw = os.getenv("TELEGRAM_ALLOWED_USERS", "").strip()
        if not raw:
            raw = _load_dotenv_value(
                dotenv_path or Path.home() / ".hermes/.env",
                "TELEGRAM_ALLOWED_USERS",
            ) or ""
    else:
        raw = value
    ids = frozenset(part.strip() for part in str(raw).split(",") if part.strip())
    # Phase 1 is intentionally single-operator and never accepts wildcard auth.
    if len(ids) != 1 or "*" in ids or not next(iter(ids), "").isdigit():
        return frozenset()
    return ids


def parse_flag_table(process_text: str) -> dict[str, str]:
    """Extract only non-secret, flag-shaped variables from a ps fixture."""
    return {name: value for name, value in FLAG_RE.findall(process_text or "")}


def _default_command_runner(argv: Sequence[str]) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=12,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult(127, "", f"{type(exc).__name__}: {exc}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _age_text(timestamp: Any, *, now: Optional[datetime] = None) -> str:
    if not timestamp:
        return "MEASUREMENT timestamp absent"
    try:
        observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        reference = now or datetime.now(timezone.utc)
        seconds = max(0, int((reference - observed.astimezone(timezone.utc)).total_seconds()))
    except (TypeError, ValueError):
        return "MEASUREMENT timestamp invalid"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


class TelegramOpsCommandSurface:
    """Server-side state and direct Telegram handlers for the ops surface."""

    def __init__(
        self,
        *,
        allowed_user_ids: Iterable[str],
        hermes_root: Path = Path.home() / ".hermes",
        status_dir: Path = Path.home() / "Documents/Claude/Projects/Codex Manager/status",
        evidence_dir: Optional[Path] = None,
        launch_agents_dir: Path = Path.home() / "Library/LaunchAgents",
        command_runner: CommandRunner = _default_command_runner,
        clock: Clock = time.monotonic,
        gateway_state_provider: Optional[GatewayStateProvider] = None,
    ) -> None:
        normalized = frozenset(str(value).strip() for value in allowed_user_ids if str(value).strip())
        if len(normalized) != 1 or "*" in normalized or not next(iter(normalized), "").isdigit():
            raise ValueError("Telegram ops commands require exactly one numeric allowed user ID")
        self.allowed_user_ids = normalized
        self.hermes_root = Path(hermes_root)
        self.status_dir = Path(status_dir)
        self.observer_dir = self.hermes_root / "robber/paper_exec/real-route-observer"
        self.evidence_dir = Path(evidence_dir or self.hermes_root / "logs/telegram-ops-command-evidence")
        self.launch_agents_dir = Path(launch_agents_dir)
        self.command_runner = command_runner
        self.clock = clock
        self.gateway_state_provider = gateway_state_provider
        self.confirmations: dict[str, Confirmation] = {}

    def is_authorized(self, user_id: Any) -> bool:
        return str(user_id or "").strip() in self.allowed_user_ids

    def _write_evidence(self, kind: str, payload: Mapping[str, Any]) -> Path:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "schema": "hermes.telegram_ops.evidence.v1",
            "created_at": _utc_now(),
            "kind": kind,
            "payload": dict(payload),
        }
        encoded = json.dumps(record, indent=2, sort_keys=True, default=str) + "\n"
        digest = secrets.token_hex(8)
        path = self.evidence_dir / f"{kind}-{digest}.json"
        tmp = path.with_suffix(f".json.{os.getpid()}.tmp")
        tmp.write_text(encoded, encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(path)
        return path

    def _record_unauthorized(
        self, *, user_id: str, chat_id: str, command: str, callback: bool = False
    ) -> None:
        self._write_evidence(
            "unauthorized-attempt",
            {
                "user_id": user_id,
                "chat_id": chat_id,
                "command": command,
                "callback": callback,
                "reply_sent": False,
            },
        )

    def _bounded_reply(self, command: str, text: str) -> str:
        if len(text) <= TELEGRAM_MESSAGE_MAX:
            return text
        evidence_path = self._write_evidence(
            "oversized-reply", {"command": command, "full_text": text}
        )
        return _truncate_with_evidence_pointer(text, TELEGRAM_MESSAGE_MAX, evidence_path)

    @staticmethod
    def _message_identity(message: Any) -> tuple[str, str, Optional[int]]:
        user = getattr(message, "from_user", None)
        chat = getattr(message, "chat", None)
        user_id = str(getattr(user, "id", "") or "")
        chat_id = str(getattr(chat, "id", "") or getattr(message, "chat_id", "") or "")
        thread_id = getattr(message, "message_thread_id", None)
        return user_id, chat_id, thread_id

    async def _send_reply(
        self,
        bot: Any,
        *,
        chat_id: str,
        thread_id: Optional[int],
        command: str,
        text: str,
        reply_markup: Any = None,
    ) -> None:
        kwargs: dict[str, Any] = {
            "chat_id": int(chat_id) if chat_id.lstrip("-").isdigit() else chat_id,
            "text": self._bounded_reply(command, text),
            "disable_web_page_preview": True,
        }
        if thread_id is not None:
            kwargs["message_thread_id"] = thread_id
        if reply_markup is not None:
            kwargs["reply_markup"] = reply_markup
        await bot.send_message(**kwargs)

    async def handle_command_message(self, message: Any, bot: Any) -> bool:
        parsed = parse_command(getattr(message, "text", ""))
        if parsed is None:
            return False
        user_id, chat_id, thread_id = self._message_identity(message)
        if not self.is_authorized(user_id):
            self._record_unauthorized(
                user_id=user_id, chat_id=chat_id, command=parsed.name, callback=False
            )
            return True

        if parsed.name == "watcher":
            if parsed.args != "restart":
                text = "Usage: /watcher restart"
                markup = None
            else:
                now = self.clock()
                self.confirmations = {
                    key: value
                    for key, value in self.confirmations.items()
                    if now - value.created_monotonic < CONFIRM_TTL_SECONDS
                }
                token = secrets.token_urlsafe(12)
                self.confirmations[token] = Confirmation(
                    action="watcher_restart",
                    user_id=user_id,
                    chat_id=chat_id,
                    created_monotonic=now,
                )
                callback_data = f"{CALLBACK_PREFIX}{token}"
                if len(callback_data.encode("utf-8")) > 64:
                    raise RuntimeError("ops callback_data exceeded Telegram's 64-byte cap")
                # A raw Bot API reply-markup dict keeps this ops-only module
                # independent of python-telegram-bot's release cadence while
                # preserving the Bot API 10.2 danger style.
                markup = {
                    "inline_keyboard": [
                        [
                            {
                                "text": "Confirm watcher restart",
                                "callback_data": callback_data,
                                "style": "danger",
                            }
                        ]
                    ]
                }
                text = "Restart hermes-ops-watcher? Confirmation expires in 120 seconds."
        else:
            text = await asyncio.to_thread(self.render_command, parsed)
            markup = None

        await self._send_reply(
            bot,
            chat_id=chat_id,
            thread_id=thread_id,
            command=parsed.name,
            text=text,
            reply_markup=markup,
        )
        return True

    async def handle_callback_query(self, query: Any, bot: Any) -> bool:
        data = str(getattr(query, "data", "") or "")
        if not data.startswith(CALLBACK_PREFIX):
            return False
        message = getattr(query, "message", None)
        user = getattr(query, "from_user", None)
        user_id = str(getattr(user, "id", "") or "")
        chat_id = str(getattr(message, "chat_id", "") or "")
        thread_id = getattr(message, "message_thread_id", None)
        if not self.is_authorized(user_id):
            self._record_unauthorized(
                user_id=user_id, chat_id=chat_id, command="watcher_restart", callback=True
            )
            return True

        opaque_id = data[len(CALLBACK_PREFIX) :]
        confirmation = self.confirmations.pop(opaque_id, None)
        if (
            confirmation is None
            or confirmation.user_id != user_id
            or confirmation.chat_id != chat_id
            or self.clock() - confirmation.created_monotonic >= CONFIRM_TTL_SECONDS
        ):
            await query.answer(text="Confirmation expired or already used.")
            try:
                await query.edit_message_reply_markup(reply_markup=None)
            except Exception:
                pass
            return True

        await query.answer(text="Restart confirmed.")
        result_text = await asyncio.to_thread(self._execute_confirmation, confirmation)
        try:
            await query.edit_message_reply_markup(reply_markup=None)
        except Exception:
            pass
        await self._send_reply(
            bot,
            chat_id=chat_id,
            thread_id=thread_id,
            command="watcher",
            text=result_text,
        )
        return True

    def render_command(self, parsed: ParsedCommand) -> str:
        if parsed.name == "help":
            return self._render_help(parsed.args)
        if parsed.name == "status":
            return self._render_status(parsed.args)
        if parsed.name == "book":
            return self._render_book(parsed.args)
        if parsed.name == "flags":
            return self._render_flags(parsed.args)
        if parsed.name == "health":
            return self._render_health(parsed.args)
        return "Unknown ops command. Use /help."

    @staticmethod
    def _render_help(args: str) -> str:
        if args:
            return "Usage: /help"
        return (
            "Telegram ops commands\n"
            "/status [slug] — list task states or show one status file\n"
            "/book — summarize real-route observer measurements\n"
            "/flags — show in-process runner and reasoner flags\n"
            "/health — show launchd services and gateway poller state\n"
            "/watcher restart — request a 120-second restart confirmation\n"
            "/help — show this help\n\n"
            "All status commands are read-only. Watcher restart runs only after the inline confirmation."
        )

    @staticmethod
    def _status_field(text: str, field: str) -> str:
        match = re.search(rf"(?m)^{re.escape(field)}:\s*(.*?)\s*$", text)
        return match.group(1).strip().strip('"') if match else "MEASUREMENT ABSENT"

    def _render_status(self, args: str) -> str:
        parts = args.split()
        if len(parts) > 1 or (parts and not SLUG_RE.fullmatch(parts[0])):
            return "Usage: /status [slug]"
        if parts:
            slug = parts[0]
            path = self.status_dir / f"{slug}.md"
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                return f"STATUS MEASUREMENT: ABSENT\nSlug: {slug}\nSource: {path}"
            except OSError as exc:
                return f"STATUS MEASUREMENT: FAILED\nSlug: {slug}\nReason: {type(exc).__name__}\nSource: {path}"
            return f"STATUS {slug}\nSource: {path}\n\n{text.rstrip()}"

        try:
            paths = sorted(self.status_dir.glob("*.md"), key=lambda item: item.stem)
        except OSError as exc:
            return f"STATUS MEASUREMENT: FAILED\nReason: {type(exc).__name__}\nSource: {self.status_dir}"
        if not paths:
            return f"STATUS MEASUREMENT: ABSENT\nNo status files at {self.status_dir}"
        lines = ["CODEX MANAGER STATUS"]
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                state = self._status_field(text, "state")
                updated = self._status_field(text, "updated_at")
            except OSError as exc:
                state = "MEASUREMENT FAILED"
                updated = type(exc).__name__
            lines.append(f"{path.stem}: {state} | {updated}")
        return "\n".join(lines)

    def _render_book(self, args: str) -> str:
        if args:
            return "Usage: /book"
        try:
            account_dirs = sorted(
                (item for item in self.observer_dir.iterdir() if item.is_dir()),
                key=lambda item: item.name,
            )
        except FileNotFoundError:
            return f"REAL-ROUTE BOOK\nMEASUREMENT ABSENT: observer directory missing\nSource: {self.observer_dir}"
        except OSError as exc:
            return f"REAL-ROUTE BOOK\nMEASUREMENT FAILED: {type(exc).__name__}\nSource: {self.observer_dir}"
        if not account_dirs:
            return f"REAL-ROUTE BOOK\nMEASUREMENT ABSENT: no account directories\nSource: {self.observer_dir}"

        lines = ["REAL-ROUTE OBSERVER BOOK"]
        for account_dir in account_dirs:
            path = account_dir / "latest.json"
            if not path.exists():
                lines.append(f"\n{account_dir.name}: MEASUREMENT ABSENT (latest.json missing)")
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                if not isinstance(data, dict):
                    raise ValueError("snapshot is not an object")
            except Exception as exc:
                lines.append(f"\n{account_dir.name}: MEASUREMENT FAILED ({type(exc).__name__})")
                continue
            status = str(data.get("status") or "MEASUREMENT STATUS ABSENT")
            contract = data.get("measurement_contract")
            receipts_complete = (
                contract.get("all_required_endpoints_complete")
                if isinstance(contract, dict)
                else None
            )
            positions = data.get("positions")
            orders = data.get("working_orders")
            position_text = str(len(positions)) if isinstance(positions, list) else "MEASUREMENT UNAVAILABLE"
            order_text = str(len(orders)) if isinstance(orders, list) else "MEASUREMENT UNAVAILABLE"
            receipt_text = (
                "yes" if receipts_complete is True else "no" if receipts_complete is False else "MEASUREMENT UNAVAILABLE"
            )
            lines.extend(
                [
                    f"\n{data.get('account') or account_dir.name}: {status}",
                    f"receipts complete: {receipt_text}",
                    f"positions: {position_text}",
                    f"working orders: {order_text}",
                    f"age: {_age_text(data.get('observed_at'))}",
                ]
            )
            reason = data.get("reason")
            if reason:
                lines.append(f"measurement reason: {reason}")
        lines.append(f"\nSource: {self.observer_dir}/*/latest.json")
        return "\n".join(lines)

    def _launchd_job(self, label: str) -> tuple[str, Optional[int], str]:
        domain = f"gui/{os.getuid()}"  # windows-footgun: ok -- launchctl-only path
        result = self.command_runner(("/bin/launchctl", "print", f"{domain}/{label}"))
        if result.returncode != 0:
            reason = (result.stderr or result.stdout or f"exit {result.returncode}").strip().splitlines()[0]
            return "MEASUREMENT FAILED", None, reason[:180]
        state_match = re.search(r"(?m)^\s*state = (\S+)", result.stdout)
        pid_match = re.search(r"(?m)^\s*pid = (\d+)", result.stdout)
        state = state_match.group(1) if state_match else "MEASUREMENT STATE ABSENT"
        pid = int(pid_match.group(1)) if pid_match else None
        return state, pid, ""

    def _process_flags(self, pid: int) -> tuple[dict[str, str], str]:
        result = self.command_runner(("/bin/ps", "eww", "-p", str(pid), "-o", "command="))
        if result.returncode != 0:
            reason = (result.stderr or result.stdout or f"exit {result.returncode}").strip().splitlines()[0]
            return {}, reason[:180]
        return parse_flag_table(result.stdout), ""

    def _render_flags(self, args: str) -> str:
        if args:
            return "Usage: /flags"
        targets = SERVICE_LABELS[:2]
        lines = ["IN-PROCESS FLAG TABLE"]
        for display, label in targets:
            state, pid, reason = self._launchd_job(label)
            if pid is None:
                lines.append(f"\n{display}: {state}; pid=MEASUREMENT UNAVAILABLE; {reason}")
                continue
            flags, flag_error = self._process_flags(pid)
            lines.append(f"\n{display}: {state}; pid={pid}")
            if flag_error:
                lines.append(f"MEASUREMENT FAILED: {flag_error}")
            elif not flags:
                lines.append("(no matching *_ENABLED/*_SHADOW/*_MODE flags)")
            else:
                lines.extend(f"{name}={flags[name]}" for name in sorted(flags))
        return "\n".join(lines)

    def _render_health(self, args: str) -> str:
        if args:
            return "Usage: /health"
        lines = ["OPS HEALTH"]
        for display, label in SERVICE_LABELS:
            state, pid, reason = self._launchd_job(label)
            pid_text = str(pid) if pid is not None else "MEASUREMENT UNAVAILABLE"
            suffix = f" | {reason}" if reason else ""
            lines.append(f"{display}: {state} | pid={pid_text}{suffix}")
        if self.gateway_state_provider is not None:
            try:
                gateway = dict(self.gateway_state_provider())
                lines.append(
                    "gateway poller: "
                    f"running={gateway.get('polling_running')} | "
                    f"progress_accepting={gateway.get('progress_accepting')} | "
                    f"send_degraded={gateway.get('send_degraded')} | "
                    f"pid={gateway.get('pid')}"
                )
            except Exception as exc:
                lines.append(f"gateway poller: MEASUREMENT FAILED ({type(exc).__name__})")
        else:
            lines.append("gateway poller: MEASUREMENT UNAVAILABLE")
        return "\n".join(lines)

    def _execute_confirmation(self, confirmation: Confirmation) -> str:
        if confirmation.action != "watcher_restart":
            return "WATCHER RESTART REFUSED: unknown confirmation action"
        domain = f"gui/{os.getuid()}"  # windows-footgun: ok -- launchctl-only path
        service = f"{domain}/{WATCHER_LABEL}"
        plist = self.launch_agents_dir / f"{WATCHER_LABEL}.plist"
        bootout = self.command_runner(("/bin/launchctl", "bootout", service))
        if bootout.returncode != 0:
            reason = (bootout.stderr or bootout.stdout or f"exit {bootout.returncode}").strip()
            return f"WATCHER RESTART FAILED at bootout\n{reason[:500]}"
        bootstrap = self.command_runner(("/bin/launchctl", "bootstrap", domain, str(plist)))
        if bootstrap.returncode != 0:
            reason = (bootstrap.stderr or bootstrap.stdout or f"exit {bootstrap.returncode}").strip()
            return f"WATCHER RESTART FAILED at bootstrap\n{reason[:500]}"
        state, pid, reason = self._launchd_job(WATCHER_LABEL)
        if state != "running" or pid is None:
            return (
                "WATCHER RESTART MEASUREMENT FAILED\n"
                f"state={state} pid={pid or 'unavailable'} reason={reason or 'verification incomplete'}"
            )
        self._write_evidence(
            "watcher-restart",
            {"state": state, "pid": pid, "user_id": confirmation.user_id, "chat_id": confirmation.chat_id},
        )
        return f"WATCHER RESTARTED\nstate={state}\npid={pid}"
