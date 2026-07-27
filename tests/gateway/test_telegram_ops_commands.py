from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from gateway.telegram_ops_commands import (
    CALLBACK_PREFIX,
    CommandResult,
    ParsedCommand,
    TelegramOpsCommandSurface,
    allowed_user_ids_from_env,
    merge_menu_commands,
    parse_command,
    parse_flag_table,
)
from plugins.platforms.telegram.adapter import TelegramAdapter


class FakeBot:
    def __init__(self):
        self.messages = []

    async def send_message(self, **kwargs):
        self.messages.append(kwargs)
        return SimpleNamespace(message_id=len(self.messages))


class FakeQuery:
    def __init__(self, *, data, user_id, chat_id=7037283812):
        self.data = data
        self.from_user = SimpleNamespace(id=user_id, first_name="Fixture")
        self.message = SimpleNamespace(
            chat_id=chat_id,
            message_thread_id=None,
        )
        self.answers = []
        self.reply_markup_edits = []

    async def answer(self, **kwargs):
        self.answers.append(kwargs)

    async def edit_message_reply_markup(self, **kwargs):
        self.reply_markup_edits.append(kwargs)


def fake_message(text, *, user_id=7037283812, chat_id=7037283812):
    return SimpleNamespace(
        text=text,
        from_user=SimpleNamespace(id=user_id),
        chat=SimpleNamespace(id=chat_id),
        chat_id=chat_id,
        message_thread_id=None,
    )


class TelegramOpsCommandFixtureTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.hermes_root = root / ".hermes"
        self.status_dir = root / "status"
        self.evidence_dir = self.hermes_root / "logs/evidence"
        self.launch_agents = root / "LaunchAgents"
        self.status_dir.mkdir(parents=True)
        self.launch_agents.mkdir(parents=True)
        self.now = [1000.0]
        self.runner_calls = []

        def runner(argv):
            self.runner_calls.append(tuple(argv))
            if argv[1] in {"bootout", "bootstrap"}:
                return CommandResult(0)
            if argv[1] == "print":
                label = argv[-1]
                pid = 111 if "paper-exec" in label else 222 if "reasoner" in label else 333
                return CommandResult(0, f"state = running\npid = {pid}\n")
            if argv[0] == "/bin/ps":
                pid = argv[3]
                if pid == "111":
                    return CommandResult(
                        0,
                        "python runner.py ROBBER_REAL_ROUTE_HARD_STOP_ENABLED=1 "
                        "ROBBER_SECRET_TOKEN=do-not-expose\n",
                    )
                return CommandResult(0, "bash reasoner.py\n")
            return CommandResult(1, "", "unexpected fixture command")

        self.surface = TelegramOpsCommandSurface(
            allowed_user_ids={"7037283812"},
            hermes_root=self.hermes_root,
            status_dir=self.status_dir,
            evidence_dir=self.evidence_dir,
            launch_agents_dir=self.launch_agents,
            command_runner=runner,
            clock=lambda: self.now[0],
            gateway_state_provider=lambda: {
                "polling_running": True,
                "progress_accepting": True,
                "send_degraded": False,
                "pid": 444,
            },
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_command_parser_positive_and_clean_fixtures(self):
        self.assertEqual(
            parse_command("/status@HermesFixtureBot telegram-ops-commands"),
            ParsedCommand("status", "telegram-ops-commands"),
        )
        self.assertIsNone(parse_command("status telegram-ops-commands"))
        self.assertIsNone(parse_command("/unknown"))

    def test_alert_utilities_fall_back_without_profile_helper(self):
        import gateway.telegram_ops_commands as commands

        root = Path(self.temp_dir.name)
        dotenv = root / ".env"
        dotenv.write_text('TOKEN="secret"\n', encoding="utf-8")
        with (
            mock.patch.object(commands.Path, "home", return_value=root),
            mock.patch.object(commands.Path, "is_file", return_value=False),
        ):
            limit, truncate, load_dotenv = commands._load_alert_utilities()

        self.assertEqual(limit, 4096)
        self.assertEqual(load_dotenv(dotenv, "TOKEN"), "secret")
        rendered = truncate("abcdefghij", 8, root / "full.txt")
        self.assertEqual(len(rendered), 8)
        self.assertTrue(rendered.endswith("txt]"))

    def test_menu_registration_puts_ops_commands_first_and_deduplicates(self):
        menu = merge_menu_commands(
            [("status", "generic status"), ("help", "generic help"), ("model", "Choose model")],
            max_commands=20,
        )
        self.assertEqual([name for name, _ in menu[:6]], ["status", "book", "flags", "health", "watcher", "help"])
        self.assertEqual(sum(1 for name, _ in menu if name == "status"), 1)
        self.assertIn(("model", "Choose model"), menu)

    def test_allowlist_derives_from_existing_dotenv_and_fails_closed(self):
        dotenv = Path(self.temp_dir.name) / "fixture.env"
        dotenv.write_text("TELEGRAM_ALLOWED_USERS=7037283812\n", encoding="utf-8")
        self.assertEqual(
            allowed_user_ids_from_env("", dotenv_path=dotenv), frozenset()
        )
        self.assertEqual(
            allowed_user_ids_from_env(None, dotenv_path=dotenv),
            frozenset({"7037283812"}),
        )
        self.assertEqual(allowed_user_ids_from_env("*"), frozenset())
        self.assertEqual(allowed_user_ids_from_env("1,2"), frozenset())

    async def test_authorized_command_acceptance_replies_directly(self):
        (self.status_dir / "fixture.md").write_text(
            "task: fixture\nstate: RUNNING\nupdated_at: 2026-07-21T22:00:00-04:00\n",
            encoding="utf-8",
        )
        bot = FakeBot()
        consumed = await self.surface.handle_command_message(fake_message("/status"), bot)
        self.assertTrue(consumed)
        self.assertEqual(len(bot.messages), 1)
        self.assertIn("fixture: RUNNING", bot.messages[0]["text"])
        self.assertEqual(list(self.evidence_dir.glob("unauthorized-attempt-*.json")), [])

    async def test_adapter_intercepts_ops_command_before_message_event_dispatch(self):
        (self.status_dir / "fixture.md").write_text(
            "state: RUNNING\nupdated_at: fixture-time\n", encoding="utf-8"
        )
        bot = FakeBot()
        adapter = object.__new__(TelegramAdapter)
        adapter._ops_commands = self.surface
        adapter._bot = bot
        # The adapter has no config/message handler at all. Success therefore
        # proves the recognized command returned before MessageEvent dispatch.
        update = SimpleNamespace(
            effective_message=fake_message("/status"),
            message=fake_message("/status"),
        )
        await TelegramAdapter._handle_command(adapter, update, None)
        self.assertEqual(len(bot.messages), 1)
        self.assertIn("fixture: RUNNING", bot.messages[0]["text"])

    async def test_unauthorized_positive_fixture_gets_no_reply_and_is_logged(self):
        bot = FakeBot()
        consumed = await self.surface.handle_command_message(
            fake_message("/health", user_id=999999), bot
        )
        self.assertTrue(consumed)
        self.assertEqual(bot.messages, [])
        files = list(self.evidence_dir.glob("unauthorized-attempt-*.json"))
        self.assertEqual(len(files), 1)
        record = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(record["payload"]["user_id"], "999999")
        self.assertFalse(record["payload"]["reply_sent"])

    async def test_confirm_flow_buttons_callback_and_action_gate(self):
        bot = FakeBot()
        consumed = await self.surface.handle_command_message(
            fake_message("/watcher restart"), bot
        )
        self.assertTrue(consumed)
        self.assertEqual(self.runner_calls, [])
        markup = bot.messages[0]["reply_markup"]
        button = markup["inline_keyboard"][0][0]
        button_data = button["callback_data"]
        self.assertTrue(button_data.startswith(CALLBACK_PREFIX))
        self.assertLessEqual(len(button_data.encode("utf-8")), 64)
        self.assertEqual(button["style"], "danger")

        query = FakeQuery(data=button_data, user_id=7037283812)
        consumed = await self.surface.handle_callback_query(query, bot)
        self.assertTrue(consumed)
        verbs = [call[1] for call in self.runner_calls]
        self.assertEqual(verbs[:2], ["bootout", "bootstrap"])
        self.assertIn("WATCHER RESTARTED", bot.messages[-1]["text"])
        self.assertEqual(query.answers[0]["text"], "Restart confirmed.")

    async def test_confirm_flow_expiry_blocks_action(self):
        bot = FakeBot()
        await self.surface.handle_command_message(fake_message("/watcher restart"), bot)
        data = bot.messages[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        self.now[0] += 120
        query = FakeQuery(data=data, user_id=7037283812)
        await self.surface.handle_callback_query(query, bot)
        self.assertEqual(self.runner_calls, [])
        self.assertEqual(query.answers[0]["text"], "Confirmation expired or already used.")

    async def test_unauthorized_callback_gets_no_answer_and_is_logged(self):
        bot = FakeBot()
        await self.surface.handle_command_message(fake_message("/watcher restart"), bot)
        data = bot.messages[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        query = FakeQuery(data=data, user_id=999999)
        await self.surface.handle_callback_query(query, bot)
        self.assertEqual(query.answers, [])
        self.assertEqual(self.runner_calls, [])
        self.assertEqual(len(list(self.evidence_dir.glob("unauthorized-attempt-*.json"))), 1)

    async def test_truncation_preserves_full_reply_in_evidence(self):
        full_body = "T" * 6000
        (self.status_dir / "oversized.md").write_text(full_body, encoding="utf-8")
        bot = FakeBot()
        await self.surface.handle_command_message(fake_message("/status oversized"), bot)
        delivered = bot.messages[0]["text"]
        self.assertLessEqual(len(delivered), 4096)
        self.assertIn("[truncated, full text at ", delivered)
        evidence_files = list(self.evidence_dir.glob("oversized-reply-*.json"))
        self.assertEqual(len(evidence_files), 1)
        record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertIn(full_body, record["payload"]["full_text"])

    def test_flag_scanner_positive_and_clean_controls(self):
        positive = parse_flag_table(
            "python runner ROBBER_REAL_ROUTE_HARD_STOP_ENABLED=1 "
            "ROBBER_REAL_ROUTE_MODE=shadow SECRET_TOKEN=hidden"
        )
        self.assertEqual(
            positive,
            {
                "ROBBER_REAL_ROUTE_HARD_STOP_ENABLED": "1",
                "ROBBER_REAL_ROUTE_MODE": "shadow",
            },
        )
        self.assertEqual(parse_flag_table("python runner SECRET_TOKEN=hidden"), {})

    def test_flags_render_uses_current_pids_and_accepts_clean_reasoner_fixture(self):
        text = self.surface.render_command(ParsedCommand("flags", ""))
        self.assertIn("paper-exec runner: running; pid=111", text)
        self.assertIn("ROBBER_REAL_ROUTE_HARD_STOP_ENABLED=1", text)
        self.assertNotIn("do-not-expose", text)
        self.assertIn("reasoner: running; pid=222", text)
        self.assertIn("no matching", text)

    def test_book_renders_unmeasured_as_measurement_state_not_flat(self):
        p2 = self.hermes_root / "robber/paper_exec/real-route-observer/p2"
        p2.mkdir(parents=True)
        (p2 / "latest.json").write_text(
            json.dumps(
                {
                    "account": "p2",
                    "status": "not_measured_unarmed",
                    "measurement_contract": {"all_required_endpoints_complete": False},
                    "positions": None,
                    "working_orders": None,
                    "observed_at": "2026-07-22T01:00:00Z",
                    "reason": "fixture_unarmed",
                }
            ),
            encoding="utf-8",
        )
        text = self.surface.render_command(ParsedCommand("book", ""))
        self.assertIn("p2: not_measured_unarmed", text)
        self.assertIn("positions: MEASUREMENT UNAVAILABLE", text)
        self.assertNotIn("positions: 0", text)

    def test_health_includes_required_services_and_local_poller_state(self):
        text = self.surface.render_command(ParsedCommand("health", ""))
        for name in (
            "paper-exec runner",
            "reasoner",
            "hermes-ops-watcher",
            "hermes-dashboard",
            "discord-hermes-bot",
            "gateway",
        ):
            self.assertIn(name, text)
        self.assertIn("gateway poller: running=True", text)


if __name__ == "__main__":
    unittest.main()
