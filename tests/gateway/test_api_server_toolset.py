"""Tests for hermes-api-server toolset and API server tool availability."""
from unittest.mock import patch, MagicMock


from toolsets import resolve_toolset, get_toolset, validate_toolset


class TestHermesApiServerToolset:
    """Tests for the hermes-api-server toolset definition."""

    def test_toolset_exists(self):
        ts = get_toolset("hermes-api-server")
        assert ts is not None

    def test_toolset_validates(self):
        assert validate_toolset("hermes-api-server")

    def test_toolset_includes_web_tools(self):
        tools = resolve_toolset("hermes-api-server")
        assert "web_search" in tools
        assert "web_extract" in tools

    def test_toolset_includes_core_tools(self):
        tools = resolve_toolset("hermes-api-server")
        expected = [
            "terminal", "process",
            "read_file", "write_file", "patch", "search_files",
            "vision_analyze", "image_generate",
            "execute_code", "delegate_task",
            "todo", "memory", "session_search", "cronjob",
        ]
        for tool in expected:
            assert tool in tools, f"Missing expected tool: {tool}"

    def test_toolset_includes_browser_tools(self):
        tools = resolve_toolset("hermes-api-server")
        for tool in ["browser_navigate", "browser_snapshot", "browser_click",
                      "browser_type", "browser_scroll", "browser_back",
                      "browser_press"]:
            assert tool in tools, f"Missing browser tool: {tool}"

    def test_toolset_includes_homeassistant_tools(self):
        tools = resolve_toolset("hermes-api-server")
        for tool in ["ha_list_entities", "ha_get_state", "ha_list_services", "ha_call_service"]:
            assert tool in tools, f"Missing HA tool: {tool}"

    def test_toolset_excludes_clarify(self):
        tools = resolve_toolset("hermes-api-server")
        assert "clarify" not in tools

    def test_toolset_excludes_send_message(self):
        tools = resolve_toolset("hermes-api-server")
        assert "send_message" not in tools

    def test_toolset_excludes_text_to_speech(self):
        tools = resolve_toolset("hermes-api-server")
        assert "text_to_speech" not in tools


class TestApiServerPlatformConfig:
    def test_platforms_dict_includes_api_server(self):
        from hermes_cli.tools_config import PLATFORMS
        assert "api_server" in PLATFORMS
        assert PLATFORMS["api_server"]["default_toolset"] == "hermes-api-server"

    def test_default_api_server_includes_terminal_toolset(self):
        """Regression #49622: desktop-only read_terminal is registered into the
        'terminal' toolset (ships in-repo), so resolve_toolset('terminal') grows
        to include it after discovery. read_terminal is NOT in the
        hermes-api-server composite, so the old all-tools subset test dropped
        'terminal' entirely. Its static membership (terminal, process) IS in the
        composite, so it must stay enabled."""
        from tools.registry import discover_builtin_tools
        from hermes_cli.tools_config import _get_platform_tools
        discover_builtin_tools()
        assert "terminal" in _get_platform_tools({}, "api_server")

    def test_registering_tool_into_toolset_does_not_drop_toolset_from_inference(self):
        """Class invariant (covers the delegate_cli overlay case): registering a
        NEW tool into an existing configurable toolset must never remove that
        toolset from a platform whose composite lists the toolset's static
        tools. Synthetic registration keeps the test hermetic in CI."""
        from tools.registry import registry
        from hermes_cli.tools_config import _get_platform_tools

        sentinel = "test_sentinel_delegation_tool"
        registry.register(
            name=sentinel,
            toolset="delegation",
            schema={"name": sentinel, "description": "test",
                    "parameters": {"type": "object", "properties": {}}},
            handler=lambda args, **kw: "{}",
        )
        try:
            # delegation's static membership (delegate_task) is in the composite,
            # so the toolset must survive inference despite the extra registry tool.
            assert "delegation" in _get_platform_tools({}, "api_server"), (
                "registering a tool into 'delegation' dropped it from api_server"
            )
        finally:
            registry.deregister(sentinel)

    def test_default_off_and_restricted_toolsets_stay_off_on_api_server(self):
        """Negative contract: the static-membership comparison must NOT newly
        enable default-off or platform-restricted toolsets."""
        import os
        from unittest.mock import patch
        from hermes_cli.tools_config import _get_platform_tools
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HASS_TOKEN", None)
            os.environ.pop("XAI_API_KEY", None)
            enabled = _get_platform_tools({}, "api_server")
        assert "homeassistant" not in enabled
        assert "discord" not in enabled
        assert "discord_admin" not in enabled
        assert "x_search" not in enabled
        assert "kanban" not in enabled


class TestApiServerAdapterToolset:
    @patch("gateway.platforms.api_server.AIOHTTP_AVAILABLE", True)
    def test_create_agent_reads_config_toolsets(self):
        """API server resolves toolsets from config like all other platforms."""
        from gateway.platforms.api_server import APIServerAdapter
        from gateway.config import PlatformConfig

        adapter = APIServerAdapter(PlatformConfig())

        with patch("gateway.run._resolve_runtime_agent_kwargs") as mock_kwargs, \
             patch("gateway.run._resolve_gateway_model") as mock_model, \
             patch("gateway.run._load_gateway_config") as mock_config, \
             patch("run_agent.AIAgent") as mock_agent_cls:

            mock_kwargs.return_value = {"api_key": "test-key", "base_url": None,
                                        "provider": None, "api_mode": None,
                                        "command": None, "args": []}
            mock_model.return_value = "test/model"
            # No platform_toolsets override — should fall back to hermes-api-server default
            mock_config.return_value = {}
            mock_agent_cls.return_value = MagicMock()

            adapter._create_agent()

            mock_agent_cls.assert_called_once()
            call_kwargs = mock_agent_cls.call_args
            toolsets = call_kwargs.kwargs.get("enabled_toolsets")
            assert isinstance(toolsets, list)
            assert len(toolsets) > 0
            assert call_kwargs.kwargs.get("platform") == "api_server"

    @patch("gateway.platforms.api_server.AIOHTTP_AVAILABLE", True)
    def test_create_agent_respects_config_override(self):
        """User can override API server toolsets via platform_toolsets in config.yaml."""
        from gateway.platforms.api_server import APIServerAdapter
        from gateway.config import PlatformConfig

        adapter = APIServerAdapter(PlatformConfig())

        with patch("gateway.run._resolve_runtime_agent_kwargs") as mock_kwargs, \
             patch("gateway.run._resolve_gateway_model") as mock_model, \
             patch("gateway.run._load_gateway_config") as mock_config, \
             patch("run_agent.AIAgent") as mock_agent_cls:

            mock_kwargs.return_value = {"api_key": "test-key", "base_url": None,
                                        "provider": None, "api_mode": None,
                                        "command": None, "args": []}
            mock_model.return_value = "test/model"
            # User overrides with just web and terminal
            mock_config.return_value = {
                "platform_toolsets": {"api_server": ["web", "terminal"]}
            }
            mock_agent_cls.return_value = MagicMock()

            adapter._create_agent()

            mock_agent_cls.assert_called_once()
            call_kwargs = mock_agent_cls.call_args
            toolsets = call_kwargs.kwargs.get("enabled_toolsets")
            assert sorted(toolsets) == ["terminal", "web"]


def _create_api_server_kanban_agent(monkeypatch, adapter):
    """Build a real quiet AIAgent through the API adapter's config seam."""
    with patch("gateway.run._resolve_runtime_agent_kwargs") as mock_kwargs, \
         patch("gateway.run._resolve_gateway_model") as mock_model, \
         patch("gateway.run._load_gateway_config") as mock_config, \
         patch("gateway.run.GatewayRunner._load_reasoning_config") as mock_reasoning, \
         patch("gateway.run.GatewayRunner._load_fallback_model") as mock_fallback, \
         patch("gateway.run._current_max_iterations") as mock_iterations, \
         patch.object(adapter, "_ensure_session_db", return_value=None):
        mock_kwargs.return_value = {
            "api_key": "test-key", "base_url": "https://example.test/v1",
            "provider": "openai", "api_mode": "chat_completions",
            "command": None, "args": [],
        }
        mock_model.return_value = "test/model"
        mock_config.return_value = {
            "platform_toolsets": {"api_server": ["kanban"]},
        }
        mock_reasoning.return_value = {}
        mock_fallback.return_value = None
        mock_iterations.return_value = 1
        return adapter._create_agent(session_id="kanban-api-session")


def _controller_tool_names(agent):
    return {
        name for name in agent.valid_tool_names
        if name.startswith("kanban_")
    }


def _clear_controller_schema_caches():
    from model_tools import _clear_tool_defs_cache
    from tools.registry import invalidate_check_fn_cache

    invalidate_check_fn_cache()
    _clear_tool_defs_cache()


class TestApiServerScopedKanbanControllers:
    """Real adapter-to-AIAgent regression coverage for controller visibility."""

    def _setup_context(self, monkeypatch, tmp_path, *, profile, issuer_profile=None):
        from gateway.config import PlatformConfig
        from gateway.platforms.api_server import APIServerAdapter
        from gateway.session_context import set_session_vars
        from hermes_cli.scoped_terminal_permits import (
            ScopedTerminalPermitIssuer,
            install_active_issuer,
        )

        home = tmp_path / ".hermes"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
        _clear_controller_schema_caches()
        issuer = None
        try:
            if issuer_profile is not None:
                issuer = ScopedTerminalPermitIssuer(
                    issuer_profile=issuer_profile,
                    lock_owner_check=lambda: True,
                )
                assert install_active_issuer(issuer)
            set_session_vars(
                platform="api_server",
                session_key="kanban-api-session",
                session_id="kanban-api-session",
                profile=profile,
                async_delivery=False,
            )
            return APIServerAdapter(PlatformConfig(enabled=True)), issuer
        except Exception:
            self._cleanup(issuer)
            raise

    def _setup_authorized_context(self, monkeypatch, tmp_path):
        return self._setup_context(
            monkeypatch,
            tmp_path,
            profile="gateway",
            issuer_profile="gateway",
        )

    @staticmethod
    def _bind_session_profile(profile):
        from gateway.session_context import set_session_vars

        set_session_vars(
            platform="api_server",
            session_key="kanban-api-session",
            session_id="kanban-api-session",
            profile=profile,
            async_delivery=False,
        )

    @staticmethod
    def _cleanup(issuer):
        from gateway.session_context import reset_session_vars
        from hermes_cli.scoped_terminal_permits import uninstall_active_issuer

        try:
            reset_session_vars()
        finally:
            try:
                if issuer is not None:
                    uninstall_active_issuer(issuer)
            finally:
                try:
                    if issuer is not None:
                        issuer.close()
                finally:
                    _clear_controller_schema_caches()

    def test_create_agent_assembles_only_scoped_controller_tools(self, monkeypatch, tmp_path):
        """The production API config seam reaches actual AIAgent assembly."""
        adapter, issuer = self._setup_authorized_context(monkeypatch, tmp_path)
        try:
            agent = _create_api_server_kanban_agent(monkeypatch, adapter)
            names = _controller_tool_names(agent)
            assert names == {
                "kanban_first_prep_resume",
                "kanban_arm_terminal_permit",
            }
            assert "kanban_prepare_terminal_contract" not in agent.valid_tool_names
        finally:
            self._cleanup(issuer)

    def test_create_agent_recomputes_controllers_for_mismatched_profile(
        self, monkeypatch, tmp_path
    ):
        """A later API request cannot reuse an authorized profile's schemas."""
        from gateway.session_context import set_session_vars

        adapter, issuer = self._setup_authorized_context(monkeypatch, tmp_path)
        try:
            authorized = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            set_session_vars(
                platform="api_server",
                session_key="kanban-api-session-other",
                session_id="kanban-api-session-other",
                profile="other-profile",
                async_delivery=False,
            )
            mismatched = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            assert authorized == {
                "kanban_first_prep_resume",
                "kanban_arm_terminal_permit",
            }
            assert mismatched == set()
        finally:
            self._cleanup(issuer)

    def test_create_agent_recomputes_controllers_for_closed_issuer(
        self, monkeypatch, tmp_path
    ):
        """A closed issuer immediately removes controllers on the next request."""
        adapter, issuer = self._setup_authorized_context(monkeypatch, tmp_path)
        try:
            authorized = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            assert issuer is not None
            issuer.close()
            closed = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            assert authorized == {
                "kanban_first_prep_resume",
                "kanban_arm_terminal_permit",
            }
            assert closed == set()
        finally:
            self._cleanup(issuer)

    def test_create_agent_refreshes_controllers_after_matching_profile_binds(
        self, monkeypatch, tmp_path
    ):
        """A profile transition from mismatch to the active issuer is fresh."""
        adapter, issuer = self._setup_context(
            monkeypatch,
            tmp_path,
            profile="other-profile",
            issuer_profile="gateway",
        )
        try:
            mismatched = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            self._bind_session_profile("gateway")
            authorized = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            assert mismatched == set()
            assert authorized == {
                "kanban_first_prep_resume",
                "kanban_arm_terminal_permit",
            }
        finally:
            self._cleanup(issuer)

    def test_create_agent_refreshes_controllers_after_new_matching_issuer(
        self, monkeypatch, tmp_path
    ):
        """An issuer transition from absent to active is fresh."""
        from hermes_cli.scoped_terminal_permits import (
            ScopedTerminalPermitIssuer,
            install_active_issuer,
        )

        adapter, issuer = self._setup_context(
            monkeypatch,
            tmp_path,
            profile="gateway",
        )
        try:
            unavailable = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            issuer = ScopedTerminalPermitIssuer(
                issuer_profile="gateway",
                lock_owner_check=lambda: True,
            )
            assert install_active_issuer(issuer)
            authorized = _controller_tool_names(
                _create_api_server_kanban_agent(monkeypatch, adapter)
            )
            assert unavailable == set()
            assert authorized == {
                "kanban_first_prep_resume",
                "kanban_arm_terminal_permit",
            }
        finally:
            self._cleanup(issuer)
