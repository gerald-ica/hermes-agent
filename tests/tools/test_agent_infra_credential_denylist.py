"""Regression (WEA-2773): bot and agent-infra credentials must never reach a child process.

Two spawn paths matter for an autonomous bot:

  * ``hermes_subprocess_env()``: Tier 1 (``_ALWAYS_STRIP_KEYS``), stripped even with
    ``inherit_credentials=True``.
  * The local terminal (the agent's own shell). It consults only
    ``_HERMES_PROVIDER_ENV_BLOCKLIST``, so a name missing from that set reaches every
    command the agent runs.

The 1Password secret source sets ``OP_SERVICE_ACCOUNT_TOKEN`` explicitly on its own ``op``
child. That path must keep working after the denylist grows, and one test below pins it.
"""

import os
from unittest.mock import patch

import pytest

from tools.environments.local import _make_run_env, hermes_subprocess_env

BOT_CREDENTIAL_ENV = (
    "OP_SERVICE_ACCOUNT_TOKEN",
    "MORPH_API_KEY",
    "ARENA_MCP_TOKEN",
    "LINEAR_API_KEY",
    "LINEAR_TOKEN",
    "GITHUB_PAT_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "SUDO_PASSWORD",
)

_BASE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/home/user", "USER": "testuser"}


def _loaded_env():
    return {**_BASE_ENV, **{name: f"fake-{name.lower()}-value" for name in BOT_CREDENTIAL_ENV}}


class TestNonTerminalSpawn:
    @pytest.mark.parametrize("inherit", [False, True], ids=["default", "inherit_credentials"])
    def test_stripped_from_child_env(self, inherit):
        with patch.dict(os.environ, _loaded_env(), clear=True):
            env = hermes_subprocess_env(inherit_credentials=inherit)
        leaked = [name for name in BOT_CREDENTIAL_ENV if name in env]
        assert not leaked, f"leaked via hermes_subprocess_env(inherit={inherit}): {leaked}"


class TestAgentShell:
    def test_terminal_run_env_strips_all(self):
        with patch.dict(os.environ, _loaded_env(), clear=True):
            env = _make_run_env({})
        leaked = [name for name in BOT_CREDENTIAL_ENV if name in env]
        assert not leaked, f"agent shell inherited: {leaked}"


class TestOpSecretSourceUnaffected:
    def test_op_child_gets_its_explicit_token(self):
        from agent.secret_sources.onepassword import _op_child_env

        with patch.dict(os.environ, _loaded_env(), clear=True):
            env = _op_child_env("ops_fake_token_value")
        assert env.get("OP_SERVICE_ACCOUNT_TOKEN") == "ops_fake_token_value"
