"""Regression (WEA-2773): agent-infra credentials must not reach a strict child process.

Strict context is a dispatcher-owned kanban worker (``HERMES_KANBAN_TASK``, where the repo-health bots
run), a cron run (``HERMES_CRON_SESSION``), or a profile whose config sets ``strict_child_env: true``.
There the names are stripped from every spawn path:

  * ``hermes_subprocess_env()``, with and without ``inherit_credentials``;
  * the local terminal (the agent's own shell), which consults the provider blocklist.

Interactive owner sessions match none of those and keep today's environment. The interactive tests pin
the survivor set measured on origin/main, so a change there shows up as a failure.

The 1Password and Bitwarden secret sources spawn their CLIs with ``scrub_secrets=False`` and set their
token explicitly. The tests below pin that they still get it in strict context.
"""

import os
from unittest.mock import patch

import pytest

from tools.env_passthrough import clear_env_passthrough, is_env_passthrough, register_env_passthrough
from tools.environments.local import (
    _make_run_env, build_subprocess_env, hermes_subprocess_env, served_profile_child_env)

BOT_CREDENTIAL_ENV = (
    "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "BWS_ACCESS_TOKEN", "MORPH_API_KEY",
    "ARENA_MCP_TOKEN", "LINEAR_API_KEY", "LINEAR_TOKEN", "GITHUB_PAT_TOKEN",
    "GH_TOKEN", "GITHUB_TOKEN", "SUDO_PASSWORD",
)
# What an interactive owner session keeps, measured on origin/main. GH_TOKEN and GITHUB_TOKEN are Tier 1
# and always stripped. SUDO_PASSWORD is stripped from the terminal but kept on the inherit path.
INTERACTIVE_KEPT = frozenset({
    "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "BWS_ACCESS_TOKEN", "MORPH_API_KEY",
    "ARENA_MCP_TOKEN", "LINEAR_API_KEY", "LINEAR_TOKEN", "GITHUB_PAT_TOKEN",
})
STRICT_CONTEXTS = [
    pytest.param({"HERMES_KANBAN_TASK": "t_fake"}, {}, id="kanban-worker"),
    pytest.param({"HERMES_CRON_SESSION": "1"}, {}, id="cron"),
    pytest.param({}, {"strict_child_env": True}, id="strict-config"),
]

# The agent-infra names a profile .env can carry into the overlay (the strict-context denylist).
INFRA_ENV_IN_PROFILE_DOTENV = (
    "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "BWS_ACCESS_TOKEN", "MORPH_API_KEY",
    "ARENA_MCP_TOKEN", "LINEAR_API_KEY", "LINEAR_TOKEN", "GITHUB_PAT_TOKEN", "SUDO_PASSWORD",
)

_BASE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/home/user", "USER": "testuser"}


def _loaded_env(extra):
    return {**_BASE_ENV, **{name: f"fake-{name.lower()}-value" for name in BOT_CREDENTIAL_ENV}, **extra}


def _spawn_envs(extra, cfg):
    """The env each spawn path produces, with the given context markers and profile config."""
    with patch.dict(os.environ, _loaded_env(extra), clear=True), \
            patch("hermes_cli.config.load_config", return_value=cfg):
        return {
            "hermes_subprocess_env(inherit=False)": hermes_subprocess_env(inherit_credentials=False),
            "hermes_subprocess_env(inherit=True)": hermes_subprocess_env(inherit_credentials=True),
            "agent shell": _make_run_env({}),
        }


@pytest.mark.parametrize(("extra", "cfg"), STRICT_CONTEXTS)
def test_strict_context_strips_every_infra_credential(extra, cfg):
    for path, env in _spawn_envs(extra, cfg).items():
        leaked = sorted(name for name in BOT_CREDENTIAL_ENV if name in env)
        assert not leaked, f"{path} leaked {leaked}"


def test_interactive_session_keeps_today_s_environment():
    for path, env in _spawn_envs({}, {}).items():
        kept = {name for name in BOT_CREDENTIAL_ENV if name in env}
        expected = set(INTERACTIVE_KEPT)
        if path.endswith("(inherit=True)"):
            expected.add("SUDO_PASSWORD")
        assert kept == expected, path


def test_op_child_gets_its_explicit_token_in_strict_context():
    from agent.secret_sources.onepassword import _op_child_env

    with patch.dict(os.environ, _loaded_env({"HERMES_KANBAN_TASK": "t_fake"}), clear=True):
        env = _op_child_env("ops_fake_token_value")
    assert env.get("OP_SERVICE_ACCOUNT_TOKEN") == "ops_fake_token_value"


def test_bws_child_keeps_its_token_in_strict_context():
    with patch.dict(os.environ, _loaded_env({"HERMES_KANBAN_TASK": "t_fake"}), clear=True), \
            patch("hermes_cli.config.load_config", return_value={}):
        env = build_subprocess_env(scrub_secrets=False, inherit_profile_home=False)
    assert env.get("BWS_ACCESS_TOKEN") == "fake-bws_access_token-value"


def test_strict_context_refuses_a_passthrough_registered_earlier():
    clear_env_passthrough()
    try:
        with patch.dict(os.environ, _loaded_env({}), clear=True), \
                patch("hermes_cli.config.load_config", return_value={}):
            register_env_passthrough(["OP_CONNECT_TOKEN"])  # allowed in an interactive session
        with patch.dict(os.environ, _loaded_env({"HERMES_KANBAN_TASK": "t_fake"}), clear=True), \
                patch("hermes_cli.config.load_config", return_value={}):
            assert not is_env_passthrough("OP_CONNECT_TOKEN")
            assert "OP_CONNECT_TOKEN" not in _make_run_env({})
    finally:
        clear_env_passthrough()


def _profile_home(tmp_path):
    """A served profile whose ``.env`` names every agent-infra credential plus one ordinary name."""
    home = tmp_path / "profile"
    home.mkdir()
    lines = [f"{name}=profile-{name.lower()}-value" for name in INFRA_ENV_IN_PROFILE_DOTENV]
    lines.append("REPO_HEALTH_TARGET=etch")
    (home / ".env").write_text("\n".join(lines) + "\n")
    return home


def test_strict_context_keeps_infra_credentials_out_of_the_profile_overlay(tmp_path):
    # inherit_credentials=True overlays the target profile's own .env on top of the scrubbed base.
    # The overlay must not re-admit an agent-infra name in a strict context.
    home = _profile_home(tmp_path)
    with patch.dict(os.environ, _loaded_env({"HERMES_KANBAN_TASK": "t_fake"}), clear=True), \
            patch("hermes_cli.config.load_config", return_value={}):
        env = served_profile_child_env(target_home=home, inherit_credentials=True)
    leaked = sorted(name for name in INFRA_ENV_IN_PROFILE_DOTENV if name in env)
    assert not leaked, f"profile overlay leaked {leaked}"
    assert env["REPO_HEALTH_TARGET"] == "etch"


def test_interactive_session_keeps_the_profile_overlay_as_before(tmp_path):
    home = _profile_home(tmp_path)
    with patch.dict(os.environ, _loaded_env({}), clear=True), \
            patch("hermes_cli.config.load_config", return_value={}):
        env = served_profile_child_env(target_home=home, inherit_credentials=True)
    assert env["LINEAR_API_KEY"] == "profile-linear_api_key-value"
    assert env["REPO_HEALTH_TARGET"] == "etch"


GITHUB_AND_PROVIDER_ENV_IN_PROFILE_DOTENV = (
    "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_PAT", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
)


def test_served_child_strictness_comes_from_the_target_profile(tmp_path):
    # The launch profile is not strict. The target profile's own config.yaml is, so its agent-infra
    # names must not come back from the target's .env.
    home = _profile_home(tmp_path)
    (home / "config.yaml").write_text("strict_child_env: true\n")
    with patch.dict(os.environ, _loaded_env({}), clear=True), \
            patch("hermes_cli.config.load_config", return_value={}):
        env = served_profile_child_env(target_home=home, inherit_credentials=True)
    leaked = sorted(name for name in INFRA_ENV_IN_PROFILE_DOTENV if name in env)
    assert not leaked, f"a strict target profile leaked {leaked}"
    assert env["REPO_HEALTH_TARGET"] == "etch"


def test_strict_launch_config_does_not_strip_a_non_strict_target(tmp_path):
    # The launch profile is strict and the target is not. The target's overlay keeps its names, as it
    # does in an interactive session.
    home = _profile_home(tmp_path)
    with patch.dict(os.environ, _loaded_env({}), clear=True), \
            patch("hermes_cli.config.load_config", return_value={"strict_child_env": True}):
        env = served_profile_child_env(target_home=home, inherit_credentials=True)
    assert env["LINEAR_API_KEY"] == "profile-linear_api_key-value"


def test_strict_overlay_blocks_tier1_github_names_and_provider_keys(tmp_path):
    # The overlay re-admits the profile's .env after the base scrub. In a strict context it must not
    # re-admit the Tier-1 GitHub names or the provider blocklist the base scrub uses.
    home = tmp_path / "profile"
    home.mkdir()
    lines = [f"{name}=profile-{name.lower()}-value" for name in GITHUB_AND_PROVIDER_ENV_IN_PROFILE_DOTENV]
    lines.append("REPO_HEALTH_TARGET=etch")
    (home / ".env").write_text("\n".join(lines) + "\n")
    with patch.dict(os.environ, _loaded_env({"HERMES_KANBAN_TASK": "t_fake"}), clear=True), \
            patch("hermes_cli.config.load_config", return_value={}):
        env = served_profile_child_env(target_home=home, inherit_credentials=True)
    leaked = sorted(name for name in GITHUB_AND_PROVIDER_ENV_IN_PROFILE_DOTENV if name in env)
    assert not leaked, f"profile overlay leaked {leaked}"
    assert env["REPO_HEALTH_TARGET"] == "etch"
