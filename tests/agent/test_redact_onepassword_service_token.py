"""1Password service-account tokens (``ops_`` prefix) must be masked on every redaction surface.

Regression for WEA-2773: the redaction canary planted ``ops_`` tokens and found them unmasked on the
tool-output, env-dump and log paths. The body is not covered by the JWT pattern (no ``eyJ``), so
only the ``ops_`` pattern masks it. Ordinary identifiers that begin with ``ops_`` must stay readable.
"""

import pytest

from agent.redact import redact_sensitive_text, redact_terminal_output


@pytest.fixture(autouse=True)
def _redaction_enabled(monkeypatch):
    monkeypatch.delenv("HERMES_REDACT_SECRETS", raising=False)
    monkeypatch.setattr("agent.redact._REDACT_ENABLED", True)


_TOKEN = "ops_" + "Qz9-Wx7_Lm3" * 20  # 200-character body; no eyJ, so only the ops_ pattern masks it


def test_token_masked_in_log_text():
    assert _TOKEN not in redact_sensitive_text(f"connected with {_TOKEN} ok", force=True)


def test_token_masked_in_tool_output_and_env_dump():
    for command in (None, "env"):
        out = redact_terminal_output(f"result: {_TOKEN} end", command=command, force=True)
        assert _TOKEN not in out, f"token survived redaction for command={command!r}"


def test_ops_prefixed_identifiers_stay_readable():
    text = "ops_status_report and ops_worker_pool are ordinary names"
    assert redact_sensitive_text(text, force=True) == text
