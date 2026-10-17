"""Tests for `pwngraph delete-scan` — the CLI-only retention lever, since
`pwngraph.api` stays read-only-plus-triage rather than exposing a browser
delete button for something this destructive and unconfirmable in a click.
"""

from __future__ import annotations

from _fake_backend import FakeGraphBackend
from click.testing import CliRunner

import pwngraph.cli.main as cli_main
from pwngraph.cli.main import cli


def test_delete_scan_unknown_scan_id_errors_without_prompting(monkeypatch):
    backend = FakeGraphBackend()
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    result = CliRunner().invoke(cli, ["delete-scan", "no-such-scan", "--yes"])

    assert result.exit_code != 0
    assert "no-such-scan" in result.output.lower() or "no-such-scan" in str(result.exception)


def test_delete_scan_with_yes_flag_skips_confirmation(monkeypatch):
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1", target_id="lab_agent")
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    result = CliRunner().invoke(cli, ["delete-scan", "scan-1", "--yes"])

    assert result.exit_code == 0, result.output
    assert "Deleted 1 node" in result.output
    assert backend.node_count == 0


def test_delete_scan_without_yes_prompts_and_aborts_on_no(monkeypatch):
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1")
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    result = CliRunner().invoke(cli, ["delete-scan", "scan-1"], input="n\n")

    assert result.exit_code == 0
    assert "Aborted" in result.output
    assert backend.node_count == 1  # nothing was deleted


def test_delete_scan_without_yes_prompts_and_deletes_on_confirm(monkeypatch):
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1")
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    result = CliRunner().invoke(cli, ["delete-scan", "scan-1"], input="y\n")

    assert result.exit_code == 0
    assert backend.node_count == 0
