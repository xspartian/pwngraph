"""Tests for `pwngraph serve` — CLI flag handling and the missing-extra
error path, without ever starting a real uvicorn server or touching Neo4j.
"""

from __future__ import annotations

import sys

from _fake_backend import FakeGraphBackend
from click.testing import CliRunner

import pwngraph.cli.main as cli_main
from pwngraph.cli.main import cli


def test_serve_reports_missing_serve_extra(monkeypatch):
    # Setting sys.modules["uvicorn"] = None forces `import uvicorn` to raise
    # ImportError — the standard way to simulate a missing optional package.
    monkeypatch.setitem(sys.modules, "uvicorn", None)
    result = CliRunner().invoke(cli, ["serve"])
    assert result.exit_code != 0
    assert "serve" in result.output.lower()
    assert "pip install" in result.output.lower()


def test_serve_builds_app_and_calls_uvicorn_run(monkeypatch):
    backend = FakeGraphBackend()
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    calls = []

    class _FakeUvicorn:
        @staticmethod
        def run(app, **kwargs):
            calls.append((app, kwargs))

    monkeypatch.setitem(sys.modules, "uvicorn", _FakeUvicorn)

    result = CliRunner().invoke(cli, ["serve", "--host", "0.0.0.0", "--port", "9001"])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    app, kwargs = calls[0]
    assert kwargs["host"] == "0.0.0.0"
    assert kwargs["port"] == 9001
    assert app.state.backend is backend


def test_serve_reload_uses_factory_import_string(monkeypatch):
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: FakeGraphBackend())

    calls = []

    class _FakeUvicorn:
        @staticmethod
        def run(target, **kwargs):
            calls.append((target, kwargs))

    monkeypatch.setitem(sys.modules, "uvicorn", _FakeUvicorn)

    result = CliRunner().invoke(cli, ["serve", "--reload"])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    target, kwargs = calls[0]
    assert target == "pwngraph.api.app:create_app_from_env"
    assert kwargs["factory"] is True
    assert kwargs["reload"] is True
