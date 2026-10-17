"""Tests for `pwngraph graph` — re-exporting graph.json for a past scan
without a live Neo4j (the success path is monkeypatched to a fake backend;
missing-argument validation needs no backend at all).
"""

from __future__ import annotations

from _fake_backend import FakeGraphBackend
from click.testing import CliRunner

import pwngraph.cli.main as cli_main
from pwngraph.cli.main import cli


def test_missing_scan_id_errors_without_touching_neo4j():
    result = CliRunner().invoke(cli, ["graph"])
    assert result.exit_code != 0
    assert "scan-id" in result.output.lower() or "scan_id" in result.output.lower()


def test_graph_writes_file_and_reports_path(tmp_path, monkeypatch):
    backend = FakeGraphBackend()
    backend.add_node(
        "n1",
        scan_id="scan-1",
        node_type="user_input",
        name="user",
        label="user",
        color="#123456",
        shape="dot",
        is_adversarial=False,
    )

    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    out_file = tmp_path / "graph.json"
    result = CliRunner().invoke(
        cli, ["graph", "--scan-id", "scan-1", "--out", str(out_file), "--target", "my agent"]
    )

    assert result.exit_code == 0, result.output
    assert out_file.exists()
    assert "n1" in out_file.read_text(encoding="utf-8")
    assert "Wrote" in result.output


def test_graph_creates_parent_directories(tmp_path, monkeypatch):
    backend = FakeGraphBackend()
    monkeypatch.setattr(cli_main, "_make_graph_backend", lambda *a, **k: backend)

    out_file = tmp_path / "nested" / "graph.json"
    result = CliRunner().invoke(cli, ["graph", "--scan-id", "scan-1", "--out", str(out_file)])

    assert result.exit_code == 0, result.output
    assert out_file.exists()
