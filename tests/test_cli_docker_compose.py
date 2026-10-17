"""Tests for `pwngraph docker-compose` — writes the bundled Neo4j compose
file for anyone who only ran `pip install pwngraph` (pip doesn't drop
project-root files like docker-compose.yml on disk)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pwngraph.cli.main import cli

_PACKAGED_SRC = (
    Path(__file__).resolve().parent.parent / "pwngraph" / "resources" / "docker-compose.yml"
)


def test_writes_docker_compose_yml_to_cwd_by_default():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["docker-compose"])
        assert result.exit_code == 0
        assert Path("docker-compose.yml").exists()
        assert "neo4j:5-community" in Path("docker-compose.yml").read_text()


def test_content_matches_the_packaged_resource_file():
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(cli, ["docker-compose"])
        written = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert written == _PACKAGED_SRC.read_text(encoding="utf-8")


def test_refuses_to_overwrite_an_existing_file_without_force():
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("docker-compose.yml").write_text("# my own edits, do not clobber\n")
        result = runner.invoke(cli, ["docker-compose"])
        assert result.exit_code != 0
        assert "already exists" in result.output
        assert Path("docker-compose.yml").read_text() == "# my own edits, do not clobber\n"


def test_force_overwrites_an_existing_file():
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("docker-compose.yml").write_text("# stale\n")
        result = runner.invoke(cli, ["docker-compose", "--force"])
        assert result.exit_code == 0
        assert "neo4j:5-community" in Path("docker-compose.yml").read_text()


def test_respects_custom_out_path():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["docker-compose", "--out", "infra/compose.yml"])
        assert result.exit_code == 0
        assert Path("infra/compose.yml").exists()
        assert not Path("docker-compose.yml").exists()
