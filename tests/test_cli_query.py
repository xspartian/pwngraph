"""CLI smoke tests for `pwngraph query` that don't need a live Neo4j.

Only the two paths that never touch a backend are covered here — listing the
registry and rejecting an unknown name. Running an actual named query goes
through ``_make_graph_backend()`` (Neo4j), which is exercised by
``tests/test_backend_contract.py`` and the query logic itself is covered
directly in ``tests/test_queries.py``.
"""

from __future__ import annotations

from click.testing import CliRunner

from pwngraph.cli.main import cli
from pwngraph.queries import QUERY_REGISTRY


def test_query_with_no_name_lists_the_registry():
    result = CliRunner().invoke(cli, ["query"])
    assert result.exit_code == 0
    for name in QUERY_REGISTRY:
        assert name in result.output


def test_query_unknown_name_errors_without_touching_neo4j():
    result = CliRunner().invoke(cli, ["query", "not-a-real-query"])
    assert result.exit_code != 0
    assert "unknown query" in result.output.lower()


def test_blast_radius_without_tool_errors_without_touching_neo4j():
    result = CliRunner().invoke(cli, ["query", "blast-radius"])
    assert result.exit_code != 0
    assert "--tool" in result.output
