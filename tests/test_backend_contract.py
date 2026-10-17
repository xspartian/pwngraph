"""Contract suite for GraphBackend implementations.

Every test here is parameterised over the ``backend`` fixture, so a new backend
inherits the whole suite by adding one entry to ``_BACKENDS``. That is the point
of the fixture: Neo4jBackend's conformance is already specified here rather
than being written from scratch and quietly diverging.

These tests assert the *contract*, not any storage library's behaviour — no
test may reach for a backend-specific escape hatch.

Two backends run here:

* ``fake`` — :class:`tests._fake_backend.FakeGraphBackend`, a dependency-free
  in-memory double. Test infrastructure only, never shipped; see that module's
  docstring for why it exists and what it does and doesn't prove.
* ``neo4j`` — the real, shipped backend. Needs a live server — bring one up
  with ``docker compose up -d`` (see ``docker-compose.yml``) and either use
  its defaults or point elsewhere via env vars::

    NEO4J_TEST_URI=bolt://localhost:7687 \\
    NEO4J_TEST_USER=neo4j \\
    NEO4J_TEST_PASSWORD=pwngraph-dev \\
        pytest tests/test_backend_contract.py -v

  With no reachable server the neo4j cases collect and skip — they never
  silently vanish, so a broken connection string shows up as a skip reason
  rather than a quietly-smaller test count. **Passing only on ``fake`` proves
  the contract is internally consistent; it does not verify Neo4jBackend.**
  Run this file against a live server before trusting that backend.
"""

from __future__ import annotations

import os

import pytest
from _fake_backend import FakeGraphBackend  # noqa: E402 — see tests/conftest.py

from pwngraph.backend import GraphBackend, make_backend

_NEO4J_URI = os.environ.get("NEO4J_TEST_URI", "bolt://localhost:7687")
_NEO4J_USER = os.environ.get("NEO4J_TEST_USER", "neo4j")
_NEO4J_PASSWORD = os.environ.get("NEO4J_TEST_PASSWORD", "pwngraph-dev")


def _neo4j_probe() -> str | None:
    """Return None if a live Neo4j is reachable, else a human-readable skip reason."""
    try:
        from pwngraph.backend.neo4j_backend import Neo4jBackend
    except ImportError:
        return "neo4j driver not installed — pip install pwngraph (it's a core dependency)"
    try:
        b = Neo4jBackend(uri=_NEO4J_URI, user=_NEO4J_USER, password=_NEO4J_PASSWORD)
        _ = b.node_count  # forces a round trip
        b.close()
    except Exception as exc:  # noqa: BLE001 — any connection failure means "skip"
        return f"no live Neo4j at {_NEO4J_URI} ({exc.__class__.__name__}): {exc}"
    return None


# Probed once per test session, not once per test — connection attempts are
# slow, and this file parametrizes ~30 tests over the fixture.
_NEO4J_SKIP_REASON = _neo4j_probe()


def _make_neo4j() -> GraphBackend:
    from pwngraph.backend.neo4j_backend import Neo4jBackend

    return Neo4jBackend(uri=_NEO4J_URI, user=_NEO4J_USER, password=_NEO4J_PASSWORD)


# Add new backends here. Entries that need external infrastructure should carry
# a skip marker so the suite still runs on a bare checkout.
_BACKENDS = [
    pytest.param(FakeGraphBackend, id="fake"),
    pytest.param(
        _make_neo4j,
        id="neo4j",
        marks=pytest.mark.skipif(_NEO4J_SKIP_REASON is not None, reason=_NEO4J_SKIP_REASON or ""),
    ),
]


@pytest.fixture(params=_BACKENDS)
def backend(request) -> GraphBackend:
    b = request.param()
    # Clear before *and* after: the fake backend is always a fresh object,
    # but neo4j wraps a persistent, shared database — a prior run (or a
    # manual scan against the same dev instance) can leave data behind that
    # would otherwise break every test's "starts empty" assumption.
    b.clear()
    yield b
    b.clear()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def test_make_backend_defaults_to_neo4j_and_threads_connection_kwargs(monkeypatch):
    """Verifies make_backend's own logic (kind dispatch, env-var fallback,
    kwarg merging) without needing a live server — stubs the constructor
    Neo4jBackend itself resolves to, rather than skipping this on no infra."""
    calls: dict[str, object] = {}

    class _StubNeo4jBackend:
        def __init__(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setattr("pwngraph.backend.neo4j_backend.Neo4jBackend", _StubNeo4jBackend)
    monkeypatch.setenv("PWNGRAPH_NEO4J_URI", "bolt://envhost:7687")

    backend = make_backend()  # kind defaults to "neo4j"

    assert isinstance(backend, _StubNeo4jBackend)
    assert calls["uri"] == "bolt://envhost:7687"  # env-var fallback applied
    assert calls["user"] == "neo4j"
    assert calls["password"] == "pwngraph-dev"


def test_make_backend_explicit_kwargs_override_env_defaults(monkeypatch):
    calls: dict[str, object] = {}

    class _StubNeo4jBackend:
        def __init__(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setattr("pwngraph.backend.neo4j_backend.Neo4jBackend", _StubNeo4jBackend)

    make_backend("neo4j", uri="bolt://explicit:7687", password="secret")

    assert calls["uri"] == "bolt://explicit:7687"
    assert calls["password"] == "secret"


def test_make_backend_rejects_unknown_kind():
    with pytest.raises(ValueError, match="Unknown graph backend"):
        make_backend("definitely-not-a-backend")


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def test_empty_backend_reports_zero_counts(backend):
    assert backend.node_count == 0
    assert backend.edge_count == 0


def test_add_node_then_read_attrs(backend):
    backend.add_node("n1", node_type="tool_call", name="send_email")
    assert backend.has_node("n1")
    attrs = backend.node_attrs("n1")
    assert attrs["node_type"] == "tool_call"
    assert attrs["name"] == "send_email"
    assert backend.node_count == 1


def test_node_attrs_missing_node_returns_empty_dict_not_error(backend):
    assert backend.node_attrs("nope") == {}


def test_has_node_false_for_absent(backend):
    assert backend.has_node("nope") is False


def test_contains_dunder_matches_has_node(backend):
    backend.add_node("n1")
    assert "n1" in backend
    assert "n2" not in backend


def test_readding_node_merges_attributes(backend):
    backend.add_node("n1", name="a")
    backend.add_node("n1", extra="b")
    attrs = backend.node_attrs("n1")
    assert attrs["name"] == "a"
    assert attrs["extra"] == "b"
    assert backend.node_count == 1


def test_nodes_iterates_all(backend):
    backend.add_node("n1", name="a")
    backend.add_node("n2", name="b")
    got = dict(backend.nodes())
    assert set(got) == {"n1", "n2"}
    assert got["n2"]["name"] == "b"


def test_node_attrs_returns_a_copy_not_live_state(backend):
    backend.add_node("n1", name="original")
    attrs = backend.node_attrs("n1")
    attrs["name"] = "mutated"
    assert backend.node_attrs("n1")["name"] == "original"


# ---------------------------------------------------------------------------
# find_nodes
# ---------------------------------------------------------------------------


def test_find_nodes_single_criterion(backend):
    backend.add_node("n1", node_type="user_input")
    backend.add_node("n2", node_type="tool_call")
    assert backend.find_nodes(node_type="user_input") == ["n1"]


def test_find_nodes_multiple_criteria_are_and_ed(backend):
    backend.add_node("n1", node_type="user_input", is_adversarial=True)
    backend.add_node("n2", node_type="user_input", is_adversarial=False)
    found = backend.find_nodes(node_type="user_input", is_adversarial=True)
    assert found == ["n1"]


def test_find_nodes_no_criteria_returns_everything(backend):
    backend.add_node("n1")
    backend.add_node("n2")
    assert set(backend.find_nodes()) == {"n1", "n2"}


def test_find_nodes_no_match_returns_empty(backend):
    backend.add_node("n1", node_type="user_input")
    assert backend.find_nodes(node_type="dangerous") == []


def test_find_nodes_missing_attribute_does_not_match(backend):
    backend.add_node("n1", node_type="user_input")  # no is_adversarial key
    assert backend.find_nodes(is_adversarial=True) == []


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------


def test_add_edge_and_read_between(backend):
    backend.add_node("a")
    backend.add_node("b")
    backend.add_edge("a", "b", edge_type="normal_flow")
    edges = backend.edges_between("a", "b")
    assert len(edges) == 1
    assert edges[0]["edge_type"] == "normal_flow"
    assert backend.edge_count == 1


def test_add_edge_auto_creates_missing_endpoint_nodes(backend):
    # Matches MultiDiGraph.add_edge's own behavior: an edge between two ids
    # neither of which was explicitly added still creates both endpoints, so
    # every backend is safe to call this way without every caller having to
    # add_node first.
    backend.add_edge("a", "b", edge_type="normal_flow")
    assert backend.has_node("a")
    assert backend.has_node("b")
    assert backend.node_count == 2


def test_edges_between_unconnected_returns_empty_list(backend):
    backend.add_node("a")
    backend.add_node("b")
    assert backend.edges_between("a", "b") == []


def test_parallel_edges_are_both_preserved(backend):
    # Load-bearing: the same pair of events can carry both a normal_flow edge
    # from parentage and an adversarial edge from canary propagation.
    backend.add_node("a")
    backend.add_node("b")
    backend.add_edge("a", "b", edge_type="normal_flow")
    backend.add_edge("a", "b", edge_type="tool_manipulation")

    edges = backend.edges_between("a", "b")

    assert len(edges) == 2
    assert {e["edge_type"] for e in edges} == {"normal_flow", "tool_manipulation"}
    assert backend.edge_count == 2


def test_edges_are_directed(backend):
    backend.add_node("a")
    backend.add_node("b")
    backend.add_edge("a", "b", edge_type="normal_flow")
    assert backend.edges_between("b", "a") == []


def test_edges_iterates_all_triples(backend):
    backend.add_node("a")
    backend.add_node("b")
    backend.add_edge("a", "b", edge_type="normal_flow")
    triples = list(backend.edges())
    assert len(triples) == 1
    src, dst, attrs = triples[0]
    assert (src, dst) == ("a", "b")
    assert attrs["edge_type"] == "normal_flow"


# ---------------------------------------------------------------------------
# Path queries
# ---------------------------------------------------------------------------


def _chain(backend: GraphBackend, *node_ids: str) -> None:
    for n in node_ids:
        backend.add_node(n)
    for u, v in zip(node_ids, node_ids[1:], strict=False):
        backend.add_edge(u, v, edge_type="normal_flow")


def test_has_path_direct_and_transitive(backend):
    _chain(backend, "a", "b", "c")
    assert backend.has_path("a", "b") is True
    assert backend.has_path("a", "c") is True


def test_has_path_false_when_unreachable(backend):
    backend.add_node("a")
    backend.add_node("z")
    assert backend.has_path("a", "z") is False


def test_has_path_false_for_missing_nodes_rather_than_raising(backend):
    backend.add_node("a")
    assert backend.has_path("a", "ghost") is False
    assert backend.has_path("ghost", "a") is False


def test_simple_paths_finds_the_chain(backend):
    _chain(backend, "a", "b", "c")
    paths = list(backend.simple_paths("a", "c"))
    assert paths == [["a", "b", "c"]]


def test_simple_paths_finds_multiple_routes(backend):
    for n in ("a", "b1", "b2", "c"):
        backend.add_node(n)
    backend.add_edge("a", "b1")
    backend.add_edge("a", "b2")
    backend.add_edge("b1", "c")
    backend.add_edge("b2", "c")

    paths = {tuple(p) for p in backend.simple_paths("a", "c")}

    assert paths == {("a", "b1", "c"), ("a", "b2", "c")}


def test_simple_paths_respects_hop_cutoff(backend):
    _chain(backend, "a", "b", "c", "d", "e")
    # 4 hops needed; a cutoff of 2 must exclude it.
    assert list(backend.simple_paths("a", "e", cutoff=2)) == []
    assert list(backend.simple_paths("a", "e", cutoff=4)) == [["a", "b", "c", "d", "e"]]


def test_simple_paths_missing_nodes_yields_nothing(backend):
    backend.add_node("a")
    assert list(backend.simple_paths("a", "ghost")) == []
    assert list(backend.simple_paths("ghost", "a")) == []


def test_simple_paths_terminates_on_a_cycle(backend):
    _chain(backend, "a", "b", "c")
    backend.add_edge("c", "a")  # cycle back to the start
    paths = list(backend.simple_paths("a", "c"))
    assert paths == [["a", "b", "c"]]


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_clear_empties_the_graph(backend):
    _chain(backend, "a", "b")
    backend.clear()
    assert backend.node_count == 0
    assert backend.edge_count == 0
    assert backend.has_node("a") is False


def test_delete_nodes_removes_only_the_given_ids(backend):
    backend.add_node("a")
    backend.add_node("b")
    deleted = backend.delete_nodes(["a"])
    assert deleted == 1
    assert backend.has_node("a") is False
    assert backend.has_node("b") is True


def test_delete_nodes_also_removes_touching_edges(backend):
    _chain(backend, "a", "b", "c")
    backend.delete_nodes(["b"])
    assert backend.has_node("a") is True
    assert backend.has_node("c") is True
    assert backend.edges_between("a", "b") == []
    assert backend.edges_between("b", "c") == []
    assert backend.edge_count == 0


def test_delete_nodes_ignores_unknown_ids(backend):
    backend.add_node("a")
    assert backend.delete_nodes(["ghost"]) == 0
    assert backend.node_count == 1


def test_delete_nodes_empty_list_is_a_noop(backend):
    backend.add_node("a")
    assert backend.delete_nodes([]) == 0
    assert backend.node_count == 1
