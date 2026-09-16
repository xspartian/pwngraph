"""Tests for pwngraph.reporter.graph_export — build_graph_view / export_graph_json.

Runs entirely against FakeGraphBackend: both functions read only through the
GraphBackend ABC (find_nodes/node_attrs/edges), same guarantee as the rest of
pwngraph.queries. No rendering library (pyvis/NetworkX) is involved any
more — the payload is plain nodes/edges/findings, the same shape both the
offline graph.json artifact and the live `/api/scans/{id}/graph` route
return (see the module docstring for why they share build_graph_view).
"""

from __future__ import annotations

import json

from _fake_backend import FakeGraphBackend

from pwngraph.reporter.graph_export import build_graph_view, export_graph_json


def _add_trace_node(backend, node_id, *, scan_id="scan-1", node_type="user_input", **extra):
    backend.add_node(
        node_id,
        scan_id=scan_id,
        node_type=node_type,
        name=extra.pop("name", node_id),
        label=extra.pop("label", node_id),
        color=extra.pop("color", "#123456"),
        shape=extra.pop("shape", "dot"),
        is_adversarial=extra.pop("is_adversarial", False),
        **extra,
    )


def test_writes_a_valid_json_file(tmp_path):
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1")
    out = export_graph_json(backend, "scan-1", tmp_path / "graph.json")
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["scan_id"] == "scan-1"
    assert "nodes" in payload and "edges" in payload and "findings" in payload


def test_nodes_and_edges_carry_the_scoped_data(tmp_path):
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", node_type="user_input", label="User")
    _add_trace_node(backend, "n2", node_type="tool_call", label="call: send_email")
    backend.add_edge("n1", "n2", edge_type="direct_injection", color="#e74c3c", is_adversarial=True)

    view = build_graph_view(backend, "scan-1")

    ids = {n["id"] for n in view["nodes"]}
    assert ids == {"n1", "n2"}
    assert len(view["edges"]) == 1
    assert view["edges"][0]["source"] == "n1"
    assert view["edges"][0]["target"] == "n2"
    assert view["edges"][0]["edge_type"] == "direct_injection"
    assert view["edges"][0]["is_adversarial"] is True


def test_scoped_to_scan_id_ignores_other_scans():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "a1", scan_id="scan-1")
    _add_trace_node(backend, "a2", scan_id="scan-2")

    view = build_graph_view(backend, "scan-1")
    assert [n["id"] for n in view["nodes"]] == ["a1"]


def test_excludes_static_surface_nodes_without_node_type():
    """kind="tool" nodes from persist_structural_graph carry no node_type —
    they're a separate, unconnected surface (see module docstring)."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "runtime1", node_type="tool_call")
    backend.add_node(
        "static1", scan_id="scan-1", kind="tool", name="read_file", evidence="possible"
    )

    view = build_graph_view(backend, "scan-1")
    assert [n["id"] for n in view["nodes"]] == ["runtime1"]


def test_excludes_edges_that_cross_out_of_the_runtime_node_set():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1", node_type="tool_call")
    backend.add_node("static1", scan_id="scan-1", kind="tool", name="read_file")
    # An edge pointing at a non-runtime node should never appear (shouldn't
    # exist in practice, but the exporter must not crash or leak it either).
    backend.add_edge("n1", "static1", edge_type="normal_flow")

    view = build_graph_view(backend, "scan-1")
    assert view["edges"] == []


def test_empty_scan_still_produces_a_valid_empty_view():
    backend = FakeGraphBackend()
    view = build_graph_view(backend, "scan-does-not-exist")
    assert view["nodes"] == []
    assert view["findings"] == []


def test_creates_parent_directories(tmp_path):
    backend = FakeGraphBackend()
    _add_trace_node(backend, "n1")
    out_path = tmp_path / "nested" / "dir" / "graph.json"
    out = export_graph_json(backend, "scan-1", out_path)
    assert out.exists()


def test_defaults_when_optional_attrs_are_missing():
    """A node written without color/shape/label (e.g. by a future caller)
    should still export cleanly with sane fallbacks, not crash."""
    backend = FakeGraphBackend()
    backend.add_node("n1", scan_id="scan-1", node_type="tool_call")

    view = build_graph_view(backend, "scan-1")
    node = view["nodes"][0]
    assert node["color"]
    assert node["shape"] == "dot"
    assert node["label"]  # falls back to node id prefix


def test_dangerous_outcome_node_gets_the_bright_sink_color():
    backend = FakeGraphBackend()
    backend.add_node(
        "sink::x",
        scan_id="scan-1",
        node_type="dangerous",
        color="#111111",  # near-black — would be invisible on the dark canvas
    )
    view = build_graph_view(backend, "scan-1")
    assert view["nodes"][0]["color"] == "#FF2E63"


def test_odd_content_round_trips_faithfully_through_json():
    """Node/edge content is attacker-controlled by construction. Since the
    payload is plain JSON (not embedded in an HTML <script> tag any more),
    json.dumps' own escaping is sufficient — this just proves content
    survives the round trip unmangled, e.g. content literally containing
    '</script>' shouldn't be altered."""
    backend = FakeGraphBackend()
    weird_content = "hi</script><script>alert(1)</script>"
    _add_trace_node(backend, "n1", node_type="tool_call", content=weird_content)

    view = build_graph_view(backend, "scan-1")
    assert view["nodes"][0]["content"] == weird_content


# ---------------------------------------------------------------------------
# Findings — from real AttackPaths, and the sink-backward-walk fallback
# ---------------------------------------------------------------------------


def _attack_path(node_ids, *, severity="high", score=3, confidence="high", description="a path"):
    """A minimal stand-in for pwngraph.types.AttackPath — build_graph_view
    only ever touches .events[].event_id/.name/.node_type, .severity(.value/
    .score), .confidence, so a lightweight namespace avoids pulling in the
    fuzzer/oracle stack this module has no other reason to depend on."""
    from types import SimpleNamespace

    sev = SimpleNamespace(value=severity, score=score)
    events = [SimpleNamespace(event_id=nid, name=nid, node_type=None) for nid in node_ids]
    return SimpleNamespace(
        events=events, severity=sev, confidence=confidence, description=description
    )


def test_findings_built_from_real_dangerous_paths_when_provided():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")
    _add_trace_node(backend, "t1", node_type="tool_call")
    _add_trace_node(backend, "sink::t1", node_type="dangerous")

    path = _attack_path(["u1", "t1", "sink::t1"], severity="critical", score=4, confidence="high")
    view = build_graph_view(backend, "scan-1", dangerous_paths=[path])
    findings = view["findings"]

    assert len(findings) == 1
    f = findings[0]
    assert f["i"] == 0
    assert f["severity"] == "critical"
    assert f["confidence"] == "high"
    assert f["nodes"] == ["u1", "t1", "sink::t1"]


def test_findings_from_paths_drops_event_ids_outside_this_scan():
    """A path event_id that isn't one of this scan's runtime nodes (shouldn't
    happen in practice, but the exporter must not leak a bogus id) is
    filtered rather than passed through verbatim."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")

    path = _attack_path(["u1", "not-a-real-node"])
    view = build_graph_view(backend, "scan-1", dangerous_paths=[path])
    assert view["findings"][0]["nodes"] == ["u1"]


def test_findings_from_paths_are_ranked_by_severity():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")
    _add_trace_node(backend, "u2", node_type="user_input")

    low = _attack_path(["u1"], severity="low", score=1)
    critical = _attack_path(["u2"], severity="critical", score=4)
    view = build_graph_view(backend, "scan-1", dangerous_paths=[low, critical])
    findings = view["findings"]

    assert [f["severity"] for f in findings] == ["critical", "low"]
    assert [f["i"] for f in findings] == [0, 1]


def test_findings_from_paths_excludes_low_confidence_paths():
    """A dangerous *path* GraphBuilder counted (find_dangerous_paths' "N
    unique paths" log line) is not always a reportable *finding* —
    PwnGraph._synthesize_findings only turns confidence=="high" paths into
    persisted Findings. A live scan's own graph.json must apply the same
    gate, or it disagrees with the report sitting right next to it (e.g.
    "7 unique paths" / "6 findings" in the scan log, but graph.json claiming
    7)."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")
    _add_trace_node(backend, "u2", node_type="user_input")

    high_conf = _attack_path(["u1"], severity="critical", confidence="high")
    low_conf = _attack_path(["u2"], severity="critical", confidence="low")
    view = build_graph_view(backend, "scan-1", dangerous_paths=[high_conf, low_conf])

    assert len(view["findings"]) == 1
    assert view["findings"][0]["nodes"] == ["u1"]


def test_findings_fallback_derives_from_sink_nodes_when_no_paths_given():
    """No dangerous_paths (a live API read, or the standalone `pwngraph
    graph` re-export case) — findings are reconstructed by walking backward
    from each dangerous node."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")
    _add_trace_node(backend, "t1", node_type="tool_call")
    backend.add_node(
        "sink::t1",
        scan_id="scan-1",
        node_type="dangerous",
        name="DangerousOutcome",
        label="DANGER",
        color="#111111",
        shape="star",
        is_adversarial=True,
        outcome_severity="critical",
        confidence="high",
        description="fallback-derived",
    )
    backend.add_edge("u1", "t1", edge_type="direct_injection")
    backend.add_edge("t1", "sink::t1", edge_type="data_exfil")

    view = build_graph_view(backend, "scan-1")  # no dangerous_paths
    findings = view["findings"]

    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["confidence"] == "high"
    assert f["nodes"] == ["u1", "t1", "sink::t1"]


def test_findings_fallback_dedupes_structurally_identical_chains():
    """trials > 1 re-delivering the same payload produces a fresh sink node
    per successful trial — same chain shape, different event ids. The
    fallback must collapse these to one representative, keeping the
    highest-severity instance, the same way a live scan's own path-finding
    (GraphBuilder.find_dangerous_paths) already dedupes by signature."""
    backend = FakeGraphBackend()

    # Trial 1: low severity.
    _add_trace_node(backend, "u1", node_type="user_input", name="user")
    _add_trace_node(backend, "t1", node_type="tool_call", name="read_file")
    backend.add_node(
        "sink::t1",
        scan_id="scan-1",
        node_type="dangerous",
        name="DangerousOutcome",
        outcome_severity="low",
        confidence="low",
    )
    backend.add_edge("u1", "t1")
    backend.add_edge("t1", "sink::t1")

    # Trial 2: identical shape (user_input -> tool_call "read_file" ->
    # dangerous), different node ids, higher severity.
    _add_trace_node(backend, "u2", node_type="user_input", name="user")
    _add_trace_node(backend, "t2", node_type="tool_call", name="read_file")
    backend.add_node(
        "sink::t2",
        scan_id="scan-1",
        node_type="dangerous",
        name="DangerousOutcome",
        outcome_severity="critical",
        confidence="high",
    )
    backend.add_edge("u2", "t2")
    backend.add_edge("t2", "sink::t2")

    view = build_graph_view(backend, "scan-1")
    findings = view["findings"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_findings_fallback_keeps_distinct_chain_shapes_separate():
    """Different tool names are a genuinely different chain — must not be
    collapsed together just because both are single-hop."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input", name="user")
    _add_trace_node(backend, "t1", node_type="tool_call", name="read_file")
    backend.add_node(
        "sink::t1", scan_id="scan-1", node_type="dangerous", outcome_severity="high"
    )
    backend.add_edge("u1", "t1")
    backend.add_edge("t1", "sink::t1")

    _add_trace_node(backend, "u2", node_type="user_input", name="user")
    _add_trace_node(backend, "t2", node_type="tool_call", name="send_email")
    backend.add_node(
        "sink::t2", scan_id="scan-1", node_type="dangerous", outcome_severity="critical"
    )
    backend.add_edge("u2", "t2")
    backend.add_edge("t2", "sink::t2")

    view = build_graph_view(backend, "scan-1")
    assert len(view["findings"]) == 2


def _chain(backend, *, user="u1", tool_node="t1", tool_name="read_file", payload_id="p1",
           severity="critical", scan_id="scan-1"):
    _add_trace_node(backend, user, scan_id=scan_id, node_type="user_input")
    _add_trace_node(backend, tool_node, scan_id=scan_id, node_type="tool_call", name=tool_name)
    backend.add_node(
        f"sink::{tool_node}",
        scan_id=scan_id,
        node_type="dangerous",
        name="DangerousOutcome",
        outcome_severity=severity,
        confidence="high",
        payload_id=payload_id,
    )
    backend.add_edge(user, tool_node)
    backend.add_edge(tool_node, f"sink::{tool_node}")


def test_findings_from_report_reconstructs_chain_by_payload_id():
    """report_findings, when supplied, takes priority over the sink-walk
    fallback — the exact same set the Report/Findings tabs show, joined back
    to the graph by payload_id (see pwngraph.attackpath.chain_for_payload)."""
    backend = FakeGraphBackend()
    _chain(backend, payload_id="p1", severity="critical")

    view = build_graph_view(
        backend,
        "scan-1",
        report_findings=[
            {"finding_id": "f1", "payload_id": "p1", "severity": "critical", "title": "Hijack"}
        ],
    )
    findings = view["findings"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["confidence"] == "high"
    assert findings[0]["label"] == "Hijack"
    assert set(findings[0]["nodes"]) == {"u1", "t1", "sink::t1"}


def test_findings_from_report_skips_findings_with_no_matching_sink():
    """A finding whose payload_id no longer resolves to a sink (shouldn't
    happen in practice, but the graph must not crash or fabricate a chain)
    is dropped rather than shown with an empty/bogus node list."""
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")

    view = build_graph_view(
        backend,
        "scan-1",
        report_findings=[
            {"finding_id": "f1", "payload_id": "does-not-exist", "severity": "high"}
        ],
    )
    assert view["findings"] == []


def test_findings_from_report_ignored_when_empty_report_has_zero_findings():
    """An empty (but present) report_findings list means "this scan
    genuinely confirmed nothing" — must not fall back to the noisier
    sink-walk and show low-confidence echoes the report itself excluded."""
    backend = FakeGraphBackend()
    _chain(backend, payload_id="p1", severity="low")  # a sink exists…

    view = build_graph_view(backend, "scan-1", report_findings=[])  # …but the report says none
    assert view["findings"] == []


def test_findings_from_report_ranked_by_severity():
    backend = FakeGraphBackend()
    _chain(backend, user="u1", tool_node="t1", tool_name="read_file", payload_id="p1", severity="low")
    _chain(backend, user="u2", tool_node="t2", tool_name="send_email", payload_id="p2", severity="critical")

    view = build_graph_view(
        backend,
        "scan-1",
        report_findings=[
            {"finding_id": "f1", "payload_id": "p1", "severity": "low"},
            {"finding_id": "f2", "payload_id": "p2", "severity": "critical"},
        ],
    )
    assert [f["severity"] for f in view["findings"]] == ["critical", "low"]


def test_findings_fallback_empty_when_no_dangerous_nodes():
    backend = FakeGraphBackend()
    _add_trace_node(backend, "u1", node_type="user_input")
    view = build_graph_view(backend, "scan-1")
    assert view["findings"] == []


def test_dangerous_node_exports_severity_and_confidence():
    backend = FakeGraphBackend()
    backend.add_node(
        "sink::x",
        scan_id="scan-1",
        node_type="dangerous",
        outcome_severity="high",
        confidence="medium",
    )
    view = build_graph_view(backend, "scan-1")
    node = view["nodes"][0]
    assert node["severity"] == "high"
    assert node["confidence"] == "medium"
