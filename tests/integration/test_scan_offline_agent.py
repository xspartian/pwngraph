"""End-to-end integration test: a full PwnGraph scan against the deliberately
vulnerable offline example agent in examples/hr_agent.

This exercises the whole pipeline for real — Connector -> Fuzzer -> Tracer ->
BehavioralOracle -> GraphBuilder -> Reporter — the same path documented in
CONTRIBUTING.md ("pytest" runs this; "pytest -m 'not integration'" skips it).
It requires the ``langchain`` extra (LangChainConnector duck-types against the
agent, but the example itself prefers a real ``@tool`` decorator when
available) but never calls an LLM: the example agent has a built-in offline
reasoning engine, so no API key or network access is needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from _fake_backend import FakeGraphBackend
from _fake_llm_client import FakeLLMClient

pytestmark = pytest.mark.integration

_EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples" / "hr_agent"


@pytest.fixture
def hr_agent_module():
    sys.path.insert(0, str(_EXAMPLES_DIR))
    try:
        import agent as hr_agent  # noqa: PLC0415 — deliberately lazy, path-dependent import

        yield hr_agent
    finally:
        sys.path.remove(str(_EXAMPLES_DIR))
        sys.modules.pop("agent", None)
        sys.modules.pop("data", None)


def test_full_scan_against_offline_hr_agent_finds_at_least_one_finding(hr_agent_module):
    from pwngraph.core import PwnGraph

    built = hr_agent_module.build_agent()
    pg = PwnGraph(agent=built, seed=0, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())

    paths = pg.scan(
        attacks=["tool_poisoning", "prompt_exfiltration", "memory_poisoning"],
        budget=4,
        baseline_runs=2,
        progress=False,
        authorized=True,
    )

    assert pg.events, "scan should have produced trace events"
    assert pg.asr.get("overall", {}).get("trials", 0) > 0
    # The demo agent is deliberately vulnerable — expect at least one hit.
    assert len(paths) >= 1
    assert len(pg.findings) >= 1
    assert all(f.cvss_score is not None for f in pg.findings)


def test_scan_adapts_and_respects_budget(hr_agent_module):
    """End to end: NEXUS's adaptive probes stay within budget, the attack
    state is populated from real observations, and the Builder/Reporter
    pipeline produces a graph from them."""
    from pwngraph.core import PwnGraph

    built = hr_agent_module.build_agent()
    pg = PwnGraph(agent=built, seed=0, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())

    pg.scan(
        attacks=["tool_poisoning", "prompt_exfiltration", "memory_poisoning"],
        baseline_runs=2,
        nexus_level=2,
        budget=6,
        progress=False,
        authorized=True,
    )

    assert pg.nexus_state is not None
    assert pg.nexus_state.iteration <= 6
    assert len(pg.nexus_state.payload_history) == pg.nexus_state.iteration
    # Every adversarial probe NEXUS ran should have produced an Observation.
    assert len(pg.nexus_state.observations) == pg.nexus_state.iteration
    assert pg.events, "scan should have produced trace events"
    assert pg.asr.get("overall", {}).get("trials", 0) == pg.nexus_state.iteration


def test_scan_requires_explicit_authorization(hr_agent_module):
    """NEXUS probes autonomously with no human between steps — scan() must
    refuse to run without an explicit authorized=True acknowledgment."""
    from pwngraph.core import PwnGraph

    built = hr_agent_module.build_agent()
    pg = PwnGraph(agent=built, seed=0, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())

    with pytest.raises(PermissionError, match="authorized"):
        pg.scan(attacks=["tool_poisoning"], budget=3, progress=False)


def test_report_writes_all_expected_artifacts(hr_agent_module, tmp_path):
    from pwngraph.core import PwnGraph

    built = hr_agent_module.build_agent()
    pg = PwnGraph(agent=built, seed=1, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
    pg.scan(
        attacks=["tool_poisoning"],
        budget=3,
        baseline_runs=1,
        progress=False,
        authorized=True,
    )

    out_dir = pg.report(tmp_path)

    assert out_dir == tmp_path
    for name in ("trace.json", "asr.json", "findings.sarif", "delivery.json", "graph.json"):
        assert (tmp_path / name).exists(), f"missing {name}"

    # No HTML is written any more — the findings write-up lives in
    # `pwngraph serve`, read back out of the backend (pwngraph.report_store).
    assert not (tmp_path / "report.html").exists()

    assert pg.graph_path == tmp_path / "graph.json"
    import json

    graph_payload = json.loads(pg.graph_path.read_text(encoding="utf-8"))
    assert graph_payload["scan_id"]
    assert graph_payload["nodes"]

    grade = pg.risk_grade()
    assert grade["grade"] in "ABCDF"
    assert 0 <= grade["score"] <= 100
