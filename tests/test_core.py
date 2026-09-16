"""Tests for pwngraph.core.PwnGraph.run_static_analysis and its report() wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _fake_backend import FakeGraphBackend

from _fake_llm_client import FakeLLMClient

from pwngraph.core import PwnGraph
from pwngraph.static import EvidenceState

_LAB_AGENT_LOCATOR = "examples/lab_agent/agent.py:build_agent"
_LAB_AGENT_FILE = Path(__file__).resolve().parents[1] / "examples" / "lab_agent" / "agent.py"


class _FakeAgent:
    """Minimal object satisfying LangChainConnector's duck-type — enough to
    construct a real PwnGraph (and its normal __init__) without needing any
    agent framework installed."""

    def invoke(self, *_a, **_k):
        return {"output": "x"}


def test_run_static_analysis_module_style_target_returns_none():
    pg = PwnGraph(agent=_FakeAgent(), graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
    assert pg.run_static_analysis("my_pkg.agents:build_agent") is None
    assert pg.structural_graph is None


def test_run_static_analysis_missing_file_returns_none():
    pg = PwnGraph(agent=_FakeAgent(), graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
    assert pg.run_static_analysis("does/not/exist.py:build_agent") is None
    assert pg.structural_graph is None


def test_run_static_analysis_non_py_file_returns_none(tmp_path):
    not_py = tmp_path / "agent.txt"
    not_py.write_text("not python")
    pg = PwnGraph(agent=_FakeAgent(), graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
    assert pg.run_static_analysis(f"{not_py}:build_agent") is None


@pytest.mark.integration
def test_run_static_analysis_against_real_lab_agent_after_a_real_scan():
    import sys

    sys.path.insert(0, str(_LAB_AGENT_FILE.parent))
    try:
        import agent as lab_agent

        built = lab_agent.build_agent(use_real_llm=False)
        pg = PwnGraph(agent=built, seed=3, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
        pg.scan(
            attacks=["prompt_exfiltration"],
            budget=2,
            baseline_runs=2,
            progress=False,
            authorized=True,
        )

        graph = pg.run_static_analysis(_LAB_AGENT_LOCATOR)

        assert graph is not None
        assert graph is pg.structural_graph
        assert {n.name for n in graph.nodes.values()} == {
            "read_file",
            "web_search",
            "send_email",
            "http_post",
            "run_code",
        }
        # At least one tool exists in source but was never exercised by this
        # narrow a scan — the exact thing a runtime-only graph can't show.
        assert len(graph.possible_only) >= 1
    finally:
        sys.path.remove(str(_LAB_AGENT_FILE.parent))
        sys.modules.pop("agent", None)
        sys.modules.pop("data", None)


@pytest.mark.integration
def test_report_writes_evidence_ladder_json_when_static_analysis_ran(tmp_path):
    import sys

    sys.path.insert(0, str(_LAB_AGENT_FILE.parent))
    try:
        import agent as lab_agent

        built = lab_agent.build_agent(use_real_llm=False)
        pg = PwnGraph(agent=built, seed=3, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
        pg.scan(
            attacks=["prompt_exfiltration"],
            budget=2,
            baseline_runs=1,
            progress=False,
            authorized=True,
        )
        pg.run_static_analysis(_LAB_AGENT_LOCATOR)
        pg.report(tmp_path)

        evidence_file = tmp_path / "evidence_ladder.json"
        assert evidence_file.exists()

        summary = json.loads(evidence_file.read_text())
        assert summary["target_id"].endswith("agent.py:build_agent")
        assert len(summary["nodes"]) == 5
        assert all(n["evidence"] in {s.value for s in EvidenceState} for n in summary["nodes"])
    finally:
        sys.path.remove(str(_LAB_AGENT_FILE.parent))
        sys.modules.pop("agent", None)
        sys.modules.pop("data", None)


@pytest.mark.integration
def test_report_omits_evidence_ladder_json_when_static_analysis_never_ran(tmp_path):
    import sys

    sys.path.insert(0, str(_LAB_AGENT_FILE.parent))
    try:
        import agent as lab_agent

        built = lab_agent.build_agent(use_real_llm=False)
        pg = PwnGraph(agent=built, seed=3, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
        pg.scan(
            attacks=["prompt_exfiltration"],
            budget=1,
            baseline_runs=1,
            progress=False,
            authorized=True,
        )
        # Deliberately not calling run_static_analysis().
        pg.report(tmp_path)

        assert not (tmp_path / "evidence_ladder.json").exists()
    finally:
        sys.path.remove(str(_LAB_AGENT_FILE.parent))
        sys.modules.pop("agent", None)
        sys.modules.pop("data", None)
