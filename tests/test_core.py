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
        pg = PwnGraph(
            agent=built, seed=3, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient()
        )
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
        pg = PwnGraph(
            agent=built, seed=3, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient()
        )
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
        pg = PwnGraph(
            agent=built, seed=3, graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient()
        )
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


class _BrokenAgent:
    """An agent whose every turn fails, e.g. its model returns 404."""

    tools: list = []

    def invoke(self, *_a, **_k):
        raise RuntimeError("Error code: 404 - model_not_found")


def test_scan_aborts_when_every_baseline_run_fails():
    from pwngraph.core import TargetUnavailableError

    llm = FakeLLMClient()
    pg = PwnGraph(agent=_BrokenAgent(), graph_backend=FakeGraphBackend(), llm_client=llm)
    with pytest.raises(TargetUnavailableError, match="404 - model_not_found"):
        pg.scan(attacks="all", budget=10, baseline_runs=3, progress=False, authorized=True)
    # Not one adversarial run was attempted against the dead target.
    assert not [r for r in pg._run_records if r.adversarial]


def test_scan_continues_when_only_some_baseline_runs_fail():
    calls = {"n": 0}

    class _Flaky:
        tools: list = []

        def invoke(self, *_a, **_k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            return {"output": "ok"}

    pg = PwnGraph(agent=_Flaky(), graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
    pg.scan(
        attacks=["prompt_exfiltration"], budget=1, baseline_runs=2, progress=False, authorized=True
    )
    assert calls["n"] > 2


def test_scan_sends_exactly_the_budgeted_number_of_probes():
    """--budget N means N adaptive probes reach the agent, not 'up to N'."""
    import sys

    sys.path.insert(0, str(_LAB_AGENT_FILE.parent))
    try:
        import agent as lab_agent

        pg = PwnGraph(
            agent=lab_agent.build_agent(use_real_llm=False),
            seed=1,
            graph_backend=FakeGraphBackend(),
            llm_client=FakeLLMClient(),
        )
        pg.scan(attacks="all", budget=15, baseline_runs=2, progress=False, authorized=True)

        adversarial = [r for r in pg._run_records if r.adversarial]
        assert len(adversarial) == 15
        assert pg.nexus_state.iteration == 15
        assert pg.probe_stop_reason == ""
    finally:
        sys.path.remove(str(_LAB_AGENT_FILE.parent))
        sys.modules.pop("agent", None)


def test_early_stop_reports_why_fewer_probes_were_sent():
    pg = PwnGraph(agent=_FakeAgent(), graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient())
    pg.scan(
        attacks=["prompt_exfiltration"],
        budget=50,
        baseline_runs=1,
        progress=False,
        authorized=True,
        max_calls=4,
    )
    assert pg.nexus_state.iteration < 50
    assert "--max-calls" in pg.probe_stop_reason


def test_static_analysis_follows_a_delegating_adapter_to_the_tool_definitions(tmp_path):
    """An adapter that only calls the repo's factory has no tools in it — static
    analysis must read the files where the live tools are actually defined."""
    pytest.importorskip("langchain_core")
    import importlib.util
    import textwrap

    (tmp_path / "helpdesk.py").write_text(textwrap.dedent('''
            from langchain_core.tools import tool

            @tool
            def lookup_ticket(ticket_id: str) -> str:
                """Look up a support ticket."""
                return ticket_id

            @tool
            def send_email(to: str, body: str) -> str:
                """Send an email."""
                return "sent"

            class Agent:
                tools = [lookup_ticket, send_email]

                def invoke(self, inputs, config=None):
                    return {"output": "ok"}

            def make_agent():
                return Agent()
            '''))
    adapter = tmp_path / "adapter.py"
    adapter.write_text("import helpdesk\n\ndef build_agent():\n    return helpdesk.make_agent()\n")
    import sys

    sys.path.insert(0, str(tmp_path))
    try:
        spec = importlib.util.spec_from_file_location("deleg_adapter", adapter)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pg = PwnGraph(
            agent=module.build_agent(), graph_backend=FakeGraphBackend(), llm_client=FakeLLMClient()
        )
        graph = pg.run_static_analysis(f"{adapter}:build_agent")
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("helpdesk", None)

    assert graph is not None
    names = {n.name for n in graph.nodes.values()}
    assert {"lookup_ticket", "send_email"} <= names
