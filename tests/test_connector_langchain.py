"""Tests for pwngraph.connector.langchain — LangChainConnector against a fake,
duck-typed agent. LangChainConnector never imports the real langchain package
at module scope (only inside optional/lazy paths), so these are pure unit
tests: no LangChain installation required.
"""

from __future__ import annotations

import pytest

from pwngraph.connector.langchain import LangChainConnector
from pwngraph.fuzzer.payload import AttackClass, Payload
from pwngraph.tracer.tracer import Tracer


class _FakeTool:
    def __init__(self, name, description="", run_fn=None):
        self.name = name
        self.description = description
        self._run = run_fn or (lambda *a, **k: f"{name}-result")


class _FakeAgent:
    def __init__(self, tools, input_keys=None, output="final answer"):
        self.tools = tools
        self.input_keys = input_keys or ["input"]
        self._output = output
        self.last_call = None

    def invoke(self, payload, config=None):
        self.last_call = (payload, config)
        return {"output": self._output}


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


def test_rejects_object_without_invoke_or_ainvoke():
    with pytest.raises(TypeError):
        LangChainConnector(object())


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


def test_list_tools_returns_specs_with_inferred_tags():
    agent = _FakeAgent([_FakeTool("send_email", "Send an email to a recipient")])
    connector = LangChainConnector(agent)

    specs = connector.list_tools()

    assert len(specs) == 1
    assert specs[0].name == "send_email"
    assert "email" in specs[0].tags
    assert specs[0].is_action_sink is True


def test_list_tools_is_cached():
    agent = _FakeAgent([_FakeTool("read_file")])
    connector = LangChainConnector(agent)
    first = connector.list_tools()
    agent.tools.append(_FakeTool("extra_tool"))  # mutate after first call
    second = connector.list_tools()
    assert first is second
    assert len(second) == 1


def test_target_name_reports_tool_count():
    agent = _FakeAgent([_FakeTool("a"), _FakeTool("b")])
    connector = LangChainConnector(agent)
    assert "2 tools" in connector.target_name()


# ---------------------------------------------------------------------------
# Input key detection
# ---------------------------------------------------------------------------


def test_detects_preferred_input_key_from_agent():
    agent = _FakeAgent([], input_keys=["chat_history", "question"])
    connector = LangChainConnector(agent)
    assert connector._input_key == "question"


def test_falls_back_to_input_when_no_input_keys():
    agent = _FakeAgent([], input_keys=[])
    connector = LangChainConnector(agent)
    assert connector._input_key == "input"


def test_explicit_input_key_overrides_detection():
    agent = _FakeAgent([], input_keys=["question"])
    connector = LangChainConnector(agent, input_key="custom_field")
    assert connector._input_key == "custom_field"


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


def test_invoke_builds_input_dict_and_returns_flattened_output():
    agent = _FakeAgent([], output={"type": "text", "text": "hello there"})
    connector = LangChainConnector(agent)
    tracer = Tracer()
    tracer.start_run("hi")

    result = connector.invoke("hi", tracer=tracer)
    tracer.end_run()

    assert result == "hello there"
    payload_sent, config = agent.last_call
    assert payload_sent == {"input": "hi"}
    assert "callbacks" in config


def test_invoke_fills_extra_required_keys_with_empty_defaults():
    agent = _FakeAgent([], input_keys=["input", "chat_history"])
    connector = LangChainConnector(agent)
    tracer = Tracer()
    tracer.start_run("hi")

    connector.invoke("hi", tracer=tracer)
    tracer.end_run()

    payload_sent, _ = agent.last_call
    assert payload_sent == {"input": "hi", "chat_history": []}


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


def test_recovers_from_a_transient_error(monkeypatch):
    calls = {"n": 0}

    def flaky_invoke(payload, config=None):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("503 Service Unavailable")
        return {"output": "ok"}

    agent = _FakeAgent([])
    agent.invoke = flaky_invoke
    connector = LangChainConnector(agent, retries=2)
    monkeypatch.setattr("pwngraph.connector.langchain.time.sleep", lambda *_: None)

    tracer = Tracer()
    tracer.start_run("hi")
    result = connector.invoke("hi", tracer=tracer)
    tracer.end_run()

    assert result == "ok"
    assert calls["n"] == 2


def test_non_transient_error_raises_without_retry():
    def bad_invoke(payload, config=None):
        raise ValueError("boom")

    agent = _FakeAgent([])
    agent.invoke = bad_invoke
    connector = LangChainConnector(agent)

    tracer = Tracer()
    tracer.start_run("hi")
    with pytest.raises(ValueError):
        connector.invoke("hi", tracer=tracer)
    tracer.end_run()


# ---------------------------------------------------------------------------
# Tool poisoning
# ---------------------------------------------------------------------------


def test_install_and_restore_poisoned_tools():
    tool = _FakeTool("web_search", run_fn=lambda *a, **k: "original")
    agent = _FakeAgent([tool])
    connector = LangChainConnector(agent)
    payload = Payload(
        attack_class=AttackClass.TOOL_POISONING,
        delivery_input="x",
        injection_text="y",
        canary="PWN-11112222",
        metadata={"target_tool": "web_search", "poisoned_output": "POISONED"},
    )

    restores = connector._install_poisoned_tools(payload)
    assert tool._run() == "POISONED"

    for t, attr, original in restores:
        setattr(t, attr, original)
    assert tool._run() == "original"


def test_poisoning_unknown_target_tool_is_a_no_op():
    tool = _FakeTool("web_search", run_fn=lambda *a, **k: "original")
    agent = _FakeAgent([tool])
    connector = LangChainConnector(agent)
    payload = Payload(
        attack_class=AttackClass.TOOL_POISONING,
        delivery_input="x",
        injection_text="y",
        canary="PWN-33334444",
        metadata={"target_tool": "does_not_exist", "poisoned_output": "POISONED"},
    )

    restores = connector._install_poisoned_tools(payload)

    assert restores == []
    assert tool._run() == "original"
