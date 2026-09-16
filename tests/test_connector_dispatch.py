"""Tests for pwngraph.connector.make_connector — auto-detection dispatch.

Each fake is shaped to satisfy exactly one connector's duck-type check, so a
misrouted dispatch shows up as the wrong TypeError or the wrong connector
class, not a silent pass.
"""

from __future__ import annotations

import pytest

from pwngraph.connector import LangChainConnector, make_connector


class _FakeAgentExecutor:
    """Satisfies only LangChainConnector's check: has .invoke()."""

    def __init__(self):
        self.tools = []

    def invoke(self, payload, config=None):
        return {"output": "ok"}


class _FakeLangGraph:
    """Satisfies only LangGraphConnector's check: .get_graph()/.stream()."""

    def get_graph(self):
        return type("G", (), {"nodes": {}})()

    def stream(self):
        return iter(())


def test_dispatches_langchain_agent_executor_to_langchain_connector():
    connector = make_connector(_FakeAgentExecutor())
    assert isinstance(connector, LangChainConnector)


def test_dispatches_langgraph_to_langgraph_connector():
    from pwngraph.connector import LangGraphConnector

    connector = make_connector(_FakeLangGraph())
    assert isinstance(connector, LangGraphConnector)


def test_object_matching_nothing_falls_through_to_langchain_and_raises():
    with pytest.raises(TypeError):
        make_connector(object())
