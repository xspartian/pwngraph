"""Connector — attaches PwnGraph to a target agent and enumerates its tools."""

from typing import Any

from pwngraph.connector.base import Connector, ToolSpec
from pwngraph.connector.langchain import LangChainConnector
from pwngraph.connector.langgraph import LangGraphConnector, _is_langgraph

__all__ = [
    "Connector", "ToolSpec",
    "LangChainConnector", "LangGraphConnector",
    "make_connector",
]


def make_connector(agent: Any, **kwargs: Any) -> Connector:
    """Auto-detect the right connector for *agent*.

    Priority:
      1. LangGraph compiled graph  (has ``.get_graph()`` + ``.stream()``)
      2. LangChain AgentExecutor   (has ``.invoke()`` / ``.ainvoke()``)
    """
    if agent is not None and _is_langgraph(agent):
        return LangGraphConnector(agent, **{k: v for k, v in kwargs.items()
                                            if k in ("retries",)})
    return LangChainConnector(agent, **kwargs)
