"""LangGraph connector — adapts compiled LangGraph graphs for pwngraph scanning.

LangGraph agents are compiled ``StateGraph`` objects.  Unlike AgentExecutor,
they communicate through message lists (``{"messages": [...]}``) and their
tools are registered on graph nodes rather than on the executor itself.

This connector:
1. Detects LangGraph compiled graphs by duck-typing (``__class__.__name__``
   contains 'CompiledGraph' or the object has ``.get_graph()``).
2. Discovers tools by inspecting node runnables in the graph's schema.
3. Invokes via ``graph.invoke({"messages": [HumanMessage(text)]})`` and
   translates the output message list into a final-answer string.
4. Shares the retry / tool-poisoning / tracer-wiring logic from the base
   ``LangChainConnector`` to avoid duplicating that code.

Requires: ``langgraph`` and ``langchain_core`` in the environment.
"""

from __future__ import annotations

import logging
from typing import Any

from pwngraph.connector.base import Connector, ToolSpec
from pwngraph.util import flatten_text

log = logging.getLogger(__name__)

_TRANSIENT_MARKERS = (
    "429",
    "resource_exhausted",
    "rate limit",
    "rate_limit",
    "503",
    "500",
    "overloaded",
    "temporarily",
    "unavailable",
    "timeout",
)


def _is_langgraph(obj: Any) -> bool:
    cls_name = type(obj).__name__
    if "CompiledGraph" in cls_name or "CompiledStateGraph" in cls_name:
        return True
    return hasattr(obj, "get_graph") and hasattr(obj, "stream")


class LangGraphConnector(Connector):
    """Adapts a compiled LangGraph ``StateGraph`` for pwngraph."""

    def __init__(self, graph: Any, retries: int = 2) -> None:
        if not _is_langgraph(graph):
            raise TypeError(
                f"LangGraphConnector expects a compiled LangGraph graph; "
                f"got {type(graph).__name__}. "
                f"Use LangChainConnector for AgentExecutor objects."
            )
        self.graph = graph
        self._retries = retries
        self._tools_cache: list[ToolSpec] | None = None

    # ------------------------------------------------------------------ #
    # Connector API
    # ------------------------------------------------------------------ #

    def list_tools(self) -> list[ToolSpec]:
        if self._tools_cache is not None:
            return self._tools_cache
        self._tools_cache = self._discover_tools()
        if not self._tools_cache:
            log.warning(
                "LangGraphConnector: no tools discovered. Tool nodes may use "
                "ToolNode with bound tools — consider listing them manually by "
                "passing a pre-built ToolSpec list to the connector."
            )
        return self._tools_cache

    def invoke(self, user_input: str, tracer: Any, payload: Any | None = None) -> str:
        # Tool poisoning: patch before invoke, restore after. Gated on the
        # mechanism (poisoned_output metadata present), not a specific
        # attack_class — see the identical comment in connector/langchain.py.
        restores: list[tuple[Any, str, Any]] = []
        if (
            payload is not None
            and getattr(payload, "metadata", None)
            and payload.metadata.get("poisoned_output")
        ):
            restores = self._install_poisoned_tools(payload)

        try:
            callbacks = tracer.langchain_callbacks()
            result = self._invoke_with_retry(user_input, callbacks)
            return flatten_text(self._extract_output(result))
        finally:
            for tool, attr, original in restores:
                setattr(tool, attr, original)

    def target_name(self) -> str:
        return f"LangGraph {type(self.graph).__name__} ({len(self.list_tools())} tools)"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _invoke_with_retry(self, user_input: str, callbacks: list[Any]) -> Any:
        import time

        try:
            from langchain_core.messages import HumanMessage
        except ImportError as e:
            raise ImportError("langchain_core is required for LangGraphConnector") from e

        payload_in = {"messages": [HumanMessage(content=user_input)]}
        config = {"callbacks": callbacks}

        delay = 2.0
        for attempt in range(self._retries + 1):
            try:
                return self.graph.invoke(payload_in, config=config)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                transient = any(m in msg for m in _TRANSIENT_MARKERS)
                if transient and attempt < self._retries:
                    wait = delay * (2**attempt)
                    log.warning(
                        "Transient LangGraph error (%s); retry %d/%d in %.0fs",
                        exc.__class__.__name__,
                        attempt + 1,
                        self._retries,
                        wait,
                    )
                    time.sleep(wait)
                    continue
                raise

    @staticmethod
    def _extract_output(result: Any) -> str:
        """Pull the final assistant text from a LangGraph message-list result."""
        try:
            from langchain_core.messages import AIMessage
        except ImportError:
            AIMessage = None  # type: ignore[assignment,misc]

        if isinstance(result, dict):
            msgs = result.get("messages", [])
            # Walk messages in reverse to find the last AI reply.
            for msg in reversed(msgs):
                if AIMessage and isinstance(msg, AIMessage):
                    return flatten_text(getattr(msg, "content", str(msg)))
                if (
                    hasattr(msg, "content")
                    and hasattr(msg, "type")
                    and getattr(msg, "type", "") in ("ai", "AIMessage")
                ):
                    return flatten_text(msg.content)
            # Fallback: last message
            if msgs:
                return flatten_text(getattr(msgs[-1], "content", str(msgs[-1])))
        return flatten_text(result)

    def _discover_tools(self) -> list[ToolSpec]:
        """Walk the graph's node map looking for ToolNode / bound-tool lists."""
        from pwngraph.connector.langchain import _infer_tags, _tool_schema

        specs: list[ToolSpec] = []
        seen: set[str] = set()

        # LangGraph 0.2+: graph.get_graph().nodes is a dict of NodeSpec
        try:
            g = self.graph.get_graph()
            nodes = getattr(g, "nodes", {})
        except Exception:  # noqa: BLE001
            nodes = {}

        for _node_id, node in nodes.items():
            runnable = getattr(node, "data", None)
            if runnable is None:
                continue
            # ToolNode stores its tools in .tools or .tools_by_name
            for attr in ("tools", "tools_by_name"):
                raw = getattr(runnable, attr, None)
                if not raw:
                    continue
                items = raw.values() if isinstance(raw, dict) else raw
                for t in items:
                    name = getattr(t, "name", None) or type(t).__name__
                    if name in seen:
                        continue
                    seen.add(name)
                    desc = getattr(t, "description", "") or ""
                    specs.append(
                        ToolSpec(
                            name=name,
                            description=desc,
                            tool_schema=_tool_schema(t),
                            tags=_infer_tags(name, desc),
                        )
                    )

        # Fallback: agent node may have llm.bind_tools() kwargs
        if not specs:
            try:
                from pwngraph.connector.langchain import LangChainConnector

                dummy = LangChainConnector.__new__(LangChainConnector)
                dummy.agent = self.graph
                dummy._warned_no_tools = True
                dummy._tools_cache = None
                specs = dummy._bound_tool_specs()
            except Exception:  # noqa: BLE001
                pass

        return specs

    def _install_poisoned_tools(self, payload: Any) -> list[tuple[Any, str, Any]]:
        """Patch target tool(s) with poisoned output for this turn."""
        restores: list[tuple[Any, str, Any]] = []
        target_name = payload.metadata.get("target_tool")
        poisoned = payload.metadata.get("poisoned_output", "")

        def _sync(*_a: Any, **_k: Any) -> str:
            return poisoned

        async def _async(*_a: Any, **_k: Any) -> str:
            return poisoned

        for spec_tool in self._all_tools():
            if getattr(spec_tool, "name", None) != target_name:
                continue
            for attr, fn in (
                ("_run", _sync),
                ("func", _sync),
                ("_arun", _async),
                ("coroutine", _async),
            ):
                if getattr(spec_tool, attr, None) is not None:
                    restores.append((spec_tool, attr, getattr(spec_tool, attr)))
                    setattr(spec_tool, attr, fn)
            break
        return restores

    def _all_tools(self) -> list[Any]:
        """Collect raw tool objects from all ToolNodes for poisoning."""
        tools: list[Any] = []
        try:
            g = self.graph.get_graph()
            for _node_id, node in getattr(g, "nodes", {}).items():
                runnable = getattr(node, "data", None)
                if runnable is None:
                    continue
                for attr in ("tools", "tools_by_name"):
                    raw = getattr(runnable, attr, None)
                    if not raw:
                        continue
                    items = list(raw.values()) if isinstance(raw, dict) else list(raw)
                    tools.extend(items)
        except Exception:  # noqa: BLE001
            pass
        return tools
