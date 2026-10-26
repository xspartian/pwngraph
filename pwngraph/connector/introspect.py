"""Find a live agent's tool objects and the source files that implement them.

Shared by ``pwngraph init``'s validator (which rejects adapters whose tools are
written inside adapter.py) and by static analysis (which must read the files
that really define the tools — an adapter usually just imports and calls the
repository's own factory, so the adapter file alone contains no tools).
"""

from __future__ import annotations

import inspect
from typing import Any


def tool_objects(agent: Any) -> list[Any]:
    """The live tool objects behind an agent, wherever the framework keeps them:
    ``.tools`` on the agent or its inner ``.agent`` (AgentExecutor, the
    plain-Python shim), or the ToolNodes of a compiled LangGraph graph."""
    found: list[Any] = []
    for obj in (agent, getattr(agent, "agent", None)):
        tools = getattr(obj, "tools", None) if obj is not None else None
        if tools and not callable(tools):
            found.extend(tools.values() if isinstance(tools, dict) else tools)
    try:
        nodes = agent.get_graph().nodes
    except Exception:  # noqa: BLE001
        nodes = {}
    for node in getattr(nodes, "values", lambda: [])():
        data = getattr(node, "data", None)
        for attr in ("tools_by_name", "tools"):
            raw = getattr(data, attr, None)
            if raw and not callable(raw):
                found.extend(raw.values() if isinstance(raw, dict) else raw)
                break
    return found


def tool_source_file(tool: Any) -> str | None:
    """Source file of the code that actually runs when the tool is called."""
    for attr in ("func", "coroutine", "_fn", "fn"):
        fn = getattr(tool, attr, None)
        if callable(fn):
            try:
                return inspect.getsourcefile(inspect.unwrap(fn))
            except (TypeError, ValueError):
                continue
    run = getattr(type(tool), "_run", None)
    if run is not None:
        try:
            return inspect.getsourcefile(run)
        except (TypeError, ValueError):
            return None
    if callable(tool) and not isinstance(tool, type):
        try:
            return inspect.getsourcefile(inspect.unwrap(tool))
        except (TypeError, ValueError):
            return None
    return None
