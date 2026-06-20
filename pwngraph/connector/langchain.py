"""LangChain adapter — the Connector shipped in v1.

Supports any object that quacks like an ``AgentExecutor``:
    - exposes its tools (``.tools``, ``.agent.tools``, or a toolkit)
    - ``.invoke(...)`` (or async ``.ainvoke(...)``) taking a single text input

LangChain is imported lazily so the core package works without it for tests.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from pwngraph.connector.base import Connector, ToolSpec
from pwngraph.util import flatten_text

log = logging.getLogger(__name__)

# Substrings that mark a transient/retryable error (rate limits, overload).
_TRANSIENT_MARKERS = (
    "429", "resource_exhausted", "rate limit", "rate_limit", "quota",
    "503", "500", "overloaded", "temporarily", "unavailable", "timeout",
)
# Input keys that take a *message list* rather than a string (LangGraph etc.).
_MESSAGE_KEYS = ("messages", "history", "chat_history")


class LangChainConnector(Connector):
    """Wraps a LangChain ``AgentExecutor``-like object.

    Works with *any* LangChain agent, not just one shape: the input key the
    agent expects (``input`` / ``question`` / ``messages`` / ...) is auto-detected
    from the agent's own ``input_keys``. Pass ``input_key=`` to override.
    """

    # Text-style input keys we prefer when an agent declares several.
    _PREFERRED_KEYS = ("input", "question", "query", "text", "prompt")

    def __init__(self, agent: Any, input_key: str | None = None, retries: int = 2) -> None:
        self.agent = agent
        self._validate()
        self._retries = retries
        self._warned_no_tools = False
        self._tools_cache: list[ToolSpec] | None = None
        self._input_key = input_key or self._detect_input_key()
        log.info("LangChainConnector: using input key %r", self._input_key)

    # ------------------------------------------------------------------
    # Connector API
    # ------------------------------------------------------------------

    def list_tools(self) -> list[ToolSpec]:
        if self._tools_cache is not None:
            return self._tools_cache

        raw = self._raw_tools()
        specs = [
            ToolSpec(
                name=getattr(t, "name", t.__class__.__name__),
                description=getattr(t, "description", "") or "",
                tool_schema=_tool_schema(t),
                tags=_infer_tags(getattr(t, "name", ""), getattr(t, "description", "") or ""),
            )
            for t in raw
        ]
        # Tools attached via llm.bind_tools() aren't BaseTool objects; recover
        # their names/schemas (best-effort) so the fuzzer can still target them.
        if not specs:
            specs = self._bound_tool_specs()

        if not specs and not self._warned_no_tools:
            self._warned_no_tools = True
            log.warning(
                "No tools discovered on %s. If your agent HAS tools they may be "
                "bound via llm.bind_tools(), nested in a graph, or otherwise not "
                "exposed — PwnGraph cannot see them, so this scan tests almost "
                "nothing (tool-poisoning needs tools; only inline injection runs). "
                "An empty result here is NOT a clean bill of health.",
                type(self.agent).__name__,
            )

        self._tools_cache = specs
        return specs

    def invoke(
        self,
        user_input: str,
        tracer: Any,
        payload: Any | None = None,
    ) -> str:
        # Tool poisoning: replace the target tool's executor(s) for this turn.
        restores: list[tuple[Any, str, Any]] = []
        if payload is not None and getattr(payload, "attack_class", None) == "tool_poisoning":
            restores = self._install_poisoned_tools(payload)

        try:
            callbacks = tracer.langchain_callbacks()
            config = {"callbacks": callbacks}
            result = self._call_with_retry(self._build_input(user_input), config)
            return flatten_text(_extract_output(result))
        finally:
            for tool, attr, original in restores:
                setattr(tool, attr, original)

    def target_name(self) -> str:
        cls = self.agent.__class__.__name__
        return f"LangChain {cls} ({len(self.list_tools())} tools)"

    # ------------------------------------------------------------------
    # Input shaping
    # ------------------------------------------------------------------

    def _build_input(self, text: str) -> dict[str, Any]:
        """Build the input dict in the shape the agent expects.

        Handles message-based agents (LangGraph: ``{"messages": [...]}``) and
        fills any *other* required input keys with empty defaults so multi-input
        chains (e.g. ``input`` + ``chat_history``) don't error.
        """
        if self._input_key in _MESSAGE_KEYS:
            return {self._input_key: [("user", text)]}

        payload: dict[str, Any] = {self._input_key: text}
        for key in self._agent_input_keys():
            if key == self._input_key or key in payload:
                continue
            payload[key] = [] if key in _MESSAGE_KEYS else ""
        return payload

    # ------------------------------------------------------------------
    # Invocation (sync/async + retry)
    # ------------------------------------------------------------------

    def _call_with_retry(self, payload: dict, config: dict) -> Any:
        delay = 2.0
        for attempt in range(self._retries + 1):
            try:
                return self._run_agent(payload, config)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                transient = any(m in msg for m in _TRANSIENT_MARKERS)
                if transient and attempt < self._retries:
                    wait = delay * (2 ** attempt)
                    log.warning(
                        "Transient agent error (%s); retry %d/%d in %.0fs",
                        exc.__class__.__name__, attempt + 1, self._retries, wait,
                    )
                    time.sleep(wait)
                    continue
                raise

    def _run_agent(self, payload: dict, config: dict) -> Any:
        """Invoke the agent, using sync ``.invoke`` or falling back to async."""
        if hasattr(self.agent, "invoke"):
            return self.agent.invoke(payload, config=config)
        return asyncio.run(self.agent.ainvoke(payload, config=config))

    # ------------------------------------------------------------------
    # Tool discovery
    # ------------------------------------------------------------------

    def _raw_tools(self) -> list:
        """Return the agent's actual tool objects, checking common locations."""
        for obj in (self.agent, getattr(self.agent, "agent", None)):
            found = getattr(obj, "tools", None) if obj is not None else None
            if found:
                return list(found)
        toolkit = getattr(self.agent, "toolkit", None)
        if toolkit is not None and hasattr(toolkit, "get_tools"):
            try:
                found = toolkit.get_tools()
                if found:
                    return list(found)
            except Exception:  # noqa: BLE001
                pass
        return []

    def _bound_tool_specs(self) -> list[ToolSpec]:
        """Best-effort recovery of tools bound via ``llm.bind_tools()``.

        These are JSON schemas, not ``BaseTool`` objects, so they give the
        fuzzer names/descriptions (enough for indirect injection and sink
        classification) but cannot be tool-poisoned.
        """
        specs: list[ToolSpec] = []
        seen: set[str] = set()
        candidates = [
            getattr(self.agent, "llm", None),
            getattr(getattr(self.agent, "agent", None), "runnable", None),
            self.agent,
        ]
        for cand in candidates:
            kwargs = getattr(cand, "kwargs", None)
            if not isinstance(kwargs, dict):
                continue
            for tdef in kwargs.get("tools", []) or []:
                fn = tdef.get("function", tdef) if isinstance(tdef, dict) else {}
                name = fn.get("name") if isinstance(fn, dict) else None
                if not name or name in seen:
                    continue
                seen.add(name)
                desc = fn.get("description", "") if isinstance(fn, dict) else ""
                specs.append(ToolSpec(
                    name=name,
                    description=desc or "",
                    tool_schema=fn.get("parameters", {}) if isinstance(fn, dict) else {},
                    tags=_infer_tags(name, desc or ""),
                ))
        if specs:
            log.info("Recovered %d bound tool(s) from schemas (cannot be poisoned).", len(specs))
        return specs

    # ------------------------------------------------------------------
    # Validation / detection
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        if not (hasattr(self.agent, "invoke") or hasattr(self.agent, "ainvoke")):
            raise TypeError(
                "LangChainConnector expects an AgentExecutor-like object with "
                f".invoke()/.ainvoke(); got {type(self.agent).__name__}"
            )

    def _agent_input_keys(self) -> list:
        try:
            keys = getattr(self.agent, "input_keys", None)
            return list(keys) if keys else []
        except Exception:  # noqa: BLE001
            return []

    def _detect_input_key(self) -> str:
        """Figure out which input key the agent expects.

        Picks a text-style key from the agent's ``input_keys`` when present;
        recognises message-based keys (LangGraph); falls back to ``"input"``.
        """
        keys = self._agent_input_keys()
        if keys:
            for pref in self._PREFERRED_KEYS:
                if pref in keys:
                    return pref
            for msg in _MESSAGE_KEYS:
                if msg in keys:
                    return msg
            log.warning(
                "Agent input_keys=%s has no standard text key; using %r. "
                "Pass input_key= to override if this is wrong.",
                keys, keys[0],
            )
            return keys[0]
        return "input"

    # ------------------------------------------------------------------
    # Tool poisoning
    # ------------------------------------------------------------------

    def _install_poisoned_tools(self, payload: Any) -> list[tuple[Any, str, Any]]:
        """Replace the target tool's executor(s) with the poisoned output.

        Patches every executor a tool might run through — ``_run``, ``func``
        (sync) and ``_arun``, ``coroutine`` (async) — so poisoning works on
        ``@tool`` functions, ``StructuredTool``s and async tools alike.
        """
        restores: list[tuple[Any, str, Any]] = []
        target_tool_name = payload.metadata.get("target_tool")
        poisoned_output = payload.metadata.get("poisoned_output", "")

        def _sync_poison(*_a: Any, **_k: Any) -> str:
            return poisoned_output

        async def _async_poison(*_a: Any, **_k: Any) -> str:
            return poisoned_output

        matched = False
        for t in self._raw_tools():
            if getattr(t, "name", None) != target_tool_name:
                continue
            matched = True
            for attr, fn in (("_run", _sync_poison), ("func", _sync_poison),
                             ("_arun", _async_poison), ("coroutine", _async_poison)):
                if getattr(t, attr, None) is not None:
                    restores.append((t, attr, getattr(t, attr)))
                    setattr(t, attr, fn)
            break

        if target_tool_name and not matched:
            log.debug(
                "Tool-poisoning target %r not found among agent tools; payload "
                "will have no effect this run.", target_tool_name,
            )
        return restores


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_output(result: Any) -> Any:
    """Pull the answer field out of an AgentExecutor result dict."""
    if isinstance(result, dict):
        for key in ("output", "result", "answer", "text"):
            if key in result:
                return result[key]
    return result


def _tool_schema(tool: Any) -> dict[str, Any]:
    """Extract a JSON-schema-ish dict from a LangChain BaseTool, best-effort."""
    args_schema = getattr(tool, "args_schema", None)
    if args_schema is None:
        return {}
    if hasattr(args_schema, "model_json_schema"):       # pydantic v2
        try:
            return args_schema.model_json_schema()
        except Exception:  # noqa: BLE001
            return {}
    if hasattr(args_schema, "schema"):                  # pydantic v1
        try:
            return args_schema.schema()
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _infer_tags(name: str, description: str = "") -> list[str]:
    """Tag a tool by likely category so the fuzzer can prioritize."""
    text = f"{name} {description}".lower()
    tags: list[str] = []
    if any(k in text for k in ("file", "read", "load", "pdf", "doc")):
        tags.append("file")
    if any(k in text for k in ("web", "http", "url", "browse", "search", "fetch")):
        tags.append("web")
    if any(k in text for k in ("email", "mail", "smtp", "send")):
        tags.append("email")
    if any(k in text for k in ("exec", "run", "shell", "code", "python")):
        tags.append("code")
    if any(k in text for k in ("db", "sql", "query", "database")):
        tags.append("db")
    return tags
