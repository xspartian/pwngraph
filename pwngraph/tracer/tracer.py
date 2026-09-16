"""Tracer — captures every tool call, input, output, state change.

Design notes
------------
* The Tracer is framework-agnostic at its core: it exposes ``record_*``
  methods that emit ``TraceEvent`` objects with proper parentage. Framework
  adapters (LangChainCallbackHandler) translate framework callbacks into
  these record calls.

* Each "run" (one agent turn) gets a fresh root and a buffer. The PwnGraph
  orchestrator calls ``start_run`` → ``end_run`` and the Connector wires the
  framework callbacks in between.

* Causality is tracked via a stack: when a tool starts, its parent is the
  current top of stack; the tool itself is then pushed; on tool end the
  result event uses the tool call as its parent, then it's popped.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from pwngraph.types import NodeType, TraceEvent

log = logging.getLogger(__name__)


class Tracer:
    """Collects TraceEvents across an agent run."""

    def __init__(self) -> None:
        self._buf: list[TraceEvent] = []
        self._stack: list[str] = []  # event_id stack for causality (fallback)
        self._fw_to_event: dict[str, str] = {}  # framework run_id → our event_id
        self._run_id: str = ""
        self._root_event_id: str | None = None
        self._adversarial: bool = False
        self._payload_id: str | None = None

    # ------------------------------------------------------------------
    # Run lifecycle
    # ------------------------------------------------------------------

    def start_run(
        self,
        user_input: str,
        adversarial: bool = False,
        payload_id: str | None = None,
        attack_class: str | None = None,
    ) -> None:
        from pwngraph.types import _short_id

        self._buf = []
        self._stack = []
        self._fw_to_event = {}
        self._run_id = _short_id()
        self._adversarial = adversarial
        self._payload_id = payload_id

        root_meta: dict[str, Any] = {"is_root": True}
        if attack_class:
            root_meta["attack_class"] = attack_class
        root = self._emit(
            node_type=NodeType.USER_INPUT,
            name="user",
            content=user_input,
            metadata=root_meta,
        )
        self._root_event_id = root.event_id
        # The root is the implicit parent for everything in this run.
        self._stack.append(root.event_id)

    def end_run(self) -> list[TraceEvent]:
        events = list(self._buf)
        self._buf = []
        self._stack = []
        self._fw_to_event = {}
        self._run_id = ""
        self._root_event_id = None
        self._adversarial = False
        self._payload_id = None
        return events

    # ------------------------------------------------------------------
    # Recording API — used by framework adapters
    # ------------------------------------------------------------------

    def record_tool_start(
        self,
        name: str,
        tool_input: str,
        run_id: Any | None = None,
        parent_run_id: Any | None = None,
        metadata: dict | None = None,
    ) -> str:
        parent_id = self._resolve_start_parent(parent_run_id)
        ev = self._emit(
            node_type=NodeType.TOOL_CALL,
            name=name,
            content=str(tool_input),
            parent_id=parent_id,
            metadata=metadata or {},
        )
        if run_id is not None:
            self._fw_to_event[str(run_id)] = ev.event_id
        self._stack.append(ev.event_id)
        return ev.event_id

    def record_tool_end(
        self,
        name: str,
        output: str,
        run_id: Any | None = None,
        parent_run_id: Any | None = None,
        metadata: dict | None = None,
    ) -> str:
        # The result's parent is the matching tool_call. Prefer the framework
        # run_id pairing (correct even when tool calls run in parallel); fall
        # back to the causality stack when no framework id is available.
        parent_id: str | None = None
        if run_id is not None:
            parent_id = self._fw_to_event.get(str(run_id))
        if parent_id is None:
            parent_id = self._stack[-1] if self._stack else self._root_event_id

        ev = self._emit(
            node_type=NodeType.TOOL_RESULT,
            name=name,
            content=str(output),
            parent_id=parent_id,
            metadata=metadata or {},
        )

        # Pop the matching tool_call from the stack.
        if run_id is not None and self._fw_to_event.get(str(run_id)) in self._stack:
            self._stack.remove(self._fw_to_event[str(run_id)])
        elif self._stack and self._stack[-1] != self._root_event_id:
            self._stack.pop()
        return ev.event_id

    def _resolve_start_parent(self, parent_run_id: Any | None) -> str | None:
        """Decide the parent event for a starting tool call.

        * If the framework gives a ``parent_run_id`` we already recorded (a tool
          invoked by another tool), parent to that event.
        * If it gives a ``parent_run_id`` we have *not* recorded (a top-level
          tool under an agent/chain run we don't trace), parent to the root —
          this avoids falsely nesting sibling/parallel tool calls under each
          other.
        * If there is no framework id at all (mock agents, direct ``record_*``
          callers), fall back to the causality stack — the legacy behavior.
        """
        if parent_run_id is not None:
            mapped = self._fw_to_event.get(str(parent_run_id))
            if mapped is not None:
                return mapped
            return self._root_event_id
        return self._stack[-1] if self._stack else self._root_event_id

    def record_llm_thought(self, content: str, name: str = "llm") -> str:
        return self._emit(
            node_type=NodeType.AGENT_THOUGHT,
            name=name,
            content=content,
        ).event_id

    def record_final_answer(self, content: str) -> str:
        return self._emit(
            node_type=NodeType.FINAL_ANSWER,
            name="agent",
            content=content,
        ).event_id

    def record_error(self, message: str) -> str:
        return self._emit(
            node_type=NodeType.AGENT_THOUGHT,
            name="error",
            content=message,
            metadata={"error": True},
        ).event_id

    # ------------------------------------------------------------------
    # Framework hooks
    # ------------------------------------------------------------------

    def langchain_callbacks(self) -> list[Any]:
        """Return a callback list to pass to AgentExecutor.invoke(config={...}).

        Imported lazily so the package works without langchain installed.
        """
        try:
            from pwngraph.tracer.langchain_handler import LangChainCallbackHandler
        except ImportError:  # pragma: no cover
            log.debug("langchain not installed; returning empty callback list")
            return []
        return [LangChainCallbackHandler(self)]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit(
        self,
        node_type: NodeType,
        name: str,
        content: str,
        parent_id: str | None = None,
        metadata: dict | None = None,
    ) -> TraceEvent:
        if parent_id is None and self._stack:
            parent_id = self._stack[-1]

        ev = TraceEvent(
            run_id=self._run_id,
            node_type=node_type,
            name=name,
            content=content,
            timestamp=time.time(),
            parent_event_id=parent_id,
            is_adversarial=self._adversarial,
            payload_id=self._payload_id,
            metadata=metadata or {},
        )
        self._buf.append(ev)
        log.debug("trace: %s", ev.short())
        return ev
