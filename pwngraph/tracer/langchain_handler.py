"""LangChain → Tracer callback bridge.

Lives in a separate module so we can ``import langchain`` only when needed.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "langchain_core is not installed. Install with: pip install 'pwngraph[langchain]' "
        "or 'pwngraph[langgraph]' (either provides langchain_core)."
    ) from exc

log = logging.getLogger(__name__)


class LangChainCallbackHandler(BaseCallbackHandler):
    """Forward LangChain callbacks to a ``Tracer``.

    Only the callbacks we use for graph construction are implemented.
    """

    def __init__(self, tracer: Any) -> None:
        super().__init__()
        self.tracer = tracer
        # Pending (run_id, name) for tool calls that have started but not ended.
        # LangChain reuses the same run_id across start/end, so we can recover
        # the tool's real name on_tool_end (the end callback doesn't carry it).
        self._pending: list[tuple[str | None, str]] = []

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        name = (serialized or {}).get("name") or "tool"
        self._pending.append((str(run_id) if run_id is not None else None, name))
        self.tracer.record_tool_start(
            name=name,
            tool_input=input_str,
            run_id=run_id,
            parent_run_id=parent_run_id,
            metadata={"tags": tags or [], **(metadata or {})},
        )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # LangChain sometimes passes a ToolMessage-like object
        text = output if isinstance(output, str) else getattr(output, "content", str(output))
        self.tracer.record_tool_end(
            name=self._resolve_name(run_id),
            output=text,
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self.tracer.record_tool_end(
            name=self._resolve_name(run_id),
            output=f"<error: {error}>",
            run_id=run_id,
            parent_run_id=parent_run_id,
            metadata={"error": True},
        )

    def _resolve_name(self, run_id: Any) -> str:
        """Recover the tool name for an ending call.

        Matches by framework ``run_id`` when it lines up (real LangChain reuses
        the id); otherwise pops the most recent pending start (LIFO), which is
        correct for sequential tool use such as the mock lab agent.
        """
        rid = str(run_id) if run_id is not None else None
        for i in range(len(self._pending) - 1, -1, -1):
            if self._pending[i][0] == rid:
                return self._pending.pop(i)[1]
        if self._pending:
            return self._pending.pop()[1]
        return "tool"

    # ------------------------------------------------------------------
    # LLM / agent
    # ------------------------------------------------------------------

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        from pwngraph.util import flatten_text

        try:
            gen = response.generations[0][0]  # type: ignore[union-attr]
            text = gen.text or flatten_text(getattr(gen, "message", None))
        except Exception:  # noqa: BLE001
            text = flatten_text(response)
        if text:
            self.tracer.record_llm_thought(content=text[:2000])

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        from pwngraph.util import flatten_text

        output = getattr(finish, "return_values", {}).get("output")
        self.tracer.record_final_answer(content=flatten_text(output) or str(finish))
