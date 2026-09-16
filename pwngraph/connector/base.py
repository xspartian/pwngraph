"""Abstract Connector interface.

A Connector is the adapter between PwnGraph and a target agent framework.
v1 ships LangChainConnector and LangGraphConnector (which also covers the
shim ``pwngraph init`` generates for a framework-less plain-Python agent).
AutoGen and other framework connectors are v2.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class ToolSpec(BaseModel):
    """A tool exposed by the target agent.

    The Fuzzer uses ``name`` + ``description`` + ``schema`` to choose where
    to deliver payloads (e.g. a tool called "read_file" is a great sink for
    indirect prompt injection via poisoned files).
    """

    name: str
    description: str = ""
    tool_schema: dict[str, Any] = {}
    # Free-form tags the connector can attach: "file", "web", "email", "code"
    tags: list[str] = []

    @property
    def is_data_sink(self) -> bool:
        """Heuristic: does this tool *consume* untrusted external data?"""
        text = f"{self.name} {self.description}".lower()
        return any(
            t in text
            for t in (
                "search",
                "read",
                "fetch",
                "load",
                "get",
                "retriev",
                "browse",
                "scrape",
                "http",
                "open",
                "download",
            )
        )

    @property
    def is_action_sink(self) -> bool:
        """Heuristic: does this tool *take action* in the world?"""
        text = f"{self.name} {self.description}".lower()
        return any(
            t in text
            for t in (
                "send",
                "post",
                "write",
                "delete",
                "execute",
                "run",
                "create",
                "update",
                "purchase",
                "transfer",
                "publish",
            )
        )


class Connector(ABC):
    """Adapter to a target agent framework."""

    @abstractmethod
    def list_tools(self) -> list[ToolSpec]:
        """Return the agent's tool inventory."""

    @abstractmethod
    def invoke(
        self,
        user_input: str,
        tracer: Any,
        payload: Any | None = None,
    ) -> str:
        """Run one agent turn with the tracer attached.

        Parameters
        ----------
        user_input : str
            The text sent to the agent.
        tracer : Tracer
            PwnGraph tracer to hook callbacks into. Connector implementations
            wire the tracer into the framework's callback system.
        payload : Payload, optional
            If this run is adversarial, the Payload object that produced the
            input. Connectors may use it to register mock tools (for tool
            output poisoning) or attach poisoned documents.
        """

    @abstractmethod
    def target_name(self) -> str:
        """Human-readable identifier for reports."""
