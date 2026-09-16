"""Payload — the unit of adversarial input the fuzzer produces."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from pwngraph.types import _short_id


class AttackClass(str, Enum):
    """Supported attack classes."""

    INDIRECT_INJECTION = "indirect_injection"
    TOOL_POISONING = "tool_poisoning"
    PROMPT_EXFILTRATION = "prompt_exfiltration"
    SHELL_INJECTION = "shell_injection"
    FILE_READ_INJECTION = "file_read_injection"
    MEMORY_POISONING = "memory_poisoning"


class Payload(BaseModel):
    """An adversarial input ready to be delivered to a target agent.

    Core fields
    -----------
    payload_id      : Unique id propagated into TraceEvents for attribution.
    attack_class    : Which attack class this payload tests.
    delivery_input  : String handed to agent.invoke({"input": ...}).
    injection_text  : The actual attacker instructions.
    canary          : Unique sentinel tracked through agent behavior.
    target_tool     : For tool_poisoning — which tool output to replace.
    metadata        : Free-form generator-specific data.

    Template fields (populated when loaded from pwngraph-templates YAML)
    -----------------------------------------------------------------------
    template_id         : Unique slug from the template ``id`` field.
    hops                : 1 = direct attack, 2 = multi-hop chain.
    requires_tool       : Tool that must exist on the agent — skip if absent.
    expected_tool_call  : Tool the oracle expects to see called on success.
    matchers            : List of matcher dicts for additional hit validation.
    template_info       : Metadata block — severity, cvss, owasp-llm, cwe,
                          remediation, reference links.
    """

    payload_id: str = Field(default_factory=_short_id)
    attack_class: AttackClass
    delivery_input: str
    injection_text: str
    canary: str
    target_tool: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Template-sourced fields
    template_id: str | None = None
    hops: int | None = None
    requires_tool: str | None = None
    expected_tool_call: str | None = None
    matchers: list[dict[str, Any]] = Field(default_factory=list)
    template_info: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def make_canary(cls) -> str:
        """A short, distinctive token unlikely to appear naturally."""
        return f"PWN-{_short_id().upper()}"
