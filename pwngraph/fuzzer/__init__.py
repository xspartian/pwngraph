"""Fuzzer — adversarial input generation for PwnGraph.

All attack classes are generated dynamically by an LLM
(``pwngraph.fuzzer.llm_generator.LLMPayloadGenerator``) — there are no
hardcoded per-class template pools. See that module's docstring.
"""

from pwngraph.fuzzer.delivery import baseline_for_tools, delivery_for_tool
from pwngraph.fuzzer.fuzzer import Fuzzer
from pwngraph.fuzzer.llm_generator import LLMClient, LLMPayloadGenerator
from pwngraph.fuzzer.payload import AttackClass, Payload

__all__ = [
    "Fuzzer",
    "Payload",
    "AttackClass",
    "LLMPayloadGenerator",
    "LLMClient",
    "delivery_for_tool",
    "baseline_for_tools",
]
