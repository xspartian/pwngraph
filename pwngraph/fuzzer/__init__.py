"""Fuzzer — adversarial input generation for PwnGraph.

v1 ships exactly two attack classes:
    - indirect_injection : poisoned documents the agent reads
    - tool_poisoning     : malicious responses from tools the agent calls
"""

from pwngraph.fuzzer.delivery import baseline_for_tools, delivery_for_tool
from pwngraph.fuzzer.fuzzer import Fuzzer
from pwngraph.fuzzer.indirect_injection import IndirectInjectionGenerator
from pwngraph.fuzzer.payload import AttackClass, Payload
from pwngraph.fuzzer.tool_poisoning import ToolPoisoningGenerator

__all__ = [
    "Fuzzer",
    "Payload",
    "AttackClass",
    "IndirectInjectionGenerator",
    "ToolPoisoningGenerator",
    "delivery_for_tool",
    "baseline_for_tools",
]
