"""Fuzzer — picks an attack class, asks a generator for a Payload, hands it back.

This is the thin top layer the PwnGraph orchestrator calls. Generators are
single-responsibility (one attack class each); this file routes between them.
"""

from __future__ import annotations

import random

from pwngraph.connector.base import ToolSpec
from pwngraph.fuzzer.file_read_injection import FileReadInjectionGenerator
from pwngraph.fuzzer.indirect_injection import IndirectInjectionGenerator
from pwngraph.fuzzer.memory_poisoning import MemoryPoisoningGenerator
from pwngraph.fuzzer.payload import AttackClass, Payload
from pwngraph.fuzzer.prompt_exfiltration import PromptExfiltrationGenerator
from pwngraph.fuzzer.shell_injection import ShellInjectionGenerator
from pwngraph.fuzzer.tool_poisoning import ToolPoisoningGenerator

# Generic fallback queries used when no tool surface is available yet (e.g.
# the very first baseline run before tools are enumerated). Once tools are
# known, ``Fuzzer.benign_query`` uses tool-aware queries instead.
_FALLBACK_QUERIES = [
    "What can you help me with?",
    "Give me a quick summary of what tools you have.",
    "What is the current status?",
    "Help me understand what you can do.",
]


class Fuzzer:
    """Routes between per-class generators and exposes benign queries for baselines."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._indirect = IndirectInjectionGenerator(seed=seed)
        self._tool_poison = ToolPoisoningGenerator(seed=seed)
        self._prompt_exfil = PromptExfiltrationGenerator(seed=seed)
        self._shell_inject = ShellInjectionGenerator(seed=seed)
        self._file_read = FileReadInjectionGenerator(seed=seed)
        self._memory_poison = MemoryPoisoningGenerator(seed=seed)
        # Built lazily on the first call to benign_query with tools.
        self._benign_pool: list[str] = []

    def next_payload(
        self,
        attack_class: str,
        tools: list[ToolSpec],
    ) -> Payload:
        """Generate a single adversarial payload for the named class."""
        ac = AttackClass(attack_class)
        if ac is AttackClass.INDIRECT_INJECTION:
            return self._indirect.generate(tools)
        if ac is AttackClass.TOOL_POISONING:
            return self._tool_poison.generate(tools)
        if ac is AttackClass.PROMPT_EXFILTRATION:
            return self._prompt_exfil.generate(tools)
        if ac is AttackClass.SHELL_INJECTION:
            return self._shell_inject.generate(tools)
        if ac is AttackClass.FILE_READ_INJECTION:
            return self._file_read.generate(tools)
        if ac is AttackClass.MEMORY_POISONING:
            return self._memory_poison.generate(tools)
        raise ValueError(f"Unknown attack class: {attack_class}")

    def benign_query(self, idx: int, tools: list[ToolSpec] | None = None) -> str:
        """Return a benign query for baseline runs.

        When ``tools`` is provided (which it is from ``core.scan()``) the pool
        is built from the actual tool surface so baseline runs exercise the
        agent's real capabilities — giving the GraphBuilder an accurate
        picture of normal flow before adversarial deviation begins.
        """
        from pwngraph.fuzzer.delivery import baseline_for_tools
        if tools and not self._benign_pool:
            self._benign_pool = baseline_for_tools(tools, self._rng) * 4
            self._rng.shuffle(self._benign_pool)
        pool = self._benign_pool or _FALLBACK_QUERIES
        return pool[idx % len(pool)]

    def cleanup(self) -> None:
        """Best-effort cleanup of generator-side temp state."""
        self._indirect.cleanup()
