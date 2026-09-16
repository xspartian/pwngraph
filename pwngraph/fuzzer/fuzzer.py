"""Fuzzer — the thin top layer the PwnGraph orchestrator calls.

All attack classes route through one ``LLMPayloadGenerator``
(``pwngraph/fuzzer/llm_generator.py``) — there are no per-class hardcoded
template pools. See that module's docstring for why, and for what stays as
code (taxonomy/routing) vs. what's generated (attack content).
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from pwngraph.connector.base import ToolSpec
from pwngraph.fuzzer.llm_generator import LLMClient, LLMPayloadGenerator
from pwngraph.fuzzer.payload import AttackClass, Payload

if TYPE_CHECKING:
    from pwngraph.recon import TargetProfile

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
    """Generates adversarial payloads via ``LLMPayloadGenerator`` and exposes
    benign queries for baselines."""

    def __init__(
        self,
        seed: int | None = None,
        llm_client: LLMClient | None = None,
        payload_cache_path: str | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self._generator = LLMPayloadGenerator(
            client=llm_client, seed=seed, cache_path=payload_cache_path
        )
        # Built lazily on the first call to benign_query with tools.
        self._benign_pool: list[str] = []

    def next_payload(
        self,
        attack_class: str,
        tools: list[ToolSpec],
        context: dict | None = None,
        target_profile: TargetProfile | None = None,
    ) -> Payload:
        """Generate a single adversarial payload for the named class.

        ``context`` is an optional, generator-specific steering hint —
        ``"desired_action_tool"`` (a tool name NEXUS wants this probe to
        bias toward) and ``"recent_signals"`` (the Oracle's own signals from
        recent failed attempts at this same target, letting the LLM adapt
        instead of re-rolling blind — see
        ``pwngraph.core.PwnGraph._run_nexus_loop``). ``target_profile`` is
        recon's ``TargetProfile`` (``pwngraph.recon``), when available, used
        to ground generation in the target's elicited objective.
        """
        ac = AttackClass(attack_class)
        return self._generator.generate(ac, tools, context=context, target_profile=target_profile)

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
        """Best-effort cleanup of generator-side temp state (carrier files)."""
        self._generator.cleanup()

    def record_delivery_outcome(self, tool_name: str, delivered: bool) -> None:
        """Forward carrier delivery-success feedback to the generator so it
        learns to stop targeting a tool that never echoes content back."""
        self._generator.record_delivery_outcome(tool_name, delivered)
