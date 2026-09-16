"""A destructive-action guard for NEXUS's autonomous loop.

Every payload PwnGraph delivers is LLM-generated at scan time — there is no
human-pre-audited fixed template behind any attack class. NEXUS decides its
own next move, unsupervised, probe after probe, and can chain a confirmed hit
toward whatever action-sink tool the capability map ranks highest. That
autonomy is exactly what needs a backstop — this module is that backstop.

This is deliberately generic, not target- or lab-specific: it matches
*shapes* of genuinely destructive real-world commands (wipe a disk, drop a
database, kill the host) that should never be part of a security probe
regardless of which agent is being tested. It is defense in depth, not the
primary safety mechanism — the primary one is authorized, scoped testing in
the first place (see ``PwnGraph.scan``'s ``authorized`` requirement).

Explicit non-goal: this does **not** screen ``--payload``/custom YAML
content. A user authoring their own payload has already made an explicit,
scoped choice — including, legitimately, proving an agent *would* run
something destructive if asked. This guard only applies to what NEXUS's own
built-in generators autonomously produce.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pwngraph.fuzzer.payload import Payload

# Shapes of genuinely destructive real-world commands — not "this agent
# obeyed an injection" evidence (that's the canary's job), but "this
# specific instruction, if actually executed for real, wipes something."
_DESTRUCTIVE_PATTERNS = [
    re.compile(p, re.I)
    for p in (
        r"rm\s+-rf\s+/(?!\S)",  # rm -rf / (not /tmp, /some/path, etc.)
        r"rm\s+-rf\s+--no-preserve-root",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # classic fork bomb
        r"dd\s+.*\bif=.*\bof=/dev/(sd|nvme|hd)",  # disk-clobbering dd
        r"\bmkfs\.\w+",
        r">\s*/dev/(sd|nvme|hd)[a-z0-9]*\b",  # redirect onto a raw disk
        r"\bdrop\s+(database|table)\b",
        r"\bshutdown\b\s*(-h|-r|now)?",
        r"\breboot\b",
        r"\bhalt\b",
        r"del\s+/f\s+/s\s+/q\s+[a-z]:\\",  # Windows recursive force-delete
        r"format\s+[a-z]:\s*(/[a-z]\s*)*$",  # Windows format C:
        r"\bmkfs\b",
    )
]


def screen_payload(payload: Payload) -> tuple[bool, str]:
    """(is_safe, reason). Checks a generated payload's text against the
    destructive-shape denylist. ``is_safe=True`` with an empty reason means
    nothing matched; a canary-bearing echo/whoami/env-style probe (the
    built-in generators' actual content) always passes.
    """
    text = "\n".join(
        s
        for s in (
            getattr(payload, "delivery_input", "") or "",
            getattr(payload, "injection_text", "") or "",
        )
        if s
    )
    for pattern in _DESTRUCTIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            return False, f"matches destructive pattern {pattern.pattern!r} ({match.group(0)!r})"
    return True, ""


__all__ = ["screen_payload"]
