"""Stable identity for structural graph elements.

This is the one decision the rest of Phase 1 stands on. Static extraction and
the runtime engine discover tools through completely different means — an AST
walk over source text versus a live ``ToolSpec`` from a connector — and both
have to agree on when they are looking at *the same tool*, or the evidence
ladder never promotes past ``possible`` and diffing across scans is meaningless.

The key insight: both sides already share one thing — the ``--target``
locator string (``path/to/agent.py:build_agent``) that names the file and
factory being scanned. Static extraction parses that same file; the CLI loads
the agent through that same locator. Anchoring identity on the locator, not on
anything about the agent's runtime shape, is what makes it stable.

A key is ``(target_id, kind, qualified_name)``:

* ``target_id``  — the normalized locator (see :func:`normalize_target_id`).
* ``kind``       — an open string, not a closed enum (``"tool"``, ``"agent"``,
  and later ``"memory"``, ``"secret"``, ``"mcp_server"``, ...). New node kinds
  must never require touching this module.
* ``qualified_name`` — for a tool, its name exactly as both the static
  extractor and ``ToolSpec.name`` report it. This is the actual reconciliation
  point: the extractor must resolve a tool's name using the same rule
  LangChain itself uses (decorator override, else the function's own name),
  or the keys silently diverge and nothing ever promotes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StructuralKey:
    """Deterministic identity for one structural element of a scanned target."""

    target_id: str
    kind: str
    qualified_name: str

    def digest(self) -> str:
        """A short, stable hash — used as the node id in the structural graph."""
        raw = f"{self.target_id}\x1f{self.kind}\x1f{self.qualified_name}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def __str__(self) -> str:
        return self.digest()


def normalize_target_id(locator: str) -> str:
    """Normalize a ``pwngraph scan --target`` locator into a stable target id.

    ``examples/hr_agent/agent.py:build_agent`` run from two different working
    directories must produce the *same* id, or a static pass and a runtime
    scan of the identical agent would key their nodes differently and nothing
    would ever reconcile. File-based locators resolve to an absolute path;
    module-style locators (``pkg.module:factory``, no filesystem path to
    resolve) pass through unchanged.
    """
    locator = locator.strip()
    if ":" not in locator:
        return locator

    path_part, factory = locator.rsplit(":", 1)
    factory = factory.strip()
    candidate = Path(path_part.strip())

    if candidate.suffix == ".py":
        try:
            resolved = str(candidate.resolve())
        except OSError:
            resolved = str(candidate)
        return f"{resolved}:{factory}"

    return f"{path_part.strip()}:{factory}"
