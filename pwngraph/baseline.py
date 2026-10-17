"""Baseline files — save a scan's dangerous paths, reload them for a later diff.

``diff_paths`` (see ``pwngraph.attackpath``) compares two path lists in
process, but the real use case is a defense regression check: scan today,
save a baseline, apply a guardrail, scan again next week, diff against the
saved file. ``AttackPath`` is already a pydantic model, so this is a thin,
honest wrapper — no custom serialization format to invent or maintain.

A baseline's *risk grade* (``PwnGraph.risk_grade()``) is saved separately, as
a ``<path>.grade.json`` sidecar, rather than folded into the baseline file
itself — the grade needs ``findings``/ASR/OWASP-coverage state a bare
``list[AttackPath]`` doesn't carry, and changing the baseline format itself
would break every baseline file already on disk (and the existing
``save_baseline``/``load_baseline`` round-trip contract). The sidecar is
optional both ways: a baseline saved before grade-tracking existed just has
no sidecar, and ``pwngraph diff``'s grade-regression check degrades to
"nothing to compare against" rather than an error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from pwngraph.types import AttackPath

_ADAPTER: TypeAdapter[list[AttackPath]] = TypeAdapter(list[AttackPath])


def save_baseline(paths: list[AttackPath], path: Path) -> Path:
    """Write *paths* to *path* as JSON. Returns *path* for chaining."""
    path.write_text(_ADAPTER.dump_json(paths, indent=2).decode("utf-8"), encoding="utf-8")
    return path


def load_baseline(path: Path) -> list[AttackPath]:
    """Read a baseline file written by :func:`save_baseline`."""
    return _ADAPTER.validate_json(path.read_text(encoding="utf-8"))


def _grade_sidecar_path(path: Path) -> Path:
    return path.with_name(path.name + ".grade.json")


def save_baseline_grade(grade: dict[str, Any], path: Path) -> Path:
    """Write *grade* (from ``PwnGraph.risk_grade()``) as a sidecar next to a
    baseline saved at *path*. Returns the sidecar path."""
    grade_path = _grade_sidecar_path(path)
    grade_path.write_text(json.dumps(grade, indent=2), encoding="utf-8")
    return grade_path


def load_baseline_grade(path: Path) -> dict[str, Any] | None:
    """Read the grade sidecar for a baseline at *path*, or ``None`` if this
    baseline predates grade-tracking (or was saved without it)."""
    grade_path = _grade_sidecar_path(path)
    if not grade_path.exists():
        return None
    return json.loads(grade_path.read_text(encoding="utf-8"))
