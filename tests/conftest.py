"""Shared fixtures for the pwngraph test suite."""

from __future__ import annotations

import sys
from pathlib import Path

# Must run before any `pwngraph` import, including the ones a few lines down
# in this very file. `pip install -e .` normally makes `pwngraph` resolve via
# a custom editable-install finder in sys.meta_path, scoped to that package
# only — the repo root itself is never on sys.path. On at least one observed
# setup (WSL2 over a DrvFs-mounted drive, pytest's assertion-rewrite import
# hook installed ahead of it in sys.meta_path) that finder wasn't being
# consulted under pytest even though a plain `python -c "import
# pwngraph.connector.base"` worked fine — so this is a second, more
# universal resolution path: an ordinary sys.path entry that Python's
# standard path-based finder can use regardless of what pytest does to
# sys.meta_path. Also covers test helpers living directly under tests/ (e.g.
# _fake_backend.py), which need tests/ itself on sys.path to be importable as
# bare top-level modules from subdirectories like tests/static/.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
_TESTS_DIR = str(Path(__file__).resolve().parent)
for _p in (_REPO_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest  # noqa: E402

from pwngraph.connector.base import ToolSpec  # noqa: E402
from pwngraph.types import NodeType, TraceEvent  # noqa: E402


@pytest.fixture
def make_event():
    """Factory fixture: build a ``TraceEvent`` with sane defaults.

    Mirrors what ``Tracer._emit`` produces, so tests can construct small
    event chains without going through a real agent invocation.
    """

    def _make(
        node_type: NodeType,
        name: str,
        content: str,
        *,
        run_id: str = "run-1",
        parent_event_id: str | None = None,
        is_adversarial: bool = False,
        payload_id: str | None = None,
        metadata: dict | None = None,
    ) -> TraceEvent:
        return TraceEvent(
            run_id=run_id,
            node_type=node_type,
            name=name,
            content=content,
            parent_event_id=parent_event_id,
            is_adversarial=is_adversarial,
            payload_id=payload_id,
            metadata=metadata or {},
        )

    return _make


@pytest.fixture
def tool_factory():
    """Factory fixture: build a ``ToolSpec`` without boilerplate."""

    def _make(name: str, description: str = "", tags: list[str] | None = None) -> ToolSpec:
        return ToolSpec(name=name, description=description, tags=tags or [])

    return _make
