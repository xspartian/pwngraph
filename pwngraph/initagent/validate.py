"""Run a candidate adapter for real, in a subprocess, and judge the result.

The parent (``validate_adapter``) writes nothing itself — the caller has
already put the candidate at its final path, because the adapter computes
``sys.path`` entries relative to ``__file__``. It then runs this module as a
child process::

    python -m pwngraph.initagent.validate <adapter.py> <repo_root> <result.json>

The child imports the adapter, calls ``build_agent()``, enumerates tools via
the same connector a scan uses, and writes a JSON verdict. A subprocess keeps
a hanging or crashing target (or one that calls ``sys.exit``) from taking the
CLI down, and gives every attempt a clean interpreter so a half-imported
module from a failed attempt can't make the next one pass by accident.

Anti-cheat
----------
The easiest way to make validation pass is to write a fake agent whose tools
are stubs defined in adapter.py — and that would make every scan meaningless.
So beyond "it loads and has tools", the child rejects an adapter when:

  * any tool's implementation lives in the adapter file itself, or
  * no module from the target repository was imported at all.

Library tools (e.g. a search tool from ``langchain_community``) are allowed:
the repo using them is the real attack surface.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pwngraph.connector.introspect import tool_objects, tool_source_file
from pwngraph.initagent.repo import SKIP_DIRS

DEFAULT_TIMEOUT = 180


@dataclass
class Verdict:
    ok: bool
    error: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)
    agent_type: str = ""
    repo_modules: list[str] = field(default_factory=list)
    stdout_tail: str = ""

    def for_model(self) -> str:
        if self.ok:
            return json.dumps(
                {
                    "result": "SUCCESS",
                    "agent_type": self.agent_type,
                    "tools": self.tools,
                    "repo_modules_imported": self.repo_modules[:15],
                }
            )
        msg = f"FAILED\n{self.error.strip()}"
        if self.stdout_tail:
            msg += f"\n\n[target output before failure]\n{self.stdout_tail}"
        return msg


def validate_adapter(adapter: Path, root: Path, timeout: int = DEFAULT_TIMEOUT) -> Verdict:
    adapter = adapter.resolve()
    with tempfile.TemporaryDirectory(prefix="pwngraph-init-") as tmp:
        result_path = Path(tmp) / "result.json"
        cmd = [
            sys.executable,
            "-m",
            "pwngraph.initagent.validate",
            str(adapter),
            str(root.resolve()),
            str(result_path),
        ]
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(adapter.parent),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired:
            return Verdict(
                ok=False,
                error=f"build_agent() did not finish within {timeout}s — it may be waiting "
                "on a network service, a prompt for input, or an infinite loop.",
            )
        tail = _tail(proc.stdout + proc.stderr)
        if not result_path.exists():
            return Verdict(
                ok=False,
                error=f"the validation process exited with code {proc.returncode} "
                "before reporting a result (the target may call sys.exit() or crash "
                "the interpreter on import).",
                stdout_tail=tail,
            )
        data = json.loads(result_path.read_text(encoding="utf-8"))
        verdict = Verdict(**data)
        if not verdict.ok:
            verdict.stdout_tail = tail
        return verdict


def _tail(text: str, lines: int = 25) -> str:
    rows = text.strip().splitlines()
    return "\n".join(rows[-lines:])


# ----------------------------------------------------------------------
# Child side
# ----------------------------------------------------------------------


def _is_repo_file(path: str | None, root: Path, adapter: Path) -> bool:
    if not path:
        return False
    try:
        p = Path(path).resolve()
    except (OSError, ValueError):
        return False
    if p == adapter or root not in p.parents:
        return False
    return not any(part in SKIP_DIRS for part in p.relative_to(root).parts)


def _child(adapter: Path, root: Path) -> dict[str, Any]:
    import importlib.util

    sys.path.insert(0, str(adapter.parent))
    spec = importlib.util.spec_from_file_location("pwngraph_adapter_candidate", adapter)
    if spec is None or spec.loader is None:
        return {"ok": False, "error": "could not load the adapter as a module"}
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:  # noqa: BLE001 — the traceback is the point
        return {"ok": False, "error": "importing adapter.py failed:\n" + traceback.format_exc()}

    build = getattr(module, "build_agent", None)
    if not callable(build):
        return {"ok": False, "error": "adapter.py has no build_agent() function"}
    try:
        agent = build()
    except BaseException:  # noqa: BLE001
        return {"ok": False, "error": "build_agent() raised:\n" + traceback.format_exc()}
    if agent is None:
        return {"ok": False, "error": "build_agent() returned None"}

    from pwngraph.connector import make_connector

    try:
        specs = make_connector(agent).list_tools()
    except BaseException:  # noqa: BLE001
        return {"ok": False, "error": "enumerating tools failed:\n" + traceback.format_exc()}
    if not specs:
        return {
            "ok": False,
            "error": f"build_agent() returned a {type(agent).__name__}, but PwnGraph found "
            "zero tools on it. Return the object that owns the tools (the compiled "
            "LangGraph graph, the AgentExecutor, or the plain-Python shim with .tools).",
        }

    repo_modules = sorted(
        name
        for name, mod in list(sys.modules.items())
        if _is_repo_file(getattr(mod, "__file__", None), root, adapter)
    )
    if not repo_modules:
        return {
            "ok": False,
            "error": "REJECTED: the adapter does not import any module from the target "
            "repository, so it cannot be testing the real agent. Import and use the "
            "repository's own agent factory and tools.",
        }

    origins: dict[str, str] = {}
    faked: list[str] = []
    for tool in tool_objects(agent):
        name = getattr(tool, "name", None) or type(tool).__name__
        src = tool_source_file(tool)
        if src and Path(src).resolve() == adapter:
            faked.append(name)
        elif src and _is_repo_file(src, root, adapter):
            origins[name] = Path(src).resolve().relative_to(root).as_posix()
        elif src:
            origins[name] = "library"
    if faked:
        return {
            "ok": False,
            "error": "REJECTED: these tools are implemented inside adapter.py instead of "
            f"coming from the target repository: {', '.join(faked)}. Never write or stub "
            "tool bodies — import the repository's real tool objects/functions.",
        }

    return {
        "ok": True,
        "agent_type": f"{type(agent).__module__}.{type(agent).__name__}",
        "repo_modules": repo_modules,
        "tools": [
            {
                "name": s.name,
                "origin": origins.get(s.name, "unknown"),
                "action_sink": s.is_action_sink,
                "data_sink": s.is_data_sink,
            }
            for s in specs
        ],
    }


def main(argv: list[str]) -> int:
    adapter, root, result_path = Path(argv[0]).resolve(), Path(argv[1]).resolve(), Path(argv[2])
    try:
        result = _child(adapter, root)
    except BaseException:  # noqa: BLE001
        result = {"ok": False, "error": traceback.format_exc()}
    result_path.write_text(json.dumps(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
