"""Preflight checks — ``pwngraph doctor`` and scan dry-run.

Two ease-of-use helpers:

* :func:`doctor` — verifies the environment can actually run a scan (Python
  version, core deps, a *reachable* Neo4j, optional framework connectors, LLM
  API keys) and returns a list of check results. This is the first thing a
  new user should run; it catches the broken-venv / missing-dep / no-Neo4j /
  no-API-key problems before a scan wastes time.

* :func:`dry_run` — connects to a target agent, enumerates its tools, classifies
  them as data/action sinks, and warns when the surface is too thin to test —
  *without* sending a single adversarial input (no API spend).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from typing import Any

# Core deps that must import for any scan.
_REQUIRED = ["neo4j", "pydantic", "click", "rich"]
# Each of these is only needed to scan the matching framework.
_OPTIONAL = ["langchain_core", "langchain", "langgraph"]
# Any one of these env keys means an LLM backend is probably configured.
_LLM_KEYS = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GROQ_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
]
_SEARCH_KEYS = ["TAVILY_API_KEY", "SERPAPI_API_KEY", "BING_SUBSCRIPTION_KEY"]


@dataclass
class Check:
    name: str
    ok: bool
    level: str  # "required" | "optional" | "info"
    detail: str

    @property
    def fatal(self) -> bool:
        return self.level == "required" and not self.ok


def _can_import(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def _neo4j_connectivity_check() -> Check:
    """Actually connect, not just import — a scan needs a live server, and
    ``docker compose up -d`` is the single most common thing a new user
    forgets before their first scan."""
    uri = os.environ.get("PWNGRAPH_NEO4J_URI", "bolt://localhost:7687")
    try:
        from pwngraph.backend.neo4j_backend import Neo4jBackend

        backend = Neo4jBackend(
            uri=uri,
            user=os.environ.get("PWNGRAPH_NEO4J_USER", "neo4j"),
            password=os.environ.get("PWNGRAPH_NEO4J_PASSWORD", "pwngraph-dev"),
        )
        _ = backend.node_count  # forces a round trip
        backend.close()
    except Exception as exc:  # noqa: BLE001 — any connection failure means "not ready"
        return Check(
            "neo4j-connection",
            False,
            "required",
            f"cannot reach {uri} ({exc.__class__.__name__}) — "
            f"run `docker compose up -d` (no docker-compose.yml? "
            f"`pwngraph docker-compose` writes one)",
        )
    return Check("neo4j-connection", True, "required", f"connected: {uri}")


def _default_password_check() -> Check:
    """Nudge toward rotating the bundled dev password once Neo4j stops being
    purely local — the docker-compose.yml this ships is explicit that
    "pwngraph-dev" is a dev-only default, not a secret, but that's only true
    as long as nothing but this machine can reach it."""
    password = os.environ.get("PWNGRAPH_NEO4J_PASSWORD", "pwngraph-dev")
    uri = os.environ.get("PWNGRAPH_NEO4J_URI", "bolt://localhost:7687")
    is_default = password == "pwngraph-dev"
    is_local = any(h in uri for h in ("localhost", "127.0.0.1", "::1"))

    if is_default and not is_local:
        return Check(
            "neo4j-password",
            False,
            "optional",
            f"default dev password against a non-local URI ({uri}) — rotate "
            f"NEO4J_AUTH's password and set PWNGRAPH_NEO4J_PASSWORD before this "
            f"is reachable by anyone but this machine.",
        )
    if is_default:
        return Check(
            "neo4j-password", True, "info", "default dev password (fine for a local instance)"
        )
    return Check("neo4j-password", True, "info", "custom password set")


def doctor() -> list[Check]:
    """Run environment checks. Returns a list of :class:`Check` results."""
    checks: list[Check] = []

    # 1) Python version
    v = sys.version_info
    py_ok = v >= (3, 10)
    checks.append(
        Check(
            "python",
            py_ok,
            "required",
            f"Python {v.major}.{v.minor}.{v.micro}"
            + ("" if py_ok else " — pwngraph needs >= 3.10"),
        )
    )

    # 2) Core dependencies
    for mod in _REQUIRED:
        ok = _can_import(mod)
        checks.append(
            Check(
                f"dep:{mod}",
                ok,
                "required",
                "installed" if ok else f"missing — pip install {mod}",
            )
        )

    # 2b) Neo4j reachability — importable isn't enough; a scan needs a live
    # server. Skip the live probe if the driver itself isn't even installed
    # (already reported as fatal above) to avoid a confusing second failure.
    if _can_import("neo4j"):
        checks.append(_neo4j_connectivity_check())
        checks.append(_default_password_check())

    # 3) Optional LangChain / LangGraph stack
    lc_any = False
    for mod in _OPTIONAL:
        ok = _can_import(mod)
        lc_any = lc_any or ok
        checks.append(
            Check(
                f"dep:{mod}",
                ok,
                "optional",
                "installed" if ok else "not installed (needed to scan this framework)",
            )
        )
    if not lc_any:
        checks.append(
            Check(
                "langchain-stack",
                False,
                "optional",
                "No supported framework found. Install one: "
                "pip install 'pwngraph[langchain]' for AgentExecutor agents, or "
                "'pwngraph[langgraph]' for LangGraph agents. A framework-less "
                "plain-Python agent needs neither — `pwngraph init` generates "
                "a shim for it.",
            )
        )

    # 4) LLM API key present? (this is about the *target* agent's own
    # backend — any provider — separate from check 4b below.)
    present_llm = [k for k in _LLM_KEYS if os.environ.get(k)]
    checks.append(
        Check(
            "llm-api-key",
            bool(present_llm),
            "optional",
            (
                f"found: {', '.join(present_llm)}"
                if present_llm
                else "no LLM API key in environment (set one for live agents, e.g. GROQ_API_KEY)"
            ),
        )
    )

    # 4b) The fuzzer's own attacker-side LLM key — required, not optional.
    # Every attack payload is generated by an LLM (pwngraph.fuzzer.llm_generator)
    # with no static-template fallback, so a scan cannot produce any
    # adversarial content at all without this, regardless of what the target
    # agent itself uses (check 4, above).
    has_openai_key = bool(os.environ.get("OPENAI_API_KEY"))
    checks.append(
        Check(
            "fuzzer-llm-key",
            has_openai_key,
            "required",
            (
                "OPENAI_API_KEY found"
                if has_openai_key
                else "OPENAI_API_KEY not set — the fuzzer generates every attack payload "
                "via an LLM and has no static-template fallback; set OPENAI_API_KEY "
                "before scanning"
            ),
        )
    )

    # 5) Search/tool API key (informational — many agents need one)
    present_search = [k for k in _SEARCH_KEYS if os.environ.get(k)]
    checks.append(
        Check(
            "tool-api-key",
            bool(present_search),
            "info",
            (
                f"found: {', '.join(present_search)}"
                if present_search
                else "no search/tool API key (some target agents need e.g. TAVILY_API_KEY)"
            ),
        )
    )

    return checks


def summarize(checks: list[Check]) -> tuple[bool, str]:
    """Return (ready_to_scan, one_line_summary)."""
    fatal = [c for c in checks if c.fatal]
    if fatal:
        return False, f"NOT READY — {len(fatal)} required check(s) failed: " + ", ".join(
            c.name for c in fatal
        )
    warns = [c for c in checks if not c.ok and c.level == "optional"]
    if warns:
        return True, f"READY (with {len(warns)} warning(s) — live agent scans may need attention)"
    return True, "READY — environment looks good"


@dataclass
class DryRunResult:
    target_name: str
    tools: list[Any]  # list[ToolSpec]
    data_sinks: list[str]
    action_sinks: list[str]
    warnings: list[str]

    @property
    def testable(self) -> bool:
        return len(self.tools) > 0


def dry_run(connector: Any) -> DryRunResult:
    """Enumerate a target's tool surface without sending any adversarial input.

    Lets a user confirm pwngraph can *see* their agent's tools — and warns when
    the surface is too thin to meaningfully test — before spending API calls.
    """
    tools = connector.list_tools()
    data_sinks = [t.name for t in tools if getattr(t, "is_data_sink", False)]
    action_sinks = [t.name for t in tools if getattr(t, "is_action_sink", False)]

    warnings: list[str] = []
    if not tools:
        warnings.append(
            "0 tools discovered. Tool-poisoning, shell, and file-read attacks "
            "need tools — only inline injection will run. An empty result here "
            "is NOT a clean bill of health (tools may be bound in a way pwngraph "
            "can't see — check the connector)."
        )
    if tools and not action_sinks:
        warnings.append(
            "No action sinks (email/http/shell/file-write). Critical exfil and "
            "RCE findings require an action tool; expect at most High severity."
        )
    if tools and not data_sinks:
        warnings.append(
            "No data sinks (search/read/fetch). Indirect injection delivers "
            "through data-retrieval tools; without one it falls back to inline."
        )

    return DryRunResult(
        target_name=connector.target_name(),
        tools=tools,
        data_sinks=data_sinks,
        action_sinks=action_sinks,
        warnings=warnings,
    )
