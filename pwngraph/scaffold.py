"""pwngraph init — detect agent framework and generate adapter.py."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

Framework = Literal[
    "langgraph_react",
    "langgraph_stategraph",
    "langchain_executor",
    "langchain_react",
    "unknown",
]

_SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", "node_modules", "dist", "build", ".tox"}
_SKIP_FILES = {"adapter.py", "setup.py", "conf.py"}

_FRAMEWORK_PATTERNS: list[tuple[str, Framework, str]] = [
    (
        r"from langgraph\.prebuilt import.*create_react_agent",
        "langgraph_react",
        "langgraph create_react_agent",
    ),
    (r"create_react_agent\(", "langgraph_react", "create_react_agent call"),
    (r"StateGraph\(", "langgraph_stategraph", "LangGraph StateGraph"),
    (r"\.compile\(\)", "langgraph_stategraph", "StateGraph .compile()"),
    (r"AgentExecutor\(", "langchain_executor", "LangChain AgentExecutor"),
    (r"create_tool_calling_agent\(", "langchain_executor", "create_tool_calling_agent"),
    (
        r"from langchain.*agents.*import.*create_react_agent",
        "langchain_react",
        "langchain create_react_agent",
    ),
]

_FACTORY_RE = re.compile(
    r"def (build_agent|create_agent|get_agent|make_agent|agent_factory|build|run)\s*\("
)
_CLASS_RE = re.compile(r"class (\w+(?:Agent|Graph|Orchestrator|Assistant|Bot|Runner))\b")
_INPUT_KEY_RE = re.compile(r"""["'](query|question|input|message|prompt|text)["']""")


@dataclass
class DetectionResult:
    framework: Framework = "unknown"
    factory_hint: str = ""
    module_hint: str = ""
    input_key_hint: str = "input"
    files_scanned: int = 0
    evidence: list[str] = field(default_factory=list)


def detect_project(directory: Path = Path(".")) -> DetectionResult:
    result = DetectionResult()

    py_files = [
        f
        for f in directory.rglob("*.py")
        if not any(part in _SKIP_DIRS for part in f.parts)
        and not f.name.startswith("test_")
        and f.name not in _SKIP_FILES
    ]
    result.files_scanned = len(py_files)

    votes: dict[str, int] = {}

    for py_file in py_files:
        try:
            text = py_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for pattern, framework, label in _FRAMEWORK_PATTERNS:
            if re.search(pattern, text):
                votes[framework] = votes.get(framework, 0) + 1
                if label not in result.evidence:
                    result.evidence.append(label)

        if not result.factory_hint:
            m = _FACTORY_RE.search(text)
            if m:
                result.factory_hint = m.group(1)
                result.module_hint = py_file.stem

        if not result.factory_hint:
            m = _CLASS_RE.search(text)
            if m:
                result.factory_hint = m.group(1)
                result.module_hint = py_file.stem

        if result.input_key_hint == "input":
            m = _INPUT_KEY_RE.search(text)
            if m and m.group(1) != "input":
                result.input_key_hint = m.group(1)

    priority: list[Framework] = [
        "langgraph_react",
        "langgraph_stategraph",
        "langchain_executor",
        "langchain_react",
    ]
    for fw in priority:
        if votes.get(fw, 0) > 0:
            result.framework = fw
            break

    return result


# ---------------------------------------------------------------------------
# Plain-Python (no framework) agent analysis
#
# Not every agent is built on LangChain/LangGraph — a lot of real
# targets are a hand-rolled loop around an OpenAI/Anthropic-style chat-
# completions call, dispatching to tools by whatever convention that
# project's developer happened to pick. There is no reliable naming
# convention across projects, so this deliberately avoids scoring functions
# by name (no "probably called run_agent/chat/handle" guesswork). Everything
# below is a structural read of the actual code shape instead:
#   - tool inventory: a name->function dispatch dict, OR an if/elif ladder
#     that compares a value against string literals and calls a different
#     function per branch (the two dominant ways people wire up tool
#     dispatch), OR documented top-level functions as a last resort.
#   - entry point: whichever function actually *is* the dispatcher (contains
#     the ladder, or references the dispatch dict), or failing that, whichever
#     function's call graph reaches the most tool functions, or is invoked
#     from a `main()` / `if __name__ == "__main__":` guard — all read from the
#     call graph, never from what the function happens to be named.
# so `pwngraph init` can generate a *working* adapter without an LLM, for any
# agent regardless of the author's naming choices, and so an LLM fallback (for
# shapes this can't confidently read) has grounded facts instead of having to
# infer everything from raw source.
# ---------------------------------------------------------------------------

# Not a naming-convention guess: "main" is the language-level idiom itself
# (excluded so it's never mistaken for the agent's own turn-handling function),
# and the *_agent names are excluded only because they'd collide with the
# adapter we generate, not because they hint at what an entry point is called.
_SKIP_FUNCTION_NAMES = {"main", "build_agent", "get_agent", "make_agent"}


@dataclass
class PlainAgentAnalysis:
    """Best-effort structural read of a framework-less agent script."""

    module_name: str = ""
    entry_function: str | None = None
    entry_confidence: str = "none"  # "high" | "medium" | "none"
    tools: list[tuple[str, str]] = field(default_factory=list)  # (name, description)
    all_functions: list[str] = field(default_factory=list)
    tools_dict_name: str | None = None

    @property
    def is_usable(self) -> bool:
        return self.entry_function is not None and self.entry_confidence in ("high", "medium")


def analyze_plain_agent(path: Path) -> PlainAgentAnalysis:
    """Parse *path* with ``ast`` to find a tool inventory and entry point.

    Returns an empty (unusable) result on any parse failure or when nothing
    confident is found — callers should fall back to the interactive/generic
    template, or an LLM pass, in that case.
    """
    result = PlainAgentAnalysis(module_name=path.stem)
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError, ValueError):
        return result

    functions: dict[str, ast.AST] = {}
    docstrings: dict[str, str] = {}
    tools_dict: dict[str, str] = {}  # tool name -> function name
    tools_dict_var: str | None = None
    schema_descriptions: dict[str, str] = {}

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
            doc = (ast.get_docstring(node) or "").strip()
            docstrings[node.name] = doc.splitlines()[0] if doc else ""

        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            mapping: dict[str, str] = {}
            for k, v in zip(node.value.keys, node.value.values, strict=False):
                if (
                    isinstance(k, ast.Constant)
                    and isinstance(k.value, str)
                    and isinstance(v, ast.Name)
                ):
                    mapping[k.value] = v.id
            if mapping and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                tools_dict = mapping
                tools_dict_var = node.targets[0].id

        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
            for item in node.value.elts:
                name, desc = _extract_schema_entry(item)
                if name:
                    schema_descriptions[name] = desc

    result.all_functions = list(functions.keys())

    dispatch_ladder: dict[str, str] = {}
    dispatch_fn: str | None = None
    if not tools_dict:
        dispatch_ladder, dispatch_fn = _find_dispatch_ladder(functions)

    # --- tool inventory ------------------------------------------------------
    if tools_dict:
        result.tools_dict_name = tools_dict_var
        for tool_name, fn_name in tools_dict.items():
            desc = schema_descriptions.get(tool_name) or docstrings.get(fn_name, "")
            result.tools.append((tool_name, desc))
        tool_fn_names = set(tools_dict.values())
    elif dispatch_ladder:
        for _label, fn_name in dispatch_ladder.items():
            desc = schema_descriptions.get(fn_name) or docstrings.get(fn_name, "")
            result.tools.append((fn_name, desc))
        tool_fn_names = set(dispatch_ladder.values())
    else:
        for name in functions:
            if name in _SKIP_FUNCTION_NAMES or name.startswith("_"):
                continue
            doc = docstrings.get(name, "")
            if doc:
                result.tools.append((name, doc))
        tool_fn_names = {n for n, _ in result.tools}

    # --- call graph — who calls whom, purely structural ------------------------
    call_graph: dict[str, set[str]] = {
        name: _direct_calls(node, functions.keys()) for name, node in functions.items()
    }

    # --- entry point: score by structure, never by name -------------------------
    candidates: list[tuple[int, str]] = []
    for name, node in functions.items():
        if name in tool_fn_names or name in _SKIP_FUNCTION_NAMES or name.startswith("_"):
            continue
        args = node.args
        required = len(args.args) - len(args.defaults)
        if required > 1:
            continue

        score = 0
        if dispatch_fn == name:
            score += 6  # *is* the dispatcher
        if tools_dict_var and tools_dict_var in _referenced_names(node):
            score += 6  # references the dispatch dict
        score += min(len(call_graph.get(name, set()) & tool_fn_names), 4)  # fan-out to tools
        if _called_from_main(tree, name):
            score += 4  # invoked from main()/__main__
        if required == 1:
            score += 1  # takes one turn of input
        if score > 0:
            candidates.append((score, name))

    if candidates:
        candidates.sort(key=lambda x: -x[0])
        best_score, best_name = candidates[0]
        result.entry_function = best_name
        result.entry_confidence = "high" if best_score >= 6 else "medium"

    return result


def _extract_schema_entry(node: ast.AST) -> tuple[str | None, str]:
    """Pull (name, description) out of one OpenAI-style tool-schema dict literal."""
    if not isinstance(node, ast.Dict):
        return None, ""
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None, ""
    fn = value.get("function", value) if isinstance(value, dict) else {}
    if not isinstance(fn, dict):
        return None, ""
    return fn.get("name"), fn.get("description", "") or ""


def _find_dispatch_ladder(functions: dict[str, ast.AST]) -> tuple[dict[str, str], str | None]:
    """Find an if/elif ladder that dispatches on string equality to a call.

    The structural equivalent of a ``{"name": fn}`` dict for codebases that
    route tool calls with ``if name == "x": x_fn(...)`` chains instead — reads
    the actual branches (each ``value == "literal"`` test paired with the
    function call in its body), not any name or comment. Returns the
    (literal -> function name) mapping and the top-level function containing
    the largest such ladder (that function *is* the dispatcher, i.e. the
    entry point) — or ``({}, None)`` if no multi-branch ladder is found.
    """
    best: tuple[int, dict[str, str], str] | None = None
    for fn_name, fn_node in functions.items():
        mapping: dict[str, str] = {}
        for sub in ast.walk(fn_node):
            if not isinstance(sub, ast.If):
                continue
            test = sub.test
            if not (
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.Eq)
            ):
                continue
            literal = next(
                (
                    side.value
                    for side in (test.left, *test.comparators)
                    if isinstance(side, ast.Constant) and isinstance(side.value, str)
                ),
                None,
            )
            if literal is None:
                continue
            for stmt in sub.body:
                call = stmt.value if isinstance(stmt, (ast.Expr, ast.Return, ast.Assign)) else None
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                    mapping[literal] = call.func.id
                    break
        if len(mapping) >= 2 and (best is None or len(mapping) > best[0]):
            best = (len(mapping), mapping, fn_name)
    return (best[1], best[2]) if best else ({}, None)


def _direct_calls(node: ast.AST, known_names: Iterable[str]) -> set[str]:
    """Top-level function names directly called anywhere inside *node*."""
    names = set(known_names)
    return {
        sub.func.id
        for sub in ast.walk(node)
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in names
    }


def _referenced_names(node: ast.AST) -> set[str]:
    """Every bare name referenced anywhere inside *node*."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _called_from_main(tree: ast.Module, func_name: str) -> bool:
    """True if *func_name* is invoked inside ``main()`` or an ``if __name__`` guard.

    This is the Python language idiom itself, not a domain-specific guess.
    """
    targets: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.If) and _is_main_guard(node):
            targets.append(node)
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            targets.append(node)
    for t in targets:
        for sub in ast.walk(t):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == func_name
            ):
                return True
    return False


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare):
        return False
    names = [test.left, *test.comparators]
    return any(isinstance(n, ast.Name) and n.id == "__name__" for n in names)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

_TEMPLATE_LANGGRAPH_REACT = '''\
"""PwnGraph adapter — generated by `pwngraph init`

Scan commands:
    pwngraph scan --target adapter.py:build_agent --dry-run
    pwngraph scan --target adapter.py:build_agent --attacks all --out ./out
"""

from langgraph.prebuilt import create_react_agent

# EDIT 1 — swap for your LLM provider
from langchain_openai import ChatOpenAI
# from langchain_google_genai import ChatGoogleGenerativeAI
# from langchain_groq import ChatGroq

# EDIT 2 — import your tools
# from {module} import tool1, tool2
# from langchain_community.tools import ShellTool, ReadFileTool


def build_agent():
    llm = ChatOpenAI(model="gpt-4o-mini")    # EDIT — your model and API key
    tools = []                                # EDIT — your tools list

    return create_react_agent(model=llm, tools=tools)
'''

_TEMPLATE_LANGGRAPH_STATEGRAPH = '''\
"""PwnGraph adapter — generated by `pwngraph init`

Scan commands:
    pwngraph scan --target adapter.py:build_agent --dry-run
    pwngraph scan --target adapter.py:build_agent --attacks all --out ./out
"""

# EDIT 1 — verify this import path
from {module} import {cls}


def build_agent():
    # EDIT 2 — fill in the config your agent class requires
    config = {{
        "{input_key}": "PLACEHOLDER",    # add other required config keys here
    }}

    # Common pattern A — class that builds a StateGraph internally
    agent  = {cls}(config)               # EDIT — adjust constructor args if needed
    graph  = agent.build_graph()         # EDIT — method that returns your StateGraph
    return graph.compile()

    # Common pattern B — class that exposes a compiled graph directly
    # return {cls}(config).graph
'''

_TEMPLATE_LANGCHAIN_EXECUTOR = '''\
"""PwnGraph adapter — generated by `pwngraph init`

Scan commands:
    pwngraph scan --target adapter.py:build_agent --dry-run
    pwngraph scan --target adapter.py:build_agent --attacks all --out ./out
"""

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

# EDIT 1 — swap for your LLM provider
from langchain_openai import ChatOpenAI
# from langchain_google_genai import ChatGoogleGenerativeAI
# from langchain_groq import ChatGroq

# EDIT 2 — import your tools
# from {module} import tool1, tool2
# from langchain_community.tools import ShellTool, ReadFileTool

PROMPT = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{{{input_key}}}"),
    ("placeholder", "{{agent_scratchpad}}"),
])


def build_agent() -> AgentExecutor:
    llm   = ChatOpenAI(model="gpt-4o-mini")  # EDIT — your model
    tools = []                                # EDIT — your tools

    agent = create_tool_calling_agent(llm, tools, PROMPT)
    return AgentExecutor(agent=agent, tools=tools, verbose=True)
'''

_TEMPLATE_GENERIC = '''\
"""PwnGraph adapter — generated by `pwngraph init`

PwnGraph could not auto-detect your agent framework.
Fill in the EDIT sections, then scan:
    pwngraph scan --target adapter.py:build_agent --dry-run
    pwngraph scan --target adapter.py:build_agent --attacks all --out ./out
"""

# EDIT 1 — import your agent
# from {module} import {cls}

# EDIT 2 — import your LLM
# from langchain_openai import ChatOpenAI
# from langchain_google_genai import ChatGoogleGenerativeAI

# EDIT 3 — import your tools
# from langchain_community.tools import ShellTool, ReadFileTool


def build_agent():
    # Return one of:
    #   LangGraph  → CompiledGraph  (from StateGraph.compile() or create_react_agent())
    #   LangChain  → AgentExecutor
    raise NotImplementedError(
        "Fill in your agent here — see EDIT sections above.\\n"
        "Run `pwngraph scan --target adapter.py:build_agent --dry-run` to verify."
    )
'''

_TEMPLATES: dict[str, str] = {
    "langgraph_react": _TEMPLATE_LANGGRAPH_REACT,
    "langgraph_stategraph": _TEMPLATE_LANGGRAPH_STATEGRAPH,
    "langchain_executor": _TEMPLATE_LANGCHAIN_EXECUTOR,
    "langchain_react": _TEMPLATE_LANGCHAIN_EXECUTOR,  # same shape
    "unknown": _TEMPLATE_GENERIC,
}


# ---------------------------------------------------------------------------
# Plain-Python adapter — wraps a framework-less agent without reimplementing it
#
# Uses str.replace() markers instead of .format() because the generated code
# is full of literal `{`/`}` (dict/set syntax) that would otherwise need
# doubling everywhere.
# ---------------------------------------------------------------------------

_TEMPLATE_PLAIN_PYTHON = '''\
"""PwnGraph adapter — generated by `pwngraph init`

Auto-generated for a framework-less agent (no LangChain/LangGraph
signals were found). PwnGraph instruments the REAL tool functions in
__MODULE__.py so its tracer sees every call your agent makes, then drives
your agent through its own entry point — nothing here is reimplemented or
mocked.

If the detected entry point or tool list below is wrong, edit
_ENTRY_FUNCTION / _TOOL_DESCRIPTIONS directly, then:
    pwngraph scan --target adapter.py:build_agent --dry-run
    pwngraph scan --target adapter.py:build_agent --attacks all --out ./out
"""

import json as _json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import __MODULE__ as _agent_module

_ENTRY_FUNCTION = "__ENTRY_FUNCTION__"
_TOOLS_DICT_NAME = __TOOLS_DICT_NAME__          # e.g. "TOOLS", or None
_TOOL_DESCRIPTIONS = __TOOL_DESCRIPTIONS__       # [(name, description), ...]


class _ShimTool:
    """Stand-in PwnGraph can list, and tool-poison, like a real BaseTool.

    ``_fn`` is captured once at construction time (before any patching), so
    poisoning this instance's ``_run`` (PwnGraph's tool_poisoning attack does
    exactly that) overrides what the agent sees without touching the module.
    """

    def __init__(self, name, description, fn):
        self.name = name
        self.description = description
        self._fn = fn

    def _run(self, *args, **kwargs):
        return self._fn(*args, **kwargs)


class _ShimAgent:
    """Wraps a plain-Python agent so it looks like a LangChain AgentExecutor.

    PwnGraph's LangChainConnector only needs two things: ``.tools`` (for tool
    discovery/poisoning) and ``.invoke(dict, config=...)`` (to run one turn
    with tracer callbacks). This shim provides both around your unmodified
    agent: for the duration of one call it replaces each tool function in
    __MODULE__ (by name, and inside the dispatch dict if there is one) with a
    wrapper that reports on_tool_start/on_tool_end/on_tool_error to PwnGraph's
    tracer and then runs the tool through its _ShimTool (so poisoning still
    applies), before calling straight into your agent's real entry point.
    """

    def __init__(self):
        self.tools = [
            _ShimTool(name, desc, getattr(_agent_module, name))
            for name, desc in _TOOL_DESCRIPTIONS
            if hasattr(_agent_module, name)
        ]

    def invoke(self, inputs, config=None):
        callbacks = (config or {}).get("callbacks") or []
        user_input = inputs.get("input", "")

        tools_dict = (
            getattr(_agent_module, _TOOLS_DICT_NAME, None) if _TOOLS_DICT_NAME else None
        )

        def _make_wrapper(tool):
            def wrapper(*args, **kwargs):
                rid = uuid.uuid4()
                try:
                    arg_str = _json.dumps(kwargs if kwargs else list(args))
                except TypeError:
                    arg_str = str(kwargs or args)
                for cb in callbacks:
                    if hasattr(cb, "on_tool_start"):
                        cb.on_tool_start({"name": tool.name}, arg_str, run_id=rid)
                try:
                    result = tool._run(*args, **kwargs)
                except Exception as exc:
                    for cb in callbacks:
                        if hasattr(cb, "on_tool_error"):
                            cb.on_tool_error(exc, run_id=rid)
                    raise
                for cb in callbacks:
                    if hasattr(cb, "on_tool_end"):
                        cb.on_tool_end(output=str(result), run_id=rid)
                return result
            return wrapper

        originals = {}
        for tool in self.tools:
            original = getattr(_agent_module, tool.name, None)
            if original is None:
                continue
            originals[tool.name] = original
            wrapped = _make_wrapper(tool)
            setattr(_agent_module, tool.name, wrapped)
            if isinstance(tools_dict, dict) and tool.name in tools_dict:
                tools_dict[tool.name] = wrapped

        try:
            entry = getattr(_agent_module, _ENTRY_FUNCTION)
            output = entry(user_input)
        finally:
            for name, original in originals.items():
                setattr(_agent_module, name, original)
                if isinstance(tools_dict, dict) and name in tools_dict:
                    tools_dict[name] = original

        for cb in callbacks:
            if hasattr(cb, "on_agent_finish"):
                cb.on_agent_finish(type("Finish", (), {"return_values": {"output": output}})())
        return {"output": output}


def build_agent():
    return _ShimAgent()
'''


def generate_plain_adapter(
    module: str,
    entry_function: str,
    tools: list[tuple[str, str]],
    tools_dict_name: str | None,
    output_path: Path,
) -> None:
    """Write a working adapter.py for a framework-less (plain Python) agent."""
    content = (
        _TEMPLATE_PLAIN_PYTHON.replace("__MODULE__", module)
        .replace("__ENTRY_FUNCTION__", entry_function)
        .replace("__TOOLS_DICT_NAME__", repr(tools_dict_name))
        .replace("__TOOL_DESCRIPTIONS__", repr(tools))
    )
    output_path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


def generate_adapter(
    framework: str,
    module: str,
    cls: str,
    input_key: str,
    output_path: Path,
) -> None:
    """Write adapter.py filled with detected values."""
    template = _TEMPLATES.get(framework, _TEMPLATE_GENERIC)
    content = template.format(
        module=module or "your_module",
        cls=cls or "YourAgent",
        input_key=input_key or "input",
    )
    output_path.write_text(content, encoding="utf-8")
