"""AST-based static extractor for LangChain tool definitions.

Finds every tool a LangChain-flavored agent source file *could* call, without
executing any code. This is what feeds the ``possible`` rung of the evidence
ladder — the runtime fuzzer only sees what it happened to trigger, so this
fills in the rest.

Recognised patterns
--------------------
1. ``@tool`` decorator (bare, or called with a name override) on a function
   def. Name: the decorator's string argument if given, else the function's
   own name — the same resolution rule LangChain itself applies. Description:
   the function's docstring, which is what LangChain's ``@tool`` uses too.

2. ``Tool(name=..., description=..., func=...)`` — the classic ``Tool``
   constructor, matched by keyword arguments.

3. ``StructuredTool.from_function(func=..., name=..., description=...)`` —
   when name/description are omitted, falls back to the referenced function's
   own name/docstring, mirroring what LangChain does at runtime.

Import aliases are tracked (``from langchain_core.tools import tool as
lc_tool`` still matches), so the extractor isn't fooled by a renamed import.

Known limitation
-----------------
A tool built behind a custom wrapper function — ``_make_tool(fn, name, desc)``
called with the name as a plain positional string — is invisible to AST-only
analysis: resolving it would mean tracing imperative control flow, which is
static analysis's actual boundary, not a bug in this extractor. Partial static
results that degrade honestly are strictly better than a static pass that
pretends to execute code.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_TOOL_DECORATOR_NAMES = {"tool"}
_TOOL_CTOR_NAMES = {"Tool"}
_STRUCTURED_TOOL_NAMES = {"StructuredTool"}


@dataclass
class ExtractedTool:
    """One statically-discovered tool definition."""

    name: str
    description: str
    lineno: int
    pattern: str  # "decorator" | "tool_ctor" | "structured_tool"


def extract_langchain_tools(source: str, *, path: str = "<string>") -> list[ExtractedTool]:
    """Parse *source* and return every tool definition found in it.

    Degrades gracefully: a syntax error logs a warning and returns an empty
    list rather than raising, so one malformed file never aborts a scan.
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        log.warning("static extractor: could not parse %s: %s", path, exc)
        return []
    return _Extractor().run(tree)


def extract_langchain_tools_from_file(path: Path) -> list[ExtractedTool]:
    """Same as :func:`extract_langchain_tools`, reading *path* first."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("static extractor: could not read %s: %s", path, exc)
        return []
    return extract_langchain_tools(source, path=str(path))


class _Extractor:
    """One-shot AST walker. Construct fresh per parse; do not reuse."""

    def __init__(self) -> None:
        self._decorator_aliases: set[str] = set()
        self._ctor_aliases: set[str] = set()
        self._structured_aliases: set[str] = set()
        self._functions: dict[str, ast.FunctionDef] = {}
        self._found: list[ExtractedTool] = []

    def run(self, tree: ast.Module) -> list[ExtractedTool]:
        self._index_imports(tree)
        self._index_functions(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._check_decorators(node)
            elif isinstance(node, ast.Call):
                self._check_call(node)
        return self._found

    # ------------------------------------------------------------------
    # Indexing passes — run before pattern matching so forward references
    # (a decorator used before its import, a func= referencing a def that
    # appears later) still resolve.
    # ------------------------------------------------------------------

    def _index_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            module = node.module or ""
            if "tool" not in module.lower() and "langchain" not in module.lower():
                continue
            for alias in node.names:
                imported, local = alias.name, alias.asname or alias.name
                if imported in _TOOL_DECORATOR_NAMES:
                    self._decorator_aliases.add(local)
                elif imported in _TOOL_CTOR_NAMES:
                    self._ctor_aliases.add(local)
                elif imported in _STRUCTURED_TOOL_NAMES:
                    self._structured_aliases.add(local)

    def _index_functions(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._functions[node.name] = node

    # ------------------------------------------------------------------
    # Pattern 1 — @tool decorator
    # ------------------------------------------------------------------

    def _check_decorators(self, fn: ast.FunctionDef) -> None:
        for dec in fn.decorator_list:
            matched = False
            override_name: str | None = None

            if isinstance(dec, ast.Name) and dec.id in self._decorator_aliases:
                matched = True
            elif isinstance(dec, ast.Call):
                callee = dec.func
                if isinstance(callee, ast.Name) and callee.id in self._decorator_aliases:
                    matched = True
                    override_name = self._first_str_arg(dec)

            if matched:
                self._found.append(
                    ExtractedTool(
                        name=override_name or fn.name,
                        description=ast.get_docstring(fn) or "",
                        lineno=fn.lineno,
                        pattern="decorator",
                    )
                )

    # ------------------------------------------------------------------
    # Patterns 2 & 3 — constructor calls
    # ------------------------------------------------------------------

    def _check_call(self, call: ast.Call) -> None:
        callee = call.func

        if isinstance(callee, ast.Name) and callee.id in self._ctor_aliases:
            self._record_ctor_call(call, pattern="tool_ctor")
            return

        if (
            isinstance(callee, ast.Attribute)
            and callee.attr == "from_function"
            and isinstance(callee.value, ast.Name)
            and callee.value.id in self._structured_aliases
        ):
            self._record_ctor_call(call, pattern="structured_tool")

    def _record_ctor_call(self, call: ast.Call, *, pattern: str) -> None:
        name = self._kw_str(call, "name")
        description = self._kw_str(call, "description")
        func_ref = self._kw_name_ref(call, "func")

        if func_ref and func_ref in self._functions:
            referenced = self._functions[func_ref]
            name = name or referenced.name
            description = description or ast.get_docstring(referenced) or ""

        if not name:
            return  # nothing usable to key on — skip rather than guess

        self._found.append(
            ExtractedTool(
                name=name, description=description or "", lineno=call.lineno, pattern=pattern
            )
        )

    # ------------------------------------------------------------------
    # AST literal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _first_str_arg(call: ast.Call) -> str | None:
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
        for kw in call.keywords:
            if (
                kw.arg == "name"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                return kw.value.value
        return None

    @staticmethod
    def _kw_str(call: ast.Call, key: str) -> str | None:
        for kw in call.keywords:
            if (
                kw.arg == key
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                return kw.value.value
        return None

    @staticmethod
    def _kw_name_ref(call: ast.Call, key: str) -> str | None:
        for kw in call.keywords:
            if kw.arg == key and isinstance(kw.value, ast.Name):
                return kw.value.id
        return None
