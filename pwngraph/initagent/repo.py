"""Read-only view of the target repository for the adapter-building agent.

Everything here is confined to one root directory: paths the model asks for
are resolved and rejected if they escape it (``..``, absolute paths, symlinks
pointing outside). Nothing in this module writes, executes, or imports target
code — that's ``validate.py``'s job, in a subprocess.

The repo map is built deterministically and handed to the model up front, so
its first step is informed rather than a blind ``list_dir('.')``: the file
tree, the manifests that name entry points (``langgraph.json``,
``pyproject.toml``), every line that constructs an agent/graph/tool, the
directories Python can import the project's packages from, and the versions
of the agent frameworks actually installed (so generated code targets the
real API — e.g. ``AgentExecutor`` lives in ``langchain_classic`` on
LangChain 1.x, not ``langchain.agents``).
"""

from __future__ import annotations

import ast
import importlib.metadata
import importlib.util
import json
import os
import re
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    ".next",
    "pwngraph_out",
}

_TEXT_SUFFIXES = {
    ".py",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".cfg",
    ".ini",
    ".txt",
    ".md",
    ".env.example",
}

_MANIFEST_NAMES = (
    "langgraph.json",
    "pyproject.toml",
    "setup.cfg",
    "requirements.txt",
    ".env.example",
    "config.example.yaml",
    "config.example.yml",
)

# Lines that construct an agent, graph, or tool — what the model most needs to
# find in a repo it has never seen. Order matters only for display.
_AGENT_PATTERNS = re.compile(
    r"create_react_agent|create_agent\(|create_deep_agent|StateGraph\(|\.compile\(|"
    r"AgentExecutor\(|initialize_agent\(|create_tool_calling_agent|create_openai_tools_agent|"
    r"@tool\b|\(BaseTool\)|StructuredTool\.from_function|Tool\(|ToolNode\(|\.bind_tools\(|"
    r"MultiServerMCPClient|load_mcp_tools|chat\.completions\.create|messages\.create\(|"
    r"^def (build|make|create|get)_\w*(agent|graph|app)\w*\("
)

_FRAMEWORK_PACKAGES = (
    "langchain",
    "langchain-core",
    "langchain-classic",
    "langchain-community",
    "langchain-openai",
    "langchain-anthropic",
    "langgraph",
    "langgraph-prebuilt",
    "openai",
    "anthropic",
    "python-dotenv",
)

MAX_READ_LINES = 800
MAX_READ_BYTES = 100_000
MAX_FILE_BYTES = 1_000_000
MAX_GREP_HITS = 80


class RepoError(ValueError):
    """A request the model made that we refuse (bad path, bad regex, ...)."""


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._files: list[Path] | None = None
        self._file_set: set[Path] = set()

    # ------------------------------------------------------------------
    # Path confinement
    # ------------------------------------------------------------------

    def resolve(self, rel: str) -> Path:
        rel = (rel or ".").strip()
        candidate = (self.root / rel).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise RepoError(f"path {rel!r} is outside the repository")
        return candidate

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix() or "."
        except ValueError:
            try:
                return path.resolve().relative_to(self.root).as_posix() or "."
            except ValueError:
                return str(path)

    def walk_files(self, suffixes: set[str] | None = None) -> Iterator[Path]:
        # One filesystem walk per session — a big repo on a slow mount (WSL
        # /mnt/*) makes every walk expensive, and the map alone needs several.
        # os.scandir gets the file type from the directory listing itself,
        # avoiding a stat() per entry.
        if self._files is None:
            files: list[Path] = []
            stack = [self.root]
            while stack:
                current = stack.pop()
                try:
                    with os.scandir(current) as it:
                        entries = sorted(it, key=lambda e: e.name, reverse=True)
                except OSError:
                    continue
                for entry in entries:
                    if entry.name in SKIP_DIRS or entry.name.endswith(".egg-info"):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        files.append(Path(entry.path))
            self._files = files
            self._file_set = set(files)
        for f in self._files:
            if suffixes is None or f.suffix in suffixes:
                yield f

    def _has(self, path: Path) -> bool:
        if self._files is None:
            list(self.walk_files())
        return path in self._file_set

    # ------------------------------------------------------------------
    # Tools exposed to the model
    # ------------------------------------------------------------------

    def list_dir(self, rel: str = ".") -> str:
        path = self.resolve(rel)
        if not path.is_dir():
            raise RepoError(f"{rel!r} is not a directory")
        lines = []
        for entry in sorted(path.iterdir()):
            if entry.name in SKIP_DIRS:
                continue
            lines.append(entry.name + ("/" if entry.is_dir() else ""))
            if len(lines) >= 200:
                lines.append("... (truncated)")
                break
        return "\n".join(lines) or "(empty)"

    def read_file(self, rel: str, start: int = 1, end: int | None = None) -> str:
        path = self.resolve(rel)
        if not path.is_file():
            raise RepoError(f"{rel!r} is not a file")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise RepoError(f"{rel!r} is too large to read")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(start or 1))
        end = min(len(lines), int(end) if end else start + MAX_READ_LINES - 1)
        end = min(end, start + MAX_READ_LINES - 1)
        out, size = [], 0
        for i in range(start, end + 1):
            row = f"{i:>5}  {lines[i - 1]}"
            size += len(row)
            if size > MAX_READ_BYTES:
                out.append(f"... (truncated at line {i}; read on from start={i})")
                break
            out.append(row)
        footer = f"[{self.rel(path)}: lines {start}-{min(end, len(lines))} of {len(lines)}]"
        return "\n".join(out + [footer])

    def outline(self, rel: str) -> str:
        """Imports, classes, functions (with signatures, line numbers and first
        docstring line) and module-level assignments of a Python file — the
        cheap way to find where to read in a big file."""
        path = self.resolve(rel)
        if not path.is_file() or path.suffix != ".py":
            raise RepoError(f"{rel!r} is not a Python file")
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise RepoError(f"cannot parse {rel!r}: {exc}") from exc

        def doc(node: ast.AST) -> str:
            d = ast.get_docstring(node)  # type: ignore[arg-type]
            return f"  # {d.strip().splitlines()[0][:100]}" if d else ""

        def sig(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            deco = "".join(f"@{ast.unparse(d)} " for d in node.decorator_list)
            return f"{deco}{prefix} {node.name}({ast.unparse(node.args)})"

        rows: list[str] = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                rows.append(f"{node.lineno:>5}  {ast.unparse(node)[:160]}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                rows.append(f"{node.lineno:>5}  {sig(node)}{doc(node)}")
            elif isinstance(node, ast.ClassDef):
                bases = ", ".join(ast.unparse(b) for b in node.bases)
                rows.append(f"{node.lineno:>5}  class {node.name}({bases}){doc(node)}")
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        rows.append(f"{sub.lineno:>5}      {sig(sub)}{doc(sub)}")
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                rows.append(f"{node.lineno:>5}  {ast.unparse(node)[:120]}")
        total = len(source.splitlines())
        return "\n".join(rows + [f"[{self.rel(path)}: {total} lines]"])

    def grep(self, pattern: str, glob: str = "*.py") -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise RepoError(f"invalid regex: {exc}") from exc
        hits: list[str] = []
        for path in self.walk_files():
            if not path.match(glob) or path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{self.rel(path)}:{n}: {line.strip()[:200]}")
                    if len(hits) >= MAX_GREP_HITS:
                        hits.append("... (more matches; narrow the pattern or glob)")
                        return "\n".join(hits)
        return "\n".join(hits) or "(no matches)"

    # ------------------------------------------------------------------
    # Up-front repo map
    # ------------------------------------------------------------------

    def top_level_packages(self) -> list[tuple[str, str]]:
        """(package_name, import_root) for the project's own importable packages.

        Anchored on project manifests: every directory holding a
        ``pyproject.toml`` / ``setup.py`` / ``setup.cfg`` (plus the repo root)
        is an import root, as is its ``src/``; the packages are the directories
        directly inside a root that have an ``__init__.py``. This finds
        a package nested several levels deep in a monorepo, and doesn't
        mistake the sub-packages of a namespace package (no ``__init__.py``) for
        top-level ones. Falls back to "a package whose parent is not a package"
        when no manifest-anchored root holds anything.
        """
        list(self.walk_files())
        manifest_dirs = {self.root} | {
            f.parent
            for f in self.walk_files({".toml", ".py", ".cfg"})
            if f.name in ("pyproject.toml", "setup.py", "setup.cfg")
        }
        roots = manifest_dirs | {d / "src" for d in manifest_dirs}
        out: set[tuple[str, str]] = set()
        for init in self.walk_files({".py"}):
            if init.name == "__init__.py" and init.parent.parent in roots:
                out.add((init.parent.name, self.rel(init.parent.parent)))
        if not out:
            for init in self.walk_files({".py"}):
                parent = init.parent.parent
                if (
                    init.name == "__init__.py"
                    and not self._has(parent / "__init__.py")
                    and "tests" not in init.parts
                ):
                    out.add((init.parent.name, self.rel(parent)))
        return sorted(out, key=lambda p: (p[0] in ("tests", "test"), p[1], p[0]))[:30]

    def import_roots(self) -> list[str]:
        return sorted({root for _, root in self.top_level_packages()})

    def tree(self, max_depth: int = 4, max_lines: int = 300) -> str:
        """Indented tree built from the cached walk (no extra filesystem I/O)."""
        nodes: set[tuple[str, ...]] = set()
        dirs: set[tuple[str, ...]] = set()
        for f in self.walk_files():
            parts = f.relative_to(self.root).parts
            if any(p.startswith(".") for p in parts):
                continue
            for depth in range(1, min(len(parts) - 1, max_depth) + 1):
                dirs.add(parts[:depth])
            if len(parts) <= max_depth and f.suffix in _TEXT_SUFFIXES:
                nodes.add(parts)
        lines = []
        for node in sorted(nodes | dirs):
            name = node[-1] + ("/" if node in dirs else "")
            lines.append("  " * (len(node) - 1) + name)
            if len(lines) >= max_lines:
                lines.append("... (truncated)")
                break
        return "\n".join(lines)

    def agent_hits(self, limit: int = 120) -> list[str]:
        paths = [
            p
            for p in self.walk_files({".py"})
            if not p.name.startswith("test_") and "tests" not in p.parts
        ]

        def scan(path: Path) -> list[str]:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return []
            if len(text) > MAX_FILE_BYTES:
                return []
            return [
                f"{self.rel(path)}:{n}: {line.strip()[:160]}"
                for n, line in enumerate(text.splitlines(), 1)
                if _AGENT_PATTERNS.search(line)
            ]

        # Reads are latency-bound on network/WSL mounts — overlap them.
        hits: list[str] = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            for found in pool.map(scan, paths):
                hits.extend(found)
                if len(hits) >= limit:
                    return hits[:limit]
        return hits

    def manifests(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for path in self.walk_files():
            if path.name in _MANIFEST_NAMES and len(found) < 12:
                try:
                    found[self.rel(path)] = path.read_text(encoding="utf-8", errors="replace")[
                        :4000
                    ]
                except OSError:
                    continue
        return found

    def build_map(self, adapter_path: Path, hint_file: Path | None = None) -> str:
        """The facts block for the model's first message."""
        versions = {}
        for pkg in _FRAMEWORK_PACKAGES:
            try:
                versions[pkg] = importlib.metadata.version(pkg)
            except importlib.metadata.PackageNotFoundError:
                versions[pkg] = "NOT INSTALLED"

        packages = self.top_level_packages()
        importable = {
            name: importlib.util.find_spec(name) is not None for name, _ in packages if name
        }

        adapter_dir = adapter_path.resolve().parent
        try:
            root_from_adapter = Path(
                *([".."] * len(adapter_dir.relative_to(self.root).parts))
            ).as_posix()
        except ValueError:
            root_from_adapter = str(self.root)

        sections = [
            f"Repository root: {self.root}",
            f"Adapter will be written to: {adapter_path.resolve()}",
            f"Repository root relative to the adapter's directory: {root_from_adapter or '.'}",
            f"Python: {sys.version.split()[0]} ({sys.executable})",
            "Installed framework versions (write code for THESE versions):\n"
            + json.dumps(versions, indent=2),
            "Top-level packages (name -> import root, relative to repo root) and whether "
            "they are already importable in this environment:\n"
            + "\n".join(
                f"  {name} -> {root}  (importable: {importable.get(name)})"
                for name, root in packages
            ),
        ]
        if hint_file is not None:
            sections.append(
                f"The user pointed at this file as the agent (start there): {self.rel(hint_file)}"
            )
        manifests = self.manifests()
        if manifests:
            sections.append(
                "Manifests:\n"
                + "\n".join(f"--- {name} ---\n{body}" for name, body in manifests.items())
            )
        sections.append("File tree (depth 4):\n" + self.tree())
        hits = self.agent_hits()
        sections.append(
            "Lines that construct agents / graphs / tools:\n" + ("\n".join(hits) or "(none found)")
        )
        return "\n\n".join(sections)
