"""Tests for the AI adapter builder behind `pwngraph init` (pwngraph.initagent).

The LLM is replaced by a scripted fake client; the validator runs for real
(subprocess import of the candidate adapter) against a tiny fixture repo.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from pwngraph.initagent import build_adapter
from pwngraph.initagent.repo import Repo, RepoError
from pwngraph.initagent.validate import validate_adapter

# ---------------------------------------------------------------------------
# Fixture repo: a package with a real tool and a factory
# ---------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    pkg = root / "src" / "myagent"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "tools.py").write_text(textwrap.dedent('''
            def lookup(query):
                """Look up a record."""
                return f"record for {query}"

            def send_email(to, body):
                """Send an email."""
                return "sent"
            '''))
    (pkg / "core.py").write_text(textwrap.dedent("""
            from myagent.tools import lookup, send_email

            class Tool:
                def __init__(self, name, description, func):
                    self.name, self.description, self.func = name, description, func

            class Agent:
                def __init__(self):
                    self.tools = [
                        Tool("lookup", "Look up a record.", lookup),
                        Tool("send_email", "Send an email.", send_email),
                    ]

                def invoke(self, inputs, config=None):
                    return {"output": "ok"}

            def make_agent():
                return Agent()
            """))
    (root / "langgraph.json").write_text(json.dumps({"graphs": {"agent": "./src/x.py:graph"}}))
    return root


GOOD_ADAPTER = textwrap.dedent("""
    \"\"\"Uses src/myagent/core.py:make_agent.\"\"\"
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
    from myagent.core import make_agent

    def build_agent():
        return make_agent()
    """)

STUBBED_TOOLS_ADAPTER = textwrap.dedent("""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
    from myagent.core import Agent, Tool

    def fake_lookup(query):
        return "stub"

    def build_agent():
        agent = Agent()
        agent.tools = [Tool("lookup", "stub", fake_lookup)]
        return agent
    """)

NO_REPO_IMPORT_ADAPTER = textwrap.dedent("""
    import json

    class _T:
        name = "lookup"
        description = "x"
        func = staticmethod(json.dumps)

    class _A:
        tools = [_T()]
        def invoke(self, inputs, config=None):
            return {"output": ""}

    def build_agent():
        return _A()
    """)


# ---------------------------------------------------------------------------
# Repo tools
# ---------------------------------------------------------------------------


def test_repo_rejects_paths_outside_root(repo: Path):
    r = Repo(repo)
    with pytest.raises(RepoError):
        r.read_file("../outside.py")
    with pytest.raises(RepoError):
        r.list_dir("/etc")


def test_repo_read_grep_and_import_roots(repo: Path):
    r = Repo(repo)
    assert "def lookup" in r.read_file("src/myagent/tools.py")
    assert "src/myagent/core.py" in r.grep(r"def make_agent")
    assert r.import_roots() == ["src"]
    assert ("myagent", "src") in r.top_level_packages()


def test_repo_map_includes_manifest_versions_and_hits(repo: Path):
    text = Repo(repo).build_map(repo / "adapter.py")
    assert "langgraph.json" in text
    assert "Installed framework versions" in text
    assert "myagent -> src" in text
    assert "src/myagent/core.py" in text  # def make_agent( hit


# ---------------------------------------------------------------------------
# Validator (real subprocess)
# ---------------------------------------------------------------------------


def test_validator_accepts_real_agent_and_reports_tool_origins(repo: Path):
    adapter = repo / "adapter.py"
    adapter.write_text(GOOD_ADAPTER)
    verdict = validate_adapter(adapter, repo)
    assert verdict.ok, verdict.error
    by_name = {t["name"]: t for t in verdict.tools}
    assert by_name["lookup"]["origin"] == "src/myagent/tools.py"
    assert by_name["send_email"]["action_sink"] is True


def test_validator_rejects_tools_defined_in_adapter(repo: Path):
    adapter = repo / "adapter.py"
    adapter.write_text(STUBBED_TOOLS_ADAPTER)
    verdict = validate_adapter(adapter, repo)
    assert not verdict.ok
    assert "implemented inside adapter.py" in verdict.error


def test_validator_rejects_adapter_that_imports_nothing_from_repo(repo: Path):
    adapter = repo / "adapter.py"
    adapter.write_text(NO_REPO_IMPORT_ADAPTER)
    verdict = validate_adapter(adapter, repo)
    assert not verdict.ok
    assert "does not import any module from the target" in verdict.error


def test_validator_reports_traceback_and_survives_sys_exit(repo: Path):
    adapter = repo / "adapter.py"
    adapter.write_text("import does_not_exist_xyz\ndef build_agent():\n    return None\n")
    verdict = validate_adapter(adapter, repo)
    assert not verdict.ok and "does_not_exist_xyz" in verdict.error

    adapter.write_text("import sys\nsys.exit(3)\n")
    verdict = validate_adapter(adapter, repo)
    assert not verdict.ok


# ---------------------------------------------------------------------------
# Agent loop with a scripted fake LLM
# ---------------------------------------------------------------------------


class _FakeClient:
    """Replays a fixed list of tool calls, one assistant turn per entry."""

    def __init__(self, turns: list[list[tuple[str, dict]]]):
        self._turns = list(turns)
        self.seen_messages: list[list[dict]] = []
        self.kwargs: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, model, messages, tools, **kwargs):
        self.kwargs.append(kwargs)
        self.seen_messages.append([dict(m) for m in messages])
        calls = self._turns.pop(0) if self._turns else []
        tool_calls = [
            SimpleNamespace(
                id=f"call_{i}",
                function=SimpleNamespace(name=name, arguments=json.dumps(args)),
            )
            for i, (name, args) in enumerate(calls)
        ]
        msg = SimpleNamespace(content=None if tool_calls else "thinking", tool_calls=tool_calls)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_loop_explores_fixes_and_succeeds(repo: Path):
    client = _FakeClient(
        [
            [("read_file", {"path": "src/myagent/core.py"})],
            [("validate_adapter", {"code": STUBBED_TOOLS_ADAPTER})],
            [("validate_adapter", {"code": "```python\n" + GOOD_ADAPTER + "\n```"})],
        ]
    )
    events: list[tuple[str, str]] = []
    out = repo / "adapter.py"
    result = build_adapter(repo, out, client, on_event=lambda k, t: events.append((k, t)))

    assert result.ok
    assert result.validations == 2
    assert {t["name"] for t in result.tools} == {"lookup", "send_email"}
    assert "from myagent.core import make_agent" in out.read_text()
    assert not out.read_text().startswith("```")
    # The validator's rejection was fed back to the model.
    last_messages = client.seen_messages[-1]
    assert any("implemented inside adapter.py" in m.get("content", "") for m in last_messages)
    assert ("ok", "2 tools") in events


def test_loop_blocker_restores_existing_adapter_and_saves_attempt(repo: Path):
    out = repo / "adapter.py"
    out.write_text("# user's previous adapter\n")
    client = _FakeClient(
        [
            [("validate_adapter", {"code": "import missing_pkg_xyz\ndef build_agent(): ...\n"})],
            [
                (
                    "report_blocker",
                    {"reason": "missing_pkg_xyz not installed", "user_action": "pip install x"},
                )
            ],
        ]
    )
    result = build_adapter(repo, out, client)

    assert not result.ok
    assert result.blocker == "missing_pkg_xyz not installed"
    assert result.user_action == "pip install x"
    assert out.read_text() == "# user's previous adapter\n"
    assert result.failed_attempt is not None
    assert "missing_pkg_xyz" in result.failed_attempt.read_text()


def test_loop_gives_up_after_step_budget_without_leaving_adapter(repo: Path):
    out = repo / "adapter.py"
    client = _FakeClient([[("list_dir", {"path": "."})]] * 3)
    result = build_adapter(repo, out, client, max_steps=3)
    assert not result.ok
    assert not out.exists()
    assert "never produced an adapter" in result.error


def test_loop_tool_errors_are_returned_to_model_not_raised(repo: Path):
    client = _FakeClient(
        [
            [("read_file", {"path": "../../etc/passwd"})],
            [("validate_adapter", {"code": GOOD_ADAPTER})],
        ]
    )
    result = build_adapter(repo, repo / "adapter.py", client)
    assert result.ok
    tool_msgs = [m for m in client.seen_messages[1] if m.get("role") == "tool"]
    assert tool_msgs[0]["content"].startswith("ERROR: path")


def test_loop_forces_a_draft_after_exploration_budget(repo: Path):
    from pwngraph.initagent.loop import DRAFT_AFTER_EXPLORE_CALLS

    explore = [[("grep", {"pattern": f"x{i}"})] for i in range(DRAFT_AFTER_EXPLORE_CALLS)]
    client = _FakeClient(explore + [[("validate_adapter", {"code": GOOD_ADAPTER})]])
    result = build_adapter(repo, repo / "adapter.py", client)
    assert result.ok
    assert "tool_choice" not in client.kwargs[DRAFT_AFTER_EXPLORE_CALLS - 1]
    assert client.kwargs[DRAFT_AFTER_EXPLORE_CALLS]["tool_choice"]["function"]["name"] == (
        "validate_adapter"
    )


def test_loop_answers_repeated_reads_with_a_pointer(repo: Path):
    read = ("read_file", {"path": "src/myagent/core.py"})
    client = _FakeClient([[read], [read], [("validate_adapter", {"code": GOOD_ADAPTER})]])
    assert build_adapter(repo, repo / "adapter.py", client).ok
    tool_msgs = [m for m in client.seen_messages[2] if m.get("role") == "tool"]
    assert "def make_agent" in tool_msgs[0]["content"]
    assert tool_msgs[1]["content"].startswith("Identical call already answered")


def test_outline_lists_definitions_with_line_numbers(repo: Path):
    text = Repo(repo).outline("src/myagent/core.py")
    assert "def make_agent()" in text
    assert "class Agent()" in text
    assert "from myagent.tools import lookup, send_email" in text
