"""Tests for pwngraph.static.langchain_extractor.

Includes an integration check against the real examples/lab_agent/agent.py —
that file uses plain @tool decorators on 5 real functions and is the intended
reference fixture for this extractor.
"""

from __future__ import annotations

from pathlib import Path

from pwngraph.static.langchain_extractor import (
    extract_langchain_tools,
    extract_langchain_tools_from_file,
)

_LAB_AGENT = Path(__file__).resolve().parents[2] / "examples" / "lab_agent" / "agent.py"


# ---------------------------------------------------------------------------
# Pattern 1 — @tool decorator
# ---------------------------------------------------------------------------


def test_bare_decorator_uses_function_name_and_docstring():
    src = '''
from langchain_core.tools import tool

@tool
def send_email(to: str, body: str) -> str:
    """Send an email to a recipient."""
    return "sent"
'''
    found = extract_langchain_tools(src)
    assert len(found) == 1
    assert found[0].name == "send_email"
    assert found[0].description == "Send an email to a recipient."
    assert found[0].pattern == "decorator"


def test_called_decorator_with_name_override():
    src = '''
from langchain_core.tools import tool

@tool("custom_name")
def internal_fn() -> str:
    """Does a thing."""
    return "ok"
'''
    found = extract_langchain_tools(src)
    assert len(found) == 1
    assert found[0].name == "custom_name"


def test_decorator_import_alias_is_tracked():
    src = '''
from langchain_core.tools import tool as lc_tool

@lc_tool
def read_file(path: str) -> str:
    """Read a file."""
    return "contents"
'''
    found = extract_langchain_tools(src)
    assert len(found) == 1
    assert found[0].name == "read_file"


def test_decorator_without_matching_import_is_ignored():
    # A function named `tool` decorating something, but never imported from a
    # langchain-flavored module — must not be treated as a tool definition.
    src = '''
def tool(fn):
    return fn

@tool
def not_a_langchain_tool():
    """Just a decorator that happens to be named tool."""
    return None
'''
    assert extract_langchain_tools(src) == []


def test_function_without_docstring_yields_empty_description():
    src = """
from langchain_core.tools import tool

@tool
def no_doc(x: str) -> str:
    return x
"""
    found = extract_langchain_tools(src)
    assert found[0].description == ""


def test_multiple_tools_in_one_file():
    src = '''
from langchain_core.tools import tool

@tool
def a():
    """A."""
    return None

@tool
def b():
    """B."""
    return None
'''
    found = extract_langchain_tools(src)
    assert {t.name for t in found} == {"a", "b"}


# ---------------------------------------------------------------------------
# Pattern 2 — Tool(name=..., description=..., func=...)
# ---------------------------------------------------------------------------


def test_tool_constructor_with_explicit_name_and_description():
    src = """
from langchain.tools import Tool

def _do_search(q):
    return "results"

search_tool = Tool(
    name="web_search",
    func=_do_search,
    description="Search the web for a query.",
)
"""
    found = extract_langchain_tools(src)
    assert len(found) == 1
    assert found[0].name == "web_search"
    assert found[0].description == "Search the web for a query."
    assert found[0].pattern == "tool_ctor"


def test_tool_constructor_falls_back_to_referenced_function_docstring():
    src = '''
from langchain.tools import Tool

def lookup(x):
    """Look something up."""
    return x

t = Tool(name="lookup_tool", func=lookup)
'''
    found = extract_langchain_tools(src)
    assert found[0].description == "Look something up."


def test_tool_constructor_without_name_and_unresolvable_func_is_skipped():
    src = """
from langchain.tools import Tool

t = Tool(func=some_external_callable, description="no name given")
"""
    assert extract_langchain_tools(src) == []


# ---------------------------------------------------------------------------
# Pattern 3 — StructuredTool.from_function(...)
# ---------------------------------------------------------------------------


def test_structured_tool_from_function_explicit_name():
    src = '''
from langchain.tools import StructuredTool

def run_query(sql: str) -> str:
    """Run a SQL query."""
    return "rows"

t = StructuredTool.from_function(func=run_query, name="sql_query")
'''
    found = extract_langchain_tools(src)
    assert len(found) == 1
    assert found[0].name == "sql_query"
    assert found[0].description == "Run a SQL query."
    assert found[0].pattern == "structured_tool"


def test_structured_tool_from_function_falls_back_to_func_name():
    src = '''
from langchain.tools import StructuredTool

def send_webhook(url: str) -> str:
    """POST to a webhook."""
    return "posted"

t = StructuredTool.from_function(func=send_webhook)
'''
    found = extract_langchain_tools(src)
    assert found[0].name == "send_webhook"
    assert found[0].description == "POST to a webhook."


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_syntax_error_returns_empty_list_not_raise():
    assert extract_langchain_tools("def broken(:\n") == []


def test_unreadable_file_returns_empty_list_not_raise(tmp_path):
    missing = tmp_path / "does_not_exist.py"
    assert extract_langchain_tools_from_file(missing) == []


def test_empty_file_returns_empty_list():
    assert extract_langchain_tools("") == []


def test_file_with_no_tools_returns_empty_list():
    src = "import os\n\ndef helper():\n    return os.getcwd()\n"
    assert extract_langchain_tools(src) == []


# ---------------------------------------------------------------------------
# Known limitation: custom wrapper indirection is invisible to AST analysis
# ---------------------------------------------------------------------------


def test_custom_wrapper_function_is_a_documented_blind_spot():
    # examples/hr_agent uses exactly this shape (_make_tool(fn, name, desc)).
    # This test pins the boundary so a future change doesn't silently start
    # guessing at imperative call sites.
    src = """
def _make_tool(fn, name, description):
    fn.__doc__ = description
    return SomeWrapper(fn, name)

def lookup_employee(employee_id):
    return "profile"

tools = [_make_tool(lookup_employee, "lookup_employee", "Look up an employee.")]
"""
    assert extract_langchain_tools(src) == []


# ---------------------------------------------------------------------------
# Integration: the real lab_agent fixture
# ---------------------------------------------------------------------------


def test_extracts_all_five_lab_agent_tools():
    assert _LAB_AGENT.exists(), "examples/lab_agent/agent.py moved or was renamed"

    found = extract_langchain_tools_from_file(_LAB_AGENT)
    names = {t.name for t in found}

    assert names == {"read_file", "web_search", "send_email", "http_post", "run_code"}
    assert all(t.pattern == "decorator" for t in found)


def test_lab_agent_tool_descriptions_come_from_docstrings():
    found = extract_langchain_tools_from_file(_LAB_AGENT)
    by_name = {t.name: t for t in found}

    assert "email" in by_name["send_email"].description.lower()
    assert "web" in by_name["web_search"].description.lower()
