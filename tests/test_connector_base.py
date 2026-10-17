"""Tests for pwngraph.connector.base — ToolSpec sink heuristics."""

from __future__ import annotations

from pwngraph.connector.base import ToolSpec


def test_is_data_sink_true_for_search_tool():
    t = ToolSpec(name="web_search", description="Search the web for information")
    assert t.is_data_sink is True


def test_is_action_sink_true_for_send_email():
    t = ToolSpec(name="send_email", description="Send an email to a recipient")
    assert t.is_action_sink is True


def test_neither_sink_for_neutral_tool():
    t = ToolSpec(name="calculator", description="Do basic arithmetic")
    assert t.is_data_sink is False
    assert t.is_action_sink is False


def test_tool_can_be_both_sinks():
    t = ToolSpec(name="fetch_and_post", description="fetch a url and post the result")
    assert t.is_data_sink is True
    assert t.is_action_sink is True


def test_sink_heuristics_are_case_insensitive():
    t = ToolSpec(name="ReadFile", description="READ a document from disk")
    assert t.is_data_sink is True
