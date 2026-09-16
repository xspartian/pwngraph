"""Tests for pwngraph.util — flatten_text output normalization."""

from __future__ import annotations

from pwngraph.util import flatten_text


def test_flatten_text_none_returns_empty_string():
    assert flatten_text(None) == ""


def test_flatten_text_plain_string_passthrough():
    assert flatten_text("hello") == "hello"


def test_flatten_text_dict_with_output_key():
    assert flatten_text({"output": "hi there"}) == "hi there"


def test_flatten_text_dict_prefers_text_key_content_block():
    assert flatten_text({"type": "text", "text": "block text"}) == "block text"


def test_flatten_text_list_of_content_blocks_joined():
    blocks = [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]
    assert flatten_text(blocks) == "a b"


def test_flatten_text_object_with_content_attribute():
    class Msg:
        content = "message text"

    assert flatten_text(Msg()) == "message text"


def test_flatten_text_object_with_text_attribute_only():
    class Gen:
        text = "generated text"

    assert flatten_text(Gen()) == "generated text"


def test_flatten_text_nested_dict_falls_back_to_answer_key():
    assert flatten_text({"answer": "42"}) == "42"


def test_flatten_text_unrecognised_object_stringified():
    assert flatten_text(123) == "123"
