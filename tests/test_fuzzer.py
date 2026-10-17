"""Tests for pwngraph.fuzzer.fuzzer — Fuzzer routing and benign-query pooling.

Content-generation behavior itself (per-class prompt construction, canary
enforcement, poison-tool wiring) is covered by tests/test_llm_generator.py;
these tests only cover Fuzzer's own routing/pooling logic, using
FakeLLMClient so nothing here needs a real API key.
"""

from __future__ import annotations

import pytest

from pwngraph.connector.base import ToolSpec
from pwngraph.fuzzer.fuzzer import Fuzzer
from pwngraph.fuzzer.payload import AttackClass
from tests._fake_llm_client import FakeLLMClient

_ALL_CLASSES = [c.value for c in AttackClass]


@pytest.fixture
def tools() -> list[ToolSpec]:
    return [
        ToolSpec(name="read_file", description="Read a file from disk"),
        ToolSpec(name="send_email", description="Send an email"),
    ]


@pytest.mark.parametrize("attack_class", _ALL_CLASSES)
def test_next_payload_produces_a_valid_payload_for_every_class(attack_class, tools):
    fuzzer = Fuzzer(seed=42, llm_client=FakeLLMClient())
    payload = fuzzer.next_payload(attack_class, tools=tools)
    assert payload.attack_class.value == attack_class
    assert payload.canary.startswith("PWN-")
    assert payload.delivery_input
    assert payload.injection_text


def test_next_payload_unknown_class_raises(tools):
    fuzzer = Fuzzer(seed=1, llm_client=FakeLLMClient())
    with pytest.raises(ValueError):
        fuzzer.next_payload("not_a_real_class", tools=tools)


@pytest.mark.parametrize("attack_class", _ALL_CLASSES)
def test_next_payload_works_with_no_tools(attack_class):
    fuzzer = Fuzzer(seed=1, llm_client=FakeLLMClient())
    payload = fuzzer.next_payload(attack_class, tools=[])
    assert payload.delivery_input


def test_benign_query_returns_a_string(tools):
    fuzzer = Fuzzer(seed=1, llm_client=FakeLLMClient())
    q = fuzzer.benign_query(0, tools=tools)
    assert isinstance(q, str) and q


def test_benign_query_no_tools_falls_back():
    fuzzer = Fuzzer(seed=1, llm_client=FakeLLMClient())
    q = fuzzer.benign_query(0, tools=None)
    assert isinstance(q, str) and q


def test_benign_query_deterministic_with_seed(tools):
    seq1 = [
        Fuzzer(seed=5, llm_client=FakeLLMClient()).benign_query(i, tools=tools) for i in range(5)
    ]
    seq2 = [
        Fuzzer(seed=5, llm_client=FakeLLMClient()).benign_query(i, tools=tools) for i in range(5)
    ]
    assert seq1 == seq2


def test_cleanup_does_not_raise(tools):
    fuzzer = Fuzzer(seed=1, llm_client=FakeLLMClient())
    fuzzer.next_payload("indirect_injection", tools=tools)
    fuzzer.cleanup()
