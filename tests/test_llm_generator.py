"""Tests for pwngraph.fuzzer.llm_generator.LLMPayloadGenerator.

Uses FakeLLMClient (tests/_fake_llm_client.py) throughout — no real API key
or network access needed, mirroring the injectable-client pattern already
established by pwngraph.nexus.reasoner.LLMClient.
"""

from __future__ import annotations

import pytest

from pwngraph.connector.base import ToolSpec
from pwngraph.fuzzer.llm_generator import _CLASS_PROFILES, LLMPayloadGenerator
from pwngraph.fuzzer.payload import AttackClass
from tests._fake_llm_client import FakeLLMClient

_ALL_CLASSES = list(AttackClass)

_POISON_TOOL_CLASSES = {
    ac for ac, profile in _CLASS_PROFILES.items() if profile.mode == "poison_tool"
}


@pytest.fixture
def tools() -> list[ToolSpec]:
    return [
        ToolSpec(name="web_search", description="Search the web", tags=["web"]),
        ToolSpec(name="read_file", description="Read a file from disk", tags=["file"]),
        ToolSpec(name="send_email", description="Send an email", tags=["email"]),
    ]


@pytest.mark.parametrize("attack_class", _ALL_CLASSES)
def test_generate_produces_a_valid_payload_for_every_class(attack_class, tools):
    gen = LLMPayloadGenerator(client=FakeLLMClient(), seed=1)
    payload = gen.generate(attack_class, tools)
    assert payload.attack_class == attack_class
    assert payload.canary.startswith("PWN-")
    assert payload.delivery_input
    assert payload.injection_text
    assert payload.canary in payload.injection_text


@pytest.mark.parametrize("attack_class", _ALL_CLASSES)
def test_generate_degrades_gracefully_with_no_tools(attack_class):
    gen = LLMPayloadGenerator(client=FakeLLMClient(), seed=1)
    payload = gen.generate(attack_class, [])
    assert payload.delivery_input
    assert payload.injection_text


@pytest.mark.parametrize("attack_class", sorted(_POISON_TOOL_CLASSES, key=lambda c: c.value))
def test_poison_tool_classes_set_poisoned_output_metadata(attack_class, tools):
    gen = LLMPayloadGenerator(client=FakeLLMClient(), seed=2)
    payload = gen.generate(attack_class, tools)
    assert payload.metadata.get("poisoned_output")
    assert payload.metadata.get("target_tool") == payload.target_tool
    assert payload.canary in payload.metadata["poisoned_output"]


def test_poison_tool_class_target_none_with_no_tools():
    gen = LLMPayloadGenerator(client=FakeLLMClient(), seed=2)
    payload = gen.generate(AttackClass.TOOL_POISONING, [])
    assert payload.target_tool == "<none>"


def test_indirect_injection_writes_a_real_carrier_file(tools):
    client = FakeLLMClient()
    gen = LLMPayloadGenerator(client=client, seed=3)
    payload = gen.generate(AttackClass.INDIRECT_INJECTION, tools)

    location = payload.metadata.get("carrier_location")
    assert location, "expected a carrier file/URL to be recorded"
    path = location.removeprefix("file://")
    from pathlib import Path

    assert Path(path).is_file()
    content = Path(path).read_text(encoding="utf-8")
    assert payload.canary in content
    gen.cleanup()
    assert not Path(path).exists()


def test_recent_signals_reach_the_prompt(tools):
    client = FakeLLMClient()
    gen = LLMPayloadGenerator(client=client, seed=4)
    gen.generate(
        AttackClass.SHELL_INJECTION,
        tools,
        context={"recent_signals": ["expected tool 'run_command' was NOT called"]},
    )
    _, user_prompt = client.calls[-1]
    assert "expected tool 'run_command' was NOT called" in user_prompt


def test_desired_action_tool_biases_tool_poisoning_content(tools):
    client = FakeLLMClient()
    gen = LLMPayloadGenerator(client=client, seed=5)
    gen.generate(
        AttackClass.TOOL_POISONING,
        tools,
        context={"desired_action_tool": "send_email"},
    )
    _, user_prompt = client.calls[-1]
    assert "send_email" in user_prompt


def test_retries_once_on_invalid_json_then_succeeds(tools):
    client = FakeLLMClient(responses=["not json at all"])
    gen = LLMPayloadGenerator(client=client, seed=6)
    payload = gen.generate(AttackClass.PROMPT_EXFILTRATION, tools)
    assert payload.injection_text
    assert len(client.calls) == 2


def test_raises_after_repeated_invalid_json(tools):
    client = FakeLLMClient(responses=["not json", "{}", "{}"])
    gen = LLMPayloadGenerator(client=client, seed=7)
    with pytest.raises(RuntimeError):
        gen.generate(AttackClass.MEMORY_POISONING, tools)


def test_canary_enforced_even_if_llm_omits_it(tools):
    import json

    client = FakeLLMClient(
        responses=[json.dumps({"injection_text": "no canary here", "delivery_input": "hi"})]
    )
    gen = LLMPayloadGenerator(client=client, seed=8)
    payload = gen.generate(AttackClass.MEMORY_POISONING, tools)
    assert payload.canary in payload.injection_text
