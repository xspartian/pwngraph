"""Tests for pwngraph.static.identity — StructuralKey and target normalization."""

from __future__ import annotations

from pwngraph.static.identity import StructuralKey, normalize_target_id


def test_digest_is_deterministic():
    a = StructuralKey("target-1", "tool", "send_email")
    b = StructuralKey("target-1", "tool", "send_email")
    assert a.digest() == b.digest()


def test_digest_differs_by_target():
    a = StructuralKey("target-1", "tool", "send_email")
    b = StructuralKey("target-2", "tool", "send_email")
    assert a.digest() != b.digest()


def test_digest_differs_by_kind():
    a = StructuralKey("target-1", "tool", "search")
    b = StructuralKey("target-1", "agent", "search")
    assert a.digest() != b.digest()


def test_digest_differs_by_name():
    a = StructuralKey("target-1", "tool", "send_email")
    b = StructuralKey("target-1", "tool", "read_file")
    assert a.digest() != b.digest()


def test_digest_is_short_and_hex():
    key = StructuralKey("t", "tool", "x")
    digest = key.digest()
    assert len(digest) == 16
    int(digest, 16)  # raises if not valid hex


def test_str_matches_digest():
    key = StructuralKey("t", "tool", "x")
    assert str(key) == key.digest()


def test_key_fields_do_not_collide_across_a_separator_boundary():
    # ("ab", "c", "d") and ("a", "bc", "d") must not hash identically just
    # because naive concatenation would read the same.
    a = StructuralKey("ab", "c", "d")
    b = StructuralKey("a", "bc", "d")
    assert a.digest() != b.digest()


# ---------------------------------------------------------------------------
# normalize_target_id
# ---------------------------------------------------------------------------


def test_normalize_module_style_locator_passes_through():
    assert normalize_target_id("my_pkg.agents:build_agent") == "my_pkg.agents:build_agent"


def test_normalize_file_locator_resolves_to_absolute_path():
    result = normalize_target_id("examples/hr_agent/agent.py:build_agent")
    assert result.endswith("examples/hr_agent/agent.py:build_agent")
    assert result.startswith("/")  # resolved absolute


def test_normalize_is_stable_regardless_of_relative_prefix(tmp_path, monkeypatch):
    agent_file = tmp_path / "agent.py"
    agent_file.write_text("def build_agent(): ...\n")

    monkeypatch.chdir(tmp_path)
    from_bare = normalize_target_id("agent.py:build_agent")
    from_dotslash = normalize_target_id("./agent.py:build_agent")

    assert from_bare == from_dotslash


def test_normalize_strips_surrounding_whitespace():
    a = normalize_target_id("  my_pkg.agents:build_agent  ")
    b = normalize_target_id("my_pkg.agents:build_agent")
    assert a == b
