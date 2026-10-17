"""Tests for pwngraph.static.schema — EvidenceState ladder and StructuralNode."""

from __future__ import annotations

import pytest

from pwngraph.static.identity import StructuralKey
from pwngraph.static.schema import KIND_TOOL, EvidenceState, StructuralNode, promote

_ORDER = [
    EvidenceState.POSSIBLE,
    EvidenceState.OBSERVED,
    EvidenceState.VALIDATED,
    EvidenceState.EXPLOITED,
]


def test_rank_is_strictly_increasing_up_the_ladder():
    ranks = [s.rank for s in _ORDER]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


@pytest.mark.parametrize(
    "current, candidate, expected",
    [
        (EvidenceState.POSSIBLE, EvidenceState.OBSERVED, EvidenceState.OBSERVED),
        (EvidenceState.OBSERVED, EvidenceState.EXPLOITED, EvidenceState.EXPLOITED),
        (
            EvidenceState.EXPLOITED,
            EvidenceState.POSSIBLE,
            EvidenceState.EXPLOITED,
        ),  # never regresses
        (EvidenceState.VALIDATED, EvidenceState.VALIDATED, EvidenceState.VALIDATED),  # idempotent
        (EvidenceState.EXPLOITED, EvidenceState.VALIDATED, EvidenceState.EXPLOITED),
    ],
)
def test_promote(current, candidate, expected):
    assert promote(current, candidate) is expected


def test_node_id_matches_key_digest():
    key = StructuralKey("t1", KIND_TOOL, "send_email")
    node = StructuralNode(key=key, kind=KIND_TOOL, name="send_email")
    assert node.node_id == key.digest()


def test_structural_node_defaults():
    node = StructuralNode(key=StructuralKey("t1", KIND_TOOL, "x"), kind=KIND_TOOL, name="x")
    assert node.evidence is EvidenceState.POSSIBLE
    assert node.source == "static"
    assert node.tags == []
    assert node.metadata == {}
