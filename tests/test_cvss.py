"""Tests for pwngraph.cvss — CVSS 3.1 vector derivation."""

from __future__ import annotations

import pytest

from pwngraph.cvss import cvss_for, severity_from_cvss
from pwngraph.types import EdgeType, Severity


def test_cvss_for_known_key():
    vector, score = cvss_for("shell_injection", [EdgeType.TOOL_MANIPULATION])
    assert vector.startswith("CVSS:3.1/")
    assert score == 9.6


def test_cvss_for_picks_highest_priority_edge():
    # data_exfil outranks context_poisoning and direct_injection in the table.
    _, score_all = cvss_for(
        "indirect_injection",
        [EdgeType.DIRECT_INJECTION, EdgeType.CONTEXT_POISONING, EdgeType.DATA_EXFIL],
    )
    _, score_exfil_only = cvss_for("indirect_injection", [EdgeType.DATA_EXFIL])
    assert score_all == score_exfil_only == 9.3


def test_cvss_for_unknown_class_falls_back_to_default():
    vector, score = cvss_for("nonexistent_class", [EdgeType.TOOL_MANIPULATION])
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    assert score == 5.4


def test_cvss_for_no_adversarial_edges_falls_back_to_default():
    vector, score = cvss_for("shell_injection", [EdgeType.NORMAL_FLOW])
    assert (vector, score) == ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4)


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, Severity.INFO),
        (3.9, Severity.LOW),
        (6.9, Severity.MEDIUM),
        (8.9, Severity.HIGH),
        (9.5, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss(score, expected):
    assert severity_from_cvss(score) is expected
