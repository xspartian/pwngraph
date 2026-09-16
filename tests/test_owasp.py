"""Tests for pwngraph.owasp — OWASP LLM Top-10 mapping and coverage matrix."""

from __future__ import annotations

from pwngraph.owasp import coverage_matrix, owasp_for_finding
from pwngraph.types import EdgeType, Finding, Severity


def test_owasp_for_finding_base_mapping():
    ids = owasp_for_finding("prompt_exfiltration", [EdgeType.DIRECT_INJECTION])
    assert set(ids) == {"LLM02", "LLM07"}


def test_owasp_for_finding_escalates_to_excessive_agency_on_tool_manipulation():
    ids = owasp_for_finding("indirect_injection", [EdgeType.TOOL_MANIPULATION])
    assert "LLM06" in ids


def test_owasp_for_finding_data_exfil_adds_disclosure_and_agency():
    ids = owasp_for_finding("shell_injection", [EdgeType.DATA_EXFIL])
    assert "LLM02" in ids
    assert "LLM06" in ids


def test_owasp_for_finding_context_poisoning_alone_does_not_escalate():
    ids = owasp_for_finding("indirect_injection", [EdgeType.CONTEXT_POISONING])
    assert "LLM06" not in ids
    assert "LLM02" not in ids


def test_owasp_for_finding_unknown_class_falls_back():
    ids = owasp_for_finding("nonexistent_class", [EdgeType.NORMAL_FLOW])
    assert ids == ["LLM01"]


def _finding(owasp_ids: list[str]) -> Finding:
    return Finding(
        title="t",
        severity=Severity.HIGH,
        target_system="x",
        attack_class="shell_injection",
        payload_id="p1",
        owasp=owasp_ids,
        summary="s",
        steps_to_reproduce=[],
        impact="i",
        remediation="r",
    )


def test_coverage_matrix_marks_detected_with_count():
    findings = [_finding(["LLM06"]), _finding(["LLM06"]), _finding(["LLM01"])]
    rows = {r["id"]: r for r in coverage_matrix(findings)}
    assert rows["LLM06"]["status"] == "detected"
    assert rows["LLM06"]["count"] == 2
    assert rows["LLM01"]["status"] == "detected"
    assert rows["LLM01"]["count"] == 1


def test_coverage_matrix_marks_out_of_scope_categories():
    rows = {r["id"]: r for r in coverage_matrix([])}
    for oid in ("LLM03", "LLM04", "LLM09"):
        assert rows[oid]["status"] == "out-of-scope"


def test_coverage_matrix_marks_partial_categories():
    rows = {r["id"]: r for r in coverage_matrix([])}
    for oid in ("LLM08", "LLM10"):
        assert rows[oid]["status"] == "partial"


def test_coverage_matrix_marks_tested_when_mapped_but_no_finding():
    rows = {r["id"]: r for r in coverage_matrix([])}
    assert rows["LLM01"]["status"] == "tested"
    assert rows["LLM05"]["status"] == "tested"


def test_coverage_matrix_covers_all_ten_categories_exactly_once():
    rows = coverage_matrix([])
    ids = [r["id"] for r in rows]
    assert len(ids) == 10
    assert len(set(ids)) == 10
