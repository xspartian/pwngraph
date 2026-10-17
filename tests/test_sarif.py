"""Tests for pwngraph.sarif — SARIF 2.1.0 export."""

from __future__ import annotations

from pwngraph.sarif import to_sarif
from pwngraph.types import Finding, Severity


def _finding(**overrides) -> Finding:
    defaults = dict(
        title="Critical hijack",
        severity=Severity.CRITICAL,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=9.3,
        target_system="x",
        attack_class="tool_poisoning",
        owasp=["LLM01", "LLM06"],
        payload_id="p1",
        summary="s",
        steps_to_reproduce=["a", "b"],
        impact="i",
        remediation="r",
        evidence={"attack_success_rate": 0.8, "trials": 5, "successes": 4},
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_to_sarif_top_level_shape():
    sarif = to_sarif([_finding()])
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1


def test_to_sarif_severity_maps_to_error_level_and_max_rank():
    sarif = to_sarif([_finding(severity=Severity.CRITICAL)])
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["rank"] == 100.0


def test_to_sarif_low_severity_maps_to_note_level():
    sarif = to_sarif([_finding(severity=Severity.LOW, cvss_score=None, cvss_vector=None)])
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert result["rank"] == 25.0


def test_to_sarif_message_includes_asr():
    sarif = to_sarif([_finding()])
    text = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "ASR: 80%" in text
    assert "4/5" in text


def test_to_sarif_rule_carries_owasp_tags():
    sarif = to_sarif([_finding(owasp=["LLM02", "LLM06"])])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/owasp/LLM02" in rule["properties"]["tags"]
    assert "external/owasp/LLM06" in rule["properties"]["tags"]


def test_to_sarif_empty_findings_produces_empty_results():
    sarif = to_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
