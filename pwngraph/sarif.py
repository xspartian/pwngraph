"""SARIF 2.1.0 export — plugs pwngraph findings into CI / bug-bounty pipelines.

SARIF (Static Analysis Results Interchange Format) is the standard schema
used by GitHub Code Scanning, VS Code, and most CI security gates. Exporting
in SARIF means pwngraph findings can:
  - Block a PR in GitHub Actions with zero glue code.
  - Show inline in VS Code's Problems panel.
  - Feed into any SIEM / bug-bounty platform that accepts SARIF.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pwngraph.types import Finding, Severity

_VERSION = "2.1.0"
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL: dict[str, str] = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value: "error",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "note",
    Severity.INFO.value: "note",
}

_RANK: dict[str, float] = {
    Severity.CRITICAL.value: 100.0,
    Severity.HIGH.value: 75.0,
    Severity.MEDIUM.value: 50.0,
    Severity.LOW.value: 25.0,
    Severity.INFO.value: 0.0,
}


def _rule(finding: Finding) -> dict[str, Any]:
    owasp_tags = [f"external/owasp/{oid}" for oid in (finding.owasp or [])]
    return {
        "id": finding.finding_id,
        "name": finding.attack_class,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.summary},
        "helpUri": "https://github.com/xspartian/pwngraph",
        "properties": {
            "tags": ["security", "ai-agent", "prompt-injection"] + owasp_tags,
            "security-severity": str(finding.cvss_score or _RANK[finding.severity.value] / 10),
            "owasp": finding.owasp or [],
        },
    }


def _result(finding: Finding) -> dict[str, Any]:
    level = _LEVEL.get(finding.severity.value, "warning")
    message_text = (
        f"{finding.summary}\n\n"
        f"Attack class: {finding.attack_class}\n"
        f"CVSS: {finding.cvss_vector or 'N/A'} ({finding.cvss_score or 'N/A'})\n"
        f"OWASP: {', '.join(finding.owasp or [])}\n\n"
        f"Impact: {finding.impact}\n\n"
        f"Remediation: {finding.remediation}"
    )
    asr = finding.evidence.get("attack_success_rate")
    if asr is not None:
        trials = finding.evidence.get("trials", "?")
        succ = finding.evidence.get("successes", "?")
        message_text += f"\n\nASR: {asr*100:.0f}% ({succ}/{trials} trials)"

    result: dict[str, Any] = {
        "ruleId": finding.finding_id,
        "level": level,
        "rank": _RANK.get(finding.severity.value, 50.0),
        "message": {"text": message_text},
        "properties": {
            "severity": finding.severity.value,
            "attack_class": finding.attack_class,
            "payload_id": finding.payload_id,
        },
    }
    if finding.cvss_vector:
        result["properties"]["cvss_vector"] = finding.cvss_vector
    return result


def to_sarif(
    findings: list[Finding],
    tool_name: str = "PwnGraph",
    tool_version: str = "1.0.0",
) -> dict[str, Any]:
    """Convert a list of ``Finding`` objects to a SARIF 2.1.0 dict."""
    rules = [_rule(f) for f in findings]
    results = [_result(f) for f in findings]
    return {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/xspartian/pwngraph",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                ],
            }
        ],
    }


def write_sarif(findings: list[Finding], output_path: Path) -> Path:
    """Write SARIF to *output_path* and return it."""
    sarif = to_sarif(findings)
    output_path.write_text(json.dumps(sarif, indent=2, default=str), encoding="utf-8")
    return output_path
