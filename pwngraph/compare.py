"""Compare two persisted scan reports — the read-only, UI-facing counterpart
to ``pwngraph diff``'s CI regression gate.

``pwngraph diff`` runs two live scans in one process and diffs their
``AttackPath`` objects by structural signature
(``pwngraph.attackpath.diff_paths``) — a strong identity guarantee, because
both scans' full event trees are in memory at once. A *persisted* report has
no such signature to compare: ``Finding.paths`` is deliberately dropped
before persistence (see ``report_store._FINDING_EXCLUDE`` — the trace graph
already represents it, better, than a JSON blob would) and the two reports
being compared here were very possibly produced by different processes,
possibly days apart.

So findings are matched here by ``(attack_class, title)`` instead — a
reasonable proxy (the same attack class producing the same titled finding
again is, in practice, "the same finding persisting"), not the same
guarantee ``diff_paths`` gives two live scans. The API/UI say so rather than
implying path-level precision they don't have.
"""

from __future__ import annotations

from typing import Any


def _finding_key(f: dict[str, Any]) -> tuple[str, str]:
    return (str(f.get("attack_class", "")), str(f.get("title", "")))


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Diff two ``report_store.load_scan_report`` payloads.

    Returns risk-grade and ASR deltas plus findings bucketed into
    added/removed/persisting (matched by ``(attack_class, title)``).
    """
    before_findings: list[dict[str, Any]] = before.get("findings", [])
    after_findings: list[dict[str, Any]] = after.get("findings", [])
    before_keys = {_finding_key(f) for f in before_findings}
    after_keys = {_finding_key(f) for f in after_findings}

    added = [f for f in after_findings if _finding_key(f) not in before_keys]
    removed = [f for f in before_findings if _finding_key(f) not in after_keys]
    persisting = [f for f in after_findings if _finding_key(f) in before_keys]

    before_grade = before.get("risk_grade") or {}
    after_grade = after.get("risk_grade") or {}
    before_asr = (before.get("asr") or {}).get("overall", {}).get("asr", 0.0)
    after_asr = (after.get("asr") or {}).get("overall", {}).get("asr", 0.0)

    b_score = before_grade.get("score", 0)
    a_score = after_grade.get("score", 0)
    if a_score < b_score:
        verdict = "improved"
    elif a_score > b_score:
        verdict = "regressed"
    else:
        verdict = "unchanged"

    return {
        "before": {
            "scan_id": before.get("scan_id"),
            "scanned_at": before.get("scanned_at"),
            "risk_grade": before_grade,
            "asr": before_asr,
            "finding_count": len(before_findings),
        },
        "after": {
            "scan_id": after.get("scan_id"),
            "scanned_at": after.get("scanned_at"),
            "risk_grade": after_grade,
            "asr": after_asr,
            "finding_count": len(after_findings),
        },
        "asr_delta": round(after_asr - before_asr, 3),
        "score_delta": a_score - b_score,
        "verdict": verdict,
        "findings_added": added,
        "findings_removed": removed,
        "findings_persisting_count": len(persisting),
        "match_method": "attack_class + title (approximate — see pwngraph.compare)",
    }
