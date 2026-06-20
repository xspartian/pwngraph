"""OWASP Top 10 for LLM Applications (2025) mapping layer.

PwnGraph is a *dynamic, runtime, agentic* security tool. It tests by actually
executing the target agent and observing multi-hop behavior. That makes it the
authoritative tool for the **behavioral subset** of the OWASP LLM Top 10 — and
a poor fit for the static / training-time / quality categories.

We are deliberately honest about scope. Claiming to cover supply-chain or
training-data poisoning with a runtime fuzzer would be misleading; this module
encodes exactly which categories pwngraph can and cannot test, and why.

Reference: https://genai.owasp.org/llm-top-10/  (2025 list)
"""

from __future__ import annotations

from pwngraph.types import EdgeType

# ---------------------------------------------------------------------------
# The list (2025)
# ---------------------------------------------------------------------------

LLM_TOP_10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# ---------------------------------------------------------------------------
# Scope honesty
# ---------------------------------------------------------------------------

# Categories pwngraph cannot meaningfully test by runtime agent fuzzing.
OUT_OF_SCOPE: dict[str, str] = {
    "LLM03": (
        "Supply-chain / dependency & model provenance — a static software-"
        "composition concern, not observable runtime agent behavior."
    ),
    "LLM04": (
        "Training- and fine-tuning-time data poisoning & model backdoors — "
        "introduced before deployment, invisible to black-box runtime fuzzing."
    ),
    "LLM09": (
        "Misinformation / hallucination — a model-quality concern that requires "
        "ground-truth datasets to measure, not an exploit with a behavioral oracle."
    ),
}

# Categories we can reach but only partially today (the slice we reach is noted).
PARTIAL: dict[str, str] = {
    "LLM08": (
        "Vector & embedding weaknesses — we reach the *retrieval-poisoning* slice "
        "(poisoned content the agent retrieves and acts on) via indirect injection; "
        "embedding inversion and cross-tenant leakage are infra-level and out of scope."
    ),
    "LLM10": (
        "Unbounded consumption — cost/loop amplification is reachable but not yet "
        "implemented as a dedicated attack class (planned)."
    ),
}

# ---------------------------------------------------------------------------
# Attack-class → OWASP base mapping
# ---------------------------------------------------------------------------

# Primary + applicable IDs each attack class demonstrates.
CLASS_TO_OWASP: dict[str, list[str]] = {
    "indirect_injection":   ["LLM01", "LLM08"],
    "tool_poisoning":       ["LLM01", "LLM05"],
    "prompt_exfiltration":  ["LLM07", "LLM02"],
    "shell_injection":      ["LLM06", "LLM05"],
    "file_read_injection":  ["LLM02", "LLM06"],
    "memory_poisoning":     ["LLM01", "LLM08"],
}


def owasp_for_finding(attack_class: str, edge_types: list[EdgeType]) -> list[str]:
    """Return the OWASP LLM IDs a finding demonstrates.

    Starts from the attack class's base mapping, then escalates by *observed
    impact*: any finding whose chain drove a tool action or exfiltration is, by
    definition, an instance of **Excessive Agency (LLM06)** — the agent did more
    than it should have — regardless of the entry vector. Exfiltration also
    implies **Sensitive Information Disclosure (LLM02)**.
    """
    ids = list(CLASS_TO_OWASP.get(attack_class, ["LLM01"]))

    if any(e in (EdgeType.DATA_EXFIL, EdgeType.TOOL_MANIPULATION) for e in edge_types):
        if "LLM06" not in ids:
            ids.append("LLM06")
    if EdgeType.DATA_EXFIL in edge_types and "LLM02" not in ids:
        ids.append("LLM02")

    # Stable, human-readable order.
    return sorted(set(ids))


def label(owasp_id: str) -> str:
    """'LLM06' -> 'LLM06: Excessive Agency'."""
    name = LLM_TOP_10.get(owasp_id)
    return f"{owasp_id}: {name}" if name else owasp_id


# ---------------------------------------------------------------------------
# Coverage matrix — the CFP artifact
# ---------------------------------------------------------------------------

def coverage_matrix(findings: list) -> list[dict]:
    """Build an honest coverage row for every one of the 10 categories.

    Status is one of:
      * "detected"     — at least one finding was tagged with this ID
      * "tested"       — an attack class maps here but produced no finding this run
      * "partial"      — only a slice is reachable (see PARTIAL note)
      * "out-of-scope" — structurally not a runtime-fuzzing concern (see reason)
    """
    # Count findings per ID.
    hit_counts: dict[str, int] = {}
    for f in findings:
        for oid in getattr(f, "owasp", []) or []:
            hit_counts[oid] = hit_counts.get(oid, 0) + 1

    mapped_ids = {oid for ids in CLASS_TO_OWASP.values() for oid in ids}

    rows: list[dict] = []
    for oid, name in LLM_TOP_10.items():
        if oid in hit_counts:
            status, detail = "detected", f"{hit_counts[oid]} finding(s) this scan"
        elif oid in OUT_OF_SCOPE:
            status, detail = "out-of-scope", OUT_OF_SCOPE[oid]
        elif oid in PARTIAL:
            status, detail = "partial", PARTIAL[oid]
        elif oid in mapped_ids:
            status, detail = "tested", "attack class exercised this category; no finding this run"
        else:
            status, detail = "out-of-scope", "no dynamic test maps to this category"
        rows.append({
            "id": oid,
            "name": name,
            "status": status,
            "detail": detail,
            "count": hit_counts.get(oid, 0),
        })
    return rows
