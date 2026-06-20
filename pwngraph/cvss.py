"""CVSS 3.1 vector builder for pwngraph findings.

We derive CVSS 3.1 base vectors from the attack class and edge mix rather than
asking the user to fill them in manually. The mapping is conservative (we score
the most common exploitation scenario for each class, not a best-case scenario).

Each attack class maps to a CVSS 3.1 base vector and score.  The data exfil
escalation and shell/file-read escalations are handled as modifiers.

Scoring follows the CVSS 3.1 specification:
  https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

from pwngraph.types import EdgeType, Severity

# Base vectors keyed by (attack_class, highest_edge_type).
# Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
#          AV = Attack Vector   (N=Network, A=Adjacent, L=Local, P=Physical)
#          AC = Attack Complexity (L=Low, H=High)
#          PR = Privileges Required (N=None, L=Low, H=High)
#          UI = User Interaction  (N=None, R=Required)
#          S  = Scope             (U=Unchanged, C=Changed)
#          C  = Confidentiality   (N=None, L=Low, H=High)
#          I  = Integrity         (N=None, L=Low, H=High)
#          A  = Availability      (N=None, L=Low, H=High)

_VECTORS: dict[tuple[str, str], tuple[str, float]] = {
    # --- indirect_injection ---
    ("indirect_injection", "data_exfil"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 9.3),
    ("indirect_injection", "tool_manipulation"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N", 8.2),
    ("indirect_injection", "context_poisoning"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    ("indirect_injection", "direct_injection"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),

    # --- tool_poisoning ---
    ("tool_poisoning", "data_exfil"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", 9.0),
    ("tool_poisoning", "tool_manipulation"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N", 8.0),
    ("tool_poisoning", "context_poisoning"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.9),

    # --- prompt_exfiltration ---
    ("prompt_exfiltration", "data_exfil"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 7.4),
    ("prompt_exfiltration", "context_poisoning"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
    ("prompt_exfiltration", "direct_injection"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),

    # --- shell_injection ---
    ("shell_injection", "tool_manipulation"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6),
    ("shell_injection", "data_exfil"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6),
    ("shell_injection", "context_poisoning"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.3),

    # --- file_read_injection ---
    ("file_read_injection", "data_exfil"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 7.4),
    ("file_read_injection", "tool_manipulation"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 7.4),
    ("file_read_injection", "context_poisoning"):
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),

    # --- memory_poisoning ---
    ("memory_poisoning", "context_poisoning"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N", 8.0),
    ("memory_poisoning", "tool_manipulation"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N", 8.0),
    ("memory_poisoning", "direct_injection"):
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
}

_EDGE_PRIORITY = [
    EdgeType.DATA_EXFIL,
    EdgeType.TOOL_MANIPULATION,
    EdgeType.CONTEXT_POISONING,
    EdgeType.DIRECT_INJECTION,
    EdgeType.NORMAL_FLOW,
]

_DEFAULT_VECTOR = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4)


def cvss_for(attack_class: str, edge_types: list[EdgeType]) -> tuple[str, float]:
    """Return (CVSS_3.1_vector_string, base_score) for a finding.

    Picks the highest-priority adversarial edge type (data_exfil > tool_manipulation
    > context_poisoning > direct_injection) then looks up the table above.
    Falls back to a conservative Medium if no exact entry is found.
    """
    dominant = EdgeType.NORMAL_FLOW
    for prio in _EDGE_PRIORITY:
        if prio in edge_types:
            dominant = prio
            break

    key = (attack_class, dominant.value)
    return _VECTORS.get(key, _DEFAULT_VECTOR)


def severity_from_cvss(score: float) -> Severity:
    """CVSS 3.1 score → Severity bucket (mirrors our existing Severity enum)."""
    if score == 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL
