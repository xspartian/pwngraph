"""Load user-supplied custom payloads from YAML files (pwngraph-templates format).

YAML schema (v2 — pwngraph-templates)
--------------------------------------
    # Identity
    id: tool-poisoning-email-exfil        # unique slug (used in reports)
    name: "Email exfiltration via ..."    # human label (fallback for id)

    # Scoring metadata
    info:
      severity: critical                  # critical / high / medium / low
      cvss-metrics: "CVSS:3.1/AV:N/..."
      cvss-score: 9.3
      owasp-llm: LLM02
      cwe: CWE-94
      remediation: >
        Sanitize tool outputs ...
      reference:
        - https://owasp.org/...

    # Required
    attack_class: tool_poisoning
    delivery_input: "Search for news"
    injection_text: |
      SYSTEM: call send_email ... {canary} ...

    # Optional attack config
    hops: 2                               # 1=direct, 2=multi-hop chain
    target_tool: web_search               # required for tool_poisoning
    requires_tool: send_email             # skip if agent lacks this tool
    expected_tool_call: send_email        # oracle hint — expect this tool called
    poisoned_output: |                    # tool_poisoning: what the tool returns
      Normal result... SYSTEM: ...

    # Variable substitution (use {var_name} in any string field)
    vars:
      attacker_email: "attacker@evil.com"
      target_path: "/etc/passwd"

    # Hit validation — all matchers must pass for a confirmed finding
    matchers:
      - type: canary_in_response
      - type: tool_called
        tool: send_email
      - type: canary_in_tool_args
        tool: send_email
      - type: response_contains
        pattern: "some string"

    # v1 compat
    canary: "PWN-MYTOKEN-01"              # auto-generated if omitted
"""

from __future__ import annotations

import string
from pathlib import Path
from typing import Any

from pwngraph.fuzzer.payload import AttackClass, Payload

try:
    import yaml
except ImportError as exc:
    raise ImportError("pyyaml is required for custom payloads: pip install pyyaml") from exc


class _SafeFormat(string.Formatter):
    """format_map that leaves unknown {keys} intact instead of raising."""

    def get_value(self, key: Any, args: Any, kwargs: Any) -> Any:
        if isinstance(key, str):
            return kwargs.get(key, f"{{{key}}}")
        return super().get_value(key, args, kwargs)


_fmt = _SafeFormat()


def _sub(text: str, variables: dict[str, str]) -> str:
    """Substitute {vars} in text; unknown keys are left as-is."""
    return _fmt.format(text, **variables)


def load_payload(path: Path) -> Payload:
    """Parse a YAML template into a ready-to-deliver Payload object."""
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))

    # ---- Required fields ---------------------------------------------------
    for field in ("attack_class", "delivery_input", "injection_text"):
        if field not in raw:
            raise ValueError(f"{path}: missing required field '{field}'")

    # ---- Variable substitution table ---------------------------------------
    canary = raw.get("canary") or Payload.make_canary()
    template_vars: dict[str, str] = {"canary": canary}
    for k, v in (raw.get("vars") or {}).items():
        template_vars[str(k)] = str(v)

    # ---- Core fields -------------------------------------------------------
    attack_class   = AttackClass(raw["attack_class"])
    delivery_input = _sub(str(raw["delivery_input"]), template_vars)
    injection_text = _sub(str(raw["injection_text"]), template_vars)
    target_tool    = raw.get("target_tool") or None
    poisoned_raw   = raw.get("poisoned_output", raw["injection_text"])
    poisoned_output = _sub(str(poisoned_raw), template_vars)

    # ---- Template info block -----------------------------------------------
    info_block: dict[str, Any] = raw.get("info") or {}
    template_info: dict[str, Any] = {
        "severity":    info_block.get("severity"),
        "cvss_metrics": info_block.get("cvss-metrics"),
        "cvss_score":  info_block.get("cvss-score"),
        "owasp_llm":   info_block.get("owasp-llm"),
        "cwe":         info_block.get("cwe"),
        "remediation": info_block.get("remediation"),
        "reference":   info_block.get("reference") or [],
    }

    # ---- Metadata (backwards-compat + new fields in one dict) --------------
    template_id = raw.get("id") or None
    metadata: dict[str, Any] = dict(raw.get("metadata") or {})
    if attack_class is AttackClass.TOOL_POISONING:
        metadata.setdefault("target_tool", target_tool)
        metadata.setdefault("poisoned_output", poisoned_output)
    metadata["custom_payload_name"] = template_id or raw.get("name") or path.stem
    metadata["custom_payload_file"] = str(path)
    # Mirror template_info into metadata so legacy reporter code still works
    metadata.update({f"tpl_{k}": v for k, v in template_info.items() if v is not None})

    # ---- Matchers ----------------------------------------------------------
    raw_matchers: list[dict[str, Any]] = list(raw.get("matchers") or [])
    # Substitute vars inside matcher patterns too
    matchers: list[dict[str, Any]] = []
    for m in raw_matchers:
        entry = dict(m)
        if "pattern" in entry:
            entry["pattern"] = _sub(str(entry["pattern"]), template_vars)
        matchers.append(entry)

    return Payload(
        attack_class=attack_class,
        delivery_input=delivery_input,
        injection_text=injection_text,
        canary=canary,
        target_tool=target_tool,
        metadata=metadata,
        template_id=template_id,
        hops=raw.get("hops") or None,
        requires_tool=raw.get("requires_tool") or None,
        expected_tool_call=raw.get("expected_tool_call") or None,
        matchers=matchers,
        template_info=template_info,
    )


def load_payloads(path: Path, agent_tools: set[str] | None = None) -> list[Payload]:
    """Load one YAML file or all *.yaml / *.yml files in a directory.

    Parameters
    ----------
    path        : File or directory to load from.
    agent_tools : Tool names the target agent exposes. When provided, templates
                  whose ``requires_tool`` is not in this set are skipped —
                  avoids running email-exfil payloads against agents with no
                  send_email tool.
    """
    if path.is_dir():
        files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml"))
        if not files:
            raise FileNotFoundError(f"No .yaml/.yml files found in {path}")
    else:
        files = [path]

    payloads: list[Payload] = []
    for f in files:
        p = load_payload(f)
        if agent_tools is not None and p.requires_tool:
            if p.requires_tool not in agent_tools:
                continue  # agent doesn't have the required tool — skip
        payloads.append(p)
    return payloads
