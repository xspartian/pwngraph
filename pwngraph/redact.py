"""Redact credential-shaped values before they reach a persisted artifact.

The BehavioralOracle's sensitive-content signal (``pwngraph.oracle``) proves
an attack worked by matching the *real* value a tool returned — a private
key, an AWS credential pair, a ``.env`` secret, an API key. That match has to
stay raw for the oracle to score the run — it is not this module's job to
change what happened. But nothing downstream of that scoring needs the
literal value: ``trace.json``, the Neo4j node content ``pwngraph serve``
displays, ``findings.sarif`` (built to be uploaded into CI), and ``poc/``
bundles are all either shared, long-lived, or leave the machine entirely. A
tool whose whole premise is "prove this agent leaked a secret" should not
then leak that same secret a second time out of its own report.

``redact_secrets`` is applied only at that boundary — see
``pwngraph.core.PwnGraph.scan`` — never to the in-memory ``TraceEvent``
content the oracle and graph builder reason about, so canary propagation and
exfil-destination classification (which key off some of the same shapes as
an attacker-planted IOC, not a real secret) are unaffected.
"""

from __future__ import annotations

import re

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.S
)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET_ASSIGN_RE = re.compile(r"(aws_secret_access_key\s*=\s*)(\S+)", re.I)
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
# Generic `.env`-shaped assignment: API_KEY=..., SECRET_KEY=..., PASSWORD=...,
# TOKEN=... — the same shape the oracle's own _SENSITIVE_CONTENT_RE looks for.
_ENV_ASSIGN_RE = re.compile(r"\b((?:API|SECRET|PRIVATE)_?KEY|PASSWORD|TOKEN)(\s*=\s*)(\S+)", re.I)


def _mask(value: str) -> str:
    """Keep the first/last 4 chars — enough to confirm a match, not enough
    to use the value — and blank the middle."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _redact_private_key_block(m: re.Match[str]) -> str:
    block = m.group(0)
    first_nl = block.find("\n")
    last_nl = block.rfind("\n")
    if first_nl == -1 or last_nl == -1 or first_nl == last_nl:
        return "-----REDACTED PRIVATE KEY-----"
    return f"{block[:first_nl]}\n[REDACTED]\n{block[last_nl + 1 :]}"


def redact_secrets(text: str) -> str:
    """Mask credential-shaped substrings in *text*, keeping structure and
    just enough context to confirm what matched.

    Idempotent and cheap — safe to call on text that has no secrets in it
    (the common case), and safe to call twice on the same text.
    """
    if not text:
        return text
    text = _PRIVATE_KEY_RE.sub(_redact_private_key_block, text)
    text = _AWS_ACCESS_KEY_RE.sub(lambda m: _mask(m.group(0)), text)
    text = _AWS_SECRET_ASSIGN_RE.sub(lambda m: m.group(1) + _mask(m.group(2)), text)
    text = _OPENAI_KEY_RE.sub(lambda m: _mask(m.group(0)), text)
    text = _ENV_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{_mask(m.group(3))}", text)
    return text
