# Changelog

All notable changes to PwnGraph are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); dates are added
once a change actually ships in a tagged release rather than backfilled.

## [1.0.0]

Initial public release.

### Engine

- Six-stage pipeline — Connector → Recon → Fuzzer → Tracer → Behavioral
  Oracle → Graph Builder — that attaches to a live agent, profiles its real
  tool surface, and fuzzes it adaptively rather than firing a fixed batch of
  payloads.
- **NEXUS**, the adaptive control loop: every scan probes one payload at a
  time, reads the Oracle's verdict, and decides what to try next
  (ENUMERATE → PLAN → PROBE → OBSERVE → EVALUATE → REASON → ADAPT →
  GENERATE) until it exhausts its budget or runs out of genuine leads. A
  safety gate screens every generated payload before delivery, and
  `--authorized` is required for any scan.
- **Pre-attack recon**: before any adversarial payload, a few benign
  meta-questions elicit the agent's stated purpose and a capped set of
  compound queries confirm which tools actually chain into which — producing
  a ranked attack plan instead of testing every class blind.
- Every attack payload is generated fresh by an LLM at scan time, grounded in
  the target's real tool schema and the Oracle's own signals from recent
  failed attempts — no fixed template strings.
- A six-signal behavioral oracle (canary-in-tool-argument, confirmed shell
  execution, sensitive-content detection, system-prompt leak, behavioral
  divergence from baseline, deceptive human-directed recommendation) with
  Wilson-interval Attack Success Rate, so a finding requires demonstrated
  behavior change, not a string match.

### Attack coverage

- Six attack classes: indirect injection, tool output poisoning, system
  prompt exfiltration, shell/code injection, sensitive file read, and
  memory/history poisoning — each mapped to the OWASP LLM Top 10 (2025) and
  the OWASP Top 10 for Agentic Applications (2026).
- Nuclei-style YAML attack templates (`pwngraph-templates/`) for
  community-contributed payloads and real-world integration attacks
  (GitHub, Slack, Stripe), runnable via `--payload` alongside or instead of
  the built-in classes.
- AST-based static analysis reconciled against the runtime graph — a
  possible/observed/validated/exploited evidence ladder for the target's
  full tool surface, not just what a given scan happened to trigger.

- **Channel-aware oracle**: a hijack counts only when attacker content
  reached the agent through an untrusted channel (a document, web page or
  tool result). An action the user's own message asked for is logged as
  user-requested, not reported as a finding.
- `--budget` is exact: NEXUS spends every probe unless `--early-stop` is
  passed, and reports `probes sent N/budget` with the reason when it stops
  short.

### Framework support

- Full runtime interception for LangChain and LangGraph agents
  (callback-level), plus a structurally-detected shim for
  framework-less, hand-rolled Python agents — `pwngraph init` uses an AI agent to
  explore the repo, write `adapter.py`, and validate it against the real agent.

### Reporting & storage

- Every scan's graph, findings, ASR, OWASP coverage, and risk grade persist
  to Neo4j and are browsable live via `pwngraph serve` (FastAPI + React +
  Sigma.js/Graphology) — Profile, Attack graph, Findings, Logs, and Report
  tabs, with no export step required.
- CVSS 3.1 vector + score and OWASP tagging on every finding, SARIF export
  for CI/GitHub Advanced Security integration, and per-finding PoC bundles
  (payload, replay command, write-up).
- `pwngraph query` — a portable named-query library over the graph
  (`scans`, `evidence-coverage`, `dangerous-outcomes`, `blast-radius`, and
  more) with `--json` output for scripting.
- `pwngraph diff` — re-scan and compare against a saved baseline, with a
  severity- and risk-grade-aware CI regression gate.
- A Python API (`PwnGraph`) for CI gates and before/after defense
  evaluation (`defense_diff`), alongside the CLI.
