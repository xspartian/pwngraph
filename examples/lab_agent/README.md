# lab_agent — PwnGraph Sandbox Target

> A generic, 5-tool agent used as a quick-start test target for PwnGraph.
> **No API key required** — it runs on a deterministic mock LLM, so scans are
> fast and reproducible. (Set `OPENAI_API_KEY` to run it against a real LLM.)

## What it is

`lab_agent` is a minimal LangChain-style agent that exposes one of every tool
category PwnGraph's attack classes target. It's not a realistic product like
[`hr_agent`](../hr_agent/) — it's a clean sandbox for exercising the scanner
across all six attack classes at once.

## Tools

| Tool | Category | Used by attack class |
|------|----------|----------------------|
| `read_file` | file read | `indirect_injection`, `file_read_injection` |
| `web_search` | data fetch | `tool_poisoning`, `indirect_injection` |
| `send_email` | action sink (outbound) | exfiltration chains |
| `http_post` | action sink (webhook) | exfiltration chains |
| `run_code` | code execution | `shell_injection` |

The mock LLM is **intentionally gullible**: when a tool result carries a planted
canary plus an embedded instruction, it obeys — routing to whichever action sink
the instruction names. This is what makes the lab agent exploitable end-to-end
so PwnGraph can discover structurally distinct attack chains (email exfil,
webhook exfil, code execution).

## Run the scan

```bash
# Full scan, all 6 attack classes:
pwngraph scan --target examples/lab_agent/agent.py:build_agent \
              --attacks all --budget 30 --authorized --out ./results

# Single attack class:
pwngraph scan --target examples/lab_agent/agent.py:build_agent \
              --attacks tool_poisoning --budget 30 --authorized --out ./results
```

## Run it standalone

```bash
python examples/lab_agent/run_agent.py            # mock LLM
python examples/lab_agent/run_agent.py --real     # real LLM (needs OPENAI_API_KEY)
```

---

*lab_agent is intentionally insecure for demonstration and testing. Do not reuse
its code in production.*
