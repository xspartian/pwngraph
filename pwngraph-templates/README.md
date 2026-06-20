# PwnGraph pwngraph-templates

Community-maintained payloads for testing AI agent security with PwnGraph.
Think of this as the **Nuclei templates** of AI agent security testing.

## Usage

Test with a single payload:
```bash
pwngraph scan --target your_agent.py:build_agent \
              --payload pwngraph-templates/attacks/tool_poisoning/email_exfil.yaml \
              --payload-only --out ./results
```

Test with an entire category:
```bash
pwngraph scan --target your_agent.py:build_agent \
              --payload pwngraph-templates/attacks/tool_poisoning/ \
              --payload-only --out ./results
```

Combine with built-in attack classes:
```bash
pwngraph scan --target your_agent.py:build_agent \
              --payload pwngraph-templates/attacks/tool_poisoning/email_exfil.yaml \
              --attacks all --out ./results
```

## Payload Library

### tool_poisoning/
| File | Description |
|------|-------------|
| `email_exfil.yaml` | Exfiltrate data via email through poisoned search result |
| `webhook_exfil.yaml` | POST sensitive data to attacker webhook |
| `code_execution.yaml` | Execute arbitrary code via poisoned tool output |

### indirect_injection/
| File | Description |
|------|-------------|
| `pdf_document.yaml` | Hidden instruction in a PDF/document the agent reads |
| `web_page_hijack.yaml` | Malicious instruction in hidden HTML div |
| `memory_context_poison.yaml` | Fake conversation history overrides agent behavior |

### prompt_exfiltration/
| File | Description |
|------|-------------|
| `system_prompt_leak.yaml` | Trick agent into revealing its system prompt |
| `role_override.yaml` | DAN-style persona hijack with canary confirmation |

### shell_injection/
| File | Description |
|------|-------------|
| `path_traversal.yaml` | Read /etc/passwd via path traversal in file tool |
| `code_exec_rce.yaml` | Execute shell commands via code/REPL tool |

### file_read_injection/
| File | Description |
|------|-------------|
| `env_file_leak.yaml` | Read .env file to leak API keys and secrets |
| `ssh_key_read.yaml` | Exfiltrate SSH private key via file read tool |

### memory_poisoning/
| File | Description |
|------|-------------|
| `false_policy_inject.yaml` | Inject fake company policy into agent memory |
| `knowledge_base_poison.yaml` | Poison RAG knowledge base with attacker directives |

### community/
Payloads contributed by the community. See [Contributing](#contributing).

## YAML Format

```yaml
name: "Human readable name"
description: >
  What this payload tests and how it works.
attack_class: tool_poisoning   # indirect_injection | tool_poisoning |
                               # prompt_exfiltration | shell_injection |
                               # file_read_injection | memory_poisoning
delivery_input: "What the user says to trigger the attack"
injection_text: |
  The malicious content. Use {canary} as placeholder —
  PwnGraph replaces it with a unique token to confirm success.
target_tool: web_search        # required for tool_poisoning
poisoned_output: |             # optional — if omitted, injection_text is used
  What the poisoned tool actually returns.
author: "Your name"
tags: [tag1, tag2]
```

## Contributing

1. Fork the repo
2. Write your payload YAML in `pwngraph-templates/community/`
3. Test it: `pwngraph scan --target examples/lab_agent/agent.py:build_agent --payload your_payload.yaml --payload-only`
4. Open a pull request

**Guidelines:**
- One payload per file
- Include a clear `description` explaining what it tests
- Use `{canary}` placeholder — never hardcode tokens
- Tag with relevant OWASP LLM categories
- Test against the lab agent before submitting
