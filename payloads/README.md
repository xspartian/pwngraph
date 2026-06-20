# Sample Payloads

Static reference corpus of attacker-controlled documents and tool responses.
These illustrate every template the runtime fuzzer generates. They're useful
for:

* **Manual testing.** Drop one into a tool that reads files or web pages and
  observe what the target agent does.
* **Regression.** Verify a defense by pointing it at this corpus and
  asserting none of them succeed.
* **Education.** Read these to understand the indirect prompt injection and
  tool output poisoning attack surface.

## Layout

One folder per attack class, mirroring `pwngraph/fuzzer/`. Each folder maps to
its OWASP LLM Top-10 (2025) categories.

```
payloads/
├── indirect_injection/    # LLM01, LLM08 — poisoned documents the agent reads
│   ├── 01_instruction_override.md
│   ├── 02_html_hidden.html
│   ├── 03_markdown_link.md
│   └── 04_action_injection.txt
├── tool_poisoning/        # LLM01, LLM05 — malicious responses from mocked tools
│   ├── 01_trailing_directive.txt
│   ├── 02_structured_json.json
│   ├── 03_multi_step_chain.txt
│   └── 04_citation_inject.txt
├── prompt_exfiltration/   # LLM07, LLM02 — trick the agent into leaking its prompt
│   ├── 01_repeat_instructions.txt
│   ├── 02_debug_mode.txt
│   ├── 03_hidden_json_leak.json
│   └── 04_translation_trick.md
├── shell_injection/       # LLM06, LLM05 — drive ShellTool/PythonREPL to run commands
│   ├── 01_direct_request.txt
│   ├── 02_doc_embedded_cmd.md
│   ├── 03_fake_readme_install.md
│   └── 04_ci_script.txt
├── file_read_injection/   # LLM02, LLM06 — read /etc/passwd, .env, SSH keys
│   ├── 01_direct_read.txt
│   ├── 02_traversal_disguised.txt
│   ├── 03_doc_instructs_read.md
│   └── 04_email_attachment_ref.txt
└── memory_poisoning/      # LLM01, LLM08 — inject false history / persona / policy
    ├── 01_fake_prior_system.txt
    ├── 02_false_memory_summary.txt
    ├── 03_fake_tool_memory.json
    └── 04_history_injection.txt
```

Findings escalate to **LLM06 (Excessive Agency)** whenever the chain drives a
tool action or exfiltration, regardless of entry vector.

## Canary tokens

Every sample contains a `PWN-DEMO####` canary token. If you observe one of
these tokens in your agent's output, in a tool call argument, or in a
follow-up tool response, the injection executed.

Token ranges are reserved per class so you can tell at a glance which sample
fired:

| Range          | Class                |
|----------------|----------------------|
| `PWN-DEMO000#` | indirect_injection / tool_poisoning (legacy) |
| `PWN-DEMO000[1-4]` | prompt_exfiltration |
| `PWN-DEMO001#` | shell_injection      |
| `PWN-DEMO002#` | file_read_injection  |
| `PWN-DEMO003#` | memory_poisoning     |

For shell and file-read samples, a canary appearing in a **tool result**
(not just the final answer) is the strong signal — it proves the command ran
or the file was actually read, rather than the model merely echoing the text.

The runtime fuzzer (`pwngraph/fuzzer/`) generates random `PWN-XXXXXXXX`
tokens dynamically; these static `PWN-DEMO####` tokens are reserved for
the corpus so they're distinguishable from live fuzzer output.

## Responsible use

These payloads target **your own** agents or systems where you have explicit
written permission to test. See `docs/BUG_BOUNTY.md` for authorized programs.
