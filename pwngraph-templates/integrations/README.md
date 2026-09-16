# PwnGraph Integration Templates

Attack templates targeting specific real-world tool integrations — Slack bots,
GitHub automation agents, Stripe payment agents, and more.

These complement the core attack-class templates (which target generic tools
like `web_search`, `send_email`, `run_command`). Integration templates target
the specific tool names used by real production agents.

## Structure

```
integrations/
├── slack/     ← agents with post_to_slack, invite_user, delete_message
├── github/    ← agents with create_pr, push_code, delete_branch
└── stripe/    ← agents with charge_card, create_refund, update_customer
```

## Adding a new integration

1. Create a folder named after the platform (e.g. `jira/`, `twilio/`, `aws/`)
2. Write templates using the standard schema (see root README.md)
3. Use the exact tool names the target agent exposes
4. Prefix the template `id` with the platform: `slack-channel-hijack`, `github-malicious-pr`
5. Open a PR

## Rules

- Target tools must be real production tool names — not generic ones
- Each template must have `requires_tool` set so PwnGraph skips it when the tool is absent
- Use placeholder values only — no real credentials, no live endpoints
- Test against a real agent before submitting
