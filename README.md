# bizlogic-audit

An [agent skill](https://skills.sh) that audits any codebase for **business logic vulnerabilities** — the class of bugs where intended functionality is used in unintended ways to cause harm.

## Install

```bash
npx skills add rigAITe/bizlogic-audit
```

## What It Does

When activated, the skill instructs your AI agent to:

1. **Discover the domain** — Map the application's business entities, critical operations, value flows, state machines, and trust boundaries
2. **Apply universal patterns** — Check every critical endpoint against 7 attack patterns that apply to any application (race conditions, state machine bypass, boundary violations, privilege escalation, resource lifecycle integrity, webhook/callback integrity, rate/limit bypass)
3. **Apply domain-specific patterns** — Based on the discovered domain, apply specialized patterns from 11 built-in libraries
4. **Report findings** — Document each vulnerability with code evidence, attack scenarios, and recommended fixes

## Supported Domains

The skill includes pattern libraries for:

| Domain | Example Patterns |
|--------|-----------------|
| **Fintech / Payments** | Exchange rate manipulation, spread inversion, fee injection |
| **E-Commerce / Retail** | Price manipulation, coupon stacking, inventory race conditions |
| **SaaS / Subscriptions** | Plan feature bypass, quota circumvention, trial abuse |
| **Healthcare** | Access control bypass, workflow authorization, consent enforcement |
| **Marketplace** | Escrow bypass, reputation manipulation, dispute abuse |
| **Gaming** | Virtual currency duplication, lootbox RNG manipulation, leaderboard abuse |
| **Logistics / Delivery** | Delivery confirmation fraud, routing manipulation, ETA gaming |
| **EdTech** | Grade manipulation, certification bypass, quiz answer leakage |
| **Social / Content** | Moderation bypass, engagement farming, account impersonation |
| **Insurance** | Claim duplication, policy backdating, coverage stacking |
| **Real Estate** | Bidding manipulation, escrow timing attacks, listing fraud |

For domains not listed, the skill instructs the agent to **generate custom patterns** based on the application's core business invariants.

## Sample Report

See [sample-report.md](sample-report.md) for an example of audit output — a real assessment of a crypto-to-fiat trading platform that found 7 business logic vulnerabilities including webhook forgery, race conditions, and state machine bypass.

## Compatible Agents

Works with any agent that supports skills — including Claude Code, Cursor, Copilot, Gemini, and [37 more](https://github.com/vercel-labs/skills#supported-agents).

## License

MIT
