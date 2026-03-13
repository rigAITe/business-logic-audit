# business-logic-audit

An [agent skill](https://skills.sh) that audits any codebase for **business logic vulnerabilities** — the class of bugs where intended functionality is used in unintended ways to cause harm. Covers **backend, frontend, and mobile** logic.

## Install

```bash
npx skills add rigAITe/business-logic-audit
```

## What It Does

When activated, the skill instructs your AI agent to:

1. **Discover the domain** — Map the application's business entities, critical operations, value flows, state machines, trust boundaries, and architecture type (backend, frontend, mobile, or full-stack)
2. **Quick-start scan** — Run a rapid 10-point checklist covering the most critical patterns before diving deep
3. **Apply universal backend patterns** — Check every critical endpoint against 13 attack patterns that apply to any backend (race conditions, state machine bypass, boundary violations, privilege escalation, resource lifecycle integrity, webhook/callback integrity, rate/limit bypass, event queue integrity, batch operation abuse, caching exploits, API architecture abuse, microservices trust gaps, notification channel abuse)
4. **Apply frontend patterns** — Check every web client against 6 patterns targeting client-side business logic (authorization leaks, state manipulation, API over-exposure, workflow integrity, bundle secrets, abuse prevention gaps)
5. **Apply mobile patterns** — Check every native/hybrid app against 5 mobile-specific patterns (local security bypass, insecure storage, deep link hijacking, in-app purchase receipt validation, inter-process communication abuse)
6. **Apply domain-specific patterns** — Based on the discovered domain, apply specialized patterns from 18 built-in libraries
7. **Report findings** — Document each vulnerability with code evidence, layer identification (backend/frontend/mobile/full-stack), attack scenarios, and recommended fixes

## Supported Domains

The skill includes pattern libraries for:

| Domain | Example Patterns |
|--------|-----------------:|
| **Fintech / Payments** | Exchange rate manipulation, spread inversion, fee injection, referral abuse |
| **E-Commerce / Retail** | Price manipulation, coupon stacking, inventory race conditions, return fraud |
| **SaaS / Subscriptions** | Plan feature bypass, quota circumvention, trial abuse, tenant isolation |
| **Healthcare** | Access control bypass, workflow authorization, consent enforcement, appointment abuse |
| **Marketplace** | Escrow bypass, reputation manipulation, dispute abuse, shill bidding |
| **Gaming** | Virtual currency duplication, lootbox RNG manipulation, leaderboard abuse |
| **Logistics / Delivery** | Delivery confirmation fraud, routing manipulation, ETA gaming |
| **EdTech** | Grade manipulation, certification bypass, quiz answer leakage |
| **Social / Content** | Moderation bypass, engagement farming, account impersonation |
| **Insurance** | Claim duplication, policy backdating, coverage stacking |
| **Real Estate** | Bidding manipulation, escrow timing attacks, listing fraud |
| **FinOps / Banking** | Loan origination fraud, interest calculation gaming, overdraft bypass |
| **Crypto / Web3 / DeFi** | Oracle manipulation, bridge integrity, airdrop duplication, NFT ownership bypass |
| **HR / Payroll** | Payroll manipulation, time tracking fraud, expense duplication |
| **Legal / RegTech** | KYC bypass, sanctions evasion, audit trail integrity |
| **IoT / Industrial** | Device command injection, firmware bypass, sensor data spoofing |
| **Travel / Hospitality** | Fare construction abuse, loyalty point manipulation, dynamic pricing exploitation |
| **Ad Tech / Marketing** | Click fraud, attribution manipulation, budget exhaustion attacks |

For domains not listed, the skill instructs the agent to **generate custom patterns** based on the application's core business invariants.

## Pattern Coverage

| Layer | Patterns | Examples |
|-------|----------|----------|
| **Backend** | 13 universal | Race conditions, state machine bypass, webhook integrity, API architecture abuse, microservices trust gaps |
| **Frontend** | 6 web-specific | Client-side auth leaks, state manipulation, bundle secrets, API over-exposure |
| **Mobile** | 5 native/hybrid | Insecure storage, deep link hijacking, IAP receipt forgery, IPC abuse |
| **Domain** | 18 libraries | Fintech, crypto, e-commerce, SaaS, healthcare, and 13 more |

## Usage

To trigger the skill, prompt your agent with:

```
Audit this codebase for business logic vulnerabilities
```

If you have **multiple projects** in your workspace or want to target a specific one:

```
Audit this codebase for business logic vulnerabilities @path/to/project
```

### More Prompts

| Goal | Prompt |
|------|--------|
| **Full audit** | `Audit this codebase for business logic vulnerabilities` |
| **Quick scan** | `Run a quick business logic security scan using the quick-start checklist` |
| **Backend only** | `Audit the backend for business logic flaws — focus on the API layer` |
| **Frontend only** | `Check this frontend for business logic vulnerabilities` |
| **Mobile only** | `Audit this mobile app for business logic and mobile-specific security issues` |
| **Specific concern** | `Check for race conditions and state machine bypass in the transaction flows` |
| **Specific domain** | `Audit this codebase for fintech business logic vulnerabilities` |

## Sample Report

See [sample-report.md](sample-report.md) for an example of audit output — an assessment of a crypto-to-fiat trading platform with a React Native mobile app, demonstrating 9 findings across backend, frontend, and mobile layers.

## Report Output

After each audit, the skill saves the report to your project:

```
your-project/
└── business-logic-audit/
    ├── report-2026-03-13.md    ← for agent UIs, GitHub, markdown renderers
    ├── report-2026-03-13.html  ← for sharing, opens styled in any browser
    └── report-2026-03-13.pdf   ← auto-generated via Chrome headless
```

Reports are timestamped so re-running the audit preserves history. Consider adding `business-logic-audit/` to your `.gitignore` since reports may contain sensitive vulnerability details.

## Compatible Agents

Works with any agent that supports skills — including Claude Code, Cursor, Copilot, Gemini, and [37 more](https://github.com/vercel-labs/skills#supported-agents).

## License

MIT
