# OWASP AI SecureShop v2 — Quick Start

This guide assumes the supported installation has completed. OWASP AI SecureShop is an
intentionally vulnerable e-commerce app with its own authentication boundary.

## 1. Boot

```bash
./start_all.sh
# → open http://localhost:3000/secureshop
```

`start_all.sh` runs the controlled backend and frontend process tree in the
foreground. With OWASP AI SecureShop enabled, the backend supervises its configured
Agent Host. The launcher does not start Ollama. Start the configured provider
separately before launch; for local Ollama, run `ollama serve` in another
terminal. A mock fallback is controlled-test or ungraded behavior and is not
genuine model or objective-credit evidence.

Press Ctrl+C in the launcher terminal, or run `./stop_all.sh` to request
shutdown of that workspace's owned application process tree. It does not stop a
shared Ollama service, PostgreSQL, or retained Docker sidecar containers.

Guests can browse the catalog at `/secureshop`. OWASP AI SecureShop has its own sign-in
at `/secureshop/login`; a workshop login is neither required nor accepted as a
shop login.

## 2. Log in with a OWASP AI SecureShop practice account

Fresh installations create the following accounts once. All three passwords
are `student123` (with no space). Existing installations preserve changed or
removed accounts on repeat initialization.

| Username | Role | Primary signed-in route |
|---|---|---|
| `student_customer` | Customer | `/secureshop/home` |
| `student_merchant` | Merchant | `/secureshop/merchant` |
| `student_admin` | Shop administrator | `/secureshop/admin` |

These are synthetic shop identities. A OWASP AI SecureShop administrator is not a OWASP Agentic AI GOAT
platform administrator and cannot manage workshop authority. Customer and
merchant registration is also available from the shop sign-in page.

## 3. The AgentLane concept in one paragraph

Agent-backed turns run through a role supervisor. Depending on the flow, it
dispatches a launch-bound local tool or a task agent over MCP-style SSE. The
AgentLane shows the recorded decisions, calls and results that are available to
the current shop session. A trace helps explain a run, but a successful request
or trace row alone does not establish objective completion; graded objectives
use their separate effect and Judge path.

Treat natural-language limits as part of the lesson, not as an enforcement
boundary. In the current installed inventory evidence, a request to check
product 129 and **not** change inventory led the genuine model to call
`set_stock` and change its own synthetic stock from 0 to 20. The rendered card
and trace prove that effect, but the run earned no read-only task or Judge
credit and does not prove cross-merchant access.

## 4. Choose a current learner surface

Each account exposes a different navigation set:

- Customer: catalog, cart, checkout, orders, account and inbox.
- Merchant: listings, reviews, pricing, analytics and inbox.
- Shop administrator: users, audit, policies, MCP, access controls and system.

Use [`VULNERABILITIES.md`](VULNERABILITIES.md) as the generated inventory of
intentional teaching sinks. Availability of a page does not mean every optional
owned service or graded workflow is active. Check the page's readiness state and
the exercise instructions before running a scenario.

## 5. Optional owned capabilities

Ordinary startup verifies configured resources; it does not provision missing
optional services. Use the supported setup flags and keep a capability disabled
until its setup and readiness checks pass:

- Strict policy rendering: follow the paired `--owned-policy-renderer` and
  `--enable-owned-policy-renderer` commands in the
  [installation guide](../install/INSTALLATION.md#optional-owned-strict-policy-renderer).
- Listings: follow the opt-in preparation and activation contract in the
  [Owned Listings guide](../install/owned-listings.md). Current evidence covers
  one vulnerable-mode fetch of an owned internal training URL and a Judge award;
  the equivalent fixed-mode denial remains pending.
- System diagnostics: follow the current recovery, configuration and
  qualification limits in
  [owned-system-diagnostics.md](owned-system-diagnostics.md).

Do not enable a private environment switch by hand to bypass the installer or a
readiness gate. Controlled tests and the scoped installed results above do not
establish overall workflow or release readiness.

## 6. Where to go next

- [`VULNERABILITIES.md`](VULNERABILITIES.md) — full catalog of every
  intentional vuln, auto-generated from source annotations.
- [`AGENTS.md`](AGENTS.md) — one paragraph per task agent, so you can see
  the whole attack surface at a glance.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — the topology diagram and request
  flow. Read this before writing new task agents.

## Safety reminder

OWASP AI SecureShop v2 is **deliberately vulnerable**. Do not deploy it. Do not
expose it to the public internet. Every `@intentional-vulnerability` tag
in the code marks a teaching sink that must not be "fixed" — the
`npm run verify:secureshop:vuln-coverage` check fails if you accidentally
remove one.
