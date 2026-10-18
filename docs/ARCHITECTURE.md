# DVAIA Architecture

DVAIA runs a single Express application that hosts two logically separate
worlds side by side:

1. **Platform layer** — production-grade secure code (auth, sessions, audit
   logging, admin dashboard).
2. **Challenge layer** — deliberately vulnerable routes and isolated challenge
   stores used for hands-on learning.

Fresh setup provisions PostgreSQL 18 with 16 isolated application databases
and separate runtime/migration roles. `server/index.js` rejects startup unless
both application database engines are `postgres`, acquires the application
maintenance lease, and then constructs the server. The supported application
and all 17 SecureShop agents do not load SQLite or MySQL drivers.

`server/secureServer.js` is retained only as an explicit retirement guard; it
throws before importing its historical database managers. Use `npm run server`
or `npm run dev`. The AWS Node 18 assets remain frozen historical deployment
material and are not qualified for this PostgreSQL-only runtime.

---

## Request flow

```
React / Vite (port 3000)
      │
      ▼
Express (port 8081) ─► PostgreSQL identity/configuration/progress
      │              ─► isolated PostgreSQL challenge databases
      │              ─► LangGraph / LangChain ─► Ollama (port 11434)
      │              ─► Bedrock / OpenAI / Anthropic  ── optional fallback
      │
      └──► Agent Host (port 8082)  ── SecureShop v2 MCP servers
```

- **React** — dev server on `3000`; the production bundle can be served by the
  supported Express application.
- **Express** — REST API on `8081`. Database-backed HTTP revision polling
  propagates workshop, admin, and leaderboard changes without socket-specific
  proxy or session-affinity requirements. Routes are grouped one file per
  feature or challenge in `server/routes/`.
- **Ollama** — local LLM engine on `11434`. Default model `llama3.1:8b`.
  Some adapters expose clearly marked offline responses when unavailable. Mock/fallback output does not prove a real model decision or earn objective credit.
- **LangChain and LangGraph** — installed Node dependencies. LangChain owns
  provider messages and typed model/tool calls; LangGraph owns observable
  branches, validation, bounded repair, tools, persistence and objective
  judging for migrated families. Neither framework requires an API key.
- **SecureShop Agent Host** — 17 MCP servers on `8082` (see the SecureShop
  docs).

---

## Platform vs. challenge split

| Concern | Platform (secure) | Challenge (vulnerable) |
|---------|-------------------|------------------------|
| Auth | `server/routes/postgresAuth.js` + PostgreSQL session/admin middleware | Isolated synthetic accounts in their challenge stores |
| Users | PostgreSQL `identity.users` | Isolated synthetic challenge accounts |
| Sessions | `middleware/sessionManager.js` | N/A |
| Audit | PostgreSQL identity audit and graph metadata | Per-challenge activity and tool records |
| Rate limits | Platform configuration and bounded model queue | Workshop controls preserve deliberate teaching behavior |
| Admin | `middleware/adminAuth.js` + admin routes | N/A |

**Do not "fix" intentional vulnerabilities** in challenge routes. SecureShop teaching sinks use `@intentional-vulnerability <id>` annotations and coverage checks. Other workshop behavior is protected by its mode, exploit and workflow tests.

---

## Database isolation and existing-data migration

`PLATFORM_DATABASE_ENGINE=postgres` and `WORKSHOP_DATABASE_ENGINE=postgres`
are both required. The canonical manifest in
`db/postgres/initialize-application.js` defines 16 stores: `identity`, `aria`,
`nova`, `xss`, `mcp`, `csrf`, `supply_chain`, `finflow`, `excessive_agency`,
`ctf`, `legacy_challenge`, `sensitive_lookup`, `secureshop`,
`secureshop_agents`, `session_disclosure`, and `secureshop_review`. Every store
has a distinct runtime URL/role and migration URL/role. Identity also owns the
platform catalog, progress, session, audit, and graph-runtime schemas.

Runtime roles have only their application's grants. Platform credentials are not shared with intentionally vulnerable challenge queries. Per-attendee keys isolate workshop state within its database. Native tests cover owner-scoped reset, canonical progress and durable Judge receipt transactions.

Schemas, role grants and append-only migrations live under `db/postgres/`.
`npm run db:initialize-all` applies PostgreSQL migrations and idempotent seeds.
The retired SQLite managers and archive CLIs are not supported runtime or
installation paths in the new repository. Preserved legacy data requires a
separately reviewed external recovery/import procedure; it must never be
opened implicitly by application startup.

---

## AI service layer

The existing service entry points remain for route compatibility. `ollamaService.js` and `multiProviderAIService.js` create providers through `server/agent-runtime/providers/langchainProvider.js`. LangChain transports provide role-separated messages, structured output and provider metadata. Bounded scheduling and cancellation govern model calls.

The documented agent graphs select and validate model actions before dispatch, preserve actual tool results for grading, and await owner-scoped traces. Explicit mock routing is labeled simulation. CSRF Inbox/RAG gadget interpretation is also an intentional teaching interpreter; it is not described as a model-selected action or browser execution proof. See [the decision/observability plan](modernization/decision-observability-plan.md) for family-level verification and remaining live workflow gates.

Provider/model selection and optional credentials are documented in the root README and `.env.example`. Local LangChain, LangGraph and Ollama need no API keys. Cloud providers and optional LangSmith tracing use operator-supplied credentials; the repository does not supply or publish them.

### Objective judge and local run observability

The shared objective judge calls a separately configured model through
LangChain and executes prepare, judge, strict validation and one bounded repair
through LangGraph. Local defaults are:

```dotenv
JUDGE_PROVIDER=ollama
JUDGE_MODEL=llama3.1:8b
```

The default uses the same installed Ollama model and needs no cloud account.
Cloud judge providers use corresponding user-supplied provider credentials.
Only a durably accepted `pass` can complete an objective; `fail`,
`inconclusive`, and `unavailable` award no new credit. Only eligible unavailable receipts expose a bounded retry of retained evidence; retry never replays exercise tools.

The Agent Run Inspector reads owner-scoped local run and event metadata. It
shows actual registered graph nodes and edges, model/tool decisions, provider,
model, reported usage, judge verdicts, sanitized errors and duration. It does
not store or display private chain-of-thought. Learners cannot request another
owner's run; administrator reads require analytics permission.

All106 canonical objectives have grading definitions; separate CTF and legacy objective families are also covered by the qualification runner. Recorded-evidence grading is distinct from connected live workflow qualification. Current versions, failures and exact proof are in [the Judge verification record](modernization/judge-verification-2026-09-11.md) and [live workflow matrix](modernization/judge-live-workflow-qualification.md).

### Agent tools

Located in `server/services/`:

- File-reading agent (`fileReadingAgent`)
- Gmail agent (`gmailAgent`)
- Excessive Agency tool router (`excessiveAgencyToolRouter`)
- ARIA SQL agent (`ariaAgentService`)
- NOVA NoSQL agent (`novaAgentService`)
- Sensitive info workshop agent (`sensitiveInfoWorkshopAgent`)
- RAG vector store
- Sandbox shell (for DevOps terminal challenge)

---

## SecureShop v2

SecureShop v2 is the flagship end-to-end LLM-driven target. It stands up its
own subsystem alongside the main app:

- **Backend routes** — `server/routes/secureshop/*` (thin proxies to the
  supervisor loop).
- **Supervisor loop** — `server/services/secureshop/supervisors/*` (one per
  role: customer, merchant, admin).
- **Provider ladder** — Ollama → Anthropic → OpenAI → Bedrock → controlled mock.
- **Agent Host** — `agent-host/index.js` boots 17 MCP servers on port `8082`.
- **Databases** — isolated PostgreSQL `secureshop`, `secureshop_agents`, and
  `secureshop_review` stores for commerce, agent state, MCP registry, vectors,
  and owner-bound review evidence.

For depth see [`secureshop/ARCHITECTURE.md`](secureshop/ARCHITECTURE.md).

---

## Configuration modes

### `LAB_MODE` (env var)

Legacy challenge paths may read this environment variable. Canonical workshop modes are per-user database state with a revision stamp captured before model/tool effects. Mode changes invalidate stale completion attempts.

- `vuln` — intentionally vulnerable exercise behavior
- `fixed` — defensive exercise behavior

Defaults differ by workshop and come from the shared mode catalog; do not infer a global default.

Frontend components `VulnerabilityGuard` and `VulnerabilityTemplate` enforce
the toggle in the UI.

### `EVENT_GATE_ENABLED`

Set to `true` with a shared `EVENT_GATE_PASSWORD` to gate the entire app
behind a password screen. Used at live workshops to prevent uninvited
traffic. See `server/middleware/eventGate.js`.

### `SECURITY_TESTING_MODE`

When `true`, enables features that would otherwise be disabled in a
"production" build (verbose errors, secret leak endpoints, etc.). Its actual value is operator configuration; deliberate teaching behavior must remain isolated from platform security.

---

## What lives where

```
Damn-Vulnerable-AI-Application/
├── server/
│   ├── index.js                 # App entry
│   ├── routes/                  # One file per feature/challenge
│   ├── services/                # AI providers, agent tools, RAG
│   ├── middleware/              # Auth, admin, rate-limit, event-gate
│   └── database/postgres/       # PostgreSQL repositories and adapters
├── client/src/
│   ├── pages/                   # Top-level page components
│   ├── pages/challenges/        # Individual challenge UIs
│   ├── pages/workshops/         # Workshop pages
│   └── components/              # Shared UI + VulnerabilityGuard
├── agent-host/                  # SecureShop MCP servers (port 8082)
├── db/postgres/                 # Canonical migrations, seeds, and 16-store manifest
├── docs/                        # This documentation
├── scripts/install/             # Per-OS install scripts
├── tests/                       # API + workshop tests
└── start_all.sh · stop_all.sh   # Master start/stop
```

---

## Frozen AWS assets

The checked-in AWS workflows, templates, and container scripts describe the
older Node 18/SQLite deployment topology. They remain frozen for historical
reference and have not been qualified against the PostgreSQL-only application.
Do not treat those assets as a supported deployment path or infer compatibility
from their presence in the repository.
