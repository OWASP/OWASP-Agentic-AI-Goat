# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What This Project Is

**DVAIA (Damn Vulnerable AI Application)** is an educational security platform with a deliberate split architecture:
- **Platform layer**: Production-grade secure infrastructure (auth, session management, audit logging)
- **Challenge layer**: Intentionally vulnerable isolated databases for hands-on learning

The same codebase has both hardened security code and deliberately insecure code. Do **not** "fix" intentional vulnerabilities in challenge routes or databases.

## Development Commands

### Start / Stop
```bash
npm run setup -- --plan     # Non-mutating fresh-setup preview
npm run setup               # Supported fresh install; provisions PostgreSQL and private config
./start_all.sh --plan       # Non-mutating check of all required PostgreSQL URL pairs
./start_all.sh              # Validated foreground backend + frontend startup
./start_all.sh --init-db    # Apply pending migrations/idempotent seeds, then start; preserves data
./stop_all.sh               # Stop only the process tree owned by start_all.sh
```

`./start_all.sh --reset` is deliberately rejected. Startup never deletes
databases. Use authenticated workshop/admin reset and student-deletion flows for
their documented scopes. Use explicit, reviewed migration/import tools for
existing data. Do not substitute legacy SQLite deployment scripts.

### Manual
```bash
npm run dev                 # Backend + frontend concurrently (ports 8081 + 3000)
npm run server              # Backend only, port 8081 (nodemon)
cd client && npm start      # Frontend only, port 3000
ollama serve                # AI engine, port 11434 (separate terminal)
```

### Build & Test
```bash
npm run build               # Build React production bundle
npm test                    # Configured unit + isolated SecureShop + frontend aggregate
npm run test:api            # Backend API tests only
npm run test:frontend       # Frontend component tests only
node tests/api.test.js      # Run a single test file directly
npm run db:initialize-all   # Apply all configured PostgreSQL migrations/seeds; preserves data
npm run test:postgres       # Disposable native PostgreSQL regression (never use app databases)
npm run verify              # SecureShop schema + intentional-vulnerability coverage

# Workshop tests require extra flags:
EXPORT_INTERNALS=1 node tests/ssrfWorkshop.test.js            # Unit tests only (no server needed)
EXPORT_INTERNALS=1 SERVER_AVAILABLE=1 node tests/ssrfWorkshop.test.js  # Full suite incl. integration

# Focused ARIA/NOVA tests (controlled unit/service providers; no real-model proof):
node scripts/test-isolated.js unit tests/workshopGraph.test.js tests/workshopModelDecision.test.js tests/sqlNoSqlExactSearchContract.test.js
# PostgreSQL route/store integration uses the separately owned disposable launcher.
# Retired SQLite/regex workshop suites are preserved outside the repository.
```

`npm run setup` is the supported first-install path. The `deploy:*`
compatibility aliases do not provision a fresh cluster: `deploy:fresh` and
`deploy:full` lazily apply the same additive PostgreSQL initializer, while reset
forms fail closed and direct operators to authenticated lifecycle controls.
Native PostgreSQL, browser and actual-model qualifications remain separate from
`npm test` and require their explicitly isolated launchers.

### Docker
```bash
docker compose up -d mcp-sandbox mailpit ssrf-target rogue-mcp  # Local lab sidecars
```

Normal local installation uses `npm run setup` and `./start_all.sh`. The former
AWS-backed `full-app` Compose profile was removed; local sidecars remain.

### CI/CD (GitHub Actions)
The tracked workflows in `.github/workflows/` run schema and SecureShop checks.
The former AWS deployment and S3 backup workflows were removed.

## Architecture

### Request Flow
```
React (port 3000) → Express (port 8081) → 16 isolated PostgreSQL databases
                                        → Ollama/configured model providers
                                        → optional owned lab sidecars
```

### Backend (`server/`)
- `index.js` — App entry, middleware, readiness and owned-resource shutdown. Platform authority uses canonical PostgreSQL JWT sessions. A separate durable teaching cookie deliberately retains weak signing/JavaScript visibility for isolated lessons; its payload cannot create platform authority and is checked against the bound platform session.
- `routes/` — Feature, platform and intentionally vulnerable challenge routers.
- `services/` — AI providers (`ollamaService`, `multiProviderAIService`), agent tools, database-backed HTTP revision polling, RAG vector store.
- `middleware/` — `auth.js` (JWT), `adminAuth.js`, `rateLimiter.js`, `performanceMonitor.js`, `sessionManager.js`, `workshopMode.js`, `eventGate.js` (live-event password barrier), `llmLogger.js` (logs all LLM provider calls to `server/logs/llm_requests.log`)
- `database/postgres/` — Active PostgreSQL repositories, runtime adapters and store initializers. Other database managers are retained only where an explicitly supported legacy fixture or challenge path still names them.

### Frontend (`client/src/`)
- `pages/` — Top-level page components (dashboards, CTF, workshop, admin)
- `pages/challenges/` — Individual challenge UIs
- `pages/workshops/` — Workshop-specific pages
- `components/` — Shared UI: `VulnerabilityGuard.js` / `VulnerabilityTemplate.js` enforce `LAB_MODE` toggling in the UI
- `context/` — React context providers (auth, etc.)
- `hooks/` — Custom React hooks

### Database Isolation (Critical Design)
Supported startup uses 16 separately provisioned PostgreSQL databases, each with
distinct runtime and migration roles. `db/postgres/initialize-application.js`
is the canonical manifest:

| Store | Purpose |
|------|---------|
| `identity` | Platform users, sessions, permissions, audit, catalog and canonical progress |
| `aria`, `nova` | SQL and NoSQL agent workshop state |
| `xss`, `mcp`, `csrf`, `supply_chain` | Isolated workshop state |
| `finflow`, `excessive_agency`, `ctf` | Isolated agent/challenge state |
| `legacy_challenge`, `sensitive_lookup` | PostgreSQL-backed retained challenge state |
| `secureshop`, `secureshop_agents`, `secureshop_review` | Commerce, agent lifecycle and owner-bound reviews |
| `session_disclosure` | Dedicated synthetic session-disclosure lab |

The `.db` files and `db/initialize-db/` tree are retained legacy/archive/test
fixtures. Do not route supported application startup back to them, and never
point disposable PostgreSQL tests at an application or learner database.

### AI Integration

Two AI service layers exist side by side:

- **`ollamaService.js`** — direct Ollama calls. Used for workshops that need reliable, fast text completion:
  - `generateResponse(prompt, opts)` → `/api/generate` — reliable, use for summarization and pre-intercept responses
  - `chatWithTools(messages, tools, opts)` → `/api/chat` with tool schemas — **unreliable** with Llama 3.1:8b (LLM often ignores tools); avoid for tool-calling workflows
- **`multiProviderAIService.js`** — selects the configured `AI_PROVIDER`; inspect its supported enum and the calling graph instead of assuming a universal fallback order. It supports Ollama, Anthropic/Claude, OpenAI/ChatGPT, Bedrock and LM Studio paths, plus controlled mock execution. SecureShop has a separate provider router. Configure optional provider credentials/model identifiers through private environment configuration; never invent provider model IDs or commit keys.
- Some ungraded teaching responses can degrade or report model unavailability.
  Mock/fallback output is never evidence of a genuine model run and must not earn
  objective credit where model provenance is required.
- Agent tools in `server/services/`: file reading agent, Gmail agent, excessive agency tool router, RAG vector store, sandbox shell

### ARIA & NOVA Agent Pattern

`ariaAgentService.js` (SQL/ShopFast) and `novaAgentService.js`
(NoSQL/ResearchVault) default to `createWorkshopGraph`:

1. `invoke()` admits a persisted run and asks the configured model for a bounded,
   schema-validated decision.
2. The graph validates exact task arguments, executes the parameterized local
   tool, persists effect/trace provenance, and produces the response.
3. Objective credit is a separate canonical Judge/evidence decision; a supplied
   fixture response, mock provider, missing effect or stale generation is not a
   genuine completion.

Both services retain regex-based `legacyChat` for explicitly selected regression
fixtures only. It is used only when `ARIA_AGENT_RUNTIME=legacy` or
`NOVA_AGENT_RUNTIME=legacy`; do not copy it as the default pattern for new agents.

Routes at `/api/workshop/sql` and `/api/workshop/nosql` expose `POST /chat`, `POST /reset`, `GET /history/:userId`, `GET /llm-status`.

**DB test isolation:** default graph/native tests use disposable PostgreSQL stores
and controlled providers. `SQL_WORKSHOP_DB_PATH` / `NOSQL_WORKSHOP_DB_PATH` apply
only to retained legacy SQLite fixtures and must point to a new temporary file
before those modules are loaded.

### Key Environment Variables (`.env`)
```
PORT=8081
OLLAMA_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://localhost:11434
SECURITY_TESTING_MODE=true   # Enables vulnerable challenge features
LAB_MODE=vuln                 # "vuln" or "fixed" switches challenge behavior
NODE_ENV=development
AI_PROVIDER=ollama            # provider override; use the exact enum supported by the selected service
# Cloud LLM fallback (optional — multiProviderAIService picks first available)
BEDROCK_MODEL_ID=             # Optional configured model ID; use one available to your provider account
AWS_REGION=us-west-2
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
# Live-event gate (optional — blocks all traffic until attendees enter shared password)
EVENT_GATE_ENABLED=false
EVENT_GATE_PASSWORD=
```

Supported startup also requires `PLATFORM_DATABASE_ENGINE=postgres` and
`WORKSHOP_DATABASE_ENGINE=postgres`, plus all 16 runtime/migration URL pairs in
the canonical store manifest. Do not paste credentials into this file or logs.
`npm run setup` writes the private `.env`; `.env.example` documents variable
names only. Use `./start_all.sh --plan` to report configured/missing pairs without
printing URLs.

## Database Schema Management (Required)

Active schema changes are forward-only PostgreSQL migrations:

1. Put platform/identity changes in `db/postgres/identity-migrations/`, or a
   workshop/store change in `db/postgres/workshop-migrations/<store>/`, using the
   next ordered filename. Foundation-only changes belong in
   `db/postgres/migrations/`.
2. Never edit, rename or delete a migration that may have been applied. The
   migration ledger verifies exact file checksums.
3. Use the migration role for DDL and grant the runtime role only the minimum
   required capabilities. Revoke unintended `PUBLIC` function execution.
4. Add idempotent/default-only seed changes through the store's checked-in seed
   path. Preserve instructor-edited catalog, hint and solution content on reseed.
5. Update `db/postgres/initialize-application.js` and provisioning only when a
   new isolated store is intentionally added. Every store requires both runtime
   and migration URL variables and roles.
6. Qualify fresh, representative populated, and second-run/no-op migration paths
   in owned disposable PostgreSQL stores. Preserve sibling learner state and
   immutable evidence. `npm run db:initialize-all` targets configured stores; it
   is not a disposable test command and never means “erase and recreate.”

The old `db/initialize-db/` schemas/seeds and the dual `users_auth.db`
initializers apply only to retained legacy SQLite fixtures. Change them only when
a task explicitly requires legacy-fixture parity; they are not the supported
application schema authority.

## Sensitive Info Workshop — FinFlow decision graph

`server/routes/sensitiveInfoWorkshop.js` admits the authenticated objective and
owner-scoped run, then calls `SensitiveInfoWorkshopAgent.processMessage()`.
The supported default uses `server/agent-runtime/finflowDecisionGraph.js`:
a real configured model selects bounded schema-validated actions, the graph
executes the owned tools and records effects, and the canonical objective
completion service evaluates evidence with the Judge before credit is stored.
Reset/generation checks fence both execution and grading.

The older regex/pre-intercept handlers remain only for explicitly selected
`decisionMode: 'scripted'` or mock-provider fixtures. Do not add route-level
regex dispatch as the default for a new objective. Scripted/mock output cannot
establish genuine model provenance or earn model-required objective credit.

Changes to an objective must keep its tool decision schema, owned artifact or
HTTP effect, evidence adapter, rubric and catalog aligned. See
`finflowDecisions.js`, `finflowDecisionGraph.js`, and the FinFlow evidence
services. Fixed mode and vulnerable mode remain distinct. Controlled tests do
not replace actual-model and rendered qualification of every objective.

Supporting files include `server/sensitive_files/config/`,
`server/workshop_data/transactions/`, and `server/workshop_data/documents/`.
Use owned synthetic teaching data and real bounded tool effects; never use
host private files as exploit fixtures.

## CTF Prompt Injection Challenge

A 10-level Gandalf/HackAPrompt-style CTF where students extract secrets from progressively harder AI guardians.

**Architecture:** `server/routes/ctf.js` → `server/database/ctfDb.js` (selects `server/database/postgres/ctfDb.js` for supported PostgreSQL startup; `ctf.db` is a retained legacy fixture) + `server/services/promptInjectionCTF.js` (classifier) + `server/services/ctfDefenseLayers.js` (defense layers).

**Level progression:** L1–L7 use static defense layers (none, output filter, input filter, meta-judge, persona guard, polyglot filter). L8–L10 add adaptive blocking:
- L8 `technique` mode — per-user technique tag memory (each tag usable once per level)
- L9 `payload` mode — global fuzzy-hash blocklist of winning payloads across all users
- L10 `hybrid` — both technique + payload blocking, plus all defense layers active

**Admin:** Managed from Admin Dashboard → CTF Management (7 sub-tabs: Overview, Levels, Solutions, Attempts, Leaderboard, Config, Danger Zone). API at `/api/ctf/admin/*`. The **Solutions** tab (admin-only spoilers) surfaces verified per-level payloads from `server/data/ctfSolutions.js` via `GET /api/ctf/admin/solutions`.

**CTF store tables:** `ctf_config`, `ctf_stages`, `ctf_participants`, `ctf_progress`, `ctf_attempts`, `ctf_leaderboard`, `ctf_technique_blocklist`, `ctf_payload_blocklist`, `ctf_bans`, `ctf_events`, `ctf_sessions`.

**Tests:** `node tests/promptInjectionCTF.smoke.test.js` (unit, no server). Supported controlled CTF authority/Judge checks: `node scripts/test-isolated.js unit tests/ctfAuthorityRouter.test.js tests/ctfStructuredJudge.test.js`. Native PostgreSQL integration remains a separate disposable-store qualification; the retired SQLite admin smoke test is preserved outside the new repository.

## Solution & Hint System Pattern

Supported PostgreSQL installations use one canonical workshop catalog/configuration path. SQLite tables described in old fixtures are not the supported runtime authority.

| Layer | Source | Role |
|-------|--------|------|
| Defaults | `server/config/workshopCatalog.js`, family curriculum modules, `server/data/*Solutions.js`, `server/data/workshopHints.js` | Checked-in default labels, content and key mappings |
| Seed | `server/database/postgres/workshopPlatformSeed.js` and `workshopPlatformSeedCore.js` | Provenance-aware default updates; preserves instructor-owned edits |
| Identity database | `workshop_platform.exercises`, `workshop_platform.objectives` | Exercise/objective visibility, hint/solution gates and editable content |
| Configuration | `server/database/postgres/workshopConfigRepository.js` | Shared effective visibility and mutation semantics |
| Student API | `server/routes/postgresWorkshopContent.js`, selected by `solutions.js` / `hints.js` | Status and content projections; unavailable content is denied |
| Admin API/UI | `server/routes/adminExercises.js`, `client/src/pages/ComprehensiveAdminDashboard.js` | Instructor visibility/content controls |

Status/content endpoints retain their documented public teaching-content access. Visibility gates are not administrator authority; mutations require canonical instructor authorization.

## Workshop Sync Invariants (ALWAYS enforce)

Whenever an exercise/objective is added, retired, edited, enabled or disabled, verify the following against the supported PostgreSQL path. Do not update only legacy fixture tables.

### Admin and content sync
- Exercise availability comes from `workshop_platform.exercises` (`catalog_active`, `is_visible`) and objective availability from `workshop_platform.objectives` (`catalog_active`, `is_enabled`).
- Master `show_hints` / `show_solutions` and per-objective `hint_enabled` / `solution_enabled` are combined with actual content by `workshopConfigRepository`. Both admin surfaces and student pages must use that effective projection.
- Hint and solution controls are independent. Master/per-objective mutations must remain consistent across `/admin/challenges`, `/admin/solutions` and the exercise page; preserve the repository's cascade semantics.

### Student dashboard parity
- `/workshop-dashboard`, `/workshop/challenges` and `/workshop/progress` must agree on counts and time, including any supported redirect between these routes.
- `workshopProgressRepository` derives totals from active/enabled catalog rows, completions from `workshop_platform.completions` joined to those rows, and time from `workshop_platform.time_tracking`. Never derive runtime totals from a hardcoded frontend list.
- Default labels/key mappings live in `server/config/workshopCatalog.js`; runtime labels/configuration are database-derived and preserve instructor edits. Do not reintroduce endpoint-specific objective switches.
- Hint/solution buttons on challenge cards and exercise pages must follow effective database gates, independently of each other. Completed objectives must project as completed in each learner view.

### Adding / updating objectives — required steps
1. Update canonical catalog/family curriculum defaults and relevant hints/solutions; maintain `CHALLENGE_TO_WORKSHOP_KEY` in `server/config/workshopCatalog.js` when keys differ.
2. Use the provenance-aware PostgreSQL seed path and forward-only migrations where needed. Retire stale catalog identities through the supported catalog mechanism; never delete immutable learner evidence or overwrite instructor-owned content to make reseeding pass.
3. Integrate the family canonical Judge/evidence decision and progress/time projection. A direct completion write or controlled fixture is not genuine model/effect proof.
4. Qualify fresh, populated and second-run/no-op behavior in disposable stores, including sibling preservation and owner/reset/session fences.
5. Verify API and rendered learner count/time parity, completed styling, admin visibility synchronization and independent hint/solution gates.

**These sync checks are required before considering an exercise/objective change complete. Legacy SQLite parity is additional work only when explicitly in scope.**

## Challenge vs Platform Code

- **Platform (secure, hardened)**: supported PostgreSQL authentication/administration, middleware, owner/session/reset checks, canonical Judge/evidence and progress boundaries. Entry points include `server/routes/postgresAuth.js` and `server/database/postgres/`.
- **Challenges (intentional teaching sinks)**: identified exploit paths and annotated vulnerabilities within workshop/SecureShop handlers and isolated stores. A workshop filename does not make every authorization or lifecycle defect intentional; preserve the teaching sink while enforcing platform and sibling isolation.

The `LAB_MODE` env var (`vuln`/`fixed`) toggles challenge behavior in several routes — both modes must be maintained when editing challenge routes. The frontend enforces this via `VulnerabilityGuard` and `VulnerabilityTemplate` components.

## Default Credentials

Fresh supported PostgreSQL setup creates only two platform users: `admin` / `admin123` (level 2 administrator) and `student` / `student 123` (one literal space). Passwords are hashed in PostgreSQL. The private `~/.dvaia/<workspace-id>/administrator.json` records the installation’s administrator credential. Never reset existing users or passwords during upgrade/repair/reseed. Legacy SQLite fixture credentials are not supported startup authority.

SecureShop has separate synthetic practice accounts and lesson personas; see the single [installation guide](docs/install/INSTALLATION.md#initial-accounts) for their default logins. These accounts cannot create platform authority.

## Access Points

| URL | Purpose |
|-----|---------|
| `http://localhost:3000` | Main frontend |
| `http://localhost:8081` | Backend API |
| `/workshop-login` | Student/instructor login |
| `/admin` | Admin dashboard |
| `/ctf` | CTF Prompt Injection Challenge (10-level Gandalf-style, adaptive defenses) |
| `/ctf/challenge` | CTF active level chat interface |
| `/ctf/leaderboard` | CTF live leaderboard |
| `/api/ctf/*` | CTF API (stages, attempts, leaderboard, admin) |
| `/api/monitoring/health` | Health check endpoint |
| `/workshop/sql` | ARIA SQL agent (ShopFast e-commerce) |
| `/workshop/nosql` | NOVA NoSQL agent (ResearchVault research library) |
| `/vulnerabilities/direct-prompt-injection` | DPI challenge |
| `/vulnerabilities/indirect-prompt-injection` | IPI challenge |
| `/workshop/sensitive-info` | Sensitive Information Disclosure workshop |
| `/workshop/supply-chain` | Supply Chain attack workshop |
| `/workshop/prompt-injection` | Direct Prompt Injection workshop (8 objectives: jailbreak, role-play, obfuscation, etc.) |
| `/workshop/xss` | XSS Workshop (reflected, stored, LLM-generated, email tabs) |
| `/workshop/rag-injection` | RAG/Indirect Prompt Injection workshop |
| `/workshop/excessive-agency` | Excessive Agency lab |


## SecureShop v2

SecureShop v2 is the second-generation deliberately-vulnerable e-commerce app.
It replaces the flat legacy `/secureshop/*` demo with a 3-supervisor, 17-task-
agent architecture that teaches the OWASP LLM Top 10 and OWASP MCP Top 10
alongside classic web sinks. Frontend lives under `/secureshop/v2/*`; legacy
`/secureshop/*` is untouched and remains for backward compatibility.

### CRITICAL: Do-not-fix notice

**SecureShop v2 contains intentional vulnerabilities annotated with
`@intentional-vulnerability <id>`.** These are teaching sinks and MUST NOT be
"fixed". Before editing any code under:

- `agent-host/*`
- `server/services/secureshop/*`
- `server/routes/secureshop/*`
- `client/src/pages/secureshop/*`

check `docs/secureshop/vuln-map.md` (regenerated by
`npm run docs:secureshop:vuln-map`). Every entry is deliberate. Removing a
tagged sink will fail `npm run verify:secureshop:vuln-coverage`.

If a v2 test fails, first ask: did someone remove the intentional vulnerability
this test proves? That is almost always the root cause.

### PostgreSQL stores

SecureShop uses the dedicated `SECURESHOP`, `SECURESHOP_AGENTS`, and
`SECURESHOP_REVIEW` runtime/migration database pairs from the application store
manifest. `server/database/secureshop.db` and
`server/database/secureshop_agents.db` are retained legacy/test artifacts, not
the supported application stores.

Vector index files live under `server/database/vector-indexes/<corpus>.hnsw`
(one per corpus — currently `manuals`, `policies`, `reviews`, `products`).

### Agent Host process

When `SS_ENABLE=true`, the 17 task agents are hosted by a **separate Node process** at
`agent-host/index.js`, port **8082** (env `SS_AGENT_HOST_PORT`). Each agent
exposes an MCP-over-SSE endpoint at `GET /mcp/<agent-name>`. The backend
process talks to them via `McpClientPool` in
`server/services/secureshop/mcpClientPool.js`. `AgentHostSupervisor` in the
same directory boots and monitors the child process. The bound launch/review
application additionally requires `SS_BOUND_REVIEWS_ENABLED=true`, all required
PostgreSQL migrations, and its readiness gates. `npm run dev` does not start the
agent host when SecureShop is disabled.

### Provider ladder

`server/services/secureshop/providerRouter.js` picks the first available:
1. **ollama** — configured local model, normally `llama3.1:8b`
2. **anthropic** — configured Anthropic model
3. **openai** — configured OpenAI model
4. **bedrock** — configured Bedrock model and region
5. **mock** — deterministic last resort for controlled tests/ungraded execution

`AI_PROVIDER=<name>` moves a configured provider to the front; unavailable
providers fall through in the order above. Mock/parity fixtures do not count as
actual-model or objective-credit proof.

### npm commands

```bash
npm run test:secureshop              # all SecureShop v2 tests (unit + integration + vuln + e2e)
npm run test:secureshop:unit         # unit — no agent-host boot required
npm run test:secureshop:integration  # integration — spawns agent-host
npm run test:secureshop:vuln         # every @intentional-vulnerability proof
npm run test:secureshop:chains       # multi-hop cross-agent chain tests (M6)
npm run test:secureshop:parity       # 6 vulns × 3 providers (M6)
npm run test:secureshop:e2e          # Puppeteer end-to-end flows (M6)
npm run verify:secureshop            # schema + vuln-coverage check
npm run verify:secureshop:schema     # schema-only
npm run verify:secureshop:vuln-coverage  # every listed vuln id has code+test annotation
npm run docs:secureshop:vuln-map     # regenerate docs/secureshop/vuln-map.md
```

### Docs

- `docs/secureshop/README.md` — one-page teaching guide + do-not-fix policy
- `docs/secureshop/architecture.md` — topology + request-flow diagram
- `docs/secureshop/agent-catalog.md` — one paragraph per task agent
- `docs/secureshop/vuln-map.md` — stable pointer to the generated map
- `docs/secureshop/VULNERABILITIES.md` — generated vulnerability table; do not hardcode its changing count

## Workflow Orchestration

### Contributor work

Follow `docs/CONTRIBUTING.md`. Plan multi-step work in ignored `tasks/`; do not commit personal execution journals. Use focused tests, disposable databases and truthful evidence. Preserve intentional sinks and platform isolation. Delegate only independent tasks when requested or useful within the user's scope, with separate file ownership. Never run competing memory-intensive local-model or native database qualifications. Historical release check IDs are not an active task for new contributors.

1. **Plan Mode Default** — Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions). If something goes sideways, STOP and re-plan immediately.

2. **Subagent Strategy** — Use subagents to keep the main context window clean. Offload research, exploration, and parallel analysis. One focused task per subagent.

3. **Self-Improvement Loop** — After ANY correction from the user: update `tasks/lessons.md` with the pattern. Review lessons at session start.

4. **Verification Before Done** — Never mark a task complete without proving it works. Run tests, check logs, demonstrate correctness.

5. **Demand Elegance (Balanced)** — For non-trivial changes: ask "is there a more elegant way?" Skip for simple, obvious fixes.

6. **Autonomous Bug Fixing** — When given a bug report: just fix it. Point at logs, errors, failing tests — then resolve them.

## Task Management

- **Plan First**: Write plan to `tasks/todo.md` with checkable items
- **Track Progress**: Mark items complete as you go
- **Capture Lessons**: Update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Only touch what's necessary. No side effects with new bugs.
