# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**OWASP Agentic AI GOAT** is an educational security platform with a deliberate split architecture:
- **Platform layer**: Production-grade secure infrastructure (auth, session management, audit logging)
- **Challenge layer**: Intentionally vulnerable isolated databases for hands-on learning

The same codebase has both hardened security code and deliberately insecure code. Do **not** "fix" intentional vulnerabilities in challenge routes or databases.

## Development Commands

### Start / Stop
```bash
./start_all.sh              # Validated PostgreSQL startup
./start_all.sh --init-db    # Apply pending PostgreSQL migrations/idempotent seeds; preserve data
./start_all.sh --reset      # Rejected; use authenticated lifecycle controls
./stop_all.sh               # Clean shutdown
```

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
npm test                    # Full comprehensive test suite
npm run test:api            # Backend API tests only
npm run test:frontend       # Frontend component tests only
node tests/api.test.js      # Run a single test file directly
npm run deploy:fresh        # Compatibility alias for additive PostgreSQL initialization
npm run db:initialize-all   # Apply configured PostgreSQL migrations/seeds; preserve data
npm run verify              # Verify server health + challenge APIs

# Workshop tests require extra flags:
EXPORT_INTERNALS=1 node tests/ssrfWorkshop.test.js            # Unit tests only (no server needed)
EXPORT_INTERNALS=1 SERVER_AVAILABLE=1 node tests/ssrfWorkshop.test.js  # Full suite incl. integration

# ARIA/NOVA agent workshop tests (DB + service layer; no server or Ollama required):
node tests/sqlWorkshop.test.js                                # ARIA SQL agent tests
node tests/nosqlWorkshop.test.js                              # NOVA NoSQL agent tests
SERVER_AVAILABLE=1 node tests/sqlWorkshop.test.js             # Include HTTP integration tests
SERVER_AVAILABLE=1 node tests/nosqlWorkshop.test.js
```

### Docker
```bash
docker compose up -d mcp-sandbox mailpit ssrf-target rogue-mcp  # Local lab sidecars
```

### CI/CD (GitHub Actions)
The tracked workflows in `.github/workflows/` run schema and SecureShop checks.
The former AWS deployment and S3 backup workflows were removed.

## Architecture

### Request Flow
```
React (port 3000) → Express (port 8081) → SQLite databases
                                        → Ollama (port 11434)
                                        → MySQL (optional, sensitive_info challenge)
```

### Backend (`server/`)
- `index.js` — App entry: middleware setup, DB init, route mounting. Session is intentionally insecure (weak secret, `httpOnly: false`) for educational purposes.
- `routes/` — One file per feature/challenge. 26 route files.
- `services/` — AI providers (`ollamaService`, `multiProviderAIService`), agent tools, database-backed HTTP revision polling, RAG vector store.
- `middleware/` — `auth.js` (JWT), `adminAuth.js`, `rateLimiter.js`, `performanceMonitor.js`, `sessionManager.js`, `workshopMode.js`, `eventGate.js` (live-event password barrier), `llmLogger.js` (logs all LLM provider calls to `server/logs/llm_requests.log`)
- `database/` — Per-database SQLite managers + schema init files. Each challenge has its own isolated DB file and manager module.

### Frontend (`client/src/`)
- `pages/` — Top-level page components (dashboards, CTF, workshop, admin)
- `pages/challenges/` — Individual challenge UIs
- `pages/workshops/` — Workshop-specific pages
- `components/` — Shared UI: `VulnerabilityGuard.js` / `VulnerabilityTemplate.js` enforce `LAB_MODE` toggling in the UI
- `context/` — React context providers (auth, etc.)
- `hooks/` — Custom React hooks

### Database Isolation (Critical Design)
Platform and challenge data are in completely separate SQLite files — no cross-access:

| File | Purpose |
|------|---------|
| `platform_secure.db` | Secure users, sessions, audit logs, admin |
| `users_auth.db` | Workshop user authentication |
| `sqli_challenge.db` | Intentionally vulnerable SQL injection |
| `xss_challenge.db` | Legacy XSS comment system |
| `xss_email_challenge.db` | XSS Workshop (4-tab: reflected, stored, LLM-generated, email) |
| `ctf.db` | CTF Prompt Injection Challenge (10-level, adaptive, leaderboard, technique/payload blocklists) |
| `ctf_ai_challenge.db` | Legacy CTF AI interactions (unused by main app) |
| `sensitive_info.db` / `sensitive_info_workshop.db` | Data exfiltration practice |
| `secureshop.db` | Ecommerce challenge |
| `excessive_agency.db` | Excessive agency lab |
| `sql_workshop.db` | ARIA agent — ShopFast e-commerce (parameterized, safe) |
| `nosql_workshop.db` | NOVA agent — ResearchVault academic library (parameterized, safe) |
| `owasp-ai-goat.db` | Workshop progress tracking (objective completions per user) |
| `supply_chain_workshop.db` | Supply Chain attack workshop |
| `challenge.db` | Legacy challenge data (sqli_challenge.db supersedes for SQL injection) |

### AI Integration

Two AI service layers exist side by side:

- **`ollamaService.js`** — direct Ollama calls. Used for workshops that need reliable, fast text completion:
  - `generateResponse(prompt, opts)` → `/api/generate` — reliable, use for summarization and pre-intercept responses
  - `chatWithTools(messages, tools, opts)` → `/api/chat` with tool schemas — **unreliable** with Llama 3.1:8b (LLM often ignores tools); avoid for tool-calling workflows
- **`multiProviderAIService.js`** — provider-agnostic wrapper. Priority order: Ollama → AWS Bedrock → OpenAI → Claude API. Used by supply chain, challenges, and any route that needs cloud-LLM fallback. Configured via:
  ```
  BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
  AWS_REGION=us-west-2
  OPENAI_API_KEY / OPENAI_MODEL=gpt-4
  ANTHROPIC_API_KEY
  ```
- App degrades gracefully without any LLM (mock responses returned)
- Agent tools in `server/services/`: file reading agent, Gmail agent, excessive agency tool router, RAG vector store, sandbox shell

### ARIA & NOVA Agent Pattern

`ariaAgentService.js` (SQL/ShopFast) and `novaAgentService.js` (NoSQL/ResearchVault) share the same architecture — use this as the template for new workshop agents:

1. **`detectIntent(message)`** — regex-based pre-LLM classification returning `{ tool, params }`. Order matters: more specific patterns (order number regex, reading list add/remove) must come before broader ones (bare "cart", bare "reading list").
2. **`executeTool(tool, params, userId)`** — dispatches to the DB module. All queries are parameterized.
3. **`chat(userId, message, history)`** → returns `{ response, toolUsed, toolResult }`. `toolResult` is populated **before** the Ollama call, so it can be tested without Ollama running.

Routes at `/api/workshop/sql` and `/api/workshop/nosql` expose `POST /chat`, `POST /reset`, `GET /history/:userId`, `GET /llm-status`.

**DB test isolation:** Both DB modules read `process.env.SQL_WORKSHOP_DB_PATH` / `process.env.NOSQL_WORKSHOP_DB_PATH` at load time — set these env vars **before** `require()`ing the module in tests to point at a temp SQLite file.

### Key Environment Variables (`.env`)
```
PORT=8081
OLLAMA_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://localhost:11434
SECURITY_TESTING_MODE=true   # Enables vulnerable challenge features
LAB_MODE=vuln                 # "vuln" or "fixed" switches challenge behavior
NODE_ENV=development
AI_PROVIDER=ollama            # ollama | bedrock | chatgpt | claude — overrides multiProviderAIService priority order
# Cloud LLM fallback (optional — multiProviderAIService picks first available)
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_REGION=us-west-2
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
# Live-event gate (optional — blocks all traffic until attendees enter shared password)
EVENT_GATE_ENABLED=false
EVENT_GATE_PASSWORD=
```

## Database Schema Management (Required)

Supported installations use the 16 PostgreSQL stores in
`db/postgres/initialize-application.js`, each with separate runtime and migration
roles. Schema changes require forward-only migrations under
`db/postgres/identity-migrations/` or `db/postgres/workshop-migrations/<store>/`;
foundation changes belong under `db/postgres/migrations/`. Never alter an
applied migration. Add defaults through the PostgreSQL seed path while preserving
instructor edits and learner evidence. Qualify fresh, populated and second-run
initialization in owned disposable stores.

`db/initialize-db/` and the `users_auth.db` initialization paths are retained
SQLite fixture references, not supported application schema authority. Neither
`npm run db:initialize-all` nor `./start_all.sh --init-db` runs that legacy tree.
For the complete migration and seed rules, follow `AGENTS.md`.

## Sensitive Info Workshop — Pre-intercept Architecture

`server/routes/sensitiveInfoWorkshop.js` uses a **pre-intercept pattern** for all Sensitive Info Workshop objectives. Rather than relying on Ollama's native tool-calling (`/api/chat` with `tool_calls`), which is unreliable with Llama 3.1:8b, the route detects attack patterns via regex and handles them directly before the message ever reaches `processMessage()`.

**Why:** Llama 3.1:8b ignores tool-call instructions and responds with text, or calls the wrong tools (e.g., calling `check_credit_score` while answering "what are your capabilities?"). The fix is route-level orchestration + `ollamaService.generateResponse()` (reliable `/api/generate`) for summarization.

**Pre-intercept order** (inside the `else` block of `if (isAdminInjection)`):

| Intercept | Detection | Action |
|-----------|-----------|--------|
| Tool enumeration | "what are your capabilities / list all functions" | Build tool list from constants, complete `tool_enum` / `tool_version` |
| LLM identity | "what AI model are you / what is your endpoint" | Return model + endpoint string, complete `llm_identify` |
| Path traversal | `../` in message | Call `get_transaction_history` or `download_statement` directly, summarize file via Ollama |
| SSRF | `http(s)://` URL in message | Call `check_credit_score` directly, summarize HTTP response via Ollama |

**For admin injection** (`ignore previous instructions` / `[admin mode]` etc.) the `if (isAdminInjection)` branch rewrites the message into a clean instruction and lets the LLM call admin tools naturally — admin tool-calling works reliably for that path.

**Adding a new pre-intercept:** Add detection regex + direct tool call + `ollamaService.generateResponse(buildYourSummaryPrompt(...))` before the `urlMatch` SSRF block. Always return early with `{ response, toolCalls, newlyCompletedObjectives, mode }`.

**Supporting files:**
- `server/sensitive_files/config/` — real files on disk read by path traversal (`llm_config.yml`)
- `server/workshop_data/transactions/` — JSON files for legitimate `get_transaction_history` calls
- `server/workshop_data/documents/` — PDF/text files for legitimate `download_statement` calls
- `server/services/sensitiveInfoWorkshopAgent.js` — `executeVaultCorpTool()`, `detectObjectives()`, `buildToolEnumResponse()` are exported and used directly by the route

## CTF Prompt Injection Challenge

A 10-level Gandalf/HackAPrompt-style CTF where students extract secrets from progressively harder AI guardians.

**Architecture:** `server/routes/ctf.js` → `server/database/ctfDb.js` (`ctf.db`) + `server/services/promptInjectionCTF.js` (classifier) + `server/services/ctfDefenseLayers.js` (defense layers).

**Level progression:** L1–L7 use static defense layers (none, output filter, input filter, meta-judge, persona guard, polyglot filter). L8–L10 add adaptive blocking:
- L8 `technique` mode — per-user technique tag memory (each tag usable once per level)
- L9 `payload` mode — global fuzzy-hash blocklist of winning payloads across all users
- L10 `hybrid` — both technique + payload blocking, plus all defense layers active

**Admin:** Managed from Admin Dashboard → CTF Management (7 sub-tabs: Overview, Levels, Solutions, Attempts, Leaderboard, Config, Danger Zone). API at `/api/ctf/admin/*`. The **Solutions** tab (admin-only spoilers) surfaces verified per-level payloads from `server/data/ctfSolutions.js` via `GET /api/ctf/admin/solutions`.

**Key tables (ctf.db):** `ctf_config`, `ctf_stages`, `ctf_participants`, `ctf_progress`, `ctf_attempts`, `ctf_leaderboard`, `ctf_technique_blocklist`, `ctf_payload_blocklist`, `ctf_bans`, `ctf_events`, `ctf_sessions`.

**Tests:** `node tests/promptInjectionCTF.smoke.test.js` (unit, no server) and `SERVER_AVAILABLE=1 node tests/ctfAdmin.smoke.test.js` (integration).

## Solution & Hint System Pattern

Challenge solutions/hints follow a consistent pattern across workshops (DPI, XSS Workshop):

| Layer | File | Role |
|-------|------|------|
| Data | `server/data/<name>Solutions.js` | Source of truth — exports solution content objects |
| DB | `users_auth.db` — `*_solution_visibility` table | Admin toggle: enabled/disabled per challenge/exercise |
| DB | `users_auth.db` — `*_solutions` table | Editable solution content (seeded from data file) |
| API (student) | `server/routes/solutions.js` | `GET /api/solutions/<workshop>/...` — checks visibility, returns content |
| API (admin) | `server/routes/admin.js` | Toggle visibility, preview, update content |
| Frontend | `client/src/pages/challenges/<Challenge>.js` | Fetches status on mount; shows hint/solution panel per-objective |
| Admin UI | `client/src/pages/ComprehensiveAdminDashboard.js` | Visibility toggles + solution editor per challenge/objective |

The student `GET /api/solutions/.../status` endpoint returns which exercises have solutions enabled (no auth required). Content endpoints return 403 if disabled.

## Workshop Sync Invariants (ALWAYS enforce)

Whenever you **add, remove, edit, enable, or disable an exercise or objective**, the toggles, stats, and student views below MUST stay in sync — all driven from the database, never hardcoded. Verify every one of these after any such change:

### Admin toggle sync (`/admin/challenges` ⇄ `/admin/solutions`)
- **Challenge Active** toggle (`/admin/challenges`) ⇄ **Exercise visibility** on the admin dashboard — one flip updates both. Source: `challenge_visibility.is_visible`.
- **Solutions Visible** — the solution toggle must update AND read consistently on **both** `/admin/challenges` and `/admin/solutions` (bidirectional sync). Master toggle: `challenge_visibility.show_solutions`; per-objective: `<workshop>_objective_solutions.solutions_enabled`. Flipping the master on `/admin/challenges` must cascade to the per-objective rows (and be reflected on `/admin/solutions`), and vice-versa.
- **Hint visibility** — toggle on `/admin/challenges` must update the hint state (`challenge_visibility.show_hints` + `workshop_hint_visibility`), reflected on `/admin/solutions`.
- The solution/hint toggles are **decoupled**: hiding hints must not hide solutions and vice-versa.

### Student dashboards are 100% DB-derived (`/workshop-dashboard`, `/workshop/challenges`, `/workshop/progress`)
- **Single source of truth:** objective TOTALS come from `workshop_objective_visibility WHERE is_enabled=1`; COMPLETIONS from `workshop_objectives_progress` (INNER JOIN visibility on `workshop_key,objective_id`, `is_enabled=1`); TIME from `workshop_time_tracking.duration_seconds`. **Never** compute totals from a hardcoded list.
- Objective **labels** come from the shared `WORKSHOP_OBJECTIVES` map in `server/routes/workshop.js` (id→text), intersected with the visibility table. Do NOT re-introduce a per-endpoint hardcoded objective `switch` — that caused a 96-vs-106 drift. Both `/api/workshop/challenges` and `/api/workshop/progress` MUST derive their objective lists the same way so their counts can never diverge.
- The challenge_key→workshop_key remap is the single `CHALLENGE_TO_WORKSHOP_KEY` constant in `server/routes/workshop.js`; add every new challenge whose keys differ.
- All three dashboards MUST show the SAME `X/total` objective count, the same "exercises completed", and the same time. After any exercise/objective change, re-verify parity across all three (API sums + rendered DOM).

### Student page hint/solution gating (`/workshop/challenges` and the challenge page)
- Per-objective hint and solution buttons MUST reflect the admin toggles live — gated by both the master `challenge_visibility.show_hints`/`show_solutions` AND the per-objective `<workshop>_objective_solutions.solutions_enabled` / `workshop_hint_visibility`.

### Adding / updating objectives — required steps
When you add or rename an objective:
1. Add it to `WORKSHOP_OBJECTIVES` (label) in `server/routes/workshop.js`.
2. Seed it into `workshop_objective_visibility` (+ `workshop_hint_visibility`) in **both** `server/database/authDb.js` (`KNOWN_OBJECTIVES`) and `db/initialize-db/seeds/01_users_auth.js`, plus a stale-row purge so removed IDs disappear.
3. Ensure the completing route writes `workshop_objectives_progress` (so it counts) and `workshop_time_tracking` (so time updates).
4. Confirm the objective renders **green when completed** on `/workshop/challenges` (the `completed` flag flows from `workshop_objectives_progress` → per-card objective list).
5. Re-run the parity verification across all three dashboards + admin toggles.

**After any exercise/objective add or update, these syncs are not optional — verify them before considering the task done.**

## Challenge vs Platform Code

- **Platform (secure, hardened)**: `server/routes/secureAuth.js`, `server/middleware/`, `server/database/platformDb.js`, `server/database/secureDbManager.js`, admin routes
- **Challenges (intentionally vulnerable)**: `server/routes/sqli*`, `server/routes/xss*`, `server/routes/ctf*`, `server/routes/workshop*`, all challenge databases

The `LAB_MODE` env var (`vuln`/`fixed`) toggles challenge behavior in several routes — both modes must be maintained when editing challenge routes. The frontend enforces this via `VulnerabilityGuard` and `VulnerabilityTemplate` components.

## Default Credentials

Fresh supported PostgreSQL setup creates only two platform users: `admin` / `admin123` (level 2 administrator) and `student` / `student 123` (one literal space). Passwords are hashed in PostgreSQL. The private `~/.owasp-ai-goat/<workspace-id>/administrator.json` records the installation’s administrator credential. Never reset existing users or passwords during upgrade/repair/reseed. Legacy SQLite fixture credentials are not supported startup authority.

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

### New databases

| File                                            | Purpose                                                            |
|-------------------------------------------------|--------------------------------------------------------------------|
| `server/database/secureshop.db` (extended)      | shop_users, products, reviews, cart, orders, policies, emails, tickets |
| `server/database/secureshop_agents.db` (new)    | agent_sessions, agent_trace, audit_events, mcp_registry, mcp_tool_cache, mcp_schema_history, vector_documents, vector_index_meta |

Vector index files live under `server/database/vector-indexes/<corpus>.hnsw`
(one per corpus — currently `manuals`, `policies`, `reviews`, `products`).

### Agent Host process

The 17 task agents are hosted by a **separate Node process** at
`agent-host/index.js`, port **8082** (env `SS_AGENT_HOST_PORT`). Each agent
exposes an MCP-over-SSE endpoint at `GET /mcp/<agent-name>`. The backend
process talks to them via `McpClientPool` in
`server/services/secureshop/mcpClientPool.js`. `AgentHostSupervisor` in the
same directory boots and monitors the child process.

### Provider ladder

`server/services/secureshop/providerRouter.js` picks the first available:
1. **mock** — deterministic scripted responses (test default)
2. **ollama** — `llama3.1:8b` at `http://localhost:11434`
3. **anthropic** — Claude via `ANTHROPIC_API_KEY`
4. **openai** — GPT via `OPENAI_API_KEY`
5. **bedrock** — Claude on AWS via `BEDROCK_MODEL_ID` + `AWS_REGION`

Set `AI_PROVIDER=<name>` in `.env` to force one. The parity test suite proves
identical exploit outcomes across Mock, Anthropic-mock, and OpenAI-mock.

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
- `docs/secureshop/vuln-map.md` — auto-generated vuln table (64 ids as of M6)

## Workflow Orchestration

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
