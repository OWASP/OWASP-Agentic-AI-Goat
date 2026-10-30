# OWASP Agentic AI GOAT Code Map

This directory is the load-on-demand engineering map for OWASP Agentic AI GOAT. It describes
the executable architecture through commit
`433296a73f4e251944ff1469591c34c8db63c9c1` (`main`, fetched 2026-08-07), not
just the intended architecture in older docs. Load
[11-main-sync-2026-08-07.md](11-main-sync-2026-08-07.md) first for the module
boundaries introduced after the original line-oriented review.

Use this file first. Load only the linked module file needed for a change.

Current storefront recovery: `client/src/pages/secureshop/bridge/handshake.mjs`
notifies the guest host when a frame reload closes its connection. The host
offers Retry with a fresh frame. `launchHeaders.mjs` keeps launch-header names
compatible with a backend started before the branding rename. See the
[shop guide](../secureshop/README.md) and the handshake, standalone-client, and
guest-landing tests for these contracts.

`SecureShopStandaloneController.mjs` handles signed-in disconnections with
current-frame/epoch fences. Its normal startup may replace a frame once after
`SHOP_FRAME_LOAD_TIMEOUT`, which the handshake emits only before port transfer.
It reuses the existing launch and scene; other failures and mutations are not
replayed. The controller tests cover the retry limit and cancellation fences.

## Analysis coverage

The synchronized branch has 954 tracked files, including this retained
load-on-demand code map and repository instructions. The original review
performed a repository-wide
inventory and structural pass over all behavior-bearing JavaScript/JSX, SQL,
shell/PowerShell/Python, JSON, YAML, HTML, CSS, and Markdown areas, then a
detailed line-oriented read of the composition roots and highest-coupling
modules. Source relationships were cross-checked through imports/requires,
route declarations/mounts, API calls, environment reads, DB table references,
function/class declarations, schemas/seeds, tests, and intentional-vulnerability
annotations.

Generated dependency locks, PNGs and historical SQLite/WAL/SHM fixtures were
classified but are not treated as independent application logic. This retained
map describes an older snapshot; verify current runtime paths in source and
the repository instructions before using its module relationships.

## System in one page

```text
Browser / React :3000
  ├─ OWASP Agentic AI GOAT workshop SPA
  │    └─ REST + scoped polling → Express :8081
  └─ SecureShop SPA (/secureshop/*)
       ├─ REST/SSE → Express :8081
       └─ Express supervisors → MCP-over-SSE → Agent Host :8082
                                               └─ 17 task-agent servers

Express :8081
  ├─ auth/admin/workshop/CTF APIs → users_auth.db + challenge DBs
  ├─ AI facade → Ollama / LM Studio / Bedrock / OpenAI / Anthropic
  ├─ RAG/vector services
  ├─ MCP workshop → four optional sidecars
  └─ SecureShop → secureshop.db + secureshop_agents.db
```

The default process is `server/index.js`. `server/secureServer.js` is an
alternate server that is not referenced by `package.json`, `start_all.sh`, or
the Docker startup path. Files used only by that alternate path are called out
as such in the backend and data maps.

## Load map

| When changing… | Load |
|---|---|
| startup, ports, middleware order, route mounting, providers | [00-runtime-topology.md](00-runtime-topology.md) |
| workshop shell, login, dashboard, admin UI, shared React components | [01-frontend-platform.md](01-frontend-platform.md) |
| platform auth, admin APIs, sessions, logging, visibility, progress | [02-backend-core-auth-admin.md](02-backend-core-auth-admin.md) |
| any workshop, challenge, CTF, AI lab, or its progress/solution flow | [03-workshops-and-ctf.md](03-workshops-and-ctf.md) |
| SecureShop pages, REST endpoints, role surfaces | [04-secureshop-frontend-and-api.md](04-secureshop-frontend-and-api.md) |
| SecureShop supervisors, providers, MCP agents, tool ACL, traces | [05-secureshop-agents-and-mcp.md](05-secureshop-agents-and-mcp.md) |
| schemas, seeds, DB ownership, initialization, data migrations | [06-data-model-and-initialization.md](06-data-model-and-initialization.md) |
| local launch, Docker sidecars, CI, installation | [07-deployment-and-operations.md](07-deployment-and-operations.md) |
| tests, fixtures, verification commands, intentional-vulnerability rules | [08-testing-and-verification.md](08-testing-and-verification.md) |
| a specific file or directory | [09-file-catalog.md](09-file-catalog.md) |
| estimating blast radius before a major edit | [10-change-impact-guide.md](10-change-impact-guide.md) |
| changes introduced by the 2026-08-07 `main` synchronization | [11-main-sync-2026-08-07.md](11-main-sync-2026-08-07.md) |
| Sensitive Information mutable-state ownership and reset ordering | [12-sensitive-info-state-isolation.md](12-sensitive-info-state-isolation.md) |
| XSS Workshop identity across JWT/session restart boundaries | [13-xss-workshop-identity.md](13-xss-workshop-identity.md) |
| protected-route visibility, retry, and nested-template behavior | [14-visibility-route-state.md](14-visibility-route-state.md) |
| SQL/NoSQL attendee-scoped progress fallback and disclosure ownership | [15-sql-nosql-progress-cache.md](15-sql-nosql-progress-cache.md) |
| polling timeout-load safeguards and measured residual risk | [16-polling-load-safeguards.md](16-polling-load-safeguards.md) |
| dashboard student-reset ownership, local progress stores, and manual reset limits | [17-student-dashboard-reset-ownership.md](17-student-dashboard-reset-ownership.md) |
| consolidated Workshop reliability change list and major-issue release gate | [18-workshop-reliability-change-ledger.md](18-workshop-reliability-change-ledger.md) |

## Architectural modules

| Module | Entry point | Owns | Depends on |
|---|---|---|---|
| Local launcher | `start_all.sh` | preflight, DB healing, Ollama, app lifecycle | `scripts/lib/preflight.sh`, npm scripts |
| Default backend | `server/index.js` | Express, HTTP, static build, polling APIs, async subsystem boot | all route groups, middleware, DB initializers, AI services |
| Workshop frontend | `client/src/App.js` → `WorkshopApp` | auth-gated workshop/admin/CTF routes | `AuthContext`, workshop APIs |
| Workshop platform | `server/routes/auth.js`, `admin.js`, `workshop.js` | users, sessions, config, visibility, progress, solutions | `users_auth.db`, change revision service |
| Challenge labs | `server/routes/*Workshop.js` and challenge pages | vulnerable interactions and objective progress | per-lab DB/service/data modules |
| CTF | `server/routes/ctf.js` | stages, attempts, defenses, write-triggered leaderboard plus polling | `ctf.db`, AI providers |
| SecureShop frontend | `client/src/App.js` → `SecureShopApp` | public/customer/merchant/admin UI | SecureShop REST/SSE APIs |
| SecureShop API | `server/services/secureshop/index.js` | async boot and six route builders | Agent Host, provider router, two DBs |
| SecureShop supervisors | `server/services/secureshop/supervisors/*` | LLM/tool loop, policies, ACL, trace | providers, MCP client pool, manifest |
| Agent Host | `agent-host/index.js` | 17 MCP-over-SSE task agents | shared DB/context/trace and tool modules |
| MCP workshop sidecars | `docker-compose.yml`, `server/services/mcp/*` | sandbox, Mailpit, SSRF target, rogue MCP | Local Docker |
| Reproducible data | `db/initialize-db/run-all.js` | 16 SQLite DB builds from schemas and seeds | SQL schemas, JS seed modules |

## Core invariants for major edits

1. `require('dotenv').config()` and SQLite tuning must execute before modules
   that capture environment variables or open databases.
2. Middleware order in `server/index.js` is behavior: request IDs/logging,
   compression/CORS/body parsing, cookie/session handling, session manager,
   request context, event gate, static assets, then routers.
3. SecureShop routers are placeholders mounted before the 404 handler and are
   populated asynchronously after Agent Host boot. Moving them below the 404
   handler makes the subsystem unreachable.
4. Workshop challenge IDs, workshop keys, objective IDs, progress tables,
   visibility tables, solution registries, frontend route IDs, and admin
   mappings form one distributed contract. Rename them as a coordinated set.
5. `db/initialize-db` is the reproducibility source, but several runtime DB
   modules also perform migrations/self-healing. Schema changes must update both
   sides where applicable.
6. SecureShop uses two databases: business data in `secureshop.db`, agent and
   control-plane state in `secureshop_agents.db`.
7. Code marked `@intentional-vulnerability` is curriculum behavior. Do not
   harden or remove it unless the exercise itself is intentionally redesigned
   with its tests and vulnerability map.
8. Test code relies heavily on environment-path overrides and temporary DBs.
   Preserve those seams when refactoring singletons.

## Known architecture drift

- `docs/ARCHITECTURE.md` describes `secureAuth.js` as the platform auth path,
  but the default server mounts `server/routes/auth.js`. The secure route pair
  is only mounted by the unused alternate `secureServer.js` entry point.
- Existing SecureShop docs describe the older `/secureshop/v2/*` location as
  primary. Current `App.js` treats `/secureshop/*` as primary and `/v2` as a
  transitional alias.
- Some existing agent documentation lists historical tool names. The source
  under `agent-host/agents/*/tools` and its tests are authoritative.
- `server/routes/admin.js` and `client/src/pages/ComprehensiveAdminDashboard.js`
  are oversized integration modules (about 5.3k and 7.2k lines). They are the
  highest-coupling refactor targets and should be split along the boundaries in
  the change-impact guide.

## Documentation maintenance rule

When application wiring changes, update this directory in the same commit:

- update this index if a module boundary or entry point changes;
- update the one module file that owns the behavior;
- update `09-file-catalog.md` for additions, removals, or ownership changes;
- update `10-change-impact-guide.md` if the dependency/blast-radius model changes.
