# Change Impact Guide

Use this before major edits to identify the smallest coherent module and the
contracts that cross it.

## Dependency hotspots

| Hotspot | Why coupled | Preferred extraction boundary |
|---|---|---|
| `server/routes/admin.js` | users, config, every lab's visibility/solutions, logs, providers, DB reset | sub-routers: users, exercises, content, analytics, operations, providers |
| `ComprehensiveAdminDashboard.js` | data loading, mutations, routing, modals, all admin renderers | section routes + domain hooks + domain views/modal packages |
| `database/authDb.js` | platform schema, migrations, default content, validation and DB lifecycle | connection/lifecycle, migrations, metadata seeds, auth security utilities |
| `server/routes/workshop.js` | canonical catalog and normalization of many progress models | catalog, progress read model, instructor/compat, time tracking |
| `multiProviderAIService.js` | generation, provider adapters, fallback, health, config and logs | provider interface/adapters, router/fallback, health/config |
| `ollamaService.js` | legacy compatibility, generation, tool simulation, concurrency | preserve API facade; extract transport/scheduler/prompt helpers behind it |
| `sensitiveInfoWorkshopAgent.js` | prompts, state, objective judges, tool catalog, fake files | objective registry, tool implementations, state/session, response formatting |
| three SecureShop supervisors | near-parallel loops with role differences | shared loop engine + explicit role policy/config adapters |

## Change recipes

### Add or rename a workshop

Touch as one unit:

- frontend lazy route/page/nav/dashboard/challenge detail;
- server route mount and router;
- service/tool router;
- DB schema/runtime init/seed;
- canonical challenge and objective IDs in `authDb.js` and `workshop.js`;
- progressSync calls and reset behavior;
- hints, solutions, visibility/admin panels;
- tests and documentation.

Avoid aliasing only in the frontend. Old stored keys require a DB migration or a
deliberate compatibility map.

### Change authentication/session fields

Search and validate:

- `authDb.js` schema/migrations and `01_users_auth.sql`;
- `auth.js`, `sessionManager.js`, `adminAuth.js`, rate limiter;
- admin user queries and frontend user-role checks;
- `AuthContext.js`, login/signup/profile pages;
- monitoring auth and private polling identity if relevant;
- SecureShop auth separately if the field is shared conceptually.

### Split the admin router/UI

Preserve public paths while moving handlers/views. Introduce a shared admin DB
adapter and canonical exercise registry first; otherwise each new submodule may
copy the same mappings and increase drift. Move one domain plus tests at a time.

### Change AI provider behavior

Determine which layer owns the caller:

- legacy Ollama-only routes → `ollamaService.js`;
- modern workshop → `multiProviderAIService.js`;
- SecureShop → `services/secureshop/providers` and `providerRouter.js`.

Then verify health/admin switching, log format, timeouts, deterministic fallback,
tool-call normalization, and provider parity.

### Change a SecureShop tool

Follow the eight-surface checklist in `05-secureshop-agents-and-mcp.md`.
Also search direct REST imports of the tool; not all executions travel through
MCP/supervisors.

### Change a DB table

Update schema, additive migration, seed, runtime create/migrate logic, every SQL
query, reset/backup, temp-path tests, and this map. Verify a completely fresh DB
and an existing pre-migration DB.

### Change startup or middleware

Preserve environment-before-require, SQLite tuning-before-open, route-before-404,
event-gate health exceptions, async subsystem boot, and child shutdown. Test dev
proxy and production static-build modes separately.

### Change deployment config

For local operation, check the supported setup/start scripts, the PostgreSQL
store manifest, and local Compose sidecars together. The former AWS deployment
implementation is no longer part of this repository.

## Cross-module contracts

| Contract | Producers | Consumers |
|---|---|---|
| challenge/workshop/objective IDs | seeds, auth DB metadata, workshop services | catalog, admin, frontend, progress, hints/solutions, tests |
| user/JWT shape | auth router/session manager | frontend contexts, admin guards, monitoring, workshops |
| visibility revisions | admin mutations/change revision service | authenticated polling clients, then nav/dashboards/challenge pages |
| LLM log record | provider services/llmLogger | admin log/stats UI and teaching tools |
| SecureShop tool schema/name | task server/tool manifest | supervisors, direct route wrappers, ACL seeds, UI traces, tests |
| `_ss_caller` | supervisors/MCP pool | Agent Host server wrappers and Layer-C guards |
| trace event shape | supervisor/task trace writers | Agent Lane, admin overview, integration tests |
| DB path overrides | tests/deploy config | every SecureShop/individual lab DB opener |
| provider result shape | all adapters | workshop services and SecureShop supervisors |
| progress completion | lab route/service | central progress, dashboard, admin analytics |

## Suggested target modularity

This is a safe direction for major refactoring without changing behavior:

```text
server/
  app/                    composition root and lifecycle
  platform/
    auth/                 router, service, repository, policy
    admin/                domain sub-routers
    catalog/              challenge/objective registry
    progress/             central read/write model
    observability/        HTTP/LLM logs and metrics
  labs/
    <lab>/                router, service/tools, repository, content registry
  secureshop/             current subsystem, further split into api/agent/data

client/src/
  platform/
    auth/ dashboard/ challenges/ admin/<domain>/
  labs/<lab>/
  secureshop/             current subsystem
  shared/                 truly cross-application primitives only
```

The first enabling step should be a typed/validated registry for challenge and
objective metadata. The same data is currently repeated across DB initialization,
student catalog, admin UI, page routing, solution/hint maps, and tests.

## Refactor sequence

1. Add characterization tests for the path/domain being moved.
2. Extract pure registries/adapters without changing routes or DB schema.
3. Move one domain behind the existing public interface.
4. Run targeted and cross-contract tests.
5. Remove old code only after searches show no live consumers.
6. Update this code map in the same commit.

### Change refresh/polling behavior

- classify each producer as global, workshop, or signed-in-user scope;
- never derive private scope from a request body/query user ID;
- persist the authoritative change before incrementing its revision;
- compare revisions first and refetch full data only when a relevant revision
  changes;
- reconcile once when the initial revision baseline is established so a
  concurrent initial-load change cannot be absorbed;
- coalesce and retry revision-write failures by scope;
- retain the startup-wide revision bump so a process crash cannot permanently
  hide a just-persisted admin change from an already-open browser;
- keep attendee progress/mode changes user-scoped; reserve global/workshop
  revisions for applicable admin changes and genuinely shared state;
- test restart persistence and two-user isolation before removing the older
  transport.

### Change vulnerable/fixed mode behavior

- treat `workshop_user_modes` as the authority for interactive labs;
- derive the owner only from authenticated request context;
- pass stored mode explicitly into agents, tools and database operations;
- never trust a chat request's mode field and never store mode in a process
  global or shared service instance;
- keep mode revision notifications private to the attendee.

## Common traps

- treating older architecture docs as more authoritative than `server/index.js`;
- assuming `npm test` covers non-SecureShop workshops;
- changing a challenge ID in one of its many registries only;
- fixing an intentional vulnerability during cleanup;
- moving async SecureShop routers below the global 404;
- opening SQLite before the global tuning patch;
- capturing env-derived DB paths/secrets too early for isolated tests;
- assuming a direct SecureShop REST action uses the supervisor/ACL path;
- deleting “duplicate” progress tables before checking legacy/admin consumers;
