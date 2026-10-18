# Data Model and Initialization

## Database layers

DVAIA uses many SQLite files to isolate curriculum and operational domains.
There are also three access styles:

- callback-based `sqlite3` in the workshop platform and most legacy labs;
- synchronous `better-sqlite3` in SecureShop/Agent Host;
- optional `mysql2` for the MySQL sensitive-info variant.

`server/database/sqliteTuning.js` patches `sqlite3.Database` before any normal
server connection opens, applying WAL and a busy timeout. `better-sqlite3`
connections configure themselves in their owning modules/tests.

## Reproducible DB build

`db/initialize-db/run-all.js` walks `DB_MAP` in order. For each database it:

1. opens/creates `<name>.db`;
2. executes the main SQL schema;
3. applies additive schemas statement-by-statement, ignoring duplicate-column
   errors;
4. invokes the main JS seed;
5. invokes additive seeds.

The default output directory is `server/database`; schemas and seeds live next
to the runner. `DB_OUTPUT_DIR`/`options.outputDir` redirect schema creation.
Current implementation detail: `runSeedWithDir` constructs its DB path from the
module-level default `DB_DIR`, not its `outDir` argument. Tests/tools that expect
fully redirected seeded output must account for or correct this before relying
on it.

## Database map

| DB | Main schema/seed | Purpose and primary tables |
|---|---|---|
| `users_auth.db` | `01_users_auth.*` | workshop users/sessions/permissions/config/activity, central progress, visibility, hints, solution registries, PI/RAG/email progress |
| `dvaia.db` | `02_dvaia_workshop.*` | legacy products/cart/orders/reviews/comments/files/AI plus older platform/admin/progress rows |
| `secureshop.db` | `03` + `17/19/20` schemas; `03/17/19/20/21/22` seeds | SecureShop business/accounts/products/reviews/cart/orders/policies/email/tickets/addresses/sessions |
| `ctf.db` | `05_ctf.*` | CTF stages/config/participants/sessions/progress/attempts/events/leaderboard/bans/blocklists |
| `sensitive_info.db` | `06_sensitive_info.*` | legacy documents and access logs |
| `sensitive_info_workshop.db` | `08_sensitive_info_workshop.*` | FinFlow registry/extractions/tool log/chat/progress/achievements/solutions |
| `platform_secure.db` | `07_platform_secure.*` | alternate secure-server users/permissions/progress |
| `xss_challenge.db` | `09_challenge_xss.*` | legacy vulnerable content plus modern XSS workshop profiles/emails/progress |
| `ctf_ai_challenge.db` | `10_ctf_ai_challenge.*` | alternate secure-server CTF AI interactions/attempts/leaderboard |
| `excessive_agency.db` | `11_excessive_agency.*` | lab users, notes, orders, refunds, audit, progress |
| `supply_chain_workshop.db` | `12_supply_chain_workshop.*` | objectives/progress and solution visibility/content |
| `sql_workshop.db` | `13_sql_workshop.*` | ARIA products/cart/orders/receipts/chat history |
| `nosql_workshop.db` | `14_nosql_workshop.*` | NOVA papers/authors/lists/chat plus solution rows |
| `csrf_workshop.db` | `15_csrf_workshop.*` | wallets/progress/tool log |
| `mcp_workshop.db` | `16_mcp_workshop.*` | progress and tool log |
| `secureshop_agents.db` | `18` + `19/21` schemas; `18/22` seeds | agent session/trace/provider/audit/jobs, MCP registry/cache/history, vectors, ACL/config |

Several runtime modules can create or migrate their own DBs even if the
reproducible initializer was not run. That is convenient for a fresh local
start but creates dual schema ownership.

## Runtime DB owners

| Module | Ownership |
|---|---|
| `authDb.js` | `users_auth.db`; integrity recovery, schema/migrations, defaults and all central workshop metadata |
| `init.js` | `dvaia.db`; legacy users/products/orders/reviews/files/conversations/visibility |
| `adminSchema.js` | reusable legacy/admin tables and default configuration |
| `ctfDb.js` | `ctf.db`; schema migrations and default stages/config |
| `secureshop.js` | baseline `secureshop.db` tables |
| `sensitiveInfoDb.js` | legacy disclosure DB and curated sensitive fixtures |
| `sensitiveInfoWorkshopDb.js` | FinFlow tables, files, resets, solutions |
| `xssWorkshopDb.js`, `xssEmailDb.js` | modern and legacy XSS state |
| `csrfWorkshopDb.js` | CSRF progress/tool/wallet tables |
| `mcpWorkshopDb.js` | MCP progress/tool log; supports path override |
| `sqlWorkshopDb.js` | ARIA operations, history and lab-mode query behavior |
| `nosqlWorkshopDb.js` | NOVA operators/document mapping, operations and history |
| `supplyChainWorkshopDb.js` | supply-chain progress and solutions |
| `excessiveAgencyLabDb.js` | class-based lab data/action API |
| `mysqlSensitiveInfoDb.js` | optional MySQL pool/schema plus fallback expectations |
| `platformDb.js`, `challengeDb.js`, `secureDbManager.js` | alternate secure-server isolation architecture |

## `users_auth.db` domains

This file is the effective platform database of the default app, despite its
historical name. Major table groups:

- identity: `users`, `user_sessions`, `admin_permissions`, verification/reset;
- operations: `activity_logs`, `security_settings`, `system_config`;
- refresh coordination: `app_change_revisions`, keyed by global/workshop/user
  scope plus change category with a monotonic persisted revision;
- attendee preferences: `workshop_user_modes`, keyed by authenticated user and
  workshop with `vuln`/`fixed` state;
- challenge metadata: `challenge_config`, `challenge_visibility`,
  `challenge_solutions`;
- normalized progress: `student_progress`, `workshop_progress`,
  `workshop_objectives_progress`, `workshop_time_tracking`;
- visibility/content: objective visibility, hints and hint visibility, plus
  lab-specific solution visibility/content tables;
- lab auxiliary state: prompt/RAG/email progress, sent email log, CSRF victim
  state.

`authDb.js` continually reconciles the canonical challenge/objective/hint and
solution data, deletes retired IDs, and adds missing migrations. A SQL schema
edit alone may be overwritten or complemented on server boot.

`changeRevisionStore.js` creates `app_change_revisions` idempotently at runtime.
Global revisions are shared with every authenticated attendee, workshop
revisions are returned only when that workshop was requested, and user
revisions are selected from authenticated identity. Revisions survive process
restart and are coordination metadata only; clients still refetch authoritative
configuration/content after detecting a change. Every ordinary server start
increments the global `server_restart` category before revision snapshots are
served. A failed increment is retried with bounded backoff, allowing clients
that survived a process replacement to reconcile even if the prior process
stopped between an admin write and its normal change signal.

`workshopModeStore.js` creates `workshop_user_modes` and its revision triggers
idempotently. A mode write and the attendee's private `mode` revision increment
share one SQLite statement, so
other attendees never observe or reload for that preference. Existing workshop
defaults are used only until that attendee saves a value; all shipped
interactive labs retain their vulnerable first-use default.

`legacyWebSocketRetirement.js` is an idempotent upgrade migration. Both normal
server startup and comprehensive initialization use it to set any pre-existing
`websocket_config.is_enabled` values to `0`; it neither creates that retired
table nor deletes historical rows.

## Progress data model

Progress is intentionally denormalized for backward compatibility:

- `student_progress` tracks challenge-level status;
- `workshop_progress` tracks workshop-level status/start/completion;
- `workshop_objectives_progress` is the central objective ledger;
- each modern lab can retain detailed local objective/action/tool rows;
- `workshop_time_tracking` stores heartbeat sessions;
- CTF uses a completely separate progress/scoring model.

`progressSync.js` is the preferred cross-lab adapter. New workshops should not
invent another platform-level progress table.

## SecureShop data model

### Business database

Core relationships:

```text
shop_users
  ├─ user_addresses / user_sessions
  ├─ cart_items → products → categories/product_images/product_manuals
  ├─ orders → order_items → products
  ├─ reviews → products
  ├─ email_threads → emails
  └─ support_tickets

policies influence supervisors and pricing strategy
coupons influence cart/order totals
```

### Agent/control database

```text
agent_sessions → conversation messages/token usage
agent_trace → supervisor/task hops and policy violations
audit_events → admin/user-management actions
mcp_registry → mcp_tool_cache → mcp_schema_history
vector_documents + vector_index_meta → retrieval corpora
tool_permissions + system_config → Layer-B ACL
agent_provider_state / background_jobs → operations UI
```

## Seeds and fixture intent

Seeds do more than create demo rows: they establish canonical identities,
challenge metadata, objective content, vulnerability preconditions, provider
state, MCP registry, bulk products/reviews/orders/email, and ACL defaults. A
schema migration that succeeds on an empty DB can still break the application
if its additive seeds are not updated.

The `server/sensitive_files`, `server/workshop_data`, sidecar `labfs`, sample
documents, and seeded malicious content are fake educational fixtures. Treat
them as code-adjacent test/curriculum assets, not real secrets.

## Schema change protocol

For a table/column change:

1. identify the DB owner and all direct SQL users with `rg`;
2. update the main or additive schema in `db/initialize-db/schemas`;
3. update relevant JS seeds;
4. update runtime create/migration/self-heal code;
5. preserve environment-path overrides and temporary-DB compatibility;
6. update reset/backup/verification scripts;
7. run schema verification and affected unit/integration/vulnerability tests;
8. update this map and file catalog.
