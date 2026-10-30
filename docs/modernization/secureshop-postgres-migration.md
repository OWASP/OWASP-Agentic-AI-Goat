# SecureShop v2 PostgreSQL migration design

Status: source review only, 2026-09-11. No SecureShop implementation or working database changes were made for this review.

The requested lowercase `docs/secureshop/vuln-map.md` and `architecture.md` do not exist in this checkout. Their current equivalents are `docs/secureshop/VULNERABILITIES.md` and `ARCHITECTURE.md`, which were reviewed. The coverage script requires 62 IDs; the generated vulnerability map contains 66, adding `llm03-supply-chain`, `path-traversal`, `sqli-coupon`, and `xss-stored-review`. Preserve all mapped sinks, not only the minimum 62 checked by the script. Do not regenerate away differences or remove annotations to make migration tests pass.

## Store boundaries and call graph

The backend serves HTTP/SSE and runs three LangGraph supervisors. Its separate agent-host process serves 17 MCP task agents. Both processes currently read/write the same two SQLite files, but through several independent connection helpers. Replacing only `agent-host/shared/db.js` would miss direct connections in backend routes, audit tools, vector storage, sessions, ACLs, manifests and traces.

| Boundary | Current files | Migration contract |
| --- | --- | --- |
| Backend commerce/account UI | `server/routes/secureshop/{auth,customer,merchant,admin}.js` | Named asynchronous operations for accounts, sessions, addresses, catalog, reviews, cart/orders, inventory, reports and administration; preserve existing response fields and status codes. |
| Cross-agent commerce tools | `agent-host/agents/{product-search,summarizer,price-advisor,cart,support,listing,inventory,pricing-strategy,review-moderator,analytics,email,user-management,policy}/tools/*` | Async native store methods; explicitly named raw-query teaching operations retain unsafe SQL construction at the annotated sink. |
| Connections/startup | `agent-host/shared/db.js`, `agent-host/index.js`, `server/services/secureshop/{index,agentHostSupervisor}.js` | Bounded process-local PostgreSQL pools, awaited schema readiness, explicit shutdown; no SQLite fallback in selected PostgreSQL mode. Child readiness must fail if its database is unavailable. |
| Supervisor conversations | `server/services/secureshop/sessionStore.js`, `server/agent-runtime/secureshopSupervisorGraph.js`, three supervisor modules | Existing Promise API is retained; transactional message append and token increments prevent lost updates between backend workers. Tool declarations remain before tool results. |
| Policy, ACL, manifest | `server/services/secureshop/supervisors/policyLoader.js`, `toolAcl.js`, `toolManifest.js` | Convert synchronous lookups and callers to awaited functions. Preserve the seeded ACL log-only behavior, explicit enforcement switch, verbatim policy content and external poisoned tool descriptions. |
| Traces | `server/services/secureshop/trace.js`, `agent-host/shared/trace.js` | Awaitable batch persistence, bounded queue, unique event IDs and ordered event retrieval across processes. Preserve live SSE event names and raw teaching evidence fields. |
| Registry/audit tools | `agent-host/agents/{mcp-registry,audit}/tools/index.js` | Native agents-store operations for registry, tool cache, schema history and audit records. Preserve rug-pull/schema changes, permissive registration and unbounded teaching reads. |
| Vectors | `server/services/secureshop/vectorStore.js`, `agent-host/shared/vectorStore.js`, upload/search tools and admin rebuild/count calls | PostgreSQL documents and corpus generations become authoritative; both processes observe committed changes without trusting a stale local HNSW file. |

Textual inventory found 88 `.prepare(` sites in the four backend route files, 27 in six backend service files, and 68 in 22 agent-host files. These counts include explanatory comments, so they are a search baseline rather than a count of distinct queries. `uploads` and `system` also belong in the migration proof even where their effects are filesystem/network operations instead of direct SQL.

Additional shared surfaces must be assigned explicitly: `server/database/secureshop.js` and schema/seed `03_secureshop`, `17_secureshop_v2`, `18_secureshop_agents`, both `19_*` files, `20_secureshop_v2_account`, and `21_secureshop_v2_rbac`. The legacy `server/routes/secureshop.js` shares the commerce database; root must migrate that consumer before a shared-database cutover. Otherwise v1 and v2 would silently diverge into separate datasets.

## Async changes that must travel together

MCP handlers are already declared async, but many branches return `_wrap(search(args))`, `_wrap(personalizedFeed(args))` or similar synchronous tool results. Every converted branch must await the tool before JSON serialization; otherwise the MCP response can become `{}` while the database operation continues after the response. `agent-host/shared/graphServer.js` cannot repair an already-stringified Promise. Update each affected `agents/*/server.js` alongside its tool implementation and test the real MCP envelope.

The supervisor graph currently calls `buildPolicyBlock`, `manifest.buildExternalMcpPromptBlock` and `checkToolAcl` synchronously. Change these graph nodes together with their providers. A Promise must never be concatenated into the system prompt or interpreted as an ACL decision. `ToolManifest.refresh()` must await persistence before exposing the refreshed view. Admin route callers of vector `count()` must await its new return value.

Trace `flush()` is currently synchronous; backend emits its in-memory SSE event before flush, while agent-host uses `setImmediate(flush)`. Define and test the distinction between live emission and durable persistence. Await final flush before reporting durable completion, preserve batches after transient errors, and drain/close on process shutdown. Do not replay an already-executed tool because a later trace write failed.

## Database and transaction design

Retain two dedicated challenge databases, commerce and agent state, isolated from platform identity and the other workshops. Proposed configuration names are `SECURESHOP_DATABASE_URL`, `SECURESHOP_MIGRATION_DATABASE_URL`, `SECURESHOP_AGENTS_DATABASE_URL`, and `SECURESHOP_AGENTS_MIGRATION_DATABASE_URL`, with matching named runtime roles and separate migration roles. These names are proposals until root coordinates bootstrap. Pool budgeting must include both pools in both processes; no pool per task agent. Runtime roles must not acquire platform schemas, migration permissions or server administration privileges. Do not add per-user row security that would remove intentional IDOR/PII exercises.

Use explicit native schema migrations and idempotent pure seed modules. Eliminate route-time `CREATE TABLE`, `ALTER TABLE`, and `PRAGMA` probing after startup readiness. Preserve stable seed IDs, edited data, raw HTML, JSON-string DTO fields, decimal serialization, timestamps and affected-row counts. `RETURNING` replaces `lastInsertRowid`; explicit conflict clauses replace `INSERT OR REPLACE`, whose delete/reinsert behavior is not equivalent to PostgreSQL updates.

Transaction groups:

- Message append and token consumption: row lock or atomic append under the session identity; never a read/overwrite race and never a database transaction spanning model inference.
- Checkout/order creation, related order items/cart effects, account default-address changes, and multirow bulk imports: inventory actual operations before defining transaction boundaries; preserve intentional ownership/authorization omissions.
- Native manifest refresh: delete only native cache entries and replace them atomically. External registry rows must survive, preserving the poisoned-description chain.
- Registry changes: group registry/cache/history writes where they share a database, while retaining the intentional schema-check/dispatch gap.
- Vector add: document plus corpus revision in one transaction. Embed outside the transaction. Rebuild a staging generation and publish it atomically instead of deleting the active corpus before a lengthy rebuild finishes.
- Commerce mutation plus audit in the other database cannot honestly be described as one ordinary PostgreSQL transaction. Use an explicit durable outbox or a documented partial-success protocol. An outbox must be delivered before a chained audit-summary tool reads the new event; preserve the user-management-reason → audit-log injection chain. A failed audit delivery must not cause duplicate commerce mutations.

Initially keep embedding arrays and exact cosine retrieval backed by PostgreSQL, preserving existing hash-fixture behavior and poisoned-content inclusion. An optional process-local HNSW index is a generation-keyed derived cache, never authority. Avoid shared mutable index files as the only cross-process synchronization. No new vector extension is required for the first migration.

## Curriculum dialect conflicts

These require reviewed PostgreSQL-specific payloads and expected outputs, not a generic SQL translator or newly parameterized sinks:

| Surface | Conflict and required proof |
| --- | --- |
| `product-search/tools/search.js` | Raw interpolated UNION sink must remain. PostgreSQL has stricter UNION column types; provide a valid typed payload matching all selected product columns and preserve reflected HTML/error DTOs. |
| `cart/tools/index.js` and coupon route | Preserve raw coupon predicates and boolean blind outcomes; PostgreSQL boolean typing and comment termination must be tested. |
| `audit/tools/index.js` | Documented `randomblob(...)` timing payload is SQLite-specific. Use an actual bounded PostgreSQL timing expression in disposable tests, with the unchanged raw username sink. Do not fake elapsed time or add a compatibility function that masks the backend. |
| `analytics/tools/index.js` | Its model prompt explicitly asks for SQLite SQL. Change the declared dialect and deterministic templates to PostgreSQL while preserving unsafe generated SQL, PII selection and the unbounded result lesson. |
| Error/schema-disclosure lessons | PostgreSQL error text and metadata catalogs differ. Grade the observed disclosure category and document native catalog queries; do not fabricate SQLite errors/catalog rows. |
| Read-only SQLite statement API versus `pg.query` | A raw query endpoint must not accidentally gain unrestricted multi-statement write capability through the transport change. Define the existing statement capability explicitly while retaining UNION/boolean/timing exploitation. Ordinary store methods stay parameterized. |

Network, filesystem, command/template/XML/deserialization sinks remain intact. Migration tests substitute disposable fixtures or local controlled servers; they must not send real email, run destructive host commands or access production credentials. Do not clamp result sizes inside the intentionally unbounded analytics/audit sink merely as a migration convenience; preserve infrastructure deadlines separately and record their limits honestly.

## Parallel ownership and sequence

With root plus three workers, use these non-overlapping slices after agreeing exported interfaces:

| Owner | Exclusive files/work | Dependencies |
| --- | --- | --- |
| Root/integrator | Schema/seed/export-import contracts, pool/bootstrap, `shared/db.js`, legacy shared-commerce consumer, HTTP route files | Publishes repository interfaces first and owns migration numbering. |
| Worker A: commerce tools | Commerce repository, product-search/cart/listing/inventory/pricing/review/support/email/user-management/analytics tool files and their MCP server adapters | Uses commerce schema; coordinates outbox contract, leaves HTTP routes to root. |
| Worker B: agent state/runtime | Agent-state repository, sessionStore, both trace modules, toolAcl, toolManifest, policyLoader, registry/audit tools and their MCP adapters, supervisor graph async callsites | Owns all session/trace/ACL/manifest async transitions together. |
| Worker C: vectors and parity | Vector repository/store, shared vector export, upload tools/adapters, disposable multi-process fixture harness and sink acceptance tests | Coordinates source-document methods with Worker A and admin rebuild/count API with root. |

`system` tools remain with root unless an identified database call requires reassignment. Workers A/B must not both edit a task server: each task agent's adapter follows its tools owner. Worker C owns only upload and vector adapters; product-search `similar` changes go through Worker A using the agreed async vector API. Shared schema files and bootstrap have one writer.

Sequence: freeze contracts and source/sink baseline; create isolated schemas and seed/import seam; implement the three workers' async paths; integrate all 17 MCP adapters and three supervisors; qualify dialect lessons and multi-process storage; migrate the shared legacy commerce reader; then switch the common engine. No dual-write rollout and no claim that a disconnected PostgreSQL repository completes migration.

## Acceptance gates

1. Fresh disposable PostgreSQL-only backend and agent-host boot with database constructors for SQLite forbidden. Both reject missing/unready stores without fallback. No current user database is opened by tests.
2. Native and imported fixture parity for HTTP statuses/DTOs, pagination, accounts, addresses, cart/order totals, inventory, policies, inbox, admin analytics and all 17 MCP result envelopes. Exercise frontend selectors that expect JSON strings or numeric values.
3. All 62 required vulnerability proofs plus the four additional mapped IDs retain their demonstrated outcomes; run the existing multi-hop and mock-provider parity suites. Add actual PostgreSQL UNION/boolean/error/timing tests where SQLite payloads are incompatible.
4. Separate backend/host processes observe policy/ACL/cache updates, appended traces, vector additions and rebuild generations. Native manifest refresh preserves registered external poisoning. Prompt/tool text remains verbatim at tagged sinks.
5. Concurrent session append/token increment loses no messages; failure after a tool effect does not replay it; trace batching survives a retry without duplicate event IDs. Do not claim distributed exactly-once external effects.
6. Vector retrieval before/after restart returns the same synthetic corpus results, including poisoned documents; stale HNSW cache cannot hide a committed upload. Rebuild failure leaves the previous generation usable.
7. Owner/role contracts and intentional cross-owner gaps are checked separately. Isolated challenge SQL cannot access platform/workshop databases or migration credentials.
8. Final React build, existing SecureShop HTTP/SSE and exploit-chain tests pass from a disposable workspace. UI layout and deliberate HTML rendering remain unchanged.

Remaining decision: raw SQL lessons need a reviewed native PostgreSQL statement-capability boundary before implementation. This is a curriculum compatibility decision, not a reason to silently preserve SQLite behind the PostgreSQL flag.

## Agent-state implementation update

The agent-state slice is implemented under `PLATFORM_DATABASE_ENGINE=postgres`; its SQLite branch remains explicit during rollout. `initializeSecureShopAgentsDb({runtimePool, migrationPool})` in `server/database/postgres/secureshopAgentsDb.js` validates dedicated roles, applies the complete `secureshop_agents` migration directory, and seeds core state from a pure ACL catalog. Migration `0001` owns sessions, traces, audit, registry/cache/history, ACL, configuration and provider/background metadata; vector migration `0002` belongs to the vector slice.

Session append uses one atomic PostgreSQL JSON-array update, so concurrent tool results cannot overwrite one another. Token increments are atomic. This does not itself serialize two entire supervisor turns for the same session; a separate run-ownership policy would be needed for that stronger guarantee. No database lock spans model inference.

Both trace writers use an awaitable PostgreSQL buffer with stable event IDs, batches of 128 and at most 4096 pending events. A failed batch remains available to a subsequent flush and the unique database event ID makes retry idempotent. The graph awaits its final flush before emitting completion. An exhausted queue raises an explicit error rather than silently dropping records. This is not a durable outbox for a process killed before flushing, and trace failure does not replay a tool. The host shutdown owner must await the shared writer's flush.

ACL and policy/manifest lookups are awaited in the supervisor graph. PostgreSQL ACL reads use current stored state, while the seeded disabled-enforcement setting still dispatches denied calls with `denied-by-acl`. Native-manifest refresh and registry/cache/history replacement are transactional and preserve external poisoned tool descriptions. Audit tools use native PostgreSQL queries, including a raw interpolated teaching SELECT. Its extended protocol and read-only transaction prevent adding multi-statement write capability; the deliberate SQL injection, log poisoning and unbounded-result behavior remain.

Registry and audit MCP adapters await results before serializing their envelopes. Their synchronous legacy branches retain their existing return contracts. PostgreSQL-selected imports for the migrated runtime modules are tested with SQLite modules forbidden. The dedicated PostgreSQL integration test additionally exercises a separate process writing audit state, concurrent message/token updates, trace deduplication, ACL changes, registry history and poisoned cache persistence, a short real `pg_sleep` query, and an actual in-memory MCP request/response.

Verification: the recovered disposable Linux PostgreSQL 18.6 run passed the 32-test aggregate, including agent-state cross-process audit persistence and the actual MCP adapter test (`/tmp/owasp-ai-goat-secureshop-linux-first.log`). The runtime/import/trace tests also pass. Audit readers now retry a configured commerce store's pending outbox delivery before reading agent audit state; an injected regression proves delivery precedes the read and delivery failure does not replay the commerce mutation or return a stale successful log. This final recovery hook requires inclusion in the next aggregate snapshot.
