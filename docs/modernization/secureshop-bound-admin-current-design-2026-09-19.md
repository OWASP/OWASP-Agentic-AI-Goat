# SecureShop bound admin: current gaps and implementation design

Status: implementation in progress, based on current source inspection on 2026-09-19. The Users read endpoint is composed with launch-scoped account profiles; 46 controlled backend checks pass. Native PostgreSQL composition25060 now passes the actual admin login/directory/denial, owner-profile and sibling/reset assertions with independently verified cleanup. Rendered45907 also passes Users listing and visible unavailable Overview, followed by owner reset/sibling preservation. The prior35414 failure exposed a real route-transition blank screen; Shell now captures useOutlet for the keyed exit animation. Activated with owned restart86674 and eleven bounded health/auth checks; no migrations or learner reset. Other admin backend operations remain unavailable. Existing UI appearance and intentional teaching sinks remain requirements.

## Current evidence

- `server/index.js:258` mounts bound dispatch before legacy shop routers. `server/middleware/secureshopBoundDispatch.js:5` explicitly prohibits launch-bearing requests from falling through to shared state.
- `server/services/secureshopBoundApplication.js:34` composes catalog, commerce, account, reviews and qualified lab routers, previously composed no admin adapter. It now includes the initial Users read adapter; the remaining operations still reach the terminal handler. `server/routes/secureshop/boundGateway.js:672` returns 503 for remaining operations.
- `client/src/pages/secureshop/bridge/operations.mjs` nevertheless registers the admin overview, users, audit, policies, MCP registry, system and access-control operations, plus admin agent session/chat/trace. These operations are transport-allowed, not implemented by the bound gateway.
- The separate bound `/v2/mcp-trust` exercise is implemented/feature-gated (`boundGateway.js:303`). It is not equivalent to the existing general MCP management page.
- `server/routes/secureshop/postgres/admin.js:140–454` supplies legacy response contracts and teaching behavior. Its repository is shared/global, so mounting this router behind the bound gateway is not a valid fix.
- Existing admin pages consume these operations: `pages/admin/Overview.jsx:35`, `Users.jsx:62`, `Audit.jsx:54`, `Policies.jsx:44`, `MCP.jsx:48`, `System.jsx:63`, `AccessControl.jsx:30`, under `client/src/pages/secureshop/`.
- HTTP error handling audit found Overview treating error JSON as refreshed state, Policies ignoring write statuses and MCP removal ignoring DELETE status. Policy save/render and MCP removal feedback are now corrected with nine focused component tests, including 200 error bodies, 403/503 and network failure. Policy save uses the existing single upsert so it renders once and persists both source and injection targets. Overview HTTP/partial-refresh handling is also corrected with focused component tests; native and rendered acceptance remains separate. The bridge preserves status (`bridge/transport.mjs:180`).

## Required authority boundary

A SecureShop admin persona administers only its learner's isolated shop launch. It is not a DVAIA platform administrator. Every operation resolves server-owned launch, owner, scenario, generation and authenticated persona; the request cannot select another owner or trust its own role. Require the admin persona before reading admin projections or executing admin operations. Revalidate generation at effects and grading boundaries.

Normal operational administration consists of catalog/persona counts, owned commerce totals, owned audit and run records, policy management and launch-local permissions. Teaching sinks include unsafe policy rendering, MCP trust/import behavior, diagnostic/config operations and deliberately vulnerable tool authorization. Preserve their documented exploit semantics inside owned targets. Consult `docs/secureshop/VULNERABILITIES.md` before implementing each sink; do not make a secure CRUD replacement and call the exercise complete.

No operation may mutate platform users, shared model configuration, shared MCP registry, host files, host processes, another learner's permissions or aggregate deployment state. Do not manufacture success or sample rows to disguise an unavailable capability.

## First useful slice: an operational read-only admin dashboard

Implement `createSecureShopBoundAdmin` plus a dedicated bound admin router, injected through the existing composition. Reuse current canonical catalog, commerce, persona-session and agent-run repositories; add narrowly scoped query methods where necessary. Match existing response envelopes so existing cards and tables work without redesign.

The slice should support all eight Overview reads together, plus Users and Audit listing:

| Operation | Required projection |
| --- | --- |
| `admin.overview.kpis` | Current target's persona counts, banned overlays, products, orders, order revenue and sessions active within the UI's stated 15-minute window. No global counts. |
| `admin.agentHost.health` | Sanitized readiness of the runtime actually serving this bound launch; do not label a separate unused process as its agent engine. Never expose host paths or secrets. |
| `admin.providerState` | Actual last provider per role from owned persisted runs; absent runs yield an honest empty list. |
| `admin.dbSizes` | Measured launch-owned logical data sizes, explicitly identified as logical PostgreSQL data, not fictitious SQLite files or total shared database size. Retain card layout; adjust misleading file wording if necessary. |
| `admin.mcp.servers`, `admin.mcp.schemaHistory` | Owned registry/target state only. For existing controlled MCP targets, expose exact persisted discovery/version records through a documented projection; do not claim a general registry is populated when it is not. |
| `admin.audit.list` | Filtered/paginated owned events with stable time ordering. Include actor, action, target, outcome and safe details consumed by the existing table. |
| `agent.admin.trace.latest` | Owned admin-role run traces, empty if no actual run exists; never substitute another role's trace. |
| `admin.users.list` | Launch personas plus launch-local profile/status overlays, preserving existing pagination/filter response fields. No platform user enumeration. |

This first slice does not complete Users mutations, policy/MCP/system tools or the admin assistant. Keep remaining operations explicitly unavailable until implemented; client errors must remain visible. If an Overview projection has no trustworthy source, implement the needed owned store/query or mark that card unavailable, rather than returning fake zero/healthy data.

## Mutation and agent lifecycle

1. Add forward migrations for launch-local admin settings, policy source/version records, persona status/credential overrides, registry records and append-only admin effect receipts as needed. Each mutable row must be bound to the same launch target/generation authority as existing account/catalog overlays. Preserve original persona templates.
2. Define role-change semantics explicitly: changing an isolated shop persona's effective role must never change its platform role or retarget immutable ownership. Revoke incompatible shop sessions; permission and ban changes must take effect on subsequent requests. Password reset modifies only the launch credential overlay and invalidates affected owned sessions/API credentials according to a documented contract.
3. Policy edits preserve raw teaching text and version identity. Rendering uses an owned execution boundary that retains the specified vulnerability while containing effects. Do not execute templates against the backend host context.
4. MCP registration/import/discovery operates on owned controlled endpoints/sidecars and persists actual schemas and changes. A submitted URL is not authority for host networking or arbitrary subprocess creation. Preserve intended trust flaws inside the target and connect existing MCP trust evidence where semantics match.
5. ACL/enforcement settings are launch-local and consumed by the actual bound tools. Separate platform isolation, which remains enforced, from the deliberately switchable tool-level authorization lesson.
6. System read-config/diagnostic/restart/index actions operate on owned synthetic files, lab processes and owned index corpora. Report real effects, not canned text. They must not restart shared Ollama, PostgreSQL, the application or another learner's sidecar.
7. Admin LangGraph decisions use bounded validated tool schemas over these same services, with bounded steps, cancellation and run provenance. REST mutations and agent tool effects share repositories and receipts. Objective credit requires matching effect evidence plus the canonical Judge; ordinary successful administration does not automatically earn exploit credit.
8. Reset/deletion invalidates the generation first, cancels or fences in-flight work, cleans only owned mutable state and artifacts, and preserves immutable evidence according to existing retention rules. Retry/idempotency behavior must be explicit for every external effect. Sibling launches remain unchanged.

## Verification before promotion

- Contract tests compile every existing admin bridge request against its actual route; distinguish implemented operations from intentional unavailability. Verify strict query/body limits and role checks.
- Disposable PostgreSQL qualification covers fresh migration, representative populated upgrade and second-run no-op; runtime role privileges; two owners and multiple launches; forged target IDs; stale generation; reset races; session revocation; pagination/filter parity.
- Render the existing Overview, Users and Audit pages using genuine disposable persisted data. Assert every displayed count/value matches owned records, errors remain errors, and refresh does not turn failure into success. Check sibling data is absent from rendered DOM and responses.
- For each mutation, verify stored effect, corresponding audit receipt, retry behavior, failure rollback/compensation and reset semantics. Test no platform account, global registry, host configuration or sibling state changes.
- For each teaching sink, retain its vulnerability coverage and prove the intended exploit effect against an owned real artifact or service. A controlled provider can test orchestration; it is not actual-model evidence.
- Qualify changed admin agent workflows with local llama3.1:8b: actual decision, exact tool arguments/effect, bounded loop, trace, canonical Judge acceptance/rejection, stale/reset rejection and sibling isolation. Record truthful model refusals without inventing completion.
- Preserve current UI baseline, protected dependency pins and AWS assets. Run focused frontend checks/build and intentional-vulnerability coverage after implementation; no whole-application acceptance claim follows from this slice alone.

### Users directory semantics
The Users directory lists all three available shop accounts from the immutable persona catalog, overlaid with the current launch's saved profiles. An account exists before its first login, just as a seeded account does in an ordinary shop. This endpoint does not represent attendance, unique logged-in people, or active sessions. Session KPIs must use exact-scope persisted session records and credential/expiry checks independently. No ban/role overlay currently exists, so those mutations remain unavailable; future implementation must extend both authentication and this projection. Passwords, bearer values and API keys are excluded from this read endpoint; the separate teaching lookup must use its own isolated disclosure contract.

### KPI implementation checkpoint
The KPI read now composes target-guarded PostgreSQL product/order aggregates with the available launch-account directory and a separate exact-scope active-session query. Products include archived launch products; order revenue is gross order total, explicitly labeled in the existing card. Active sessions require current credential version, no revocation, unexpired lifetime and activity within fifteen minutes. Native83598 passes actual order totals, sibling zero totals, expired/inactive/credential-mismatch exclusions and lifecycle regression. Controlled backend checks52 pass. Rendered57242 verifies account/product/revenue/session values against actual isolated data, after correcting the old revenue label exposed by82021. Qualified changes are active under owned launcher68913; eleven bounded health/auth checks passed, with no migration or learner reset. Other dashboard sources remain unavailable.

### Provider and trace observation checkpoint
Current-launch provider observations use persisted model decisions, excluding configured preferences and failed starts. Admin traces require the current admin persona and project metadata only across conversation purposes. Forty-six focused controls, native44072 and rendered21040 pass, including role denial, owner/sibling isolation and reset behavior. Controlled providers are explicitly fixtures, not actual-model proof. Activated with owned restart55010 and eleven bounded HTTP/auth checks; no migrations or learner reset. Remaining Overview sources and admin workflows are still open.

### Audit source gap and next implementation boundary
The shared `secureshop_agents.audit_events` and legacy commerce outbox have no immutable launch coordinates. They cannot supply bound admin history. Bound conversation traces prove attempts/model activity, not a complete effect journal; they must stay distinct. Orders, profile overlays and credential state also cannot reconstruct the history of updates or revocations. Existing inbox/MCP/SSRF effect receipts remain authoritative for their own actions only.

The next audit implementation must append an event in the same transaction as each covered effect. Required identity is event UUID plus launch, scenario, generation, original platform owner/session, authenticated shop actor and role. Include action, target, timestamp, source identity, outcome and exact training parameters. Retain immutable events across launch reset while hiding old generations from current admin reads; explicitly extend owner-deletion retention/cleanup contracts. Never backfill invented history from current state or unscoped global rows.

For isolated databases, prefer store-local append-only journals and a bounded federated read over introducing asynchronous cross-store writes solely for this page. Each source applies the same trusted scope and parameterized filters, returns its top K ordered by timestamp/event ID, and the service merges to the global top K with a store tie-breaker. This is a live observation, not a cross-database transaction snapshot. A failed source must make completeness unavailable, not silently yield an apparently empty/complete history. Final launch-generation validation remains required. This design is under implementation review; no journal or effect coverage is yet claimed.

Keep the normal filtered GET separate from the deliberate raw SQL search exercise. Adding a scope predicate before interpolating attacker SQL is insufficient: injection can escape that predicate. The teaching query needs a real owned SQL target with no authority over shared journals or sibling data. Similarly, the log-injection summarizer must consume actual raw owned event fields through its real agent/Judge workflow; rendering a constructed prompt alone is not evidence of an executed model or successful exploit.

Independent source review supports the federated journal design. Initial writer coverage must be enumerated, not implied by endpoint availability: agents-store persona session/credential/API-key changes and inbox/MCP/SSRF effects; review-store cart/checkout/refund, review moderation, listing/profile/address and manual/retrieval changes. Store-local runtime roles receive append/read capability, not general journal update/delete; privileged exact-owner cleanup must produce deletion receipts. Both relations must enter composition readiness and deletion manifests before promotion. Identity/platform lifecycle audit stays outside shop-admin authority. Journal timestamps and IDs need deterministic ordering; normal GET count means the returned row count, matching the existing page contract.

### Journal candidate implementation checkpoint
Draft agents0020 and review0013 now live under `docs/modernization/drafts/secureshop-bound-audit/`, outside active migrations. The shared audit repository validates exact scope, preserves raw JSON text, rejects conflicting event-ID reuse, searches with literal parameterized substrings, and merges store pages without losing PostgreSQL microsecond timestamp ordering. Store-prefixed UI IDs prevent cross-store key collisions. The optional admin service/gateway contract is implemented but not injected into production.

Native31499 qualifies both schemas and native32060 adds actual commerce writers: cart add/update and checkout append in the owning transaction; an injected audit outage leaves the cart intact and rolls back the order. Runtime UPDATE/DELETE are denied, and owner cleanup is receipt-backed, replayable, rejects later owner writes, and preserves the sibling. These are candidate proofs, not deployed audit coverage. Remaining writers, deletion composition/readiness, representative populated upgrades, concurrent cleanup and actual rendered audit data must be qualified before active migration promotion. No model or Judge run is implied by database tests.

Audit writer compatibility: accepted listing fields can expand beyond 1.6 MB when encoded as JSON. The candidate append contract therefore permits 2 MiB rather than imposing a new 64 KiB lesson-input limit. Before promotion, the ordinary admin list needs an explicit response-byte/pagination budget and clear truncation/continuation feedback. Keep this separate from the intentional unbounded summarizer exercise; do not silently truncate raw stored training input or weaken the sink to fit the logger.


### Installed audit checkpoint (supersedes draft-only status above)

Agents0020/review0013 are now forward migrations. Both journals are wired through retained startup, readiness, effect writers, bounded admin reads and existing student-deletion cleanup. Store-local effect transactions preserve raw teaching inputs; MCP/SSRF events explicitly record remote receipt persistence rather than claiming network rollback. Pagination preserves microseconds and store ties, uses a conservative16MiB response budget and fetches raw payloads only after page selection. Older/latest controls retain existing button styling and pause polling for historical pages; iframe bridge cursor allowlisting is verified in the browser.

Evidence: `tasks/secureshop-bound-audit-journal-current-review.json`, `tasks/application-audit-upgrade.json` and `tasks/application-installed-audit-acceptance.json`. All16 installed database backups were restored in isolation, preexisting table digests preserved, and actual installed session creation was visible in the owner-bound admin journal. Application owner93635 is running.

Remaining admin audit work: search-by-user SQL injection must execute against an owned SQL target, never the shared journals; summarize-anomalies must use an actual model-driven graph with exact source-event provenance and objective-specific Judge evidence. Both currently report unavailable rather than inventing results. This journal checkpoint does not qualify those teaching workflows or the full goal.

## Scoped operational reads, September 19 successor

Current source adds four exact Overview reads through BoundAdmin and the bound
gateway: `/admin/agent-host/health`, `/admin/mcp/servers`,
`/admin/mcp/schema-history`, `/admin/db-sizes`. Every read validates the current
launch/platform session and actual administrator persona before and after the
projection. Query-supplied ownership is rejected. MCP returns only this active
launch's persisted target/schema records; disabled configuration returns a
specific 503, and observed records never claim network health. No global
registry or shared database size is exposed.

Data sizes are explicitly selected logical JSON row bytes (product source rows
and MCP schema rows), not physical disk usage or a complete launch total. Health
uses cheap indexed scoped store probes with LIMIT 1, not size scans. A legitimate
empty launch still has available storage. Its status is SERVICE_READY for the
in-process LangGraph service, separately from provider availability. Ollama's
configured model is checked via bounded two-second, one-MiB `/api/tags`; no model
inference occurs. Cloud credentials only establish configured_unknown, mock is
mock_not_genuine, and every response says model_execution:not_tested. Draining,
failed store reads and stale launch authority cannot return service readiness.

Focused endpoint/authority/composition tests and frontend failure/partial-state
checks accompany the change. Native evidence is
`tasks/secureshop-bound-admin-reads-native-2026-09-19.json`: actual scoped stores,
owner/sibling separation, admin persona/current session/generation checks and
mounted gateway reads. Catalog availability is controlled in that native
fixture; it is not a live MCP transport health or new model qualification.
Installed activation and full composed browser acceptance remain separate.

The full App browser successor uses actual canonical platform username/password
login, actual bound admin persona login, opaque iframe/bridge transport and real
scoped PostgreSQL read adapters. It verifies all four endpoint responses and
visible SERVICE_READY/untested-model/persisted-discovery/logical-byte labels,
with no sibling target names. Unrelated KPI/provider/trace capabilities in this
narrow assembled fixture remain visibly unavailable; no fake healthy values are
supplied. Evidence: `tasks/secureshop-bound-admin-reads-rendered-2026-09-19.json`.
This is a copied frontend build plus mounted application routes, not a claim of
full server/index startup or installed activation. Exact remaining24 unmatched
bridge operations are listed in
`secureshop-bound-admin-remaining-2026-09-19.md`.
