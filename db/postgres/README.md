# PostgreSQL migration status

For the current fresh-install namespaces and deliberately retained historical SQL identifiers, see [Project naming and fresh installations](../../docs/install/BRANDING.md). Verification records below describe their original source versions; the branding change does not requalify those historical builds.

Fresh setup and the normal launcher now select PostgreSQL; existing-installation migration and full release parity remain in progress. Converted repositories now include identity, canonical workshop configuration/progress/Judge receipts, ARIA, NOVA, XSS (including the legacy email builder), MCP, CSRF, supply chain, FinFlow, Excessive Agency, CTF, SecureShop commerce/agent state/vectors, legacy generic challenge data and sensitive lookup. See their tests and current implementation checkpoint in `tasks/todo.md`; full application startup has been verified; lossless existing-data import and complete release parity remain open. AWS/deployment files remain frozen.

`npm run db:postgres:initialize -- --plan` prints the sixteen dedicated database role/configuration pairs without connecting or printing credentials. After provisioning the restricted roles/databases, `npm run db:postgres:initialize` applies the converted schemas and deterministic seeds sequentially, then closes its pools. It validates that all required URL pairs are present before starting. Each database migration is transactional; a failure in a later database does not undo earlier databases, and rerunning resumes through checksum-verified migrations. The command never imports or modifies existing SQLite data and does not provision cluster roles or create a platform administrator. Existing data requires the explicit import tools, with a dry run and an empty destination.

The SecureShop bound-review store uses its own dedicated database and restricted runtime role, separate from the intentionally vulnerable commerce SQL runtime. Its migration and lifecycle are initialized only when both review URLs are configured. The review route remains unmounted, and owner deletion/archive cleanup remains an activation blocker rather than an implied capability.

The XSS email builder shares the canonical XSS database/pool, with separate tables. Unsanitized learning HTML is preserved. Composite owner foreign keys prevent attaching another attendee's profile/template to a record. Reset deletes only that attendee's templates, previews and progress in one transaction, retaining profiles and grading metadata. The API-only script-element objective uses the authenticated sandboxed document renderer and browser-owned execution proof; database migration does not lower its success condition.

The sections below document the staged implementation history; earlier “not wired” inventories describe the phase when written, rather than the current converted-route status. The final removal of legacy engine dependencies, historical installer retirement and lossless existing-data import remain outstanding.

## Original foundation and migration contracts

Migration SQL must not open or end a transaction: the loader owns the transaction,
advisory lock, and ledger write. SQL inside a dollar-quoted function may use its
normal PL/pgSQL blocks. Never rewrite an applied migration to remove a wrapper.
The loader has one exact filename/content-checksum exception for historical CTF
`0004_system_prompt_default_provenance.sql`: it removes the outer wrapper only
from the execution string and keeps the original file checksum in the ledger.
New migration tests must exercise the production loader, rollback after a later
failure, and a second no-op run; executing SQL directly does not prove ledger
atomicity.


This isolated foundation requires `pg` and PostgreSQL **18**. PostgreSQL 18.6 is the current supported release verified on 2026-09-10 against the [official version policy](https://www.postgresql.org/support/versioning/). Existing application databases and startup remain unchanged. No SQLite/MySQL runtime driver can yet be removed.

Provision a dedicated database and a login without SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, or BYPASSRLS. The migration login needs CREATE on that database. Use a separate runtime login with only the table/sequence privileges its repositories need. The helper verifies cluster administrative flags; it does not prove all grants or prevent a database owner from altering its own database. Never share these roles/databases with attackable challenge tools. Separate instances are required for lessons exposing host/cluster capabilities.

Set `PG_MIGRATION_DATABASE_URL=postgresql://<migration-user>:<password>@localhost:5432/<database>` outside source control, then run `node db/postgres/migrate.js`. Runtime pool consumers explicitly supply `DATABASE_URL`. Neither variable falls back to the other or to SQLite. Remote hosts require `PG_TLS=require` and valid trusted server certificates. URL query options are rejected; pool and timeout limits are fixed in the configuration. Do not put real credentials in the README.

Migrations run on one checked-out connection, inside one transaction, serialized by a transaction advisory lock. The ledger validates the checksum and ordering of all previously applied files. Changes to already applied migrations fail rather than quietly modifying history. Migration SQL is trusted repository code: do not add transaction-control statements or nontransactional operations such as CREATE INDEX CONCURRENTLY. A rollback failure discards the pooled connection. See the [node-postgres transaction guidance](https://node-postgres.com/features/transactions).

The bootstrap intentionally creates only migration bookkeeping. Platform/challenge schema conversion and deterministic seeds are still outstanding. This entrypoint is separate from the existing SQLite `db:initialize-all` path; merging those entrypoints must accompany the actual runtime cutover. Existing AWS artifacts are incompatible with this future PostgreSQL target and remain frozen.

Run foundation unit checks with `node --test tests/postgres/foundation.test.js`. For real integration checks, supply a newly created disposable PG18 database owned by the restricted test role:

```
PG_TEST_DISPOSABLE=yes PG_TEST_DATABASE_URL=postgresql://<test-user>:<password>@localhost:5432/owasp_ai_goat_test_<unique_suffix> node --test tests/postgres/migrations.integration.test.js
```

Tests reject non-test database names and pre-existing migration ledgers. They create only a probe table and ledger, leave the disposable database for inspection, and never reset application databases. They prove concurrent migration serialization, idempotence, rollback after a SQL failure, and checksum mismatch rejection. Without explicit configuration the integration test is skipped, which is not evidence of PostgreSQL runtime compatibility.

## Conversion inventory and curriculum conflicts

Direct driver consumers include:

- Callback `sqlite3`: `server/database/authDb.js`, `platformDb.js`, `challengeDb.js`, `ctfDb.js`, `sqlWorkshopDb.js`, `nosqlWorkshopDb.js`, `sensitiveInfoDb.js`, `sensitiveInfoWorkshopDb.js`, `supplyChainWorkshopDb.js`, `xssEmailDb.js`, `xssWorkshopDb.js`, `csrfWorkshopDb.js`, `mcpWorkshopDb.js`, `secureshop.js`, plus initialization, seed, migration helpers and `server/routes/challenges.js`.
- Synchronous `better-sqlite3`: `agent-host/shared/db.js`, registry/audit/policy/user-management tools, SecureShop admin/auth/customer/merchant routes, session/trace/vector stores, policy loader, tool ACL and manifest modules. Their immediate `.prepare().get()/all()/run()` return values and synchronous transactions require async call-chain changes; `pg` is not a drop-in adapter.
- MySQL: `server/database/mysqlSensitiveInfoDb.js` and its consumers require explicit engine/payload review before retirement.

Callback transaction state uses `this.lastID`/`this.changes`; synchronous inserts use `lastInsertRowid`. Replace explicitly with RETURNING and rowCount. Convert `?` parameters, INSERT OR REPLACE/IGNORE, AUTOINCREMENT, datetime expressions, JSON extraction, PRAGMA schema discovery, WAL/integrity checks, and sqlite_master queries. Do not use global regex rewriting of raw SQL.

Concrete teaching conflicts: `server/database/nosqlWorkshopData.js` includes a schema-discovery solution that UNIONs `sqlite_master`; `nosqlWorkshopDb.js` exposes PRAGMA index/table metadata. Those exercises require PostgreSQL catalog equivalents and updated exploit proofs/solutions before removing SQLite. The MySQL-sensitive-info branch represents an engine-specific curriculum conflict if genuine MySQL semantics are required. Do not silently relabel PostgreSQL as MySQL. Preserve every SecureShop `@intentional-vulnerability` sink and re-prove it using PostgreSQL before any engine/driver removal. This inventory identifies direct consumers, not a claim that all transitive SQL/dialect usage has been converted.

## ARIA and NOVA repositories

The new `server/database/postgres/sqlWorkshopDb.js` and `nosqlWorkshopDb.js` implement the existing async tool methods with PostgreSQL queries. Existing module paths select them only when `WORKSHOP_DATABASE_ENGINE=postgres`; unset/`sqlite` retains the staged legacy runtime, and an invalid value fails. PostgreSQL failures never fall back. This temporary switch must be removed when the rest of the application completes the PostgreSQL cutover. ARIA's intentionally injectable `searchProducts(..., 'vuln')` remains injectable; the fixed mode binds values. NOVA remains a MongoDB-style operator simulation and its metadata now identifies PostgreSQL honestly. PostgreSQL UNION columns require compatible types; table enumeration uses `pg_catalog.pg_tables`, and column metadata uses PostgreSQL catalogs.

Provision **two dedicated databases**, distinct from platform storage, owned by restricted migration logins. Pre-create restricted runtime logins named `dvaia_aria_runtime` and `dvaia_nova_runtime`, with no administrative flags or membership in trusted roles. Revoke public CONNECT on each database and grant CONNECT only to that database's migration and runtime roles. Each workshop migration creates a private schema (`aria` or `nova`) and grants its named runtime role only the read/write privileges required by its tools. Neither runtime role receives migration-ledger, seed-state, or solution-control access. Dangerous arbitrary-SQL labs must additionally use a separate instance from platform storage. Schema grants cannot protect other databases if provisioning grants broad cross-database access.

Set these outside source control:

```
SQL_WORKSHOP_DATABASE_URL=postgresql://dvaia_aria_runtime:<password>@localhost:5432/<aria_database>
SQL_WORKSHOP_MIGRATION_DATABASE_URL=postgresql://<aria_migration_role>:<password>@localhost:5432/<aria_database>
NOSQL_WORKSHOP_DATABASE_URL=postgresql://dvaia_nova_runtime:<password>@localhost:5432/<nova_database>
NOSQL_WORKSHOP_MIGRATION_DATABASE_URL=postgresql://<nova_migration_role>:<password>@localhost:5432/<nova_database>
```

Call `initializeSqlWorkshopDb()` / `initializeNosqlWorkshopDb()` before serving requests. These use independent migration ledgers in the respective databases, then atomically apply deterministic fixtures once. Restarts do not resurrect deleted carts/reading lists or overwrite refunded orders. Factories `createSqlWorkshopDb(runtimePool)` and `createNosqlWorkshopDb(runtimePool)` accept injected pools; their initialize methods accept an optional migration pool for tests. Initialize verifies the expected runtime identity and a separate migration identity on the same database. Existing tool names and object keys are preserved; PostgreSQL timestamps are Date objects internally and serialize as ISO timestamps through Express. Numeric prices remain numbers, and checkout totals remain fixed-decimal strings.

Per-user operations always bind user IDs. ARIA cart, checkout, refund, and address changes use a transaction-scoped per-user lock, so concurrent checkouts cannot duplicate orders and a receipt failure rolls back the whole checkout. NOVA uses its unique `(user_id,paper_id)` constraint for duplicate-safe reading-list additions. These protections preserve normal attendee isolation; ARIA's intentional SQL-injection mode can disclose the synthetic workshop order records as the lesson requires.

`python3 tests/postgres/run-isolated.py` creates an independent loopback PG18 cluster using installed `initdb`, `pg_ctl`, `psql`, and `createdb`; provisions restricted roles and fresh test databases; runs all real database tests; and stops the cluster in `finally`. Temporary logs/data remain for diagnosis. It does not contact an application database. The suite covers curriculum exploit/fixed pairs, owner-scoped history and mutations, concurrent checkout/refund/addition, rollback after receipt failure, deterministic restart seeding, runtime permission denials, PostgreSQL metadata, and repository recreation.

## Identity/session repository (not wired to auth routes)

`server/database/postgres/identityRepository.js` exports `createIdentityRepository(runtimePool)` and `initializeIdentityRepository(runtimePool, migrationPool)`. Provision a third trusted database, separate from both workshop databases, with a restricted owner/migration role and the named runtime role `dvaia_identity_runtime`. Revoke public CONNECT and grant access only to its trusted roles. The identity migrations create a private `identity` schema and grant the runtime role explicit privileges; audit records are append-only to that role. Callers may create pools from `IDENTITY_DATABASE_URL` / `IDENTITY_MIGRATION_DATABASE_URL`; these are consumed by the explicit staged `PLATFORM_DATABASE_ENGINE=postgres` identity adapter. The flag remains off until the remaining platform consumers migrate. No PostgreSQL error falls back to SQLite.

Wiring seams:

- Login: `findCredentialByUsername(username)` returns the bcrypt hash only for password verification. After bcrypt verification, call `createSession({userId, token, expiresAt, expectedPasswordHash, deviceInfo, ipAddress, location})`. The expected hash plus a user-row lock prevents an old credential check from issuing a new session after password rotation. The repository stores SHA-256 digests of tokens, not bearer-token plaintext. JWT signing and verification remain the authentication layer's responsibility.
- Authentication/status: after verifying JWT claims, call `findActiveSession(token, decoded.userId)`. Missing, revoked, expired, wrong-owner, inactive-account, and currently locked-account records return null. Returned user/session objects omit passwords, 2FA secrets and token hashes. `getUserPermissions` / `hasPermission` enforce active/unexpired grants.
- Logout: await `revokeSession(token,userId)` before acknowledging logout. Cleanup never makes a missing token valid. Session lists omit tokens and hashes.
- Password changes: verify the submitted old password against the retrieved hash, compute the new bcrypt hash, then call `rotatePasswordAndRevoke(userId, expectedHash, newHash)`. Password replacement, all user-session revocations, and the audit event commit together. A stale hash or failed revocation rolls back the entire change.
- Login failure: `recordFailedLogin(userId)` serializes attempts, locks at five failures for 30 minutes, and does not extend an already active lock on further attempts. Successful session creation clears attempts. Administrative permission mutation methods require authorization by their caller.
- Audit: `recordAudit` stores only method, query-free route URL and timestamp in action details. Bodies, arbitrary error text, password/token fields and nested submitted objects are discarded. Supply the route template, not an attacker-selected URL path containing sensitive text.

`identityImport.js` accepts explicit `{users, permissions, sessions, audit}` DTO arrays; it never opens SQLite files. Validation rejects unknown fields, unsupported hashes, ambiguous timestamps, invalid flags/IDs and missing user references. Password hashes and numeric IDs are preserved; SQLite UTC timestamp strings normalize to ISO UTC with up to six fractional digits preserved; invalid calendar/time fields and excess precision are rejected. Session plaintext is converted to digests and legacy audit details are allowlisted. `importIdentity(pool, dto)` defaults to a native constraint dry run: it executes inserts and transactional sequence changes, then rolls them back. Passing a null pool performs DTO validation only and explicitly returns `validationOnly:true`. An explicit `{dryRun:false}` requires an empty destination and imports all rows in one locked transaction, then advances generated-ID sequences. It neither overwrites existing destination records nor edits source data. This is a migration boundary, not a generic SQL translator or completed platform migration.

The isolated PostgreSQL test harness also verifies this repository with imported fixtures, permissions, session ownership and cleanup, concurrent password/login races, forced revocation rollback, lockout, session limits, audit redaction and restart persistence. It additionally runs the existing ARIA/NOVA DB/service suites through the staged module paths with an explicitly fake model; their HTTP sections remain skipped because this harness does not start the full application.

## Canonical workshop platform repositories

Identity migration `0002_workshop_platform.sql` adds the private `workshop_platform` schema in the same trusted database. `seedWorkshopPlatform(migrationPool)` loads all current IDs and labels from `server/config/workshopCatalog.js`, seeded display metadata, canonical hint data, and solution data without importing a SQLite module. Repeated seeding preserves admin gates and edited content. Removed catalog entries become inactive and disappear from every projection while historical completion rows remain available for migration/audit. No hardcoded objective total is used in runtime queries.

The following factories accept the trusted runtime pool:

- `createWorkshopConfigRepository` mirrors the config read and admin mutation interfaces: snapshot/revision, exercise/objective visibility, master/per-objective hint and solution controls, content updates, and bulk visibility operations. Master switches cascade only to their own gates, and per-objective gates recompute only their own master. A configuration row lock, mutation, revision increment, and revision notification commit together. No-op writes do not advance the revision. `getStudentContent` enforces visibility; administrative content methods require authorization by the caller.
- `createWorkshopProgressRepository` exposes `getUsersProgress`, `getUserProgress`, `getWorkshopProgress`, `getVisibleUserProgress`, and `getVisibleUsersProgress` with the existing canonical dashboard object keys. Counts come from enabled DB objectives joined to owner-scoped completions; time comes from summed recorded durations. Labels, objective lists, statuses and all visible projections are built from one consistent database snapshot. A caller-supplied old total is ignored by `checkAndMarkWorkshopComplete`.
- The same progress repository provides `syncObjectiveComplete`, `syncWorkshopStarted`, `resetWorkshopProgress`, `getUserWorkshopProgress`, `recordHeartbeat`, and `getGeneration`. Completion is idempotent and preserves its first timestamp. Disabled or unknown objectives cannot be completed. Heartbeats retain the existing 120-second gap rule: repeated/backward timestamps add no time, and long gaps start a new session without crediting idle time. Full reset clears only that user's workshop completions/time; objective-scoped reset preserves time and other completions. All resets advance the user/workshop generation. Capture `getGeneration` at run start and pass `expectedGeneration` to completion/heartbeat/reset to reject stale work finishing after a reset. Without this run context, a newly submitted completion intentionally applies to the current generation.
- `createWorkshopModeRepository` implements the existing mode-store interface (`initialize`, `getMode`, `setMode`) and can be passed to `createWorkshopModeService(store)`. It validates the existing per-workshop allowed modes, preserves defaults, serializes attendee changes and bumps only that user's mode revision when changed.
- `createWorkshopRevisionStore` implements `initialize`, `bump`, and `getSnapshot` for `createChangeRevisionService(store)`. Snapshots include global revisions, requested workshop scopes and only the specified user's revisions. Callers must provide the authenticated owner; this storage API does not authenticate HTTP requests.

PostgreSQL selection wires these repositories into configuration, progress, time, revision and workshop routes together. They are native asynchronous APIs, not callback-compatible `authDb` replacements. Full startup has been tested with legacy database imports forbidden; complete browser and existing-data migration parity remain release gates.

The real-PG suite verifies the current 106 seeded objective IDs, shared count/completion/time projections, hint/solution independence in both toggle directions, atomic rollback of a failed master cascade, edited-content persistence, disabled-objective exclusion, concurrent completion/heartbeat/mode changes, reset rollback and generation rejection, per-attendee isolation, filtered revisions, and catalog removal/recovery. All tests use freshly created disposable databases.

## Authentication/session wiring status

`PLATFORM_DATABASE_ENGINE=postgres` selects the PostgreSQL factories through the existing `server/routes/auth.js`, `server/middleware/adminAuth.js`, and `server/middleware/sessionManager.js` paths. `server/services/postgresIdentityAdapter.js` owns their shared runtime pool and exports `initializePostgresIdentity()` for the application's startup readiness gate. It requires `IDENTITY_DATABASE_URL` and `IDENTITY_MIGRATION_DATABASE_URL`; startup must finish initialization before accepting traffic. Rate-limit configuration uses the same PostgreSQL repository when selected. An invalid engine value fails rather than choosing an unintended store.

The adapter/router implements registration, verification-token rotation/consumption, feature/signup configuration, login and secure-login, profile ownership, password rotation, status, logout, permissions and session management. Verification tokens and session tokens are hashed in storage. Rapid logins receive distinct JWT IDs. Existing token-returning registration behavior is retained for the local workshop; the router does not send email. The reset-password endpoint retains its existing generic response and still does not implement email delivery. Platform authentication failures do not disclose SQL error details.

The original SQLite branch contains an explicitly commented vulnerable `/login` query; that code remains unchanged. The PostgreSQL platform login uses parameterized SQL. Any lesson that relies on the original platform-login injection must be mapped to a separately isolated PostgreSQL challenge before the legacy engine is removed. This adapter does not add raw-query access to trusted identity tables.

The PostgreSQL startup path now selects native admin, shared platform, workshop, SecureShop and monitoring stores before their legacy imports. Full application boot with all 17 task-agent processes has passed with SQLite/MySQL imports forbidden. The former direct-import inventory has been resolved for that selected startup path; this does not establish complete existing-data migration or every legacy endpoint's behavioral parity. Follow the current migration coverage and release checklist before replacing an existing installation.

### Mounted platform workshop wiring

`PLATFORM_DATABASE_ENGINE=postgres` now selects the PostgreSQL implementation at
`server/routes/workshop.js`, `hints.js`, and `solutions.js`, as well as the existing
configuration/mutation/progress/heartbeat/mode/revision/progressSync service entry
points. The workshop dashboard handlers are shared with the legacy branch; their
counts, enabled objectives, content gates and time come from the canonical PG
repository. The startup readiness promise now includes identity schema migration
and canonical workshop seeding; a failure prevents listening.

`getPostgresPlatformStores()` supplies `{pool, config, progress, revisions, modes}`
from the trusted identity pool. Explicitly injected legacy database handles retain
the old test/service factory behavior. There is no callback-to-SQL translator.
The public solution URL map is storage-independent in `workshopSolutionPaths.js`.

`getPostgresWorkshopResetService()` exposes `resetStudent({userId,workshopKey})`,
`resetWorkshop({workshopKey})`, `resetAll()` and `assertSupported(workshopKey)`.
ARIA/NOVA resets use the same owner string and agent coordinator as chat, drain
active work, clear native history/cart or reading list, then reset canonical
progress and increment its generation. Since these are separate restricted
databases, failure reports `RESET_PARTIAL_FAILURE` (503), never an atomic-success
claim. Other native challenge reset adapters are not migrated yet and return
`RESET_STORAGE_NOT_READY` (503) before modifying anything. Full reset preflights
all adapters before its first write. Do not enable a full-platform rollout until
those native stores and adapters have completed migration.

The real PG HTTP suite verifies dashboard parity, independently gated hints and
solutions, denied unauthenticated/instructor access, retired DPI self-grading,
owner-scoped reset generation and full-reset preflight. A separate selected-module
process proves auth/workshop/hints/solutions/config/revision/progressSync imports
load no SQLite driver. Native challenge routes still needing direct `authDb`
removal include DPI, RAG, XSS, CSRF, email agent,
monitoring, and the CSRF victim sandbox; admin migration is a separate active
slice. Platform and workshop engine flags remain explicit staging switches.

### Native MCP and CSRF workshop stores

The workshop selector now uses dedicated PostgreSQL stores for MCP and CSRF.
Provision separate databases and named restricted roles `dvaia_mcp_runtime` and
`dvaia_csrf_runtime`, with distinct migration users. Configure
`MCP_WORKSHOP_DATABASE_URL`, `MCP_WORKSHOP_MIGRATION_DATABASE_URL`,
`CSRF_WORKSHOP_DATABASE_URL` and `CSRF_WORKSHOP_MIGRATION_DATABASE_URL`.
The startup readiness gate initializes both schemas (and the XSS store).
Their versioned schemas live under `db/postgres/workshop-migrations/mcp` and
`csrf`. Native stores start empty; CSRF's existing per-tab teaching personas are
reproduced from the sandbox defaults when no stored state exists.

MCP routes use named async methods for progress, activity and owner resets.
CSRF routes use the same pattern; its victim JSON has moved out of platform
`authDb` into the isolated CSRF schema. Authenticated requests await `ready()`
before reading the sandbox. `persist()` stages a snapshot; the owner-coordinated
`beforePublish` hook awaits `flush()` before reporting success. GET/POST forged
agent actions retain their intentional CSRF behavior and GIF/HTML responses.
Per-tab reset clears only its objective IDs/logs and preserves the other tabs.
The email address lookup shares `emailWorkshopStore` with the email workshop.

Shared native reset adapters now include MCP and CSRF using the same coordinator
as their route handlers. XSS native reset is available as well. Other families
still require their own adapters; full reset remains preflighted and cannot
silently clear canonical progress while leaving native exercise state intact.

`tests/postgres/nativeWorkshops.integration.test.js` mounts the selected MCP/CSRF
routes on a disposable HTTP server and verifies no SQLite driver is loaded,
owner isolation, raw lesson content, activity, completion/reset, persisted victim
defense state and reset cleanup. The isolated harness now provisions independent
XSS, email, native-platform and graph-runtime databases so suites do not race on
migration or seed state. Latest combined run: 18 PG tests passed, ARIA 105 passed,
NOVA 137 passed; seven server-only checks skipped in each legacy service suite.

### Durable objective judgment receipts

`server/database/postgres/objectiveJudgmentRepository.js` exports
`createObjectiveJudgmentRepository(identityPool)`. Migration
`identity-migrations/0007_objective_judgments.sql` places receipts in the same
trusted database as canonical completions. It does not modify old completions or
expose a public verdict-writing route. Only server grading adapters may call it.

Call `beginEvaluation({userId,evaluationId,workshopKey,objectiveId,family,scenario,
rubricVersion,evidenceDigest,runId,mode})` **before Judge LLM inference**. IDs are
UUIDs (`runId` may be null); `evidenceDigest` is lowercase SHA256. The call captures
canonical reset generation, locks the owner/workshop state briefly and verifies
current visibility. The same attendee/evaluation ID cannot be reused for other
evidence or rubric scope. A different attendee may independently use that UUID.
The model call runs outside the database transaction.

Call `recordVerdict({userId,evaluationId,result})` with the trusted engine result.
The result must match the immutable family/scenario/objective/rubric/evidence,
run ID and mode. Its verdict is `pass`, `fail`, `inconclusive` or `unavailable`;
criteria are `{id,satisfied,evidenceRefs}` entries; explanation is bounded to2000
characters; provider/model and measured `inputTokens`/`outputTokens`/`totalTokens`
(or null) are allowlisted metadata. A pass requires nonempty satisfied criteria.
The engine still owns rubric-required facts and evidence validation: a raw client
verdict must never reach this repository.

The commit transaction rechecks generation, exercise/objective visibility and
canonical mode under the same owner/configuration locks as reset/config updates.
A valid pass inserts canonical completion and bumps its revision atomically with
the immutable verdict receipt. `disposition` distinguishes `awarded`,
`already_complete`, `not_pass`, `stale_generation`, `hidden` and `mode_changed`.
A stale verdict remains auditable without awarding completion. Exact repeated
verdicts return the original receipt; conflicting verdicts reject. Replaying a
historical receipt after reset never restores the cleared objective. A later
failure does not revoke an earlier valid completion.

`mode` uses `vuln`/`fixed` (legacy `vulnerable` normalizes to `vuln`). Canonical
mode-aware families capture/recheck `canonicalMode`; other families accept the
server adapter's scoped mode and explicitly report `modeGuard:'server_scope'`,
`canonicalMode:null`. This is not a claim that per-tab CSRF defense or another
nonpersisted mode has a database revision guard. Those adapters must supply their
own mode-generation authority before universal cross-process mode fencing can
be claimed. `getEvaluation({userId,evaluationId})` returns null for another
owner's evaluation. A supplied `runId` is immutable provenance provided by the
server adapter; this repository does not infer ownership of non-durable runtime
runs.

Real PG tests cover concurrent retry, cross-owner isolation, conflicting scope,
reset/visibility/mode changes, unavailable judgments, mode normalization,
transaction rollback after completion insertion, and non-revocation of history.
Legacy native progress and direct completion endpoints still require integration
through this grade boundary; adding the receipt store alone does not close those
bypasses.

### Shared completion orchestration

`server/services/objectiveCompletionService.js` exports
`createObjectiveCompletionService({receipts,progress,judge,prepareJudgeInput})`
and a PostgreSQL-only `getObjectiveCompletionService()` singleton. Tests and
staged adapters must explicitly inject their stores; there is no implicit
in-memory grade fallback.

Inside a protected owner execution, call
`beginAttempt({userId,workshopKey,execution,objectiveId?})` **before producing tool
or model evidence**. It captures canonical workshop generation once. Omitting
objectiveId allows several subsequently detected objectives in that workshop to
share this context. It does not equate graph generation with canonical progress
generation. The context is tied to the exact execution object, owner, workshop,
and run; do not reconstruct it from a browser payload.

Then call `evaluate({userId,workshopKey,rubric,evidence,facts,execution,attempt,
evaluationId?})`. It uses the judge engine's shared `prepareJudgeInput` helper,
detaches the valid evidence packet, begins the immutable receipt before inference,
and records the structured verdict afterward. `expectedGeneration` is checked
inside the repository's locked begin transaction, closing reset-between-evidence-
and-judge admission. Further generation/visibility/mode checks occur at commit.
Repeated checks of the protected execution prevent cancellation from being
reported as an ordinary model failure. Oversized supported-shape evidence is
recorded inconclusive without a provider call; ordinary provider errors are
recorded unavailable. Invalid rubric/input schemas reject before a receipt.

The result is `{judgment,receipt,completed,replayed}`. `completed` means the
receipt awarded or found an existing completion in the captured generation, not
merely that the model returned pass. An old receipt replay after reset does not
report current completion. The optional evaluationId supports deliberate
idempotent retry; otherwise a new UUID identifies the evaluation. This service
makes no direct route changes and is not a replacement for authenticating the
caller or validating trusted tool evidence.

Observability read SQL now has a dedicated real-PG suite covering exact JSON
owner keys, admin owner/family filtering, absent cross-owner detail/events,
sequence paging and sub-millisecond keyset pagination. Cursor timestamps retain
PostgreSQL microseconds even though display timestamps may use JavaScript Dates.

### Bounded objective execution evidence

Migration `0008_objective_evidence.sql` adds local evidence history in the trusted
identity database. `createObjectiveEvidenceRepository(pool, options)` in
`server/database/postgres/objectiveEvidenceRepository.js` accepts `maxEntries`
(default20, range1–100), `maxBytes` (default16000, range256–16000) and
`retentionSeconds` (default86400, range60–2592000). This is evidence content for
grading, separate from metadata-only run traces and effect replay tombstones.

Server execution adapters call `append({userId,workshopKey,scenario,generation,
runId,evidenceID,evidence})` after observing a tool outcome and before invoking
the judge. `generation` must be the canonical progress generation captured before
the protected execution produced its evidence. The repository checks it under
the same owner/workshop transaction lock as reset; stale appends and reads reject.
There is no HTTP append endpoint and no client-supplied `source=tool` trust model.
The server adapter must select only the challenge tool DTO it actually observed,
never request headers, process environment, general provider responses or secrets.

`list({userId,workshopKey,scenario,generation,limit?})` returns the most recent
bounded set **in chronological order**, including `evidenceID`, `runId`, evidence,
omission status and timestamps. Thus an SQL column-count rubric can observe a
successful ORDER BY8 result followed by ORDER BY9's database error. It cannot
combine another user's result, another scenario, or a previous reset generation.
Only valid JSON within depth/byte bounds is stored. Oversized/non-JSON outcomes
produce explicit omission records rather than silently truncated proof. Known
transport/credential fields (`headers`, `authorization`, `apiKey`, etc.) omit the
entire entry; this is defense in depth, not a promise to identify arbitrary
credentials embedded in opaque strings. Caller DTO selection is mandatory.

Evidence IDs deduplicate within their retained owner/workshop/scenario/generation
scope and reject conflicting content/run IDs. Omitted outcomes use an omission
reason digest without serializing the rejected input; that ID becomes an
immutable omission marker while retained. Expired or pruned evidence is not a
permanent idempotency tombstone and must not govern external-effect replay.

Append/list prune old generations and expired records for the touched owner and
workshop, and retain the configured last entries per scenario.
`purgeExpired({limit=1000})` performs bounded global maintenance (maximum10000
rows per call); startup/maintenance orchestration must call it to remove expired
records for inactive attendees. No scheduled purge is silently installed by the
repository. The runtime role can read/insert/delete evidence; only migration
roles create its schema. Tests cover owner/scenario separation, concurrent
idempotency, ordered boundary proof, omission limits, reset and expiration.

### Supply Chain native progress

`PLATFORM_DATABASE_ENGINE=postgres` selects the named Supply Chain repository in
`server/database/postgres/supplyChainWorkshopDb.js`. Provision a separate database
with runtime role `dvaia_supply_chain_runtime`, a distinct restricted migration
role, and `SUPPLY_CHAIN_WORKSHOP_DATABASE_URL` /
`SUPPLY_CHAIN_WORKSHOP_MIGRATION_DATABASE_URL`. Startup awaits its schema and six
canonical objective seed IDs under `workshop-migrations/supply_chain`. Solution
content and visibility remain in the canonical platform repository rather than
creating another mutable copy inside the native challenge database.

The existing mounted `/api/workshop/supply-chain` routes call `ensureObjectives`,
`getProgress`, `completeObjective` and `resetUser`; no SQL-string translation is
introduced. Reset uses the same CodeBot owner coordinator in both native and
shared-admin reset paths. Repeated native completion returns
`{changed:false,completed:true}`, allowing the existing detector completion path
to reconcile a previously failed canonical sync without rerunning the tool or
claiming another newly completed objective. This repairs retry consistency but
is **not** universal judge integration: existing CodeBot detection/grading remains
unchanged until its trusted judge adapter is connected.

The selected route test uses a durable platform token and verifies native
progress/init/reset and ignored foreign user IDs. Repository checks cover
reproducible seeds, per-owner isolation and completed retry behavior. CodeBot tool
implementations, command-injection teaching sinks and package pins are untouched.

## Connection budget and evidence maintenance

The PostgreSQL factory reserves each pool's configured maximum against
`PG_POOL_BUDGET` (default **78**), independently in each process. Dedicated
connection reservations consume the same budget. Pool shutdown or release of a
dedicated reservation returns that capacity. The limit applies to configured
capacity, independently of the number of currently connected clients.

| Environment variable | Default | Purpose |
|---|---:|---|
| `PG_POOL_MAX_CONTROL` | 8 | Shared identity/auth/progress pool |
| `PG_POOL_MAX_WORKSHOP` | 2 | Each isolated challenge database pool |
| `PG_POOL_MAX_LEASE` | 4 | Graph advisory-lock lease pool |
| `PG_POOL_MAX_TEACHING` | 2 | Teaching effect leases |
| `PG_POOL_MAX_PROTECTED` | 2 | Protected identity/resource leases |
| `PG_POOL_MAX_MIGRATION` | 1 | Each temporary migration pool |
| `PG_POOL_BUDGET` | 78 | Maximum aggregate configured capacity per process |

Values must be positive integers at most 100. A category maximum cannot exceed
the process budget. The factory rejects a new allocation when its reserved
capacity would exceed that budget. `getPoolBudgetSnapshot()` reports the current
process's reservations; it does not inspect another process or PostgreSQL server.

The PostgreSQL agent-host initializes shared commerce and agents pools through
`secureshopPools`, each with a default maximum of **2** connections. These pools
are separate from the backend's pools. Its supervisor passes the configured
environment to the child; it does not assign a separate smaller pool budget.

The factory does not enforce a server-wide or cross-process limit. Size each
PostgreSQL server against the actual process allocations, replicas, migration
and maintenance connections, and operational headroom. No fixed combined
backend/agent-host capacity is established here. No PostgreSQL server settings
are modified by these pool controls. Pool sizes bound database concurrency,
not attendee count; qualify workload latency separately for a 200-attendee event.

After PostgreSQL identity initialization, evidence maintenance deletes at most
1,000 expired evidence rows immediately and every five minutes. Batches never
overlap, the timer is unreferenced, and shutdown stops scheduling and drains the
current batch before closing pools. Failures are logged without evidence content
and retried on the next scheduled tick. The repository's default evidence
retention is 24 hours; bounded cleanup also reaches owners who no longer submit
requests. A backlog can take multiple batches to clear.

### NOVA grading evidence and synthetic access scope

Migration `nova/0002_paper_access.sql` adds a public/restricted classification for
training only. Existing records default to public; only the exact known seeded
IDs and titles for PAPER-2024-039/040 are classified restricted. Fresh seeds use
the same labels. These labels do not describe the real publications' access.
Normal literal and fixed searches exclude restricted rows, while the intentional
operator bypass still returns them. This preserves the access-bypass lesson and
provides actual server evidence for `nosqli_10`. The retained SQLite engine has
not received this access classification and cannot qualify that objective as an
actual restricted-record disclosure.

NOVA judge evidence retains every returned row and every credential/access field,
but omits long abstract, biography, citation-list, and URL fields explicitly.
`rowCount` and `omittedFields` describe that projection; no rows are invented or
silently truncated. ARIA keeps its full query results and persisted ORDER BY
history, including the successful position8 and failing position9 probes.

Version/schema solutions for NOVA objectives4/5 now agree across the base defaults
and PostgreSQL defaults. Native PostgreSQL seeding uses the PostgreSQL adapter.
Seed conflict handling leaves existing instructor-edited solutions unchanged.
Run `tests/manual/sqlNoSqlJudge8b.js` only after the isolated PostgreSQL harness
writes `/tmp/dvaia-sql-nosql-judge-cases.json`; the model run consumes those real
recorded query outcomes and does not call a live application database.

### Judge outage recovery

Identity migration `0009_grade_recovery.sql` stores the exact server-prepared
judge packet atomically with its evaluation receipt. Packets are capped at
24,000 UTF-8 bytes, retained for 24 hours and limited to the latest twenty
recoverable packets per owner. Scheduled evidence maintenance clears expired
packet bodies; immutable verdict receipts remain. No provider credentials,
request headers or environment data belong in the named evidence contracts.

Authenticated learners can POST an empty object to
`/api/agent-runs/judgments/:evaluationId/retry` when the server judgment includes
`canRetry: true`. The server retrieves evidence by authenticated owner and
receipt ID, acquires the original owner/family execution lease, and rechecks
canonical reset generation, durable owner generation, exact mode timestamp,
visibility and judge version. The exact mode timestamp lives on the durable
evaluation receipt, so clearing a packet cannot erase the scoring fence.
It grades the stored rubric and evidence; it does
not call workshop tools, resend emails, mutate the victim, or rerun chat.

Each unavailable evaluation permits one immutable linked child. Repeated
requests return that child's terminal result, with `canRetry: false` and
`retryExhausted: true` if it is unavailable again. An interrupted pending child
can resume under the exclusive lease, up to three total judge invocations.
Expired, evicted, invalid, version-changed or reset evidence cannot be retried.
The original receipt and original evidence run ID remain unchanged; the retry
has its own execution trace, returned as `retryRunId`; judge start/end/verdict
events attach to that new run. This path requires PostgreSQL and does not provide
a SQLite fallback.

A crash after an external side effect but before the grading packet is stored
still has no recoverable packet. The runtime keeps uncertain effect markers and
never repeats that effect automatically. This feature recovers grading outages,
not arbitrary interrupted workflows.

`GET /api/agent-runs/judgments` returns the authenticated owner's latest twenty
evaluation summaries and current `canRetry` eligibility, so an evaluation ID
can be recovered after a refresh or lost response. It exposes no evidence
packet and accepts no owner filters. Discovery does not start grading; the
retry POST rechecks eligibility. All run coordinators default to the shared
bounded PostgreSQL ledger in PostgreSQL mode, resolved lazily on first run or
reset. Explicit injected ledgers or `null` overrides remain supported.

### FinFlow native workshop

The PostgreSQL path selects `postgres/sensitiveInfoWorkshopDb.js` before loading
SQLite. Its dedicated `finflow` database/schema and runtime role store all 18
native objective statuses and owner-scoped tool logs. Configure
`FINFLOW_WORKSHOP_DATABASE_URL` and
`FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL`; startup awaits
`initializeFinflowWorkshopDb()`. Versioned schema `finflow/0001_schema.sql` and
idempotent objective seeds reproduce the store without existing SQLite files.

Mounted init/chat/reset routes use named, parameterized methods. Tool behavior,
synthetic secrets and intentionally vulnerable FinFlow actions remain in the
existing agent. PostgreSQL progress reads canonical judged completions, including
successful grading retries, instead of treating native status as authority.
Admin reset and learner reset use the same owner execution fence.

Legacy `workshop_progress`, achievements, extracted-files and file-registry
SQLite helpers belong to the previous Sensitive Info flow and are not part of
this native FinFlow path. Existing SQLite files are neither opened nor imported
by PostgreSQL initialization. Historical progress should use the explicit
platform migration/import process; native legacy statuses alone must not create
new canonical judged credit. Legacy admin/solution helpers still reference the
SQLite manager only behind the staged non-PostgreSQL selection.

### Legacy file/SSI Sensitive Info

`finflow/0002_legacy_sensitive.sql` adds a separate `legacy_sensitive` schema on
the existing FinFlow database and pool. It stores the five file/SSI objective
receipts, public document metadata, and owner-scoped access logs. It does not
merge these objectives into the canonical 106-objective workshop namespace.
The existing authenticated owner workflow guards the file and SSI teaching
sinks. Judgment writes recheck the captured native reset generation; reset
advances that generation and deletes only that owner's logs. Immutable receipt
history remains, while current statistics exclude earlier generations.
Runtime receipt UPDATE/DELETE is denied.

The PostgreSQL selector imports no SQLite and does not generate files. File
creation is separately explicit:
`node server/database/sensitiveInfoFiles.js --initialize-missing` creates only
missing synthetic challenge fixtures and preserves existing files. Neither
PostgreSQL migrations nor database imports invoke it. Existing SQLite data is
not read or silently imported. The separate MySQL-sensitive API and its dialect
remain unchanged in this slice; its shared dependency here is the file-root
constant, not the native PostgreSQL query interface.

## Fresh application setup verification

`npm run setup` is the fresh PostgreSQL entrypoint. It refuses an existing `.env`, installs locked application dependencies, provisions isolated roles/databases, runs all14 initializers and creates a private administrator login. Use `npm run setup -- --plan` for a non-mutating overview. An explicit `PG_ADMIN_DATABASE_URL` selects an existing server; otherwise setup creates only its own labeled local Docker container/volume and persists a fixed host port for restarts.

Provisioning credentials and the ownership manifest live under the user's private `.owasp-ai-goat/<workspace-id>/` directory outside the repository. The application `.env` is created with mode0600. Existing resource-name collisions are refused. A completed provision can be verified and reused; incomplete provisioning is retained for explicit remediation and is never automatically deleted.

Fresh-cluster provisioning, setup-wrapper (`--no-install`, using already installed locked dependencies), private credential modes, bootstrap login, and refusal to overwrite configuration passed. Real local Docker setup authenticated successfully and retained its port/credentials after restart. Logs: `/tmp/dvaia-provision-integration.log`, `/tmp/dvaia-setup-integration-final.log`, `/tmp/dvaia-local-setup-integration-final.log`.

Latest regression:696 tests,677 passed,19 skipped,0 failed. Native PostgreSQL36/36 plus full application boot1/1, all14 initializers and ARIA105/NOVA137 passed after the DPI/IPI reset changes. Historical data is not silently imported or reclassified as Judge-verified progress; see `docs/modernization/data-migration-inventory.md`.


## Atomic import checkpoint

`db/postgres/import-platform-identity.js` now provides a transaction-owning, dry-run-by-default library for explicit identity/platform inputs and optional100 source-backed canonical solution records plus four independent legacy XSS solution records. It writes an immutable `identity.import_batches` audit record containing plan/archive hashes and metadata only. A dry run or late failure rolls back the audit row together with all imported state and generated-ID sequence changes. This is not yet the complete archive import command: remaining archive source coverage and release parity are tracked in `tasks/todo.md`. The combined native import test verifies all100 canonical writes and legacy XSS rows, including rollback after a late batch failure and preserved restart seeds.

## Offline platform archive plan

After exporting quiesced legacy copies, inspect platform migration coverage without connecting to PostgreSQL:

```sh
npm run --silent db:legacy:plan-platform -- --archive /private/owasp-ai-goat-archive --identity-map /private/identity-map.json --naive-timestamps UTC --output /private/platform-plan.json
```

The identity map is explicit source-owner to preserved native-user ID data, for example `{"7":7}`. The planner refuses mappings to users absent from the archived identity collection. `UTC` explicitly interprets naive SQLite timestamps; omit it to reject ambiguous timestamps. Optional `--resolutions FILE` supplies archive-bound NOVA solution choices, and `--identity-review FILE` validates an exact identity metadata normalization review.

The output file is created privately with mode0600 and refuses overwrite. Standard output contains only summary metadata; private import DTOs, raw session tokens and instructor payloads are never printed. No apply option or database connection exists in this command. Successful exit means the archive plan was generated, not that migration is ready: `readyToApply` remains false while complete source/default/retention review and the operator apply coordinator are unfinished.

### MCP archive preservation

`readMcpArchive` verifies the exported `mcp_workshop.db` archive before producing private input for `importMcpArchive`. An archive-bound `review.retainedTables` must name exactly the populated unknown source tables; unknown columns in supported tables reject instead of being discarded. The importer defaults to a transactional dry run and requires empty native targets for apply. Historical progress stays historical, with no fabricated Judge receipt or canonical completion.

Migration `mcp/0002_import_provenance.sql` preserves nullable SQLite history and adds immutable source-row provenance and a batch header even for an empty import. Tool arguments/results remain exact text. Native tests cover rollback, seed restart, sequence continuation, owner-scoped reset and incomplete objective completion. This library is part of the staged existing-data migration; it does not itself provide the final whole-application cutover command.
