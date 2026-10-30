# Legacy ecommerce and sensitive lookup agent consolidation

Status: implementation design only. This document does not qualify a model,
database, browser, or live route and does not authorize activation.

## Decision

Use two applications built from the existing agent infrastructure rather than
introduce a new generic legacy assistant:

1. Keep `/ecommerce/ai-assistant` as its own SQL-injection lesson. Replace its
   browser-generated SQL with a model-selected `execute_sql` action, executed
   as PostgreSQL SQL inside a disposable per-run workspace populated from
   an owner-and-generation-bound target. Reuse the decision-observe graph,
   qualified provider, run ledger, reset fencing, and Judge infrastructure,
   but do not reuse ARIA's parameterized product-search tool or objectives.
2. Replace the keyword-selected behavior of PostgreSQL sensitive lookup's
   `/mysql/ai-chat` with the existing `LegacySensitiveInfo` decision-observe
   application, extended by a PostgreSQL reference/template tool adapter and a
   private same-action receipt. Keep its direct path-traversal, SSI, and
   combined endpoints as explicit compatibility teaching sinks.

ARIA teaches injection through an application-built query whose input reaches
a deliberately weak search boundary. The legacy page teaches a different
agent boundary: the model itself chooses the SQL shown in the panel and sent to
the executor. Redirecting the page to ARIA would remove that lesson. The design
therefore shares orchestration and authority code while retaining separate
tools, data, objectives, and effects. Redirecting sensitive lookup to FinFlow
would likewise couple a small file/SSI lab to unrelated banking resources and
reset lifecycle.

## Current gaps

The ecommerce page decides intent and builds SQL in the browser. It parses
names and addresses, classifies attacks, and interpolates `user.id` into SQL in
`client/src/pages/labs/AIAssistant.js:178-280`, then submits caller-generated
SQL and caller-selected `userId` to `/api/ecommerce/ai-query` at
`client/src/pages/labs/AIAssistant.js:282-387`. The server executes that SQL at
`server/routes/ecommerce.js:353-428`. This path invokes no decision model and
has no owner-bound graph receipt or canonical completion. The raw SQL execution
is the lesson and must remain real, but neither browser-generated SQL nor a
caller-supplied `attackType` establishes that a model chose it. The mounted
`/ai-query` replacement must accept learner text, execute only the model's
exact selected SQL in the controlled executor, and derive every display and
grading field from that action. Other raw ecommerce endpoints remain explicit
compatibility sinks outside this first slice.

PostgreSQL sensitive lookup authenticates and wraps POST handlers in an owner
run at `server/routes/postgres/sensitiveLookup.js:6-15`, and it records
owner-scoped exploitation logs in
`server/database/postgres/sensitiveLookupDb.js:31-33`. Its `/mysql/ai-chat`
calls the provider for prose and then independently selects database/file/SSI
operations with keyword checks at
`server/routes/postgres/sensitiveLookup.js:382-518`. The model therefore does
not select the executed action or arguments. The store's seed catalog is real
PostgreSQL data (`db/postgres/seeds/sensitiveLookup.json`), but the file and SSI
effects have no durable target identity or private action receipt.

The repository already contains the intended replacement seams:

- `server/agent-runtime/decisionObserveGraph.js:39-141` compiles the exact
  decide, validate, execute, observe flow and wraps the selected action in the
  durable run ledger's `effectWithReceipt`.
- `server/services/legacySensitiveAgent.js:5-109` defines strict model-selected
  file and SSI actions and builds evidence from the decision, exact call,
  observation, and response.
- `server/services/legacySensitiveAgentProduction.js:15-107` can supply a
  neutral shared provider seam: it snapshots one supported provider, uses
  `createLangChainProvider`, rejects mock/fallback or changing identities, and
  privately consumes each model response once.
- `server/services/legacySensitiveCandidateApplication.js:11-34` derives the
  objective from the selected action and evaluates through the canonical
  completion service inside the same owner run.
- `server/services/legacySensitiveObjectiveGrader.js:59-119` requires actual
  effect facts and model provenance, then persists a prepared Judge packet
  through `objectiveCompletionService`.
- `server/agent-runtime/runCoordinator.js:37-155` and
  `server/agent-runtime/postgresRunLedger.js:95-141` provide owner generation,
  cancellation, trace, effect, and reset fencing.
- `server/database/postgres/legacyChallengeDb.js:21-33` already selects the
  PostgreSQL legacy store, and `:57-72` demonstrates a cross-store platform
  owner authority. Its broad `executeAiSql` method must not be exposed to the
  new model action; the new executor has a separate least-privilege connection
  and repository interface.

### Existing FinFlow qualification is not a consolidation target

Do not prioritize this work by treating FinFlow's remaining admin objectives
as simulated or uniformly unqualified. The retained r4 cohort at
`~/.owasp-ai-goat/native-verification/owasp-ai-goat-finflow-admin-error-model-6pw8xj7p`
qualified nine actual-model scenarios for configuration disclosure, directory
discovery, and missing-account error disclosure. Its agent source SHA-256 was
`3dac23ade5cb07c9a085b2443a3f54966493ee4dd9819ff3809bc76ed3663ee9`.
The installed agent source is a later composition with SHA-256
`85dfe2427a4db3089d6566a4ec238f85199cd43e6d3be0e73a687fec14738518`;
the private admin artifact receipt is unchanged, while the graph, policy
evidence, and resource composition incorporate later trace and durable-log
work. The r4 result therefore remains evidence for that retained snapshot, not
an exact-byte qualification claim for the installed composition. A current
source rerun can establish the composed behavior. It does not justify
redesigning or replacing the already implemented trusted-artifact paths.

The first slices below address independently reachable legacy routes where the
model-selection and owner-bound evidence gaps are visible in the current code.

## First vertical slice

### Ecommerce model-selected SQL

Keep the visual component, message list, SQL/result panel, vulnerability label,
and `/ecommerce/ai-assistant` route. Remove `parseNameFromMessage`,
`parseAddressFromMessage`, `detectAttackType`, and `generateSQLFromQuery` from
the authority path in `client/src/pages/labs/AIAssistant.js:178-280`. The page
sends one request to its existing endpoint:

```text
POST /api/ecommerce/ai-query
{ "message": <exact learner text>, "requestId": <client retry UUID> }
```

It does not send `userId`, SQL, attack type, mode, target, or objective. The
response keeps the existing `aiResponse`, `sqlQuery`, `results`,
`vulnerability`, and `educationalNote` fields so the SQL panel remains the
center of the lesson. It adds `run`, `toolCalls`, `judgment`, and
`newlyCompletedObjectives`, all projected from the server-owned run. Profile
update and NoSQL branches remain their current ungraded compatibility paths
until separately modernized. Product, review, cart, order, upload, and checkout
sinks remain unchanged.

Add a `LegacyEcommerceSql` application around
`decisionObserveGraph.runDecisionObserveGraph`. Its decision schema has only:

```text
execute_sql({ "sql": <nonempty selected PostgreSQL query> })
search_products_safe({ "searchTerm": <exact learner search text> })
general_chat({})
```

The model sees the learner message, the controlled lab table contract, and the
current mode. It returns one selected SQL string. The accepted grammar is a
nonempty, NUL-free UTF-8 string of at most 16 KiB whose first unquoted token is
`SELECT` or `WITH`, with no second statement, data-changing CTE, `SELECT INTO`,
transaction/role/session control, locking clause, COPY, large-object,
extension, filesystem, network, or server-administration call. Literals,
comments, boolean predicates, subqueries, read-only CTEs, UNION composition,
and catalog discovery inside the executor cluster remain allowed. Lexical
acceptance does not promise that every PostgreSQL `SELECT` form is composable;
a database syntax or semantic rejection is returned as a no-effect native
observation.

The selected bytes shown in the SQL panel are distinct from the command sent to
PostgreSQL. The executor embeds those bytes unchanged as a derived table inside
an outer `SELECT ... LIMIT 129`. This bounds transfer and detects a 129th row,
but it intentionally excludes top-level locking/`SELECT INTO` behavior, changes
the command tag, and does not promise top-level ordering semantics. Persist and
hash both `selected_sql` and `execution_sql`; the private receipt proves their
reviewed wrapper relationship. This is actual PostgreSQL evaluation of the
model-selected query, not byte-identical execution of that string as the whole
wire command, a regex-selected fixture, or a parameterized search wrapper.

Execution uses a dedicated `owasp_ai_goat_legacy_ecommerce_agent` login and
`LEGACY_ECOMMERCE_AGENT_DATABASE_URL`. The URL must identify the auxiliary
`owasp_ai_goat_legacy_ecommerce_executor` database on a dedicated PostgreSQL lab
cluster, not the cluster that hosts the 16 application stores. That role has
`CONNECT` and `TEMP` only, no membership in the runtime or migration roles, and
no schema/table/function/sequence privileges outside `pg_catalog`.
On one pinned connection the executor starts a transaction, creates a fresh
`pg_temp` workspace, and parameter-loads owner target snapshot rows into temp
tables named `users`, `products`, `orders`, and `order_items`. It sets
`search_path` to `pg_temp,pg_catalog` and places the exact selected SQL bytes
unchanged inside a derived query capped at one row above the result limit. It
captures rows or the bounded native PostgreSQL error, rolls back, discards the
connection on any cleanup uncertainty, and records separate selected-command
and executed-command digests. The model SQL therefore cannot address the shared
`legacy_challenge` tables because they do not exist on this cluster, or a
sibling's workspace because temp schemas are connection-local. The executor
must verify those denials at readiness; a parser allowlist alone is not the
isolation boundary.

The PostgreSQL role boundary also closes server-level capabilities. PostgreSQL
permits a role to signal another backend owned by that role, and session-level
advisory locks live until explicit unlock or session end. It also grants
`EXECUTE` on functions and `TEMP` on databases to `PUBLIC` by default. See the
[PostgreSQL 18 administration functions](https://www.postgresql.org/docs/18/functions-admin.html),
[predefined roles](https://www.postgresql.org/docs/18/predefined-roles.html),
and [privilege defaults](https://www.postgresql.org/docs/18/ddl-priv.html).
PostgreSQL roles and `pg_database` are cluster-wide, but ordinary system
catalogs are stored per database; `pg_proc` function ACL changes in one database
do not rewrite another database's copy. A role-specific `REVOKE` still cannot
override an effective grant inherited from `PUBLIC`, so the executor database
bootstrap must revoke `PUBLIC` execution before granting its narrow role. See
the PostgreSQL 18 [`pg_authid`](https://www.postgresql.org/docs/18/catalog-pg-authid.html),
[`pg_database`](https://www.postgresql.org/docs/18/catalog-pg-database.html),
[`pg_proc`](https://www.postgresql.org/docs/18/catalog-pg-proc.html), and
[database file layout](https://www.postgresql.org/docs/18/storage-file-layout.html)
documentation for those scopes.

The recommended profile still uses a separate executor cluster, for a different
reason: otherwise the intentionally broad catalog-discovery lesson can reveal
application-cluster database and role metadata, the executor role exists beside
application roles, and CPU, memory, temp storage, backend signaling, and failure
domains remain shared. A dedicated database in the application cluster is a
lower-cost alternative because its routine ACLs are local, but it must restrict
catalog discovery and prove equivalent resource and connection isolation; it is
not the first-slice default. The separate cluster bootstrap must revoke
`PUBLIC` execution of
`pg_cancel_backend`, every `pg_terminate_backend` overload, advisory-lock
functions, `pg_sleep` variants, `set_config`, large-object import/export, and
server-file/program functions. It must prove the role is not a member of
`pg_signal_backend`, `pg_read_server_files`, `pg_write_server_files`,
`pg_execute_server_program`, monitoring, all-data, or ownership roles. Revoke
`PUBLIC` schema access/default function execution in that isolated database; do
not grant an ordinary application runtime access because none runs there.
Readiness enumerates effective function privileges by OID and fails on a new
callable user/extension routine or a denied built-in overload. The application
cluster and its existing legacy lesson ACLs remain byte-for-byte unchanged.

The agent role has fixed per-role `statement_timeout`, `lock_timeout`,
`transaction_timeout`, `idle_in_transaction_session_timeout`,
`temp_file_limit`, bounded `work_mem`, `max_parallel_workers_per_gather=0`, and
`jit=off`; application code sets the same or stricter local values before
loading the workspace. PostgreSQL documents `statement_timeout` as covering
extended-protocol Parse/Bind/Execute through Execute or Sync and recommends
per-session rather than global configuration in its
[client connection settings](https://www.postgresql.org/docs/18/runtime-config-client.html).
The validator rejects `SET`, `RESET`, and direct calls that can alter those
limits, but server ACLs and role settings remain the independent boundary. The
application also caps SQL/result bytes and rows, aborts on deadline, and
destroys the connection after timeout, cancellation, cleanup error, or any
unexpected transaction state. Explicit denials and server timeouts prevent one
shared-login request from canceling, locking, sleeping, or exhausting a peer.

Vulnerable and fixed behavior use the same decision schema and authorization
boundary. In `vuln` mode, the executor evaluates the accepted selected query
inside the exact bounded outer command. In `fixed` mode, it rejects
`execute_sql` as a no-effect observation and offers a separate server-built,
parameterized `search_products_safe({searchTerm})` action if normal shopping
search is needed. It never rewrites the selected attack SQL into a successful
safe query. The identical positive prompt must therefore show the same model
selection only in deterministic authorization tests that inject the same
validated action. Actual-model fixed runs record whatever qualified decision
or refusal the provider returns and still require an explicit no-effect result
and no attack credit. `legacy_challenge.vulnerability_settings.sql_injection` remains the
instructor availability gate; `LAB_MODE` supplies the per-request teaching
mode. Missing or disabled gates fail before the model call.

The response model receives the exact SQL, exact rows/error, and action
receipt. Use the qualified-provider receipt pattern from
`legacySensitiveAgentProduction.createQualifiedModel`, generalized into a
shared module, for both decision and response. Add a private SQL action receipt
issued only after target/readback/action-digest verification. The Judge fact
`trusted_model_selected_sql_effect` requires both private receipts for the same
call index, owner, run, generation, target, SQL digest, and result digest. The
displayed `sqlQuery` and `results` must hash to those same bytes. A valid result
from another call, caller-supplied SQL, model prose, a durable row alone, or a
later refusal cannot substitute for the paired action.

The first objective rubric pins these criterion IDs and evidence sources:
`model_selected_sql` from the matching private `server_observation`,
`controlled_sql_executed` from the matching private `server_observation`, and
`cross_table_record_returned` from that call's `tool_result`. Required facts
are `qualified_model_decision`, `trusted_model_selected_sql_effect`, and
`vulnerable_mode`. Failed and unpaired calls remain visible as diagnostic
`server_observation` entries with `eligibleForContentCriterion: false`; they do
not disappear from the packet and cannot provide the `tool_result` criterion.

The first-slice code boundary is deliberately small:

- reuse `server/agent-runtime/decisionObserveGraph.js`,
  `runCoordinator.js`, `postgresRunLedger.js`, `objectiveCompletionService.js`,
  and the shared structured Judge without changing their contracts;
- extract the qualified-provider issuer from
  `server/services/legacySensitiveAgentProduction.js` into a neutral shared
  module, retaining its private one-use receipt semantics;
- add `legacyEcommerceSqlAgent.js`, `legacyEcommerceSqlApplication.js`,
  `legacyEcommerceSqlComposition.js`, `legacyEcommerceSqlReceipt.js`, and
  `legacyEcommerceSqlObjectiveGrader.js` under `server/services/`;
- add a narrow target/action repository and TEMP executor under
  `server/database/postgres/`; do not route the graph through
  `legacyChallengeDb.executeAiSql`;
- replace only `server/routes/ecommerce.js:353-428` with the fail-closed
  application call, and remove only the client authority logic at
  `client/src/pages/labs/AIAssistant.js:178-387`; preserve the rendered panel
  and all other route handlers;
- extend application setup/start config with an explicit auxiliary-cluster
  provisioning step and readiness check for the executor role, add one forward
  legacy-store migration and one separately
  reserved identity catalog migration, then extend the existing
  `studentDeletionAdapters.js:149-158` legacy hook rather than adding another
  owner drain.

### PostgreSQL sensitive lookup agent

Extend `LegacySensitiveInfo` rather than build another graph. Parameterize its
action catalog so the sensitive-lookup composition supplies two strict actions:

- `read_database_reference({referenceKey, queryText})`
- `render_database_template({templateName, queryText})`

The decision model receives only these action schemas and the learner message.
The database tool adapter calls `getFilePathByReference` or
`getTemplateByName`, preserving the deliberate raw-query branch in
`server/database/postgres/sensitiveLookupDb.js:20-28`. It then delegates the
actual bounded file read or SSI interpretation to
`server/services/legacySensitiveTools.js:31-164`. That helper already confines
reads to the controlled teaching root, records whether the read crossed the
public subdirectory, uses descriptor-based reads for the real filesystem, and
states that SSI command output is simulated.

Add `createSensitiveLookupAgentComposition` beside
`legacySensitiveCandidateComposition`. It must fail closed unless all of these
dependencies are ready: exact migration ledger, migration/runtime role pair,
canonical objective catalog, `sensitive_lookup` repository, controlled
teaching root, PostgreSQL graph run ledger, configured qualified provider,
objective completion service, and reset/deletion hooks. It returns the same
application interface (`run`, `reset`) so `/mysql/ai-chat` can delegate without
embedding graph logic in the route.

Preserve the existing response keys used by compatibility consumers:
`success`, `aiResponse`, `vulnerability`, `exploited`, `mysqlPathUsed`,
`mysqlTemplateUsed`, `flagsCaptured`, `model`, `provider`, and `pattern`. Add
`run`, `toolCalls`, `judgments`, and `newlyCompletedObjectives`. Values must be
derived from the selected action and observed result. The route must ignore
the body `userId`. Provider failure, missing storage, invalid decisions, or an
unqualified response returns a bounded unavailable/no-credit result and never
falls back to keyword-selected execution.

The direct `/mysql/path-traversal`, `/mysql/ssi-injection`, and
`/mysql/combined-attack` endpoints retain their current sinks and response
shape. They can keep recording owner-scoped practice logs, but they do not
establish model selection and cannot satisfy an AI-assisted objective.

## Owner targets and receipts

### Ecommerce SQL workspace

Reserve and qualify the next `legacy_challenge` forward migration after
`0003_student_deletion.sql`. It adds:

- `ecommerce_agent_owner_state(platform_owner_id, generation, updated_at)`;
- `ecommerce_agent_targets(target_id, platform_owner_id, generation,
  dataset_revision, snapshot_json JSONB, snapshot_sha256, status, created_at,
  retired_at)`, unique for one active target per owner and generation;
- `ecommerce_agent_actions(operation_id, target_id, platform_owner_id,
  generation, run_id, call_index, mode, selected_sql, selected_sql_sha256,
  execution_sql, execution_sql_sha256, result_json JSONB, result_sha256, status,
  committed_at)`, with an exact-operation replay key and immutable
  owner/target/run/selected-command/executed-command/result lineage.

The ordinary legacy runtime repository reserves and reads targets. It copies a
versioned, checked-in synthetic ecommerce dataset into `snapshot_json` once per
owner generation; it never derives ownership from the legacy shop `users.id`.
The agent executor cannot read these tables. Application code validates the
target, loads its bounded rows into that connection's temp workspace with
parameters, executes SQL, canonicalizes PostgreSQL rows/errors, and asks the
ordinary repository to commit the action metadata. The private receipt issuer
then re-reads the committed action and compares every scope and digest before
issuing authority to the Judge. Snapshot and result hashes use the shared
stable-key JSON serializer after JSONB readback. `selected_sql_sha256` covers
the exact UTF-8 model-selected bytes and `execution_sql_sha256` covers the exact
outer command sent through the extended protocol; JSONB storage order is never
treated as file-byte order.

The migration updates `legacy_challenge.destroy_student_owner` through a new
signature or composition-owned helper without changing the applied `0003`
function. Reset first invalidates the owner generation, drains admitted runs,
retires the current target, and clears current retrievable conversations before
completion; it does not create the next target until a later admitted request.
Account deletion additionally scrubs or removes `snapshot_json`, `selected_sql`,
`execution_sql`, and `result_json` under the existing job-bound deletion drain while retaining
only non-content hashes required by immutable platform history. Sibling target,
action, conversation, and completion rows remain unchanged. Startup readiness
checks the exact application-store migration ledger, all three connection
identities, executor-cluster TEMP capability and empty durable namespace,
trigger/function identity, catalog rows, deletion hook, and private receipt
verifier before mounting the graph path.

The auxiliary executor credential is a supported setup input, not a value the
legacy-store migration invents. Extend application provisioning and
`.env.example` with `LEGACY_ECOMMERCE_AGENT_DATABASE_URL`; generate its private
password during setup and require the database name
`owasp_ai_goat_legacy_ecommerce_executor`. Provisioning must also prove that the URL's
server identity differs from every application-store server identity. A second
database in the same cluster would isolate routine ACLs, but roles, catalog
metadata, backend resources, and failure domains would remain shared.
`start_all.sh --plan`, setup upgrade, readiness, and redacted
diagnostics must include it without printing the URL. Existing installations
remain fail-closed on the model-selected endpoint until this auxiliary cluster,
credential, ACL bootstrap, and legacy migration are present; compatibility
ecommerce endpoints continue using the existing legacy runtime role.

### Sensitive lookup targets

Reserve, review, and qualify a new forward migration
`sensitive_lookup/0003_agent_targets.sql`; do not edit `0001` or `0002`. The
migration should add:

- `owner_state(user_id, generation, updated_at)`, one current generation per
  authenticated platform owner;
- `agent_targets(target_id, user_id, generation, target_kind, source_key,
  source_revision, source_sha256, status, created_at, retired_at)`, unique for
  `(user_id, generation, target_kind, source_key)`;
- `agent_actions(operation_id, target_id, user_id, generation, run_id, action,
  request_sha256, result_sha256, status, committed_at)`, with immutable
  owner/target/run/digest lineage and exact-operation replay.

Targets bind an owner and generation to a checked-in PostgreSQL seed reference
or template. The underlying teaching bytes may be shared immutable fixtures;
the authorization, action history, and progress are owner-specific. The tool
must re-read the current database row and actual file/template bytes before it
commits a result digest. A target from another owner or generation, a changed
source revision, a missing exact path, or a symlink escaping the teaching root
fails without an action receipt.

Runtime grants are limited to the necessary select/insert/update operations and
execute privileges on fixed-search-path functions. Revoke `PUBLIC`. Readiness
must resolve schema/table/function OIDs safely and validate trigger relation,
function, event type, and enabled state rather than checking trigger names.

The database action row is durable metadata, not secret authority. Add a
module-local receipt issuer/verifier backed by a `WeakMap`. It issues a frozen
receipt only after `agent_actions` readback and exact result-digest validation.
The verifier must require the same application instance, action call index,
owner, run, generation, operation, target, selected arguments, and returned
tool bytes. The Judge receives a bounded `server_observation` derived from that
verification; serializable action rows, copied graph receipts, learner text,
assistant prose, or a different valid call cannot satisfy the fact.

The action-specific rubrics use exact facts:

- path: `qualified_model_decision`, `trusted_sensitive_lookup_action`,
  `protected_path_read`, `known_controlled_flag_returned`;
- SSI: `qualified_model_decision`, `trusted_sensitive_lookup_action`,
  `ssi_substitution_observed`, and `no_os_command_execution`.

The content criterion cites only the matching `tool_result`. Failed, stale,
unpaired, and unrelated calls remain visible as `server_observation`
diagnostics with `eligibleForContentCriterion: false`.

Owner reset must invalidate the graph generation first, drain admitted work,
retire current `agent_targets`, and clear retrievable owner action state before
reporting completion. It must not seed a new generation before the reset
commits. Account deletion extends the existing
`sensitive_lookup.destroy_student_owner` through the forward migration and the
mandatory deletion composition. It removes retrievable owner target/action
data or performs an authorized job-bound scrub while retaining only
non-content hashes. Sibling targets, actions, progress, and files are unchanged.

## Catalog and admin parity

Register ecommerce as a distinct canonical workshop,
`legacy_ecommerce_ai_sql`, routed to `/ecommerce/ai-assistant`. Its first slice
has one objective, `model_selected_sql_exfiltration`: induce the configured
model to select SQL that escapes the intended product lookup and returns a
known controlled record from another temp workspace table. This objective does
not alias ARIA's ten technique objectives at
`server/config/workshopCatalog.js:117-128`; ARIA grades injection through its
parameterized `search_products` boundary, while this exercise grades a model
choosing an over-privileged SQL statement. Later profile-write or NoSQL lessons
must add distinct reviewed actions and objectives rather than reuse this
completion.

Reserve one of the next available identity migrations at implementation time
and seed the ecommerce challenge/objective with default-only provenance. The
current reservation file has no unassigned prefix, so this design does not
claim `0061` or any later number. Add it to
`WORKSHOP_OBJECTIVES`, `workshopChallengeFixtures`, solution/hint content,
admin preview/update/toggle maps, dashboard projections, and reset/deletion
composition. Preserve instructor-edited label, description, hint, solution,
visibility, enabled, and hidden values on reseed. The page reads its own
catalog status and progress; it does not display ARIA progress.

PostgreSQL sensitive lookup should not add its five legacy objectives to
FinFlow's current eighteen-objective `sensitive_info_disclosure` exercise.
Create a distinct canonical workshop key, `sensitive_lookup`, and challenge key
of the same name. Reserve a separate available identity migration at
implementation time; `0059` and `0060` are already reserved and the current
reservation file has no free prefix. Seed these IDs
with default-only provenance:

- `path_traversal`
- `ssi_injection`
- `combined_traversal_ssi`
- `ai_assisted_path_traversal`
- `ai_assisted_ssi`

Move the canonical grader's `WORKSHOP_KEY` from
`sensitive_info_disclosure` to `sensitive_lookup`. Preserve existing
`legacy_sensitive.judgments` as historical records; do not silently convert
them into new canonical completions. The catalog migration changes only
recognized defaults and preserves instructor labels, descriptions, hints,
solutions, visibility, enabled state, hidden state, and learner progress.

Add `sensitive_lookup` to `WORKSHOP_OBJECTIVES`, checked-in challenge fixtures,
solution/hint registries, admin solution preview/update/toggle mappings,
student dashboard routes, and the reset/deletion store maps. All student
totals and completions remain database-derived. A hidden or disabled objective
cannot be attempted or credited; changing its toggle must appear consistently
on admin challenge and solution screens and both student progress projections.

Neither first slice requires a new learner page. The existing authenticated
ecommerce page remains visually recognizable and keeps its SQL/result panel.
A dedicated sensitive-lookup page can follow only after its catalog and mounted
route have passed the same parity tests.

## Acceptance tests

### Deterministic contracts

- The ecommerce component sends the exact message once to
  `/api/ecommerce/ai-query`, sends no SQL/owner/mode/objective assertion, and
  renders the exact model-selected SQL and actual ordered result from the
  server receipt. Retry UUID replay returns the original completed response
  without a second model call or SQL execution.
- Existing ecommerce compatibility route tests continue to prove the raw SQL,
  stored-XSS, cart, and checkout sinks are unchanged and ungraded.
- A genuine provider-issued decision receipt and private SQL action receipt for
  the same `execute_sql` call can reach the Judge. Mock, scripted, copied,
  reused, wrong-index, mixed-result, caller-SQL, or response-only provenance
  cannot. A later assistant refusal does not erase an already returned SQL
  result, and response prose alone cannot invent one.
- Vulnerable mode evaluates the accepted selected query against actual temp
  tables and can return the controlled cross-table record. Fixed mode receives
  the same decision but records an explicit no-effect denial, returns no leaked
  record, and awards no attack completion. Normal safe product search succeeds
  only through the parameterized safe action.
- Two owners with identical prompts receive separate target IDs and temp
  workspaces. SQL cannot read the durable target tables, application schemas,
  another connection's temp tables, host files, network, roles, or server
  settings. Delayed execution after reset is stale and cannot record an action
  or completion.
- Sensitive lookup accepts only strict action/parameter objects, preserves
  query/path/template bytes, and executes at most the selected bounded action.
- The private receipt verifier rejects forged, reused, stale, wrong-owner,
  wrong-run, wrong-generation, wrong-target, mixed-call, and altered-result
  inputs. Valid failed calls remain diagnostic and cannot award credit.
- A real file read proves the resolved public-boundary crossing and exact
  controlled bytes. Missing paths, in-root files, symlink escapes, template
  metadata alone, and invented assistant content fail.
- SSI credit requires actual substitution in returned content. An unchanged
  directive, pre-supplied flag, simulated command text presented as OS output,
  or a different successful action fails.
- Owner reset races a delayed tool and Judge evaluation, prevents late
  completion, retires only that generation, and cannot resurrect old targets.
  Exact replay is idempotent. Sibling history, targets, actions, and progress
  remain byte-for-byte unchanged.
- Startup fails closed for missing ledgers, roles, catalog rows, triggers,
  cleanup hooks, controlled roots, provider qualification, or receipt
  verification.

### Disposable PostgreSQL and mounted HTTP

- Apply each forward migration on fresh and representative populated stores;
  verify exact ledger hashes, replay, least privileges, trigger/function
  identity, immutable lineage, valid retirement, and a failing next migration
  rollback.
- Connect as the ecommerce executor role on the dedicated cluster and prove it
  can create/query its own temp tables but cannot connect to an application
  store or access any durable application schema, filesystem/server function,
  role change, advisory lock, backend signal, or evidence table. Verify the
  application cluster's preexisting role and function ACL catalog is unchanged
  before and after executor provisioning. Crash and timeout paths destroy the
  pinned connection; a later run observes no prior temp objects.
- Run every accepted grammar family through the real driver: simple SELECT,
  read-only CTE, UNION, subquery, quoted identifier, string/comment containing a
  denied token, inner ORDER/LIMIT, catalog read, and a PostgreSQL semantic error.
  Require the selected bytes to be an exact substring of the generated command,
  verify separate selected/execution hashes, and reject semicolons,
  data-changing CTEs, SELECT INTO, locking clauses, and quoted or qualified
  spellings of every denied function.
- Exercise native budgets with `generate_series`, recursive CTEs, a large sort,
  an oversized scalar, 129 rows, a blocked advisory lock, a blocked signal
  against a concurrent same-role executor session, cancellation, disconnect,
  and rollback failure. Assert the deadline and byte/row/temp limits, bounded
  concurrent connection count, process RSS/container memory ceiling, exact
  connection destruction after uncertainty, no retained temp object or lock,
  and continued health of an independent peer request.
- Through mounted JWT routes, prove body `userId`, SQL, target, mode, and
  objective fields have no authority. Revoked/mismatched sessions fail before
  model or tool work.
- Query the actual action, graph event, grade packet, judgment, completion, and
  history rows and require one owner/run/generation chain for every awarded
  objective.
- Exercise visible, hidden, disabled, instructor-customized, no-completion,
  reset, deletion, duplicate request, and sibling cases. Dashboard totals and
  admin toggles must agree after every transition.

### Actual provider qualification

- For ecommerce, use the mounted legacy UI request shape with the configured
  model selecting `execute_sql`; require the exact selected SQL in the panel,
  actual PostgreSQL temp-workspace result, same-action private receipts, exact
  Judge criteria, provider/model provenance, and canonical completion. Repeat
  a benign parameterized search and the identical attack in fixed mode; neither
  earns attack credit. Model refusal is a semantic failure, while executor,
  authority, or persistence failure is fatal infrastructure evidence.
- For sensitive lookup, use one plain positive request per AI-assisted
  objective, one benign public read, and the identical positives after fixed
  authorization is introduced. Require the selected action, exact database
  lookup, physical controlled file or SSI bytes, private same-action receipt,
  Judge evidence, reset, sibling, and retained history. Semantic refusal is a
  measured failure; infrastructure failure is reported separately and stops
  dependent model calls.

These provider runs require an isolated launcher and one-use grant. Unit,
fixture, or mocked Judge passes do not establish model qualification.

## Delivery order

1. Add and natively qualify ecommerce targets, the separate executor cluster
   with its TEMP-only role, exact SQL action lineage, reset/deletion, and the
   one-objective catalog entry.
2. Mount the decision-observe ecommerce application at `/ecommerce/ai-query`
   and switch only the AI page's general SQL branch to learner-text requests;
   preserve the other compatibility branches and visual SQL contract.
3. Add and natively qualify sensitive-lookup owner targets, action lineage,
   reset, and deletion.
4. Extend the existing Legacy Sensitive decision-observe composition with the
   PostgreSQL tool adapter and same-action verifier; mount it at
   `/mysql/ai-chat` behind readiness.
5. Register `sensitive_lookup` catalog/admin/default-only content and verify all
   parity surfaces.
6. Run mounted PostgreSQL qualifications, then separately grant the actual
   provider cohorts.

Each step remains disabled until its own readiness and rollback evidence is
complete. This order produces a coherent ecommerce vertical slice that retains
the model-selected SQL lesson, then keeps the sensitive-lookup migration behind
a separate fail-closed composition.
