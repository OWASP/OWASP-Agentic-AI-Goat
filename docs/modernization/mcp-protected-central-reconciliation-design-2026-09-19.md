# Central protected-operation reconciliation

Proposed next migration/protocol. No migration number reserved; current identity source head was0096 at review. Existing graph effects remain immutable observations of execution acknowledgement, including `uncertain`. Reconciliation is append-only evidence, never automatic tool execution or objective credit.

## Why a historical recovery endpoint is not safe yet

`db/postgres/identity-migrations/0004_graph_runtime.sql` stores owner/generation/run/effect/status, not exact protected arguments, target ID or platform session. `server/agent-runtime/mcpDecision.js` records decision tool/provider metadata without the exact argument binding needed to recover a model invocation. `mcpConversationRepository.js` publishes conversation turns only for completed runs. Current protected result witnesses are private process-local objects. Consequently a failed historical run cannot be safely reconstructed from graph rows, chat text, caller-supplied target or sidecar receipt alone.

The connected explicit runner readback is valid only inside its existing private admitted invocation; current client tests reject absent/unknown capability, digest mismatch, foreign result target, stale generation and revoked execution before transport. It does not authorize a cross-process historical readback endpoint. No new public route or synthetic model witness is added in this step.

## Admission must be durable before sidecar execution

Proposed forward identity migration creates:

1. `workshop_conversations.mcp_protected_intents`: immutable operation_id primary key; user_id, owner_key, generation, run_id, platform_session_id, target_id; SDK effect suffix and **fully expanded ledger effect key**; operation enum; exact bounded protected argument JSON and request digest; original invocation ID; origin enum `model`, `manual`, `controlled`; optional decision digest; created_at. The full ledger key includes the coordinator idempotency prefix, unlike the SDK suffix. Store both and verify their original mapping. Run ID alone is never an operation ID. Legacy private invocations may receive an ephemeral generated effect suffix from protocolContext; those IDs are not durable cross-process recovery authority. New intent admission must require an explicitly persisted SDK effect suffix and its fully expanded ledger key, never guess either from the random fallback.
2. `workshop_conversations.mcp_protected_reconciliations`: immutable reconciliation UUID, operation FK, original request digest, target receipt digest, outcome `completed`, `pending`, `absent`, or `invalid`, checked generation/session snapshot, authority check time, record digest. Unique `(operation_id, outcome, receipt_digest)` permits exact replay but rejects conflicting completed receipts. Pending/absent do not authorize rerun. Retain conflicting/corrupt transport diagnosis separately from verified completion.
3. An optional private `mcp_protected_receipt_payloads` table, keyed by verified receipt digest, holds bounded result bytes for authorized inspection. Separate destroy/tombstone procedure removes disclosure payloads during owner deletion while retaining immutable identity/digests. Do not put credential output into generic traces or public run metadata. If payload retention is not needed, store digest and typed state facts only; actual secret-output grading recovery then remains unsupported.

Use migration role for DDL. Runtime SELECT only on immutable tables, narrowly scoped SECURITY DEFINER admission/append routines, `REVOKE ALL ON FUNCTION ... FROM PUBLIC`, fixed search_path, exact parameter validation. No generic UPDATE/DELETE or update of `graph_runtime.effects`. Routines check existing owner/run/effect coordinates and current platform session on admission. Test effective permissions, not only object existence. No new database engine/store required.

`ownedTargetClient.js` derives operation ID from canonical domain-separated original run ID and SDK effect suffix. Before network, new `mcpProtectedReceiptRepository.begin` runs under the actual graph lease/transaction, checking current session and exact target admission with the MCP resource repository. The target store is a separate database/service: explicitly acquire/check its current resource lease before dispatch and after response; do not claim distributed SQL atomicity. Register cleanup debt before resource provisioning when needed by lifecycle orchestration.

Origin cannot come from a model argument. `mcpWorkshopGraph.js` and the SDK must capture the exact validated model decision privately before tool dispatch and bind its parsed arguments, provider/model provenance, run and invocation. Manual Inspector uses `origin=manual`; fixtures use `controlled`. Neither may become `model` on recovery. Existing historical effects without this new intent return `legacy_unrecoverable` metadata, never backfilled guessed authority.

## Explicit reconciliation flow

A trusted service accepts an operation ID only. It loads the immutable intent using the authenticated platform principal; users cannot submit target, run, arguments, generation, labRole or receipt. Under current owner/session/target lease, it verifies unchanged generation, active original owning session, active target, original run/effect ownership, exact request digest and existing uncertain effect. Revoked or deleted owners, retired targets and old generations get no private result disclosure. Instructor observation uses a separately authorized read projection rather than impersonating a learner session.

Call only `/owned-targets/protected-receipt`, never execute. Sidecar authority checks bracket the read; central authority checks bracket response processing and append. Validate the full result envelope against the original intent. Append verified completed/pending/absent reconciliation only if still current. If the final authority check fails, do not publish to the user or create a completed reconciliation; preserve local diagnostic debt without inventing failure or success. Repeat reads return the same completed receipt digest and never change original graph status.

Initial public projection should be metadata only: operation ID, tool name, original effect status, reconciliation status/time and current availability. Display “effect receipt recovered; original run remains uncertain” instead of “run completed”. No raw synthetic secrets unless a separately scoped result endpoint is authorized. No progress award. Later Judge recovery is a separate service gated on original durable model decision and actual effect, generating a new append-only grading attempt linked to that evidence; never fabricate the missing original in-memory witness.

## Files and lifecycle integration

New migration and `server/database/postgres/mcpProtectedReceiptRepository.js`; trusted `server/services/mcp/protectedReconciliationService.js`; SDK/graph admission hook; `ownedResourceApplication.js` resource lease and observer wiring; owner-scoped run detail metadata repository/route. Coordinate SDK ownership before edits (history agent currently confirmed no overlap). Readiness must require schema routines/ACLs and `mcp-owned-protected-operation-journal.v1`. Preserve older runner behavior as recovery unavailable.

Reset fences generation before target cleanup; retain immutable reconciliation identities but make old result payloads unavailable. Deletion adds a payload-scrub adapter to canonical durable deletion, with receipt/digest tombstones and reconciliation retry semantics. Disabled configuration must not bypass cleanup debt. Existing target retirement already removes target-contained protected journals; native connected proof records this and sibling preservation. Package the new journal in the local sidecar image and qualify immutable image/profile before installation; no AWS asset changes.

## Required native gate

Fresh/populated/no-op migration; least privileges; intent committed before socket; post-effect lost acknowledgement; completed readback across process recreation; same operation conflict and exact replay; two effects in one run; pending/absent never rerun; unavailable sidecar; return-phase authority loss; cross-owner/session/generation denial; reset/deletion races and payload destruction; sibling preservation; manual/control origins denied model credit; forged JSON cannot enroll private provenance. Inspect original uncertain graph row before and after reconciliation. No actual model call is necessary for these storage/authority gates.

## Implemented unmounted candidate (2026-09-19)

`drafts/mcp-protected-recovery/protected_reconciliation.candidate.sql` and
`server/database/postgres/mcpProtectedReceiptRepository.js` now implement the
intent and append-only digest projection. They are not registered in startup,
mounted on a route, or granted any grading role. The repository requires captured
origin, target-authority and readback services; callers cannot submit a recovered
receipt. Completed readback additionally requires the target client's private
receipt identity. Original graph effects remain uncertain.

Native evidence: `tasks/mcp-protected-central-candidate-native-2026-09-19.json`,
owned workspace suffix `jn_1gpbz`, terminal zero, container removed. The single
native contract test covers full fresh migration, populated migration preserving
the exact previous ledger, second no-op, least privilege, concurrent admission
and reconciliation replay, request/result conflicts, forged receipt rejection,
pending reconciliation, model/manual/controlled origin preservation (including mutation of the origin service result during asynchronous admission), full ledger
key versus SDK suffix, reset during readback, revoked session, deleted owner,
retained digest history and sibling preservation. Both target authority and origin
are controlled constructor callbacks in this candidate test: this is PostgreSQL
storage/authority proof, not assembled production recovery or a genuine model
admission proof. The earlier fixture key-order assertion failure is retained in
`tasks/mcp-protected-central-candidate-native-key-order-failure-2026-09-19.json`.

Remaining integration gates: bind origin to the actual private validated graph
decision before effect dispatch; bind readback to durable operation context after
process recreation; compose the real current target lease; qualify combined
central intent + sidecar socket + reset/deletion cleanup; package and qualify the
new immutable sidecar image. Only then select a forward migration number and
consider a metadata-only explicit recovery route. Historical effects without an
intent remain unrecoverable; no automatic retry, grade, history rewrite or
backfill is implemented.

## Connected pre-network admission candidate

The optional `protectedResourceLeasePool` composition argument now enables
pre-network intent admission. It is not supplied by default startup. It requires
a separate resource pool with 1–4 connections and a bounded connection wait;
ordinary request pools are not retained through network calls.

`mcpDecision` privately records each schema-validated response; the graph carries
that exact object through an async decision scope to the SDK. The SDK compares
the selected tool and exact argument digest. Inspector/streamable calls remain
manual. Cloned JSON, changed arguments, retired async contexts or absent model
decision scope cannot claim model origin. This provenance is metadata, never a
new grading witness. Controlled model fixtures explicitly remain controlled
qualification, even though they exercise the model-origin contract.

`postgresRunLedger` supplies a private already-claimed effect scope containing the
fully expanded ledger key. The server does not infer this key from a run ID or
learner argument. `protectedOperationAdmission` commits the immutable intent
before dispatch and then obtains the actual `mcp.runner_targets` row lease from
`mcpResourceRepository`. The ordering is central admission/commit first, resource
lease second: central identity/owner row locks are never acquired while holding
the resource row. Current session/generation checks bracket the lease and socket.
A race before the resource lease leaves an unexecuted intent; it cannot dispatch
under retired authority. The lease covers only this bounded protected operation,
not model or Judge work. SQL rollback cannot undo a sidecar mutation.

Native evidence: `tasks/mcp-protected-admission-native-2026-09-19.json`, workspace
`h6x0z1hh`, terminal zero and owned container absent. Real PostgreSQL identity/MCP
stores, JWT validation, LangGraph, SDK, private HTTP API, filesystem key rotation
and current lifecycle repositories prove intent visibility before every socket,
lost acknowledgement uncertainty, blocked replay, exact full-key linkage, manual
origin, canonical reset while an effect is held, session revocation after commit,
bounded transport timeout with no retained pool lease, sibling preservation and
target cleanup. Five protected sockets caused five real rotations. The model was
a controlled provider; the macOS target fixture controls Linux readiness and
does not establish AppArmor/image qualification. 24 context/client/journal checks
and 68 graph/SDK/composition regression checks also pass.

Explicit readback after process recreation still needs a trusted service that
loads this intent, reestablishes the real current target lease and uses only the
read-only journal endpoint. No public recovery route, numbered migration,
default installation, automatic retry, historical effect rewrite or completion
credit was added. The separate earlier reconciliation repository proof remains
valid for its controlled readback constructor scope; it is not a claim that this
combined recovery service is already wired.

## Cross-process explicit readback implemented

`protectedReconciliationService.js` now provides the previously missing private
readback composition. It accepts authenticated request plus operation ID, loads
the original immutable intent, locks identity/session/owner/run/effect before the
real resource row lease, and appends metadata in the identity transaction.
After commit it rechecks principal, generation and target before returning.
This does not expose a public route or reconstruct grading provenance.

The private runner API adds recover-existing-only `/owned-targets/recover` and
advertises `mcp-owned-protected-readback.v1`. The client uses a shared bounded
budget for recover+read, validates exact original request digest and receipt,
and clears cached capability on failed readiness. No admission/provisioning or
execution endpoint is called during recovery.

Final native evidence `tasks/mcp-protected-recovery-native-2026-09-19.json`,
workspace `jc75tnzu`, passes with current source hashes and container absent.
Fresh Node child processes reconstruct session/client/service state, recover the
exact completed receipt, and preserve a single append-only reconciliation on
repeat. Foreign owner, conflicting receipt, reset and revocation are rejected;
original graph effect remains uncertain and credit remains false. The cohort
also retains actual intent-before-socket, bounded timeout, canonical lifecycle
cleanup and sibling checks. Models are controlled; no actual inference occurs.
18 target-client tests pass including downgrade denial and exact read-only URL
sequence (previous context/journal tests also remain separately passing).

The concrete source migration, managed pool accounting, readiness, route and
installer release delta is documented in
`mcp-protected-recovery-source-activation-2026-09-19.md`. Linux immutable image
qualification is separate from this macOS native socket/PostgreSQL fixture.
