# Workshop RAG durability

## Current source status — September 26

The implementation notes below describe earlier staging checkpoints. Current supported startup awaits `initializeWorkshopRagProduction()` after store initialization and before platform lifecycle readiness and HTTP listen. That factory binds both IPI and CSRF routes to the PostgreSQL composition; migration `0082_workshop_rag_sources.sql` is in the canonical identity migration directory. The memory store remains for explicitly unconfigured legacy/test paths, not the supported initialized PostgreSQL route authority.

Retained evidence includes `tasks/workshop-rag-source-promotion-2026-09-19.json`, `tasks/workshop-rag-production-bootstrap-native-2026-09-19.json`, and `tasks/ipi-durable-http-actual8b-2026-09-19.json`. These prove their recorded migration/bootstrap/lifecycle and separate genuine IPI scopes; they do not prove every current objective, installed-process activation, or 200-student capacity. Current bootstrap/composition controls pass 17 tests. Their source-order assertion now follows the extracted initializer helper; no runtime behavior changed.

The installed RAM-preservation warning below remains applicable before restarting an older process. Inspect its actual configuration and resource state; source wiring does not prove an existing process has activated the new store. Full current rendered acceptance and workshop capacity remain separate work.

## Historical design and staging record

## Current boundary

IPI document chunks, vectors, filenames and selection live in `ragVectorStore`
process memory. Canonical objective progress already lives in PostgreSQL. After
restart, `/current-session` correctly returns empty, although an already-open
page can retain an obsolete upload indicator until its next request.

CSRF victim state persists clean/poison IDs, flags and `ragDocText` in
`csrf.victim_state`; vectors do not persist. The immediate source patch isolates
RAG and CSRF resource families, checks actual corpus presence, safely reseeds
only canonical clean text, and reports missing poison as unavailable. It retains
saved poison text and historical credit. It does not claim durable retrieval.
Existing CLI, agent policy, raw injection content, UI layout and objective IDs
are unchanged. Retrieval failures must never become fabricated empty success.

## Before activating any memory-changing patch

Do not restart the installed process without a reviewed capture strategy for
live IPI documents and current selections: those bytes may exist only in RAM.
Do not infer that there are no live documents from PostgreSQL absence. The legacy memory store retains trimmed chunks and vectors, not the original upload buffer; even a future chunk export must label original-byte provenance as unavailable rather than inventing exact source bytes. Capture
must use the authenticated owning application process, freeze relevant admission,
record exact source/chunk hashes and resource scope, and preserve unknown
provenance without assigning credit. Do not attach a debugger to extract arbitrary
process memory. If no safe capture interface exists, leave activation pending
until an explicit application-level preservation path has been implemented and
reviewed. Saved CSRF `ragDocText` must remain intact until its migration is
verified. Never silently replace it with a preset.

## Authoritative PostgreSQL design

Use the existing **identity PostgreSQL database**, in a dedicated `workshop_rag`
schema. Existing `identity.ipi_email_artifacts` demonstrates owner/run-bound
untrusted text storage in this database. No additional database, engine,
extension, AWS resource or deployment change is needed. Keep SecureShop's
product/manual revision domain separate; reuse fingerprinting and established
transaction patterns, not its target tables.

Persist immutable original UTF-8 document content, display filename, content
hash, ingestion kind and ordered chunks with a versioned chunking manifest.
Scope every resource by canonical platform owner, workshop/family, resource
generation and document ID. Use separate clean/poison selection slots for CSRF
and a current-document slot for IPI. Never accept owner, generation or run
identity from tool arguments. A new authenticated session of the same owner may
restore the document; uploading-session metadata is provenance, not a substitute
for current authentication.

Keep derived vectors in immutable revisions keyed by source-set digest and the
schema-2 actual loaded embedding runtime fingerprint. Publish a separate active
head. Bound both source storage and per-owner document/chunk counts; reuse the
current 1 MB IPI upload limit and explicitly specify equivalent CSRF limits.
Use bounded owner-only cosine retrieval initially; a new vector extension is not
required for the current workload. Measure the 200-owner workload before adding
indexing complexity.

Inference runs outside long database transactions. Source creation, selection
and vector publication must independently validate the admitted run and current
generation against `graph_runtime`. Publication compares source digest and
expected head atomically. Reset/deletion blocks admission and makes late
publication impossible. A runtime mismatch requires a new derived revision from
exact stored chunks, never regenerated catalog defaults or sanitized content.

A bounded process cache may hold source/vector projections keyed by family,
owner, generation, document ID and revision fingerprint. It is disposable and
never decides resource existence. Readiness returns source availability and
retrieval availability separately. Model unavailability preserves the document
and returns a retryable error. Restart/multiple-process behavior comes from the
repository, not sticky routing or process-local flags.

## Lifecycle and evidence

IPI reset retires only its family. CSRF poison reset removes only poison;
indirect-tab/full reset clears the appropriate CSRF corpus without touching IPI.
Student deletion erases raw source and vectors from both families and retains
only bounded metadata cleanup receipts. Cross-store CSRF victim-state cleanup
uses the existing retryable deletion/reset composition; it is not falsely
claimed as one transaction with identity storage. Sibling state remains exact.

Graph/Judge evidence must bind document, chunk and revision hashes to the same
admitted owner/run/generation. Keep actual untrusted chunk text for model input
and the deliberate prompt-injection exercise. Missing bytes, stale heads or
failed retrieval cannot yield completion. Data repair and import never award
retrospective credit or erase historical credit merely because vectors need
rebuilding. Existing CSRF legacy text may be explicitly imported with
`legacy_unverified` provenance; preserve its exact bytes and do not reconstruct
old model or ingestion receipts.

## Implementation checklist

- [ ] Inventory current live memory and saved CSRF text; implement/review an
  explicit owner-bound capture/import workflow before installed activation.
- [ ] Add the next forward identity migration after rechecking the migration
  head: `workshop_rag` documents/chunks/selections, embedding revisions/vectors/
  heads and metadata-only cleanup receipts, with minimal runtime grants.
- [ ] Add `server/database/postgres/workshopRagRepository.js` with exact-scope
  admission/publication/retirement and readiness checks.
- [ ] Add `server/services/workshopRagStore.js` as the production facade and
  bounded cache; retain `ragVectorStore` for shared inference/chunking and
  explicit memory fixtures only.
- [ ] Update `ragInjection`, `ragIngestGraph`, `ragQueryGraph`, `csrfWorkshop`
  and `csrfRagGraph` to await durable publication/retrieval and attach receipts.
- [ ] Make `csrfVictimSandbox` stop treating duplicate RAG flags/text as corpus
  authority, while preserving old rows until verified migration.
- [ ] Integrate exact-family reset/deletion with
  `postgresWorkshopResetService` and `studentDeletionAdapters`.
- [ ] Preserve frontend shapes/layout; invalidate stale loaded state on
  authoritative absence and display retryable retrieval unavailability.
- [ ] Qualify fresh/populated/no-op migrations, runtime ACLs and unknown legacy
  provenance without destructive startup or automatic data replacement.
- [ ] Test restart and two processes; same-owner/same-ID cross-family isolation;
  sibling preservation; poison-only/tab/full reset; deletion and replay.
- [ ] Hold embedding work across reset/deletion and reject late publication;
  verify runtime mismatch/reindex and repeated retrieval publication no-op.
- [ ] Test actual model/Judge evidence with unsanitized injected source;
  independently verify UI loaded/poison state and historical progress.
- [ ] Measure memory, latency and PostgreSQL load with 200 bounded owners.

No durable repository or migration is implemented by this design document.

The exact source-byte hash, chunking/extraction pipeline fingerprint, and actual
embedding runtime fingerprint are separate identities. A changed pipeline must
not rewrite original source or ingestion provenance. Missing retained CSRF poison
remains unavailable until an explicit owner re-upload or reset; canonical clean
reseed cannot select clean content in place of the saved poisoned context.
Resource repair and authenticated state reads never award retrospective credit.

## Staged facade and vector adapter contract

`server/services/workshopRagStore.js` is an unwired factory, not a configured
production store. Its source repository now targets the separately staged
candidate `workshop_rag` schema. Construction also requires a durable vector
repository; a source-only repository cannot activate it. Controlled adapter unit
tests do not establish PostgreSQL vector persistence.

`bind(scope, {signal})` takes trusted admission coordinates: owner, authenticated
session, family, slot, graph generation, resource generation and run ID.
`ingestAndSelect` snapshots the previous selection ID and monotonic selection
version, stages immutable exact source/chunks, embeds outside transactions, then
calls `publishAndSelect`. The prior selection remains until this final atomic
operation succeeds. Failed staged sources consume the bounded source quota and
require explicit lifecycle cleanup; the service never silently deletes them.

The vector adapter must implement:

- `snapshot(scope, {documentId})`: return exact source hash, chunk-manifest hash,
  chunk-pipeline hash and nullable expected revision head.
- `publish(scope, input)`: atomically compare authoritative source hashes,
  expected head, admitted run, both generations, session and trusted loaded
  runtime fingerprint; insert complete immutable vectors and publish the head.
- `publishAndSelect(scope, input)`: perform the same publication and compare
  `selection.expectedSelection` plus `selection.expectedSelectionVersion` in
  that **same transaction**, then update selection. A separate `select` call
  after vector publication does not satisfy this contract.
- `search(scope, input)`: validate current authority and the trusted runtime,
  read the complete current revision, and return exact chunk text, index and
  cosine score with a scope-bound observation receipt. Only explicit
  `EMBEDDING_REINDEX_REQUIRED` / `EMBEDDING_RUNTIME_MISMATCH` triggers one rebuild;
  other failures propagate.

Publication input includes an idempotent operation UUID, document ID, source
hash, chunk-manifest hash, chunk-pipeline hash, expected head, expected loaded
runtime fingerprint and ordered chunk vectors. Receipts contain document and
revision IDs, those hashes, runtime fingerprint and current observation scope
(owner/family/slot/resource generation/graph generation/run). A read on a later
run must bind that **new observation** without rewriting original ingestion or
revision provenance. Replays must not duplicate revision or selection changes.

The fixed producer descriptor is exported as `WORKSHOP_RAG_CHUNK_PIPELINE`:
500 Unicode code points, overlap 50, edge whitespace trimming, minimum 20 with
whole-trimmed short-document fallback. Exact source bytes, including UTF-8 BOM,
remain unchanged. `utf8-byte-ranges-v1` is the storage representation; the
separate producer descriptor hash identifies this algorithm. It intentionally
does not pretend to be the old JavaScript UTF-16 window algorithm.

`ragIngestGraph` accepts an optional already-bound `durableRagStore` and sends its
publication receipt to grading only after atomic ingestion/selection. Existing
memory fixtures retain their prior path. Query decision-loop work is separate:
see [RAG agent decision loop](rag-agent-decision-loop.md). Merely wrapping a
fixed retrieval pipeline in `StateGraph` does not establish model-driven agent
decisions. No route selects the staged durable factory yet.

Completed logical-operation retry uses `findIngestReplay` before new ingestion.
The repository checks the exact requested source hash, byte ranges, filename,
ingestion kind and pipeline identity against the immutable completed operation,
plus current ownership, session and generations. A match returns the original
publication receipt and a separate current-authority observation, with
`currentlySelected` explicitly reported. It must neither re-embed nor select an
older document over a newer selection. Retired resources reject stale replay.
The ingestion graph skips all attempt/Judge/credit work for a completed replay.
This is a service-level logical-operation contract; HTTP idempotency-key wiring
is still pending and must not be claimed from these tests.
