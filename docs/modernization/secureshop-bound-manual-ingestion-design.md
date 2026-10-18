# SecureShop bound product-manual ingestion design

Status: implemented candidate, not activated. Controlled writer/extraction/graph/gateway contracts pass. Disposable native PostgreSQL fresh/populated/no-op, append/replay, privilege, cleanup and deterministic lock-order checks pass (tasks/secureshop-manual-ingest-native-69725.json). Mounted real-file/CPU-embedding controlled qualification55391 and actual llama3.1:8b qualification90163 pass (1 test each, zero skips); owner reset removes retrieval and retires files while sibling bytes survive. Rendered qualification, subsequent actual-model poisoned retrieval, and application activation remain pending.

Implemented retry choice: identical bytes and upload metadata for the same merchant, product and full launch generation deliberately replay one deterministic operation. Changed metadata/content selects a new operation. Each attempt still requires a new model decision. This is documented idempotency, not support for creating duplicate identical manuals.

## Goal and boundary

The bound SecureShop application needs an authentic product-manual upload chain:

1. the authenticated merchant uploads real bytes through the existing multipart request shape;
2. the bytes are written into that launch's owned file target and read back;
3. extraction and chunking operate on those read-back bytes;
4. every chunk is embedded and appended to that launch's product retrieval target;
5. a later customer retrieval can expose the unfiltered chunk to the model and demonstrate the intentional prompt-injection and RAG-poisoning sinks; and
6. launch reset retires both the uploaded bytes and the indexed chunks.

The legacy upload router is not an implementation dependency for this path. It writes to a process-global upload directory and a global vector corpus (`server/routes/secureshop/uploads.js`; `agent-host/agents/uploads/tools/index.js`). Mounting or wrapping it would preserve the public URL while losing owner, launch, generation, and reset authority.

The intended vulnerable behavior is the passage of attacker-authored manual text into retrieval and then into model context. Host-path traversal, global-file access, and cross-learner vector sharing are not required for that lesson and must remain confined to the legacy challenge.

## Existing contracts to retain

### Public request and UI

`client/src/pages/secureshop/components/UploadZone.jsx` sends `POST /api/secureshop/uploads` as `multipart/form-data` with one `file` part and four string fields:

- `kind`
- `scope_id`
- `mime`
- `public`

The editable filename is the multipart file name. `client/src/pages/secureshop/bridge/uploads.mjs` preserves the exact `Blob`, filename, MIME value, and fields and caps the file at 20 MiB. The bridge must remain byte preserving; it must not JSON/base64 encode the upload or replace the filename. No current page instantiates `UploadZone` for `product_manual`; the first backend increment must not redesign the component or silently claim a merchant UI is already mounted. A later merchant page can use the existing component shape.

The bound gateway owns any request carrying the SecureShop launch header before legacy routers can see it (`server/routes/secureshop/boundGateway.js`). It should add a bound `POST /uploads` handler for `kind=product_manual` ahead of its terminal fallback. The handler must use the existing launch middleware and require an authenticated `merchant` persona. It must accept the existing multipart parts without adding learner-supplied owner, launch, generation, file-target, retrieval-target, conversation-purpose, or operation-authority fields.

The response should preserve the legacy product-manual projection needed by the existing upload UI:

```text
ok, kind, scope_id, filename, cleaned_filename, relative_path, mime,
size_bytes, is_traversal, extracted_bytes, chunk_count, chunk_ids,
extractor, extractor_error, indexed_corpus
```

For the bound path, `is_traversal` is always `false`, `relative_path` is a virtual path, and `chunk_ids` are opaque target-owned identifiers. The response may add an opaque operation ID plus actual provider/model metadata. Capabilities, host paths, platform owner/session IDs, launch/scenario IDs, generations, embeddings, and protected traces must not be returned.

### Owned file target

`sidecars/sandbox-runner/secureshopFiles.js` already provides the required file primitive:

- `provisionReservedTarget(binding)` opens the exact reserved target and returns a process-local capability;
- `writeFile(capability, virtualPath, bytes, { expectedGeneration })` writes atomically and returns the path, byte count, and SHA-256;
- `readFile(capability, virtualPath, { expectedGeneration, maxBytes })` returns the actual bytes and independently computed SHA-256; and
- `retireReservedTarget(binding, { operationId, authorize })` deletes the target under durable reset authority.

`server/services/secureshopReservedFiles.js` is currently a read-only backend facade. Product-manual ingestion needs a sibling writer facade; it must not receive a path returned by `assetPaths` or call the host filesystem directly.

Production bound composition currently accepts an optional `files` dependency, and cleanup only installs file-target cleanup when that dependency exists (`server/services/secureshopCleanupComposition.js`). Activation therefore requires one retained, privately configured `createSecureShopFiles` instance shared by ingestion, reads, and cleanup. The public 20 MiB contract exceeds the primitive defaults of 1 MiB write and 256 KiB read. Either configure this retained instance for 20 MiB and keep tighter limits on other reads, or lower the public bound explicitly. Silently accepting 20 MiB in the bridge and rejecting it later as an unrelated sandbox failure is not acceptable.

### Product retrieval target

`server/services/secureshopBoundProductRetrieval.js` and `server/database/postgres/secureshopBoundProductRetrievalRepository.js` bind retrieval configuration and documents to the canonical product target in `secureshop_review`. The later `similar` operation deliberately returns target-owned manual text unfiltered and `applyRetrievalBias` recognizes product references in that text. Those two intentional sinks remain.

The current repository's `replaceDocuments` method cannot implement manual upload. It deletes the base product corpus and every previously uploaded manual. Existing document identity `(target_id, generation, source_kind, source_id, chunk_index)` also collides if `source_id` remains the product ID for two manuals uploaded for the same product.

## Proposed components

### 1. Bound upload route

Extend `createSecureShopBoundGateway` with an optional `productManualIngestion` dependency exposing:

```js
upload({ scope, persona, productId, bytes, filename, mime, isPublic, signal })
```

The route uses memory-backed multipart parsing with the existing 20 MiB cap and rejects duplicate parts, unknown fields, invalid UTF-8 metadata bounds, a non-`product_manual` kind, nonpositive `scope_id`, query parameters, and a nonmerchant persona. It passes `req.ssLaunch` and `req.boundPersona`, never body-derived authority. Client disconnect cancellation must drain the selected graph/tool callback before the HTTP handler returns.

Requests with a launch header must never fall through to the legacy upload router. Other bound upload kinds keep their current unavailable behavior until they receive their own owned adapters.

### 2. Reserved file writer

Add `createSecureShopReservedFileWriter({ launches, files })` with one method:

```js
writeAndReadBack(trustedScope, {
  operationId, productId, bytes, filename, mime
})
```

It snapshots all input before its first await, reserves the launch's `files` target, verifies the returned target tuple, checks the launch, provisions the exact reserved target, and writes to a server-selected virtual path such as:

```text
/uploads/product_manuals/<productId>/<operationId>-manual
```

The editable filename and MIME remain metadata; neither selects the storage path. The facade then reads the file back, checks current authority again, and requires exact path, generation, byte length, byte equality, and SHA-256 equality. It returns a frozen receipt containing only the exact file-target binding needed by private cleanup/recovery code, virtual path, byte count, digest, display filename, and MIME. The capability never leaves the facade.

Both the product target and files target must be reserved before publishing the ingestion effect. A partial file write remains visible as cleanup debt; it is not reported as an indexed upload.

### 3. Byte-based extraction and chunks

Add a bounded server service such as `server/services/secureshopBoundManualExtraction.js`:

```js
extractAndChunk({ bytes, filename, mime })
```

It accepts the read-back `Buffer`, not a host path. It supports legitimate UTF-8 text/Markdown/HTML/SVG, actual PDF parsing, and actual DOCX extraction. It returns frozen `{ extractor, textSha256, extractedBytes, chunks }`, with deterministic 500-token chunks and explicit limits on extracted bytes, chunk bytes, and chunk count.

An invalid or malformed PDF is a parse failure and produces no indexed chunks. The legacy helper's raw-UTF-8 fallback for a `.pdf` file is a fixture compatibility behavior, not successful PDF extraction, and must not be copied into the bound path. Legitimate raw text remains supported under a text-like filename/MIME. An empty extraction, parser failure, over-limit output, or zero chunks fails before retrieval publication.

No content filter, system-prompt stripping, or instruction escaping is applied to extracted text. That absence is the intentional RAG-poisoning sink.

### 4. Append-only manual ingest schema

Add the next forward `secureshop_review` migration after the applied retrieval migration. Do not edit the applied retrieval migration.

Create an immutable `product_target_manual_ingests` table with at least:

- `operation_id uuid` primary key;
- exact product target ID and generation;
- selected product ID;
- a generated positive `manual_source_id` unique within the store;
- exact files-target ID, launch ID, scenario ID, generation, owner and session;
- virtual path, byte count, file SHA-256, display filename, and MIME;
- extractor name, extracted-text SHA-256;
- embedding model and dimension;
- canonical chunk/document digest and count; and
- completion timestamp.

Add a fixed-search-path `SECURITY DEFINER` function `append_product_manual_retrieval(...)`. It must:

1. lock the canonical product target before retrieval configuration or child rows;
2. require the exact active owner/session/launch/scenario/generation tuple;
3. require an active retrieval configuration with the exact embedding model and dimension;
4. validate a closed, bounded JSON chunk array and compute the canonical digest inside PostgreSQL;
5. replay an existing operation only when every immutable coordinate and digest matches;
6. allocate one `manual_source_id` for a new operation;
7. insert each chunk into the existing retrieval documents as `source_kind='manual'`, `source_id=manual_source_id`, and its bounded chunk index; and
8. insert the immutable ingest receipt in the same transaction.

This identity lets two different operations append manuals for the same product without replacing base product documents or another manual. An exact operation replay inserts nothing. A changed file, metadata, target, product, model, or chunks under the same operation is rejected.

The runtime role receives `EXECUTE` only. Revoke `PUBLIC`; do not grant runtime direct insert, update, or delete on documents or ingest receipts. Extend product retrieval cleanup so its count and empty-state validation cover all appended manual documents. The ingest receipt may remain as immutable audit metadata tied to the retained product-target tombstone; the file-target cleanup removes the actual bytes.

Expose repository methods:

```js
appendManual(binding, {
  operationId, productId, fileReceipt, filename, mime,
  extractor, extractionSha256,
  embeddingModel, embeddingDimension, documents
})

readManualIngestReceipt(binding, { operationId })
```

The repository repeats strict closed-object and bound checks before SQL but treats the SQL function as the authority for digest, append, and replay.

### 5. Provisioning and embeddings

Factor the current base-corpus preparation in `secureshopBoundProductRetrieval` into a private `ensureProvisioned` operation shared by customer similarity and merchant ingestion. Manual ingestion must prepare the canonical catalog target, prove the authenticated merchant owns the launch's merchant inventory, and provision all base product documents before appending the first manual. `catalog.hasProduct` alone is insufficient because it proves existence for any valid persona rather than merchant ownership.

Every extracted chunk is embedded with the same actual embedding model and dimension recorded by the retrieval config. Provider/model identity changes during one upload fail closed. A manual-first upload must not create a config that causes the later customer path to skip base product provisioning.

### 6. Merchant graph and tool

Use the existing retained `createBoundAgentRunner`, conversation repository, turn journal, and run coordinator. Add a merchant-only operation `uploads.upload_product_manual` and a dedicated server-selected conversation purpose such as `secureshop_product_manual_ingest`; adding that purpose requires the next forward `secureshop_agents` migration plus the local purpose enum. Reusing `secureshop_product_assist` would be mechanically possible because persona-bound sessions are distinct, but it obscures the workflow's role and cleanup evidence.

The model receives bounded metadata only: selected product ID, display filename, MIME, byte count, and file digest. It never receives the bytes, reserved-file capability, virtual path, owner/session IDs, target IDs, or generation. The configured provider must make one actual structured tool selection with exact arguments. Mock, fixture, scripted, fallback, missing identity, refusal, wrong tool, or changed arguments cannot call the local effect.

The local tool authority closure holds the frozen byte/read-back receipt and selected product binding. Inside the retained coordinator lease it:

1. rechecks launch authority;
2. extracts and chunks the read-back bytes;
3. embeds every exact chunk;
4. appends the manual through the repository function;
5. rechecks launch authority; and
6. returns a bounded observation containing receipt metadata, never embeddings or capabilities.

The upload model decision does not sanitize or rewrite the document. The later customer `product-search.similar` graph continues to put retrieved manual chunks into the tool observation and model context verbatim.

### 7. Retry and lifecycle behavior

The existing bridge and UI do not supply an operation ID. A server-random ID returned only after success cannot resume a disconnect or crash between file write and database append. Before activation, choose and test one of these server-owned approaches without changing the visible form fields:

- have the bound bridge attach an internal UUID idempotency header and preserve it for transport retry; or
- durably begin an ingest operation keyed by the exact launch/product/file request digest and resume the matching nonterminal operation.

The second option can distinguish a pending retry from a later intentional duplicate; a permanent digest-only operation ID cannot. Explicitly uploading the same bytes twice should either create two documented manuals or be a documented idempotent replay, never an accidental primary-key collision.

The upload graph must run under the same retained conversation coordinator used by launch reset. Reset first drains bound sessions, retires the product retrieval target and the files target, and only then commits the next launch generation. The same retained `files` primitive must be injected into `createSecureShopCleanupComposition`; otherwise a reserved file target has no cleanup adapter and activation must fail readiness.

Cross-store file and retrieval effects are not atomic. Checks around each await detect observed revocation, while durable file and retrieval receipts support bounded recovery and cleanup. They do not justify a claim of atomic publication across the filesystem and PostgreSQL.

## Acceptance checklist

Implementation is not ready for activation until all items below pass.

### Controlled contracts

- [ ] Existing `UploadZone` and bridge multipart fields, editable filename, MIME, and exact bytes reach the bound handler unchanged.
- [ ] Duplicate parts, unknown fields, forged owner/target/generation fields, oversized bytes/metadata, invalid product IDs, and nonmerchant personas fail before effects.
- [ ] Merchant ownership is proven against the current launch's catalog target; another merchant/product, owner, session, launch, scenario, or generation is rejected.
- [ ] The owned file writer writes and reads back the exact bytes and rejects a changed path, count, digest, target tuple, generation, symlink, or capability.
- [ ] Valid text, actual PDF, and actual DOCX extraction use read-back bytes; malformed PDF, parser failure, empty extraction, and bounds failures index nothing.
- [ ] Raw instruction text survives extraction, chunking, embedding, search, tool observation, and the intentional customer model-context sink.
- [ ] The upload graph requires a genuine merchant-model structured selection; mock, fallback, scripted, refusal, wrong tool, wrong arguments, or missing identity creates no file or retrieval receipt.
- [ ] No bytes, host paths, capabilities, embeddings, or protected authority fields appear in public responses or traces.

### Repository and migration

- [x] Fresh, representative populated, and second-run/no-op migration paths pass in disposable stores.
- [x] Base product documents survive one and multiple manual uploads.
- [x] Manual A survives upload of manual B for the same product.
- [x] Exact operation replay inserts no duplicate; a mismatched replay fails; intentional separate upload behavior is explicit.
- [ ] Runtime direct DML, forged target/file tuples, wrong embedding identity/dimension, invalid vectors, oversized chunks, duplicate indexes, and digest substitution fail.
- [x] Product cleanup deletes every retrieval document, reports the exact combined count, retains only intended immutable receipts, and replays exactly.
- [x] Deterministic parent-lock races prove append-before-cleanup is included and cleanup-before-append rejects the late write.

### Mounted lifecycle

- [x] A real authenticated merchant uses the unchanged multipart endpoint and the bound graph; the legacy upload router/global corpus is not called.
- [x] The stored file digest matches the original uploaded bytes, and indexed chunks derive from that exact read-back file.
- [ ] A customer actual-model similarity request retrieves the target-owned manual and demonstrates the intended poisoning behavior without crossing launch boundaries.
- [ ] Two learners can upload identical filenames, product IDs, and content without observing each other's files, vectors, receipts, model traces, or results.
- [ ] Reset waits for an in-flight selected tool to drain, then removes file bytes and retrieval documents; a stale callback cannot publish afterward.
- [ ] Partial file-write, extraction, embedding, append, response-disconnect, and reset failures retain enough bounded evidence for retry or cleanup without claiming successful ingestion.
- [ ] Reset replay and process restart preserve exact cleanup results and do not delete a sibling launch.

Actual-model, native PostgreSQL, mounted HTTP, and reset qualifications remain separate evidence gates. Controlled fixtures alone cannot establish them.

## Merchant surface and model-output correction

The existing active listing edit modal now reuses `UploadZone` after its save form. Create and archived listing flows do not offer manual upload. Styling, editable filename, raw multipart bytes, MIME and public fields remain the shared component contract. HTTP failures never trigger success callbacks; selection/scope changes and unmount abort pending work. StrictMode effect replay is explicitly covered.

Customer similarity previously discarded the genuine graph final response while showing deterministic tool-ranked cards. The adapter now returns the exact validated final text as `recommendation`, and the existing Related products section renders it as React text, including refusals. This does not turn regex-based card ordering into model evidence. The intentional retrieval-bias sink remains; neither card order nor mere nonce exposure earns Judge credit. Actual-model qualification must separately record whether an uploaded instruction changed the model narrative, with a matched sibling negative and persisted trace provenance. Rendered and objective-credit acceptance remain separate gates.

Actual-model retrieval checkpoint60900: owner and matched sibling each made a genuine structured selection plus final response (four retrieval calls total). Exact target manual context and durable final narrative parity passed; sibling never observed owner nonce. Owner narrative mentioned the requested catalog product but omitted the nonce, so instruction-following classification is false. This is a negative attack outcome, not a successful prompt-injection demonstration or Judge completion. Rendered qualification remains pending.
