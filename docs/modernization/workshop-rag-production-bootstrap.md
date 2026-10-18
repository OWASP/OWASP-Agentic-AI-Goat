# Durable workshop RAG production bootstrap

`server/services/workshopRagProduction.js` is now awaited by supported PostgreSQL startup in `server/index.js`. Migration `0082_workshop_rag_sources.sql` is registered with exactly the qualified candidate bytes. This is a source-level promotion only: the installed process and its stores have not been restarted or migrated. Importing the module itself performs no initialization or private environment loading.

The factory snapshots the PostgreSQL engine configuration and credential-free identity database name, resolves the canonical identity singleton, creates the shared real CPU embedder, and invokes exact storage readiness. It then binds one composition to both mounted route objects and constructs the canonical reset/deletion adapter registries with those same route references. Existing application reset/deletion compositions resolve these lazy route adapters, so there is no second document lifecycle service.

Storage or adapter contract failure rejects initialization with a sanitized error and prevents bootstrap readiness. Model initialization is separate: asynchronous warm-up exposes `embeddingStatus()` and retryable `warmEmbedding()`. A pending download or unavailable model does not block platform login/admin or unrelated exercises. Upload/query still use the same actual embedder and cannot substitute mock vectors or RAM documents.

## Promotion ordering

After all store initialization results succeed and before `platformDataLifecycle.initialize(...)`, the supported PostgreSQL branch now executes:

```js
const workshopRag = await require('./services/workshopRagProduction')
  .getWorkshopRagProduction().initialize();
app.locals.workshopRagProduction = workshopRag;
```

Await storage initialization. Follow existing fatal-startup handling if it rejects. Do not await model warm-up before `server.listen`. No user-facing opt-in should remain for the supported PostgreSQL path after promotion. Explicit legacy fixtures retain their own paths. Both route modules must already be loaded, as in current index setup; the bootstrap requires their real cached route objects.

The unchanged qualified candidate is registered as `0082_workshop_rag_sources.sql` (SHA256 `c8c12676190ca08d7147441a4a032b8a8ba8dc1267e814d9a573d9e50fa24e85`). Never edit this applied-capable migration. Registered fresh/populated/second-no-op qualification accompanies this source promotion. Candidate0083 and0084 are separately owned changes; their readiness gates must also be coherent if promoted in the same application release.

## Preservation and remaining gates

- Saved CSRF `ragDocText` stays in the existing PostgreSQL victim-state JSON. Bootstrap never reads, rewrites, clears or autoimports it. Owner-bound missing durable poison returns503; explicit owner re-upload/reset remains available. This is an explicit recovery boundary, **not an automatic legacy-source migration** or claim that poison retrieval survived restart.
- Existing installed IPI RAM documents still block an ordinary activation restart. Their original upload bytes were discarded by the legacy store. No reconstructed chunk export can claim exact original provenance. Resolve the separate originating-process preservation/review plan before stopping that process; this bootstrap performs no RAM export trick.
- Review existing native source/vector/readiness, mounted IPI/CSRF, actual8B Judge, reset/deletion and rendered retry evidence against the exact promotion snapshot. The new bootstrap native test uses controlled embeddings and external CSRF/email continuations; it does not replace actual CPU/model or full sixteen-store deletion qualification.
- Back up configured stores privately and verify additive preservation and no-op initialization before any installed activation. No cloud/AWS assets change.
