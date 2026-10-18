'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');

const MAX_PRODUCTS = 256;
const PAGE_SIZE = 100;
const MAX_SOURCE_BYTES = 32768;
const RESULT_LIMIT = 5;
const SOURCE_KINDS = new Set(['product', 'listing', 'review', 'manual']);

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}
function unavailable(message) {
  return failure('BOUND_RETRIEVAL_UNAVAILABLE', message);
}
function exactPersona(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length !== 2 || !Number.isSafeInteger(value.id)
      || value.id < 1 || value.id > 2147483647 || value.role !== 'customer') {
    throw failure('INVALID_ARGUMENT', 'Customer persona is invalid');
  }
  return Object.freeze({ id: value.id, role: 'customer' });
}
function exactProductId(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw failure('INVALID_ARGUMENT', 'Product id is invalid');
  }
  return value;
}
function sourceText(product) {
  if (typeof product?.name !== 'string' || !product.name.trim()
      || (product.description !== null && product.description !== undefined
        && typeof product.description !== 'string')) {
    throw unavailable('Product source is invalid');
  }
  const value = `${product.name}\n${product.description || ''}`;
  if (!value.trim() || Buffer.byteLength(value, 'utf8') > MAX_SOURCE_BYTES) {
    throw unavailable('Product source exceeds the retrieval bound');
  }
  return value;
}
function productRow(value) {
  if (!value || !Number.isSafeInteger(value.id) || value.id < 1
      || value.id > 2147483647 || typeof value.name !== 'string' || !value.name
      || (value.description != null && typeof value.description !== 'string')
      || (value.description_html != null && typeof value.description_html !== 'string')
      || !Number.isFinite(value.price) || value.price < 0
      || (value.category != null && typeof value.category !== 'string')
      || (value.image_url != null && typeof value.image_url !== 'string')
      || !Number.isSafeInteger(value.stock_quantity) || value.stock_quantity < 0
      || !Array.isArray(value.images) || value.images.some(image => typeof image !== 'string')) {
    throw unavailable('Catalog returned an invalid product');
  }
  return Object.freeze({
    id: value.id,
    name: value.name,
    description: value.description ?? null,
    description_html: value.description_html ?? null,
    price: value.price,
    category: value.category ?? null,
    image_url: value.image_url ?? null,
    images: Object.freeze(Array.isArray(value.images) ? [...value.images] : []),
    stock_quantity: value.stock_quantity,
    retailer_id: value.retailer_id,
    status: value.status,
    template_source: value.template_source,
    created_at: value.created_at,
    updated_at: value.updated_at,
  });
}
function embeddingResult(value) {
  if (!value || typeof value.embeddingModel !== 'string' || !value.embeddingModel
      || !Number.isSafeInteger(value.embeddingDimension) || value.embeddingDimension < 1
      || value.embeddingDimension > 4096 || !Array.isArray(value.embedding)
      || value.embedding.length !== value.embeddingDimension
      || value.embedding.some(number => !Number.isFinite(number))
      || !value.embedding.some(number => number !== 0)) {
    throw unavailable('Embedding output is invalid');
  }
  return Object.freeze({ embeddingModel: value.embeddingModel,
    embeddingDimension: value.embeddingDimension, embedding: Object.freeze([...value.embedding]) });
}
function metadata(value) {
  if (!value || typeof value.embeddingModel !== 'string' || !value.embeddingModel
      || !Number.isSafeInteger(value.embeddingDimension) || value.embeddingDimension < 1
      || value.embeddingDimension > 4096 || !Number.isSafeInteger(value.documentCount)
      || value.documentCount < 0) throw unavailable('Retrieval metadata is invalid');
  return value;
}
function sameBinding(value, binding) {
  return value && ['targetId', 'launchId', 'scenarioId', 'generation', 'platformOwnerId',
    'platformSessionId'].every(key => value[key] === binding[key]);
}
function keywordFallback(seed, all) {
  const tokens = String(`${seed.name} ${seed.description || ''}`).toLowerCase()
    .split(/\W+/).filter(Boolean);
  const targetTokens = new Set(tokens);
  const seenNames = new Set([seed.name]);
  return all.filter(row => {
    if (row.id === seed.id || seenNames.has(row.name)) return false;
    seenNames.add(row.name);
    return true;
  }).map((row, index) => {
    const overlap = String(`${row.name} ${row.description || ''}`).toLowerCase()
      .split(/\W+/).filter(Boolean).filter(token => targetTokens.has(token)).length;
    return { row, index, score: overlap + (row.category === seed.category ? 2 : 0) };
  }).sort((left, right) => right.score - left.score || left.index - right.index)
    .slice(0, RESULT_LIMIT).map(entry => entry.row);
}
function applyRetrievalBias(results, retrieved, all, seedId) {
  // @intentional-vulnerability llm08-embedding-poisoning
  // Poisoned target-owned embeddings may bias recommendations, but cannot
  // introduce a product that is absent from this launch's catalog snapshot.
  const promotedIds = new Set();
  for (const row of retrieved) {
    for (const match of String(row.text).match(/product\s*#?\s*(\d+)/gi) || []) {
      const id = Number(match.replace(/\D+/g, ''));
      if (Number.isSafeInteger(id) && id > 0) promotedIds.add(id);
    }
  }
  const promoted = [...promotedIds].filter(id => id !== seedId)
    .map(id => all.find(row => row.id === id)).filter(Boolean);
  const seen = new Set(promoted.map(row => row.id));
  return [...promoted, ...results.filter(row => !seen.has(row.id))].slice(0, RESULT_LIMIT);
}
function contextRows(rows) {
  if (!Array.isArray(rows) || rows.length > RESULT_LIMIT) throw unavailable('Retrieval result is invalid');
  return Object.freeze(rows.map(row => {
    if (!row || !SOURCE_KINDS.has(row.sourceKind) || !Number.isSafeInteger(row.sourceId)
        || row.sourceId < 1 || !Number.isSafeInteger(row.chunkIndex) || row.chunkIndex < 0
        || typeof row.text !== 'string' || !Number.isFinite(row.score)) {
      throw unavailable('Retrieval result is invalid');
    }
    // @intentional-vulnerability llm04-rag-poisoning
    // Target-owned retrieved text is deliberately passed through unfiltered.
    return Object.freeze({ sourceKind: row.sourceKind, sourceId: row.sourceId,
      chunkIndex: row.chunkIndex, text: row.text, score: row.score });
  }));
}
const MANUAL_LIMIT = 3;
const MANUAL_BYTES = 16384;
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digestText = text => createHash('sha256').update(text, 'utf8').digest('hex');
function manualExact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== keys.length
      || keys.some(key => !Object.hasOwn(value, key)
        || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))) {
    throw unavailable('Manual search result is invalid');
  }
}
function manualText(value, max) {
  return typeof value === 'string' && value.trim() && !value.includes('\0')
    && Buffer.byteLength(value, 'utf8') <= max;
}
function validateManualSearchResult(value) {
  manualExact(value, ['product','query','limit','count','hasMore','revision','status','sources']);
  manualExact(value.product, ['id','name']);
  exactProductId(value.product.id);
  manualExact(value.revision, ['revisionId','runtimeFingerprint','sourceSetDigest']);
  if (!manualText(value.product.name, 4096) || !manualText(value.query, 4096)
      || value.limit !== MANUAL_LIMIT || !Number.isInteger(value.count)
      || value.count < 0 || value.count > MANUAL_LIMIT || typeof value.hasMore !== 'boolean'
      || (value.hasMore && value.count !== MANUAL_LIMIT)
      || !['complete','oversized'].includes(value.status)
      || !(typeof value.revision.revisionId === 'string' && UUID.test(value.revision.revisionId)) || !(typeof value.revision.runtimeFingerprint === 'string' && HASH.test(value.revision.runtimeFingerprint))
      || !(typeof value.revision.sourceSetDigest === 'string' && HASH.test(value.revision.sourceSetDigest)) || !Array.isArray(value.sources)
      || value.sources.length !== value.count || (value.status === 'oversized' && !value.count)) {
    throw unavailable('Manual search result is invalid');
  }
  const seen = new Set();
  for (const row of value.sources) {
    manualExact(row, ['sourceKind','sourceId','chunkIndex','text','score','sourceSha256',
      'filename','operationId','receiptSha256','documentDigest','completedAt','textBytes','textSha256']);
    const key = `${row.sourceId}:${row.chunkIndex}`;
    if (row.sourceKind !== 'manual' || !Number.isSafeInteger(row.sourceId) || row.sourceId < 1
        || !Number.isInteger(row.chunkIndex) || row.chunkIndex < 0 || row.chunkIndex > 128
        || !Number.isFinite(row.score) || row.score < -1 || row.score > 1
        || !(typeof row.sourceSha256 === 'string' && HASH.test(row.sourceSha256)) || !manualText(row.filename, 4096)
        || !(typeof row.operationId === 'string' && UUID.test(row.operationId)) || !(typeof row.receiptSha256 === 'string' && HASH.test(row.receiptSha256))
        || !(typeof row.documentDigest === 'string' && HASH.test(row.documentDigest)) || typeof row.completedAt !== 'string'
        || !Number.isFinite(Date.parse(row.completedAt))
        || new Date(row.completedAt).toISOString() !== row.completedAt
        || !Number.isInteger(row.textBytes) || row.textBytes < 1 || row.textBytes > 65536
        || !(typeof row.textSha256 === 'string' && HASH.test(row.textSha256)) || seen.has(key)) throw unavailable('Manual source is invalid');
    seen.add(key);
    if (value.status === 'oversized' ? row.text !== null
      : typeof row.text !== 'string' || !row.text.trim()
        || Buffer.byteLength(row.text, 'utf8') !== row.textBytes || digestText(row.text) !== row.textSha256) {
      throw unavailable('Manual source text is invalid');
    }
  }
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > MANUAL_BYTES) {
    throw failure('MANUAL_SEARCH_RESULT_TOO_LARGE', 'Manual search metadata exceeds the observation bound');
  }
  return Object.freeze({ ...value, product: Object.freeze({ ...value.product }),
    revision: Object.freeze({ ...value.revision }),
    sources: Object.freeze(value.sources.map(row => Object.freeze({ ...row }))) });
}
function retrievalMode(rows) {
  const manuals = rows.some(row => row.sourceKind === 'manual');
  const products = rows.some(row => row.sourceKind !== 'manual');
  return manuals && products ? 'mixed' : manuals ? 'manuals' : 'products';
}

function createSecureShopBoundProductRetrieval({ catalog, repository, embedder, checkCurrent, revisionRepository, reindex } = {}) {
  if (typeof catalog?.prepareTarget !== 'function' || typeof catalog?.getProduct !== 'function'
      || typeof catalog?.listProducts !== 'function' || typeof repository?.readMetadata !== 'function'
      || typeof repository?.provision !== 'function' || typeof repository?.search !== 'function'
      || typeof embedder?.embed !== 'function' || typeof checkCurrent !== 'function') {
    throw new TypeError('Bound product retrieval dependencies required');
  }
  const revisionMode = revisionRepository !== undefined || reindex !== undefined;
  if (revisionMode && (typeof revisionRepository?.search !== 'function'
      || typeof revisionRepository?.readHead !== 'function' || typeof reindex?.reindex !== 'function'
      || typeof embedder.getRuntimeFingerprint !== 'function')) throw new TypeError('Revision retrieval dependencies required');
  // One bounded queue per composed runtime. Each waiter keeps its own authority
  // and cancellation; a cancelled learner cannot abort another learner's rebuild.
  let revisionActive = false;
  const revisionWaiters = [];
  const check = async (scope, signal) => {
    signal?.throwIfAborted();
    await checkCurrent(scope);
    signal?.throwIfAborted();
  };
  const boundary = async (scope, signal, operation) => {
    await check(scope, signal);
    const result = await operation();
    await check(scope, signal);
    return result;
  };
  function drainRevisionQueue() {
    if (revisionActive || !revisionWaiters.length) return;
    const item = revisionWaiters.shift();
    clearTimeout(item.timer); item.signal?.removeEventListener('abort', item.abort);
    revisionActive = true;
    (async () => {
      await check(item.scope, item.signal);await item.personaEffect?.check(item.scope);await item.beforeEffect?.();
      if (await boundary(item.scope, item.signal, () => revisionRepository.readHead(item.binding))) return;
      await boundary(item.scope, item.signal, () => reindex.reindex({ scope: item.scope,
        binding: item.binding, operationId: randomUUID(), signal: item.signal, personaEffect:item.personaEffect, beforeEffect:item.beforeEffect }));
    })().then(item.resolve, item.reject).finally(() => { revisionActive = false; drainRevisionQueue(); });
  }
  async function ensureRevision(scope, signal, binding, personaEffect, beforeEffect) {
    await check(scope, signal);
    if (revisionWaiters.length >= 32) throw failure('EMBEDDING_REINDEX_CAPACITY', 'Embedding rebuild queue is full; retry shortly');
    return new Promise((resolve, reject) => {
      const item = { scope, signal, binding, personaEffect, beforeEffect, resolve, reject };
      const remove = error => {
        const index = revisionWaiters.indexOf(item);
        if (index < 0) return;
        revisionWaiters.splice(index, 1); clearTimeout(item.timer);
        signal?.removeEventListener('abort', item.abort); reject(error);
      };
      item.abort = () => remove(signal.reason || failure('ABORTED', 'Embedding request cancelled'));
      item.timer = setTimeout(() => remove(failure('EMBEDDING_REINDEX_QUEUE_TIMEOUT', 'Embedding rebuild queue timed out; retry shortly')), 60000);
      revisionWaiters.push(item); signal?.addEventListener('abort', item.abort, { once: true });
      if (signal?.aborted) item.abort();
      drainRevisionQueue();
    });
  }
  function runtimeFingerprint() {
    const fingerprint = embedder.getRuntimeFingerprint()?.fingerprint;
    if (typeof fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(fingerprint)) {
      throw failure('EMBEDDING_FINGERPRINT_UNAVAILABLE', 'Verified embedding runtime is unavailable');
    }
    return fingerprint;
  }
  async function revisionSearch(scope, signal, binding, query, fingerprint, personaEffect, withLineage = false) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await check(scope, signal);
      if (runtimeFingerprint() !== fingerprint) throw failure('EMBEDDING_RUNTIME_CHANGED', 'Query embedding runtime changed');
      try {
        const method = withLineage && typeof revisionRepository.searchWithLineage === 'function' ? 'searchWithLineage' : 'search';
        const result = await boundary(scope, signal, () => revisionRepository[method](binding, {
          embedding: query.embedding, limit: RESULT_LIMIT,
        }));
        if (runtimeFingerprint() !== fingerprint) throw failure('EMBEDDING_RUNTIME_CHANGED', 'Query embedding runtime changed');
        return result;
      } catch (error) {
        if (!['EMBEDDING_REINDEX_REQUIRED', 'EMBEDDING_RUNTIME_MISMATCH'].includes(error.code) || attempt === 1) throw error;
        await ensureRevision(scope, signal, binding, personaEffect);
      }
    }
  }
  async function readCatalog(scope, persona, signal, personaEffect) {
    const rows = [];
    let expectedTotal = null;
    for (let page = 1; rows.length < MAX_PRODUCTS; page += 1) {
      const offset = (page - 1) * PAGE_SIZE;
      const value = await boundary(scope, signal, () => catalog.listProducts({ scope, persona,
        personaEffect, query: { category: null, search: null, sort: '', page, limit: PAGE_SIZE, offset } }));
      if (!value || !Array.isArray(value.products) || !Number.isSafeInteger(value.total)
          || value.total < 1 || value.total > MAX_PRODUCTS || value.products.length > PAGE_SIZE) {
        throw unavailable('Catalog source exceeds the retrieval bound');
      }
      if (expectedTotal === null) expectedTotal = value.total;
      if (value.total !== expectedTotal || rows.length + value.products.length > expectedTotal) {
        throw unavailable('Catalog changed during retrieval preparation');
      }
      rows.push(...value.products.map(productRow));
      if (rows.length === expectedTotal) break;
      if (!value.products.length) throw unavailable('Catalog source is incomplete');
    }
    if (rows.length !== expectedTotal || new Set(rows.map(row => row.id)).size !== rows.length) {
      throw unavailable('Catalog source is invalid');
    }
    return Object.freeze(rows);
  }
  async function embed(scope, signal, text) {
    return boundary(scope, signal, async () => {
      const before = revisionMode ? embedder.getRuntimeFingerprint()?.fingerprint : null;
      const encoded = embeddingResult(await embedder.embed(text, { signal }));
      if (!revisionMode) return encoded;
      const fingerprint = runtimeFingerprint();
      if (before && before !== fingerprint) throw failure('EMBEDDING_RUNTIME_CHANGED', 'Embedding runtime changed during query inference');
      return Object.freeze({ ...encoded, runtimeFingerprint: fingerprint });
    });
  }
  async function ensureCorpus(scope, signal, binding, products, personaEffect, beforeEffect) {
      let meta = await boundary(scope, signal, () => repository.readMetadata(binding));
      if (meta !== null && !sameBinding(meta, binding)) {
        throw failure('BOUND_RETRIEVAL_MISMATCH', 'Retrieval target binding mismatch');
      }
      if (meta === null) {
        const documents = [];
        let identity = null;
        for (const product of products) {
          const text = sourceText(product);
          const encoded = await embed(scope, signal, text);
          if (identity && (identity.embeddingModel !== encoded.embeddingModel
              || identity.embeddingDimension !== encoded.embeddingDimension)) {
            throw failure('BOUND_RETRIEVAL_MISMATCH', 'Embedding identity changed during provisioning');
          }
          identity ||= encoded;
          documents.push(Object.freeze({ sourceKind: 'product', sourceId: product.id,
            chunkIndex: 0, text, embedding: encoded.embedding }));
        }
        const provisionInput={
          embeddingModel: identity.embeddingModel,
          embeddingDimension: identity.embeddingDimension,
          documents,
        };
        await beforeEffect?.();
        meta=await boundary(scope,signal,()=>personaEffect?personaEffect.provision(repository,binding,provisionInput):repository.provision(binding,provisionInput));
        if (!sameBinding(meta, binding)) {
          throw failure('BOUND_RETRIEVAL_MISMATCH', 'Retrieval target binding mismatch');
        }
      }
      return metadata(meta);
  }
  return Object.freeze({
    async ensureProvisioned(input = {}) {
      const personaEffect=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
      const scope = createLaunchScope(input.scope);
      const value = input.persona;
      if (!value || !Number.isSafeInteger(value.id) || value.id < 1 || value.id > 2147483647
          || !['merchant', 'customer'].includes(value.role)
          || Object.keys(value).length !== 2) throw failure('INVALID_ARGUMENT', 'Invalid retrieval persona');
      const persona = Object.freeze({ id: value.id, role: value.role });
      const binding = await boundary(scope, input.signal, () => catalog.prepareTarget({ scope, persona, personaEffect }));
      await personaEffect?.check(scope);
      const products = await readCatalog(scope, persona, input.signal, personaEffect);
      const result = await ensureCorpus(scope, input.signal, binding, products, personaEffect);
      await personaEffect?.check(scope);
      return result;
    },
    async searchManuals(input = {}) {
      const personaEffect = require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
      if (!personaEffect) throw failure('SHOP_AUTH_INVALID', 'Merchant product authority required');
      if (!revisionMode || typeof revisionRepository.searchManuals !== 'function'
          || typeof catalog.getOwnedMerchantProduct !== 'function') throw unavailable('Manual revision search unavailable');
      const scope = createLaunchScope(input.scope), signal = input.signal;
      manualExact(input.persona, ['id','role']);
      const merchantId = exactProductId(input.persona.id), productId = exactProductId(input.productId);
      if (input.persona.role !== 'merchant' || !manualText(input.query, 4096)
          || (input.beforeEffect !== undefined && typeof input.beforeEffect !== 'function')) {
        throw failure('INVALID_ARGUMENT', 'Manual query is invalid');
      }
      const persona = Object.freeze({ id: merchantId, role: 'merchant' });
      const queryText = input.query, beforeEffect = input.beforeEffect;
      const guard = async () => { await check(scope, signal); await personaEffect.check(scope);
        await beforeEffect?.(); signal?.throwIfAborted(); };
      await guard();
      const selected = await catalog.getOwnedMerchantProduct({ scope, persona, productId, personaEffect });
      await guard();
      if (!selected?.binding || selected.product?.id !== productId
          || selected.product.retailer_id !== merchantId || selected.product.status !== 'active') {
        throw failure('OWNER_MISMATCH', 'Selected merchant product is unavailable');
      }
      const binding = selected.binding;
      // Ingestion normally provisions the shared corpus. An empty manual search
      // uses that same corpus, never a parallel merchant-only embedding index.
      const products = await readCatalog(scope, persona, signal, personaEffect);
      await guard();
      await ensureCorpus(scope, signal, binding, products, personaEffect, guard);
      await guard();
      const encoded = await embed(scope, signal, queryText);
      await guard();
      let found;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        await guard();
        if (runtimeFingerprint() !== encoded.runtimeFingerprint) throw failure('EMBEDDING_RUNTIME_CHANGED', 'Query embedding runtime changed');
        try {
          found = await revisionRepository.searchManuals(binding, { merchantId, productId,
            embedding: encoded.embedding, limit: MANUAL_LIMIT });
          break;
        } catch (error) {
          if (!['EMBEDDING_REINDEX_REQUIRED','EMBEDDING_RUNTIME_MISMATCH'].includes(error.code) || attempt === 1) throw error;
          await guard();
          await ensureRevision(scope, signal, binding, personaEffect, guard);
        }
      }
      await guard();
      if (runtimeFingerprint() !== encoded.runtimeFingerprint
          || found?.revision?.runtimeFingerprint !== encoded.runtimeFingerprint
          || found?.product?.id !== productId) throw unavailable('Manual revision changed');
      const sources = found.sources.map(row => ({ ...row, textBytes: Buffer.byteLength(row.text, 'utf8'),
        textSha256: digestText(row.text) }));
      const result = { product: found.product, query: queryText, limit: MANUAL_LIMIT,
        count: sources.length, hasMore: found.hasMore, revision: found.revision, status: 'complete', sources };
      // Raw teaching text remains intact or is omitted entirely with an explicit
      // oversized status. A digest-only result cannot ground a manual answer.
      if (Buffer.byteLength(JSON.stringify(result), 'utf8') > MANUAL_BYTES) {
        result.status = 'oversized'; result.sources = sources.map(row => ({ ...row, text: null }));
      }
      return validateManualSearchResult(result);
    },
    async similar(input = {}) {
      if (input.captureManualRagSource !== undefined && typeof input.captureManualRagSource !== 'function') throw invalid();
      const personaEffect=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
      if(personaEffect&&!revisionMode)throw failure('EMBEDDING_REVISION_REQUIRED','Candidate authority requires revision retrieval');
      const scope = createLaunchScope(input.scope);
      const persona = exactPersona(input.persona);
      const productId = exactProductId(input.productId);
      const signal = input.signal;
      await personaEffect?.check(scope);
      await check(scope, signal);
      const binding = await boundary(scope, signal,
        () => catalog.prepareTarget({ scope, persona, personaEffect }));
      const selected = await boundary(scope, signal,
        () => catalog.getProduct({ scope, persona, productId, personaEffect }));
      if (!selected?.product) throw failure('NOT_FOUND', 'Product not found');
      const seed = productRow(selected.product);
      if (seed.id !== productId) throw unavailable('Catalog returned the wrong product');
      const products = await readCatalog(scope, persona, signal, personaEffect);
      if (!products.some(row => row.id === productId)) throw unavailable('Selected product is absent from the catalog source');

      const meta = await ensureCorpus(scope, signal, binding, products, personaEffect);
      await personaEffect?.check(scope);
      const query = await embed(scope, signal, sourceText(seed));
      await personaEffect?.check(scope);
      if (!revisionMode && (query.embeddingModel !== meta.embeddingModel
          || query.embeddingDimension !== meta.embeddingDimension)) {
        throw failure('BOUND_RETRIEVAL_MISMATCH', 'Retrieval embedding identity mismatch');
      }
      // Query inference warms the shared attested pipeline before any head read.
      // Production always supplies revision dependencies; the legacy path is
      // retained only for explicitly constructed older qualification fixtures.
      const searched = revisionMode
        ? await revisionSearch(scope, signal, binding, query, query.runtimeFingerprint, personaEffect, !!input.captureManualRagSource)
        : await boundary(scope, signal, () => repository.search(binding, {
          embeddingModel: query.embeddingModel, embedding: query.embedding, limit: RESULT_LIMIT,
        }));
      const privateSearch = !Array.isArray(searched) && searched && Array.isArray(searched.rows);
      const retrieved = contextRows(privateSearch ? searched.rows : searched);
      if (input.captureManualRagSource) input.captureManualRagSource({
        target: JSON.parse(JSON.stringify(binding)),
        lineage: privateSearch ? searched.lineage : { eligible: false, reason: 'missing_original' },
      });
      const results = applyRetrievalBias(keywordFallback(seed, products), retrieved, products, seed.id)
        .map(productRow);
      await check(scope, signal);
      await personaEffect?.check(scope);
      return Object.freeze({
        seed: Object.freeze({ id: seed.id, name: seed.name }),
        results: Object.freeze(results), count: results.length,
        mode: retrievalMode(retrieved), retrieved_context: retrieved,
      });
    },
  });
}

module.exports = { createSecureShopBoundProductRetrieval, validateManualSearchResult };
