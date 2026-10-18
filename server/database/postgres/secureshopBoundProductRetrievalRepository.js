'use strict';

const { withTransaction } = require('./index');
const { copySceneBinding, executionScope, assertSceneGrant, withSceneLease } = require('../../services/secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SOURCE_KINDS = new Set(['product', 'listing', 'review', 'manual']);
const TARGET_FIELDS = Object.freeze([
  ['target_id', 'targetId'],
  ['launch_id', 'launchId'],
  ['scenario_id', 'scenarioId'],
  ['generation', 'generation'],
  ['original_platform_owner_id', 'platformOwnerId'],
  ['original_platform_session_id', 'platformSessionId'],
]);

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}
function isPlain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function uuid(value, name) {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value.toLowerCase();
}
function integer(value, name, min = 1, max = 2147483647) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value;
}
function text(value, name, maxBytes) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value, 'utf8') > maxBytes) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value;
}
function scope(value) {
  if (!isPlain(value)) throw failure('INVALID_ARGUMENT', 'target binding is invalid');
  return copySceneBinding(value, {
    targetId: uuid(value.targetId, 'targetId'),
    launchId: uuid(value.launchId, 'launchId'),
    scenarioId: uuid(value.scenarioId, 'scenarioId'),
    generation: integer(value.generation, 'generation', 1, Number.MAX_SAFE_INTEGER),
    platformOwnerId: integer(value.platformOwnerId, 'platformOwnerId'),
    platformSessionId: integer(value.platformSessionId, 'platformSessionId'),
  });
}
function scopeValues(value) {
  return [value.targetId, value.launchId, value.scenarioId, value.generation,
    value.platformOwnerId, value.platformSessionId];
}
function targetWhere(alias = 't') {
  return `${alias}.target_id=$1 AND ${alias}.launch_id=$2 AND ${alias}.scenario_id=$3
    AND ${alias}.generation=$4 AND ${alias}.original_platform_owner_id=$5
    AND ${alias}.original_platform_session_id=$6`;
}
function vector(value, name, dimension) {
  if (!Array.isArray(value) || value.length !== dimension
      || value.some(number => typeof number !== 'number' || !Number.isFinite(number))) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value.slice();
}
function documents(value, dimension) {
  if (!Array.isArray(value) || value.length > 4096) {
    throw failure('INVALID_ARGUMENT', 'documents are invalid');
  }
  const normalized = value.map(document => {
    if (!isPlain(document)) throw failure('INVALID_ARGUMENT', 'document is invalid');
    const sourceKind = text(document.sourceKind, 'sourceKind', 32);
    if (!SOURCE_KINDS.has(sourceKind)) throw failure('INVALID_ARGUMENT', 'sourceKind is invalid');
    return Object.freeze({
      sourceKind,
      sourceId: integer(document.sourceId, 'sourceId', 1, Number.MAX_SAFE_INTEGER),
      chunkIndex: integer(document.chunkIndex ?? 0, 'chunkIndex', 0, 128),
      text: text(document.text, 'text', 65536),
      embedding: Object.freeze(vector(document.embedding, 'embedding', dimension)),
    });
  });
  const keys = normalized.map(row => `${row.sourceKind}:${row.sourceId}:${row.chunkIndex}`);
  if (new Set(keys).size !== keys.length) throw failure('INVALID_ARGUMENT', 'duplicate document');
  return Object.freeze(normalized);
}
function documentRow(row) {
  if (!row || !SOURCE_KINDS.has(row.source_kind) || !Number.isSafeInteger(Number(row.source_id))
      || !Number.isSafeInteger(Number(row.chunk_index)) || typeof row.body !== 'string'
      || !Buffer.isBuffer(row.source_sha256) || row.source_sha256.length !== 32
      || !Array.isArray(row.embedding) || row.embedding.some(number => !Number.isFinite(Number(number)))) {
    throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval document is invalid');
  }
  return Object.freeze({
    sourceKind: row.source_kind,
    sourceId: Number(row.source_id),
    chunkIndex: Number(row.chunk_index),
    text: row.body,
    embedding: Object.freeze(row.embedding.map(Number)),
    sourceSha256: row.source_sha256.toString('hex'),
  });
}
function matchesReceiptTuple(row, binding, operationId) {
  if (!row || row.operation_id !== operationId || row.receipt_valid !== true) return false;
  return TARGET_FIELDS.every(([column, key]) => {
    const actual = ['generation', 'original_platform_owner_id', 'original_platform_session_id'].includes(column)
      ? Number(row[column]) : row[column];
    return actual === binding[key];
  });
}
function cleanupReceipt(row, binding, operationId) {
  if (!matchesReceiptTuple(row, binding, operationId)
      || !Number.isSafeInteger(Number(row.deleted_document_count))
      || Number(row.deleted_document_count) < 0 || Number(row.deleted_document_count) > 4096
      || !Buffer.isBuffer(row.receipt_sha256) || row.receipt_sha256.length !== 32) {
    throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval cleanup receipt does not match');
  }
  const completedAt = new Date(row.completed_at);
  if (!Number.isFinite(completedAt.getTime())) {
    throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval cleanup receipt is invalid');
  }
  return Object.freeze({
    operationId,
    ...binding,
    deletedDocumentCount: Number(row.deleted_document_count),
    receiptSha256: row.receipt_sha256.toString('hex'),
    completedAt: completedAt.toISOString(),
  });
}

const RECEIPT_SELECT = `SELECT r.*,
  r.receipt_sha256 = secureshop_review.product_retrieval_cleanup_digest(
    r.operation_id,r.target_id,r.launch_id,r.scenario_id,r.generation,
    r.original_platform_owner_id,r.original_platform_session_id,r.deleted_document_count
  ) AS receipt_valid
  FROM secureshop_review.product_target_retrieval_cleanup_receipts r
  WHERE r.operation_id=$1 AND r.target_id=$2 AND r.launch_id=$3 AND r.scenario_id=$4
    AND r.generation=$5 AND r.original_platform_owner_id=$6
    AND r.original_platform_session_id=$7`;

function createSecureShopBoundProductRetrievalRepository(pool, { checkCurrent, checkCleanup } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
      || typeof checkCurrent !== 'function' || typeof checkCleanup !== 'function') {
    throw failure('BOUND_RETRIEVAL_UNAVAILABLE', 'retrieval authority unavailable');
  }
  function online(binding, work) {
    return withSceneLease(binding, () => withTransaction(pool, async client => {
      await assertSceneGrant(client, binding);
      const result = await work(client);
      await assertSceneGrant(client, binding);
      await checkCurrent(executionScope(binding));
      return result;
    }));
  }
  async function recordSceneEffect(client, binding, kind, operationId) {
    if (!binding.scene) return;
    await client.query(`SELECT secureshop_review.record_scene_retrieval_embedding_effect($1,$2,$3,$4)`,
      [kind, operationId, binding.targetId, binding.scene.grantId]);
  }

  async function requireActive(client, binding, lock = 'FOR SHARE') {
    const row = (await client.query(`SELECT t.*,c.embedding_model,c.embedding_dimension,
      c.lifecycle AS retrieval_lifecycle
      FROM secureshop_review.product_targets t
      JOIN secureshop_review.product_target_retrieval_config c USING(target_id)
      WHERE ${targetWhere('t')} ${lock} OF t`, scopeValues(binding))).rows[0];
    if (!row || row.lifecycle !== 'active' || row.retrieval_lifecycle !== 'active') {
      throw failure('BOUND_RETRIEVAL_UNAVAILABLE', 'retrieval target unavailable');
    }
    return row;
  }

  async function requireRetired(client, binding, lock = 'FOR UPDATE') {
    const target = (await client.query(`SELECT t.lifecycle
      FROM secureshop_review.product_targets t
      WHERE ${targetWhere('t')} ${lock} OF t`, scopeValues(binding))).rows[0];
    if (!target || target.lifecycle !== 'retired') {
      throw failure('PRODUCT_TARGET_UNAVAILABLE', 'canonical product target must be retired');
    }
    const state = (await client.query(`SELECT c.lifecycle AS retrieval_lifecycle,
      (SELECT count(*)::integer FROM secureshop_review.product_target_retrieval_documents d
        WHERE d.target_id=c.target_id) AS document_count
      FROM secureshop_review.product_target_retrieval_config c
      WHERE c.target_id=$1`, [binding.targetId])).rows[0];
    return state || Object.freeze({ retrieval_lifecycle: null, document_count: 0 });
  }

  async function readVerifiedReceipt(client, binding, operationId) {
    const row = (await client.query(RECEIPT_SELECT,
      [operationId, ...scopeValues(binding)])).rows[0];
    if (!row) {
      throw failure('BOUND_RETRIEVAL_RECEIPT_UNAVAILABLE', 'retrieval cleanup receipt unavailable');
    }
    return cleanupReceipt(row, binding, operationId);
  }

  async function readMetadata(value) {
    const binding = scope(value);
    await checkCurrent(executionScope(binding));
    return online(binding, async client => {
    const row = (await client.query(`SELECT c.embedding_model,c.embedding_dimension,
      (SELECT count(*)::integer FROM secureshop_review.product_target_retrieval_documents d
        WHERE d.target_id=t.target_id AND d.generation=t.generation) AS document_count
      FROM secureshop_review.product_targets t
      JOIN secureshop_review.product_target_retrieval_config c USING(target_id)
      WHERE ${targetWhere('t')} AND t.lifecycle='active' AND c.lifecycle='active'`,
    scopeValues(binding))).rows[0];
    if (!row) return null;
    return Object.freeze({ ...binding, embeddingModel: row.embedding_model,
      embeddingDimension: Number(row.embedding_dimension), documentCount: Number(row.document_count) });
    });
  }

  async function provision(value, input, {effectTimeoutMs} = {}) {
    const binding = scope(value);
    if (!isPlain(input)) throw failure('INVALID_ARGUMENT', 'provision is invalid');
    const embeddingModel = text(input.embeddingModel, 'embeddingModel', 256);
    const embeddingDimension = integer(input.embeddingDimension, 'embeddingDimension', 1, 4096);
    const rows = documents(input.documents, embeddingDimension);
    await checkCurrent(executionScope(binding));
    if(effectTimeoutMs!==undefined&&(!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000))throw new TypeError('Invalid effect timeout');
  return online(binding, async client => {
   if(effectTimeoutMs!==undefined)await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(effectTimeoutMs)]);
      const parent = (await client.query(`SELECT t.* FROM secureshop_review.product_targets t
        WHERE ${targetWhere('t')} FOR UPDATE`, scopeValues(binding))).rows[0];
      if (!parent || parent.lifecycle !== 'active') {
        throw failure('PRODUCT_TARGET_UNAVAILABLE', 'canonical product target unavailable');
      }
      const config = (await client.query(`SELECT *
        FROM secureshop_review.product_target_retrieval_config
        WHERE target_id=$1`, [binding.targetId])).rows[0];
      if (config && (config.embedding_model !== embeddingModel
          || Number(config.embedding_dimension) !== embeddingDimension
          || config.lifecycle !== 'active')) {
        throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval config mismatch');
      }
      await client.query(`SELECT secureshop_review.provision_product_retrieval(
        $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, [
        ...scopeValues(binding), embeddingModel, embeddingDimension, JSON.stringify(rows),
      ]);
      if (!config) await recordSceneEffect(client, binding, 'retrieval_provision', binding.targetId);
      const count = Number((await client.query(`SELECT count(*)::integer AS count
        FROM secureshop_review.product_target_retrieval_documents
        WHERE target_id=$1 AND generation=$2`, [binding.targetId, binding.generation])).rows[0].count);
      return Object.freeze({ ...binding, embeddingModel, embeddingDimension, documentCount: count });
    });
  }

  async function replaceDocuments(value, input) {
    const binding = scope(value);
    if (!isPlain(input)) throw failure('INVALID_ARGUMENT', 'replacement is invalid');
    const embeddingModel = text(input.embeddingModel, 'embeddingModel', 256);
    const embeddingDimension = integer(input.embeddingDimension, 'embeddingDimension', 1, 4096);
    const rows = documents(input.documents, embeddingDimension);
    const operationId = uuid(input.operationId, 'operationId');
    await checkCurrent(executionScope(binding));
    return online(binding, async client => {
      const current = await requireActive(client, binding, 'FOR UPDATE');
      if (current.embedding_model !== embeddingModel
          || Number(current.embedding_dimension) !== embeddingDimension) {
        throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval config mismatch');
      }
      const result = (await client.query(`SELECT *
        FROM secureshop_review.replace_product_retrieval($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
      [...scopeValues(binding), operationId, JSON.stringify(rows)])).rows[0];
      if (result.replayed !== true) await recordSceneEffect(client, binding, 'retrieval_ingest', operationId);
      return Object.freeze({ ...binding, operationId, embeddingModel, embeddingDimension,
        replacedDocumentCount: Number(result.replaced_count),
        documentCount: Number(result.document_count), replayed: result.replayed });
    });
  }

  async function search(value, input) {
    const binding = scope(value);
    if (!isPlain(input)) throw failure('INVALID_ARGUMENT', 'search is invalid');
    const embeddingModel = text(input.embeddingModel, 'embeddingModel', 256);
    const limit = integer(input.limit ?? 5, 'limit', 1, 20);
    await checkCurrent(executionScope(binding));
    return online(binding, async client => {
    const metadata = (await client.query(`SELECT c.embedding_model,c.embedding_dimension
      FROM secureshop_review.product_targets t
      JOIN secureshop_review.product_target_retrieval_config c USING(target_id)
      WHERE ${targetWhere('t')} AND t.lifecycle='active' AND c.lifecycle='active'`,
    scopeValues(binding))).rows[0];
    if (!metadata) throw failure('BOUND_RETRIEVAL_UNAVAILABLE', 'retrieval target unavailable');
    if (metadata.embedding_model !== embeddingModel) {
      throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval model mismatch');
    }
    const query = vector(input.embedding, 'embedding', Number(metadata.embedding_dimension));
    const norm = Math.sqrt(query.reduce((sum, number) => sum + number * number, 0));
    if (!(norm > 0)) throw failure('INVALID_ARGUMENT', 'embedding must be nonzero');
    const result = await client.query(`SELECT d.*
      FROM secureshop_review.product_target_retrieval_documents d
      WHERE d.target_id=$1 AND d.generation=$2
      ORDER BY d.source_kind,d.source_id,d.chunk_index LIMIT 4096`,
    [binding.targetId, binding.generation]);
    const ranked = result.rows.map(row => {
      const document = documentRow(row);
      if (document.embedding.length !== query.length) {
        throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval document dimension mismatch');
      }
      const documentNorm = Math.sqrt(document.embedding.reduce(
        (sum, number) => sum + number * number, 0));
      const score = documentNorm > 0 ? document.embedding.reduce(
        (sum, number, index) => sum + number * query[index], 0) / (documentNorm * norm) : 0;
      return Object.freeze({ ...document, score });
    }).sort((left, right) => right.score - left.score).slice(0, limit);
    return Object.freeze(ranked);
    });
  }

  async function retire(value, input = {}) {
    const binding = scope(value);
    const operationId = uuid(input.operationId, 'operationId');
    const authority = Object.freeze({ ...binding, operationId });
    await checkCleanup(authority);
    return withTransaction(pool, async client => {
      const state = await requireRetired(client, binding, 'FOR UPDATE');
      const conflicts = (await client.query(`SELECT operation_id,target_id
        FROM secureshop_review.product_target_retrieval_cleanup_receipts
        WHERE target_id=$1`, [binding.targetId])).rows;
      if (conflicts.length) {
        if (conflicts.length !== 1 || conflicts[0].operation_id !== operationId
            || conflicts[0].target_id !== binding.targetId) {
          throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval cleanup replay mismatch');
        }
      } else {
        if (state.retrieval_lifecycle !== 'active') {
          throw failure('BOUND_RETRIEVAL_UNAVAILABLE', 'retrieval config unavailable');
        }
        await client.query(`SELECT * FROM secureshop_review.retire_product_target_retrieval(
          $1,$2,$3,$4,$5,$6,$7)`, [operationId, ...scopeValues(binding)]);
      }
      const receipt = await readVerifiedReceipt(client, binding, operationId);
      await checkCleanup(authority);
      return receipt;
    });
  }

  async function readCleanupReceipt(value, input = {}) {
    const binding = scope(value);
    const operationId = uuid(input.operationId, 'operationId');
    const authority = Object.freeze({ ...binding, operationId });
    await checkCleanup(authority);
    return withTransaction(pool, async client => {
      const state = await requireRetired(client, binding, 'FOR SHARE');
      if (state.retrieval_lifecycle !== 'retired' || Number(state.document_count) !== 0) {
        throw failure('BOUND_RETRIEVAL_MISMATCH', 'retrieval cleanup state does not match');
      }
      const receipt = await readVerifiedReceipt(client, binding, operationId);
      await checkCleanup(authority);
      return receipt;
    });
  }

  return Object.freeze({ provision, readMetadata, open: readMetadata, replaceDocuments,
    search, retire, readCleanupReceipt });
}

module.exports = { createSecureShopBoundProductRetrievalRepository };
