'use strict';

const { withTransaction } = require('./index');

const CORPORA = new Set(['reviews', 'manuals', 'policies', 'products']);

function corpus(value) {
  if (!CORPORA.has(value)) throw new Error(`unknown corpus: ${value}`);
  return value;
}

function dimension(value) {
  const result = Number(value);
  if (!Number.isInteger(result) || result < 1 || result > 4096) throw new Error('invalid embedding dimension');
  return result;
}

function embedding(value, expectedDimension) {
  const result = Array.from(value || [], Number);
  if (result.length !== expectedDimension || result.some((number) => !Number.isFinite(number))) {
    throw new Error('invalid embedding');
  }
  return result;
}

function identity(value, dim) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'algorithm,dimension,model,provider'
      || value.dimension !== dim
      || ['provider','model','algorithm'].some(k => typeof value[k] !== 'string' || !value[k].length || value[k].length > (k === 'model' ? 500 : 200))) {
    throw Object.assign(new Error('Embedding provenance required'), {code:'EMBEDDING_REBUILD_REQUIRED'});
  }
  return {provider:value.provider,model:value.model,algorithm:value.algorithm,dimension:dim};
}
function compatible(state, expected) {
  const actual = identity(state.embedding_identity, state.dimension);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw Object.assign(new Error('Embedding identity mismatch; explicit rebuild required'), {code:'EMBEDDING_REBUILD_REQUIRED'});
}

function source(item) {
  const sourceKind = String(item.sourceKind || '');
  const sourceId = Number(item.sourceId);
  const chunkIndex = Number(item.chunkIndex || 0);
  if (!sourceKind || sourceKind.length > 80) throw new Error('invalid vector source kind');
  if (!Number.isSafeInteger(sourceId)) throw new Error('invalid vector source id');
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0) throw new Error('invalid vector chunk index');
  if (typeof item.text !== 'string' || !item.text.length) throw new Error('vector text required');
  return { sourceKind, sourceId, chunkIndex, text: item.text };
}

function mapDocument(row) {
  return {
    id: Number(row.id),
    sourceKind: row.source_kind,
    sourceId: Number(row.source_id),
    chunkIndex: row.chunk_index,
    text: row.text,
    embedding: row.embedding.map(Number),
  };
}

function createSecureShopVectorRepository(pool) {
  if (!pool?.query) throw new TypeError('SecureShop agents pool required');

  async function lockCorpus(client, name, dim, model) {
    await client.query(
      `INSERT INTO secureshop_agents.vector_corpora(corpus,dimension,embedder_model)
       VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
      [name, dim, model]
    );
    const row = (await client.query(
      'SELECT * FROM secureshop_agents.vector_corpora WHERE corpus=$1 FOR UPDATE', [name]
    )).rows[0];
    
    return row;
  }

  return {
    async add(input) {
      const name = corpus(input.corpus);
      const dim = dimension(input.dimension);
      const item = source(input);
      const vector = embedding(input.embedding, dim);
      const provenance = identity(input.embeddingIdentity, dim);
      return withTransaction(pool, async (client) => {
        const state = await lockCorpus(client, name, dim, provenance.model);
        if (state.document_count > 0) compatible(state, provenance);
        await client.query('UPDATE secureshop_agents.vector_corpora SET dimension=$2,embedding_identity=$3::jsonb WHERE corpus=$1', [name,dim,JSON.stringify(provenance)]);
        const row = (await client.query(
          `INSERT INTO secureshop_agents.vector_documents
             (corpus,generation,source_kind,source_id,chunk_index,text,embedding)
           VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
          [name, state.active_generation, item.sourceKind, item.sourceId, item.chunkIndex, item.text, vector]
        )).rows[0];
        await client.query(
          `UPDATE secureshop_agents.vector_corpora SET revision=revision+1,
             document_count=document_count+1,embedder_model=$2,updated_at=now() WHERE corpus=$1`,
          [name, provenance.model]
        );
        return Number(row.id);
      });
    },

    async listActive(name, expectedDimension, expectedIdentity) {
      name = corpus(name);
      const result = await pool.query(
        `SELECT c.dimension,c.embedding_identity,c.document_count,d.id,d.source_kind,d.source_id,d.chunk_index,d.text,d.embedding
         FROM secureshop_agents.vector_corpora c
         LEFT JOIN secureshop_agents.vector_documents d
           ON d.corpus=c.corpus AND d.generation=c.active_generation
         WHERE c.corpus=$1 ORDER BY d.id`, [name]
      );
      if (!result.rows.length) return [];
      if (result.rows[0].document_count > 0) compatible(result.rows[0], identity(expectedIdentity, dimension(expectedDimension)));
      return result.rows.filter((row) => row.id !== null).map(mapDocument);
    },

    async count(name) {
      name = corpus(name);
      const row = (await pool.query(
        'SELECT document_count,revision,active_generation FROM secureshop_agents.vector_corpora WHERE corpus=$1',
        [name]
      )).rows[0];
      return row ? {
        count: row.document_count,
        revision: Number(row.revision),
        generation: Number(row.active_generation),
      } : { count: 0, revision: 0, generation: 0 };
    },

    async rebuild({ corpus: rawCorpus, dimension: rawDimension, embedderModel, embeddingIdentity, documents = null }) {
      const name = corpus(rawCorpus);
      const dim = dimension(rawDimension);
      const prepared = documents === null ? null : documents.map((item) => ({
        ...source(item), embedding: embedding(item.embedding, dim), embeddingIdentity: identity(item.embeddingIdentity, dim),
      }));
      return withTransaction(pool, async (client) => {
        const state = await lockCorpus(client, name, dim, embedderModel || 'unverified');
        const provenance = prepared === null ? identity(state.embedding_identity, state.dimension) : (prepared.length ? identity(embeddingIdentity,dim) : null);
        if (prepared === null && state.dimension !== dim) throw Object.assign(new Error('Embedding dimension mismatch'),{code:'EMBEDDING_REBUILD_REQUIRED'});
        if (prepared) for (const item of prepared) compatible({embedding_identity:item.embeddingIdentity,dimension:dim}, provenance);
        const active = Number(state.active_generation);
        const next = active + 1;
        const rows = prepared === null
          ? (await client.query(
            `SELECT source_kind AS "sourceKind",source_id AS "sourceId",chunk_index AS "chunkIndex",text,embedding
             FROM secureshop_agents.vector_documents
             WHERE corpus=$1 AND generation=$2 ORDER BY id`, [name, active]
          )).rows
          : prepared;
        for (const item of rows) {
          await client.query(
            `INSERT INTO secureshop_agents.vector_documents
               (corpus,generation,source_kind,source_id,chunk_index,text,embedding)
             VALUES($1,$2,$3,$4,$5,$6,$7)`,
            [name, next, item.sourceKind, item.sourceId, item.chunkIndex, item.text, item.embedding]
          );
        }
        await client.query(
          `UPDATE secureshop_agents.vector_corpora SET active_generation=$2,revision=revision+1,
             document_count=$3,embedder_model=$4,dimension=$5,embedding_identity=$6::jsonb,updated_at=now() WHERE corpus=$1`,
          [name, next, rows.length, provenance?.model || 'unverified', dim, provenance ? JSON.stringify(provenance) : null]
        );
        await client.query(
          'DELETE FROM secureshop_agents.vector_documents WHERE corpus=$1 AND generation<>$2',
          [name, next]
        );
        return { corpus: name, count: rows.length, generation: next };
      });
    },
  };
}

let singleton;
function getSecureShopVectorRepository() {
  return singleton ||= createSecureShopVectorRepository(require('./secureshopPools').getAgentsPool());
}

module.exports = { createSecureShopVectorRepository, getSecureShopVectorRepository };
