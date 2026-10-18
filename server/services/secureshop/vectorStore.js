'use strict';

/**
 * SecureShop v2 PostgreSQL vector store.
 *
 * Embeddings prefer configured local providers and retain the deterministic
 * hash fallback used by controlled tests.
 *
 * @intentional-vulnerability llm04-rag-poisoning
 * Anything added lands in retrievals without a content filter.
 */

const http = require('node:http');
const https = require('node:https');

const OLLAMA_URL = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
const EMBED_MODEL = process.env.SS_EMBED_MODEL || 'nomic-embed-text';
const OLLAMA_TIMEOUT_MS = Number(process.env.SS_EMBED_TIMEOUT_MS || 1200);
const EMBED_PROVIDER = (process.env.SS_EMBED_PROVIDER || 'auto').toLowerCase();
const LMSTUDIO_URL = process.env.LMSTUDIO_BASE_URL || 'http://localhost:1234/v1';
const LMSTUDIO_EMBED_MODEL = process.env.SS_LMSTUDIO_EMBED_MODEL || EMBED_MODEL;
const VALID_CORPUS = new Set(['reviews', 'manuals', 'policies', 'products']);

class VectorStore {
  constructor({ corpus, dim = 768 } = {}) {
    if (!VALID_CORPUS.has(corpus)) throw new Error(`unknown corpus: ${corpus}`);
    this.corpus = corpus;
    this.dim = dim;
    this._ollamaAvailable = null;
    this._lmStudioAvailable = null;
    this._repository = require('../../database/postgres/secureshopVectorRepository')
      .getSecureShopVectorRepository();
  }

  async _isOllamaReachable() {
    if (this._ollamaAvailable !== null) return this._ollamaAvailable;
    if (process.env.SS_DISABLE_OLLAMA === 'true') return (this._ollamaAvailable = false);
    this._ollamaAvailable = await new Promise((resolve) => {
      try {
        const url = new URL('/', OLLAMA_URL);
        const req = http.get({ hostname: url.hostname, port: url.port, path: '/', timeout: 400 }, (res) => {
          resolve(res.statusCode < 500);
          res.resume();
        });
        req.on('error', () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
      } catch { resolve(false); }
    });
    return this._ollamaAvailable;
  }

  async _isLMStudioReachable() {
    if (this._lmStudioAvailable !== null) return this._lmStudioAvailable;
    this._lmStudioAvailable = await new Promise((resolve) => {
      try {
        const url = new URL('/models', LMSTUDIO_URL);
        const client = url.protocol === 'https:' ? https : http;
        const req = client.get(
          { hostname: url.hostname, port: url.port, path: url.pathname + url.search, timeout: 400 },
          (res) => { resolve(res.statusCode < 500); res.resume(); },
        );
        req.on('error', () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
      } catch { resolve(false); }
    });
    return this._lmStudioAvailable;
  }

  async embed(text) {
    return (await this.embedWithIdentity(text)).vector;
  }

  async embedWithIdentity(text) {
    const shape = (value) => {
      if (!Array.isArray(value) || value.length !== this.dim
          || value.some((number) => typeof number !== 'number' || !Number.isFinite(number))) return null;
      return _l2normalize(Float32Array.from(value));
    };
    const tryOllama = async () => {
      if (!(await this._isOllamaReachable())) return null;
      try { return shape(await _embedViaOllama(text)); } catch { return null; }
    };
    const tryLMStudio = async () => {
      if (!(await this._isLMStudioReachable())) return null;
      try { return shape(await _embedViaLMStudio(text)); } catch { return null; }
    };

    let vector = null;
    let provider = null;
    if (EMBED_PROVIDER === 'lmstudio') {
      vector = await tryLMStudio();
      provider = vector ? 'lmstudio' : null;
    } else if (EMBED_PROVIDER === 'ollama') {
      vector = await tryOllama();
      provider = vector ? 'ollama' : null;
    } else if (EMBED_PROVIDER !== 'hash') {
      vector = await tryOllama();
      provider = vector ? 'ollama' : null;
      if (!vector) {
        vector = await tryLMStudio();
        provider = vector ? 'lmstudio' : null;
      }
    }

    return {
      vector: vector || _hashEmbedding(text, this.dim),
      identity: {
        provider: provider || 'hash',
        model: provider === 'ollama' ? EMBED_MODEL
          : provider === 'lmstudio' ? LMSTUDIO_EMBED_MODEL : 'dvaia-bow-hash-v1',
        algorithm: provider ? 'float32-l2-v1' : 'dvaia-bow-hash-v1',
        dimension: this.dim,
      },
    };
  }

  async add({ sourceKind, sourceId, chunkIndex = 0, text }) {
    if (!text || typeof text !== 'string') throw new Error('add: text required');
    const embedded = await this.embedWithIdentity(text);
    return this._repository.add({
      corpus: this.corpus,
      dimension: this.dim,
      embedderModel: embedded.identity.model,
      embeddingIdentity: embedded.identity,
      sourceKind,
      sourceId: Number(sourceId) || 0,
      chunkIndex: Number(chunkIndex) || 0,
      text: String(text),
      embedding: embedded.vector,
    });
  }

  /**
   * @intentional-vulnerability llm08-embedding-inversion
   * @teaches OWASP-LLM:LLM08
   * @location server/services/secureshop/vectorStore.js
   * Returns indexed plaintext without document authorization.
   */
  async search(text, k = 5) {
    const embedded = await this.embedWithIdentity(text);
    const rows = await this._repository.listActive(this.corpus, this.dim, embedded.identity);
    return rows.map((row) => ({
      sourceKind: row.sourceKind,
      sourceId: row.sourceId,
      chunkIndex: row.chunkIndex,
      text: row.text,
      score: _cosineArr(embedded.vector, row.embedding),
    })).sort((a, b) => b.score - a.score).slice(0, Math.max(0, Number(k) || 0));
  }

  async rebuild(sourceItems) {
    let documents = null;
    if (sourceItems === undefined && this.corpus !== 'manuals') {
      const commerce = require('../../database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
      if (this.corpus === 'reviews') {
        sourceItems = (await commerce.listReviews()).filter((row) => row.body != null)
          .map((row) => ({ sourceKind: 'review', sourceId: row.id, chunkIndex: 0, text: row.body }));
      } else if (this.corpus === 'policies') {
        sourceItems = (await commerce.listPolicies()).filter((row) => row.markdown_source != null)
          .map((row) => ({ sourceKind: 'policy', sourceId: row.id, chunkIndex: 0, text: row.markdown_source }));
      } else if (this.corpus === 'products') {
        sourceItems = (await commerce.listProducts()).filter((row) => row.description != null)
          .map((row) => ({
            sourceKind: 'product_desc',
            sourceId: row.id,
            chunkIndex: 0,
            text: `${row.name}\n${row.description || ''}`,
          }));
      }
    }
    if (sourceItems !== undefined) {
      if (!Array.isArray(sourceItems)) throw new TypeError('rebuild source items must be an array');
      documents = [];
      for (const item of sourceItems) {
        const embedded = await this.embedWithIdentity(item.text);
        documents.push({ ...item, embedding: embedded.vector, embeddingIdentity: embedded.identity });
      }
    }
    return this._repository.rebuild({
      corpus: this.corpus,
      dimension: this.dim,
      embedderModel: documents?.[0]?.embeddingIdentity.model,
      embeddingIdentity: documents?.[0]?.embeddingIdentity,
      documents,
    });
  }

  async count() {
    return (await this._repository.count(this.corpus)).count;
  }
}

function _embedViaOllama(text) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model: EMBED_MODEL, prompt: text });
    const url = new URL('/api/embeddings', OLLAMA_URL);
    const req = http.request({
      method: 'POST', hostname: url.hostname, port: url.port, path: url.pathname,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      let chunks = '';
      res.on('data', (chunk) => chunks += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(chunks || '{}');
          if (Array.isArray(parsed.embedding)) resolve(parsed.embedding);
          else reject(new Error('no embedding'));
        } catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.setTimeout(OLLAMA_TIMEOUT_MS, () => req.destroy(new Error('timeout')));
    req.write(body);
    req.end();
  });
}

function _embedViaLMStudio(text) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model: LMSTUDIO_EMBED_MODEL, input: text });
    const url = new URL('/embeddings', LMSTUDIO_URL);
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request({
      method: 'POST', hostname: url.hostname, port: url.port, path: url.pathname + url.search,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      let chunks = '';
      res.on('data', (chunk) => chunks += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(chunks || '{}');
          const embedding = parsed.data?.[0]?.embedding;
          if (Array.isArray(embedding)) resolve(embedding);
          else reject(new Error('no embedding'));
        } catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.setTimeout(OLLAMA_TIMEOUT_MS, () => req.destroy(new Error('timeout')));
    req.write(body);
    req.end();
  });
}

function _hashEmbedding(text, dim = 768) {
  const out = new Float32Array(dim);
  const tokens = String(text || '').toLowerCase().split(/\W+/).filter(Boolean);
  for (const token of tokens) {
    const index = _fnv1a(token) % dim;
    out[index] += _fnv1a(`s:${token}`) % 2 === 0 ? 1 : -1;
  }
  return _l2normalize(out);
}

function _fnv1a(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function _l2normalize(vector) {
  let sum = 0;
  for (let index = 0; index < vector.length; index += 1) sum += vector[index] * vector[index];
  const norm = Math.sqrt(sum) || 1;
  for (let index = 0; index < vector.length; index += 1) vector[index] /= norm;
  return vector;
}

function _cosineArr(left, right) {
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    dot += left[index] * right[index];
    leftNorm += left[index] * left[index];
    rightNorm += right[index] * right[index];
  }
  return dot / (Math.sqrt(leftNorm) * Math.sqrt(rightNorm) || 1);
}

function chunkText(text, maxTokens = 500) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const chunks = [];
  for (let index = 0; index < words.length; index += maxTokens) {
    chunks.push(words.slice(index, index + maxTokens).join(' '));
  }
  return chunks;
}

module.exports = { VectorStore, chunkText, _hashEmbedding, _cosineArr };
