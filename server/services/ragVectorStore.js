/**
 * RAG Vector Store — in-memory document chunks + embeddings (Node.js only, no Python).
 * Uses @huggingface/transformers (Xenova/all-MiniLM-L6-v2) for embeddings.
 * Singleton: one instance per process.
 */

if (typeof globalThis.self === 'undefined') {
  globalThis.self = globalThis;
}

const CHUNK_SIZE = 500;
const CHUNK_OVERLAP = 50;
const MIN_CHUNK_LENGTH = 20;

class RagVectorStore {
  constructor({ loadTransformers, runtimeFingerprinter } = {}) {
    this.defaultTransformerRuntime = !loadTransformers;
    this.loadTransformers = loadTransformers || (() => import('@huggingface/transformers'));
    // Injected providers cannot inherit production provenance implicitly.
    this.runtimeFingerprinter = runtimeFingerprinter || (!loadTransformers
      ? require('./embeddingRuntimeFingerprint').createEmbeddingRuntimeFingerprinter() : null);
    this.runtimeFingerprint = null;
    this.disposalFailure = null;
    this.initialization = null;
    this.retryInitialization = null;
    this.resourceFamilies = new Map();
    this.sessions = new Map(); // key → [{ text, embedding, chunkIndex }]
    this.sessionMetadata = new Map(); // key → { filename }
    this.lastSessionByUser = new Map(); // userKey → { sessionId, filename, chunksStored } — so document stays "loaded" after refresh
    this.embedder = null;
    this.modelReady = false;
  }

  /**
   * Load Xenova/all-MiniLM-L6-v2 feature-extraction pipeline. Call once at server startup.
   */
  async init() {
    if (this.modelReady) return;
    if (this.initialization) return this.initialization;
    this.initialization = this.loadModel();
    try { return await this.initialization; }
    finally { this.initialization = null; }
  }

  // Pipeline loading is not cancellable. Keep one underlying load until it
  // settles; a timeout race must never start overlapping model allocations.
  async initWithRetry({ attempts = 3, delayMs = 5000, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
    if (!Number.isInteger(attempts) || attempts < 1 || attempts > 3 ||
        !Number.isFinite(delayMs) || delayMs < 0 || delayMs > 60000) throw new TypeError('Invalid embedding retry bounds');
    if (this.modelReady) return;
    if (this.retryInitialization) return this.retryInitialization;
    this.retryInitialization = (async () => {
      for (let attempt = 1; attempt <= attempts; attempt++) {
        try { return await this.init(); }
        catch (error) {
          if (attempt === attempts) throw error;
          await delay(delayMs);
        }
      }
    })();
    try { return await this.retryInitialization; }
    finally { this.retryInitialization = null; }
  }

  getRuntimeFingerprint() { return this.runtimeFingerprint; }

  async loadModel() {
    let candidate = null;
    const dispose = async value => {
      try { if (typeof value?.dispose !== 'function') throw new Error('Embedding pipeline cannot be disposed'); await value.dispose(); }
      catch (error) { this.disposalFailure = error; throw error; }
    };
    try {
      if (this.disposalFailure) throw this.disposalFailure;
      const { pipeline, env } = await this.loadTransformers();
      if (process.env.HF_HUB_OFFLINE === '1' || process.env.TRANSFORMERS_OFFLINE === '1') {
        env.allowRemoteModels = false;
      }
      // Use pre-baked model cache in Docker image; falls back to Xenova default for local dev.
      if (process.env.XENOVA_CACHE || process.env.TRANSFORMERS_CACHE) {
        env.cacheDir = process.env.XENOVA_CACHE || process.env.TRANSFORMERS_CACHE;
      }
      const reportedProgress = new Map();
      const options = {
        dtype: 'q8',
        device: 'cpu',
        progress_callback: (progress) => {
          if (progress.status === 'progress' && progress.loaded != null) {
            const milestone = Math.floor(Number(progress.progress || 0) / 10) * 10;
            if (reportedProgress.get(progress.file) !== milestone) {
              reportedProgress.set(progress.file, milestone);
              console.log(`[RAG] Loading embedding model: ${progress.file} ${milestone}%`);
            }
          }
        }
      };
      const create = local => pipeline('feature-extraction',
        local && this.defaultTransformerRuntime
          ? require('node:path').resolve(env.cacheDir, 'Xenova/all-MiniLM-L6-v2')
          : 'Xenova/all-MiniLM-L6-v2',
        { ...options, ...(local ? { local_files_only: true } : {}) });
      let fingerprint = null;
      if (this.runtimeFingerprinter) {
        let before;
        try { before = await this.runtimeFingerprinter.snapshot(); }
        catch (error) {
          if (error.code !== 'EMBEDDING_FINGERPRINT_UNAVAILABLE' || env.allowRemoteModels === false) throw error;
          // First download may populate the cache, but cannot attest the loading
          // session. Drain it before constructing the verified offline session.
          candidate = await create(false);
          const downloaded = candidate; candidate = null; await dispose(downloaded);
          before = await this.runtimeFingerprinter.snapshot();
        }
        candidate = await create(true);
        const after = await this.runtimeFingerprinter.snapshot();
        if (before.fingerprint !== after.fingerprint) throw Object.assign(
          new Error('Embedding assets or runtime changed during initialization'), { code: 'EMBEDDING_FINGERPRINT_CHANGED' });
        fingerprint = after;
      } else candidate = await create(false);
      this.embedder = candidate; candidate = null;
      this.runtimeFingerprint = fingerprint;
      this.modelReady = true;
      console.log('[RAG] Embedding model Xenova/all-MiniLM-L6-v2 loaded.');
    } catch (err) {
      if (candidate) { const rejected = candidate; candidate = null; await dispose(rejected); }
      this.runtimeFingerprint = null;
      this.modelReady = false;
      console.error('[RAG] Failed to load embedding model:', err.message);
      throw err;
    }
  }

  /**
   * Slide a window of chunkSize chars with overlap. Discard whitespace-only chunks < MIN_CHUNK_LENGTH.
   * @param {string} text
   * @param {number} chunkSize
   * @param {number} overlap
   * @returns {string[]}
   */
  chunkText(text, chunkSize = CHUNK_SIZE, overlap = CHUNK_OVERLAP) {
    const chunks = [];
    let start = 0;
    const len = text.length;
    while (start < len) {
      let end = Math.min(start + chunkSize, len);
      let chunk = text.slice(start, end).trim();
      if (chunk.length >= MIN_CHUNK_LENGTH) {
        chunks.push(chunk);
      }
      if (end >= len) break;
      start = end - overlap;
      if (start >= len) break;
    }
    return chunks.length ? chunks : [text.trim() || ' '];
  }

  /**
   * Embed a single text and return Float32Array (normalized for cosine similarity).
   * @param {string} text
   * @returns {Promise<Float32Array>}
   */
  async embedText(text) {
    if (!this.embedder) { const error = new Error('RAG embedding model is not ready. Check RAG health and retry after initialization completes.'); error.code = 'RAG_EMBEDDING_NOT_READY'; error.status = 503; throw error; }
    const out = await this.embedder(text, { pooling: 'mean', normalize: true });
    const data = out && (out.data ?? out);
    if (data instanceof Float32Array) return data;
    if (Array.isArray(data)) return new Float32Array(data);
    if (out && typeof out.then === 'function') {
      const resolved = await out;
      const d = resolved.data ?? resolved;
      return d instanceof Float32Array ? d : new Float32Array(d);
    }
    throw new Error('Unexpected embedding output format');
  }

  /**
   * Cosine similarity: dot(A,B) / (||A|| * ||B||). Vectors assumed normalized => dot product is cosine.
   * @param {Float32Array} vecA
   * @param {Float32Array} vecB
   * @returns {number} in [-1, 1]
   */
  cosineSimilarity(vecA, vecB) {
    if (vecA.length !== vecB.length) return 0;
    let dot = 0;
    for (let i = 0; i < vecA.length; i++) dot += vecA[i] * vecB[i];
    let normA = 0, normB = 0;
    for (let i = 0; i < vecA.length; i++) {
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }
    normA = Math.sqrt(normA) || 1e-10;
    normB = Math.sqrt(normB) || 1e-10;
    return dot / (normA * normB);
  }

  // Resource families share inference, never document ownership or selection.
  forFamily(family) {
    if (!['RAG', 'CSRF'].includes(family)) throw new TypeError('Known RAG resource family required');
    if (family === 'RAG') return this;
    if (!this.resourceFamilies.has(family)) {
      const scoped = Object.create(this);
      scoped.sessions = new Map();
      scoped.sessionMetadata = new Map();
      scoped.lastSessionByUser = new Map();
      scoped.embedText = this.embedText.bind(this);
      scoped.init = this.init.bind(this);
      scoped.getRuntimeFingerprint = this.getRuntimeFingerprint.bind(this);
      scoped.forFamily = this.forFamily.bind(this);
      this.resourceFamilies.set(family, scoped);
    }
    return this.resourceFamilies.get(family);
  }

  _userSessionKey(userKey, sessionId) {
    return `${userKey}::${sessionId}`;
  }

  /**
   * Store document: decode buffer → chunk → embed each chunk → save in session.
   * Sessions are scoped by userKey so each student has isolated RAG data.
   * @param {string} userKey - User id (e.g. "1") or anonymous key (e.g. "anon_xyz")
   * @param {string} sessionId
   * @param {Buffer} fileBuffer
   * @param {string} [filename] - Original filename (e.g. normal_policy.txt) for progress objectives
   * @returns {Promise<{ chunksStored: number }>}
   */
  async storeDocument(userKey, sessionId, fileBuffer, filename = '') {
    const text = fileBuffer.toString('utf-8').trim();
    if (!text) throw new Error('Document is empty');
    const chunkStrings = this.chunkText(text);
    const chunks = [];
    for (let i = 0; i < chunkStrings.length; i++) {
      const embedding = await this.embedText(chunkStrings[i]);
      chunks.push({ text: chunkStrings[i], embedding, chunkIndex: i });
    }
    const key = this._userSessionKey(userKey, sessionId);
    this.sessions.set(key, chunks);
    this.sessionMetadata.set(key, { filename: filename || '' });
    return { chunksStored: chunks.length };
  }

  /** Set the current (last used) session for this user so it can be restored after refresh. Call with display filename. */
  setCurrentSession(userKey, sessionId, filename, chunksStored) {
    this.lastSessionByUser.set(userKey, { sessionId, filename: filename || 'document.txt', chunksStored: chunksStored || 0 });
  }

  /** Get the current (last used) session for this user if it still exists. Used to restore "document loaded" after refresh. */
  getCurrentSession(userKey) {
    const last = this.lastSessionByUser.get(userKey);
    if (!last) return null;
    const info = this.getSessionInfo(userKey, last.sessionId);
    if (!info.exists) {
      this.lastSessionByUser.delete(userKey);
      return null;
    }
    return { session_id: last.sessionId, filename: last.filename, chunks_stored: last.chunksStored };
  }

  /** Clear the current session for this user (e.g. on Reset progress). Removes from store and lastSessionByUser. */
  clearCurrentSession(userKey) {
    const last = this.lastSessionByUser.get(userKey);
    if (last) {
      this.deleteSession(userKey, last.sessionId);
      this.lastSessionByUser.delete(userKey);
    }
  }

  /** Remove every uploaded session owned by one user, including sessions that
   * are no longer selected. Administrative workshop resets use this boundary so
   * an older document cannot survive a reset and become selectable again. */
  clearUserSessions(userKey) {
    const prefix = `${userKey}::`;
    let deleted = 0;
    for (const key of [...this.sessions.keys()]) {
      if (!key.startsWith(prefix)) continue;
      this.sessions.delete(key);
      this.sessionMetadata.delete(key);
      deleted += 1;
    }
    this.lastSessionByUser.delete(userKey);
    return deleted;
  }

  /**
   * Embed question, score vs all chunks in session, return top-K.
   * @param {string} userKey
   * @param {string} sessionId
   * @param {string} question
   * @param {number} topK
   */
  async similaritySearch(userKey, sessionId, question, topK = 3) {
    const key = this._userSessionKey(userKey, sessionId);
    const sessionChunks = this.sessions.get(key);
    if (!sessionChunks || sessionChunks.length === 0) {
      throw new Error('Session not found');
    }
    const queryEmbedding = await this.embedText(question);
    const scored = sessionChunks.map(({ text, embedding, chunkIndex }) => ({
      text,
      score: this.cosineSimilarity(queryEmbedding, embedding),
      chunkIndex
    }));
    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, topK);
  }

  deleteSession(userKey, sessionId) {
    const key = this._userSessionKey(userKey, sessionId);
    this.sessionMetadata.delete(key);
    const last = this.lastSessionByUser.get(userKey);
    if (last && last.sessionId === sessionId) this.lastSessionByUser.delete(userKey);
    return this.sessions.delete(key);
  }

  getSessionInfo(userKey, sessionId) {
    const key = this._userSessionKey(userKey, sessionId);
    const chunks = this.sessions.get(key);
    const meta = this.sessionMetadata.get(key) || {};
    return {
      exists: !!chunks,
      chunkCount: chunks ? chunks.length : 0,
      filename: meta.filename || ''
    };
  }

  getActiveSessionsCount(userKey) {
    if (!userKey) return this.sessions.size;
    const prefix = userKey + '::';
    let count = 0;
    for (const k of this.sessions.keys()) {
      if (k.startsWith(prefix)) count++;
    }
    return count;
  }
}

module.exports = new RagVectorStore();
module.exports.RagVectorStore = RagVectorStore;
