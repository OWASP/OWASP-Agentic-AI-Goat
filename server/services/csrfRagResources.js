'use strict';
const { randomUUID } = require('node:crypto');
function unavailable(message = 'Stored RAG document is unavailable; retry or explicitly re-upload the retained document') {
  return Object.assign(new Error(message), { code: 'CSRF_RAG_RESOURCE_UNAVAILABLE', statusCode: 503 });
}
function createCsrfRagResources({ store, cleanText }) {
  if (!store?.getSessionInfo || typeof cleanText !== 'string' || !cleanText) throw new TypeError('CSRF RAG resources required');
  const exists = (owner, id) => { const info = id && store.getSessionInfo(owner, id); return Boolean(info?.exists && info.chunkCount > 0); };
  function state(owner, tab) {
    const cleanReady = exists(owner, tab.ragCleanSessionId);
    const poisonRecorded = Boolean(tab.ragPoisoned || tab.ragDocText);
    const poisonReady = poisonRecorded && exists(owner, tab.ragSessionId);
    return { cleanReady, poisonRecorded, poisonReady, available: cleanReady && (!poisonRecorded || poisonReady) };
  }
  return Object.freeze({
    state,
    assertPoisonAvailable(owner, tab) {
      const current = state(owner, tab);
      if (current.poisonRecorded && !current.poisonReady) throw unavailable();
    },
    async ensureClean(owner, tab) {
      if (exists(owner, tab.ragCleanSessionId)) { tab.ragCleanSeeded = true; return tab.ragCleanSessionId; }
      const id = tab.ragCleanSessionId || `csrf_rag_clean_${randomUUID()}`;
      tab.ragCleanSeeded = false;
      try {
        const result = await store.storeDocument(owner, id, Buffer.from(cleanText, 'utf8'), 'vaultlink-kb.txt');
        if (!result?.chunksStored || !exists(owner, id)) throw unavailable();
        tab.ragCleanSessionId = id; tab.ragCleanSeeded = true;
        return id;
      } catch (error) { throw unavailable('Clean knowledge base is unavailable; retry when embedding is ready'); }
    },
    async resetPoison(owner, tab) {
      if (tab.ragSessionId) await store.deleteSession(owner, tab.ragSessionId);
      tab.ragSessionId = null; tab.ragPoisoned = false; tab.ragDocText = null; tab.ragFiredQuestions = [];
    },
    clearOwner: owner => store.clearUserSessions(String(owner)),
  });
}
module.exports = { createCsrfRagResources, unavailable };
