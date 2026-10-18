'use strict';

const { randomUUID } = require('node:crypto');
const { createXssParentReset } = require('./xssParentReset');
const { createXssParentResetJournalRepository } = require('../database/postgres/xssParentResetJournalRepository');
const { createXssProfileResetJournalRepository } = require('../database/postgres/xssProfileResetJournalRepository');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Administrative whole-workshop reset. Admission is held by the caller; the
// composition reuses the mounted coordinator and existing runtime stores.
function createXssParentResetComposition({ identityPool, store, runs } = {}) {
  if (typeof store?.assertReady !== 'function') throw new TypeError('XSS reset store readiness required');
  const journal = createXssParentResetJournalRepository(identityPool);
  const childJournal = createXssProfileResetJournalRepository(identityPool);
  const resetParent = createXssParentReset({ journal, childJournal, store, runs });
  return Object.freeze({
    async assertReady() {
      try {
        await journal.assertReady();
        await childJournal.assertReady();
        await store.assertReady();
      } catch (cause) {
        throw Object.assign(new Error('XSS reset storage is not ready'), {
          code: 'XSS_PARENT_RESET_STORAGE_NOT_READY', statusCode: 503, cause,
        });
      }
      return true;
    },
    async reset({ ownerId, operationId, lifecycle }) {
      if (operationId !== undefined && (typeof operationId !== 'string' || !UUID.test(operationId))) {
        throw Object.assign(new Error('Reset operation ID must be a UUID'), { code: 'BAD_REQUEST', statusCode: 400 });
      }
      if (operationId === undefined) {
        if (!Number.isSafeInteger(ownerId) || ownerId < 1 || ownerId > 2147483647
            || lifecycle?.ownerId !== ownerId || typeof lifecycle?.check !== 'function') {
          throw new TypeError('Protected XSS reset lifecycle authority required');
        }
        // Existing UI and bulk callers omit operation IDs. Resolve a previous
        // interrupted operation under the same lifecycle lock, so retrying does
        // not strand the owner behind its pending-reset admission fence.
        await lifecycle.check();
        const admitted = await journal.begin({ ownerId, operationId:randomUUID() });
        await lifecycle.check();
        if (admitted.ownerId !== ownerId) throw new Error('XSS parent reset owner mismatch');
        operationId = admitted.operationId;
      }
      return resetParent({ ownerId, operationId:operationId.toLowerCase(), lifecycle });
    },
  });
}

let configured;
async function getXssParentResetComposition() {
  if (!configured) {
    const identityPool = require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
    const store = await require('../database/postgres/xssWorkshopDb').getScopedProfileResetRepository();
    // Concurrent first callers share the underlying singleton repositories and
    // mounted coordinator. No composition owns or allocates a connection pool.
    configured ||= createXssParentResetComposition({ identityPool, store,
      runs: { reset: (owner, work) => require('../routes/xssWorkshop').resetOwner(owner, work) },
    });
  }
  return configured;
}

module.exports = { createXssParentResetComposition, getXssParentResetComposition };
