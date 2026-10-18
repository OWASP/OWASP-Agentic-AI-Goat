'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const { createXssScopedProfileReset } = require('./xssScopedProfileReset');
const { createXssProfileResetJournalRepository } = require('../database/postgres/xssProfileResetJournalRepository');
const { createXssParentResetJournalRepository } = require('../database/postgres/xssParentResetJournalRepository');
const badRequest = message => Object.assign(new TypeError(message), { code:'BAD_REQUEST', statusCode:400 });

function ownerId(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw badRequest('Authenticated XSS reset owner required');
  }
  return value;
}

function createXssScopedProfileResetComposition({ identityPool, store, runs, ledger, lifecycle } = {}) {
  if (typeof identityPool?.query !== 'function' || typeof identityPool?.connect !== 'function'
      || typeof store?.assertReady !== 'function' || typeof store?.apply !== 'function'
      || typeof runs?.withScopesQuiesced !== 'function' || typeof runs?.cancelScopes !== 'function' || typeof ledger?.withOwnerLease !== 'function'
      || typeof lifecycle !== 'function') {
    throw new TypeError('Complete scoped XSS reset composition dependencies required');
  }
  const journal = createXssProfileResetJournalRepository(identityPool);
  const parentJournal = createXssParentResetJournalRepository(identityPool);
  const resetProfile = createXssScopedProfileReset({
    pool:identityPool, runs, ledger, journal, store, lifecycle,
    readWorkshopGeneration:async owner => {
      const result = await identityPool.query(`SELECT generation::text AS generation
        FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='xss_workshop'`, [owner]);
      return result.rows[0]?.generation || '0';
    },
  });
  return Object.freeze({
    async assertReady() {
      try {
        await journal.assertReady();
        await parentJournal.assertReady();
        await store.assertReady();
      } catch (cause) {
        throw Object.assign(new Error('XSS scoped profile reset storage is not ready'), {
          code:'XSS_PROFILE_RESET_STORAGE_NOT_READY', statusCode:503, cause,
        });
      }
      return true;
    },
    reset(input) {
      if (!input || typeof input !== 'object' || Array.isArray(input)
          || Object.keys(input).some(key => !['ownerId','operationId'].includes(key))) {
        throw badRequest('Exact scoped profile reset request required');
      }
      const owner = ownerId(input.ownerId);
      let operationId = input.operationId;
      if (operationId !== undefined) {
        if (typeof operationId !== 'string' || !UUID.test(operationId)) {
          throw badRequest('Reset operation ID must be a UUID');
        }
        operationId = operationId.toLowerCase();
      }
      return resetProfile.resetCurrent({ownerId:owner, ...(operationId ? {operationId} : {})});
    },
  });
}

let configured;
async function getXssScopedProfileResetComposition() {
  if (!configured) {
    const identityPool = require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
    const store = await require('../database/postgres/xssWorkshopDb').getScopedProfileResetRepository();
    const ledger = require('../agent-runtime/postgresRunLedger').configuredRunLedger({family:'XSS'});
    const lifecycle = (_pool, owner, work) => require('./xssMutationAdmission')
      .configuredXssMutationAdmission(owner, guard => work(null, guard));
    configured ||= createXssScopedProfileResetComposition({ identityPool, store, ledger, lifecycle,
      runs:{cancelScopes:(owner, scopes) => require('../routes/xssWorkshop').cancelProfileScopes(owner, scopes),
        withScopesQuiesced:(owner, scopes, work) => require('../routes/xssWorkshop')
        .withProfileScopesQuiesced(owner, scopes, work)},
    });
  }
  return configured;
}

module.exports = { createXssScopedProfileResetComposition, getXssScopedProfileResetComposition };
