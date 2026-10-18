'use strict';

const { inspectStores, assertPrivateConfigBytes } = require('./qualify-sensitive-info-reset-promotion');
const { repositories, initializeApplication } = require('../db/postgres/initialize-application');

const EXPECTED_NAMES = Object.freeze(repositories.map(([name]) => name));

async function assertPersonaReadiness(dependencies = {}) {
  const postgres = require('../server/database/postgres');
  const createPool = dependencies.createPool || postgres.createPool;
  const closePostgresPools = dependencies.closePostgresPools || postgres.closePostgresPools;
  const assertPersonaInboxReadiness = dependencies.assertPersonaInboxReadiness
    || require('../server/services/secureshopBoundReviewComposition').assertPersonaInboxReadiness;
  const createSecureShopPersonaInboxAvailability = dependencies.createSecureShopPersonaInboxAvailability
    || require('../server/services/secureshopPersonaInboxAvailability').createSecureShopPersonaInboxAvailability;
  const identityPool = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const agentsPool = createPool(process.env, 'SECURESHOP_AGENTS_DATABASE_URL');
  try {
    await assertPersonaInboxReadiness({ identityPool, agentsPool });
    const availability = await createSecureShopPersonaInboxAvailability(identityPool).read();
    if (!availability.registered || availability.visible || availability.enabled.size !== 0) {
      throw Object.assign(new Error('persona inbox hidden catalog defaults changed'), {
        code: 'PERSONA_INBOX_DEFAULTS_CHANGED',
      });
    }
    return { ready: true, registered: true, visible: false, enabledObjectives: [] };
  } finally {
    await Promise.allSettled([identityPool.end(), agentsPool.end()]);
    await closePostgresPools();
  }
}

async function main(argument) {
  assertPrivateConfigBytes();
  require('dotenv').config({ quiet: true });
  assertPrivateConfigBytes();
  let result;
  if (argument === '--initialize') {
    await initializeApplication();
    result = { initialized: EXPECTED_NAMES };
  } else if (argument === '--ledger') {
    result = await inspectStores();
  } else if (argument === '--replay') {
    result = await inspectStores({ replay: true });
  } else if (argument === '--readiness') {
    result = await assertPersonaReadiness();
  } else {
    throw Object.assign(new Error('Usage: node scripts/qualify-secureshop-persona-promotion.js --initialize|--ledger|--replay|--readiness'), {
      code: 'INVALID_ARGUMENT',
    });
  }
  assertPrivateConfigBytes();
  return result;
}

if (require.main === module) main(process.argv[2]).then(result => {
  process.stdout.write(`SECURESHOP_PERSONA_QUALIFICATION=${JSON.stringify(result)}\n`);
}).catch(error => {
  console.error('SecureShop persona promotion qualification failed:', error.code || error.name);
  process.exitCode = 1;
});

module.exports = { EXPECTED_NAMES, assertPersonaReadiness, main };
