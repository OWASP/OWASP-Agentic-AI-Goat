'use strict';

const PG_ONLY_MESSAGE =
  'SecureShop uses awaited PostgreSQL repositories; synchronous database handles are unavailable';

function requirePostgresRepository() {
  throw new Error(PG_ONLY_MESSAGE);
}

// Retain the historical interface while callers move to the native, awaited
// PostgreSQL repositories. Returning a synchronous compatibility handle here
// would make it possible to bypass transaction and ownership boundaries.
const getSecureshopDb = requirePostgresRepository;
const getAgentsDb = requirePostgresRepository;
function closeAll() {}

module.exports = { getSecureshopDb, getAgentsDb, closeAll, PG_ONLY_MESSAGE };
