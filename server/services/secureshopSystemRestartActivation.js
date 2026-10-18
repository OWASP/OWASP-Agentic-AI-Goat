'use strict';

const { createSecureShopSystemRestartClient } = require('./secureshopSystemRestartClient');

const FLAG = 'SS_BOUND_SYSTEM_RESTART_ENABLED';
const BASE_URL = 'SS_SYSTEM_RESTART_BASE_URL';
const TOKEN = 'SS_SYSTEM_RESTART_TOKEN';

function invalid() {
  return Object.assign(new Error('Bound System restart activation is invalid'), {
    code: 'INVALID_CONFIGURATION',
  });
}

function activationPolicy(env = process.env) {
  const flag = env[FLAG];
  if (flag !== undefined && !['true', 'false'].includes(flag)) throw invalid();
  if (flag !== 'true') return Object.freeze({ requested: false });
  if (env.SS_ENABLE !== 'true' || env.SS_BOUND_REVIEWS_ENABLED !== 'true'
      || env.PLATFORM_DATABASE_ENGINE !== 'postgres'
      || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') throw invalid();
  let origin;
  try {
    const value = new URL(env[BASE_URL]);
    if (!['http:', 'https:'].includes(value.protocol) || value.username || value.password
        || value.pathname !== '/' || value.search || value.hash) throw invalid();
    origin = value.origin;
  } catch {
    throw invalid();
  }
  if (typeof env[TOKEN] !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(env[TOKEN])) throw invalid();
  return Object.freeze({ requested: true, baseUrl: origin });
}

async function prepareSystemRestartClient({ env = process.env, fetchImpl = fetch,
  timeoutMs = 18000 } = {}) {
  const policy = activationPolicy(env);
  if (!policy.requested) return undefined;
  try {
    const client = createSecureShopSystemRestartClient({ baseURL: policy.baseUrl,
      token: env[TOKEN], fetchImpl, timeoutMs });
    await client.health();
    return client;
  } catch {
    throw Object.assign(new Error('Requested owned System restart service is unavailable'), {
      code: 'SYSTEM_RESTART_UNAVAILABLE',
    });
  }
}

module.exports = { SYSTEM_RESTART_FLAG: FLAG, activationPolicy, prepareSystemRestartClient };
