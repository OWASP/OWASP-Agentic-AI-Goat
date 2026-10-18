'use strict';

const { createSecureShopSystemDiagnosticClient } = require('./secureshopSystemDiagnosticClient');

const FLAG = 'SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED';
const BASE_URL = 'SS_SYSTEM_DIAGNOSTIC_BASE_URL';
const TOKEN = 'SS_SYSTEM_DIAGNOSTIC_TOKEN';

function invalid() {
  return Object.assign(new Error('Bound System diagnostic activation is invalid'), {
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
  if (typeof env[TOKEN] !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(env[TOKEN])) {
    throw invalid();
  }
  return Object.freeze({ requested: true, baseUrl: origin });
}

async function prepareSystemDiagnosticClient({ env = process.env, fetchImpl = fetch,
  timeoutMs = 18000 } = {}) {
  const policy = activationPolicy(env);
  if (!policy.requested) return undefined;
  try {
    const client = createSecureShopSystemDiagnosticClient({ baseURL: policy.baseUrl,
      token: env[TOKEN], fetchImpl, timeoutMs });
    await client.assertReady();
    return client;
  } catch {
    throw Object.assign(new Error('Requested owned System diagnostic reader is unavailable'), {
      code: 'SYSTEM_DIAGNOSTIC_UNAVAILABLE',
    });
  }
}

module.exports = { SYSTEM_DIAGNOSTIC_FLAG: FLAG, activationPolicy, prepareSystemDiagnosticClient };
