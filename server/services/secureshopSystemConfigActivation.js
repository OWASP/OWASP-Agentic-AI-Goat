'use strict';

const { createSecureShopSystemConfigClient } = require('./secureshopSystemConfigClient');

const FLAG = 'SS_BOUND_SYSTEM_CONFIG_ENABLED';
const BASE_URL = 'SS_SYSTEM_CONFIG_BASE_URL';
const TOKEN = 'SS_SYSTEM_CONFIG_TOKEN';

function invalid() {
  return Object.assign(new Error('Bound System config activation is invalid'), {
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

async function prepareSystemConfigClient({ env = process.env, fetchImpl = fetch,
  timeoutMs = 3000 } = {}) {
  const policy = activationPolicy(env);
  if (!policy.requested) return undefined;
  try {
    const client = createSecureShopSystemConfigClient({ baseURL: policy.baseUrl,
      token: env[TOKEN], fetchImpl, timeoutMs });
    await client.assertReady();
    await client.metrics();
    return client;
  } catch {
    throw Object.assign(new Error('Requested owned System config reader is unavailable'), {
      code: 'SYSTEM_CONFIG_UNAVAILABLE',
    });
  }
}

module.exports = { SYSTEM_CONFIG_FLAG: FLAG, activationPolicy, prepareSystemConfigClient };
