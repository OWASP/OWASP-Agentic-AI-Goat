'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { activationPolicy, prepareSystemConfigClient } = require(
  '../server/services/secureshopSystemConfigActivation');
const { HTTP_VERSION, CAPABILITY } = require('../server/services/secureshopSystemConfigClient');
const { ISOLATION } = require('../sidecars/sandbox-runner/owned-system/contract');

const token = 's'.repeat(43);
const enabled = Object.freeze({ SS_BOUND_SYSTEM_CONFIG_ENABLED: 'true', SS_ENABLE: 'true',
  SS_BOUND_REVIEWS_ENABLED: 'true', PLATFORM_DATABASE_ENGINE: 'postgres',
  WORKSHOP_DATABASE_ENGINE: 'postgres', SS_SYSTEM_CONFIG_BASE_URL: 'http://127.0.0.1:8090/',
  SS_SYSTEM_CONFIG_TOKEN: token });
const health = Object.freeze({ version: HTTP_VERSION, ready: true, isolation: ISOLATION,
  configReadCapability: CAPABILITY });
const metrics = Object.freeze({ version: 'secureshop-owned-system-metrics.v1', ok: true, hostname: 'listener', platform: 'linux', node: 'node-v26', uptime_s: 1, loadavg: null, freemem_mb: null, totalmem_mb: null, ts: '2026-09-20T00:00:00.000Z', metricsSource: 'owned-system-listener', memorySource: 'unavailable', uptimeSource: 'listener-process', loadSource: 'unavailable' });

test('absent or explicit-false System activation neither validates private settings nor probes', async () => {
  let calls = 0; const fetchImpl = async () => { calls++; throw new Error('must not probe'); };
  assert.deepEqual(activationPolicy({}), { requested: false });
  assert.equal(await prepareSystemConfigClient({ env: {}, fetchImpl }), undefined);
  const disabled = { SS_BOUND_SYSTEM_CONFIG_ENABLED: 'false',
    SS_SYSTEM_CONFIG_BASE_URL: 'file:///private', SS_SYSTEM_CONFIG_TOKEN: 'invalid' };
  assert.deepEqual(activationPolicy(disabled), { requested: false });
  assert.equal(await prepareSystemConfigClient({ env: disabled, fetchImpl }), undefined);
  assert.equal(calls, 0);
});

test('requested System activation requires bound PostgreSQL prerequisites and private exact config', () => {
  for (const change of [
    { SS_BOUND_SYSTEM_CONFIG_ENABLED: '1' }, { SS_ENABLE: 'false' },
    { SS_BOUND_REVIEWS_ENABLED: 'false' }, { PLATFORM_DATABASE_ENGINE: 'sqlite' },
    { WORKSHOP_DATABASE_ENGINE: 'sqlite' }, { SS_SYSTEM_CONFIG_BASE_URL: undefined },
    { SS_SYSTEM_CONFIG_BASE_URL: 'file:///private' },
    { SS_SYSTEM_CONFIG_BASE_URL: 'http://user:secret@localhost' },
    { SS_SYSTEM_CONFIG_BASE_URL: 'http://localhost/private' },
    { SS_SYSTEM_CONFIG_BASE_URL: 'http://localhost/?secret=yes' },
    { SS_SYSTEM_CONFIG_TOKEN: undefined }, { SS_SYSTEM_CONFIG_TOKEN: 'short' },
    { SS_SYSTEM_CONFIG_TOKEN: `${token}\n` },
  ]) assert.throws(() => activationPolicy({ ...enabled, ...change }), { code: 'INVALID_CONFIGURATION' });
  assert.deepEqual(activationPolicy(enabled), { requested: true, baseUrl: 'http://127.0.0.1:8090' });
});

test('prepared System client performs authenticated strict readiness before publication', async () => {
  const seen = [];
  const client = await prepareSystemConfigClient({ env: enabled, fetchImpl: async (url, options) => {
    seen.push({ url: String(url), method: options.method, authorization: options.headers.authorization });
    return Response.json(String(url).endsWith('/metrics') ? metrics : health);
  } });
  assert.equal(typeof client.read, 'function'); assert.equal(typeof client.assertReady, 'function');
  assert.deepEqual(seen, [
    { url: 'http://127.0.0.1:8090/secureshop/system/health', method: 'GET', authorization: `Bearer ${token}` },
    { url: 'http://127.0.0.1:8090/secureshop/system/metrics', method: 'GET', authorization: `Bearer ${token}` },
  ]);
});

test('requested readiness rejects unhealthy or malformed sidecars without private detail', async () => {
  for (const body of [{ ...health, ready: false }, { ...health, isolation: 'plain' },
    { ...health, configReadCapability: 'wrong' }, { ...health, extra: true }]) {
    await assert.rejects(prepareSystemConfigClient({ env: enabled,
      fetchImpl: async (url) => Response.json(String(url).endsWith('/metrics') ? metrics : body) }), error => error.code === 'SYSTEM_CONFIG_UNAVAILABLE'
        && !error.message.includes(token));
  }
  await assert.rejects(prepareSystemConfigClient({ env: enabled,
    fetchImpl: async () => { throw new Error(`private ${token}`); } }), error =>
    error.code === 'SYSTEM_CONFIG_UNAVAILABLE' && !error.message.includes(token));
});
test('requested readiness rejects a healthy config probe when metrics are absent or malformed', async () => {
  await assert.rejects(prepareSystemConfigClient({ env: enabled, fetchImpl: async (url) =>
    Response.json(String(url).endsWith('/metrics') ? { ...metrics, memorySource: 'host' } : health) }),
  error => error.code === 'SYSTEM_CONFIG_UNAVAILABLE');
});
