'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { requiredStoreManifest } = require('../db/postgres/initialize-application');
const { assertFullBackendSecureShopAdmission: admit, MODEL_DIGEST } = require('./fixtures/fullBackendSecureShopAdmission');
function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ss-admission-')));
  const sourceRoot = root + '/source', evidenceRoot = root + '/runtime';
  fs.mkdirSync(sourceRoot, { mode: 0o555 });fs.mkdirSync(evidenceRoot, { mode: 0o700 });
  for (const name of ['trust','ssrf']) fs.mkdirSync(evidenceRoot + '/' + name, { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const env = { PG_FULL_BACKEND_SECURESHOP: '1', PG_FULL_BACKEND_AUTH: '1', PG_FULL_BACKEND_RENDERED: '1',
    PG_TEST_DISPOSABLE: 'yes', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    SS_ENABLE: 'true', SS_BOUND_REVIEWS_ENABLED: 'true', SS_PERSONA_INBOX_READY: 'true', SS_MCP_TRUST_READY: 'true',
    SS_CONTROLLED_SSRF_READY: 'true', AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'llama3.1:8b', JUDGE_PROVIDER: 'ollama',
    JUDGE_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'http://127.0.0.1:11434', PG_FULL_BACKEND_SECURESHOP_MODEL_DIGEST: MODEL_DIGEST,
    DVAIA_ISOLATED_TEST_WORKSPACE: sourceRoot, DVAIA_FULL_BACKEND_RUNTIME_ROOT: evidenceRoot,
    SS_MCP_TRUST_FIXTURE_ROOT: evidenceRoot + '/trust', SS_CONTROLLED_SSRF_FIXTURE_ROOT: evidenceRoot + '/ssrf', SS_AGENT_HOST_PORT: '35002' };
  for (const row of requiredStoreManifest) {
    env[row.runtimeVariable] = `postgresql://${row.runtimeRole}@127.0.0.1:35001/dvaia_test_full_backend_${row.schema}`;
    env[row.migrationVariable] = `postgresql://dvaia_${row.schema}_migration@127.0.0.1:35001/dvaia_test_full_backend_${row.schema}`;
  }
  const endpointManifest = { version: 1, postgres: { host: '127.0.0.1', port: 35001 },
    agentHost: { host: '127.0.0.1', port: 35002 }, model: { host: '127.0.0.1', port: 11434 },
    fixtures: [{ name: 'fixture_ssrf', host: '127.0.0.1', port: 35003 }] };
  return { env, options: { sourceRoot, evidenceRoot, endpointManifest }, root };
}
test('explicit SecureShop admission validates all sixteen pairs without claiming readiness', t => {
  const f = fixture(t), result = admit(f.env, f.options);
  assert.equal(requiredStoreManifest.length, 16);assert.equal(result.readinessVerified, false);
  assert.deepEqual(result.networkConfiguration.services.map(row => row.name), ['agent_host','model','fixture_ssrf']);
});
test('SecureShop admission rejects missing flags, cloud fallback, source mismatch and unsafe endpoint forms', t => {
  const f = fixture(t);
  for (const change of [
    e => delete e.PG_FULL_BACKEND_SECURESHOP, e => { e.SS_ENABLE_REAL_MCP_SPAWN = 'true'; },
    e => { e.SS_BOUND_REVIEWS_ENABLED = 'false'; }, e => { e.SS_MCP_TRUST_READY = 'false'; },
    e => { e.AWS_PROFILE = 'ambient'; }, e => { e.OPENAI_API_KEY = 'controlled'; },
    e => { e.JUDGE_MODEL = 'other'; }, e => { e.PG_FULL_BACKEND_SECURESHOP_MODEL_DIGEST = 'a'.repeat(64); },
    e => { e.OLLAMA_BASE_URL = 'http://localhost:11434'; }, e => { e.SS_AGENT_HOST_PORT = '35003'; },
    e => { e.SS_MCP_TRUST_FIXTURE_ROOT = f.root; }, e => { e.DVAIA_ISOLATED_TEST_WORKSPACE = f.root; },
    e => { e.IDENTITY_DATABASE_URL += '?sslmode=disable'; }, e => { e.IDENTITY_DATABASE_URL += '#fragment'; },
    e => { e.IDENTITY_DATABASE_URL = e.IDENTITY_DATABASE_URL.replace('35001','5432'); },
    e => { e.IDENTITY_DATABASE_URL = e.IDENTITY_MIGRATION_DATABASE_URL; },
  ]) { const env = { ...f.env };change(env);assert.throws(() => admit(env, f.options)); }
  for (const change of [m => { m.agentHost.host = 'localhost'; }, m => { m.agentHost.port = '35002'; },
    m => { m.agentHost.port = 0; }, m => { m.agentHost.port = 8082; }, m => { m.agentHost.path = '/tmp/socket'; },
    m => { m.fixtures[0].host = 'example.invalid'; }, m => { m.fixtures[0].port = 35001; },
    m => { m.fixtures.push({ ...m.fixtures[0] }); }, m => { m.model.port = 35004; }]) {
    const endpointManifest = structuredClone(f.options.endpointManifest);change(endpointManifest);
    assert.throws(() => admit(f.env, { ...f.options, endpointManifest }));
  }
});
test('SecureShop admission rejects writable source, public runtime and aliased fixture roots', t => {
  const f = fixture(t);fs.chmodSync(f.options.sourceRoot, 0o755);assert.throws(() => admit(f.env, f.options));
  fs.chmodSync(f.options.sourceRoot, 0o555);fs.chmodSync(f.options.evidenceRoot, 0o755);assert.throws(() => admit(f.env, f.options));
  fs.chmodSync(f.options.evidenceRoot, 0o700);const alias = f.options.evidenceRoot + '/alias';
  fs.symlinkSync(f.env.SS_MCP_TRUST_FIXTURE_ROOT, alias);
  assert.throws(() => admit({ ...f.env, SS_MCP_TRUST_FIXTURE_ROOT: alias }, f.options));
  const nested = f.env.SS_MCP_TRUST_FIXTURE_ROOT + '/nested';fs.mkdirSync(nested, { mode: 0o700 });
  assert.throws(() => admit({ ...f.env, SS_CONTROLLED_SSRF_FIXTURE_ROOT: nested }, f.options));
  assert.throws(() => admit({ ...f.env, SS_CONTROLLED_SSRF_FIXTURE_ROOT: f.env.SS_MCP_TRUST_FIXTURE_ROOT,
    SS_MCP_TRUST_FIXTURE_ROOT: nested }, f.options));
});
