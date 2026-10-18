'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assertFullBackendMcpAdmission, MODEL_DIGEST } = require('./fixtures/fullBackendMcpAdmission');
const { networkGuardSource } = require('./fixtures/fullBackendBootControls');

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-full-mcp-admission-')));
  const source = path.join(root, 'source'), evidence = path.join(root, 'evidence');
  fs.mkdirSync(source); fs.mkdirSync(evidence); fs.chmodSync(source, 0o555); fs.chmodSync(evidence, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const env = { PG_FULL_BACKEND_MCP_INDIRECT: '1', PG_FULL_BACKEND_AUTH: '1', PG_FULL_BACKEND_RENDERED: '1',
    PG_TEST_DISPOSABLE: 'yes', DVAIA_ISOLATED_TEST_WORKSPACE: fs.realpathSync(source),
    DVAIA_FULL_BACKEND_RUNTIME_ROOT: fs.realpathSync(evidence), PG_FULL_BACKEND_MCP_MODEL_DIGEST: MODEL_DIGEST,
    AI_PROVIDER: 'ollama', OLLAMA_BASE_URL: 'http://127.0.0.1:11434', OLLAMA_MODEL: 'llama3.1:8b',
    JUDGE_PROVIDER: 'ollama', JUDGE_MODEL: 'llama3.1:8b', MCP_OWNED_RESOURCES_ENABLED: 'true',
    MCP_OBSERVED_ACTION_ENABLED: 'true', MCP_INDIRECT_INJECTION_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'false',
    MCP_OWNED_TARGET_URL: 'http://127.0.0.1:38091', MAILPIT_SMTP_HOST: '127.0.0.1', MAILPIT_SMTP_PORT: '38092',
    MAILPIT_API_URL: 'http://127.0.0.1:38093' };
  for (const key of ['MCP_PROTECTED_STATE_CANDIDATE', 'MCP_OBSERVED_ACTION_CANDIDATE', 'MCP_INDIRECT_INJECTION_CANDIDATE', 'MCP_CATALOG_RECON_CANDIDATE', 'MCP_CATALOG_RECON_PRODUCTION']) env[key] = 'no';
  const endpointManifest = { version: 1, postgres: { host: '127.0.0.1', port: 38090 }, runner: { host: '127.0.0.1', port: 38091 }, smtp: { host: '127.0.0.1', port: 38092 }, mailpit: { host: '127.0.0.1', port: 38093 }, model: { host: '127.0.0.1', port: 11434 } };
  return { root, source, evidence, env, endpointManifest };
}

test('full-backend indirect MCP admission is explicit and returns production flags', t => {
    const f = fixture(t); const result = assertFullBackendMcpAdmission(f.env, { sourceRoot: f.source, evidenceRoot: f.evidence, endpointManifest: f.endpointManifest });
  assert.equal(result.MCP_INDIRECT_INJECTION_ENABLED, 'true'); assert.equal(result.model.digest, MODEL_DIGEST); assert.equal(result.endpoints.model, 11434);
  assert.deepEqual(result.networkConfiguration.services.map(service => service.name), ['fixture_runner', 'fixture_smtp', 'fixture_mailpit', 'model']);
  assert.match(networkGuardSource(result.databaseEndpoint, result.networkConfiguration), /QUALIFICATION_NETWORK_BLOCKED/);
});
test('full-backend indirect MCP admission rejects missing gate, candidate, foreign and colliding endpoints', t => {
  const f = fixture(t);
  for (const mutate of [
    (e) => { e.PG_FULL_BACKEND_MCP_INDIRECT = '0'; },
    (e) => { e.MCP_INDIRECT_INJECTION_CANDIDATE = 'yes'; },
    (e) => { e.OLLAMA_BASE_URL = 'http://localhost:11434'; },
    (e) => { e.MAILPIT_API_URL = 'http://user:pass@127.0.0.1:38093'; },
    (e) => { e.BEDROCK_MODEL_ID = 'cloud-fallback'; },
    (_e, m) => { m.mailpit.port = m.runner.port; },
    (_e, m) => { m.runner.url = 'http://127.0.0.1:38091'; },
  ]) {
    const env = { ...f.env }; const manifest = structuredClone(f.endpointManifest); mutate(env, manifest);
    assert.throws(() => assertFullBackendMcpAdmission(env, { sourceRoot: f.source, evidenceRoot: f.evidence, endpointManifest: manifest }));
  }
});

test('full-backend admission binds the pinned digest and rejects symlink aliases', t => {
  const f = fixture(t);
  const alias = path.join(f.root, 'source-alias');
  fs.symlinkSync(f.source, alias, 'dir');
  assert.throws(() => assertFullBackendMcpAdmission(f.env, {
    sourceRoot: alias, evidenceRoot: f.evidence, endpointManifest: f.endpointManifest,
  }));
  const env = { ...f.env, PG_FULL_BACKEND_MCP_MODEL_DIGEST: 'b'.repeat(64) };
  assert.throws(() => assertFullBackendMcpAdmission(env, {
    sourceRoot: f.source, evidenceRoot: f.evidence, endpointManifest: f.endpointManifest,
  }));
});
