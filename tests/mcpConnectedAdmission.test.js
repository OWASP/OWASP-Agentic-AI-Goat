'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assertMcpConnectedAdmission } = require('./fixtures/mcpConnectedAdmission');
test('baseline admission binds source, private evidence, four endpoints and exact model before resources', t => {
  const evidence = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-admission-')));
  fs.chmodSync(evidence, 0o700); t.after(() => fs.rmSync(evidence, { recursive: true }));
  const source = fs.realpathSync(path.resolve(__dirname, '..'));
  const env = { MCP_BASELINE_PRODUCTION: 'yes', RUN_MCP_OWNED_CONNECTED: 'yes', PG_TEST_DISPOSABLE: 'yes',
    MCP_PROTECTED_STATE_CANDIDATE: 'no', MCP_OBSERVED_ACTION_CANDIDATE: 'no',
    MCP_CATALOG_RECON_CANDIDATE: 'no', MCP_CATALOG_RECON_PRODUCTION: 'no',
    MCP_CONNECTED_SOURCE_ROOT: source, MCP_CONNECTED_EVIDENCE_ROOT: evidence,
    LOGS_DIR: path.join(evidence, 'logs'), MCP_JUDGE_INVALID_ATTEMPTS_PATH: path.join(evidence, 'judge-invalid-attempts.jsonl'),
    MCP_CONNECTED_PG_PORT: '35432', MCP_CONNECTED_SMTP_PORT: '31025', MCP_CONNECTED_API_PORT: '38025', MCP_CONNECTED_RUNNER_PORT: '38090',
    PG_MCP_CONNECTED_ADMIN_URL: 'postgresql://mcp_connected_admin@127.0.0.1:35432/postgres',
    MAILPIT_SMTP_HOST: '127.0.0.1', MAILPIT_SMTP_PORT: '31025', MAILPIT_API_URL: 'http://127.0.0.1:38025',
    MCP_OWNED_TARGET_URL: 'http://127.0.0.1:38090', OLLAMA_BASE_URL: 'http://127.0.0.1:11434',
    OLLAMA_MODEL: 'llama3.1:8b', MCP_CONNECTED_MODEL_DIGEST: 'a'.repeat(64) };
  assert.doesNotThrow(() => assertMcpConnectedAdmission(env, source));
  for (const key of Object.keys(env)) {
    const missing = { ...env }; delete missing[key];
    assert.throws(() => assertMcpConnectedAdmission(missing, source), key);
  }
  for (const delta of [
    { MCP_OBSERVED_ACTION_CANDIDATE: 'yes' }, { MCP_CONNECTED_SOURCE_ROOT: path.dirname(source) },
    { MCP_CONNECTED_PG_PORT: '5432' }, { MCP_CONNECTED_SMTP_PORT: '1025' },
    { MCP_CONNECTED_API_PORT: '8025' }, { MCP_CONNECTED_RUNNER_PORT: '8090' },
    { MCP_CONNECTED_RUNNER_PORT: '38025' }, { MCP_CONNECTED_PG_PORT: '65536' },
    { PG_MCP_CONNECTED_ADMIN_URL: env.PG_MCP_CONNECTED_ADMIN_URL + '?options=unsafe' },
    { PG_MCP_CONNECTED_ADMIN_URL: env.PG_MCP_CONNECTED_ADMIN_URL.replace('mcp_connected_admin', 'postgres') },
    { MCP_JUDGE_INVALID_ATTEMPTS_PATH: path.join(source, 'unexpected.jsonl') },
    { OLLAMA_MODEL: 'different' }, { MCP_CONNECTED_MODEL_DIGEST: 'unknown' },
  ]) assert.throws(() => assertMcpConnectedAdmission({ ...env, ...delta }, source));
  const observed = { ...env, MCP_CONNECTED_COHORT: 'observed_action', MCP_OBSERVED_ACTION_CANDIDATE: 'yes' };
  assert.doesNotThrow(() => assertMcpConnectedAdmission(observed, source));
  for (const delta of [{ MCP_OBSERVED_ACTION_CANDIDATE: 'no' },
    { MCP_CONNECTED_COHORT: 'other' }, { MCP_CONNECTED_COHORT: 'baseline' },
    { MCP_PROTECTED_STATE_CANDIDATE: 'yes' }, { MCP_CATALOG_RECON_CANDIDATE: 'yes' },
    { MCP_CATALOG_RECON_PRODUCTION: 'yes' }]) {
    assert.throws(() => assertMcpConnectedAdmission({ ...observed, ...delta }, source));
  }
  const indirect = { ...env, MCP_CONNECTED_COHORT: 'indirect_injection', MCP_INDIRECT_INJECTION_CANDIDATE: 'yes' };
  assert.doesNotThrow(() => assertMcpConnectedAdmission(indirect, source));
  for (const delta of [{ MCP_INDIRECT_INJECTION_CANDIDATE: 'no' },
    { MCP_CONNECTED_COHORT: 'baseline' }, { MCP_CONNECTED_COHORT: 'observed_action' },
    { MCP_OBSERVED_ACTION_CANDIDATE: 'yes' }, { MCP_PROTECTED_STATE_CANDIDATE: 'yes' },
    { MCP_CATALOG_RECON_CANDIDATE: 'yes' }, { MCP_CATALOG_RECON_PRODUCTION: 'yes' }]) {
    assert.throws(() => assertMcpConnectedAdmission({ ...indirect, ...delta }, source));
  }
  const publicIndirect = { ...env, MCP_CONNECTED_COHORT: 'indirect_injection_production',
    MCP_INDIRECT_INJECTION_PRODUCTION: 'yes', MCP_INDIRECT_INJECTION_ENABLED: 'true',
    MCP_OBSERVED_ACTION_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'false' };
  assert.doesNotThrow(() => assertMcpConnectedAdmission(publicIndirect, source));
  for (const delta of [{ MCP_INDIRECT_INJECTION_ENABLED: 'false' }, { MCP_OBSERVED_ACTION_ENABLED: 'false' },
    { MCP_INDIRECT_INJECTION_CANDIDATE: 'yes' }, { MCP_SUPPLY_CHAIN_ENABLED: 'true' },
    { MCP_INDIRECT_INJECTION_PRODUCTION: 'no' }, { MCP_CONNECTED_COHORT: 'baseline' }]) {
    assert.throws(() => assertMcpConnectedAdmission({ ...publicIndirect, ...delta }, source));
  }
  fs.chmodSync(evidence, 0o755);
  assert.throws(() => assertMcpConnectedAdmission(env, source));
});
