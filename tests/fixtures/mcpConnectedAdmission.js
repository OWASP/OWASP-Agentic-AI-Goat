'use strict';
const fs = require('node:fs');
const path = require('node:path');
function assertMcpConnectedAdmission(env, sourceRoot) {
  const fail = () => { throw new Error('Exact isolated MCP baseline coordinates required'); };
  if (env.MCP_BASELINE_PRODUCTION !== 'yes' || env.RUN_MCP_OWNED_CONNECTED !== 'yes'
      || env.PG_TEST_DISPOSABLE !== 'yes') fail();
  const cohort = env.MCP_CONNECTED_COHORT || 'baseline';
  if (!['baseline', 'observed_action', 'indirect_injection', 'indirect_injection_production'].includes(cohort)
      || (env.MCP_INDIRECT_INJECTION_CANDIDATE || 'no') !== (cohort === 'indirect_injection' ? 'yes' : 'no')
      || env.MCP_OBSERVED_ACTION_CANDIDATE !== (cohort === 'observed_action' ? 'yes' : 'no')) fail();
  const publicIndirect = cohort === 'indirect_injection_production';
  if ((env.MCP_INDIRECT_INJECTION_PRODUCTION || 'no') !== (publicIndirect ? 'yes' : 'no')
      || (env.MCP_OBSERVED_ACTION_ENABLED || 'false') !== (publicIndirect ? 'true' : 'false')
      || (env.MCP_INDIRECT_INJECTION_ENABLED || 'false') !== (publicIndirect ? 'true' : 'false')
      || (env.MCP_SUPPLY_CHAIN_ENABLED || 'false') !== 'false') fail();
  for (const key of ['MCP_PROTECTED_STATE_CANDIDATE',
    'MCP_CATALOG_RECON_CANDIDATE', 'MCP_CATALOG_RECON_PRODUCTION']) if (env[key] !== 'no') fail();
  const source = fs.realpathSync(sourceRoot);
  if (env.MCP_CONNECTED_SOURCE_ROOT !== source) fail();
  const evidence = env.MCP_CONNECTED_EVIDENCE_ROOT;
  if (typeof evidence !== 'string' || !path.isAbsolute(evidence) || fs.realpathSync(evidence) !== evidence) fail();
  const stat = fs.statSync(evidence);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077)
      || evidence === source || evidence.startsWith(source + path.sep)) fail();
  if (env.LOGS_DIR !== path.join(evidence, 'logs')
      || env.MCP_JUDGE_INVALID_ATTEMPTS_PATH !== path.join(evidence, 'judge-invalid-attempts.jsonl')) fail();
  const port = key => {
    const value = env[key];
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,4}$/.test(value)
        || Number(value) > 65535 || [5432, 1025, 8025, 8090, 11434].includes(Number(value))) fail();
    return value;
  };
  const pg = port('MCP_CONNECTED_PG_PORT'), smtp = port('MCP_CONNECTED_SMTP_PORT');
  const api = port('MCP_CONNECTED_API_PORT'), runner = port('MCP_CONNECTED_RUNNER_PORT');
  if (new Set([pg, smtp, api, runner]).size !== 4) fail();
  let url; try { url = new URL(env.PG_MCP_CONNECTED_ADMIN_URL); } catch { fail(); }
  if (url.protocol !== 'postgresql:' || url.hostname !== '127.0.0.1' || url.port !== pg
      || url.username !== 'mcp_connected_admin' || url.pathname !== '/postgres' || url.search || url.hash) fail();
  if (env.MAILPIT_SMTP_HOST !== '127.0.0.1' || env.MAILPIT_SMTP_PORT !== smtp
      || env.MAILPIT_API_URL !== `http://127.0.0.1:${api}`
      || env.MCP_OWNED_TARGET_URL !== `http://127.0.0.1:${runner}`
      || env.OLLAMA_BASE_URL !== 'http://127.0.0.1:11434' || env.OLLAMA_MODEL !== 'llama3.1:8b'
      || !/^[a-f0-9]{64}$/.test(env.MCP_CONNECTED_MODEL_DIGEST || '')) fail();
}
module.exports = { assertMcpConnectedAdmission };
