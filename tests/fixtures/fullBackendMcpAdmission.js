'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { validateNetworkConfiguration } = require('./fullBackendBootControls');

const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const LOOPBACK = '127.0.0.1';
const DYNAMIC_SERVICES = Object.freeze(['postgres', 'runner', 'smtp', 'mailpit']);

function fail() { throw new Error('Exact isolated full-backend MCP admission required'); }
function ownedDirectory(value, source) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) fail();
  let real;
  try { real = fs.realpathSync(value); } catch { fail(); }
  if (value !== real) fail();
  const stat = fs.statSync(real);
  if (!stat.isDirectory() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0
      || real === source || real.startsWith(`${source}${path.sep}`)
      || source.startsWith(`${real}${path.sep}`)) fail();
  return real;
}
function port(value, reserved = []) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 65535
      || reserved.includes(value)) fail();
  return value;
}
function exactEndpoint(value, expectedPort) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'host,port'
      || value.host !== LOOPBACK || value.port !== expectedPort) fail();
}
function assertFullBackendMcpAdmission(env, { sourceRoot, evidenceRoot, endpointManifest } = {}) {
  if (!env || env.PG_FULL_BACKEND_MCP_INDIRECT !== '1' || env.PG_FULL_BACKEND_AUTH !== '1'
      || env.PG_FULL_BACKEND_RENDERED !== '1' || env.PG_TEST_DISPOSABLE !== 'yes') fail();
  let source;
  try { source = fs.realpathSync(sourceRoot); } catch { fail(); }
  const sourceStat = fs.statSync(source);
  if (sourceRoot !== source || !path.isAbsolute(source) || !sourceStat.isDirectory() || sourceStat.uid !== process.getuid?.()
      || (sourceStat.mode & 0o222) !== 0) fail();
  const evidence = ownedDirectory(evidenceRoot, source);
  if (env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE !== source
      || env.OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT !== evidence) fail();
  if (env.PG_FULL_BACKEND_MCP_MODEL_DIGEST !== MODEL_DIGEST) fail();
  if (env.AI_PROVIDER !== 'ollama' || env.OLLAMA_BASE_URL !== `http://${LOOPBACK}:11434`
      || env.OLLAMA_MODEL !== MODEL || env.JUDGE_PROVIDER !== 'ollama' || env.JUDGE_MODEL !== MODEL) fail();
  for (const key of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_REGION', 'BEDROCK_MODEL_ID']) {
    if (env[key]) fail();
  }
  if (env.MCP_OWNED_RESOURCES_ENABLED !== 'true' || env.MCP_OBSERVED_ACTION_ENABLED !== 'true'
      || env.MCP_INDIRECT_INJECTION_ENABLED !== 'true' || env.MCP_SUPPLY_CHAIN_ENABLED !== 'false') fail();
  for (const key of ['MCP_PROTECTED_STATE_CANDIDATE', 'MCP_OBSERVED_ACTION_CANDIDATE',
    'MCP_INDIRECT_INJECTION_CANDIDATE', 'MCP_CATALOG_RECON_CANDIDATE', 'MCP_CATALOG_RECON_PRODUCTION']) {
    if ((env[key] || 'no') !== 'no') fail();
  }
  if (!endpointManifest || Object.getPrototypeOf(endpointManifest) !== Object.prototype
      || Object.keys(endpointManifest).sort().join(',') !== 'mailpit,model,postgres,runner,smtp,version'
      || endpointManifest.version !== 1) fail();
  const used = new Set([11434]);
  const endpoints = {};
  for (const name of DYNAMIC_SERVICES) {
    const endpoint = endpointManifest[name];
    if (!endpoint || endpoint.host !== LOOPBACK) fail();
    const p = port(endpoint.port, [5432, 1025, 8025, 8090, 11434]);
    if (used.has(p)) fail();
    used.add(p); exactEndpoint(endpoint, p); endpoints[name] = p;
  }
  exactEndpoint(endpointManifest.model, 11434);
  if (env.MCP_OWNED_TARGET_URL !== `http://${LOOPBACK}:${endpoints.runner}`
      || env.MAILPIT_SMTP_HOST !== LOOPBACK || env.MAILPIT_SMTP_PORT !== String(endpoints.smtp)
      || env.MAILPIT_API_URL !== `http://${LOOPBACK}:${endpoints.mailpit}`) fail();
  const validatedNetwork = validateNetworkConfiguration(endpointManifest.postgres, {
    version: 1,
    services: [
      { name: 'fixture_runner', host: LOOPBACK, port: endpoints.runner },
      { name: 'fixture_smtp', host: LOOPBACK, port: endpoints.smtp },
      { name: 'fixture_mailpit', host: LOOPBACK, port: endpoints.mailpit },
      { name: 'model', host: LOOPBACK, port: 11434 },
    ],
  });
  // Keep the database endpoint separate: networkGuardSource(endpoint, configuration)
  // accepts the exact { version, services } configuration shape.
  const databaseEndpoint = validatedNetwork.database;
  const networkConfiguration = Object.freeze({ version: validatedNetwork.version,
    services: validatedNetwork.services });
  return Object.freeze({ model: Object.freeze({ name: MODEL, digest: MODEL_DIGEST }),
    MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_OBSERVED_ACTION_ENABLED: 'true',
    MCP_INDIRECT_INJECTION_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'false',
    endpoints: Object.freeze({ ...endpoints, model: 11434 }), databaseEndpoint, networkConfiguration,
    sourceRoot: source, evidenceRoot: evidence });
}

module.exports = { assertFullBackendMcpAdmission, MODEL, MODEL_DIGEST, LOOPBACK };
