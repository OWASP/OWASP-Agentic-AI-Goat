'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { requiredStoreManifest } = require('../../db/postgres/initialize-application');
const { validateNetworkConfiguration } = require('./fullBackendBootControls');
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
function fail() { throw Error('Exact isolated full-backend SecureShop admission required'); }
function directory(value, writable) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || fs.realpathSync(value) !== value) fail();
  const stat = fs.lstatSync(value);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (writable ? (stat.mode & 0o777) !== 0o700 : (stat.mode & 0o222) !== 0)) fail();
  return value;
}
function inside(child, parent) { return child !== parent && child.startsWith(parent + path.sep); }
function endpoint(value, model = false) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join(',') !== 'host,port'
      || value.host !== '127.0.0.1' || !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535
      || (model ? value.port !== 11434 : [5432,8081,8082,11434].includes(value.port))) fail();
  return { host: value.host, port: value.port };
}
// Configuration admission only. Does not establish ownership, model inventory,
// production readiness, migration correctness, or OS network confinement.
function assertFullBackendSecureShopAdmission(env, { sourceRoot, evidenceRoot, endpointManifest } = {}) {
  for (const [key, expected] of Object.entries({ PG_FULL_BACKEND_SECURESHOP: '1', PG_FULL_BACKEND_AUTH: '1',
    PG_FULL_BACKEND_RENDERED: '1', PG_TEST_DISPOSABLE: 'yes', PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres', SS_ENABLE: 'true', SS_BOUND_REVIEWS_ENABLED: 'true',
    SS_PERSONA_INBOX_READY: 'true', SS_MCP_TRUST_READY: 'true', SS_CONTROLLED_SSRF_READY: 'true',
    AI_PROVIDER: 'ollama', OLLAMA_MODEL: MODEL, JUDGE_PROVIDER: 'ollama', JUDGE_MODEL: MODEL,
    OLLAMA_BASE_URL: 'http://127.0.0.1:11434', PG_FULL_BACKEND_SECURESHOP_MODEL_DIGEST: MODEL_DIGEST })) {
    if (env?.[key] !== expected) fail();
  }
  if (env.SS_ENABLE_REAL_MCP_SPAWN !== undefined && env.SS_ENABLE_REAL_MCP_SPAWN !== 'false') fail();
  for (const key of ['OPENAI_API_KEY','ANTHROPIC_API_KEY','CLAUDE_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN','AWS_PROFILE','AWS_REGION','BEDROCK_MODEL_ID','GOOGLE_API_KEY','GEMINI_API_KEY']) if (env[key]) fail();
  const source = directory(sourceRoot, false), evidence = directory(evidenceRoot, true);
  if (source === evidence || inside(evidence, source) || inside(source, evidence)
      || env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE !== source || env.OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT !== evidence) fail();
  const roots = {};
  for (const key of ['SS_MCP_TRUST_FIXTURE_ROOT','SS_CONTROLLED_SSRF_FIXTURE_ROOT']) {
    roots[key] = directory(env[key], true);if (!inside(roots[key], evidence)) fail();
  }
  if (roots.SS_MCP_TRUST_FIXTURE_ROOT === roots.SS_CONTROLLED_SSRF_FIXTURE_ROOT
      || inside(roots.SS_MCP_TRUST_FIXTURE_ROOT, roots.SS_CONTROLLED_SSRF_FIXTURE_ROOT)
      || inside(roots.SS_CONTROLLED_SSRF_FIXTURE_ROOT, roots.SS_MCP_TRUST_FIXTURE_ROOT)) fail();
  if (!endpointManifest || Object.keys(endpointManifest).sort().join(',') !== 'agentHost,fixtures,model,postgres,version'
      || endpointManifest.version !== 1 || !Array.isArray(endpointManifest.fixtures) || endpointManifest.fixtures.length > 8) fail();
  const postgres = endpoint(endpointManifest.postgres), agentHost = endpoint(endpointManifest.agentHost);
  const model = endpoint(endpointManifest.model, true), ports = new Set([postgres.port,agentHost.port,model.port]);
  if (ports.size !== 3 || env.SS_AGENT_HOST_PORT !== String(agentHost.port)) fail();
  const services = [{ name: 'agent_host', ...agentHost }, { name: 'model', ...model }];
  const names = new Set();
  for (const item of endpointManifest.fixtures) {
    if (!item || Object.keys(item).sort().join(',') !== 'host,name,port' || !/^fixture_[a-z][a-z0-9_]{0,31}$/.test(item.name)
        || names.has(item.name)) fail();
    const value = endpoint({ host: item.host, port: item.port });
    if (ports.has(value.port)) fail();ports.add(value.port);names.add(item.name);services.push({ name: item.name, ...value });
  }
  for (const store of requiredStoreManifest) {
    for (const [variable, role] of [[store.runtimeVariable, store.runtimeRole],
      [store.migrationVariable, `dvaia_${store.schema}_migration`]]) {
      let url;try { url = new URL(env[variable]); } catch { fail(); }
      if (url.protocol !== 'postgresql:' || url.hostname !== postgres.host || url.port !== String(postgres.port)
          || url.pathname !== `/owasp_ai_goat_test_full_backend_${store.schema}` || url.username !== role
          || url.search || url.hash) fail();
    }
  }
  const network = validateNetworkConfiguration(postgres, { version: 1, services });
  return Object.freeze({ scope: 'full_backend_secureshop_configuration', readinessVerified: false,
    sourceRoot: source, evidenceRoot: evidence, fixtureRoots: Object.freeze(roots),
    databaseEndpoint: network.database, networkConfiguration: Object.freeze({ version: 1, services: network.services }),
    model: Object.freeze({ name: MODEL, digest: MODEL_DIGEST }) });
}
module.exports = { assertFullBackendSecureShopAdmission, MODEL, MODEL_DIGEST };
