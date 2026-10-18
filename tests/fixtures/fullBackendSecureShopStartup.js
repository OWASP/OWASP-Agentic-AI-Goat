'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { assertFullBackendSecureShopAdmission } = require('./fullBackendSecureShopAdmission');
const KEYS = Object.freeze(['SS_ENABLE','SS_BOUND_REVIEWS_ENABLED','SS_PERSONA_INBOX_READY','SS_MCP_TRUST_READY',
  'SS_CONTROLLED_SSRF_READY','SS_AGENT_HOST_PORT','SS_MCP_TRUST_FIXTURE_ROOT','SS_CONTROLLED_SSRF_FIXTURE_ROOT',
  'AI_PROVIDER','OLLAMA_BASE_URL','OLLAMA_MODEL','JUDGE_PROVIDER','JUDGE_MODEL','SECURESHOP_REVIEW_RENDERER_ROOT']);
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function selectSecureShop(env) {
  if (env.PG_FULL_BACKEND_SECURESHOP === undefined) return false;
  assert.equal(env.PG_FULL_BACKEND_SECURESHOP, '1');
  assert.equal(env.PG_FULL_BACKEND_RENDERED, '1');
  assert.equal(env.PG_FULL_BACKEND_MCP_INDIRECT, undefined, 'SecureShop and MCP cohorts are exclusive');
  return true;
}
function prepareSecureShopStartup(env, { sourceRoot, evidenceRoot }) {
  assert.equal(selectSecureShop(env), true);
  for (const value of [sourceRoot,evidenceRoot]) { assert.ok(path.isAbsolute(value));assert.equal(fs.realpathSync(value),value);assert.ok(fs.statSync(value).isDirectory());assert.equal(fs.statSync(value).uid,process.getuid()); }
  assert.equal(fs.statSync(sourceRoot).mode & 0o222,0);assert.equal(fs.statSync(evidenceRoot).mode & 0o777,0o700);
  assert.ok(sourceRoot!==evidenceRoot&&!sourceRoot.startsWith(evidenceRoot+'/')&&!evidenceRoot.startsWith(sourceRoot+'/'));
  const roots = { SS_MCP_TRUST_FIXTURE_ROOT: path.join(evidenceRoot,'secureshop-mcp-trust'),
    SS_CONTROLLED_SSRF_FIXTURE_ROOT: path.join(evidenceRoot,'secureshop-ssrf') };
  for (const [key, value] of Object.entries(roots)) {
    assert.equal(env[key], value, 'Exact owned fixture destination required');
    fs.mkdirSync(value, { mode: 0o700 });
  }
  const endpointManifest = JSON.parse(env.PG_FULL_BACKEND_SECURESHOP_ENDPOINTS_JSON || 'null');
  const admission = assertFullBackendSecureShopAdmission(env, { sourceRoot, evidenceRoot, endpointManifest });
  const rendererRoot = env.SECURESHOP_REVIEW_RENDERER_ROOT;
  assert.ok(rendererRoot && path.isAbsolute(rendererRoot));assert.equal(fs.realpathSync(rendererRoot), rendererRoot);
  for (const other of [sourceRoot,evidenceRoot]) assert.ok(rendererRoot !== other && !rendererRoot.startsWith(other + '/') && !other.startsWith(rendererRoot + '/'));
  const stat = fs.statSync(rendererRoot);assert.ok(stat.isDirectory());assert.equal(stat.uid,process.getuid());assert.equal(stat.mode & 0o222,0);
  function read(name, max) {
    const file = path.join(rendererRoot,name);assert.equal(fs.realpathSync(file),file);
    const info=fs.lstatSync(file);assert.ok(info.isFile());assert.equal(info.uid,process.getuid());assert.equal(info.mode & 0o222,0);assert.ok(info.size>0&&info.size<=max);
    return fs.readFileSync(file);
  }
  const bytes=read('manifest.json',8192);
  assert.match(env.PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256 || '',/^[a-f0-9]{64}$/);
  assert.equal(hash(bytes),env.PG_FULL_BACKEND_SECURESHOP_RENDERER_MANIFEST_SHA256);
  const manifest=JSON.parse(bytes);
  assert.equal(Object.keys(manifest).sort().join(','),'artifact,artifactSha256,component,source,sourceSha256,version');
  assert.equal(manifest.version,1);assert.equal(manifest.component,'SecureShop.ReviewCard');
  assert.equal(manifest.source,'client/src/pages/secureshop/components/ReviewCard.jsx');
  assert.match(manifest.artifact,/^[A-Za-z0-9_-]+\.c?js$/);
  assert.equal(hash(fs.readFileSync(path.join(sourceRoot,manifest.source))),manifest.sourceSha256);
  assert.equal(hash(read(manifest.artifact,4*1024*1024)),manifest.artifactSha256);
  const mainEnv=Object.fromEntries(KEYS.map(key=>{assert.equal(typeof env[key],'string');return[key,env[key]];}));
  mainEnv.SS_ENABLE_REAL_MCP_SPAWN='false';
  return Object.freeze({admission,mainEnv:Object.freeze(mainEnv),renderer:Object.freeze({manifestSha256:hash(bytes),artifactSha256:manifest.artifactSha256,sourceSha256:manifest.sourceSha256})});
}
function assertSecureShopReadiness(result) {
  assert.equal(result.status,200);assert.equal(result.body?.ready,true);
  for(const key of ['catalog','review','storedBrowser','personaInbox','mcpTrust','controlledSsrf'])assert.equal(result.body.panels?.[key],true);
}
function unavailableRenderedSecureShop() {
  throw Object.assign(Error('SecureShop startup admission is not all-ten rendered semantic qualification'),{code:'SECURESHOP_RENDERED_QUALIFICATION_UNAVAILABLE'});
}
module.exports={selectSecureShop,prepareSecureShopStartup,assertSecureShopReadiness,unavailableRenderedSecureShop};
