'use strict';

// Current-main, disposable-store, rendered qualification of the owned MCP
// registry. The launcher owns the executor, browser executable and cleanup.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'MCP_ASSEMBLY_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const NAME = 'readiness-catalog';
const PEER = 'http://benign.training/mcp';
const MANIFEST = 'http://metadata.training/manifest.xml';
const IMPORTED = 'imported-catalog';
const HEX = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const ENABLED = process.env.MCP_REGISTRY_RENDERED_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const V43_ENABLED = process.env.MCP_IMPERSONATION_V43_NATIVE === '1';
const V42_ENABLED = process.env.MCP_REGISTRY_SSRF_V42_NATIVE === '1';
const V66_ENABLED = process.env.MCP_MANIFEST_V66_NATIVE === '1';
const V39_ENABLED = process.env.MCP_DESCRIPTION_V39_NATIVE === '1';
const Q05_HANDOFF_ENABLED = process.env.MCP_REGISTERED_HANDOFF_Q05_NATIVE === '1';
const V39_PAIR_ENABLED = process.env.MCP_DESCRIPTION_V39_ATOMIC_PAIR_NATIVE === '1';
const V39_CURRENT_HOST_EVIDENCE = V39_ENABLED
  && process.env.MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE === '1';
const Q05_CURRENT_HOST_EVIDENCE = Q05_HANDOFF_ENABLED
  && process.env.MCP_REGISTERED_HANDOFF_Q05_CURRENT_HOST_EVIDENCE === '1';
const MODEL_REGISTRY_ENABLED = V43_ENABLED || V66_ENABLED || V39_ENABLED || V42_ENABLED || Q05_HANDOFF_ENABLED;
if (Q05_HANDOFF_ENABLED) {
  assert.equal(V43_ENABLED || V66_ENABLED || V39_ENABLED || V42_ENABLED || V39_PAIR_ENABLED, false,
    'Q05 handoff is an exclusive ungraded rendered cohort');
  assert.equal(ENABLED, true);
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1');
}
if(V42_ENABLED){assert.equal(V43_ENABLED||V66_ENABLED||V39_ENABLED,false,'V42 is a closed distinct registry cohort');assert.equal(ENABLED,true);assert.equal(process.env.LIVE_OLLAMA_TEST,'1');}
if (V39_ENABLED) {
  assert.equal(V43_ENABLED || V66_ENABLED, false, 'V39 has its own rendered objective');
  assert.equal(ENABLED, true);
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1');
}
if (V39_PAIR_ENABLED) {
  assert.equal(V39_ENABLED, true, 'atomic pair is an explicit V39 rendered variant');
  assert.equal(V42_ENABLED || V43_ENABLED || V66_ENABLED, false);
  assert.equal(process.env.MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE, '1');
}
if (V66_ENABLED) {
  assert.equal(V43_ENABLED, false, 'V66 is a distinct owned MCP cohort');
  assert.equal(ENABLED, true, 'V66 requires the owned registry rendered cohort');
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1', 'V66 requires the actual configured model');
}
if (V43_ENABLED) {
  assert.equal(ENABLED, true, 'V43 requires the owned registry rendered cohort');
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1', 'V43 requires the actual configured model');
}
const D16_ENABLED = process.env.MCP_TRUST_STANDALONE_RENDERED_NATIVE === '1'
  && process.env.LIVE_OLLAMA_TEST === '1' && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const V40_ENABLED = process.env.MCP_RUG_PULL_V40_NATIVE === '1';
if (V40_ENABLED) assert.equal(D16_ENABLED, true, 'V40 requires the genuine D16 cohort');

function disposableUrls() {
  const result = {}; let nonce; let port;
  for (const [store, basename] of Object.entries(STORES)) {
    const db = { IDENTITY: 'identity', AGENTS: 'agents', REVIEW: 'review', COMMERCE: 'commerce' }[store];
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`, url = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      assert.match(url.port, /^[1-9]\d{0,4}$/); assert.ok(Number(url.port) <= 65535);
      const database = D16_ENABLED || MODEL_REGISTRY_ENABLED
        ? `agent_host_([a-f0-9]{12})_${basename}`
        : `mcp_assembly_([a-f0-9]{12})_${db}`;
      const match = new RegExp(`^/owasp_ai_goat_test_${database}$`).exec(url.pathname);
      assert.ok(match, `disposable owned MCP database required for ${key}`);
      assert.equal(url.username, `dvaia_${basename}_${role.toLowerCase()}`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      result[key] = url.href;
    }
    assert.equal(new URL(result[`${store}_MIGRATION`]).pathname,
      new URL(result[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES)
    .map(store => new URL(result[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(result);
}
async function waitFor(read, label, timeoutMs = 20000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const value = await read(); if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw Object.assign(new Error(`${label} was not observed`), { code: 'OBSERVATION_TIMEOUT' });
}
async function frameOn(page) {
  return waitFor(async () => {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    return frame && !frame.detached ? frame : null;
  }, 'standalone SecureShop frame');
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
function switchV39AtomicProvider(current, next) {
  const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');
  assert.equal(Object.getPrototypeOf(current), OllamaProvider.prototype);
  assert.equal(Object.getPrototypeOf(next), OllamaProvider.prototype);
  assert.equal(current.model, next.model);
  assert.equal(current.model, 'llama3.1:8b');
  const previous = new URL(current.baseUrl), successor = new URL(next.baseUrl);
  for (const url of [previous, successor]) {
    assert.equal(url.protocol, 'http:'); assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.pathname, '/'); assert.equal(url.search, '');
  }
  assert.notEqual(previous.origin, successor.origin, 'the treatment must use a new physical relay');
  current.baseUrl = next.baseUrl;
  current.transport = next.transport;
  for (const method of ['chat', 'finalResponse', 'routeWorkflow', 'isReachable']) {
    assert.equal(typeof next[method], 'function');
    current[method] = (...args) => next[method](...args);
  }
  return current;
}
function q05RegisteredInvocationCompositionOptions(enabled, readInvocation) {
  if (!enabled) return {};
  assert.equal(typeof readInvocation, 'function');
  return { registeredInvocationApplication: () => {
    const invocation = readInvocation();
    return invocation?.ready === true ? invocation : null;
  } };
}
function admitPrivateCurrentHostEvidence({ env, source, evidencePath, enabled, marker, rootName, label }) {
  assert.equal(enabled, true, `only the original ${label} rendered cohort admits current-host evidence`);
  assert.equal(env[marker], '1');
  assert.equal(fsSync.realpathSync(source), source, 'canonical current-main source required');
  const parent = path.join(source, 'tasks', 'qualification');
  const run = env[rootName];
  assert.equal(typeof run, 'string');
  assert.match(path.basename(run), /^owasp-ai-goat-mcp-assembly-[a-z0-9_]{8}$/);
  assert.equal(path.dirname(run), parent);
  assert.equal(evidencePath, path.join(run, 'candidate-result.json'));
  assert.equal(env.TMPDIR, path.join(run, 'tmp'));
  assert.equal(env.MAC_CHROMIUM_TMPDIR, path.join(run, 'tmp'));
  for (const directory of [source, path.join(source, 'tasks'), parent, run, path.join(run, 'tmp')]) {
    const info = fsSync.lstatSync(directory);
    assert.equal(info.isDirectory(), true);
    assert.equal(info.isSymbolicLink(), false);
    assert.equal(info.uid, process.getuid());
    assert.equal(fsSync.realpathSync(directory), directory);
    if (directory === parent || directory === run || directory === path.join(run, 'tmp'))
      assert.equal(info.mode & 0o777, 0o700);
  }
  assert.equal(fsSync.existsSync(evidencePath), false, `${label} result must be fresh`);
  return run;
}
function admitV39CurrentHostEvidence({ env, source, evidencePath, enabled }) {
  assert.notEqual(env.MCP_REGISTERED_HANDOFF_Q05_CURRENT_HOST_EVIDENCE, '1');
  return admitPrivateCurrentHostEvidence({ env, source, evidencePath, enabled,
    marker: 'MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE',
    rootName: 'MCP_DESCRIPTION_V39_EVIDENCE_ROOT', label: 'V39' });
}
function admitQ05CurrentHostEvidence({ env, source, evidencePath, enabled }) {
  assert.notEqual(env.MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE, '1');
  return admitPrivateCurrentHostEvidence({ env, source, evidencePath, enabled,
    marker: 'MCP_REGISTERED_HANDOFF_Q05_CURRENT_HOST_EVIDENCE',
    rootName: 'MCP_REGISTERED_HANDOFF_Q05_EVIDENCE_ROOT', label: 'Q05' });
}
function createPrivateWriter(directory, { allowed, label, atomicPair = false } = {}) {
  assert.equal(typeof atomicPair, 'boolean');
  const open = new Map();
  function write(name, bytes) {
    assert(allowed.has(name), `closed ${label} private artifact name required`);
    if (label === 'Q05') {
      const owner = fsSync.lstatSync(directory);
      assert.ok(owner.isDirectory() && !owner.isSymbolicLink()
        && owner.uid === process.getuid() && (owner.mode & 0o777) === 0o700,
      'Q05 private evidence owner changed');
    }
    assert.equal(fsSync.realpathSync(directory), directory);
    const file = path.join(directory, name);
    let descriptor = open.get(name);
    if (descriptor === undefined) {
      descriptor = fsSync.openSync(file, fsSync.constants.O_WRONLY | fsSync.constants.O_CREAT
        | fsSync.constants.O_EXCL | fsSync.constants.O_NOFOLLOW, 0o600);
      open.set(name, descriptor);
    }
    const initial = fsSync.fstatSync(descriptor), linked = fsSync.lstatSync(file);
    assert(initial.isFile() && linked.isFile() && initial.nlink === 1 && linked.nlink === 1
      && initial.uid === process.getuid() && linked.uid === process.getuid()
      && (initial.mode & 0o777) === 0o600 && (linked.mode & 0o777) === 0o600
      && initial.dev === linked.dev && initial.ino === linked.ino, 'V39 private artifact replaced');
    const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    if (name.startsWith('mcp-description-atomic-')) {
      const maximum = name.endsWith('-wire.json') ? 128 * 1024 * 1024
        : name.endsWith('-model.json') ? 32 * 1024 * 1024
        : name.endsWith('-qualification.json') ? 8 * 1024 * 1024 : 8192;
      assert.ok(body.length > 0 && body.length <= maximum, 'bounded atomic pair artifact required');
    } else if (label === 'Q05') {
      const maximum = name.endsWith('-wire.json') ? 128 * 1024 * 1024
        : name.endsWith('-model.json') ? 32 * 1024 * 1024
        : name.endsWith('-qualification.json') ? 8 * 1024 * 1024 : 16384;
      assert.ok(body.length > 0 && body.length <= maximum, 'bounded Q05 artifact required');
    }
    fsSync.ftruncateSync(descriptor, 0);
    for (let offset = 0; offset < body.length;) {
      const written = fsSync.writeSync(descriptor, body, offset, body.length - offset, offset);
      assert(written > 0, 'V39 private artifact short write'); offset += written;
    }
    fsSync.fsyncSync(descriptor);
    const after = fsSync.lstatSync(file);
    assert.equal(after.dev, initial.dev); assert.equal(after.ino, initial.ino);
  }
  return { write, close() {
    let firstError;
    for (const descriptor of open.values()) try { fsSync.closeSync(descriptor); }
    catch (error) { firstError ||= error; }
    open.clear();
    if (firstError) throw firstError;
  } };
}
function createV39PrivateWriter(directory, { atomicPair = false } = {}) {
  const allowed = new Set(['candidate-result.json', 'mcp-description-model.json',
    'mcp-description-wire.json', 'mcp-description-qualification.json',
    'mcp-description-receipt.json', 'v39-browser-diagnostic.json']);
  if (atomicPair) for (const name of [
    'mcp-description-atomic-control-model.json', 'mcp-description-atomic-control-wire.json',
    'mcp-description-atomic-control-qualification.json',
    'mcp-description-atomic-treatment-model.json', 'mcp-description-atomic-treatment-wire.json',
    'mcp-description-atomic-treatment-qualification.json',
    'mcp-description-atomic-pair-receipt.json']) allowed.add(name);
  return createPrivateWriter(directory, { allowed, label: 'V39', atomicPair });
}
function createQ05PrivateWriter(directory) {
  return createPrivateWriter(directory, { label: 'Q05', allowed: new Set([
    'candidate-result.json', 'registered-handoff-model.json', 'registered-handoff-wire.json',
    'registered-handoff-committed-loss.json', 'registered-handoff-qualification.json',
    'registered-handoff-receipt.json']) });
}
async function q05InitialPrivateSave(save, writer) {
  try { await save(); }
  catch (primary) {
    try { writer.close(); }
    catch (error) {
      try { primary.q05WriterCloseCode = typeof error?.code === 'string' ? error.code : 'Q05_CLOSE_FAILED'; }
      catch { /* A frozen primary still outranks a retirement diagnostic. */ }
    }
    throw primary;
  }
}
async function q05FinalPrivateSave({ writer, receiptBytes, save, status, receipt, primary }) {
  let failure = primary;
  const record = error => {
    const code = typeof error?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(error.code)
      ? error.code : 'Q05_PRIVATE_EVIDENCE_ERROR';
    failure ||= error;
    status.status = 'failed'; status.cleanupComplete = false;
    status.cleanupErrors.push(code);
    status.error ||= { code, message: 'Q05 private evidence publication failed' };
    receipt.passed = false;
  };
  try {
    let resultSaved = false;
    try { await save(); resultSaved = true; }
    catch (error) { record(error); }
    if (resultSaved) {
      try { writer.write('registered-handoff-receipt.json', receiptBytes); }
      catch (error) {
        record(error);
        try { await save(); }
        catch (saveError) { record(saveError); }
      }
    }
  } finally {
    try { writer.close(); }
    catch (error) { record(error); }
  }
  return failure;
}
function publishV39AtomicFinalReceipt(directory, receipt) {
  require('../fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification')
    .assertPairReceipt(receipt);
  const parent = fsSync.lstatSync(directory);
  assert.ok(parent.isDirectory() && !parent.isSymbolicLink()
    && parent.uid === process.getuid() && (parent.mode & 0o777) === 0o700
    && fsSync.realpathSync(directory) === directory);
  const file = path.join(directory, 'mcp-description-atomic-pair-receipt.json');
  const candidate = path.join(directory, `.mcp-description-atomic-pair-receipt-${randomUUID()}.tmp`);
  const bytes = Buffer.from(JSON.stringify(receipt, null, 2) + '\n');
  assert.ok(bytes.length > 0 && bytes.length <= 8192);
  const descriptor = fsSync.openSync(candidate, fsSync.constants.O_WRONLY | fsSync.constants.O_CREAT
    | fsSync.constants.O_EXCL | fsSync.constants.O_NOFOLLOW, 0o600);
  let candidateIdentity, linked = false, closed = false;
  try {
    candidateIdentity = fsSync.fstatSync(descriptor);
    assert.ok(candidateIdentity.isFile() && candidateIdentity.nlink === 1
      && candidateIdentity.uid === process.getuid()
      && (candidateIdentity.mode & 0o777) === 0o600);
    for (let offset = 0; offset < bytes.length;) {
      const written = fsSync.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
      assert.ok(written > 0); offset += written;
    }
    fsSync.fsyncSync(descriptor);
    fsSync.closeSync(descriptor); closed = true;
    const candidateOnDisk = fsSync.lstatSync(candidate);
    assert.ok(candidateOnDisk.isFile() && !candidateOnDisk.isSymbolicLink()
      && candidateOnDisk.nlink === 1 && candidateOnDisk.uid === process.getuid()
      && (candidateOnDisk.mode & 0o777) === 0o600
      && candidateOnDisk.dev === candidateIdentity.dev
      && candidateOnDisk.ino === candidateIdentity.ino);
    fsSync.linkSync(candidate, file); linked = true;
    fsSync.unlinkSync(candidate);
    const published = fsSync.lstatSync(file);
    assert.ok(published.isFile() && published.nlink === 1
      && published.dev === candidateIdentity.dev && published.ino === candidateIdentity.ino);
    const dirDescriptor = fsSync.openSync(directory, fsSync.constants.O_RDONLY);
    try { fsSync.fsyncSync(dirDescriptor); } finally { fsSync.closeSync(dirDescriptor); }
  } catch (error) {
    const cleanupErrors = [];
    if (!closed) try { fsSync.closeSync(descriptor); } catch (closeError) { cleanupErrors.push(closeError); }
    if (!candidateIdentity) cleanupErrors.push(Error('V39 receipt candidate identity unavailable; retained'));
    else for (const target of linked ? [file, candidate] : [candidate]) try {
      const current = fsSync.lstatSync(target);
      if (current.dev !== candidateIdentity.dev || current.ino !== candidateIdentity.ino)
        throw Error('V39 receipt candidate changed; retained');
      fsSync.unlinkSync(target);
    } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') cleanupErrors.push(cleanupError);
    }
    if (cleanupErrors.length) throw new AggregateError([error, ...cleanupErrors],
      'V39 receipt publication failed with cleanup debt');
    throw error;
  }
}
const V39_ATOMIC_BROWSER_FIXED = new Set([
  'GET /api/secureshop/admin/policies',
  'GET /api/secureshop/admin/system/restart',
  'GET /api/secureshop/admin/system/diagnostic',
  'GET /api/secureshop/admin/access-control',
  'GET /api/secureshop/v2/auth/whoami',
  'GET /api/secureshop/auth/reset-readiness',
  'POST /api/secureshop/agents/admin/assistant/mcp/confirm',
  'POST /api/secureshop/agents/admin/session',
  'POST /api/secureshop/auth/login', 'POST /api/secureshop/auth/bootstrap',
  'GET /api/secureshop/auth/session', 'GET /api/secureshop/auth/reset-recovery',
  'GET /api/secureshop/auth/mode', 'POST /api/secureshop/auth/mode',
  'GET /api/secureshop/auth/progress', 'GET /api/secureshop/auth/assessment-objectives',
  'GET /api/secureshop/auth/assessments', 'GET /api/secureshop/v2/scenes',
  'GET /api/secureshop/v2/mcp-trust/readiness',
  'GET /api/secureshop/admin/mcp/servers', 'GET /api/secureshop/admin/mcp/schema-history',
  'POST /api/secureshop/agents/admin/assistant/session',
  'POST /api/secureshop/agents/admin/assistant/chat',
  'POST /api/secureshop/agents/admin/chat',
  'POST /api/secureshop/agents/admin/chat/description-assessment',
  'GET /api/changes/revisions',
]);
const v39AdmissionWitnesses = new WeakSet();
function retainV39Admission(objective, admitted, qualification, enabled) {
  assert.equal(objective.objectiveId, 'ss_mcp_description_instruction_adoption');
  assert.equal(objective.qualification, 'pending'); assert.equal(objective.enabled, false);
  assert.equal(admitted.rowCount, 1);
  assert.deepEqual(admitted.rows, [{ objective_id: objective.objectiveId, qualification: 'native-model', is_enabled: false }]);
  assert.equal(qualification, 'native-model'); assert.equal(enabled.enabled, true);
  const witness = Object.freeze({ objectiveId: objective.objectiveId,
    fixtureLocalCandidateAdmission: true, canonicalObjectiveEnabled: true });
  v39AdmissionWitnesses.add(witness); return witness;
}
function initializeV39Receipt(contract, witness, receipt = contract.createReceipt()) {
  assert.ok(v39AdmissionWitnesses.has(witness), 'observed V39 catalog admission required');
  assert.ok(receipt && typeof receipt === 'object');
  receipt.fixtureLocalCandidateAdmission = witness.fixtureLocalCandidateAdmission;
  receipt.canonicalObjectiveEnabled = witness.canonicalObjectiveEnabled;
  return receipt;
}
async function initializeObservedV39Receipt({ contract, witness, receipt, admission, pools, scope, actor, issued }) {
  const authority = require('../../server/services/secureshopAssessmentReleaseAdmission')
    .resolveAssessmentReleaseAdmission(admission, { identityPool: pools.IDENTITY_RUNTIME,
      agentsPool: pools.AGENTS_RUNTIME, reviewPool: pools.REVIEW_RUNTIME, commercePool: pools.COMMERCE_RUNTIME });
  assert.equal(authority.isCandidate('ss_mcp_description_instruction_adoption'), true);
  // Rechecks all eight actual database identities and current launch/session.
  await authority.assertScope(scope);
  assert.equal(issued.persona.user.username, 'student_admin');
  assert.equal(actor.user.role, 'admin');
  assert.ok(actor.sessionId && actor.authorityVersion != null);
  const value = initializeV39Receipt(contract, witness, receipt);
  value.isolatedStores = true; value.registeredAdminAuthority = true;
  return value;
}
function registryBrowserLoginUrl(origin, atomicPair = false) {
  return `${origin}/secureshop/login${atomicPair ? '?next=%2Fsecureshop%2Fadmin%2Fmcp' : ''}`;
}
function v39AtomicBrowserRequestAllowed({ origin, build, url, method }) {
  let target;
  try { target = new URL(url); } catch { return false; }
  if (target.origin !== origin || target.username || target.password
    || target.pathname.includes('%')) return false;
  const pathname = target.pathname;
  if (target.hash && (pathname !== '/secureshop-frame.html'
    || !/^#[a-f0-9]{64}$/.test(target.hash))) return false;
  if (pathname.startsWith('/api/')) {
    if (pathname === '/api/secureshop/auth/admin/progress/learners') {
      return method === 'GET' && target.search === '?limit=25';
    }
    if (target.search) return false;
    if (V39_ATOMIC_BROWSER_FIXED.has(`${method} ${pathname}`)) return true;
    const U = '[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
    return method === 'GET' && [
      new RegExp(`^/api/secureshop/agents/admin/assistant/operations/${U}/${U}$`),
      new RegExp(`^/api/secureshop/agents/admin/chat/requests/${U}/${U}$`),
      new RegExp(`^/api/secureshop/agents/admin/chat/description-assessment/${U}/${U}$`),
      new RegExp(`^/api/secureshop/admin/mcp/operations/${U}$`),
      /^\/api\/secureshop\/admin\/mcp\/servers\/[a-z0-9][a-z0-9_-]{0,63}\/tools$/,
    ].some(pattern => pattern.test(pathname));
  }
  if (method !== 'GET') return false;
  if (pathname === '/secureshop/login'
    && target.search === '?next=%2Fsecureshop%2Fadmin%2Fmcp') return true;
  if ((pathname === '/secureshop/login' || pathname === '/secureshop/admin/mcp')
    && target.search === '') return true;
  if (pathname === '/secureshop-frame.html') {
    const params = target.searchParams;
    return [...params.keys()].sort().join(',') === 'entry,standalone'
      && params.get('entry') === '/secureshop/admin/mcp' && params.get('standalone') === '1';
  }
  if (target.search || !(/^\/assets\/[A-Za-z0-9_.-]+\.(?:js|css|woff2|svg|png|webp)$/
    .test(pathname) || pathname === '/favicon.svg')) return false;
  try { const file = path.join(fsSync.realpathSync(build), pathname.slice(1));
    const entry = fsSync.lstatSync(file);
    return entry.isFile() && !entry.isSymbolicLink() && fsSync.realpathSync(file) === file;
  } catch { return false; }
}
function createV39AtomicBrowserAudit({ origin, build, maximumRequests = 1200 }) {
  assert.ok(Number.isSafeInteger(maximumRequests) && maximumRequests > 0 && maximumRequests <= 1200);
  const pending = new Set(), denied = [];
  let total = 0, apiRequests = 0, interceptionErrors = 0;
  const snapshot = () => ({ total, apiRequests, denied: structuredClone(denied), interceptionErrors });
  return Object.freeze({
    intercept(request) {
      total += 1;
      const url = request.url(), method = request.method();
      let pathname = 'invalid';
      try { const parsed = new URL(url); pathname = parsed.pathname;
        if (parsed.origin === origin && pathname.startsWith('/api/')) apiRequests += 1;
      } catch { /* Invalid URLs are denied without retaining their bytes. */ }
      const allowed = total <= maximumRequests && apiRequests <= maximumRequests
        && v39AtomicBrowserRequestAllowed({ origin, build, url, method });
      if (!allowed && denied.length < 16) {
        // Retain only source-declared static paths, never arbitrary URL/path
        // segments, credentials, query values, fragment bytes or bodies.
        const known = ['/secureshop/login', '/secureshop/admin', '/secureshop/admin/mcp',
          '/secureshop-frame.html', ...[...V39_ATOMIC_BROWSER_FIXED].map(row => row.split(' ')[1])];
        denied.push({ method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) ? method : 'OTHER',
          path: known.includes(pathname) ? pathname : '[unrecognized-path]',
          pathSha256: createHash('sha256').update(pathname).digest('hex') });
      }
      let task;
      try { task = allowed ? request.continue() : request.abort(); }
      catch { interceptionErrors += 1; return; }
      const observed = Promise.resolve(task).then(() => {}, () => { interceptionErrors += 1; });
      pending.add(observed);
      void observed.then(() => pending.delete(observed));
    },
    async finish(retain = async () => {}) {
      await Promise.all([...pending]);
      await retain(snapshot()); // Failure evidence precedes admission assertions.
      assert.equal(denied.length, 0, 'atomic pair browser requested an unowned route or exceeded its cap');
      assert.equal(interceptionErrors, 0, 'atomic pair browser interception did not settle cleanly');
      return snapshot();
    }, snapshot,
  });
}
function privateCurrentHostBrowserOptions({ directory, origin, profile, executablePath }) {
  const ordinary = { headless: true, userDataDir: profile, executablePath };
  if (!directory) return ordinary;
  const target = new URL(origin);
  assert.equal(target.origin, origin);
  assert.equal(target.protocol, 'http:'); assert.equal(target.hostname, '127.0.0.1');
  assert.match(target.port, /^[1-9][0-9]{0,4}$/);
  assert.equal(target.pathname, '/'); assert.equal(target.search, ''); assert.equal(target.hash, '');
  assert.equal(path.dirname(profile), path.join(directory, 'tmp'));
  assert.match(path.basename(profile), /^owasp-ai-goat-mcp-registry-rendered-[A-Za-z0-9_-]+$/);
  const info = fsSync.lstatSync(profile);
  assert.ok(info.isDirectory() && !info.isSymbolicLink());
  assert.equal(info.uid, process.getuid()); assert.equal(info.mode & 0o777, 0o700);
  assert.equal(fsSync.realpathSync(profile), profile);
  return { ...ordinary, args: ['--no-sandbox', '--disable-background-networking',
    '--disable-component-update', '--disable-domain-reliability', '--disable-quic',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--proxy-server=http://blocked.invalid:9',
    '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'] };
}
function v39CurrentHostBrowserOptions(options) {
  return privateCurrentHostBrowserOptions(options);
}
function q05CurrentHostBrowserOptions(options) {
  assert.equal(typeof options?.directory, 'string', 'Q05 private browser requires admitted evidence');
  for (const directory of [options.directory, path.join(options.directory, 'tmp')]) {
    const owner = fsSync.lstatSync(directory);
    assert.ok(owner.isDirectory() && !owner.isSymbolicLink()
      && owner.uid === process.getuid() && (owner.mode & 0o777) === 0o700
      && fsSync.realpathSync(directory) === directory,
    'Q05 private browser owner changed');
  }
  return privateCurrentHostBrowserOptions(options);
}
function createV39BrowserDiagnostic({ origin, write }) {
  const target = new URL(origin);
  assert.equal(target.origin, origin); assert.equal(target.hostname, '127.0.0.1');
  let phase = 'launch-requested', child, recorded = false;
  let stderr = Buffer.alloc(0), observed = 0;
  const onData = chunk => {
    const bytes = Buffer.from(chunk);
    observed = Math.min(16385, observed + bytes.length);
    if (stderr.length < 16384) stderr = Buffer.concat([stderr, bytes.subarray(0, 16384 - stderr.length)]);
  };
  const attach = browser => {
    assert.equal(phase, 'launch-requested');
    child = browser.process();
    assert.ok(Number.isSafeInteger(child?.pid) && child.pid > 1);
    child.stderr?.on('data', onData);
    phase = 'launch-returned';
  };
  const advance = next => {
    const stages = ['launch-requested', 'launch-returned', 'page-created',
      'viewport-ready', 'target-guard-ready'];
    assert.equal(stages.indexOf(next), stages.indexOf(phase) + 1);
    phase = next;
  };
  const record = error => {
    if (recorded) return;
    child?.stderr?.off('data', onData);
    write('v39-browser-diagnostic.json', JSON.stringify({ version: 1,
      scope: 'V39-current-host-pre-model-browser-v1', origin, phase,
      browserPid: child?.pid ?? null, browserExitCodeAtRecord: child?.exitCode ?? null,
      browserSignalCodeAtRecord: child?.signalCode ?? null,
      stderrCapture: 'post-launch-through-target-guard',
      stderrObservedBytes: observed, stderrTruncated: observed > stderr.length,
      stderr: stderr.toString('utf8'),
      failure: error ? { name: String(error.name).slice(0, 80),
        message: String(error.message).slice(0, 1024) } : null }, null, 2) + '\n');
    recorded = true;
  };
  return { attach, advance, record };
}
async function clickRendered(frame, { label, selector, diagnosticPath } = {}) {
  let button;
  try { button = await waitFor(async () => {
    const candidates = selector ? await frame.$$(selector) : await frame.$$('button');
    for (const candidate of candidates) {
      if (label && await candidate.evaluate((node, expected) => node.textContent.trim() !== expected,
        label).catch(() => true)) continue;
      const scrolled = await candidate.evaluate(node => {
        if (!node.isConnected) return false;
        node.scrollIntoView({ block: 'center', inline: 'center' });
        return true;
      }).catch(() => false);
      if (!scrolled) continue;
      const first = await candidate.evaluate(node => {
        const rect = node.getBoundingClientRect();
        return [rect.x, rect.y, rect.width, rect.height];
      }).catch(() => null);
      await new Promise(resolve => setTimeout(resolve, 80));
      const reachable = await candidate.evaluate((node, before) => {
        if (!node.isConnected || node.disabled) return false;
        const a = node.getBoundingClientRect();
        if (!before || [a.x, a.y, a.width, a.height]
          .some((value, index) => Math.abs(value - before[index]) > 2)) return false;
        const left = Math.max(0, a.left), right = Math.min(innerWidth, a.right);
        const topEdge = Math.max(0, a.top), bottom = Math.min(innerHeight, a.bottom);
        if (right - left < 2 || bottom - topEdge < 2) return false;
        const x = (left + right) / 2, y = (topEdge + bottom) / 2;
        const top = document.elementFromPoint(x, y);
        return top === node || node.contains(top)
          ? { x: x - a.left, y: y - a.top } : false;
      }, first).catch(() => false);
      if (reachable) return { candidate, offset: reachable };
    }
    return null;
  }, `rendered action ${selector || label}`, 15000); }
  catch (error) {
    if (!diagnosticPath || error.code !== 'OBSERVATION_TIMEOUT') throw error;
    const geometry = await frame.evaluate(query => [...document.querySelectorAll(query)].slice(0, 4)
      .map(node => { const r = node.getBoundingClientRect();
        const x = Math.max(0, Math.min(innerWidth, (Math.max(0, r.left) + Math.min(innerWidth, r.right)) / 2));
        const y = Math.max(0, Math.min(innerHeight, (Math.max(0, r.top) + Math.min(innerHeight, r.bottom)) / 2));
        return { connected: node.isConnected, disabled: Boolean(node.disabled),
          rect: [r.x, r.y, r.width, r.height].map(Math.round),
          viewport: [innerWidth, innerHeight], topTag: document.elementFromPoint(x, y)?.tagName || null };
      }), selector).catch(() => []);
    await fs.writeFile(diagnosticPath, await frame.page().screenshot({ fullPage: false }),
      { flag: 'wx', mode: 0o600 }).catch(() => {});
    throw Object.assign(new Error(`${error.message}; geometry=${JSON.stringify(geometry).slice(0, 1200)}`),
      { code: error.code });
  }
  await button.candidate.click({ offset: button.offset });
}
async function dropOneCommittedRegistration(page, endpoint, kind = 'registration') {
  assert(['registration', 'discovery-assessment'].includes(kind));
  const cdp = await page.createCDPSession();
  let captured, failure; const pending = new Set();
  const onPaused = event => {
    const work = (async () => {
      if (!captured && event.request.url === endpoint && event.request.method === 'POST') {
        assert.equal(event.responseStatusCode, 200, 'only a real committed registry ACK is lost');
        const request = JSON.parse(event.request.postData);
        const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
        const receipt = JSON.parse(Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8').toString());
        if (kind === 'discovery-assessment') {
          assert.deepEqual(Object.keys(request).sort(), ['proposalId', 'requestId', 'sessionId']);
          assert(Object.values(request).every(value => UUID.test(value)));
          assert.equal(receipt.completed, true); assert.equal(receipt.replayed, false);
          assert.equal(receipt.judgment?.verdict, 'pass'); assert(UUID.test(receipt.judgment.evaluationId));
        } else {
          assert.equal(receipt.ok, true); assert.equal(receipt.state, 'completed');
          assert.equal(receipt.operationId, request.operationId); assert.equal(request.name, NAME);
          assert.equal(request.transport, 'sse'); assert.equal(request.url, PEER);
        }
        captured = { request, receipt };
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => {
      failure = error;
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    pending.add(work); void work.finally(() => pending.delete(work));
  };
  cdp.on('Fetch.requestPaused', onPaused);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
  return { captured() { if (failure) throw failure; return captured; }, async close() {
    await Promise.all([...pending]); await cdp.send('Fetch.disable');
    cdp.off('Fetch.requestPaused', onPaused); await cdp.detach(); if (failure) throw failure;
  } };
}

if (!D16_ENABLED) test(V42_ENABLED
  ? 'standalone admin confirms model-selected owned internal MCP discovery with canonical Judge evidence and fixed isolation'
  : V39_PAIR_ENABLED
  ? 'standalone admin compares clean and treatment registered descriptions with independent physical Judge evidence'
  : V39_ENABLED
  ? 'standalone admin adopts a registered tool description after original competing catalog and canonical Judge evidence'
  : Q05_HANDOFF_ENABLED
  ? 'standalone admin completes saved registered handoff by physical Ask, one owned invocation, and exact GET recovery'
  : V66_ENABLED
  ? 'standalone admin confirms model-selected owned MCP manifest import with canonical Judge evidence'
  : V43_ENABLED
    ? 'standalone admin replaces a trusted MCP server and genuinely invokes its impersonated tool with canonical Judge evidence'
    : 'standalone admin registers, inspects, recovers, and removes an owned MCP server in the rendered UI',
  { skip: !ENABLED, timeout: 240000 }, async () => {
    const root = path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(root, process.cwd(), 'reviewed current-main source required');
    const evidencePath = Q05_HANDOFF_ENABLED ? process.env.MCP_REGISTERED_HANDOFF_Q05_RESULT || ''
      : V42_ENABLED ? process.env.MCP_REGISTRY_SSRF_V42_RESULT || ''
      : V39_ENABLED ? process.env.MCP_DESCRIPTION_V39_RESULT || ''
      : V66_ENABLED ? process.env.MCP_MANIFEST_V66_RESULT || ''
      : process.env.MCP_REGISTRY_RENDERED_RESULT || '';
    const v39Directory = V39_CURRENT_HOST_EVIDENCE
      ? admitV39CurrentHostEvidence({ env: process.env, source: root,
        evidencePath, enabled: V39_ENABLED && ENABLED }) : null;
    const q05Directory = Q05_CURRENT_HOST_EVIDENCE
      ? admitQ05CurrentHostEvidence({ env: process.env, source: root,
        evidencePath, enabled: Q05_HANDOFF_ENABLED && ENABLED }) : null;
    assert.ok(!v39Directory || !q05Directory, 'rendered evidence cohorts are exclusive');
    if (!v39Directory && !q05Directory) assert.ok(path.isAbsolute(evidencePath)
      && !path.resolve(evidencePath).startsWith(`${root}${path.sep}`));
    const build = path.resolve(process.env.MCP_REGISTRY_RENDERED_BUILD || '/');
    assert.equal(build, path.join(root, 'client/build'));
    await fs.access(path.join(build, 'index.html')); await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    const executorUrl = new URL(process.env.MCP_ASSEMBLY_EXECUTOR_URL || '');
    assert.equal(executorUrl.protocol, 'http:'); assert.equal(executorUrl.hostname, '127.0.0.1');
    assert.equal(executorUrl.pathname, '/'); assert.equal(executorUrl.search, '');
    assert.match(process.env.MCP_ASSEMBLY_EXECUTOR_TOKEN || '', /^[A-Za-z0-9_-]{43,128}$/);
    assert.match(process.env.MCP_ASSEMBLY_EXECUTOR_DIGEST || '', HEX);
    const urls = disposableUrls();
    const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
      const key = `${store}_${role}`;
      return [key, new Pool({ connectionString: urls[key], max: role === 'RUNTIME' ? 12 : 3,
        connectionTimeoutMillis: 5000, statement_timeout: 10000 })];
    })));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4,
      connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    const status = { status: 'running', scope: Q05_HANDOFF_ENABLED ? 'Q05-registered-handoff-standalone'
      : V42_ENABLED ? 'V42-standalone'
      : V39_PAIR_ENABLED ? 'V39-atomic-pair-standalone' : V39_ENABLED ? 'V39-standalone'
      : V66_ENABLED ? 'V66-standalone' : 'standalone-registry-rendered',
      modelCalls: 0, browserCalls: 0,
      standaloneAdminRendered: false, ownedNamespaceRegistration: false,
      renderedToolsAndHistory: false, exactSavedOperationReadback: false,
      renderedManifestImportSaved: false,
      renderedRemovalHistoryRetained: false, siblingDenied: false,
      cleanupComplete: false, cleanupErrors: [] };
    const v39Writer = v39Directory
      ? createV39PrivateWriter(v39Directory, { atomicPair: V39_PAIR_ENABLED }) : null;
    const q05Writer = q05Directory ? createQ05PrivateWriter(q05Directory) : null;
    const privateWriter = v39Writer || q05Writer;
    let v39BrowserDiagnostic, v39AtomicBrowserAudit;
    const save = () => privateWriter
      ? Promise.resolve(privateWriter.write('candidate-result.json', JSON.stringify(status, null, 2) + '\n'))
      : fs.writeFile(evidencePath, JSON.stringify(status, null, 2) + '\n', { mode: 0o600 });
    const v43Contract = require('../fixtures/secureshopMcpRegistryExploitQualification');
    const v39Contract = V39_ENABLED || Q05_HANDOFF_ENABLED
      ? require('../fixtures/secureshopMcpDescriptionRenderedQualification') : null;
    const v39Receipt = V39_ENABLED && !V39_PAIR_ENABLED ? v39Contract.createReceipt() : null;
    const handoffReceipt = Q05_HANDOFF_ENABLED ? v39Contract.createHandoffReceipt() : null;
    const v66Contract = V66_ENABLED || V42_ENABLED ? require('../fixtures/secureshopMcpManifestQualification') : null;
    const v66Receipt = V66_ENABLED ? v66Contract.createV66Receipt() : null;
    const v42Receipt = V42_ENABLED ? v66Contract.createV42Receipt() : null;
    const v43Receipt = V43_ENABLED ? Object.fromEntries(v43Contract.V43_FLAGS.map(key => [key, false])) : null;
    if (v43Receipt) Object.assign(v43Receipt, { scope: v43Contract.V43_SCOPE,
      actorCalls: 0, judgeCalls: 0, actualTurns: 0, genuineCredit: 0, errors: [] });
    if (q05Writer) await q05InitialPrivateSave(save, q05Writer);
    else await save();
    let composition, registry, server, browser, profile, dropper, failure;
    let v43Transport, v43Recorder, registeredInvocation, v39PairTransport, v39PairReceipt, handoffLoss;
    let v39PairArm, v39PairIds, v39ActiveArm = 'control';
    let captureV39Model, recordV39Wire;
    let executorCalls = 0;
    const executorObservations=[];
    try {
      for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop']]) {
        await migrate(pools[`${store}_MIGRATION`], path.join(root, 'db/postgres', directory));
      }
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seedClient = await pools.COMMERCE_MIGRATION.connect();
      try { await seedClient.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
        await seedClient.query('COMMIT');
      } catch (error) { await seedClient.query('ROLLBACK'); throw error; }
      finally { seedClient.release(); }
      if (v43Receipt) v43Receipt.isolatedStores = true;
      if (v39Receipt) v39Receipt.isolatedStores = true;
      if (handoffReceipt) handoffReceipt.isolatedStores = true;
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const assessmentReleaseAdmission = V39_ENABLED
        ? await require('../../server/services/secureshopAssessmentReleaseAdmission')
          .createDisposableAssessmentReleaseAdmission({
            stores: Object.fromEntries(Object.keys(STORES).map(store => [store.toLowerCase(), {
              runtimePool: pools[`${store}_RUNTIME`], migrationPool: pools[`${store}_MIGRATION`],
              runtimeUrl: urls[`${store}_RUNTIME`], migrationUrl: urls[`${store}_MIGRATION`],
            }])),
            objectiveIds: ['ss_mcp_description_instruction_adoption'],
          }) : undefined;
      const platformBefore = (await identity.query(`SELECT
        (SELECT count(*)::integer FROM identity.users) AS users,
        (SELECT count(*)::integer FROM identity.user_sessions) AS sessions`)).rows[0];
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review, includeRunArtifacts: true });
      const registryConfiguration = {
        version: 1, workspace: require('../../server/services/mcp/ownedManagedConfiguration').workspaceId(root),
        enabled: true, mode: 'vuln', baseURL: executorUrl.origin,
        token: process.env.MCP_ASSEMBLY_EXECUTOR_TOKEN,
        runtimeDigest: process.env.MCP_ASSEMBLY_EXECUTOR_DIGEST,
      };
      const invocationInfrastructure = MODEL_REGISTRY_ENABLED
        ? require('../../server/services/secureshopRegisteredInvocationProduction')
          .createRegisteredInvocationInfrastructure({ configuration: registryConfiguration,
            identityPool: identity, agentsPool: agents }) : undefined;
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, audit,
          ...(MODEL_REGISTRY_ENABLED ? { registeredInvocation: invocationInfrastructure } : {}) });
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const noJudge = async () => { status.modelCalls++; throw Error('No Judge admitted in MCP registry cohort'); };
      if (MODEL_REGISTRY_ENABLED) {
        const evidenceDirectory = path.dirname(evidencePath);
        const captureModel = value => {
          const name = Q05_HANDOFF_ENABLED ? 'registered-handoff-model.json'
            : V42_ENABLED ? 'mcp-discovery-model.json'
            : V39_PAIR_ENABLED ? `mcp-description-atomic-${v39ActiveArm}-model.json`
            : V39_ENABLED ? 'mcp-description-model.json'
            : V66_ENABLED ? 'mcp-manifest-model.json' : 'mcp-impersonation-model.json';
          const bytes = JSON.stringify(value, null, 2) + '\n';
          if (privateWriter) privateWriter.write(name, bytes);
          else fsSync.writeFileSync(path.join(evidenceDirectory, name), bytes, { mode: 0o600 });
        };
        if (V39_PAIR_ENABLED) captureV39Model = captureModel;
        const recordWire = value => {
            const name = V42_ENABLED ? 'mcp-discovery-wire.json'
              : Q05_HANDOFF_ENABLED ? 'registered-handoff-wire.json'
              : V39_PAIR_ENABLED ? `mcp-description-atomic-${v39ActiveArm}-wire.json`
              : V39_ENABLED ? 'mcp-description-wire.json'
              : V66_ENABLED ? 'mcp-manifest-wire.json' : 'mcp-impersonation-wire.json';
            const bytes = JSON.stringify(value, null, 2) + '\n';
            if (privateWriter) privateWriter.write(name, bytes);
            else fsSync.writeFileSync(path.join(evidenceDirectory, name), bytes, { mode: 0o600 });
        };
        if (V39_PAIR_ENABLED) recordV39Wire = recordWire;
        if (V39_PAIR_ENABLED) {
          const ids = { control: randomUUID().replaceAll('-', ''),
            treatment: randomUUID().replaceAll('-', '') };
          v39PairIds = ids;
          v39PairTransport = require('./secureshopMailActualTransport')
            .createMcpDescriptionAtomicPairTransport({ controlRunId: ids.control,
              treatmentRunId: ids.treatment, record: (arm, value) => {
                assert.equal(arm, v39ActiveArm, 'retired arm cannot write the next arm artifact');
                recordWire(value);
              } });
          v39PairArm = await v39PairTransport.beginArm('control', ids.control);
          v43Transport = v39PairArm.transport;
        } else v43Transport = await require('./secureshopMailActualTransport').createMailActualTransport({
          maxHttpCalls: Q05_HANDOFF_ENABLED ? 12 : V42_ENABLED ? 5 : V66_ENABLED ? v66Contract.V66_MAX_HTTP_CALLS : 14,
          allowMetadata: true, record: recordWire,
        });
        v43Recorder = require('../fixtures/secureshopMcpRegistryExploitQualification')
          .createV43ModelRecorder({ transport: v43Transport, record: captureModel });
      }
      const pairJudge = V39_PAIR_ENABLED ? (...args) => v43Recorder.judge(...args) : null;
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset, assessmentReleaseAdmission,
          judge: MODEL_REGISTRY_ENABLED ? pairJudge || v43Recorder.judge : noJudge,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const provider = MODEL_REGISTRY_ENABLED ? v43Recorder.provider : { async chat() { status.modelCalls++; throw Error('No model admitted'); },
        async finalResponse() { status.modelCalls++; throw Error('No model admitted'); } };
      const toolPolicyRepository = MODEL_REGISTRY_ENABLED
        ? require('../../server/database/postgres/secureshopBoundAclRepository')
          .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
            audit: reset.audit.agents }) : undefined;
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, assessmentReleaseAdmission, scenes, modeAuthority, ownedMcpRegistryReads: true,
          ...(MODEL_REGISTRY_ENABLED ? { toolPolicyRepository, judge: pairJudge || v43Recorder.judge,
            personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
              .activationPolicy(process.env).requested,
            mcpRegistryApplication: () => registry ? { mode: registryConfiguration.mode,
              service: registry.service } : null,
            ...q05RegisteredInvocationCompositionOptions(Q05_HANDOFF_ENABLED,
              () => registeredInvocation) } : {}),
          fixtures: [], requiredObjectives: ['ss_stored_browser_execution'],
          jwtSecret: 'disposable-mcp-registry-persona-secret-at-least-32-bytes',
          agentRuntime: { provider } });
      await composition.repositories.personas.ensureTemplates();
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const protectedReset = require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes,
          resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight });
      registry = await require('../../server/services/secureshopOwnedMcpRegistryProduction')
        .createOwnedMcpRegistryProduction({ configuration: registryConfiguration,
        agentsPool: agents, personaAuthority: grading.personaAuthority,
        authenticatePersona: composition.personaAuth.authenticatePersona,
        expectedDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1),
        createClient: options => {
          const actual = require('../../server/services/secureshopOwnedMcpRegistryClient')
            .createOwnedMcpRegistryClient(options);
          return Object.freeze({ ...actual, async execute(...args) {
            executorCalls += 1;
            try{const value=await actual.execute(...args);executorObservations.push({request:structuredClone(args[0]),mode:args[1]?.mode,result:structuredClone(value)});return value;}
            catch(error){executorObservations.push({request:structuredClone(args[0]),mode:args[1]?.mode,error:{code:error.code,effectNotStarted:error.effectNotStarted===true,drained:error.drained===true}});throw error;}
          } });
        } });
      assert.equal(registry.ready, true); await registry.assertReady();
      if (MODEL_REGISTRY_ENABLED) {
        assert.equal(composition.roleAssistants.admin.ready, true);
        registeredInvocation = await require('../../server/services/secureshopRegisteredInvocationProduction')
          .createRegisteredInvocationProduction({ infrastructure: invocationInfrastructure,
            resetComposition: reset, provider, authenticatePersona: composition.personaAuth.authenticatePersona,
            migrationPool: pools.AGENTS_MIGRATION, modeAuthority, identityPool: identity,
            gradingBootstrap: grading, judge: pairJudge || v43Recorder.judge, assessmentReleaseAdmission });
        assert.equal(registeredInvocation.ready, true);
      }
      const mountedRegistry = V42_ENABLED ? v66Contract.currentRegistryMount(() => registry) : registry;
      const mounted = { ...composition, scenes, ownedMcpRegistry: mountedRegistry,
        standaloneAuth: { service: auth, bootstrap, reset: protectedReset } };
      if (MODEL_REGISTRY_ENABLED) {
        const envelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
          .createRegisteredAdminResetEnvelope({ activeKeyId: 'v43-owned',
            keys: new Map([['v43-owned', require('node:crypto').randomBytes(32)]]) });
        const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
          .createRegisteredAdminResetRepository({ pool: identity, envelope });
        await resetRepository.checkReadiness();
        if (registeredInvocation) mounted.registeredInvocation = registeredInvocation;
        mounted.publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
          .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
            reviewPool: review, commercePool: commerce });
        Object.assign(mounted.standaloneAuth, {
          ...(V42_ENABLED || V39_ENABLED ? { assessmentProgress:
            require('../../server/services/secureshopAssessmentProgress').createSecureShopAssessmentProgress({
              repository: require('../../server/database/postgres/secureshopAssessmentProgressRepository')
                .createSecureShopAssessmentProgressRepository({ pool: identity, assessmentReleaseAdmission }),
            }) } : {}),
          registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
            .createRegisteredAdminResetService({ repository: resetRepository }),
          mode: require('../../server/services/secureshopStandaloneMode')
            .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository }),
          assessmentObjectives: require('../../server/services/secureshopAssessmentCatalog')
            .createSecureShopAssessmentCatalog({ pool: identity, authService: auth, assessmentReleaseAdmission }),
          assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
            .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
              bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
              personaAuthority: grading.personaAuthority, judge: pairJudge || v43Recorder.judge,
              assessmentReleaseAdmission }),
          cartImport: require('../../server/services/secureshopStandaloneCartImport')
            .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
              personaAuth: composition.personaAuth, commerce: composition.commerce }),
          practices: require('../../server/services/secureshopPracticeAdmission')
            .createSecureShopPracticeAdmission({ repository:
              require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
                .createSecureShopPracticeAdmissionRepository({ pool: identity }),
              catalog: composition.catalog }),
        });
      }
      // The bound application requires all panel mounts. These unrelated
      // panels expose no fixture routes; the MCP registry router is real.
      for (const panel of MODEL_REGISTRY_ENABLED ? [] : ['personaInbox', 'mcpTrust', 'ssrf']) {
        mounted[panel] = Object.freeze({ ready: true, router: express.Router() });
      }
      const v43JsonCaptures = [];
      const v43Json = MODEL_REGISTRY_ENABLED
        ? require('../fixtures/secureshopMcpRegistryExploitQualification') : null;
      const app = express(); app.use(express.json(MODEL_REGISTRY_ENABLED ? {
        verify: (request, response, bytes) => {
          v43Json.captureV43JsonRequestBody(request, response, bytes);
          if (V66_ENABLED || V42_ENABLED) v66Contract.captureV66Body(request, response, bytes);
          if (V39_ENABLED) v39Contract.captureBody(request, response, bytes);
        },
      } : {}));
      let handoffBinding;
      if (Q05_HANDOFF_ENABLED) {
        handoffLoss = v39Contract.createCommittedRegisteredSseLoss({
          readCompleted: async ({ sessionId, requestId }) => {
            assert.ok(handoffBinding, 'physical owner binding required before interception');
            const row = await reset.journal.readRegisteredAdminRequest({ binding: handoffBinding,
              sessionId, requestId });
            assert.equal(row?.status, 'completed');
            return { status: row.status, replayed: true, result: row.result_json };
          },
          record: value => q05Writer
            ? q05Writer.write('registered-handoff-committed-loss.json', JSON.stringify(value, null, 2) + '\n')
            : fsSync.writeFileSync(path.join(path.dirname(evidencePath),
              'registered-handoff-committed-loss.json'), JSON.stringify(value, null, 2) + '\n',
            { mode: 0o600, flag: 'wx' }),
        });
        app.use(handoffLoss.middleware);
      }
      if (MODEL_REGISTRY_ENABLED) app.use((request, response, next) => {
        if (!V66_ENABLED && !V42_ENABLED) v43Json.observeOriginalV43Json(request, response, v43JsonCaptures);
        if (V39_ENABLED) v39Contract.observeJson(request, response, v43JsonCaptures);
        if (V66_ENABLED || V42_ENABLED) v66Contract.observeV66Json(request, response, v43JsonCaptures);
        next();
      });
      let requestHeaders;
      const observedOperations = [];
      const v43Bootstraps = [];
      app.use((request, _response, next) => {
        if (MODEL_REGISTRY_ENABLED && request.method === 'POST' && request.path === '/api/secureshop/auth/bootstrap') {
          const original = _response.json;
          _response.json = function (...args) {
            const result = original.apply(this, args);
            if (_response.statusCode === 200 && args[0]?.persona?.user?.role === 'admin') {
              v43Bootstraps.push(structuredClone(args[0]));
            }
            return result;
          };
        }
        if (request.path.startsWith('/api/secureshop/admin/mcp/')
            && ['POST', 'DELETE'].includes(request.method)
            && typeof request.body?.operationId === 'string') {
          observedOperations.push({ method: request.method, path: request.path,
            action: request.body.action, operationId: request.body.operationId });
        }
        if (request.method === 'POST' && request.path === '/api/secureshop/admin/mcp/register') {
          requestHeaders = { authorization: request.headers.authorization,
            'x-owasp-ai-goat-secureshop-launch': request.headers['x-owasp-ai-goat-secureshop-launch'],
            cookie: request.headers.cookie, 'content-type': 'application/json' };
        }
        next();
      });
      server = await new Promise(resolve => { const opened = app.listen(0, '127.0.0.1', () => resolve(opened)); });
      const origin = `http://127.0.0.1:${server.address().port}`;
      if (v39Writer) v39BrowserDiagnostic = createV39BrowserDiagnostic({ origin,
        write: (name, body) => v39Writer.write(name, body) });
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          ...(MODEL_REGISTRY_ENABLED ? { applicationMode: 'standalone' } : {}),
          authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap,
          reset: protectedReset,
          ...(MODEL_REGISTRY_ENABLED ? mounted.standaloneAuth : {}),
          allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      if (MODEL_REGISTRY_ENABLED) app.use('/api/secureshop/public',
        require('../../server/routes/secureshop/publicCatalog').createSecureShopPublicCatalogRouter({
          getRepository: () => mounted.publicCatalog, isAvailable: () => bound.standaloneReadiness.ready,
        }));
      app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside registry qualifier' }));
      app.use(express.static(build, { setHeaders: response => response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-mcp-registry-rendered-'));
      assert.ok(profile.startsWith(`${path.resolve(process.env.TMPDIR || os.tmpdir())}${path.sep}`));
      status.browserCalls = 1;
      browser = await require('puppeteer').launch(q05Directory
        ? q05CurrentHostBrowserOptions({ directory: q05Directory, origin, profile, executablePath })
        : v39CurrentHostBrowserOptions({ directory: v39Directory, origin, profile, executablePath }));
      v39BrowserDiagnostic?.attach(browser);
      const page = await browser.newPage(); v39BrowserDiagnostic?.advance('page-created');
      await page.setViewport({ width: 1280, height: 900 });
      v39BrowserDiagnostic?.advance('viewport-ready');
      await page.setRequestInterception(true);
      if (V39_PAIR_ENABLED) v39AtomicBrowserAudit = createV39AtomicBrowserAudit({ origin, build });
      page.on('request', request => V39_PAIR_ENABLED
        ? v39AtomicBrowserAudit.intercept(request)
        : request.url().startsWith(`${origin}/`)
          ? request.continue() : request.abort());
      v39BrowserDiagnostic?.advance('target-guard-ready');
      v39BrowserDiagnostic?.record(null);
      const apiStatuses = [];
      page.on('response', response => {
        const pathname = new URL(response.url()).pathname;
        if (pathname.startsWith('/api/secureshop/')) apiStatuses.push({
          method: response.request().method(), path: pathname, status: response.status() });
      });
      assert.ok([200, 304].includes((await page.goto(registryBrowserLoginUrl(origin, V39_PAIR_ENABLED))).status()));
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', 'student_admin');
      await page.type('#ss-login-pw', 'student123');
      await page.click('button[type="submit"]');
      await frameOn(page);
      assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/admin/mcp`)).status()));
      let frame = await frameOn(page);
      if (MODEL_REGISTRY_ENABLED) {
        assert.equal(bound.standaloneReadiness.ready, true);
        assert.equal(Object.keys(bound.standaloneReadiness.checks).length, 10);
        assert.ok(Object.values(bound.standaloneReadiness.checks).every(value => value === true));
        const issued = v43Bootstraps.at(-1);
        assert.ok(issued?.bearer && issued.persona.user.username === 'student_admin');
        const scope = await composition.launches.resolveCapability(issued.bearer);
        const actor = await composition.personaAuth.authenticateBoundToken({ scope, token: issued.persona.token });
        assert.equal(actor.user.role, 'admin');
        const binding = require('../../server/services/secureshopConversationBinding')
          .createConversationBinding(scope, { role: 'admin', id: actor.user.id });
        const personaSession = { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion };
        const headers = { authorization: `Bearer ${issued.persona.token}`,
          'x-owasp-ai-goat-secureshop-launch': issued.bearer };
        const cookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
          .find(value => value.name === 'owasp_ai_goat_shop_session');
        assert.ok(cookie?.httpOnly);
        const ownerBase = await auth.authenticate(cookie.value);
        const principal = await auth.establishTenantContext(ownerBase);
        if (v43Receipt) v43Receipt.registeredAdminAuthority = true;
        if (v39Receipt) v39Receipt.registeredAdminAuthority = true;
        if (handoffReceipt) handoffReceipt.registeredAdminAuthority = true;
        const catalog = mounted.standaloneAuth.assessmentObjectives;
        const objective = Q05_HANDOFF_ENABLED ? null : (await catalog.list(ownerBase)).objectives
          .find(value => value.objectiveId === (V42_ENABLED ? 'ss_mcp_registry_internal_discovery' : V39_ENABLED ? 'ss_mcp_description_instruction_adoption'
            : V66_ENABLED ? 'ss_mcp_manifest_disclosure' : 'ss_mcp_server_impersonation'));
        if (!Q05_HANDOFF_ENABLED) {
          assert.ok(objective);
          assert.equal(objective.enabled, false, 'the fresh objective is naturally disabled before qualification');
        }
        let v42Admission, v39Admission, v39Admitted, v39Qualification;
        if (Q05_HANDOFF_ENABLED) {
          assert.equal(assessmentReleaseAdmission, undefined, 'no objective admission or Judge in Q05 handoff');
        } else if(V42_ENABLED){
          v42Admission=await v66Contract.admitV42DisposableCandidate({migration:pools.IDENTITY_MIGRATION,catalog,administratorContext:ownerBase,curriculum:require('../../server/config/secureshopCurriculum')});
        }else if (V39_ENABLED) {
          assert.equal(objective.qualification, 'pending');
          await assert.rejects(catalog.set(ownerBase, { objectiveId: objective.objectiveId,
            enabled: true, expectedRevision: objective.revision }), { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
          const defaultObjective = require('../../server/config/secureshopCurriculum').OBJECTIVES
            .find(value => value.id === objective.objectiveId);
          assert.ok(defaultObjective);
          const sourceDocument = JSON.stringify({ version: 1, id: defaultObjective.id,
            label: defaultObjective.text, defaultEnabled: defaultObjective.defaultEnabled,
            qualification: defaultObjective.qualification });
          const sourceSha256 = require('node:crypto').createHash('sha256')
            .update(sourceDocument).digest('hex');
          const admitted = await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.assessment_objectives
            SET qualification='native-model' WHERE objective_id=$1 AND qualification='pending'
              AND is_enabled=false AND catalog_active=true
              AND configuration_source='checked_in_default'
              AND source_sha256=$2 AND source_document=$3::jsonb
            RETURNING objective_id,qualification,is_enabled`,
          [objective.objectiveId, sourceSha256, sourceDocument]);
          assert.deepEqual(admitted.rows, [{ objective_id: objective.objectiveId,
            qualification: 'native-model', is_enabled: false }]);
          assert.equal(admitted.rowCount, 1);
          v39Admitted = admitted;
          v39Qualification = (await catalog.list(ownerBase)).objectives
            .find(value => value.objectiveId === objective.objectiveId).qualification;
          assert.equal(v39Qualification, 'native-model');
        } else assert.equal(objective.qualification, 'native-model');
        if(!V42_ENABLED && !Q05_HANDOFF_ENABLED) {
          const enabled = await catalog.set(ownerBase, { objectiveId: objective.objectiveId,
            enabled: true, expectedRevision: objective.revision });
          assert.equal(enabled.enabled, true);
          if (V39_ENABLED) {
            v39Admission = retainV39Admission(objective, v39Admitted, v39Qualification, enabled);
            if (!V39_PAIR_ENABLED) initializeV39Receipt(v39Contract, v39Admission, v39Receipt);
          }
        }
        if (V66_ENABLED) {
          const enabled = (await catalog.list(ownerBase)).objectives
            .find(value => value.objectiveId === objective.objectiveId);
          assert.equal(enabled.enabled, true);
          await require('../../server/database/postgres/workshopPlatformSeed')
            .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
          await require('../../server/database/postgres/secureshopAssessmentSeed')
            .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
          assert.deepEqual((await catalog.list(ownerBase)).objectives
            .find(value => value.objectiveId === objective.objectiveId), enabled,
          'second-run defaults preserve the admin objective revision, label and enabled state');
        }
        if (V66_ENABLED || V42_ENABLED) {
          const qualify=V42_ENABLED?v66Contract.qualifyV42:v66Contract.qualifyV66;
          const qualified = await qualify({ page, frame, frameFor: frameOn,
            click: clickRendered, origin, binding, personaSession, headers, principal,
            scope, actor, auth, ownerBase, bootstrap, composition, grading, registry,
            registryConfiguration, expectedDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1),
            agents, identity, review, commerce, pools, reset, provider: v43Recorder.provider,
            recorder: v43Recorder, transport: v43Transport, observedOperations,
            apiStatuses, originalJsonCaptures: v43JsonCaptures,
            catalogAdmission:v42Admission,
            beginAssessmentAckLoss:async()=>{dropper=await dropOneCommittedRegistration(page,`${origin}/api/secureshop/agents/admin/assistant/mcp-discovery/assess`,'discovery-assessment');},
            finishAssessmentAckLoss:async()=>{const value=await waitFor(()=>dropper.captured(),'committed discovery assessment ACK');await dropper.close();dropper=null;return value;},
            readExecutorObservations:()=>structuredClone(executorObservations),
            getRegistry:()=>registry,
            setRegistryMode:async mode=>{assert.equal(mode,'fixed');await registry.close();registryConfiguration.mode=mode;registry=await require('../../server/services/secureshopOwnedMcpRegistryProduction').createOwnedMcpRegistryProduction({configuration:registryConfiguration,agentsPool:agents,personaAuthority:grading.personaAuthority,authenticatePersona:composition.personaAuth.authenticatePersona,expectedDatabase:new URL(urls.AGENTS_RUNTIME).pathname.slice(1),createClient:options=>{const client=require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient(options);return {...client,async execute(request,options){try{const result=await client.execute(request,options);executorObservations.push({request:structuredClone(request),mode:options?.mode,result:structuredClone(result)});return result;}catch(error){executorObservations.push({request:structuredClone(request),mode:options?.mode,error:{code:error.code,effectNotStarted:error.effectNotStarted===true,drained:error.drained===true}});throw error;}}};}});},
            readPublicProgress:completed=>v66Contract.readV42PublicProgress(page,completed),
            savePrivate: value => fsSync.writeFileSync(path.join(path.dirname(evidencePath),
              V42_ENABLED?'mcp-discovery-qualification.json':'mcp-manifest-qualification.json'), JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }) });
          Object.assign(V42_ENABLED?v42Receipt:v66Receipt, qualified);
          if(V42_ENABLED)status.discoveryQualification=true;else status.manifestQualification = true;
          await save();
        } else if (V39_ENABLED || Q05_HANDOFF_ENABLED) {
          const readRegistryFor = async requestedScope => {
            const where = `platform_launch_id=$1 AND platform_scenario_id=$2
              AND platform_launch_generation=$3 AND original_platform_owner_id=$4
              AND original_platform_session_id=$5`;
            const values = [requestedScope.launchId, requestedScope.scenarioId, requestedScope.generation,
              requestedScope.platformOwnerId, requestedScope.platformSessionId];
            const reader = require('../../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository')
              .createOwnedMcpRegistryAdminReadRepository({ pool: agents });
            return {
              registryVersion: await reader.head(requestedScope),
              scopeKey: require('node:crypto').createHash('sha256').update(JSON.stringify(
                require('../../server/services/secureshopConversationBinding').createLaunchScope(requestedScope))).digest('hex'),
              head: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_heads WHERE ${where}`, values)).rows[0] ?? null,
              entries: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_entries WHERE ${where} ORDER BY entry_id`, values)).rows,
              revisions: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions WHERE ${where} ORDER BY registry_version`, values)).rows,
              operations: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations WHERE ${where} ORDER BY operation_id`, values)).rows,
            };
          };
          const readRegistry = () => readRegistryFor(scope);
          const peerId = randomUUID(), peerName = `v39_peer_${randomUUID().slice(0, 8)}`;
          const peerTenantId = randomUUID(), peerSlug = `v39_peer_${randomUUID().slice(0, 8)}`;
          const peerHash = await require('bcryptjs').hash('disposable-v39-peer', 12);
          const peerRow = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
            (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin') RETURNING shop_user_id`,
          [peerId, peerName, `${peerName}@example.invalid`, peerHash])).rows[0];
          await pools.IDENTITY_MIGRATION.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
            [peerTenantId, peerSlug]);
          const peerMerchantId = randomUUID(), peerMerchantName = `${peerName}_merchant`;
          const peerMerchant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
            (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant') RETURNING shop_user_id`,
          [peerMerchantId, peerMerchantName, `${peerMerchantName}@example.invalid`, peerHash])).rows[0];
          await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
            (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
          [peerTenantId, peerMerchantId, peerMerchant.shop_user_id]);
          assert.equal((await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
            SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL`,
          [peerTenantId, peerMerchant.shop_user_id])).rowCount, 1);
          await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
            (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
          [peerTenantId, peerId, peerRow.shop_user_id]);
          const peerAuth = require('../../server/services/secureshopStandaloneAuth')
            .createSecureShopStandaloneAuthService({ repository:
              require('../../server/database/postgres/secureshopStandaloneAuthRepository')
                .createSecureShopStandaloneAuthRepository({ pool: identity, executionTenantSlug: peerSlug }) });
          const peerLogin = await peerAuth.login({ username: peerName, password: 'disposable-v39-peer' });
          const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
            .createSecureShopStandaloneBootstrap({ launches: composition.launches,
              personaAuth: composition.personaAuth, authService: peerAuth });
          const peerIssued = await peerBootstrap(peerLogin.context);
          const peerScope = await composition.launches.resolveCapability(peerIssued.bearer);
          assert.notEqual(peerScope.platformOwnerId, scope.platformOwnerId);
          assert.notEqual(peerScope.launchId, scope.launchId);
          const peerActor = await composition.personaAuth.authenticateBoundToken({ scope: peerScope,
            token: peerIssued.persona.token });
          const peerSetup = await registry.service.mutate({ scope: peerScope,
            persona: { id: peerActor.user.id, role: 'admin' },
            personaSession: { sessionId: peerActor.sessionId, authorityVersion: peerActor.authorityVersion },
            request: { version: 1, action: 'register', operationId: randomUUID(), expectedVersion: '0',
              name: 'v39-peer-catalog', transport: 'streamable-http',
              url: 'http://benign.training/mcp', stdio_cmd: '' } });
          assert.equal(peerSetup.state, 'completed');
          const peerHeaders = { authorization: `Bearer ${peerIssued.persona.token}`,
            'x-owasp-ai-goat-secureshop-launch': peerIssued.bearer };
          const peerBefore = await readRegistryFor(peerScope);
          assert.equal(peerBefore.entries.length, 1);
          assert.equal(peerBefore.operations.length, 1);
          const qualifyV39Arm = (context, atomicArm, armReceipt) => v39Contract.qualify({
            page, frame: context.frame, frameFor: frameOn, click: clickRendered,
            origin, binding: context.binding, personaSession: context.personaSession,
            headers: context.headers, agents, identity,
            conversationRepository: reset.conversations, turnJournal: reset.journal,
            invocationJournal: invocationInfrastructure.journal,
            registryRepository: require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository')
              .createOwnedMcpRegistryRepository({ pool: agents, personaAuthority: grading.personaAuthority }),
            provider, recorder: v43Recorder, transport: v43Transport,
            principal: context.principal, readRegistry: () => readRegistryFor(context.scope),
            originalJsonCaptures: v43JsonCaptures, receipt: armReceipt,
            scope: context.scope, ownerBase: context.ownerBase,
            bootstrap, composition, reset, peerHeaders, peerScope, peerBefore,
            readPeerRegistry: () => readRegistryFor(peerScope),
            readPublicProgress: async completed => {
              const response = await page.evaluate(async () => {
                const result = await fetch('/api/secureshop/auth/progress', { credentials: 'same-origin' });
                return { status: result.status, body: await result.json() };
              });
              assert.equal(response.status, 200, JSON.stringify(response));
              const rows = response.body.objectives.filter(row =>
                row.objectiveId === 'ss_mcp_description_instruction_adoption');
              assert.equal(rows.length, 1);
              assert.equal(rows[0].completed, completed);
              assert.equal(response.body.totalObjectives, response.body.objectives.length);
              assert.equal(response.body.completedObjectives,
                response.body.objectives.filter(row => row.completed).length);
              return response;
            },
            recordComposerDiagnostic: async ({ state, screenshot }) => {
              const directory = path.dirname(evidencePath);
              await fs.writeFile(path.join(directory, 'mcp-description-composer-timeout.json'),
                JSON.stringify({ version: 1, state }, null, 2) + '\n',
                { mode: 0o600, flag: 'wx' });
              if (screenshot) await fs.writeFile(path.join(directory,
                'mcp-description-composer-timeout.png'), screenshot,
              { mode: 0o600, flag: 'wx' });
            },
            authenticateObservedBearer: token => composition.personaAuth.authenticateBoundToken({
              scope: context.scope, token }),
            atomicArm,
            retirePhysicalArm: atomicArm === 'control' ? async () => {
              v43Recorder.close();
              await v39PairArm.finish();
              assert.equal(v39PairTransport.snapshot().arms.control.state, 'finished');
            } : null,
            savePrivate: value => v39Writer
              ? v39Writer.write(atomicArm
                ? `mcp-description-atomic-${atomicArm}-qualification.json`
                : 'mcp-description-qualification.json', JSON.stringify(value, null, 2) + '\n')
              : fsSync.writeFileSync(path.join(path.dirname(evidencePath),
                atomicArm ? `mcp-description-atomic-${atomicArm}-qualification.json`
                  : 'mcp-description-qualification.json'), JSON.stringify(value, null, 2) + '\n',
              { mode: 0o600 }) });
          const firstContext = { frame, binding, personaSession, headers, principal, scope, ownerBase };
          if (Q05_HANDOFF_ENABLED) handoffBinding = binding;
          const controlReceipt = V39_PAIR_ENABLED ? await initializeObservedV39Receipt({ contract: v39Contract,
            witness: v39Admission, admission: assessmentReleaseAdmission, pools, scope, actor, issued }) : v39Receipt;
          const control = Q05_HANDOFF_ENABLED
            ? await v39Contract.qualify({ page, frame, frameFor: frameOn, click: clickRendered,
              origin, binding, personaSession, headers, agents, identity,
              conversationRepository: reset.conversations, turnJournal: reset.journal,
              invocationJournal: invocationInfrastructure.journal,
              registryRepository: require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository')
                .createOwnedMcpRegistryRepository({ pool: agents, personaAuthority: grading.personaAuthority }),
              provider, recorder: v43Recorder, transport: v43Transport, principal,
              readRegistry, originalJsonCaptures: v43JsonCaptures, receipt: handoffReceipt,
              scope, ownerBase, bootstrap, composition, reset, peerHeaders, peerScope, peerBefore,
              readPeerRegistry: () => readRegistryFor(peerScope),
              authenticateObservedBearer: token => composition.personaAuth.authenticateBoundToken({ scope, token }),
              handoffOnly: true, handoffLoss,
              savePrivate: value => q05Writer
                ? q05Writer.write('registered-handoff-qualification.json', JSON.stringify(value, null, 2) + '\n')
                : fsSync.writeFileSync(path.join(path.dirname(evidencePath),
                  'registered-handoff-qualification.json'), JSON.stringify(value, null, 2) + '\n',
                { mode: 0o600 }) })
            : await qualifyV39Arm(firstContext,
              V39_PAIR_ENABLED ? 'control' : null, controlReceipt);
          if (V39_PAIR_ENABLED) {
            const controlCalls = structuredClone(v43Transport.calls);
            assert.equal(v39PairTransport.snapshot().arms.control.state, 'finished');
            const resetRows = (await identity.query(`SELECT reset_id,launch_id,from_generation,
              to_generation,status,reconciliation_required,conversation_reconciliation_required,
              progress_reconciliation_required,committed_at
              FROM identity.secureshop_launch_resets WHERE reset_id=$1`,
            [control.fences.resetId])).rows;
            assert.equal(resetRows.length, 1);
            v43Contract.assertV43ResetCheckpoint(control.fences.reset, scope, resetRows[0]);
            v39ActiveArm = 'treatment';
            v39PairArm = await v39PairTransport.beginArm('treatment', v39PairIds.treatment);
            v43Transport = v39PairArm.transport;
            v43Recorder = require('../fixtures/secureshopMcpRegistryExploitQualification')
              .createV43ModelRecorder({ transport: v43Transport, record: captureV39Model });
            // Composition retains the original exact OllamaProvider instance. Switch only
            // its fixture-owned dispatch to a second exact OllamaProvider after the first
            // physical relay is retired; no response, trace or identity is synthesized.
            switchV39AtomicProvider(provider, v43Recorder.provider);
            const oldBootstraps = v43Bootstraps.length;
            const reloaded = await page.goto(`${origin}/secureshop/admin/mcp`);
            assert.ok([200, 304].includes(reloaded.status()));
            const newFrame = await frameOn(page);
            const nextIssued = await waitFor(() => v43Bootstraps.length > oldBootstraps
              ? v43Bootstraps.at(-1) : null, 'fresh treatment browser bootstrap');
            assert.notEqual(nextIssued.bearer, issued.bearer);
            assert.notEqual(nextIssued.persona.token, issued.persona.token);
            const nextScope = await composition.launches.resolveCapability(nextIssued.bearer);
            assert.ok(nextScope.launchId !== scope.launchId ||
              BigInt(nextScope.generation) > BigInt(scope.generation));
            if (nextScope.launchId === scope.launchId)
              assert.equal(String(nextScope.generation), String(resetRows[0].to_generation));
            const nextActor = await composition.personaAuth.authenticateBoundToken({
              scope: nextScope, token: nextIssued.persona.token });
            assert.equal(nextActor.user.id, actor.user.id);
            assert.notEqual(nextActor.sessionId, actor.sessionId);
            const nextBinding = require('../../server/services/secureshopConversationBinding')
              .createConversationBinding(nextScope, { role: 'admin', id: nextActor.user.id });
            const nextSession = { sessionId: nextActor.sessionId,
              authorityVersion: nextActor.authorityVersion };
            const nextHeaders = { authorization: `Bearer ${nextIssued.persona.token}`,
              'x-owasp-ai-goat-secureshop-launch': nextIssued.bearer };
            const nextCookie = (await page.cookies(`${origin}/api/secureshop/auth/session`))
              .find(value => value.name === 'owasp_ai_goat_shop_session');
            assert.ok(nextCookie?.httpOnly);
            const nextOwnerBase = await auth.authenticate(nextCookie.value);
            const nextPrincipal = await auth.establishTenantContext(nextOwnerBase);
            assert.equal(nextPrincipal.principalId, principal.principalId);
            assert.deepEqual(await readRegistryFor(peerScope), peerBefore);
            await clickRendered(newFrame, { label: 'Shop settings' });
            await page.waitForSelector('aside[aria-label="Shop settings"]');
            await newFrame.waitForFunction(() => document.querySelector('[aria-label="Shop feature mode"]')
              ?.textContent.includes('Current: '), { timeout: 20000 });
            const treatmentMode = await newFrame.$eval('[aria-label="Shop feature mode"]',
              node => node.textContent.includes('Current: Fixed') ? 'fixed'
                : node.textContent.includes('Current: Vulnerable') ? 'vuln' : null);
            assert.ok(treatmentMode === 'fixed' || treatmentMode === 'vuln');
            if (treatmentMode === 'fixed') await clickRendered(newFrame, { label: 'Vulnerable' });
            await newFrame.waitForFunction(() => document.querySelector('[aria-label="Shop feature mode"]')
              ?.textContent.includes('Current: Vulnerable'), { timeout: 20000 });
            await clickRendered(newFrame, { label: 'Shop settings' });
            await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
            const treatmentReceipt = await initializeObservedV39Receipt({ contract: v39Contract,
              witness: v39Admission, admission: assessmentReleaseAdmission, pools,
              scope: nextScope, actor: nextActor, issued: nextIssued });
            const treatment = await qualifyV39Arm({ frame: newFrame, binding: nextBinding,
              personaSession: nextSession, headers: nextHeaders, principal: nextPrincipal,
              scope: nextScope, ownerBase: nextOwnerBase }, 'treatment', treatmentReceipt);
            const treatmentCalls = structuredClone(v43Transport.calls);
            v43Recorder.close();
            await v39PairArm.finish();
            assert.equal(v39PairTransport.snapshot().arms.treatment.state, 'finished');
            const qualifyModelTrace = require('../../server/services/secureshopModelQualification')
              .createSecureShopModelQualifier(provider);
            v39PairReceipt = require('../fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification')
              .assertPairCaptured({ control, treatment, controlCalls, treatmentCalls,
                qualifyModelTrace });
          }
          if (Q05_HANDOFF_ENABLED) status.registeredHandoff = true;
          else status.descriptionQualification = true;
          await save();
        } else {
        // Controlled authority/setup only: genuine registered peer membership,
        // login and launch, with its own populated registry before model calls.
        const peerId = randomUUID(), peerName = `v43_peer_${randomUUID().slice(0, 8)}`;
        const peerTenantId = randomUUID(), peerSlug = `v43_peer_${randomUUID().slice(0, 8)}`;
        const peerHash = await require('bcryptjs').hash('disposable-v43-peer', 12);
        const peerRow = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
          (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin') RETURNING shop_user_id`,
        [peerId, peerName, `${peerName}@example.invalid`, peerHash])).rows[0];
        await pools.IDENTITY_MIGRATION.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
          [peerTenantId, peerSlug]);
        const peerMerchantId = randomUUID(), peerMerchantName = `${peerName}_merchant`;
        const peerMerchant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
          (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant') RETURNING shop_user_id`,
        [peerMerchantId, peerMerchantName, `${peerMerchantName}@example.invalid`, peerHash])).rows[0];
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
        [peerTenantId, peerMerchantId, peerMerchant.shop_user_id]);
        assert.equal((await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
          SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL`,
        [peerTenantId, peerMerchant.shop_user_id])).rowCount, 1);
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
        [peerTenantId, peerId, peerRow.shop_user_id]);
        const peerAuth = require('../../server/services/secureshopStandaloneAuth')
          .createSecureShopStandaloneAuthService({ repository:
            require('../../server/database/postgres/secureshopStandaloneAuthRepository')
              .createSecureShopStandaloneAuthRepository({ pool: identity, executionTenantSlug: peerSlug }) });
        const peerLogin = await peerAuth.login({ username: peerName, password: 'disposable-v43-peer' });
        const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
          .createSecureShopStandaloneBootstrap({ launches: composition.launches,
            personaAuth: composition.personaAuth, authService: peerAuth });
        const peerIssued = await peerBootstrap(peerLogin.context);
        const peerScope = await composition.launches.resolveCapability(peerIssued.bearer);
        assert.notEqual(peerScope.platformOwnerId, scope.platformOwnerId);
        assert.notEqual(peerScope.launchId, scope.launchId);
        const peerActor = await composition.personaAuth.authenticateBoundToken({ scope: peerScope,
          token: peerIssued.persona.token });
        const peerHeaders = { authorization: `Bearer ${peerIssued.persona.token}`,
          'x-owasp-ai-goat-secureshop-launch': peerIssued.bearer };
        const peerSession = { sessionId: peerActor.sessionId, authorityVersion: peerActor.authorityVersion };
        const peerSetup = await registry.service.mutate({ scope: peerScope,
          persona: { id: peerActor.user.id, role: 'admin' }, personaSession: peerSession,
          request: { version: 1, action: 'register', operationId: randomUUID(), expectedVersion: '0',
            name: 'v43-peer-catalog', transport: 'streamable-http', url: 'http://benign.training/mcp', stdio_cmd: '' } });
        assert.equal(peerSetup.state, 'completed');
        const protectedGet = async (urlPath, suppliedHeaders) => {
          const response = await fetch(`${origin}${urlPath}`, { headers: suppliedHeaders,
            signal: AbortSignal.timeout(20000) });
          return { status: response.status, value: await response.json() };
        };
        const peerPositive = await protectedGet('/api/secureshop/v2/auth/users/me', peerHeaders);
        assert.equal(peerPositive.status, 200);
        const readRegistryFor = async requested => {
          const args = [requested.launchId, requested.scenarioId, requested.generation,
            requested.platformOwnerId, requested.platformSessionId];
          const where = 'platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3 AND original_platform_owner_id=$4 AND original_platform_session_id=$5';
          const reader = require('../../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository')
            .createOwnedMcpRegistryAdminReadRepository({ pool: agents });
          return {
            registryVersion: await reader.head(requested),
            scopeKey: require('node:crypto').createHash('sha256')
              .update(JSON.stringify(require('../../server/services/secureshopConversationBinding').createLaunchScope(requested)))
              .digest('hex'),
            head: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_heads WHERE ${where}`, args)).rows[0] ?? null,
            entries: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_entries WHERE ${where} ORDER BY entry_id`, args)).rows,
            revisions: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions WHERE ${where} ORDER BY registry_version`, args)).rows,
            operations: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations WHERE ${where} ORDER BY operation_id`, args)).rows,
          };
        };
        const readRegistry = () => readRegistryFor(scope);
        const peerBefore = await readRegistryFor(peerScope);
        assert.equal(peerBefore.entries.length, 1);
        assert.equal(peerBefore.operations.length, 1);
        v43Receipt.distinctTenantPreflight = true;
        const captured = await require('../fixtures/secureshopMcpRegistryExploitQualification')
          .qualifyV43OriginalTurn({ page, frame, origin, binding, personaSession, headers,
            originalActor: actor,
            authenticateObservedBearer: token => composition.personaAuth.authenticateBoundToken({ scope, token }),
            agents, identity, conversationRepository: reset.conversations,
            turnJournal: reset.journal, invocationJournal: invocationInfrastructure.journal,
            registryRepository: require('../../server/database/postgres/secureshopOwnedMcpRegistryRepository')
              .createOwnedMcpRegistryRepository({ pool: agents, personaAuthority: grading.personaAuthority }),
            provider, recorder: v43Recorder, transport: v43Transport, principal,
            readRegistry, click: clickRendered, frameFor: frameOn, originalJsonCaptures: v43JsonCaptures,
            afterPositive: async ({ original, assessment, judgment, proof, frame: currentFrame, send }) => {
              const savedPath = original.savedPath;
              const foreign = await protectedGet(savedPath, peerHeaders);
              assert.equal(foreign.status, 401);
              assert.deepEqual(await readRegistryFor(peerScope), peerBefore);
              const beforeCalls = v43Transport.calls.length;
              const beforeInvocations = (await agents.query(`SELECT invocation_id FROM secureshop_agents.owned_mcp_invocation_journal
                WHERE platform_launch_id=$1 ORDER BY invocation_id`, [scope.launchId])).rows;
              const beforeJudgments = (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows;
              await clickRendered(page, { label: 'Shop settings' });
              await page.waitForSelector('aside[aria-label="Shop settings"]');
              await clickRendered(page, { label: 'Fixed' });
              await page.waitForFunction(() => document.querySelector('[aria-label="Shop feature mode"]')
                ?.textContent.includes('Current: Fixed'), { timeout: 20000 });
              await clickRendered(page, { label: 'Shop settings' });
              await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
              const fixed = await send(true, 'Use the registered search_catalog tool to search for "V43 fixed catalog".');
              assert.equal(fixed.saved.result.stopReason, 'end_turn');
              const fixedTurn = await reset.journal.readRegisteredAdminRequest({ binding,
                sessionId: fixed.posted.body.sessionId, requestId: fixed.posted.body.requestId });
              const fixedMetadata = fixedTurn.result_json.taskMetadata.registeredAdmin;
              assert.equal(fixedMetadata.version, 3);
              assert.equal(fixedMetadata.execution.mode, 'fixed');
              const fixedTraces = await reset.conversations.getTraceEvents(fixed.posted.body.sessionId,
                binding, fixedMetadata.traceEventIds, 'general');
              const fixedTerminal = fixedTraces.filter(row => row.kind === 'terminal' && row.actor === 'supervisor');
              assert.equal(fixedTerminal.length, 1);
              assert.equal(require('../../server/services/secureshopRealModelTrace').isQualifiedSecureShopModelTrace(
                fixedTerminal[0], require('../../server/services/secureshopModelQualification')
                  .createSecureShopModelQualifier(provider)), true);
              assert.ok(fixed.saved.result.hops.every(hop => !/^owned_/.test(hop.tool)),
                'Fixed mode cannot dispatch the unapproved owned tool');
              const afterInvocations = (await agents.query(`SELECT invocation_id FROM secureshop_agents.owned_mcp_invocation_journal
                WHERE platform_launch_id=$1 ORDER BY invocation_id`, [scope.launchId])).rows;
              assert.deepEqual(afterInvocations, beforeInvocations);
              const afterJudgments = (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows;
              assert.deepEqual(afterJudgments, beforeJudgments);
              assert.equal(v43Transport.calls.slice(beforeCalls).filter(row => row.kind === 'judge').length, 0);
              await composition.personaAuth.revokeOwnedSession({ scope,
                shopPersona: { id: actor.user.id, role: 'admin' }, currentSessionId: personaSession.sessionId,
                authorityVersion: personaSession.authorityVersion, sessionId: personaSession.sessionId });
              assert.equal((await protectedGet(savedPath, headers)).status, 401);
              const renewed = await bootstrap(ownerBase);
              const renewedHeaders = { authorization: `Bearer ${renewed.persona.token}`,
                'x-owasp-ai-goat-secureshop-launch': renewed.bearer };
              assert.equal((await protectedGet('/api/secureshop/v2/auth/users/me', renewedHeaders)).status, 200);
              const immutableBefore = (await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows;
              assert.equal(immutableBefore.length, 1);
              const contributionsBefore = (await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows;
              assert.equal(contributionsBefore.length, 1);
              const registryBeforeReset = await readRegistry();
              const resetResult = await reset.launchResetCoordinator.reset({ ...scope,
                expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
              const resetRows = (await identity.query(`SELECT reset_id,launch_id,from_generation,
                to_generation,status,reconciliation_required,conversation_reconciliation_required,
                progress_reconciliation_required,committed_at
                FROM identity.secureshop_launch_resets WHERE reset_id=$1`, [resetResult.resetId])).rows;
              assert.equal(resetRows.length, 1);
              require('../fixtures/secureshopMcpRegistryExploitQualification')
                .assertV43ResetCheckpoint(resetResult, scope, resetRows[0]);
              assert.equal((await protectedGet(savedPath, renewedHeaders)).status, 401);
              const immutableAfter = (await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows;
              assert.deepEqual(immutableAfter, immutableBefore);
              assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows, contributionsBefore);
              const registryAfterReset = await readRegistry();
              const retainedHashes = rows => rows.map(row => ({ operation_id: row.operation_id,
                request_sha256: row.request_sha256, receipt_sha256: row.receipt_sha256 }));
              assert.deepEqual(retainedHashes(registryAfterReset.operations), retainedHashes(registryBeforeReset.operations));
              assert.ok(registryAfterReset.operations.every(row => row.request_json === null && row.receipt_json === null));
              assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
                WHERE tenant_id=$1 AND principal_id=$2 ORDER BY evaluation_id`,
              [principal.tenantId, principal.principalId])).rows, beforeJudgments);
              assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.active_assessment_contributions
                WHERE tenant_id=$1 AND principal_id=$2`, [principal.tenantId, principal.principalId])).rows, []);
              assert.deepEqual(await protectedGet('/api/secureshop/v2/auth/users/me', peerHeaders), peerPositive);
              assert.deepEqual(await readRegistryFor(peerScope), peerBefore);
              return { foreign, fixed, fixedTurn, fixedTraces, resetResult, peerBefore, peerAfter: await readRegistryFor(peerScope),
                immutableBefore, immutableAfter, assessment, evaluationId: judgment.evaluation_id,
                invocationId: proof.invocationId };
            },
            recordScreenshot: bytes => fsSync.writeFileSync(path.join(path.dirname(evidencePath),
              'mcp-impersonation-failure.png'), bytes, { mode: 0o600, flag: 'wx' }),
            record: value => fsSync.writeFileSync(path.join(path.dirname(evidencePath),
              'mcp-impersonation-qualification.json'), JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }),
          });
        assert.equal(captured.assessment.completed, true);
        for (const flag of ['trustedRegistration', 'sameNameReplacement', 'originalSelectedInvocation',
          'canonicalJudgeCredit', 'physicalAssessmentRead', 'savedReloadNoEffect', 'fixedNoInvocationNoCredit',
          'siblingPreserved', 'sessionDenied', 'resetFenced', 'immutablePreserved']) v43Receipt[flag] = true;
        v43Receipt.actualTurns = 4;
        v43Receipt.genuineCredit = 1;
        status.scope = 'V43-standalone';
        status.actualModelEvidence = true;
        status.registeredJudgeCredit = true;
        await save();
        }
      } else {
      await frame.waitForFunction(() => document.body.textContent.includes('MCP Registry')
        && document.body.textContent.includes('no MCP servers registered'), { timeout: 20000 });
      status.standaloneAdminRendered = true; await save();
      dropper = await dropOneCommittedRegistration(page, `${origin}/api/secureshop/admin/mcp/register`);
      await clickRendered(frame, { label: '+ register new' });
      await frame.waitForSelector('.ss-role-modal form');
      const fields = await frame.$$('.ss-role-modal form input');
      assert.equal(fields.length, 2, 'SSE registration has name and URL controls');
      await fields[0].type(NAME); await fields[1].type(PEER);
      await clickRendered(frame, { selector: '.ss-role-modal form button[type="submit"]' });
      const captured = await waitFor(() => dropper.captured(), 'committed owned registry response', 30000);
      await dropper.close(); dropper = null;
      assert.match(captured.request.operationId, UUID);
      const operationId = captured.request.operationId;
      const rows = (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
        WHERE operation_id=$1`, [operationId])).rows;
      assert.equal(rows.length, 1); assert.equal(rows[0].state, 'completed');
      assert.equal(rows[0].request_sha256.toString('hex'), captured.receipt.requestSha256);
      assert.equal(captured.receipt.ok, true, 'HTTP route added a successful completion envelope');
      const { ok: _routeEnvelope, ...publicReceipt } = captured.receipt;
      assert.deepEqual(publicReceipt, { ...rows[0].receipt_json, replayed: false });
      assert.match(rows[0].receipt_sha256.toString('hex'), HEX);
      const firstScope = await composition.launches.resolveCapability(requestHeaders['x-owasp-ai-goat-secureshop-launch']);
      assert.ok(firstScope);
      assert.equal(rows[0].platform_launch_id, firstScope.launchId);
      assert.equal(rows[0].platform_scenario_id, firstScope.scenarioId);
      assert.equal(String(rows[0].platform_launch_generation), String(firstScope.generation));
      assert.equal(rows[0].original_platform_owner_id, firstScope.platformOwnerId);
      assert.equal(rows[0].original_platform_session_id, firstScope.platformSessionId);
      assert.equal((await agents.query(`SELECT count(*)::integer AS n FROM secureshop_agents.bound_mcp_registry_revisions
        WHERE operation_id=$1`, [operationId])).rows[0].n, 1);
      status.ownedNamespaceRegistration = true; await save();
      assert.ok([200, 304].includes((await page.reload({ waitUntil: 'domcontentloaded' })).status()));
      frame = await frameOn(page);
      await frame.waitForFunction(() => document.body.textContent.includes('Check saved operation'), { timeout: 15000 });
      assert.equal(observedOperations.filter(item => item.action === 'register').length, 1);
      await clickRendered(frame, { label: 'Check saved operation' });
      await frame.waitForFunction(name => document.body.textContent.includes(name)
        && !document.body.textContent.includes('A saved registry operation awaits verification.'),
      { timeout: 20000 }, NAME);
      assert.ok(apiStatuses.some(row => row.method === 'GET'
        && row.path === `/api/secureshop/admin/mcp/operations/${operationId}` && row.status === 200));
      assert.equal(observedOperations.filter(item => item.action === 'register').length, 1,
        'rendered recovery is GET-only after remount');
      assert.ok(requestHeaders?.authorization && requestHeaders['x-owasp-ai-goat-secureshop-launch']);
      const replay = await fetch(`${origin}/api/secureshop/admin/mcp/register`, { method: 'POST',
        headers: requestHeaders, body: JSON.stringify(captured.request) });
      assert.equal(replay.status, 200);
      const replayBody = await replay.json(); assert.equal(replayBody.replayed, true);
      assert.equal(replayBody.operationId, operationId);
      assert.equal((await agents.query(`SELECT count(*)::integer AS n FROM secureshop_agents.bound_mcp_registry_revisions
        WHERE operation_id=$1`, [operationId])).rows[0].n, 1);
      const staleRequest = require('../../server/services/secureshopMcpRegistryContract')
        .normalizeRegistryRequest({ ...captured.request, operationId: randomUUID(),
          expectedVersion: '1', name: `${NAME}-stale` });
      assert.equal((await agents.query(`SELECT registry_version FROM secureshop_agents.bound_mcp_registry_heads
        WHERE platform_launch_id=$1`, [firstScope.launchId])).rows[0].registry_version, '1');
      await clickRendered(frame, { selector: `button[aria-label="Toggle tools for ${NAME}"]` });
      await frame.waitForFunction(() => document.body.textContent.includes('search_catalog'), { timeout: 20000 });
      const serverRows = (await agents.query(`SELECT name,transport,endpoint_text,schema_sha256,current_version
        FROM secureshop_agents.bound_mcp_registry_entries WHERE name=$1 AND lifecycle='active'`, [NAME])).rows;
      assert.equal(serverRows.length, 1); assert.equal(serverRows[0].transport, 'sse');
      assert.equal(serverRows[0].endpoint_text, PEER); assert.match(serverRows[0].schema_sha256.toString('hex'), HEX);
      const revisions = (await agents.query(`SELECT operation_id,name,registry_version,tools_json,schema_sha256
        FROM secureshop_agents.bound_mcp_registry_revisions WHERE operation_id=$1`, [operationId])).rows;
      assert.equal(revisions.length, 1);
      assert.equal(revisions[0].name, NAME);
      assert.deepEqual(revisions[0].schema_sha256, serverRows[0].schema_sha256);
      assert.equal(revisions[0].tools_json.length, 1);
      assert.equal(revisions[0].tools_json[0].name, 'search_catalog');
      assert.equal(revisions[0].tools_json[0].description,
        'Search the bounded synthetic product catalog.');
      const toolsRead = await fetch(`${origin}/api/secureshop/admin/mcp/servers/${NAME}/tools`,
        { headers: requestHeaders });
      assert.equal(toolsRead.status, 200);
      const toolsBody = await toolsRead.json();
      assert.equal(toolsBody.version, serverRows[0].current_version);
      assert.equal(toolsBody.schema_hash, serverRows[0].schema_sha256.toString('hex'));
      assert.deepEqual(toolsBody.tools, revisions[0].tools_json.map(tool => ({
        tool_name: tool.name, description: tool.description,
        input_schema_json: JSON.stringify(tool.inputSchema) })));
      await frame.waitForFunction(description => document.body.textContent.includes(description),
        { timeout: 20000 }, revisions[0].tools_json[0].description);
      await clickRendered(frame, { selector: 'details summary', label: 'inputSchema',
        diagnosticPath: path.join(path.dirname(evidencePath), 'schema-details-click.png') });
      await frame.waitForFunction(schema => document.body.textContent.includes(schema),
        { timeout: 10000 }, toolsBody.tools[0].input_schema_json);
      const historyRead = await fetch(`${origin}/api/secureshop/admin/mcp/schema-history`,
        { headers: requestHeaders });
      assert.equal(historyRead.status, 200);
      const historyBody = await historyRead.json();
      const firstHistory = historyBody.history.filter(item => item.name === NAME);
      assert.equal(firstHistory.length, 1);
      assert.equal(firstHistory[0].schema_hash, toolsBody.schema_hash);
      const timelineDot = await frame.evaluateHandle((name, hash) => {
        const section = [...document.querySelectorAll('section')]
          .find(node => node.querySelector('h2')?.textContent === 'Schema-hash timeline');
        const title = [...(section?.querySelectorAll('b') || [])].find(node => node.textContent === name);
        const lane = title?.parentElement?.parentElement?.parentElement;
        const dot = lane?.children[1]?.children[0];
        return dot?.textContent?.trim() === hash.slice(0, 2).toUpperCase() ? dot : null;
      }, NAME, toolsBody.schema_hash);
      assert.ok(timelineDot.asElement(), 'rendered timeline includes the exact server hash dot');
      await timelineDot.asElement().hover();
      await frame.waitForFunction((name, hash) => {
        const section = [...document.querySelectorAll('section')]
          .find(node => node.querySelector('h2')?.textContent === 'Schema-hash timeline');
        return Boolean(section?.textContent.includes(name)
          && section.textContent.includes(`current hash: ${hash}`));
      }, { timeout: 15000 }, NAME, toolsBody.schema_hash);
      assert.ok(apiStatuses.some(row => row.path === `/api/secureshop/admin/mcp/servers/${NAME}/tools`
        && row.status === 200));
      assert.ok(apiStatuses.some(row => row.path === '/api/secureshop/admin/mcp/schema-history'
        && row.status === 200));
      status.renderedToolsAndHistory = true; await save();
      // This manifest is an owned synthetic XXE lesson fixture. Its import
      // establishes the registry operation, not a safety or Judge outcome.
      await clickRendered(frame, { label: 'import manifest' });
      await frame.waitForSelector('.ss-role-modal form input');
      await frame.type('.ss-role-modal form input', MANIFEST);
      await clickRendered(frame, { selector: '.ss-role-modal form button[type="submit"]' });
      const importedOperation = await waitFor(() => observedOperations.find(item => item.action === 'import'),
        'rendered manifest import operation');
      await frame.waitForFunction(() => document.body.textContent.includes('Registry import completed at version 2'),
        { timeout: 30000 });
      const importedRows = (await agents.query(`SELECT operation_id,registry_version,name,action
        FROM secureshop_agents.bound_mcp_registry_revisions WHERE operation_id=$1`,
      [importedOperation.operationId])).rows;
      assert.equal(importedRows.length, 1);
      assert.equal(importedRows[0].name, IMPORTED);
      assert.equal(importedRows[0].action, 'import');
      assert.equal(importedRows[0].registry_version, '2');
      const importedReceipt = (await agents.query(`SELECT state,receipt_json
        FROM secureshop_agents.bound_mcp_registry_operations WHERE operation_id=$1`,
      [importedOperation.operationId])).rows;
      assert.equal(importedReceipt.length, 1);
      assert.equal(importedReceipt[0].state, 'completed');
      assert.equal(importedReceipt[0].receipt_json.operationId, importedOperation.operationId);
      assert.equal(importedReceipt[0].receipt_json.registryVersion, '2');
      assert.equal((await agents.query(`SELECT count(*)::integer AS n
        FROM secureshop_agents.bound_mcp_registry_entries WHERE name=$1 AND lifecycle='active'`,
      [IMPORTED])).rows[0].n, 1);
      const stateBeforeStale = {
        heads: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_heads
          WHERE platform_launch_id=$1`, [firstScope.launchId])).rows,
        entries: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_entries
          WHERE platform_launch_id=$1 ORDER BY name`, [firstScope.launchId])).rows,
        revisions: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions
          WHERE platform_launch_id=$1 ORDER BY registry_version`, [firstScope.launchId])).rows,
        operations: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
          WHERE platform_launch_id=$1 ORDER BY operation_id`, [firstScope.launchId])).rows,
        audit: (await agents.query(`SELECT * FROM secureshop_agents.bound_audit_events
          WHERE launch_id=$1 ORDER BY event_id`, [firstScope.launchId])).rows,
        executorCalls,
      };
      assert.equal(stateBeforeStale.heads[0]?.registry_version, '2');
      const stale = await fetch(`${origin}/api/secureshop/admin/mcp/register`, { method: 'POST',
        headers: requestHeaders, body: JSON.stringify(staleRequest) });
      assert.equal(stale.status, 409, 'a prepared version-one change cannot confirm after import advanced the head');
      assert.deepEqual(await stale.json(), { ok: false, error: 'Owned MCP registry conflict',
        code: 'MCP_REGISTRY_OPERATION_CONFLICT', automaticRetry: false });
      assert.deepEqual({
        heads: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_heads
          WHERE platform_launch_id=$1`, [firstScope.launchId])).rows,
        entries: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_entries
          WHERE platform_launch_id=$1 ORDER BY name`, [firstScope.launchId])).rows,
        revisions: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions
          WHERE platform_launch_id=$1 ORDER BY registry_version`, [firstScope.launchId])).rows,
        operations: (await agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
          WHERE platform_launch_id=$1 ORDER BY operation_id`, [firstScope.launchId])).rows,
        audit: (await agents.query(`SELECT * FROM secureshop_agents.bound_audit_events
          WHERE launch_id=$1 ORDER BY event_id`, [firstScope.launchId])).rows,
        executorCalls,
      }, stateBeforeStale, 'stale confirmation cannot dispatch executor, publish, or write an operation receipt');
      const missingStale = await fetch(`${origin}/api/secureshop/admin/mcp/operations/${staleRequest.operationId}`,
        { headers: requestHeaders });
      assert.equal(missingStale.status, 404, 'stale proposal has no saved operation to replay');
      const completedReplay = await fetch(`${origin}/api/secureshop/admin/mcp/register`, { method: 'POST',
        headers: requestHeaders, body: JSON.stringify(captured.request) });
      assert.equal(completedReplay.status, 200);
      assert.deepEqual(await completedReplay.json(), replayBody,
        'a completed UUID retains its exact receipt after later head advancement');
      assert.equal(executorCalls, stateBeforeStale.executorCalls);
      status.exactSavedOperationReadback = true; await save();
      await frame.waitForFunction(name => {
        const section = [...document.querySelectorAll('section')]
          .find(node => node.textContent.includes('Schema-hash timeline'));
        return Boolean(section?.textContent.includes(name));
      }, { timeout: 15000 }, IMPORTED);
      status.renderedManifestImportSaved = true; await save();
      const adminSecond = await auth.login({ username: 'student_admin', password: 'student123' });
      const second = await bootstrap(adminSecond.context);
      const secondScope = await composition.launches.resolveCapability(second.bearer);
      assert.notEqual(secondScope.launchId, rows[0].platform_launch_id);
      const siblingHeaders = { authorization: `Bearer ${second.persona.token}`,
        'x-owasp-ai-goat-secureshop-launch': second.bearer,
        cookie: `owasp_ai_goat_shop_session=${adminSecond.token}` };
      const other = await fetch(`${origin}/api/secureshop/admin/mcp/servers`, { headers: siblingHeaders });
      assert.equal(other.status, 200);
      assert.deepEqual((await other.json()).servers, []);
      const privateGet = await fetch(`${origin}/api/secureshop/admin/mcp/operations/${operationId}`,
        { headers: siblingHeaders });
      assert.equal(privateGet.status, 404);
      const customerName = `mcp_sibling_${randomUUID().slice(0, 8)}`;
      const customer = await auth.register({ username: customerName,
        email: `${customerName}@example.invalid`, password: 'disposable-mcp-browser', role: 'customer' });
      const customerReady = await bootstrap(customer.context);
      const denied = await fetch(`${origin}/api/secureshop/admin/mcp/servers`, { headers: {
        authorization: `Bearer ${customerReady.persona.token}`,
        'x-owasp-ai-goat-secureshop-launch': customerReady.bearer,
        cookie: `owasp_ai_goat_shop_session=${customer.token}` } });
      assert.equal(denied.status, 403);
      assert.equal((await identity.query(`SELECT count(*)::integer AS n FROM identity.users WHERE id=$1`,
        [rows[0].original_platform_owner_id])).rows[0].n, 0);
      assert.equal((await identity.query(`SELECT count(*)::integer AS n FROM identity.user_sessions WHERE id=$1`,
        [rows[0].original_platform_session_id])).rows[0].n, 0);
      status.siblingDenied = true; await save();
      await clickRendered(frame, { selector: `button[aria-label="Remove ${NAME}"]` });
      await frame.waitForFunction(() => document.body.textContent.includes('Remove MCP server?'), { timeout: 10000 });
      await clickRendered(frame, { label: 'remove' });
      await frame.waitForFunction(name => !document.querySelector(`button[aria-label="Remove ${name}"]`),
        { timeout: 20000 }, NAME);
      await clickRendered(frame, { selector: `button[aria-label="Remove ${IMPORTED}"]` });
      await frame.waitForFunction(() => document.body.textContent.includes('Remove MCP server?'),
        { timeout: 10000 });
      await clickRendered(frame, { label: 'remove' });
      await frame.waitForFunction(() => document.body.textContent.includes('no MCP servers registered'),
        { timeout: 20000 });
      assert.equal((await agents.query(`SELECT count(*)::integer AS n FROM secureshop_agents.bound_mcp_registry_entries
        WHERE name=$1 AND lifecycle='active'`, [NAME])).rows[0].n, 0);
      assert.deepEqual((await agents.query(`SELECT name,action,registry_version
        FROM secureshop_agents.bound_mcp_registry_revisions ORDER BY registry_version`)).rows,
      [{ name: NAME, action: 'register', registry_version: '1' },
        { name: IMPORTED, action: 'import', registry_version: '2' },
        { name: NAME, action: 'retire', registry_version: '3' },
        { name: IMPORTED, action: 'retire', registry_version: '4' }]);
      assert.ok(await frame.evaluate((first, imported) => {
        const section = [...document.querySelectorAll('section')]
          .find(node => node.textContent.includes('Schema-hash timeline'));
        return Boolean(section?.textContent.includes(first) && section.textContent.includes(imported));
      }, NAME, IMPORTED));
      status.renderedRemovalHistoryRetained = true; await save();
      assert.deepEqual((await identity.query(`SELECT
        (SELECT count(*)::integer FROM identity.users) AS users,
        (SELECT count(*)::integer FROM identity.user_sessions) AS sessions`)).rows[0], platformBefore,
      'standalone registry did not create platform users or sessions');
      assert.equal(status.modelCalls, 0);
      }
    } catch (error) { failure = error; status.status = 'failed'; status.error = {
      code: error.code || null, message: error.message.slice(0, 300) };
      if (v39AtomicBrowserAudit) status.browserApi = v39AtomicBrowserAudit.snapshot();
      v39BrowserDiagnostic?.record(error); await save(); }
    finally {
      for (const close of [() => registeredInvocation?.close(), () => v43Recorder?.close(),
        () => v39PairTransport?.close(),
        async () => { await v43Transport?.close();
          if (v43Receipt && v43Transport) v43Receipt.wireClosed = true;
          if (v39Receipt && v43Transport) v39Receipt.wireClosed = true;
          if (handoffReceipt && v43Transport) handoffReceipt.wireClosed = true;
          if (v66Receipt && v43Transport) v66Receipt.wireClosed = true;
          if (v42Receipt && v43Transport) v42Receipt.wireClosed = true; },
        () => dropper?.close(), () => browser?.close(),
        async () => { if (v39AtomicBrowserAudit)
          status.browserApi = await v39AtomicBrowserAudit.finish(async snapshot => {
            status.browserApi = snapshot; await save(); }); },
        () => closeServer(server), () => registry?.close(),
        () => composition?.closeBrowserAssessment?.(),
        () => profile ? fs.rm(profile, { recursive: true, force: true }) : undefined,
        ...Object.values(pools).map(pool => () => pool.end()),
        () => leasePool.end()]) {
        try { await close(); } catch (error) { status.cleanupErrors.push(error.code || error.message); }
      }
      status.cleanupComplete = status.cleanupErrors.length === 0;
      if (MODEL_REGISTRY_ENABLED && v43Transport) {
        const pairSnapshot = V39_PAIR_ENABLED ? v39PairTransport?.snapshot() : null;
        status.actorCalls = pairSnapshot ? pairSnapshot.arms.control.actor + pairSnapshot.arms.treatment.actor
          : v43Transport.calls.filter(row => row.kind === 'actor').length;
        status.judgeCalls = pairSnapshot ? pairSnapshot.arms.control.judge + pairSnapshot.arms.treatment.judge
          : v43Transport.calls.filter(row => row.kind === 'judge').length;
        status.modelCalls = status.actorCalls + status.judgeCalls;
        if (v43Receipt) { v43Receipt.actorCalls = status.actorCalls; v43Receipt.judgeCalls = status.judgeCalls; }
        if (v39Receipt) { v39Receipt.actorCalls = status.actorCalls; v39Receipt.judgeCalls = status.judgeCalls; }
        if (handoffReceipt) { handoffReceipt.actorCalls = status.actorCalls;
          handoffReceipt.judgeCalls = status.judgeCalls; }
        if (v66Receipt) { v66Receipt.actorCalls = status.actorCalls; v66Receipt.judgeCalls = status.judgeCalls; }
        if(v42Receipt){v42Receipt.actorCalls=status.actorCalls;v42Receipt.judgeCalls=status.judgeCalls;}
      }
      if (status.cleanupComplete && !failure) status.status = 'passed';
      if (V39_PAIR_ENABLED) {
        if (!failure) try {
          assert.ok(v39PairReceipt, 'both original rendered arms must complete');
          const pairSnapshot = v39PairTransport.snapshot();
          v39PairReceipt = require('../fixtures/secureshopMcpDescriptionAtomicPairRenderedQualification')
            .finalizePairReceipt(v39PairReceipt, {
              cleanupComplete: status.cleanupComplete,
              relayRetired: !pairSnapshot.failed && pairSnapshot.arms.control.state === 'finished'
                && pairSnapshot.arms.treatment.state === 'finished',
              browserApi: status.browserApi,
            });
          assert.equal(status.actorCalls, v39PairReceipt.control.actorCalls + v39PairReceipt.treatment.actorCalls);
          assert.equal(status.judgeCalls, v39PairReceipt.control.judgeCalls + v39PairReceipt.treatment.judgeCalls);
        } catch (error) { failure = error; status.status = 'failed'; status.error = {
          code: error.code || null, message: error.message.slice(0, 300) }; }
      }
      if (v43Receipt) {
        v43Receipt.fixtureCleaned = status.cleanupComplete;
        v43Receipt.passed = status.status === 'passed';
        v43Receipt.errors = status.cleanupErrors;
        await fs.writeFile(path.join(path.dirname(evidencePath), 'mcp-impersonation-receipt.json'),
          JSON.stringify(v43Receipt, null, 2) + '\n', { mode: 0o600 });
      }
      if (v39Receipt) {
        v39Receipt.fixtureCleaned = status.cleanupComplete;
        v39Receipt.passed = status.status === 'passed';
        v39Receipt.errors = status.cleanupErrors;
        if (!failure) try { v39Contract.assertReceipt(v39Receipt); }
        catch (error) { failure = error; status.status = 'failed'; v39Receipt.passed = false;
          status.error = { code: error.code || null, message: error.message.slice(0, 300) }; }
        if (v39Writer) v39Writer.write('mcp-description-receipt.json', JSON.stringify(v39Receipt, null, 2) + '\n');
        else await fs.writeFile(path.join(path.dirname(evidencePath), 'mcp-description-receipt.json'),
          JSON.stringify(v39Receipt, null, 2) + '\n', { mode: 0o600 });
      }
      let q05ReceiptBytes;
      if (handoffReceipt) {
        handoffReceipt.fixtureCleaned = status.cleanupComplete;
        handoffReceipt.passed = status.status === 'passed';
        handoffReceipt.errors = status.cleanupErrors;
        if (!failure) try { v39Contract.assertHandoffReceipt(handoffReceipt); }
        catch (error) { failure = error; status.status = 'failed'; handoffReceipt.passed = false;
          status.error = { code: error.code || null, message: error.message.slice(0, 300) }; }
        if (q05Writer) q05ReceiptBytes = JSON.stringify(handoffReceipt, null, 2) + '\n';
        else await fs.writeFile(path.join(path.dirname(evidencePath), 'registered-handoff-receipt.json'),
          JSON.stringify(handoffReceipt, null, 2) + '\n', { mode: 0o600 });
      }
      if (v66Receipt) {
        v66Receipt.fixtureCleaned = status.cleanupComplete;
        v66Receipt.passed = status.status === 'passed';
        v66Receipt.errors = status.cleanupErrors;
        if (!failure) try { v66Contract.assertV66Receipt(v66Receipt); }
        catch (error) { failure = error; status.status = 'failed'; status.error = {
          code: error.code || null, message: error.message.slice(0, 300) };
          v66Receipt.passed = false; }
        await fs.writeFile(path.join(path.dirname(evidencePath), 'mcp-manifest-receipt.json'),
          JSON.stringify(v66Receipt, null, 2) + '\n', { mode: 0o600 });
      }
      if(v42Receipt){v42Receipt.fixtureCleaned=status.cleanupComplete;v42Receipt.passed=status.status==='passed';v42Receipt.errors=status.cleanupErrors;
        if(!failure)try{v66Contract.assertV42Receipt(v42Receipt);}catch(error){failure=error;status.status='failed';v42Receipt.passed=false;status.error={code:error.code||null,message:error.message.slice(0,300)};}
        await fs.writeFile(path.join(path.dirname(evidencePath),'mcp-discovery-receipt.json'),JSON.stringify(v42Receipt,null,2)+'\n',{mode:0o600});}
      if (q05Writer) failure = await q05FinalPrivateSave({ writer: q05Writer,
        receiptBytes: q05ReceiptBytes, save, status, receipt: handoffReceipt, primary: failure });
      else try { await save(); } finally { v39Writer?.close(); }
    }
    if (failure) throw failure;
    assert.equal(status.cleanupComplete, true, 'all fixture-local resources must close');
    if (V39_PAIR_ENABLED) publishV39AtomicFinalReceipt(v39Directory, v39PairReceipt);
    if (v43Receipt) v43Contract.assertV43Receipt(v43Receipt);
    if (v66Receipt) v66Contract.assertV66Receipt(v66Receipt);
    if(v42Receipt)v66Contract.assertV42Receipt(v42Receipt);
  });

module.exports = { admitV39CurrentHostEvidence, createV39PrivateWriter,
  admitQ05CurrentHostEvidence, createQ05PrivateWriter, q05CurrentHostBrowserOptions,
  q05RegisteredInvocationCompositionOptions,
  q05InitialPrivateSave, q05FinalPrivateSave,
  retainV39Admission, initializeV39Receipt, initializeObservedV39Receipt,
  v39CurrentHostBrowserOptions, createV39BrowserDiagnostic, switchV39AtomicProvider,
  registryBrowserLoginUrl, v39AtomicBrowserRequestAllowed, createV39AtomicBrowserAudit, publishV39AtomicFinalReceipt };

if (D16_ENABLED) test('standalone MCP trust physically selects rogue and changed tools with registered Judge evidence and reset isolation',
  { timeout: 360000 }, async () => {
    const root = path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(root, process.cwd(), 'reviewed current-main source required');
    const build = path.resolve(process.env.MCP_TRUST_STANDALONE_RENDERED_BUILD || '/');
    assert.equal(build, path.join(root, 'client/build'));
    await fs.access(path.join(build, 'index.html'));
    await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    const evidencePath = process.env.MCP_TRUST_STANDALONE_RENDERED_RESULT || '';
    assert.ok(path.isAbsolute(evidencePath)
      && !path.resolve(evidencePath).startsWith(`${root}${path.sep}`));
    const evidenceDirectory = path.dirname(evidencePath);
    const evidenceStat = await fs.lstat(evidenceDirectory);
    assert.equal(evidenceStat.isDirectory(), true);
    assert.equal(evidenceStat.isSymbolicLink(), false);
    assert.equal(evidenceStat.uid, process.getuid());
    assert.equal(evidenceStat.mode & 0o777, 0o700);
    assert.equal(fsSync.existsSync(evidencePath), false, 'D16 result must be fresh');
    assert.equal(process.env.PLATFORM_DATABASE_ENGINE, 'postgres');
    assert.equal(process.env.WORKSHOP_DATABASE_ENGINE, 'postgres');
    assert.equal(process.env.SS_MCP_TRUST_READY, 'true');
    const fixtureRoot = path.resolve(process.env.SS_MCP_TRUST_FIXTURE_ROOT || '/');
    assert.ok(fixtureRoot !== '/' && !fixtureRoot.startsWith(`${root}${path.sep}`));
    const fixtureStat = await fs.lstat(fixtureRoot);
    assert.equal(fixtureStat.isDirectory(), true);
    assert.equal(fixtureStat.isSymbolicLink(), false);
    assert.equal(fixtureStat.uid, process.getuid());
    assert.equal(fixtureStat.mode & 0o777, 0o700);
    const urls = disposableUrls();
    const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
      const key = `${store}_${role}`;
      return [key, new Pool({ connectionString: urls[key], max: role === 'RUNTIME' ? 12 : 3,
        connectionTimeoutMillis: 5000, statement_timeout: 10000 })];
    })));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4,
      connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    const provisionPool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 1,
      connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    const status = { status: 'running', scope: 'D16-standalone', isolatedStores: false,
      distinctTenantSibling: false, genuineAdminSessions: false, renderedControls: false,
      actualModelEvidence: false, registeredJudgeCredit: false, exactReplay: false,
      siblingDenied: false, resetFenced: false, wireClosed: false,
      actorCalls: 0, judgeCalls: 0, cleanupComplete: false, cleanupErrors: [] };
    const save = () => fs.writeFile(evidencePath, JSON.stringify(status, null, 2) + '\n',
      { mode: 0o600 });
    await save();
    let transport, recorder, composition, resetComposition, server, peerServer, browser, ownerContext, peerContext;
    let profile, ownerPage, peerPage, failure;
    const capture = name => value => {
      const file = path.join(evidenceDirectory, name);
      const bytes = JSON.stringify(value);
      assert.ok(Buffer.byteLength(bytes) <= 64 * 1024 * 1024, 'private capture is bounded');
      fsSync.writeFileSync(file, bytes + '\n', { mode: 0o600 });
    };
    const captureActor = capture('mcp-trust-d16-model.json');
    const captureQualification = capture('mcp-trust-d16-qualification.json');
    try {
      for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'],
        ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop']]) {
        await migrate(pools[`${store}_MIGRATION`], path.join(root, 'db/postgres', directory));
      }
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed')
        .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed')
        .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seedClient = await pools.COMMERCE_MIGRATION.connect();
      try { await seedClient.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
        await seedClient.query('COMMIT');
      } catch (error) { await seedClient.query('ROLLBACK'); throw error; }
      finally { seedClient.release(); }
      status.isolatedStores = true; await save();
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const authFactory = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService;
      const authRepository = require('../../server/database/postgres/secureshopStandaloneAuthRepository')
        .createSecureShopStandaloneAuthRepository;
      const auth = authFactory({ repository: authRepository({ pool: identity }) });
      const catalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const configurationAdmin = await auth.login({ username: 'student_admin', password: 'student123' });
      for (const objectiveId of ['ss_rogue_tool_selected', 'ss_rug_pull_invoked']) {
        const current = (await catalog.list(configurationAdmin.context)).objectives
          .find(row => row.objectiveId === objectiveId);
        assert.ok(current && current.qualification === 'native-model');
        if (!current.enabled) assert.equal((await catalog.set(configurationAdmin.context,
          { objectiveId, enabled: true, expectedRevision: current.revision })).enabled, true);
      }
      const peerId = randomUUID(), peerName = `mcp_peer_${randomUUID().slice(0, 8)}`;
      const peerHash = await require('bcryptjs').hash('disposable-mcp-trust-peer', 12);
      const peerRow = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
        (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin') RETURNING shop_user_id`,
      [peerId, peerName, `${peerName}@example.invalid`, peerHash])).rows[0];
      const peerTenantId = randomUUID(), peerSlug = `mcp_peer_${randomUUID().slice(0, 8)}`;
      await pools.IDENTITY_MIGRATION.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
        [peerTenantId, peerSlug]);
      const peerMerchantName = `mcp_peer_merchant_${randomUUID().slice(0, 8)}`;
      const peerMerchant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
        (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant') RETURNING principal_id,shop_user_id`,
      [randomUUID(), peerMerchantName, `${peerMerchantName}@example.invalid`, peerHash])).rows[0];
      await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
      [peerTenantId, peerMerchant.principal_id, peerMerchant.shop_user_id]);
      const peerSeed = await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants AS t
        SET seed_merchant_id=$2 WHERE t.tenant_id=$1 AND t.seed_merchant_id IS NULL
        AND EXISTS (SELECT 1 FROM secureshop_auth.tenant_memberships AS m
          WHERE m.tenant_id=t.tenant_id AND m.principal_id=$3 AND m.shop_user_id=$2
            AND m.role='merchant' AND m.is_active=true)`,
      [peerTenantId, peerMerchant.shop_user_id, peerMerchant.principal_id]);
      assert.equal(peerSeed.rowCount, 1);
      await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
      [peerTenantId, peerId, peerRow.shop_user_id]);
      const peerAuth = authFactory({ repository: authRepository({ pool: identity,
        executionTenantSlug: peerSlug }) });
      const audit = require('../../server/services/secureshopBoundAuditComposition')
        .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
          includeRunArtifacts: true });
      const reset = require('../../server/services/secureshopCleanupComposition')
        .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, leasePool, provisionPool, audit,
          mcpTrustFactory: require('../../server/services/secureshopCleanupComposition')
            .createDefaultMcpTrustBundle, mcpTrustFixtureRoot: fixtureRoot });
      assert.equal(typeof reset.mcpTrust?.repository?.readInvocation, 'function');
      assert.equal(typeof reset.mcpTrust?.targetPool?.ensure, 'function');
      assert.equal(typeof reset.mcpTrust?.authorizeRotation, 'function');
      assert.equal(typeof reset.conversationService?.create, 'function');
      assert.equal(typeof reset.turns?.run, 'function');
      assert.equal(typeof reset.conversations?.appendTraces, 'function');
      resetComposition = reset;
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identity);
      const wireDirectory = path.join(evidenceDirectory, 'mcp-trust-wire');
      await fs.mkdir(wireDirectory, { mode: 0o700 });
      transport = await require('./secureshopMailBrowserJudgeTransport')
        .createInboxTransport({ evidence: wireDirectory, profile: 'mcp-trust-actual' });
      const qualifier = require('../fixtures/secureshopMcpTrustStandaloneQualification');
      recorder = qualifier.createMcpTrustD16Recorder({ transport, record: captureActor });
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset, judge: recorder.judge,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopProductionSceneRepository({ pool: identity, provisionPool,
            leasePool, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
        .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
      const standaloneModeFactory = V40_ENABLED
        ? require('../../server/services/secureshopStandaloneMode').createSecureShopStandaloneMode : null;
      const ownerStandaloneMode = standaloneModeFactory
        ? standaloneModeFactory({ authService: auth, repository: modeRepository }) : null;
      const peerStandaloneMode = standaloneModeFactory
        ? standaloneModeFactory({ authService: peerAuth, repository: modeRepository }) : null;
      composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, scenes, modeAuthority, mcpTrustFeature: true,
          mcpTrustFixtureRoot: fixtureRoot, fixtures: [],
          requiredObjectives: ['ss_rogue_tool_selected', 'ss_rug_pull_invoked'],
          jwtSecret: 'disposable-mcp-trust-secret-at-least-32-bytes',
          agentRuntime: { provider: recorder.provider }, judge: recorder.judge });
      assert.equal(composition.mcpTrust.ready, true);
      const v40Denials = [];
      const v40Application = V40_ENABLED ? Object.freeze({ ...composition.mcpTrust.application,
        async run(input) {
          try { return await composition.mcpTrust.application.run(input); }
          catch (error) {
            if (input.trustScenario === 'rug_pull' && v40Denials.length < 4)
              v40Denials.push({ requestId: input.requestId, code: error.code || null,
                message: String(error.message).slice(0, 160) });
            throw error;
          }
        } }) : null;
      const v40Router = V40_ENABLED ? require('../../server/routes/secureshop/boundMcpTrust')
        .createBoundMcpTrustRouter({ launches: composition.launches,
          authenticatePersona: composition.personaAuth.authenticatePersona,
          application: v40Application }) : null;
      const visibility = require('../../server/database/postgres/workshopConfigRepository')
        .createWorkshopConfigRepository(identity, {
          isSecureShopReady: () => composition?.mcpTrust?.ready === true });
      await visibility.setExerciseVisibility('secureshop_agent_security', true);
      for (const objectiveId of ['ss_rogue_tool_selected', 'ss_rug_pull_invoked'])
        await visibility.setObjectiveVisibility('secureshop_agent_security', objectiveId, true);
      const available = await require('../../server/services/secureshopMcpTrustAvailability')
        .createSecureShopMcpTrustAvailability(identity).read();
      assert.equal(available.visible, true);
      assert.deepEqual(available.enabled, { rogue_registration: true, rug_pull: true });
      await composition.repositories.personas.ensureTemplates();
      const bootstrapFactory = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap;
      const bootstrap = bootstrapFactory({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
      const peerBootstrap = bootstrapFactory({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: peerAuth });
      const resetFactory = require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset;
      const protectedReset = resetFactory({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes,
          resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight });
      const peerProtectedReset = resetFactory({ identityPool: identity, authService: peerAuth,
        launches: composition.launches, scenes,
        resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight });
      const mounted = service => ({ ...composition, scenes,
        ...(V40_ENABLED && service === auth ? { mcpTrust: { ...composition.mcpTrust,
          router: v40Router } } : {}),
        standaloneAuth: { service, bootstrap: service === auth ? bootstrap : peerBootstrap,
          reset: service === auth ? protectedReset : peerProtectedReset,
          ...(V40_ENABLED ? { mode: service === auth ? ownerStandaloneMode : peerStandaloneMode } : {}) },
        personaInbox: { ready: true, router: express.Router() },
        ssrf: { ready: true, router: express.Router() } });
      const boundFactory = require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication;
      const originApps = [];
      for (const [service, boot] of [[auth, bootstrap], [peerAuth, peerBootstrap]]) {
        const current = mounted(service);
        const bound = await boundFactory({ engine: 'postgres', shopEnabled: true,
          authenticateToken: (_request, response) => response.sendStatus(401),
          audit: async () => {}, agentRuntime: {}, getComposition: async () => current });
        const app = express(); app.use(express.json());
        const opened = await new Promise(resolve => {
          const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
        });
        if (service === auth) server = opened;
        else peerServer = opened;
        const origin = `http://127.0.0.1:${opened.address().port}`;
        app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
          .createSecureShopStandaloneAuthRouter({ service, bootstrap: boot,
            reset: service === auth ? protectedReset : peerProtectedReset,
            ...(V40_ENABLED ? { mode: service === auth ? ownerStandaloneMode : peerStandaloneMode } : {}),
            allowedOrigins: [origin], secureCookies: false }));
        app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
          .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
        app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside D16 qualifier' }));
        app.use(express.static(build, { setHeaders: response => response.set('Access-Control-Allow-Origin', '*') }));
        app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
        originApps.push({ origin, server: opened });
      }
      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-mcp-trust-rendered-'));
      browser = await require('puppeteer').launch({ headless: true, userDataDir: profile, executablePath });
      ownerContext = await browser.createBrowserContext(); peerContext = await browser.createBrowserContext();
      const openAdmin = async (context, origin, username, password) => {
        const page = await context.newPage(); await page.setViewport({ width: 1280, height: 900 });
        const apiResponses = [], failedRequests = [];
        page.on('response', response => {
          const url = new URL(response.url());
          if (url.origin === origin && url.pathname.startsWith('/api/secureshop/')
            && apiResponses.length < 32) apiResponses.push({ path: url.pathname,
              method: response.request().method(), status: response.status() });
        });
        page.on('requestfailed', request => {
          const url = new URL(request.url());
          if (url.origin === origin && failedRequests.length < 12)
            failedRequests.push({ path: url.pathname, method: request.method(),
              failure: String(request.failure()?.errorText || '').slice(0, 80) });
        });
        await page.setRequestInterception(true);
        page.on('request', request => request.url().startsWith(`${origin}/`)
          ? request.continue() : request.abort());
        const bootResponse = page.waitForResponse(response =>
          response.request().method() === 'POST'
          && new URL(response.url()).origin === origin
          && new URL(response.url()).pathname === '/api/secureshop/auth/bootstrap',
        { timeout: 30000 }).then(response => ({ response }), error => ({ error }));
        await page.goto(`${origin}/secureshop/login?next=%2Fsecureshop%2Fadmin%2Fmcp`,
          { waitUntil: 'domcontentloaded' });
        await page.waitForSelector('#ss-login-user'); await page.type('#ss-login-user', username);
        await page.type('#ss-login-pw', password); await page.click('button[type="submit"]');
        const observed = await bootResponse; if (observed.error) throw observed.error;
        assert.equal(observed.response.status(), 200);
        const issued = await observed.response.json();
        assert.ok(issued.bearer && issued.persona?.token);
        const trustReadiness = await fetch(`${origin}/api/secureshop/v2/mcp-trust/readiness`, {
          headers: { 'x-owasp-ai-goat-secureshop-launch': issued.bearer,
            authorization: `Bearer ${issued.persona.token}` },
          signal: AbortSignal.timeout(10000) });
        const trustStatus = trustReadiness.status;
        const trustBody = await trustReadiness.json();
        assert.equal(trustStatus, 200);
        assert.equal(trustBody.ready, true);
        assert.deepEqual(trustBody.scenarios,
          { rogue_registration: true, rug_pull: true });
        await page.waitForFunction(() => location.pathname === '/secureshop/admin/mcp', { timeout: 30000 });
        const frame = await frameOn(page);
        try {
          await frame.waitForSelector('section[aria-label="Controlled MCP trust lab"]', { visible: true });
        } catch (error) {
          const diagnostic = { role: username === peerName ? 'peer' : 'owner', apiResponses,
            failedRequests, parentPath: new URL(page.url()).pathname };
          try {
            diagnostic.frame = await frame.evaluate(() => ({ path: location.pathname,
              headings: [...document.querySelectorAll('h1,h2')].slice(0, 12)
                .map(node => node.textContent.trim().slice(0, 100)),
              alerts: [...document.querySelectorAll('[role="alert"]')].slice(0, 8)
                .map(node => node.textContent.trim().slice(0, 160)),
              statuses: [...document.querySelectorAll('[role="status"]')].slice(0, 8)
                .map(node => node.textContent.trim().slice(0, 160)),
              trustLabPresent: Boolean(document.querySelector('section[aria-label="Controlled MCP trust lab"]')) }));
          } catch (cause) { diagnostic.frameError = cause.name; }
          capture(`mcp-trust-open-${diagnostic.role}.json`)(diagnostic);
          try {
            const image = await page.screenshot({ type: 'png', fullPage: false });
            assert.ok(image.length <= 8 * 1024 * 1024);
            await fs.writeFile(path.join(evidenceDirectory,
              `mcp-trust-open-${diagnostic.role}.png`), image, { mode: 0o600, flag: 'wx' });
          } catch { /* Preserve the original rendered failure and JSON diagnostic. */ }
          throw error;
        }
        return { page, frame, issued };
      };
      const ownerUi = await openAdmin(ownerContext, originApps[0].origin,
        'student_admin', 'student123');
      ownerPage = ownerUi.page;
      const peerUi = await openAdmin(peerContext, originApps[1].origin,
        peerName, 'disposable-mcp-trust-peer');
      peerPage = peerUi.page;
      const session = async (ui, service, origin) => {
        const cookie = (await ui.page.cookies(`${origin}/api/secureshop/auth/session`))
          .find(row => row.name === 'owasp_ai_goat_shop_session');
        assert.equal(cookie?.httpOnly, true);
        const principal = await service.authenticate(cookie.value);
        assert.ok(principal && principal.role === 'admin');
        const scope = await composition.launches.resolveCapability(ui.issued.bearer);
        assert.ok(scope);
        const actor = await composition.personaAuth.authenticateBoundToken({ scope,
          token: ui.issued.persona.token });
        assert.equal(actor.user.role, 'admin');
        return { page: ui.page, frame: ui.frame,
          binding: { ...scope, shopUserId: actor.user.id, role: actor.user.role },
          personaSessionId: actor.sessionId,
          personaAuthorityVersion: actor.authorityVersion,
          headers: { 'x-owasp-ai-goat-secureshop-launch': ui.issued.bearer,
            authorization: `Bearer ${ui.issued.persona.token}` }, principal };
      };
      const owner = await session(ownerUi, auth, originApps[0].origin);
      const sibling = await session(peerUi, peerAuth, originApps[1].origin);
      assert.notEqual(owner.binding.platformOwnerId, sibling.binding.platformOwnerId);
      assert.notEqual(owner.binding.launchId, sibling.binding.launchId);
      if (V40_ENABLED) {
        const cookie = (await owner.page.cookies(`${originApps[0].origin}/api/secureshop/auth/mode`))
          .find(row => row.name === 'owasp_ai_goat_shop_session');
        assert.ok(cookie?.value, 'authenticated owner mode preflight requires the real shop session');
        const modeRead = await fetch(`${originApps[0].origin}/api/secureshop/auth/mode`, {
          headers: { cookie: `owasp_ai_goat_shop_session=${cookie.value}` }, signal: AbortSignal.timeout(10000) });
        assert.equal(modeRead.status, 200, 'standalone mode route must be mounted before model turns');
        const modeState = await modeRead.json();
        assert.equal(modeState.mode, 'vuln');
        assert.match(modeState.revision, /^[1-9][0-9]*$/);
      }
      status.distinctTenantSibling = true; status.genuineAdminSessions = true; await save();
      const summary = await qualifier.qualifyMcpTrustStandalone({ identityRuntime: identity,
        agentsRuntime: agents, owner, sibling, origin: originApps[0].origin, fixtureRoot,
        recorder, beforeReset: V40_ENABLED ? async ({ owner: subject, positive }) => {
          const contrast = await require('../fixtures/secureshopMcpRugPullV40Qualification')
            .qualifyFixedRugPull({ owner: subject, origin: originApps[0].origin,
              identityRuntime: identity, agentsRuntime: agents, transport,
              positive, getFrame: frameOn,
              readOriginalDenial: async requestId => {
                const matches = v40Denials.filter(row => row.requestId === requestId);
                assert.equal(matches.length, 1, 'one original production denial for physical request');
                return matches[0];
              }, record: capture('mcp-trust-v40-qualification.json') });
          assert.deepEqual(contrast, { scope: 'V40-fixed-contrast', physicalMode: true,
            physicalChangedRunDenied: true, noInvocation: true, noEffect: true,
            noJudgeCredit: true, sameIdentity: true });
          return contrast;
        } : undefined, resetOwner: async subject => {
          const target = await composition.catalog.prepareTarget({ scope: subject.binding,
            persona: { id: subject.binding.shopUserId, role: 'admin' },
            personaSession: { sessionId: subject.personaSessionId,
              authorityVersion: subject.personaAuthorityVersion } });
          assert.ok(target.targetId);
          const readiness = await protectedReset.readiness(subject.principal);
          assert.equal(readiness.available, true);
          return protectedReset.reset(subject.principal, {
            confirmation: 'RESET_SHARED_PRACTICE', expectedGeneration: readiness.generation,
            idempotencyKey: randomUUID(), launchId: readiness.launchId,
            sceneId: readiness.scene.id });
        }, record: captureQualification });
      assert.equal(summary.qualified, true);
      assert.equal(summary.actualModelProof, true);
      assert.equal(summary.genuineCredit, 2);
      assert.equal(summary.renderedControls, 6);
      assert.equal(summary.actualTurns, 3);
      const peerTargets = (await agents.query(`SELECT target_id,launch_id,scenario_id,generation,
        original_platform_owner_id,original_platform_session_id
        FROM secureshop_agents.bound_mcp_targets WHERE launch_id=$1 ORDER BY target_id`,
      [sibling.binding.launchId])).rows;
      assert.equal(peerTargets.length, 1);
      const peerTarget = await composition.catalog.prepareTarget({ scope: sibling.binding,
        persona: { id: sibling.binding.shopUserId, role: 'admin' },
        personaSession: { sessionId: sibling.personaSessionId,
          authorityVersion: sibling.personaAuthorityVersion } });
      assert.ok(peerTarget.targetId);
      const peerReadiness = await peerProtectedReset.readiness(sibling.principal);
      assert.equal(peerReadiness.available, true);
      assert.equal(peerReadiness.launchId, sibling.binding.launchId);
      const peerReset = await peerProtectedReset.reset(sibling.principal, {
        confirmation: 'RESET_SHARED_PRACTICE', expectedGeneration: peerReadiness.generation,
        idempotencyKey: randomUUID(), launchId: peerReadiness.launchId,
        sceneId: peerReadiness.scene.id });
      assert.equal(peerReset.status, 'committed');
      assert.equal(peerReset.cleanupComplete, true);
      const peerCleanup = (await agents.query(`SELECT operation_id,target_id,launch_id,scenario_id,
        generation,original_platform_owner_id,original_platform_session_id,receipt_sha256
        FROM secureshop_agents.bound_mcp_cleanup_receipts WHERE target_id=$1 AND operation_id=$2`,
      [peerTargets[0].target_id, peerReset.resetId])).rows;
      assert.equal(peerCleanup.length, 1);
      assert.equal(peerCleanup[0].target_id, peerTargets[0].target_id);
      for (const key of ['launch_id','scenario_id','generation','original_platform_owner_id',
        'original_platform_session_id']) assert.equal(String(peerCleanup[0][key]), String(peerTargets[0][key]));
      assert.equal(peerCleanup[0].receipt_sha256.length, 32);
      assert.deepEqual(await fs.readdir(fixtureRoot), []);
      status.renderedControls = true; status.actualModelEvidence = true;
      status.registeredJudgeCredit = true; status.exactReplay = true;
      status.siblingDenied = true; status.resetFenced = true;
      status.actorCalls = summary.actorCalls; status.judgeCalls = summary.judgeCalls;
      await save();
    } catch (error) {
      failure = error; status.status = 'failed'; status.error = {
        code: error.code || null, message: String(error.message).slice(0, 300) };
      await save();
    } finally {
      for (const close of [() => recorder?.close(), () => ownerPage?.close(), () => peerPage?.close(),
        () => ownerContext?.close(), () => peerContext?.close(), () => browser?.close(),
        () => closeServer(server), () => closeServer(peerServer),
        () => composition?.closeBrowserAssessment?.(),
        () => resetComposition?.mcpTrust?.close?.(),
        () => transport?.close(),
        () => profile ? fs.rm(profile, { recursive: true, force: true }) : undefined,
        ...Object.values(pools).map(pool => () => pool.end()),
        () => provisionPool.end(), () => leasePool.end()]) {
        try { await close(); } catch (error) { status.cleanupErrors.push(error.code || error.message); }
      }
      if (transport) {
        const wire = transport.snapshot();
        const qualifiedCounts = { actor: status.actorCalls, judge: status.judgeCalls };
        status.actorCalls = wire.calls.filter(row => row.role === 'actor').length;
        status.judgeCalls = wire.calls.filter(row => row.role === 'judge').length;
        status.wireClosed = wire.closed === true && wire.failed === false
          && wire.physicalPending === 0 && wire.calls.every(row => row.status === 'returned');
        if (!status.wireClosed) status.cleanupErrors.push('D16_WIRE_NOT_TERMINAL');
        if (!failure && (status.actorCalls !== qualifiedCounts.actor
          || status.judgeCalls !== qualifiedCounts.judge)) {
          status.cleanupErrors.push('D16_WIRE_COUNT_MISMATCH');
        }
      }
      status.cleanupComplete = status.cleanupErrors.length === 0;
      if (status.cleanupComplete && !failure) status.status = 'passed';
      await save();
    }
    if (failure) throw failure;
    assert.equal(status.cleanupComplete, true);
    assert.equal(status.wireClosed, true);
  });
