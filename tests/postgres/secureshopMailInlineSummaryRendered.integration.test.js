'use strict';

// Opted, disposable V55 browser qualification. This file owns its evidence;
// controlled route/component tests are never a substitute for the gated run.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const express = require('express');
const { Pool } = require('pg');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { migrate } = require('../../db/postgres/migrate');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_';
const GATE = 'SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_NATIVE';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const OBJECTIVE = 'ss_mail_inline_image_ssrf';
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const TITLE = 'merchant physically saves and summarizes owned inline mail with original HTTP and canonical Judge proof';
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function capturedShopAuthority(launch, authorization) {
  // The launch capability is the raw 43-character header value. Only the
  // separately authenticated persona JWT uses the Authorization scheme.
  assert.match(launch, /^[A-Za-z0-9_-]{43}$/);
  assert.match(authorization, /^Bearer [A-Za-z0-9_.-]+$/);
  return { launch, personaToken: authorization.slice('Bearer '.length) };
}

function nativeConfiguration(env = process.env) {
  assert.equal(env[GATE], '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.LIVE_OLLAMA_TEST, '1');
  assert.equal(path.resolve(env.DVAIA_CURRENT_MAIN_WORKSPACE || ''), ROOT);
  assert.equal(process.cwd(), ROOT);
  assert.equal(path.resolve(env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_BUILD || ''),
    path.join(ROOT, 'client/build'));
  assert.match(env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_MODEL_DIGEST || '', SHA);
  assert.match(env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_BROWSER_SHA256 || '', SHA);
  const evidencePath = env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_EVIDENCE_PATH;
  const recordPath = env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_RECORD_PATH;
  assert.ok(path.isAbsolute(evidencePath || '') && path.isAbsolute(recordPath || ''));
  assert.equal(path.dirname(evidencePath), path.dirname(recordPath));
  assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
  const urls = {};
  let nonce, port;
  for (const [key, name] of Object.entries(STORES)) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const url = new URL(env[`${PREFIX}${key}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = /^\/dvaia_test_agent_host_([0-9a-f]{12})_([a-z_]+)$/.exec(url.pathname);
      assert.ok(match && match[2] === name, `${key} must use its owned disposable store`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[`${key}_${role}`] = url.href;
    }
    assert.equal(new URL(urls[`${key}_MIGRATION`]).pathname,
      new URL(urls[`${key}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(key =>
    new URL(urls[`${key}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze({ urls, evidencePath, recordPath,
    browser: env.PUPPETEER_EXECUTABLE_PATH, build: env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_BUILD });
}

function teachingResponse(value, requestId) {
  if (exact(value, ['ok', 'status', 'requestId']) && value.ok === true
    && value.status === 'unconfirmed' && value.requestId === requestId) return value;
  assert.ok(exact(value, ['ok', 'status', 'requestId', 'messageId', 'threadId', 'replayed']));
  assert.equal(value.ok, true); assert.equal(value.status, 'saved');
  assert.equal(value.requestId, requestId);
  assert.ok(Number.isSafeInteger(value.messageId) && value.messageId > 0);
  assert.ok(Number.isSafeInteger(value.threadId) && value.threadId > 0);
  assert.equal(typeof value.replayed, 'boolean');
  return value;
}
function summaryResponse(value, requestId) {
  if (exact(value, ['ok', 'status', 'requestId']) && value.ok === true
    && value.status === 'unconfirmed' && value.requestId === requestId) return value;
  assert.ok(exact(value, ['ok', 'status', 'requestId', 'sessionId', 'text',
    'replayed', 'assessmentStatus']));
  assert.equal(value.ok, true); assert.equal(value.status, 'completed');
  assert.equal(value.requestId, requestId); assert.match(value.sessionId, UUID);
  assert.ok(typeof value.text === 'string' && value.text.trim()
    && value.text.isWellFormed() && Buffer.byteLength(value.text) <= 32768);
  assert.equal(typeof value.replayed, 'boolean');
  assert.equal(value.assessmentStatus, 'pending');
  return value;
}
function assessmentResponse(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated'])
    && value.completed === false && value.modelEvaluated === false
    && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
  assert.ok(exact(value, ['completed', 'judgment', 'replayed']));
  assert.equal(typeof value.completed, 'boolean');
  assert.equal(typeof value.replayed, 'boolean');
  assert.ok(exact(value.judgment, ['verdict', 'evaluationId', 'canRetry']));
  assert.match(value.judgment.evaluationId, UUID);
  assert.ok(['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict));
  assert.equal(typeof value.judgment.canRetry, 'boolean');
  if (value.completed) assert.equal(value.judgment.verdict, 'pass');
  return value;
}

function originalHttpResponse(record, binding, summaryRequestId, bytes) {
  assert.ok(record && Object.getPrototypeOf(record) === Object.prototype);
  assert.equal(record.method, 'GET'); assert.equal(record.status, 200);
  assert.ok(bytes.length > 0 && bytes.length <= 65536);
  assert.equal(digest(bytes), record.responseSha256);
  assert.match(record.issuanceId, UUID); assert.match(summaryRequestId, UUID);
  assert.equal(record.issuanceId, binding.issuanceId);
  assert.equal(record.sendOperationId, binding.sendOperationId);
  assert.equal(record.targetId, binding.targetId);
  assert.equal(record.listenerTargetId, binding.listenerTargetId);
  assert.notEqual(record.issuanceId, summaryRequestId);
  assert.notEqual(record.listenerTargetId, record.targetId);
  assert.equal(record.nonceSha256, binding.nonceSha256);
  assert.equal(record.path, binding.path);
  assert.equal(record.resourceKind, binding.resourceKind);
  assert.equal(record.urlSha256, binding.urlSha256);
  const base = Object.fromEntries(['version', 'issuanceId', 'sendOperationId',
    'targetId', 'listenerTargetId', 'nonceSha256', 'path', 'resourceKind',
    'urlSha256', 'method', 'status', 'responseSha256']
    .map(key => [key, record[key]]));
  assert.ok(exact(record, [...Object.keys(base), 'receiptSha256']));
  assert.equal(digest(JSON.stringify(base)), record.receiptSha256);
  return record;
}

async function visibleButton(frame, label) {
  await frame.waitForFunction(text => [...document.querySelectorAll('button')]
    .some(node => node.textContent.trim() === text && !node.disabled && node.getClientRects().length),
  { timeout: 30000 }, label);
  const matches = await frame.$$('button');
  const selected = [];
  for (const node of matches) {
    const result = await node.evaluate((element, text) => {
      if (element.textContent.trim() !== text || element.disabled || !element.getClientRects().length) return false;
      element.scrollIntoView({ block: 'center' });
      const box = element.getBoundingClientRect();
      const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      return hit === element || element.contains(hit);
    }, label);
    if (result) selected.push(node);
  }
  assert.equal(selected.length, 1, `one physical ${label} control required`);
  return selected[0];
}
async function listen(app) {
  return new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function frameFor(page) {
  for (let n = 0; n < 600; n++) {
    const node = await page.$('iframe[title="SecureShop"]');
    const frame = node && await node.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw Error('SecureShop frame unavailable');
}
async function completedTurns(frame, expected) {
  await frame.waitForFunction(count => [...document.querySelectorAll(
    '[data-testid="merchant-role-assistant"] [data-testid="role-assistant-turn"]')]
    .filter(node => /· done$/.test(node.querySelector('.ss-turn__supervisor')?.textContent || ''))
    .length >= count, { timeout: 90000 }, expected);
  const count = await frame.$$eval('[data-testid="merchant-role-assistant"] [data-testid="role-assistant-turn"]',
    nodes => nodes.filter(node => /· done$/.test(node.querySelector('.ss-turn__supervisor')?.textContent || '')).length);
  assert.equal(count, expected, 'exact completed original merchant turn count');
}
function savedMailCard(saved, kind, sourceId) {
  const result = saved?.mailRead?.result;
  const records = kind === 'merchant_mail_recipient' && result?.kind === 'recipients'
    ? result.recipients : kind === 'merchant_mail_message' && result?.kind === 'list'
      ? result.headers : null;
  assert.ok(Array.isArray(records) && Array.isArray(saved.cards));
  assert.equal(records.length, saved.cards.length);
  const matches = [];
  records.forEach((record, index) => {
    const card = saved.cards[index];
    assert.equal(card.kind, kind);
    assert.equal(card.title, kind === 'merchant_mail_recipient'
      ? record.username : record.subject || '(No subject)');
    assert.equal(card.detail, kind === 'merchant_mail_recipient'
      ? `${record.email} · ${record.role}` : `From ${record.from} · ${record.createdAt}`);
    assert.match(card.choiceId, UUID);
    if (record.id === sourceId) matches.push(card);
  });
  assert.equal(matches.length, 1, `one protected ${kind} source required`);
  return matches[0];
}
async function selectCurrentMailChoice(frame, card, label) {
  assert.ok(card && typeof card.title === 'string' && typeof card.detail === 'string');
  await frame.waitForFunction((title, detail, text) => {
    const turns = document.querySelectorAll(
      '[data-testid="merchant-role-assistant"] [data-testid="role-assistant-turn"]');
    const latest = turns[turns.length - 1];
    return [...(latest?.querySelectorAll('[role="group"][aria-label="Merchant mail choices"] .ss-card') || [])]
      .some(node => node.querySelector('strong')?.textContent === title
        && node.querySelector('p.ss-mono')?.textContent === detail
        && [...node.querySelectorAll('button')].some(button => button.getAttribute('aria-label') === text
          && !button.disabled && button.getClientRects().length));
  }, { timeout: 30000 }, card.title, card.detail, label);
  const turns = await frame.$$('[data-testid="merchant-role-assistant"] [data-testid="role-assistant-turn"]');
  assert.ok(turns.length > 0);
  const choices = await turns.at(-1).$$('[role="group"][aria-label="Merchant mail choices"] .ss-card button');
  const matching = [];
  for (const choice of choices) if (await choice.evaluate((element, input) => {
    const cardNode = element.closest('.ss-card');
    return cardNode?.querySelector('strong')?.textContent === input.title
      && cardNode.querySelector('p.ss-mono')?.textContent === input.detail
      && element.getAttribute('aria-label') === input.label
      && !element.disabled && element.getClientRects().length > 0;
  }, { title: card.title, detail: card.detail, label })) matching.push(choice);
  assert.equal(matching.length, 1, `one current protected ${label} card required`);
  await matching[0].click();
}
async function loginShop(page, origin, username, password) {
  const landing = await page.goto(`${origin}/secureshop/login`, { waitUntil: 'domcontentloaded' });
  assert.ok([200, 304].includes(landing.status()));
  await page.waitForSelector('#ss-login-user');
  await page.type('#ss-login-user', username); await page.type('#ss-login-pw', password);
  const pending = page.waitForResponse(response => new URL(response.url()).pathname
    === '/api/secureshop/auth/bootstrap' && response.request().method() === 'POST', { timeout: 30000 });
  await page.click('button[type="submit"]'); assert.equal((await pending).status(), 200);
  const frame = await frameFor(page); await frame.waitForSelector('[aria-label="Account menu"]');
  return frame;
}
async function recordBrowser(browser, target, executablePath, expectedSha) {
  const pid = browser?.process?.()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const real = await fs.realpath(executablePath);
  const actualSha = digest(await fs.readFile(real)); assert.equal(actualSha, expectedSha);
  const startTime = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8' }).trim();
  assert.match(startTime, /^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$/);
  const temp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(temp, JSON.stringify({ schemaVersion: 1, processes: [{
    kind: 'mail_inline_summary_browser', pid, startTime,
    executablePath: real, executableSha256: actualSha }] }) + '\n', { mode: 0o600, flag: 'wx' });
  await fs.rename(temp, target);
}
async function migrateAndSeed(pools) {
  for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
    ['AGENTS', 'workshop-migrations/secureshop_agents'],
    ['REVIEW', 'workshop-migrations/secureshop_review'],
    ['COMMERCE', 'workshop-migrations/secureshop']]) {
    await migrate(pools[`${store}_MIGRATION`], path.join(ROOT, 'db/postgres', directory));
  }
  await require('../../server/database/postgres/workshopPlatformSeed')
    .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopAssessmentSeed')
    .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopStandaloneSeed')
    .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopSeed')
    .seedSecureShop(pools.COMMERCE_MIGRATION);
}

test('closed original V55 public and independent HTTP receipt contracts', () => {
  const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  assert.equal(teachingResponse({ ok: true, status: 'saved', requestId,
    messageId: 1, threadId: 2, replayed: false }, requestId).messageId, 1);
  assert.equal(summaryResponse({ ok: true, status: 'completed', requestId,
    sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', text: 'Saved summary',
    replayed: false, assessmentStatus: 'pending' }, requestId).text, 'Saved summary');
  assert.equal(assessmentResponse({ completed: true, judgment: {
    verdict: 'pass', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false },
  replayed: false }).completed, true);
  const bytes = Buffer.from('owned listener bytes');
  const binding = { issuanceId: requestId,
    sendOperationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    targetId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    listenerTargetId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    nonceSha256: '1'.repeat(64), path: '/owned-image',
    resourceKind: 'mail_inline_image_v1', urlSha256: '2'.repeat(64) };
  const base = { version: 1, issuanceId: binding.issuanceId,
    sendOperationId: binding.sendOperationId, targetId: binding.targetId,
    listenerTargetId: binding.listenerTargetId, nonceSha256: binding.nonceSha256,
    path: binding.path, resourceKind: binding.resourceKind,
    urlSha256: binding.urlSha256, method: 'GET', status: 200,
    responseSha256: digest(bytes) };
  const record = { ...base, receiptSha256: digest(JSON.stringify(base)) };
  const summaryRequestId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  assert.equal(originalHttpResponse(record, binding, summaryRequestId, bytes), record);
  assert.equal(originalHttpResponse(Object.fromEntries(Object.entries(record).reverse()),
    binding, summaryRequestId, bytes).receiptSha256, record.receiptSha256);
  assert.throws(() => originalHttpResponse({ ...record, responseSha256: '0'.repeat(64) },
    binding, summaryRequestId, bytes));
  assert.throws(() => originalHttpResponse(record, binding, requestId, bytes));
  assert.throws(() => teachingResponse({ ok: true, status: 'saved', requestId,
    messageId: 1, threadId: 2, replayed: false, url: 'forged' }, requestId));
});

test('standalone mail mount requires the real cart import capability', () => {
  const methods = names => Object.fromEntries(names.map(name => [name, () => {}]));
  const commerce = { ...methods(['cart', 'add', 'update', 'remove', 'summary',
    'checkout', 'orders', 'order']), importGuestCart() {} };
  const auth = { service: methods(['authenticate', 'register', 'login', 'renew',
    'logout', 'changePassword', 'establishTenantContext']), bootstrap() {},
  reset: methods(['readiness', 'reset', 'readRecovery', 'recover']),
  registeredAdminReset: methods(['preview', 'reset', 'read', 'reveal', 'acknowledge']),
  mode: methods(['get', 'set']), assessmentObjectives: methods(['list', 'set']),
  assessmentRecovery: methods(['list', 'retry']) };
  const composition = { standaloneAuth: auth,
    publicCatalog: methods(['browse', 'product', 'related', 'categories', 'reviews']),
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts',
      'categories', 'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct']),
    commerce, account: methods(['profile', 'updateProfile', 'addresses',
      'createAddress', 'updateAddress', 'deleteAddress']), admin: methods(['users', 'kpis']),
    personaAuth: { authenticatePersona() {}, authenticateBoundToken() {} },
    router() {}, browserRouter() {} };
  const readiness = require('../../server/routes/secureshopRuntimeReadiness').standaloneReadiness;
  assert.throws(() => readiness(composition), /Standalone SecureShop core readiness incomplete/);
  const cartImport = require('../../server/services/secureshopStandaloneCartImport')
    .createSecureShopStandaloneCartImport({ bootstrap: auth.bootstrap,
      launches: { resolveCapability() {} }, personaAuth: composition.personaAuth, commerce });
  assert.equal(typeof cartImport, 'function');
  auth.cartImport = cartImport;
  assert.equal(readiness(composition).checks.commerce, true);
});

test('captured launch and persona tokens retain their distinct wire shapes', () => {
  const launch = 'a'.repeat(43), authorization = 'Bearer header.payload.signature';
  assert.deepEqual(capturedShopAuthority(launch, authorization),
    { launch, personaToken: 'header.payload.signature' });
  assert.throws(() => capturedShopAuthority(`Bearer ${launch}`, authorization));
  assert.throws(() => capturedShopAuthority(launch, 'header.payload.signature'));
  assert.throws(() => capturedShopAuthority('a'.repeat(42), authorization));
  assert.throws(() => capturedShopAuthority('a'.repeat(42) + '!', authorization));
});

test('duplicate visible mail names resolve only through protected source and card detail', () => {
  const first = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const second = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const saved = { mailRead: { result: { kind: 'recipients', recipients: [
    { id: 12, username: 'student_merchant', email: 'student_merchant@dvaia.local', role: 'merchant' },
    { id: 1000000001, username: 'student_merchant', email: 'student_merchant@secureshop.local', role: 'merchant' },
  ] } }, cards: [
    { kind: 'merchant_mail_recipient', choiceId: first, title: 'student_merchant',
      detail: 'student_merchant@dvaia.local · merchant' },
    { kind: 'merchant_mail_recipient', choiceId: second, title: 'student_merchant',
      detail: 'student_merchant@secureshop.local · merchant' },
  ] };
  assert.equal(savedMailCard(saved, 'merchant_mail_recipient', 12).choiceId, first);
  assert.equal(savedMailCard(saved, 'merchant_mail_recipient', 1000000001).choiceId, second);
  assert.throws(() => savedMailCard(saved, 'merchant_mail_recipient', 99));
  const mismatched = structuredClone(saved);
  mismatched.cards[0].detail = mismatched.cards[1].detail;
  assert.throws(() => savedMailCard(mismatched, 'merchant_mail_recipient', 12));
  const messages = { mailRead: { result: { kind: 'list', headers: [
    { id: 1, subject: 'Inline image summary exercise', from: 'first', createdAt: 'now' },
    { id: 2, subject: 'Inline image summary exercise', from: 'second', createdAt: 'later' },
  ] } }, cards: [
    { kind: 'merchant_mail_message', choiceId: first, title: 'Inline image summary exercise',
      detail: 'From first · now' },
    { kind: 'merchant_mail_message', choiceId: second, title: 'Inline image summary exercise',
      detail: 'From second · later' },
  ] };
  assert.equal(savedMailCard(messages, 'merchant_mail_message', 2).choiceId, second);
});

test(TITLE, { skip: process.env[GATE] !== '1', timeout: 600000 }, async () => {
  const config = nativeConfiguration();
  const pools = Object.fromEntries(Object.keys(STORES).flatMap(store =>
    ['MIGRATION', 'RUNTIME'].map(role => [`${store}_${role}`,
      new Pool({ connectionString: config.urls[`${store}_${role}`], max: role === 'RUNTIME' ? 12 : 3 })])));
  const leasePool = new Pool({ connectionString: config.urls.IDENTITY_RUNTIME, max: 3 });
  const status = { passed: false, scope: 'current-main owned mail inline image summary, physical save and selection, original actor/HTTP and canonical Judge',
    isolatedStores: false, physicalTeachingSave: false, originalBoundMessage: false,
    physicalProtectedSelection: false, modelSelectedSummary: false,
    originalHttpEffect: false, canonicalJudgePass: false, genuineCredit: false,
    savedGetOnlyRecovery: false, fixedSameSourceDenied: false,
    siblingDenied: false, resetDenied: false, immutableHistory: false,
    fixtureCleaned: false, actorCalls: 0, roleTurns: 0, judgeCalls: 0,
    listenerGets: 0, errors: [] };
  const failures = [], requests = [], responses = [], pageErrors = [], rawCalls = [],
    judgeTranscripts = [], originalHttp = [];
  let proof = null;
  let reset, mail, composition, server, browser, profile, actorTransport, judgeTransport,
    stage = 'migrate', thrown;
  try {
    await migrateAndSeed(pools); status.isolatedStores = true;
    const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME,
      review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit });
    judgeTransport = await require('./secureshopMailActualTransport')
      .createMailActualTransport({ maxHttpCalls: 4, allowMetadata: true });
    actorTransport = await require('./secureshopMailActualTransport')
      .createMailActualTransport({ maxHttpCalls: 14, allowMetadata: true });
    assert.equal(actorTransport.digest, MODEL_DIGEST);
    assert.equal(judgeTransport.digest, MODEL_DIGEST);
    process.env.OLLAMA_BASE_URL = judgeTransport.judgeUrl;
    process.env.JUDGE_PROVIDER = 'ollama'; process.env.JUDGE_MODEL = MODEL;
    const configuredJudge = require('../../server/agent-runtime/objectiveJudge')
      .createObjectiveJudge({ observeExecutionTranscript: value => judgeTranscripts.push(structuredClone(value)) });
    let judgeInvocations = 0;
    const judge = async value => {
      assert.ok(++judgeInvocations <= 1, 'one canonical mail inline assessment');
      return configuredJudge(value);
    };
    require('../../server/agent-runtime/judgeProviderConfiguration')
      .registerConfiguredJudge(judge, () => require('../../server/agent-runtime/judgeProviderConfiguration')
        .readJudgeProviderConfig(configuredJudge));
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
        progress, resetComposition: reset, judge,
        expectedIdentityDatabase: new URL(config.urls.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(config.urls.AGENTS_RUNTIME).pathname.slice(1) });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({ repository:
      require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
      reviewPool: review, launches: reset.launches });
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: reset.audit.agents });
    const provider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      baseUrl: actorTransport.actorUrl, model: MODEL });
    for (const method of ['chat', 'finalResponse']) {
      const original = provider[method].bind(provider);
      provider[method] = async input => {
        const result = await original({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
        assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
        rawCalls.push({ method, offeredTools: (input.tools || []).map(tool => `${tool.agent}.${tool.tool}`),
          selected: (result.tool_uses || []).map(tool => ({ name: tool.name, args: tool.args })),
          stopReason: result.stop_reason || null });
        assert.ok(rawCalls.length <= 14, 'bounded original actor selections');
        return result;
      };
    }
    const promptPolicyRepository = await require('../../server/services/secureshopAgentSnapshotPolicies')
      .createAgentSnapshotPolicyResolver({ personaAuthority: grading.personaAuthority,
        agentsPool: agents, identityPool: identity, auditStore: reset.audit.agents })();
    composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        getMailApplication: () => mail?.ready === true ? mail.application : null,
        personaInboxFeature: true, fixtures: [], requiredObjectives: [OBJECTIVE],
        jwtSecret: 'disposable-inline-mail-persona-secret-at-least-32-bytes',
        agentRuntime: { provider }, judge });
    const inlineModule = require('../../server/services/secureshopMailInlineHttpAdapter');
    const originalInlineFactory = inlineModule.createMailInlineHttpAdapter;
    inlineModule.createMailInlineHttpAdapter = options => originalInlineFactory({ ...options,
      fetchImpl: async (url, init) => {
        assert.ok(originalHttp.length < 2, 'one original owned HTTP effect');
        const input = new URL(url);
        assert.equal(input.protocol, 'http:'); assert.equal(input.hostname, '127.0.0.1');
        assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error');
        const event = { method: init.method, path: input.pathname, urlSha256: digest(url),
          status: null, bytes: null, responseSha256: null };
        originalHttp.push(event);
        const response = await fetch(url, init);
        event.status = response.status;
        const body = Buffer.from(await response.clone().arrayBuffer());
        assert.ok(body.length > 0 && body.length <= 65536);
        event.bytes = body.toString('base64'); event.responseSha256 = digest(body);
        return response;
      } });
    try { mail = await require('../../server/services/secureshopMailProduction').createMailProduction({
      enabled: true, identityPool: identity, agentsPool: agents, resetComposition: reset,
      personaAuthority: grading.personaAuthority, personaRepository: composition.repositories.personas,
      provider, promptPolicyRepository, toolPolicyRepository, modeAuthority,
      mailScenes: composition.mailScenes, authenticatePersona: composition.personaAuth.authenticatePersona,
      assessmentDependencies: { ...grading.assessmentDependencies, publicationModes: modeRepository, judge },
      mode: 'vuln' }); }
    finally { inlineModule.createMailInlineHttpAdapter = originalInlineFactory; }
    assert.equal(mail.ready, true); assert.ok(mail.inline?.assessment);
    await composition.repositories.personas.ensureTemplates();
    await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
      .assertBoundToolPolicyReadiness(agents);
    stage = 'standalone-mount';
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
      .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
    const adminLogin = await auth.login({ username: 'student_admin', password: 'student123' });
    const objective = (await assessmentCatalog.list(adminLogin.context)).objectives
      .find(row => row.objectiveId === OBJECTIVE);
    assert.equal(objective?.qualification, 'native-model'); assert.equal(objective.enabled, false);
    assert.equal((await assessmentCatalog.set(adminLogin.context, { objectiveId: OBJECTIVE,
      enabled: true, expectedRevision: objective.revision })).enabled, true);
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const protectedReset = require('../../server/services/secureshopStandaloneReset')
      .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
        launches: composition.launches, scenes, resetCoordinator: reset.launchResetCoordinator,
        preflight: reset.sceneResetPreflight });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
        reviewPool: review, commercePool: commerce });
    const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
      .createRegisteredAdminResetEnvelope({ activeKeyId: 'inline-owned',
        keys: new Map([['inline-owned', randomBytes(32)]]) });
    const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
      .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
    await resetRepository.checkReadiness();
    const mounted = Object.freeze({ ...composition, mail,
      standaloneAuth: Object.freeze({ service: auth, bootstrap, reset: protectedReset,
        mode: standaloneMode, assessmentObjectives: assessmentCatalog,
        registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({ repository: resetRepository }),
        assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
            bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
            personaAuthority: grading.personaAuthority, modeAuthority, scenes, judge,
            mailInlineAssessment: mail.inline.assessment }),
        cartImport: require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
            personaAuth: composition.personaAuth, commerce: composition.commerce }) }), publicCatalog });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        applicationMode: 'standalone', authenticateToken: (_req, res) => res.sendStatus(401),
        audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
    assert.equal(bound.standaloneReadiness.ready, true);
    const app = express(); app.use(express.json()); server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ ...mounted.standaloneAuth,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', (request, response, next) => {
      const row = { method: request.method, path: request.path,
        launch: request.get('x-dvaia-secureshop-launch') || null,
        authorization: request.get('authorization') || null,
        ...(request.method === 'POST' ? { body: structuredClone(request.body) } : {}) };
      if (/\/email\/inline\/|\/agents\/merchant\/assistant\//.test(request.path)) {
        requests.push(row); response.once('finish', () => { row.status = response.statusCode; });
        const original = response.json.bind(response);
        response.json = value => {
          const body = Buffer.from(JSON.stringify(value), 'utf8');
          assert.ok(body.length <= 65536, 'bounded original mail response');
          responses.push({ method: request.method, path: request.path,
            status: response.statusCode, body: structuredClone(value),
            bytes: body.length, sha256: digest(body) });
          return original(value);
        };
      }
      next();
    });
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
      .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
    app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
      .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
        isAvailable: async () => true }));
    app.use(express.static(config.build, { setHeaders: response =>
      response.set('Access-Control-Allow-Origin', '*') }));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: config.build }));
    stage = 'physical-browser';
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-inline-mail-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath: config.browser, args: ['--disable-background-networking'] });
    await recordBrowser(browser, config.recordPath, config.browser,
      process.env.SECURESHOP_MAIL_INLINE_SUMMARY_BROWSER_BROWSER_SHA256);
    const page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    page.on('pageerror', error => pageErrors.push(error.name || 'PageError'));
    const nextResponse = async (method, pathValue, before = 0) => {
      const deadline = Date.now() + 60000;
      while (Date.now() < deadline) {
        const found = responses.filter(row => row.method === method && row.path === pathValue);
        if (found.length > before) return found.at(-1);
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      throw Error(`Original ${method} ${pathValue} response unavailable`);
    };
    let frame = await loginShop(page, origin, 'student_merchant', 'student123');
    stage = 'physical-teaching-save';
    await frame.waitForSelector('a[href="/secureshop/merchant/inbox"]');
    await frame.click('a[href="/secureshop/merchant/inbox"]');
    await frame.waitForSelector('button');
    await (await visibleButton(frame, 'Save teaching message')).click();
    const savePost = await nextResponse('POST', '/email/inline/teaching-message');
    assert.equal(savePost.status, 200);
    assert.ok(exact(requests.find(row => row.method === 'POST'
      && row.path === '/email/inline/teaching-message')?.body, ['requestId']));
    const teachingRequestId = requests.find(row => row.method === 'POST'
      && row.path === '/email/inline/teaching-message').body.requestId;
    assert.match(teachingRequestId, UUID);
    const savedTeaching = teachingResponse(savePost.body, teachingRequestId);
    assert.equal(savedTeaching.status, 'saved'); assert.equal(savedTeaching.replayed, false);
    const teachingGet = await nextResponse('GET', `/email/inline/teaching-message/${teachingRequestId}`);
    assert.equal(teachingGet.status, 200);
    assert.deepEqual(teachingResponse(teachingGet.body, teachingRequestId),
      { ...savedTeaching, replayed: true });
    const sendRows = (await agents.query(`SELECT operation_id,action,result
      FROM secureshop_agents.lab_mail_operation_receipts WHERE operation_id=$1`,
    [teachingRequestId])).rows;
    assert.equal(sendRows.length, 1); assert.equal(sendRows[0].action, 'send');
    const bindingRows = (await pools.AGENTS_MIGRATION.query(`SELECT issuance_id,send_operation_id,
      target_id,message_id,message_sha256,thread_id,recipient_id,listener_target_id,
      nonce_sha256,path,resource_kind,url_sha256
      FROM secureshop_agents.lab_mail_inline_bindings WHERE send_operation_id=$1`,
    [teachingRequestId])).rows;
    assert.equal(bindingRows.length, 1);
    const boundMessage = bindingRows[0];
    assert.equal(Number(boundMessage.message_id), savedTeaching.messageId);
    assert.equal(Number(boundMessage.thread_id), savedTeaching.threadId);
    assert.equal(boundMessage.send_operation_id, teachingRequestId);
    assert.match(boundMessage.issuance_id, UUID);
    assert.notEqual(boundMessage.issuance_id, teachingRequestId);
    const messageRows = (await pools.AGENTS_MIGRATION.query(`SELECT message_id,thread_id,
      sender_id,recipient_id,subject,body_markdown,body_html,content_sha256
      FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 AND message_id=$2`,
    [boundMessage.target_id, boundMessage.message_id])).rows;
    assert.equal(messageRows.length, 1);
    assert.equal(Number(messageRows[0].recipient_id), Number(boundMessage.recipient_id));
    assert.equal(messageRows[0].subject, 'Inline image summary exercise');
    assert.ok(messageRows[0].body_markdown.includes('<img src="http://127.0.0.1:'));
    assert.equal(Buffer.from(boundMessage.message_sha256).toString('hex'),
      Buffer.from(messageRows[0].content_sha256).toString('hex'));
    status.physicalTeachingSave = true; status.originalBoundMessage = true;
    const ownerRequest = requests.find(row => row.method === 'POST'
      && row.path === '/email/inline/teaching-message');
    const capturedAuthority = capturedShopAuthority(ownerRequest.launch,
      ownerRequest.authorization);
    const scope = await composition.launches.resolveCapability(capturedAuthority.launch);
    const actor = await composition.personaAuth.authenticateBoundToken({ scope,
      token: capturedAuthority.personaToken });
    assert.equal(actor.user.role, 'merchant');
    assert.equal(actor.user.id, Number(boundMessage.recipient_id));
    const directory = await composition.repositories.personas.listMailActors(scope);
    const recipient = directory.find(row => row.id === actor.user.id && row.role === 'merchant');
    assert.ok(recipient?.username);
    stage = 'physical-protected-selection';
    await frame.waitForSelector('a[href="/secureshop/merchant"]');
    await frame.click('a[href="/secureshop/merchant"]');
    await frame.waitForSelector('select[id^="agent-lane-task-merchant-"]');
    await frame.select('select[id^="agent-lane-task-merchant-"]', 'assistant');
    const chat = async (message, expected) => {
      const input = 'textarea[id^="lane-merchant-assistant-"]';
      await frame.locator(input).fill(message);
      await frame.locator(`form:has(${input}) button[type="submit"]`).click();
      await completedTurns(frame, expected);
      const posts = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/merchant/assistant/chat');
      assert.equal(posts.length, expected);
      const sent = posts.at(-1);
      assert.match(sent.body.sessionId, UUID); assert.match(sent.body.requestId, UUID);
      const savedPath = `/agents/merchant/assistant/operations/${sent.body.sessionId}/${sent.body.requestId}`;
      const retained = await nextResponse('GET', savedPath);
      assert.equal(retained.status, 200);
      assert.equal(retained.body.sessionId, sent.body.sessionId);
      assert.equal(retained.body.requestId, sent.body.requestId);
      return { sent, retained: retained.body };
    };
    const found = await chat(`Find the mail recipient named "${recipient.username}".`, 1);
    assert.equal(found.retained.mailRead?.result?.kind, 'recipients');
    const recipientCard = savedMailCard(found.retained, 'merchant_mail_recipient', actor.user.id);
    assert.equal(recipientCard.title, recipient.username);
    assert.equal(recipientCard.detail, `${recipient.email} · ${recipient.role}`);
    await selectCurrentMailChoice(frame, recipientCard, `View mailbox for ${recipientCard.title}`);
    await completedTurns(frame, 2);
    const mailboxPost = requests.filter(row => row.method === 'POST'
      && row.path === '/agents/merchant/assistant/chat').at(-1);
    assert.deepEqual(mailboxPost.body.selection,
      { choiceId: recipientCard.choiceId, intent: 'mail_list' });
    const mailboxPath = `/agents/merchant/assistant/operations/${mailboxPost.body.sessionId}/${mailboxPost.body.requestId}`;
    const mailbox = (await nextResponse('GET', mailboxPath)).body;
    assert.equal(mailbox.mailRead?.result?.kind, 'list');
    const messageCard = savedMailCard(mailbox, 'merchant_mail_message', savedTeaching.messageId);
    assert.equal(messageCard.title, 'Inline image summary exercise');
    await selectCurrentMailChoice(frame, messageCard, `View message: ${messageCard.title}`);
    await completedTurns(frame, 3);
    const detailPost = requests.filter(row => row.method === 'POST'
      && row.path === '/agents/merchant/assistant/chat').at(-1);
    assert.deepEqual(detailPost.body.selection,
      { choiceId: messageCard.choiceId, intent: 'mail_detail' });
    const detailPath = `/agents/merchant/assistant/operations/${detailPost.body.sessionId}/${detailPost.body.requestId}`;
    const detail = (await nextResponse('GET', detailPath)).body;
    assert.equal(detail.mailRead?.result?.kind, 'detail');
    assert.equal(detail.mailRead.result.messageId, savedTeaching.messageId);
    assert.equal(detail.mailRead.result.message.sha256,
      Buffer.from(boundMessage.message_sha256).toString('hex'));
    assert.ok(detail.mailRead.result.message.bodyMarkdown.includes('<img src="http://127.0.0.1:'));
    status.physicalProtectedSelection = true;
    stage = 'physical-summary';
    await (await visibleButton(frame, 'Summarize selected message')).click();
    const summaryPost = await nextResponse('POST', '/email/inline/summary');
    assert.equal(summaryPost.status, 200);
    const summaryRequest = requests.find(row => row.method === 'POST'
      && row.path === '/email/inline/summary');
    assert.ok(summaryRequest);
    assert.ok(exact(summaryRequest.body, ['requestId', 'readOperationId', 'messageId']));
    assert.match(summaryRequest.body.requestId, UUID);
    assert.equal(summaryRequest.body.readOperationId, detail.mailRead.result.readOperationId);
    assert.equal(summaryRequest.body.messageId, savedTeaching.messageId);
    const summary = summaryResponse(summaryPost.body, summaryRequest.body.requestId);
    assert.equal(summary.status, 'completed'); assert.equal(summary.replayed, false);
    const summaryGetPath = `/email/inline/summary/${summary.requestId}`;
    const summaryGet = await nextResponse('GET', summaryGetPath);
    assert.equal(summaryGet.status, 200);
    assert.deepEqual(summaryResponse(summaryGet.body, summary.requestId),
      { ...summary, replayed: true });
    await frame.waitForFunction(text => document.querySelector(
      '[aria-label="Saved merchant mail summary"] pre')?.textContent === text,
    { timeout: 30000 }, summary.text);
    const turnRows = (await agents.query(`SELECT session_id,request_id,request_hash,
      request_version,status,result_json FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`, [summary.sessionId, summary.requestId])).rows;
    assert.equal(turnRows.length, 1); assert.equal(turnRows[0].status, 'completed');
    const turn = turnRows[0].result_json;
    const metadata = turn.taskMetadata?.mailSummary;
    assert.equal(turn.stopReason, 'end_turn'); assert.equal(turn.text, summary.text);
    assert.equal(metadata?.requestId, summary.requestId);
    assert.equal(metadata?.purpose, 'secureshop_mail_summary');
    assert.equal(metadata?.mode, 'vuln');
    assert.equal(metadata?.selected?.readOperationId, summaryRequest.body.readOperationId);
    assert.equal(metadata?.selected?.messageId, summaryRequest.body.messageId);
    assert.equal(metadata?.selected?.messageSha256,
      Buffer.from(boundMessage.message_sha256).toString('hex'));
    assert.equal(metadata?.httpRecord?.summaryRequestId, summary.requestId);
    assert.equal(metadata?.httpRecord?.binding?.issuanceId, boundMessage.issuance_id);
    assert.equal(metadata?.httpRecord?.binding?.sendOperationId, teachingRequestId);
    assert.equal(metadata?.httpRecord?.runId, metadata.runId);
    assert.ok(Array.isArray(metadata?.traceEventIds) && metadata.traceEventIds.length >= 5);
    assert.ok(metadata?.summaryObservation?.result);
    assert.equal(metadata.summaryObservation.tool, 'email.summarize_thread');
    assert.equal(metadata.summaryObservation.callId, metadata.httpRecord.callId);
    assert.equal(metadata.summaryObservation.effectReceipt?.effectKey, metadata.httpRecord.effectKey);
    const runRows = (await identity.query(`SELECT run_id,owner_key,generation,status
      FROM graph_runtime.runs WHERE run_id=$1`, [metadata.runId])).rows;
    assert.equal(runRows.length, 1); assert.equal(runRows[0].status, 'completed');
    const effectRows = (await identity.query(`SELECT run_id,owner_key,generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND effect_key=$2`,
    [metadata.runId, metadata.httpRecord.effectKey])).rows;
    assert.equal(effectRows.length, 1); assert.equal(effectRows[0].status, 'completed');
    assert.equal(effectRows[0].owner_key, runRows[0].owner_key);
    assert.equal(String(effectRows[0].generation), String(runRows[0].generation));
    assert.equal(originalHttp.length, 1);
    const originalBytes = Buffer.from(originalHttp[0].bytes, 'base64');
    const receipt = metadata.httpRecord.targetReceipt;
    originalHttpResponse(receipt, metadata.httpRecord.binding, summary.requestId, originalBytes);
    assert.equal(originalHttp[0].responseSha256, receipt.responseSha256);
    assert.equal(originalHttp[0].urlSha256,
      Buffer.from(boundMessage.url_sha256).toString('hex'));
    assert.equal(originalHttp[0].path, boundMessage.path);
    const invocationRows = (await pools.AGENTS_MIGRATION.query(`SELECT *
      FROM secureshop_agents.lab_mail_inline_http_invocations WHERE summary_request_id=$1`,
    [summary.requestId])).rows;
    assert.equal(invocationRows.length, 1);
    assert.equal(invocationRows[0].run_id, metadata.runId);
    assert.equal(invocationRows[0].effect_key, metadata.httpRecord.effectKey);
    assert.equal(Buffer.from(invocationRows[0].response_sha256).toString('hex'),
      receipt.responseSha256);
    assert.equal(Buffer.from(invocationRows[0].target_receipt_sha256).toString('hex'),
      receipt.receiptSha256);
    status.modelSelectedSummary = rawCalls.some(call => call.selected.some(selection =>
      selection.name === 'email.summarize_thread' && exact(selection.args, [])))
      && rawCalls.some(call => call.selected.some(selection =>
        selection.name === 'email.read_thread' && exact(selection.args, [])));
    assert.equal(status.modelSelectedSummary, true);
    status.originalHttpEffect = true; status.listenerGets = originalHttp.length;
    const protectedContext = { scope, persona: { id: actor.user.id, role: 'merchant' },
      personaSession: { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion } };
    let originalSource = null, sourceFailure = null;
    try {
      originalSource = await require('../../server/database/postgres/secureshopMailInlineEvidenceRepository')
        .createMailInlineEvidenceRepository({ identityPool: identity,
          conversationRepository: reset.conversations,
          readSavedSource: mail.inline.readSavedSource })
        .readSource(protectedContext, { sessionId: summary.sessionId, requestId: summary.requestId });
    } catch (error) {
      sourceFailure = { code: error.code || null, name: error.name || 'Error',
        message: String(error.message || '').slice(0, 300) };
    }
    const allEffectRows = (await identity.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND effect_key=ANY($2::text[])`,
    [metadata.runId, [metadata.readEffectReceipt.effectKey,
      metadata.summaryEffectReceipt.effectKey]])).rows;
    const originalBeforeAssessment = { version: 1, sourceReaderCompleted: !!originalSource,
      sourceFailure, source: originalSource, savedTurn: turnRows[0], run: runRows[0],
      effects: allEffectRows, invocation: invocationRows[0], boundMessage,
      originalHttp: originalHttp[0] };
    const originalBeforeBytes = JSON.stringify(originalBeforeAssessment);
    assert.ok(Buffer.byteLength(originalBeforeBytes) <= 8 * 1024 * 1024,
      'bounded protected pre-assessment source');
    await fs.writeFile(path.join(path.dirname(config.evidencePath),
      'mail-inline-summary-preassessment.json'), originalBeforeBytes,
    { flag: 'wx', mode: 0o600 });
    if (sourceFailure) throw Error(`Protected original mail source unavailable: ${sourceFailure.code || sourceFailure.name}`);
    assert.equal(originalSource.turn.result.text, summary.text);
    assert.deepEqual(originalSource.effects.map(row => row.effect_key),
      [metadata.readEffectReceipt.effectKey, metadata.summaryEffectReceipt.effectKey]);
    stage = 'physical-assessment';
    await (await visibleButton(frame, 'Assess saved summary')).click();
    const assessmentPost = await nextResponse('POST', '/email/inline/assessment');
    assert.equal(assessmentPost.status, 200);
    const assessmentRequest = requests.find(row => row.method === 'POST'
      && row.path === '/email/inline/assessment');
    assert.deepEqual(assessmentRequest.body,
      { sessionId: summary.sessionId, requestId: summary.requestId });
    const assessment = assessmentResponse(assessmentPost.body);
    assert.equal(assessment.completed, true);
    assert.equal(assessment.replayed, false);
    assert.equal(assessment.judgment.verdict, 'pass');
    const assessmentPath = `/email/inline/assessment/${summary.sessionId}/${summary.requestId}`;
    const assessmentGet = await nextResponse('GET', assessmentPath);
    assert.equal(assessmentGet.status, 200);
    assert.deepEqual(assessmentResponse(assessmentGet.body),
      { ...assessment, replayed: true });
    assert.equal(judgeInvocations, 1);
    assert.ok(judgeTranscripts.length >= 1);
    const judgments = (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
      WHERE objective_id=$1 ORDER BY evaluation_id`, [OBJECTIVE])).rows;
    assert.equal(judgments.length, 1);
    assert.equal(judgments[0].evaluation_id, assessment.judgment.evaluationId);
    assert.equal(judgments[0].verdict, 'pass');
    assert.equal(judgments[0].disposition, 'awarded');
    assert.equal(judgments[0].rubric_version, 'secureshop-mail-inline-image-v6');
    assert.equal(judgments[0].evidence_digest, judgeTranscripts[0].header.evidenceDigest);
    assert.equal(judgments[0].packet, judgeTranscripts[0].header.packet);
    const contributions = (await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
      WHERE evaluation_id=$1`, [assessment.judgment.evaluationId])).rows;
    const completions = (await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
      WHERE evaluation_id=$1`, [assessment.judgment.evaluationId])).rows;
    assert.equal(contributions.length, 1); assert.equal(completions.length, 1);
    status.canonicalJudgePass = true; status.genuineCredit = true;
    assert.equal(originalSource.turn.result.text, summary.text);
    assert.deepEqual(originalSource.turn.result.taskMetadata.mailSummary.traceEventIds,
      metadata.traceEventIds);
    assert.equal(originalSource.run.run_id, metadata.runId);
    assert.deepEqual(originalSource.effects.map(row => row.effect_key),
      [metadata.readEffectReceipt.effectKey, metadata.summaryEffectReceipt.effectKey]);
    assert.equal(originalSource.http.record.targetReceipt.receiptSha256, receipt.receiptSha256);
    const packet = JSON.parse(judgments[0].packet);
    assert.equal(packet.rubric.version, 'secureshop-mail-inline-image-v6');
    assert.equal(packet.rubric.mailInlineCitationContract, 'scoped-excerpts-v1');
    const scopedCitations = [
      ['mail_inline_source_image', 'mail_inline_source',
        packet.evidence[1].content.imageContext],
      ['mail_inline_image_fetched', 'mail_inline_execution',
        packet.evidence[2].content.verifiedContext] ];
    const scopedOutcome = judgeTranscripts[0].outcome.value.criteria;
    const acceptedScoped = judgeTranscripts[0].calls.filter(row => row.disposition === 'accepted');
    assert.equal(scopedOutcome.length, 2);
    assert.equal(acceptedScoped.length, 2);
    scopedCitations.forEach(([criterionId, evidenceId, quote], index) => {
      assert.equal(scopedOutcome[index].id, criterionId);
      assert.equal(scopedOutcome[index].satisfied, true);
      assert.deepEqual(scopedOutcome[index].citations, [{ evidenceId, quote }]);
      const raw = JSON.parse(acceptedScoped[index].response);
      assert.equal(raw.satisfied, true);
      assert.deepEqual(raw.citations, [{ evidenceId, quote }]);
      const format = acceptedScoped[index].request.schema;
      assert.equal(format.additionalProperties, false);
      assert.deepEqual(format.required, ['observation', 'citations', 'satisfied']);
      assert.equal(format.properties.citations.minItems, 1);
      assert.equal(format.properties.citations.maxItems, 1);
      assert.equal(format.properties.citations.items.additionalProperties, false);
      assert.equal(format.properties.citations.items.properties.evidenceId.const, evidenceId);
      assert.deepEqual(format.properties.citations.items.properties.quote.enum, [quote]);
    });
    const assessmentExecution = packet.evidence?.[0]?.content?.assessmentExecution;
    assert.ok(exact(assessmentExecution, ['runId', 'ownerKey', 'generation']));
    assert.equal(assessmentExecution.runId, judgments[0].run_id);
    const mailEvidence = require('../../server/services/secureshopMailInlineEvidence');
    const candidate = mailEvidence.buildMailInlineCandidate({ ...originalSource,
      assessmentExecution: { runId: assessmentExecution.runId,
        ownerKey: assessmentExecution.ownerKey,
        durableGeneration: assessmentExecution.generation },
      qualifyModelTrace: require('../../server/services/secureshopModelQualification')
        .createSecureShopModelQualifier(provider) });
    assert.ok(candidate, 'protected original mail source must produce eligible canonical evidence');
    const prepared = require('../../server/agent-runtime/objectiveJudge')
      .prepareJudgeInput({ rubric: mailEvidence.RUBRIC, ...candidate });
    assert.equal(prepared.evidenceError, undefined);
    assert.equal(prepared.packet, judgments[0].packet);
    assert.equal(prepared.evidenceDigest, judgments[0].evidence_digest);
    proof = { savedTurn: turnRows[0], run: runRows[0], effects: originalSource.effects,
      invocation: invocationRows[0], boundMessage, judgment: judgments[0],
      contributions, completions };
    stage = 'saved-reload-get-only';
    const counted = () => ({ summaryPosts: requests.filter(row => row.method === 'POST'
      && row.path === '/email/inline/summary').length,
    assessmentPosts: requests.filter(row => row.method === 'POST'
      && row.path === '/email/inline/assessment').length,
    actorCalls: actorTransport.calls.length, judgeCalls: judgeTransport.calls.length,
    listenerGets: originalHttp.length });
    const beforeReload = counted();
    const priorSummaryGets = responses.filter(row => row.method === 'GET'
      && row.path === summaryGetPath).length;
    const priorAssessmentGets = responses.filter(row => row.method === 'GET'
      && row.path === assessmentPath).length;
    const reloaded = await page.reload({ waitUntil: 'domcontentloaded' });
    assert.ok([200, 304].includes(reloaded.status()));
    frame = await frameFor(page);
    await frame.waitForSelector('select[id^="agent-lane-task-merchant-"]');
    await frame.select('select[id^="agent-lane-task-merchant-"]', 'assistant');
    await (await visibleButton(frame, 'Check saved summary')).click();
    const recoveredSummary = await nextResponse('GET', summaryGetPath, priorSummaryGets);
    assert.equal(recoveredSummary.status, 200);
    assert.deepEqual(summaryResponse(recoveredSummary.body, summary.requestId),
      { ...summary, replayed: true });
    await frame.waitForFunction(text => document.querySelector(
      '[aria-label="Saved merchant mail summary"] pre')?.textContent === text,
    { timeout: 30000 }, summary.text);
    await (await visibleButton(frame, 'Check saved assessment')).click();
    const recoveredAssessment = await nextResponse('GET', assessmentPath, priorAssessmentGets);
    assert.equal(recoveredAssessment.status, 200);
    assert.deepEqual(assessmentResponse(recoveredAssessment.body),
      { ...assessment, replayed: true });
    assert.deepEqual(counted(), beforeReload, 'reload and saved checks must be GET-only');
    status.savedGetOnlyRecovery = true;
    stage = 'physical-fixed-mode';
    const modePost = page.waitForResponse(response => new URL(response.url()).pathname
      === '/api/secureshop/auth/mode' && response.request().method() === 'POST', { timeout: 30000 });
    await (await visibleButton(page, 'Shop settings')).click();
    await page.waitForSelector('aside[aria-label="Shop settings"]');
    await page.waitForFunction(() => document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent.includes('Current: Vulnerable'));
    await (await visibleButton(page, 'Fixed')).click();
    assert.equal((await modePost).status(), 200);
    await page.waitForFunction(() => document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent.includes('Current: Fixed'));
    await (await visibleButton(page, 'Shop settings')).click();
    await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
    frame = await frameFor(page);
    await frame.waitForSelector('select[id^="agent-lane-task-merchant-"]');
    await frame.select('select[id^="agent-lane-task-merchant-"]', 'assistant');
    const doneCount = async () => frame.$$eval(
      '[data-testid="merchant-role-assistant"] [data-testid="role-assistant-turn"]',
      nodes => nodes.filter(node => /· done$/.test(
        node.querySelector('.ss-turn__supervisor')?.textContent || '')).length);
    const sendFixed = async message => {
      const before = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/merchant/assistant/chat').length;
      const displayed = await doneCount();
      const input = 'textarea[id^="lane-merchant-assistant-"]';
      await frame.locator(input).fill(message);
      await frame.locator(`form:has(${input}) button[type="submit"]`).click();
      await completedTurns(frame, displayed + 1);
      const sent = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/merchant/assistant/chat');
      assert.equal(sent.length, before + 1);
      const current = sent.at(-1), savedPath =
        `/agents/merchant/assistant/operations/${current.body.sessionId}/${current.body.requestId}`;
      const saved = await nextResponse('GET', savedPath);
      assert.equal(saved.status, 200);
      return saved.body;
    };
    const fixedMailbox = await sendFixed('Show my own inbox.');
    assert.equal(fixedMailbox.mailRead?.result?.kind, 'list');
    assert.equal(fixedMailbox.mailRead.result.recipient.id, actor.user.id);
    const fixedMessageCard = savedMailCard(fixedMailbox, 'merchant_mail_message', savedTeaching.messageId);
    assert.equal(fixedMessageCard.title, 'Inline image summary exercise');
    const fixedPostsBeforeDetail = requests.filter(row => row.method === 'POST'
      && row.path === '/agents/merchant/assistant/chat').length;
    const fixedDoneBeforeDetail = await doneCount();
    await selectCurrentMailChoice(frame, fixedMessageCard, `View message: ${fixedMessageCard.title}`);
    await completedTurns(frame, fixedDoneBeforeDetail + 1);
    const fixedDetailPost = requests.filter(row => row.method === 'POST'
      && row.path === '/agents/merchant/assistant/chat');
    assert.equal(fixedDetailPost.length, fixedPostsBeforeDetail + 1);
    assert.deepEqual(fixedDetailPost.at(-1).body.selection,
      { choiceId: fixedMessageCard.choiceId, intent: 'mail_detail' });
    const fixedDetailPath = `/agents/merchant/assistant/operations/${fixedDetailPost.at(-1).body.sessionId}/${fixedDetailPost.at(-1).body.requestId}`;
    const fixedDetail = (await nextResponse('GET', fixedDetailPath)).body;
    assert.equal(fixedDetail.mailRead?.result?.kind, 'detail');
    assert.equal(fixedDetail.mailRead.result.messageId, savedTeaching.messageId);
    assert.equal(fixedDetail.mailRead.result.message.sha256,
      Buffer.from(boundMessage.message_sha256).toString('hex'));
    const fixedPostsBeforeSummary = requests.filter(row => row.method === 'POST'
      && row.path === '/email/inline/summary').length;
    await (await visibleButton(frame, 'Summarize selected message')).click();
    const fixedOutcome = await nextResponse('POST', '/email/inline/summary', fixedPostsBeforeSummary);
    const fixedRequestBody = requests.filter(row => row.method === 'POST'
      && row.path === '/email/inline/summary').at(-1)?.body;
    assert.ok(exact(fixedRequestBody, ['requestId', 'readOperationId', 'messageId']));
    assert.equal(fixedRequestBody.readOperationId, fixedDetail.mailRead.result.readOperationId);
    assert.equal(fixedRequestBody.messageId, savedTeaching.messageId);
    const fixedId = fixedRequestBody.requestId;
    assert.match(fixedId, UUID);
    assert.equal(fixedOutcome.status, 403);
    assert.deepEqual(fixedOutcome.body, { ok: false, code: 'MAIL_INLINE_FIXED_DENIED',
      error: 'Inline image fetch blocked in fixed mode' });
    const ownerHeaders = { 'x-dvaia-secureshop-launch': ownerRequest.launch,
      authorization: ownerRequest.authorization, 'content-type': 'application/json' };
    assert.equal(originalHttp.length, 1); assert.equal(judgeInvocations, 1);
    assert.equal((await agents.query(`SELECT count(*)::int AS n FROM secureshop_agents.turn_requests
      WHERE request_id=$1`, [fixedId])).rows[0].n, 0);
    status.fixedSameSourceDenied = true;
    stage = 'sibling-denial';
    const ownerLogin = await auth.login({ username: 'student_merchant', password: 'student123' });
    const tenant = await auth.establishTenantContext(ownerLogin.context);
    const siblingId = randomUUID(), siblingName = `mail_sibling_${randomUUID().slice(0, 8)}`;
    const siblingPassword = 'disposable-mail-sibling';
    const siblingHash = await require('bcryptjs').hash(siblingPassword, 12);
    const siblingRow = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant')
      RETURNING owner_id,shop_user_id`, [siblingId, siblingName,
      `${siblingName}@example.invalid`, siblingHash])).rows[0];
    const siblingTenantId = randomUUID();
    const siblingSlug = `mail_inline_peer_${randomUUID().slice(0, 8)}`;
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
      VALUES($1,$2)`, [siblingTenantId, siblingSlug]);
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
    [siblingTenantId, siblingId, siblingRow.shop_user_id]);
    assert.equal((await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
      SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL`,
    [siblingTenantId, siblingRow.shop_user_id])).rowCount, 1);
    const siblingAuth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity,
            executionTenantSlug: siblingSlug }) });
    const siblingLogin = await siblingAuth.login({ username: siblingName,
      password: siblingPassword });
    const siblingTenant = await siblingAuth.establishTenantContext(siblingLogin.context);
    assert.equal(siblingTenant.tenantId, siblingTenantId);
    assert.notEqual(siblingTenant.tenantId, tenant.tenantId);
    const siblingBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: siblingAuth });
    const siblingBase = await siblingBootstrap(siblingLogin.context);
    assert.equal(siblingBase.persona.user.role, 'merchant');
    assert.notEqual(siblingRow.owner_id, scope.platformOwnerId);
    const siblingHeaders = { 'x-dvaia-secureshop-launch': siblingBase.bearer,
      authorization: `Bearer ${siblingBase.persona.token}` };
    const siblingInbox = await fetch(`${origin}/api/secureshop/email/inbox/${siblingBase.persona.user.id}?requestId=${randomUUID()}`,
      { headers: siblingHeaders });
    assert.equal(siblingInbox.status, 200);
    const siblingScope = await composition.launches.resolveCapability(siblingBase.bearer);
    const siblingTarget = await composition.mailScenes.readRetained(siblingScope);
    assert.match(siblingTarget.targetId, UUID);
    assert.notEqual(siblingTarget.targetId, boundMessage.target_id);
    assert.notEqual(siblingScope.platformOwnerId, scope.platformOwnerId);
    const siblingSummary = await fetch(`${origin}/api/secureshop${summaryGetPath}`,
      { headers: siblingHeaders });
    assert.equal(siblingSummary.status, 200);
    assert.deepEqual(await siblingSummary.json(), { ok: true,
      status: 'unconfirmed', requestId: summary.requestId });
    const siblingAssessment = await fetch(`${origin}/api/secureshop${assessmentPath}`,
      { headers: siblingHeaders });
    assert.equal(siblingAssessment.status, 503);
    assert.deepEqual(await siblingAssessment.json(), { ok: false,
      error: 'Mail inline assessment unavailable' });
    assert.equal(originalHttp.length, 1); assert.equal(judgeInvocations, 1);
    status.siblingDenied = true;
    stage = 'reset-denial';
    const committedReset = await reset.launchResetCoordinator.reset({ launchId: scope.launchId,
      platformSessionId: scope.platformSessionId, platformOwnerId: scope.platformOwnerId,
      expectedGeneration: scope.generation,
      idempotencyKey: `mail-inline-summary-reset-${randomUUID()}` });
    assert.equal(committedReset.status, 'committed');
    assert.equal(committedReset.fromGeneration, scope.generation);
    assert.equal(committedReset.toGeneration, scope.generation + 1);
    const cleanupReceipt = (await agents.query(`SELECT * FROM secureshop_agents.persona_inbox_cleanup_receipts
      WHERE target_id=$1 AND operation_id=$2`, [boundMessage.target_id, committedReset.resetId])).rows;
    assert.equal(cleanupReceipt.length, 1);
    const mailCleanup = (await agents.query(`SELECT * FROM secureshop_agents.lab_mail_cleanup_receipts
      WHERE target_id=$1 AND operation_id=$2`, [boundMessage.target_id, committedReset.resetId])).rows;
    assert.equal(mailCleanup.length, 1);
    const retiredMessages = (await pools.AGENTS_MIGRATION.query(`SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_messages
      WHERE target_id=$1`, [boundMessage.target_id])).rows;
    assert.equal(retiredMessages[0].n, 0);
    const activeContribution = (await identity.query(`SELECT count(*)::int AS n
      FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1`,
    [assessment.judgment.evaluationId])).rows;
    assert.equal(activeContribution[0].n, 0);
    const creditRetirement = (await identity.query(`SELECT * FROM secureshop_auth.assessment_cleanup_history
      WHERE reset_id=$1`, [committedReset.resetId])).rows;
    assert.equal(creditRetirement.length, 1);
    assert.equal(creditRetirement[0].retired_judgment_count, 1);
    assert.equal(creditRetirement[0].retired_contribution_count, 1);
    const inlineUrl = /<img src="([^"]+)"/.exec(messageRows[0].body_markdown)?.[1];
    assert.ok(inlineUrl && digest(inlineUrl) === Buffer.from(boundMessage.url_sha256).toString('hex'));
    await assert.rejects(fetch(inlineUrl, { signal: AbortSignal.timeout(2000) }),
      'the owned one-shot listener must close on committed reset');
    const retiredSummary = await fetch(`${origin}/api/secureshop${summaryGetPath}`,
      { headers: ownerHeaders });
    assert.equal(retiredSummary.status, 401);
    const retiredAssessment = await fetch(`${origin}/api/secureshop${assessmentPath}`,
      { headers: ownerHeaders });
    assert.equal(retiredAssessment.status, 401);
    assert.equal(originalHttp.length, 1); assert.equal(judgeInvocations, 1);
    status.resetDenied = true;
    const retainedJudgment = (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
      WHERE evaluation_id=$1`, [assessment.judgment.evaluationId])).rows;
    assert.equal(retainedJudgment.length, 1);
    for (const key of ['evaluation_id', 'packet', 'evidence_digest', 'result_digest'])
      assert.equal(retainedJudgment[0][key], judgments[0][key]);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_contributions
      WHERE evaluation_id=$1`, [assessment.judgment.evaluationId])).rows, contributions);
    assert.deepEqual((await identity.query(`SELECT * FROM secureshop_auth.assessment_completions
      WHERE evaluation_id=$1`, [assessment.judgment.evaluationId])).rows, completions);
    assert.equal((await composition.mailScenes.readRetained(siblingScope)).targetId,
      siblingTarget.targetId);
    status.immutableHistory = true;
    assert.deepEqual(pageErrors, []);
  } catch (error) { thrown = error; failures.push({ stage, code: error.code || null,
    name: error.name || 'Error', message: String(error.message || '').slice(0, 300) }); }
  finally {
    const cleanup = [];
    for (const close of [() => browser?.close(), () => closeServer(server),
      () => mail?.close(), () => actorTransport?.close(), () => judgeTransport?.close(),
      () => reset?.closeFeatureTransports?.(), () => reset?.auditLedger?.close?.(),
      () => profile && fs.rm(profile, { recursive: true, force: true }),
      () => leasePool.end(), ...Object.values(pools).map(pool => () => pool.end())]) {
      try { await close(); } catch (error) { cleanup.push(error); }
    }
    status.fixtureCleaned = cleanup.length === 0;
    status.actorCalls = actorTransport?.calls.filter(call => call.kind === 'actor').length || 0;
    status.judgeCalls = judgeTransport?.calls.filter(call => call.kind === 'judge').length || 0;
    status.roleTurns = requests.filter(row => row.method === 'POST'
      && row.path === '/agents/merchant/assistant/chat').length;
    if (!thrown && !cleanup.length) try {
      assert.equal(status.roleTurns, 5);
      assert.ok(status.actorCalls >= 13 && status.actorCalls <= 14);
      assert.ok(status.judgeCalls >= 2 && status.judgeCalls <= 4);
      assert.equal(status.listenerGets, 1);
      for (const key of ['isolatedStores', 'physicalTeachingSave', 'originalBoundMessage',
        'physicalProtectedSelection', 'modelSelectedSummary', 'originalHttpEffect',
        'canonicalJudgePass', 'genuineCredit', 'savedGetOnlyRecovery',
        'fixedSameSourceDenied', 'siblingDenied', 'resetDenied', 'immutableHistory',
        'fixtureCleaned']) assert.equal(status[key], true, `${key} requires original proof`);
      status.passed = true;
    } catch (error) {
      thrown = error;
      failures.push({ stage: 'final-proof', code: error.code || null,
        name: error.name || 'Error', message: String(error.message || '').slice(0, 300) });
    }
    status.errors = failures;
    const wire = { version: 1, model: MODEL, modelDigest: MODEL_DIGEST,
      calls: [...(actorTransport?.calls || []), ...(judgeTransport?.calls || [])],
      requests, responses, originalHttp, judgeTranscripts, proof, pageErrors };
    const wireBytes = JSON.stringify(wire);
    assert.ok(Buffer.byteLength(wireBytes) <= 80 * 1024 * 1024, 'bounded original wire');
    await fs.writeFile(path.join(path.dirname(config.evidencePath), 'mail-inline-summary-original-wire.json'),
      wireBytes, { flag: 'wx', mode: 0o600 });
    await fs.writeFile(config.evidencePath, JSON.stringify(status, null, 2), { flag: 'wx', mode: 0o600 });
    if (cleanup.length) throw new AggregateError(cleanup, 'Mail inline fixture cleanup failed');
  }
  if (thrown) throw thrown;
});
