'use strict';

// Opted, disposable V48 browser qualification. The fixture never reads the
// random target character before the physical learner turn and assessment.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createLaunchScope, createConversationBinding } = require('../../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../../server/services/secureshopTurnRequest');
const Guided = require('../../server/services/secureshopCouponProbeGuidedProtocol');
const Request = require('../../server/services/secureshopCouponProbeRequest');
const { BASELINE, BIT_CODES, MESSAGE, CONTINUATION_FEEDBACK, BLIND_RENDERED_FLAGS,
  BLIND_RENDERED_SCOPE, BLIND_RENDERED_HISTORICAL_SCOPE, inferCharacterFromPublicObservations,
  assertRenderedReceipt } = require('../fixtures/secureshopCouponBlindRenderedQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_COUPON_BLIND_BROWSER_';
const GATE = 'SECURESHOP_COUPON_BLIND_BROWSER_NATIVE';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const OBJECTIVE = 'ss_sqli_blind_boolean';
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const TITLE = 'customer physically infers an unknown coupon target character with original boolean probes and canonical Judge proof';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const enabled = process.env[GATE] === '1' && process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.LIVE_OLLAMA_TEST === '1' && Object.keys(STORES).every(store =>
    ['RUNTIME', 'MIGRATION'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function nativeConfiguration(env = process.env) {
  assert.equal(env[GATE], '1'); assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.LIVE_OLLAMA_TEST, '1');
  assert.equal(path.resolve(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || ''), ROOT);
  assert.equal(process.cwd(), ROOT);
  const evidencePath = env.SECURESHOP_COUPON_BLIND_BROWSER_EVIDENCE_PATH;
  const recordPath = env.SECURESHOP_COUPON_BLIND_BROWSER_RECORD_PATH;
  const build = env.SECURESHOP_COUPON_BLIND_BROWSER_BUILD;
  const browser = env.PUPPETEER_EXECUTABLE_PATH;
  assert.ok([evidencePath, recordPath, build, browser].every(item => path.isAbsolute(item || '')));
  assert.equal(path.dirname(evidencePath), path.dirname(recordPath));
  assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
  assert.equal(path.resolve(build), path.join(ROOT, 'client/build'));
  assert.match(env.SECURESHOP_COUPON_BLIND_BROWSER_SHA256 || '', HASH);
  assert.match(env.SECURESHOP_COUPON_BLIND_BROWSER_MODEL_DIGEST || '', HASH);
  assert.equal(env.SECURESHOP_COUPON_BLIND_BROWSER_MODEL_DIGEST, MODEL_DIGEST);
  const urls = {}; let nonce, port;
  for (const [store, name] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(env[`${PREFIX}${store}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = /^\/owasp_ai_goat_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
      assert.ok(match && match[2] === name);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[`${store}_${role}`] = url.href;
    }
    assert.equal(new URL(urls[`${store}_RUNTIME`]).pathname,
      new URL(urls[`${store}_MIGRATION`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(store =>
    new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return { evidencePath, recordPath, build, browser, urls };
}

async function recordBrowser(browser, target, executablePath, expectedSha) {
  const pid = browser?.process?.()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const real = await fs.realpath(executablePath);
  const actualSha = digest(await fs.readFile(real)); assert.equal(actualSha, expectedSha);
  const startTime = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='],
    { encoding: 'utf8' }).trim();
  assert.match(startTime, /^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$/);
  const temp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(temp, JSON.stringify({ schemaVersion: 1, processes: [{
    kind: 'coupon_blind_browser', pid, startTime,
    executablePath: real, executableSha256: actualSha }] }) + '\n',
  { mode: 0o600, flag: 'wx' });
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
  const client = await pools.COMMERCE_MIGRATION.connect();
  try { await client.query('BEGIN');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(client);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function frameFor(page) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await sleep(50);
  }
  throw Error('Owned customer frame did not mount');
}

async function physicalButton(frame, label, selector = 'button') {
  const handle = await frame.waitForFunction(({ selector, label }) => {
    const matches = [...document.querySelectorAll(selector)]
      .filter(node => node.textContent.trim() === label && !node.disabled
        && node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden');
    return matches.length === 1 ? matches[0] : null;
  }, { timeout: 20000 }, { selector, label });
  try {
    const element = handle.asElement(); assert.ok(element);
    await element.evaluate(node => node.scrollIntoView({ block: 'center' }));
    await element.evaluate(async node => {
      const deadline = performance.now() + 20000; let stable = 0, prior = null;
      while (performance.now() < deadline) {
        if (!node.isConnected) throw Error('Physical button detached');
        const rect = node.getBoundingClientRect();
        const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
        const hit = document.elementFromPoint(x, y);
        const box = [rect.left, rect.top, rect.width, rect.height];
        const ready = !node.disabled && rect.width > 0 && rect.height > 0
          && x >= 0 && y >= 0 && x < innerWidth && y < innerHeight
          && (hit === node || node.contains(hit));
        if (ready && prior && box.every((value, index) => value === prior[index])) stable += 25;
        else stable = 0;
        if (stable >= 125) return;
        prior = ready ? box : null;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      throw Error('Physical button not stable and unobstructed');
    });
    await element.click();
  } finally { await handle.dispose(); }
}

async function physicalRequestMode(frame, page) {
  const selector = '#coupon-assistant-request-mode';
  const handle = await frame.waitForFunction(({ selector, guided, guidedV1 }) => {
    const node = document.querySelector(selector);
    if (!(node instanceof HTMLSelectElement) || node.disabled || node.value !== 'raw'
      || node.options.length !== 3 || node.options[0].value !== 'raw'
      || node.options[1].value !== guidedV1
      || node.options[2].value !== guided || !node.getClientRects().length
      || getComputedStyle(node).visibility === 'hidden') return null;
    return node;
  }, { timeout: 20000 }, { selector, guided: Request.GUIDED_V2,
    guidedV1: Request.GUIDED });
  try {
    const element = handle.asElement(); assert.ok(element);
    await element.evaluate(node => node.scrollIntoView({ block: 'center' }));
    await element.evaluate(async node => {
      const deadline = performance.now() + 20000; let stable = 0, prior = null;
      while (performance.now() < deadline) {
        if (!node.isConnected || node.disabled || node.value !== 'raw')
          throw Error('Request mode selector changed before selection');
        const rect = node.getBoundingClientRect();
        const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
        const hit = document.elementFromPoint(x, y);
        const box = [rect.left, rect.top, rect.width, rect.height];
        const ready = rect.width > 0 && rect.height > 0
          && x >= 0 && y >= 0 && x < innerWidth && y < innerHeight
          && (hit === node || node.contains(hit));
        if (ready && prior && box.every((value, index) => value === prior[index])) stable += 25;
        else stable = 0;
        if (stable >= 125) return;
        prior = ready ? box : null;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      throw Error('Request mode selector not stable and unobstructed');
    });
    await element.click();
    assert.equal(await frame.evaluate(node => document.activeElement === node, element), true);
    await page.keyboard.type('Guided boolean investigation with calculator');
    await page.keyboard.press('Enter');
    await frame.waitForFunction(({ selector, guided }) =>
      document.querySelector(selector)?.value === guided,
    { timeout: 20000 }, { selector, guided: Request.GUIDED_V2 });
    assert.equal(await frame.$eval(selector, node => node.value), Request.GUIDED_V2);
  } finally { await handle.dispose(); }
}

function waitResponse(page, method, pathname, timeout = 90000) {
  return page.waitForResponse(response => response.request().method() === method
    && new URL(response.url()).pathname === pathname, { timeout });
}

function headersFrom(request) {
  const headers = request.headers();
  assert.match(headers.authorization || '', /^Bearer [A-Za-z0-9_.-]+$/);
  assert.match(headers['x-owasp-ai-goat-secureshop-launch'] || '', /^[A-Za-z0-9_-]{43}$/);
  return { authorization: headers.authorization,
    'x-owasp-ai-goat-secureshop-launch': headers['x-owasp-ai-goat-secureshop-launch'] };
}

async function protectedGet(origin, pathname, headers, status = 200, onUnexpected) {
  const response = await fetch(`${origin}${pathname}`, { headers,
    redirect: 'error', signal: AbortSignal.timeout(10000) });
  const raw = await response.text(); assert.ok(Buffer.byteLength(raw) <= 131072);
  if (response.status !== status && onUnexpected) await onUnexpected({
    status: response.status, contentType: response.headers.get('content-type') || '', raw,
  });
  assert.equal(response.status, status);
  return JSON.parse(raw);
}

async function captureSavedGetFailure({ status, contentType, raw }, directRead) {
  const bytes = Buffer.byteLength(raw), maximum = 4096;
  const record = { status, contentType, bytes, sha256: digest(raw),
    truncated: bytes > maximum, body: bytes <= maximum ? raw : null };
  try {
    const result = await directRead();
    record.privateRead = { outcome: 'returned', status: result?.status ?? null };
  } catch (error) {
    // The private diagnostic records only bounded guard locations, never internal values.
    const frames = [...String(error.stack || '').matchAll(
      /secureshopCouponProbeApplication\.js:(\d+):(\d+)/g)].slice(0, 4)
      .map(match => ({ line: Number(match[1]), column: Number(match[2]) }));
    record.privateRead = { outcome: 'rejected', name: String(error.name || '').slice(0, 80),
      code: String(error.code || '').slice(0, 80), frames };
  }
  return record;
}

async function boundedJsonResponse(response, maxBytes = 131072) {
  const raw = await response.text();
  assert.ok(Buffer.byteLength(raw) <= maxBytes);
  assert.match(response.headers()['content-type'] || '', /^application\/json(?:;|$)/i);
  return { status: response.status(), raw, sha256: digest(raw), body: JSON.parse(raw) };
}

function observeOriginalRunResponse(response, requestBody, records) {
  const maximum = 512 * 1024;
  const hash = createHash('sha256');
  const chunks = [];
  let bytes = 0, recorded = false, ended = false;
  const capture = (chunk, encoding) => {
    if (chunk === undefined || chunk === null) return;
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk,
      typeof encoding === 'string' ? encoding : 'utf8');
    bytes += data.length;
    hash.update(data);
    if (bytes <= maximum) chunks.push(data);
  };
  const originalWrite = response.write;
  const originalEnd = response.end;
  response.write = function (...args) {
    capture(args[0], args[1]);
    return originalWrite.apply(this, args);
  };
  response.end = function (...args) {
    if (!ended) { capture(args[0], args[1]); ended = true; }
    return originalEnd.apply(this, args);
  };
  const record = complete => {
    if (recorded) return;
    recorded = true;
    records.push({ sessionId: requestBody?.sessionId ?? null,
      requestId: requestBody?.requestId ?? null, status: response.statusCode,
      contentType: String(response.getHeader?.('content-type') || ''),
      complete, bytes, sha256: hash.digest('hex'), truncated: bytes > maximum,
      body: bytes <= maximum ? Buffer.concat(chunks).toString('utf8') : null });
  };
  response.once('finish', () => record(true));
  response.once('close', () => record(false));
}

function assertSavedRequestHash(source, expectedHash) {
  assert.ok(source?.savedRequest && source?.turn);
  assert.equal(source.savedRequest.requestHash, expectedHash);
  assert.equal(Object.hasOwn(source.turn, 'request_hash'), false);
}

async function readOriginalTraces(conversations, scope, persona, sessionId, eventIds) {
  assert.ok(Array.isArray(eventIds) && eventIds.length > 0);
  const rows = await conversations.getTraceEvents(sessionId,
    createConversationBinding(scope, persona), eventIds, 'secureshop_coupon_probe');
  assert.deepEqual(rows.map(row => row.event_id), eventIds);
  assert.ok(rows.every(row => row.session_id === sessionId));
  return rows;
}

module.exports.observeOriginalRunResponse = observeOriginalRunResponse;
module.exports.assertSavedRequestHash = assertSavedRequestHash;
module.exports.captureSavedGetFailure = captureSavedGetFailure;
module.exports.readOriginalTraces = readOriginalTraces;

test(TITLE, { skip: !enabled, timeout: 600000 }, async t => {
  // All executable resources remain root-owned through the disposable launcher.
  const config = nativeConfiguration();
  await fs.access(path.join(config.build, 'index.html'));
  await fs.access(path.join(config.build, 'secureshop-frame.html'));
  await fs.access(config.browser);
  const pools = Object.fromEntries(Object.entries(config.urls).map(([key, connectionString]) =>
    [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
      connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
  const leasePool = new Pool({ connectionString: config.urls.IDENTITY_RUNTIME, max: 4 });
  const status = Object.fromEntries(BLIND_RENDERED_FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: BLIND_RENDERED_SCOPE, actorCalls: 0, judgeCalls: 0,
    roleTurns: 0, probeCount: 0, genuineCredit: 0, errors: [], cleanupErrors: [] });
  let analyticsPool, server, browser, profile, transportV, transportF, reset, failure;
  const originalModelURL = process.env.OLLAMA_BASE_URL;
  const requests = [], pages = [], actorSpans = [], judgePackets = [], judgeResults = [];
  const originalCapture = { runResponses: [] };
  const wirePath = path.join(path.dirname(config.evidencePath), 'coupon-blind-original-wire.json');
  const saveWire = async () => {
    const raw = JSON.stringify({ version: 1, model: MODEL, modelDigest: MODEL_DIGEST,
      vulnerableCalls: transportV?.calls || [], fixedCalls: transportF?.calls || [],
      actorSpans, judgePackets, judgeResults, requests, pages, originalCapture });
    assert.ok(Buffer.byteLength(raw) <= 64 * 1024 * 1024);
    await fs.writeFile(wirePath, raw, { mode: 0o600 });
  };
  try {
    await migrateAndSeed(pools);
    status.isolatedStores = true;
    const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
    const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
    const ownerToken = process.env.SECURESHOP_COUPON_ANALYTICS_OWNER || '';
    const analyticsPort = Number(process.env.SECURESHOP_COUPON_ANALYTICS_PORT);
    assert.match(ownerToken, /^[a-f0-9]{12}$/);
    assert.ok(Number.isSafeInteger(analyticsPort) && analyticsPort > 0 && analyticsPort <= 65535);
    const analyticsDatabase = `owasp_ai_goat_analytics_control_${ownerToken}`;
    const analyticsCluster = `owasp-ai-goat-owned-analytics-${ownerToken}`;
    assert.equal(process.env.SECURESHOP_COUPON_ANALYTICS_DATABASE, analyticsDatabase);
    assert.equal(process.env.SECURESHOP_COUPON_ANALYTICS_CLUSTER, analyticsCluster);
    const expectedSystemId = process.env.SECURESHOP_COUPON_ANALYTICS_SYSTEM_IDENTIFIER || '';
    assert.match(expectedSystemId, /^[0-9]{10,20}$/);
    const analyticsConnection = { host: '127.0.0.1', port: analyticsPort,
      user: 'postgres', database: analyticsDatabase, connectionTimeoutMillis: 2000 };
    analyticsPool = new Pool({ ...analyticsConnection, max: 5 });
    analyticsPool.on('error', () => {});
    const systemId = (await analyticsPool.query(
      'SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0]?.id;
    assert.equal(systemId, expectedSystemId);
    const analyticsIdentity = { systemIdentifier: systemId,
      controlDatabase: analyticsDatabase, clusterName: analyticsCluster };
    const analyticsBootstrap = require('../../sidecars/analytics-sql-target/bootstrap');
    await analyticsBootstrap.initializeControl({ pool: analyticsPool,
      identity: analyticsIdentity, requiredVersion: 2 });
    for (const database of ['postgres', 'template1', analyticsDatabase]) {
      assert.match(database, /^[a-z0-9_]+$/);
      await analyticsPool.query(`REVOKE CONNECT ON DATABASE ${database} FROM PUBLIC`);
    }
    const analyticsService = require('../../sidecars/analytics-sql-target/service')
      .createOwnedAnalyticsService({ controlPool: analyticsPool,
        identity: analyticsIdentity, createPool: options => new Pool(options),
        connection: analyticsConnection, fixedCapabilities: true });
    const analyticsRuntime = Object.freeze({ admissions: true, fixedCapabilities: true,
      service: analyticsService, assertReady: async () => {
        const current = (await analyticsPool.query(
          'SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0]?.id;
        assert.equal(current, systemId);
        await analyticsBootstrap.assertControlReady({ pool: analyticsPool,
          identity: analyticsIdentity, requiredVersion: 2 });
      } });
    status.ownedAnalyticsReady = true;

    const authRepository = require('../../server/database/postgres/secureshopStandaloneAuthRepository')
      .createSecureShopStandaloneAuthRepository({ pool: identity });
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository: authRepository });
    const suffix = randomUUID().slice(0, 8), username = `blind_browser_${suffix}`;
    const password = 'disposable-blind-browser-only';
    const owner = await auth.register({ username, password,
      email: `${username}@owned.invalid`, role: 'customer' });
    const peer = await auth.register({ username: `blind_peer_${suffix}`, password,
      email: `blind-peer-${suffix}@owned.invalid`, role: 'customer' });
    const peerMerchant = await auth.register({ username: `blind_merchant_${suffix}`, password,
      email: `blind-merchant-${suffix}@owned.invalid`, role: 'merchant' });
    const ownerTenant = await auth.establishTenantContext(owner.context);
    const peerTenantId = randomUUID(), peerSlug = `blind_peer_tenant_${suffix}`;
    const peerTenant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO
      secureshop_auth.tenants (tenant_id,slug) VALUES($1,$2) RETURNING owner_id`,
    [peerTenantId, peerSlug])).rows[0];
    assert.notEqual(peerTenant.owner_id, ownerTenant.ownerId);
    for (const [registration, role] of [[peer, 'customer'], [peerMerchant, 'merchant']]) {
      await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
      [peerTenantId, registration.context.principalId,
        registration.context.shopUserId, role]);
    }
    await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
      SET seed_merchant_id=$2 WHERE tenant_id=$1`,
    [peerTenantId, peerMerchant.context.shopUserId]);
    const peerAuth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity,
            executionTenantSlug: peerSlug }) });
    const peerLogin = await peerAuth.login({ username: peer.context.username, password });
    const peerPrincipal = await peerAuth.establishTenantContext(peerLogin.context);
    assert.equal(peerPrincipal.tenantId, peerTenantId);
    assert.equal(peerPrincipal.ownerId, peerTenant.owner_id);

    const administrator = await auth.login({ username: 'student_admin', password: 'student123' });
    const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
      .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
    const objective = (await assessmentCatalog.list(administrator.context)).objectives
      .find(row => row.objectiveId === OBJECTIVE);
    const checkedInQualification = require('../../server/config/secureshopCurriculum').OBJECTIVES
      .find(row => row.id === OBJECTIVE)?.qualification;
    assert.ok(['pending', 'native-browser-judge'].includes(checkedInQualification));
    assert.equal(objective?.qualification, checkedInQualification);
    assert.equal(objective.enabled, false);
    let admittedObjective = objective;
    if (checkedInQualification === 'pending') {
      await assert.rejects(assessmentCatalog.set(administrator.context,
        { objectiveId: OBJECTIVE, enabled: true, expectedRevision: objective.revision }),
      { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
      const admitted = await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.assessment_objectives
        SET qualification='native-browser-judge' WHERE objective_id=$1 AND qualification='pending'
          AND is_enabled=false AND catalog_active=true
          AND configuration_source='checked_in_default'
          AND source_document->>'qualification'='pending'
        RETURNING objective_id,qualification,is_enabled`, [OBJECTIVE]);
      assert.equal(admitted.rowCount, 1);
      assert.deepEqual(admitted.rows, [{ objective_id: OBJECTIVE,
        qualification: 'native-browser-judge', is_enabled: false }]);
      admittedObjective = (await assessmentCatalog.list(administrator.context)).objectives
        .find(row => row.objectiveId === OBJECTIVE);
      status.fixtureLocalCandidateAdmission = true;
      status.scope = BLIND_RENDERED_HISTORICAL_SCOPE;
      t.diagnostic('Historical fixture-local admission in an owned disposable identity store; checked-in objective remains pending');
    } else {
      status.fixtureLocalCandidateAdmission = false;
      t.diagnostic('Checked-in qualified objective enabled normally in the owned disposable identity store');
    }
    assert.equal(admittedObjective.qualification, 'native-browser-judge');
    assert.equal(admittedObjective.enabled, false);
    assert.equal(admittedObjective.revision, objective.revision);
    assert.equal((await assessmentCatalog.set(administrator.context,
      { objectiveId: OBJECTIVE, enabled: true, expectedRevision: admittedObjective.revision })).enabled, true);
    status.canonicalObjectiveEnabled = true;

    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    const analyticsLifecycle = require('../../server/services/secureshopAnalyticsLifecycle')
      .createAnalyticsLifecycle({ cleanupAuthority:
        require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository')
          .createSecureShopResetCleanupAuthorityRepository(identity),
        service: analyticsService, agentsPool: agents, reviewPool: review });
    reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit, analyticsLifecycle, analyticsRuntime });
    transportV = await require('./secureshopMailActualTransport')
      .createMailActualTransport({ maxHttpCalls: 14, allowMetadata: true });
    process.env.OLLAMA_BASE_URL = transportV.judgeUrl;
    const configuredJudge = require('../../server/agent-runtime/objectiveJudge')
      .createObjectiveJudge({ observeExecutionTranscript: packet => judgePackets.push(packet) });
    let judgeRuns = 0;
    const judge = async input => {
      assert.ok(++judgeRuns <= 1, 'one original configured Judge evaluation');
      const result = await configuredJudge(input);
      judgeResults.push(result);
      status.judgeCalls = transportV.calls.filter(call => call.kind === 'judge').length;
      assert.ok(status.judgeCalls >= 1 && status.judgeCalls <= 2);
      return result;
    };
    require('../../server/agent-runtime/judgeProviderConfiguration')
      .registerConfiguredJudge(judge, () =>
        require('../../server/agent-runtime/judgeProviderConfiguration')
          .readJudgeProviderConfig(configuredJudge));
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
        progress, resetComposition: reset, judge,
        expectedIdentityDatabase: new URL(config.urls.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(config.urls.AGENTS_RUNTIME).pathname.slice(1) });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository: require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
      reviewPool: review, launches: reset.launches });
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const modeAuthority = reset.modeAuthority;
    const provider = new (require('../../server/services/secureshop/providers/ollamaProvider')
      .OllamaProvider)({ baseUrl: transportV.actorUrl, model: MODEL });
    let mode = 'vuln', actorRuns = 0;
    for (const method of ['chat', 'finalResponse']) {
      const invoke = provider[method].bind(provider);
      provider[method] = async input => {
        assert.ok(++actorRuns <= 19, 'two bounded original graph turns');
        const currentTransport = mode === 'vuln' ? transportV : transportF;
        assert.ok(currentTransport);
        const start = currentTransport.calls.length;
        const result = await invoke({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
        assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
        const wires = currentTransport.calls.slice(start);
        assert.ok(wires.length >= 1 && wires.every(wire => wire.kind === 'actor'
          && wire.status === 200 && wire.responseComplete === true
          && wire.responseCaptureTruncated === false));
        actorSpans.push({ mode, method, result, wireIndices: wires.map(wire => wire.index) });
        status.actorCalls = [transportV, transportF].filter(Boolean)
          .flatMap(t => t.calls).filter(call => call.kind === 'actor').length;
        assert.ok(status.actorCalls <= 27);
        return result;
      };
    }
    const couponDependencies = await require('../../server/services/secureshopCouponProduction')
      .prepareCommerceDependencies({ modeAuthority, reviewPool: review,
        launches: reset.launches, mode: 'vuln' });
    const probeDependencies = await require('../../server/services/secureshopCouponProbeProduction')
      .prepareCouponProbeDependencies({ runtime: analyticsRuntime,
        lifecycle: analyticsLifecycle, commercePool: commerce });
    await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
      .assertBoundToolPolicyReadiness(agents);
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: audit.agents });
    const promptPolicyRepository = require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
      .createBoundPromptPolicyRepository({ pool: agents,
        personaAuthority: grading.personaAuthority, audit: audit.agents,
        checkRunBinding: require('../../server/services/secureshopPromptPolicyRunBinding')
          .createPromptPolicyRunBinding({ identityPool: identity }), modeAuthority });
    await promptPolicyRepository.checkReadiness();
    const composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, couponDependencies,
        couponProbeDependencies: probeDependencies, toolPolicyRepository,
        personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
          .activationPolicy(process.env).requested,
        promptPolicyRepository,
        // The coupon graph uses real durable run-snapshot admission. Admin
        // policy rendering is outside this customer cohort and fails closed.
        promptPolicyRenderer: { render() { throw Error('Policy rendering is outside coupon qualification'); } },
        fixtures: [], requiredObjectives: [OBJECTIVE], judge,
        jwtSecret: 'owned-blind-browser-persona-secret-at-least-32-bytes',
        agentRuntime: { provider } });
    await composition.repositories.personas.ensureTemplates();
    assert.equal(composition.couponProbe?.ready, true);
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
        reviewPool: review, commercePool: commerce });
    const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
      .createRegisteredAdminResetEnvelope({ activeKeyId: 'blind-owned',
        keys: new Map([['blind-owned', randomBytes(32)]]) });
    const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
      .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
    await resetRepository.checkReadiness();
    const standaloneAuthority = { service: auth, bootstrap, mode: standaloneMode,
      reset: require('../../server/services/secureshopStandaloneReset')
        .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
          launches: composition.launches, scenes,
          resetCoordinator: reset.launchResetCoordinator,
          preflight: reset.sceneResetPreflight }),
      registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
        .createRegisteredAdminResetService({ repository: resetRepository }),
      assessmentObjectives: assessmentCatalog,
      assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
        .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth,
          bootstrap, launches: composition.launches, personaAuth: composition.personaAuth,
          personaAuthority: grading.personaAuthority, modeAuthority, scenes,
          qualifyIdorModel: require('../../server/services/secureshopModelQualification')
            .createSecureShopModelQualifier(provider), judge }),
      cartImport: require('../../server/services/secureshopStandaloneCartImport')
        .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
          personaAuth: composition.personaAuth, commerce: composition.commerce }),
      practices: require('../../server/services/secureshopPracticeAdmission')
        .createSecureShopPracticeAdmission({ catalog: composition.catalog,
          repository: require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
            .createSecureShopPracticeAdmissionRepository({ pool: identity }) }) };
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        applicationMode: 'standalone', authenticateToken: (_request, response) =>
          response.sendStatus(401), audit: async () => {}, agentRuntime: {},
        getComposition: async () => ({ ...composition,
          standaloneAuth: standaloneAuthority, publicCatalog }) });
    assert.equal(bound.standaloneReadiness.ready, true);
    const app = express(); app.use(express.json());
    app.use('/api/secureshop', (request, response, next) => {
      if (request.path.startsWith('/customer/coupon-probe/')) {
        assert.ok(requests.length < 48);
        requests.push({ method: request.method, path: request.path,
          body: request.method === 'POST' ? structuredClone(request.body) : null });
        if (request.method === 'POST' && request.path === '/customer/coupon-probe/run')
          { assert.ok(++status.roleTurns <= 2, 'exactly two physical coupon probe turns');
            observeOriginalRunResponse(response, request.body, originalCapture.runResponses); }
      }
      next();
    });
    server = await new Promise(resolve => {
      const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
    });
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ ...standaloneAuthority,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
      .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
    app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
      .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
        isAvailable: async () => true }));
    app.use('/api', (_request, response) =>
      response.status(404).json({ error: 'Outside coupon blind qualification' }));
    app.use(express.static(config.build, { setHeaders: response =>
      response.set('Access-Control-Allow-Origin', '*') }));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: config.build }));
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-coupon-blind-browser-'));
    browser = await require('puppeteer').launch({ headless: true,
      userDataDir: profile, executablePath: config.browser });
    await recordBrowser(browser, config.recordPath, config.browser,
      process.env.SECURESHOP_COUPON_BLIND_BROWSER_SHA256);
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 900 });
    page.on('pageerror', error => { if (pages.length < 16)
      pages.push({ kind: 'pageerror', message: String(error.message).slice(0, 200) }); });
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    page.on('requestfailed', request => {
      if (pages.length < 16 && request.url().startsWith(`${origin}/`))
        pages.push({ kind: 'requestfailed', method: request.method(),
          path: new URL(request.url()).pathname,
          error: String(request.failure()?.errorText || 'unknown').slice(0, 100) });
    });
    assert.ok([200, 304].includes((await page.goto(`${origin}/secureshop/login`)).status()));
    await page.waitForSelector('#ss-login-user');
    await page.type('#ss-login-user', username);
    await page.type('#ss-login-pw', password);
    const login = waitResponse(page, 'POST', '/api/secureshop/auth/login', 30000);
    const bootstrapResponse = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 30000);
    const firstCart = waitResponse(page, 'GET', '/api/secureshop/cart', 30000);
    void login.catch(() => {}); void bootstrapResponse.catch(() => {});
    void firstCart.catch(() => {});
    await page.click('button[type="submit"]');
    assert.equal((await login).status(), 200);
    assert.equal((await bootstrapResponse).status(), 200);
    const cart = await firstCart; assert.equal(cart.status(), 200);
    const ownerHeaders = headersFrom(cart.request());
    const scope = await composition.launches.resolveCapability(
      ownerHeaders['x-owasp-ai-goat-secureshop-launch']);
    const actor = await composition.personaAuth.authenticateBoundToken({ scope,
      token: ownerHeaders.authorization.slice('Bearer '.length) });
    const persona = { id: actor.user.id, role: 'customer' };
    const personaSession = { sessionId: actor.sessionId,
      authorityVersion: actor.authorityVersion };
    const ownerPrincipal = await auth.establishTenantContext(
      await auth.authenticate((await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'owasp_ai_goat_shop_session').value));
    assert.equal(ownerPrincipal.ownerId, ownerTenant.ownerId);
    await composition.catalog.prepareTarget({ scope, persona, personaSession });
    const target = await scenes.readExisting(scope);
    assert.ok(target?.targetId);
    const product = (await review.query(`SELECT product_id FROM
      secureshop_review.product_target_products WHERE target_id=$1 AND stock_quantity>0
      AND status='active' AND price>0 ORDER BY product_id LIMIT 1`,
    [target.targetId])).rows[0];
    assert.ok(Number.isSafeInteger(product?.product_id));
    await composition.commerce.add({ scope, persona, personaSession,
      productId: product.product_id, quantity: 1 });
    const ownedCart = await composition.commerce.cart({ scope, persona, personaSession });
    assert.ok(ownedCart.subtotal > 0 && ownedCart.items.some(item =>
      item.product_id === product.product_id && item.quantity === 1));
    const cartReload = waitResponse(page, 'GET', '/api/secureshop/cart', 30000);
    void cartReload.catch(() => {});
    await page.reload({ waitUntil: 'domcontentloaded' });
    const renderedCart = await boundedJsonResponse(await cartReload);
    assert.equal(renderedCart.status, 200);
    assert.ok(renderedCart.body.items?.some(item => item.product_id === product.product_id
      && item.quantity === 1));
    const couponBank = (await commerce.query(`SELECT id,code,discount_percent,active
      FROM secureshop.coupons ORDER BY id LIMIT 65`)).rows;
    const baseline = couponBank.filter(row => row.code === BASELINE && row.active === 1);
    assert.equal(baseline.length, 1);
    assert.ok(Number.isInteger(baseline[0].discount_percent)
      && baseline[0].discount_percent > 0);
    status.unknownCharacterAtAdmission = true;
    let frame = await frameFor(page);
    await frame.waitForSelector('a[href="/secureshop/cart"]');
    const capability = waitResponse(page, 'GET',
      '/api/secureshop/customer/coupon-probe/capabilities', 30000);
    void capability.catch(() => {});
    await frame.click('a[href="/secureshop/cart"]');
    frame = await frameFor(page);
    await frame.waitForSelector('[aria-label="Coupon assistant"]', { visible: true });
    // The panel is mounted only after the authenticated readiness capability.
    const capabilityValue = await boundedJsonResponse(await capability);
    assert.equal(capabilityValue.status, 200);
    assert.deepEqual(capabilityValue.body, { ready: true });
    const ownerContext = { scope, persona, personaSession };
    const assessmentRows = async table => (await identity.query(`SELECT * FROM
      secureshop_auth.${table} WHERE tenant_id=$1 AND principal_id=$2
      AND objective_id=$3 ORDER BY evaluation_id`,
    [ownerPrincipal.tenantId, ownerPrincipal.principalId, OBJECTIVE])).rows;
    const sqlRows = async () => (await analyticsPool.query(`SELECT * FROM
      public.owned_analytics_queries ORDER BY target_id,operation_id`)).rows;
    assert.deepEqual(await sqlRows(), []);
    assert.deepEqual(await assessmentRows('assessment_judgments'), []);
    const physicalTurn = async currentMode => {
      frame = await frameFor(page);
      await physicalRequestMode(frame, page);
      const textarea = await frame.waitForSelector('#coupon-assistant-message', { visible: true });
      await textarea.type(MESSAGE);
      const sessionWait = waitResponse(page, 'POST', '/api/secureshop/customer/coupon-probe/session');
      const runWait = waitResponse(page, 'POST', '/api/secureshop/customer/coupon-probe/run', 240000);
      void sessionWait.catch(() => {}); void runWait.catch(() => {});
      await physicalButton(frame, 'Ask coupon assistant', '[aria-label="Coupon assistant"] button');
      const session = await boundedJsonResponse(await sessionWait);
      assert.equal(session.status, 200);
      assert.deepEqual(Object.keys(session.body), ['sessionId']);
      assert.match(session.body.sessionId, UUID);
      const run = await boundedJsonResponse(await runWait, 512 * 1024);
      assert.equal(run.status, 200);
      const posted = requests.filter(row => row.method === 'POST'
        && row.path === '/customer/coupon-probe/run').at(-1)?.body;
      assert.ok(posted && posted.sessionId === session.body.sessionId
        && UUID.test(posted.requestId) && posted.message === MESSAGE
        && posted.protocol === Request.GUIDED_V2);
      assert.deepEqual(Object.keys(posted).sort(), ['sessionId', 'requestId', 'message', 'protocol'].sort());
      assert.deepEqual(JSON.parse((await runWait).request().postData()), posted);
      assert.equal(run.body.status, 'completed');
      assert.equal(run.body.sessionId, posted.sessionId);
      assert.equal(run.body.requestId, posted.requestId);
      assert.equal(run.body.stopReason, 'end_turn');
      assert.equal(run.body.provider, 'ollama'); assert.equal(run.body.model, MODEL);
      const savedPath = `/api/secureshop/customer/coupon-probe/operations/${posted.sessionId}/${posted.requestId}`;
      const saved = await protectedGet(origin, savedPath, ownerHeaders, 200,
        async unexpected => { originalCapture.savedGetFailure = await captureSavedGetFailure(
          unexpected, () => composition.couponProbe.application.read({
            ...ownerContext, sessionId: posted.sessionId, requestId: posted.requestId })); });
      assert.equal(saved.status, 'completed'); assert.equal(saved.replayed, true);
      assert.deepEqual(saved.probes, run.body.probes);
      assert.equal(saved.text, run.body.text);
      frame = await frameFor(page);
      await frame.waitForFunction(text => {
        const panel = document.querySelector('[aria-label="Coupon assistant"]');
        return panel?.querySelector('[role="status"]')?.textContent === text;
      }, { timeout: 30000 }, saved.text);
      const privateSource = await composition.couponProbe.application.readSavedSource(
        ownerContext, { sessionId: posted.sessionId, requestId: posted.requestId });
      const encoded = Request.encode(MESSAGE, Request.GUIDED_V2);
      assert.equal(privateSource.savedRequest.message, encoded);
      assertSavedRequestHash(privateSource, createTurnRequest({
        sessionId: posted.sessionId, requestId: posted.requestId,
        binding: createConversationBinding(scope, persona), message: encoded,
      }).hash);
      assert.equal(privateSource.turn.text, saved.text);
      assert.equal(privateSource.turn.stopReason, 'end_turn');
      assert.equal(privateSource.turn.taskMetadata.couponProbe.version, 3);
      assert.equal(privateSource.turn.taskMetadata.couponProbe.protocol, Request.GUIDED_V2);
      assert.equal(privateSource.turn.taskMetadata.couponProbe.originalMessage, MESSAGE);
      assert.equal(privateSource.turn.taskMetadata.couponProbe.sourceBinding
        .couponMode.mode, currentMode);
      return { mode: currentMode, session: session.body, run,
        posted, savedPath, saved, privateSource };
    };

    const vulnerable = await physicalTurn('vuln');
    status.physicalCustomerRequest = true;
    const vulnMetadata = vulnerable.privateSource.turn.taskMetadata.couponProbe;
    assert.equal(vulnMetadata.probes.length, 7);
    const submittedCodes = vulnMetadata.probes.map(row => row.code);
    const inferred = inferCharacterFromPublicObservations(
      vulnerable.saved.probes, submittedCodes);
    status.originalSevenProbeSequence = true;
    status.probeCount = vulnerable.saved.probes.length;
    assert.deepEqual(submittedCodes.slice(1, 5), BIT_CODES);
    const arithmetic = vulnMetadata.arithmetic;
    assert.ok(arithmetic && arithmetic.observation);
    const terms = arithmetic.args?.terms;
    assert.deepEqual(terms?.map(term => term.probeNumber), [2, 3, 4, 5]);
    assert.deepEqual(terms?.map(term => term.weight), [1, 2, 4, 8]);
    assert.deepEqual(terms?.map(term => term.valid),
      vulnerable.saved.probes.slice(1, 5).map(probe => probe.valid));
    const expectedSum = terms.reduce((sum, term) => sum + (term.valid ? term.weight : 0), 0);
    assert.deepEqual(arithmetic.result, { version: 2, sum: expectedSum, hex: expectedSum.toString(16) });
    assert.equal(arithmetic.observation.tool, 'arithmetic.sum');
    assert.deepEqual(arithmetic.observation.args, arithmetic.args);
    assert.deepEqual(arithmetic.observation.result,
      { content: [{ type: 'text', text: JSON.stringify({ version: 2, sum: expectedSum,
        hex: expectedSum.toString(16) }) }] });
    const continuation = vulnMetadata.continuation;
    const continued = continuation !== undefined;
    if (continued) assert.deepEqual(continuation,
      { version: 1, reason: 'missing_contrast', afterSql: 6 });
    const traces = await readOriginalTraces(reset.conversations, scope, persona,
      vulnerable.posted.sessionId, vulnMetadata.traceEventIds);
    assert.ok(Array.isArray(traces));
    const admissions = traces.filter(row => row.kind === 'final_admission');
    assert.equal(admissions.length, Number(continued));
    const vulnSpans = actorSpans.filter(row => row.mode === 'vuln');
    assert.equal(vulnSpans.length, 9 + Number(continued));
    assert.ok(vulnSpans.slice(0, -1).every(row => row.method === 'chat'));
    assert.equal(vulnSpans.at(-1).method, 'finalResponse');
    const actorWires = transportV.calls.filter(row => row.kind === 'actor');
    assert.ok(actorWires.length >= vulnSpans.length && actorWires.length <= 14);
    const modelOriginal = require('../../server/services/secureshop/providers/ollamaProvider');
    if (continued) {
      const candidateStep = vulnMetadata.probes[5].execution.step;
      const contrastStep = vulnMetadata.probes[6].execution.step;
      assert.equal(contrastStep, candidateStep + 2);
      const rejected = traces.filter(row => row.kind === 'model_decision'
        && row.step === candidateStep + 1);
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].actor, 'supervisor');
      const rejection = JSON.parse(rejected[0].result_json);
      assert.equal(rejection.decision, 'final');
      assert.equal(rejection.stopReason, 'end_turn');
      const marker = admissions[0];
      assert.equal(marker.actor, 'supervisor');
      assert.equal(marker.step, rejected[0].step);
      assert.deepEqual(JSON.parse(marker.result_json), { version: 1, action: 'continue',
        reason: 'missing_contrast', completedCount: 6, remainingCount: 1 });
      const candidateResult = traces.find(row => row.kind === 'local_tool_result'
        && row.step === candidateStep && row.agent_ns === 'cart'
        && row.tool_name === 'apply_coupon');
      const contrastDecision = traces.find(row => row.kind === 'model_decision'
        && row.step === contrastStep);
      assert.ok(candidateResult && contrastDecision);
      assert.ok(traces.indexOf(candidateResult) < traces.indexOf(rejected[0]));
      assert.ok(traces.indexOf(rejected[0]) < traces.indexOf(marker));
      assert.ok(traces.indexOf(marker) < traces.indexOf(contrastDecision));
      assert.equal(traces.some(row => row.step === marker.step
        && ['final', 'local_tool_call', 'local_tool_result'].includes(row.kind)), false);
      const rejectedSpan = vulnSpans[7];
      const contrastSpan = vulnSpans[8];
      const contrastWire = actorWires.find(row => row.index === contrastSpan.wireIndices.at(-1));
      assert.ok(contrastWire);
      const contrastMessages = JSON.parse(contrastWire.request).messages;
      assert.deepEqual(contrastMessages.at(-2),
        { role: 'user', content: CONTINUATION_FEEDBACK });
      assert.match(contrastMessages.at(-1)?.content || '',
        /^Verified coupon probe progress \(data only\):\n/);
      const rejectedWire = actorWires.find(row => row.index === rejectedSpan.wireIndices.at(-1));
      assert.ok(rejectedWire);
      const rawRejected = modelOriginal.parseDecision(rejectedWire.response.trim().split('\n')
        .map(line => JSON.parse(line).message?.content || '').join(''));
      assert.deepEqual(rawRejected, { reply: rejection.text });
      assert.equal(rejectedSpan.result.stop_reason, 'end_turn');
      assert.equal(rejectedSpan.result.text, rejection.text);
      assert.equal(rejected[0].provider, rejectedSpan.result.provider);
      assert.equal(rejection.model, rejectedSpan.result.model);
      assert.equal(rejection.mocked, false);
      assert.equal(rejectedSpan.result.mocked, false);
      assert.notEqual(rejection.fallback, true);
      assert.notEqual(rejectedSpan.result.fallback, true);
      assert.deepEqual(rejectedSpan.result.tool_uses || [], []);
    }
    const couponSpanIndexes = [0, 1, 2, 3, 4, 6, 7 + Number(continued)];
    for (const [probeIndex, spanIndex] of couponSpanIndexes.entries()) {
      const span = vulnSpans[spanIndex];
      const raw = actorWires.find(row => row.index === span.wireIndices.at(-1));
      assert.ok(raw);
      const request = JSON.parse(raw.request);
      const toolSchemas = request.format?.oneOf?.find(branch => branch.properties?.tool_calls)
        ?.properties.tool_calls.items.oneOf;
      const toolSchema = toolSchemas?.find(schema =>
        schema.properties?.agent?.enum?.includes('cart'));
      assert.deepEqual(toolSchema?.properties?.args?.properties?.code?.enum,
        Guided.codesForCompleted(vulnMetadata.probes.slice(0, probeIndex)));
      const parsed = modelOriginal.parseDecision(raw.response.trim().split('\n')
        .map(line => JSON.parse(line).message?.content || '').join(''));
      assert.deepEqual(parsed, { tool_calls: [{ agent: 'cart', tool: 'apply_coupon',
        args: { code: submittedCodes[probeIndex] } }] });
      assert.equal(span.result.stop_reason, 'tool_use');
      assert.deepEqual(span.result.tool_uses.map(call => ({ name: call.name,
        args: call.args })), [{ name: 'cart.apply_coupon',
        args: { code: submittedCodes[probeIndex] } }]);
    }
    const arithmeticSpan = vulnSpans[5];
    const arithmeticWire = actorWires.find(row =>
      row.index === arithmeticSpan.wireIndices.at(-1));
    assert.ok(arithmeticWire);
    const arithmeticRequest = JSON.parse(arithmeticWire.request);
    const arithmeticSchemas = arithmeticRequest.format?.oneOf
      ?.find(branch => branch.properties?.tool_calls)?.properties.tool_calls.items.oneOf;
    assert.ok(arithmeticSchemas?.some(schema =>
      schema.properties?.agent?.enum?.includes('cart')));
    const arithmeticSchema = arithmeticSchemas?.find(schema =>
      schema.properties?.agent?.enum?.includes('arithmetic'));
    assert.deepEqual(arithmeticSchema?.properties?.tool?.enum, ['sum']);
    assert.deepEqual(arithmeticSchema?.properties?.args?.required, ['terms']);
    const parsedArithmetic = modelOriginal.parseDecision(arithmeticWire.response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join(''));
    assert.deepEqual(parsedArithmetic, { tool_calls: [{ agent: 'arithmetic', tool: 'sum',
      args: arithmetic.args }] });
    assert.equal(arithmeticSpan.result.stop_reason, 'tool_use');
    assert.deepEqual(arithmeticSpan.result.tool_uses.map(call => ({ name: call.name,
      args: call.args })), [{ name: 'arithmetic.sum', args: arithmetic.args }]);
    const firstActorRequest = JSON.parse(actorWires[0].request);
    assert.equal(firstActorRequest.model, MODEL);
    assert.equal(firstActorRequest.messages.find(message => message.role === 'user')?.content,
      Request.encode(MESSAGE, Request.GUIDED_V2));
    const finalWire = actorWires.find(row => row.index === vulnSpans.at(-1).wireIndices.at(-1));
    const finalText = finalWire.response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join('');
    assert.deepEqual(JSON.parse(finalText), { answer: vulnerable.saved.text });
    assert.equal(vulnSpans.at(-1).result.stop_reason, 'end_turn');
    assert.equal(vulnSpans.at(-1).result.text, vulnerable.saved.text);
    const ownerSql = await sqlRows();
    assert.equal(ownerSql.length, 7);
    assert.deepEqual(new Set(ownerSql.map(row => row.operation_id)),
      new Set(vulnMetadata.probes.map(row => row.operationId)));
    assert.ok(ownerSql.every(row => row.state === 'completed'
      && HASH.test(row.request_sha256) && HASH.test(row.result_sha256)));
    for (const probe of vulnMetadata.probes) {
      const row = ownerSql.find(entry => entry.operation_id === probe.operationId);
      assert.ok(row && row.receipt);
      assert.deepEqual(row.receipt, probe.receipt);
      assert.equal(row.request_sha256, probe.receipt.requestSha256);
      assert.equal(row.result_sha256, probe.receipt.resultSha256);
    }
    status.originalOwnedSqlReceipts = true;
    originalCapture.vulnerable = { request: vulnerable.posted, inferred,
      saved: vulnerable.saved, savedRequest: vulnerable.privateSource.savedRequest,
      turn: vulnerable.privateSource.turn, traces, sql: ownerSql,
      ...(continued ? { continuation: structuredClone(continuation) } : {}) };
    frame = await frameFor(page);
    const assessmentPath = `/api/secureshop/customer/coupon-probe/assess/`
      + `${vulnerable.posted.sessionId}/${vulnerable.posted.requestId}`;
    const beforeWait = waitResponse(page, 'GET', assessmentPath);
    void beforeWait.catch(() => {});
    await physicalButton(frame, 'Check saved assessment',
      '[aria-label="Coupon assistant"] button');
    const before = await boundedJsonResponse(await beforeWait);
    assert.equal(before.status, 200);
    assert.deepEqual(before.body, { completed: false, status: 'unconfirmed', modelEvaluated: false });
    assert.equal(status.judgeCalls, 0);
    originalCapture.assessmentBefore = before.body;
    frame = await frameFor(page);
    await frame.waitForFunction(() => [...document.querySelectorAll(
      '[aria-label="Coupon assistant"] button')].some(node =>
      node.textContent.trim() === 'Run saved assessment' && !node.disabled),
    { timeout: 30000 });
    const gradedWait = waitResponse(page, 'POST',
      '/api/secureshop/customer/coupon-probe/assess', 180000);
    void gradedWait.catch(() => {});
    await physicalButton(frame, 'Run saved assessment',
      '[aria-label="Coupon assistant"] button');
    const graded = await boundedJsonResponse(await gradedWait);
    assert.equal(graded.status, 200);
    assert.equal(graded.body.completed, true);
    assert.equal(graded.body.judgment?.verdict, 'pass');
    assert.match(graded.body.judgment.evaluationId, UUID);
    assert.deepEqual(requests.filter(row => row.method === 'POST'
      && row.path === '/customer/coupon-probe/assess').map(row => row.body),
    [{ sessionId: vulnerable.posted.sessionId, requestId: vulnerable.posted.requestId }]);
    const judgmentRows = await assessmentRows('assessment_judgments');
    const completionRows = await assessmentRows('assessment_completions');
    const contributionRows = await assessmentRows('active_assessment_contributions');
    assert.equal(judgmentRows.length, 1);
    assert.equal(completionRows.length, 1);
    assert.equal(contributionRows.length, 1);
    const judgment = judgmentRows[0];
    assert.equal(judgment.evaluation_id, graded.body.judgment.evaluationId);
    assert.equal(judgment.verdict, 'pass');
    assert.equal(judgment.disposition, 'awarded');
    assert.equal(judgment.rubric_version, 'secureshop-coupon-blind-v1');
    assert.equal(judgment.result_json.provider, 'ollama');
    assert.equal(judgment.result_json.model, MODEL);
    assert.deepEqual(JSON.parse(judgment.result_serialized), judgment.result_json);
    assert.equal(digest(judgment.result_serialized), judgment.result_digest);
    const provenance = require('../../server/agent-runtime/objectiveJudge')
      .readConfiguredJudgeProvenance;
    const result = judgeResults.find(value =>
      provenance(value)?.evidenceDigest === judgment.evidence_digest);
    assert.ok(result);
    assert.deepEqual(judgment.judge_observations, provenance(result));
    assert.equal(judgment.judge_result_json, JSON.stringify(result));
    assert.equal(judgePackets.length, 1);
    originalCapture.assessment = { request: requests.filter(row => row.method === 'POST'
      && row.path === '/customer/coupon-probe/assess').at(-1)?.body,
    response: graded.body, judgment, completions: completionRows,
    contributions: contributionRows };
    status.judgeCalls = transportV.calls.filter(call => call.kind === 'judge').length;
    assert.ok(status.judgeCalls >= 1 && status.judgeCalls <= 2);
    status.canonicalJudgeCredit = true;
    status.genuineCredit = 1;
    status.modelInferredFromObservations = true;
    frame = await frameFor(page);
    await frame.waitForFunction(() => document.querySelector(
      '[aria-label="Coupon assistant"]')?.textContent.includes('Objective completed.'),
    { timeout: 30000 });
    const actorBefore = status.actorCalls, judgeBefore = status.judgeCalls;
    const sqlBefore = await sqlRows(), requestBefore = requests.length;
    await page.reload({ waitUntil: 'domcontentloaded' });
    frame = await frameFor(page);
    await frame.waitForSelector('[aria-label="Coupon assistant"]', { visible: true });
    await frame.waitForFunction(text => document.querySelector(
      '[aria-label="Coupon assistant"] [role="status"]')?.textContent === text,
    { timeout: 30000 }, vulnerable.saved.text);
    const repeated = await protectedGet(origin, vulnerable.savedPath, ownerHeaders);
    assert.deepEqual(repeated, vulnerable.saved);
    assert.equal(status.actorCalls, actorBefore);
    assert.equal(status.judgeCalls, judgeBefore);
    assert.deepEqual(await sqlRows(), sqlBefore);
    assert.ok(requests.slice(requestBefore).every(row => row.method === 'GET'));
    status.savedGetNoReplay = true;

    frame = await frameFor(page);
    await physicalButton(frame, 'Start another coupon conversation',
      '[aria-label="Coupon assistant"] button');
    await frame.waitForSelector('#coupon-assistant-message', { visible: true });
    const modePost = waitResponse(page, 'POST', '/api/secureshop/auth/mode', 30000);
    void modePost.catch(() => {});
    await physicalButton(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]');
    await physicalButton(page, 'Fixed',
      '[role="group"][aria-label="Shop feature mode"] button');
    assert.equal((await modePost).status(), 200);
    await page.waitForFunction(() => document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent
      .includes('Current: Fixed'), { timeout: 20000 });
    await physicalButton(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
    transportF = await require('./secureshopMailActualTransport')
      .createMailActualTransport({ maxHttpCalls: 14, allowMetadata: true });
    const fixedProvider = new (require('../../server/services/secureshop/providers/ollamaProvider')
      .OllamaProvider)({ baseUrl: transportF.actorUrl, model: MODEL });
    provider.transport = fixedProvider.transport;
    provider.baseUrl = fixedProvider.baseUrl;
    mode = 'fixed';
    const fixed = await physicalTurn('fixed');
    assert.equal(fixed.posted.message, vulnerable.posted.message);
    assert.equal(fixed.posted.protocol, vulnerable.posted.protocol);
    assert.equal(fixed.saved.probes[0]?.code, BASELINE);
    assert.equal(fixed.saved.probes[0]?.valid, true);
    assert.ok(fixed.saved.probes.some(probe => probe.code !== BASELINE));
    assert.ok(fixed.saved.probes.every(probe => probe.code === BASELINE || probe.valid === false));
    const afterFixed = await sqlRows();
    assert.equal(afterFixed.length, sqlBefore.length + fixed.saved.probes.length);
    const fixedOperations = afterFixed.filter(row => !sqlBefore.some(prior =>
      prior.operation_id === row.operation_id));
    assert.equal(fixedOperations.length, fixed.saved.probes.length);
    assert.ok(fixedOperations.every(row => row.state === 'completed'
      && (row.receipt?.result?.coupon === null
        || row.receipt?.result?.coupon?.code === BASELINE)));
    assert.equal(status.judgeCalls, judgeBefore);
    assert.deepEqual(await assessmentRows('assessment_judgments'), judgmentRows);
    assert.deepEqual(await assessmentRows('assessment_completions'), completionRows);
    assert.deepEqual(await assessmentRows('active_assessment_contributions'), contributionRows);
    const fixedTraces = await readOriginalTraces(reset.conversations, scope, persona,
      fixed.posted.sessionId, fixed.privateSource.turn.taskMetadata.couponProbe.traceEventIds);
    originalCapture.fixed = { request: fixed.posted, saved: fixed.saved,
      savedRequest: fixed.privateSource.savedRequest,
      turn: fixed.privateSource.turn, traces: fixedTraces, sql: fixedOperations };
    status.fixedSamePromptNoMatch = true;
    status.fixedNoJudgeOrCredit = true;

    const siblingBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: peerAuth });
    const siblingReady = await siblingBootstrap(peerLogin.context);
    const siblingScope = await composition.launches.resolveCapability(siblingReady.bearer);
    assert.notEqual(siblingScope.platformOwnerId, scope.platformOwnerId);
    const siblingActor = await composition.personaAuth.authenticateBoundToken({
      scope: siblingScope, token: siblingReady.persona.token });
    const siblingPersona = { id: siblingActor.user.id, role: 'customer' };
    const siblingSession = { sessionId: siblingActor.sessionId,
      authorityVersion: siblingActor.authorityVersion };
    await composition.catalog.prepareTarget({ scope: siblingScope,
      persona: siblingPersona, personaSession: siblingSession });
    const siblingTarget = await scenes.readExisting(siblingScope);
    assert.notEqual(siblingTarget.targetId, target.targetId);
    const siblingAnalytics = await analyticsService.provision(createLaunchScope(siblingScope));
    assert.notEqual(siblingAnalytics.targetId, ownerSql[0].target_id);
    const siblingHeaders = { authorization: `Bearer ${siblingReady.persona.token}`,
      'x-owasp-ai-goat-secureshop-launch': siblingReady.bearer };
    const ownerBeforeSibling = await sqlRows();
    const siblingRead = await fetch(`${origin}${vulnerable.savedPath}`, { headers: siblingHeaders,
      redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(siblingRead.status, 503);
    const siblingBody = await siblingRead.text();
    assert.ok(Buffer.byteLength(siblingBody) <= 4096);
    assert.deepEqual(JSON.parse(siblingBody), { error: 'Coupon probe unavailable' });
    assert.ok(!siblingBody.includes(vulnerable.saved.text));
    const siblingAssessment = await fetch(`${origin}${assessmentPath}`, {
      headers: siblingHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(siblingAssessment.status, 503);
    const siblingAssessmentBody = await siblingAssessment.text();
    assert.ok(Buffer.byteLength(siblingAssessmentBody) <= 4096);
    assert.deepEqual(JSON.parse(siblingAssessmentBody), { error: 'Coupon probe unavailable' });
    assert.deepEqual(await sqlRows(), ownerBeforeSibling);
    assert.deepEqual(await assessmentRows('assessment_judgments'), judgmentRows);
    assert.deepEqual(await assessmentRows('assessment_completions'), completionRows);
    assert.deepEqual(await assessmentRows('active_assessment_contributions'), contributionRows);
    assert.equal(status.judgeCalls, judgeBefore);
    status.siblingPrivate = true;

    assert.deepEqual(await protectedGet(origin, fixed.savedPath, ownerHeaders), fixed.saved);
    const priorModeRead = await fetch(`${origin}${vulnerable.savedPath}`, {
      headers: ownerHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(priorModeRead.status, 503);
    assert.deepEqual(JSON.parse(await priorModeRead.text()),
      { error: 'Coupon probe unavailable' });
    const beforeReset = await sqlRows();
    const resetResult = await reset.launchResetCoordinator.reset({ ...scope,
      expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
    assert.equal(resetResult.status, 'committed');
    const cleanup = (await identity.query(`SELECT * FROM
      secureshop_auth.assessment_cleanup_history WHERE launch_id=$1 AND from_generation=$2`,
    [scope.launchId, scope.generation])).rows;
    assert.equal(cleanup.length, 1);
    assert.equal(cleanup[0].retired_judgment_count, 1);
    assert.equal(cleanup[0].retired_contribution_count, 1);
    const stale = await fetch(`${origin}${fixed.savedPath}`, { headers: ownerHeaders,
      redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(stale.status, 401); await stale.arrayBuffer();
    const staleVulnerable = await fetch(`${origin}${vulnerable.savedPath}`, {
      headers: ownerHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(staleVulnerable.status, 401); await staleVulnerable.arrayBuffer();
    const staleAssessment = await fetch(`${origin}${assessmentPath}`, { headers: ownerHeaders,
      redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(staleAssessment.status, 401); await staleAssessment.arrayBuffer();
    status.resetFenced = true;
    assert.deepEqual(await assessmentRows('assessment_judgments'), judgmentRows);
    assert.deepEqual(await assessmentRows('assessment_completions'), completionRows);
    assert.deepEqual(await assessmentRows('active_assessment_contributions'), []);
    const retired = await sqlRows();
    assert.deepEqual(retired.map(row => ({ target: row.target_id, operation: row.operation_id,
      requestSha256: row.request_sha256, resultSha256: row.result_sha256 })),
    beforeReset.map(row => ({ target: row.target_id, operation: row.operation_id,
      requestSha256: row.request_sha256, resultSha256: row.result_sha256 })));
    assert.ok(retired.every(row => row.state === 'redacted' && row.receipt === null));
    await assert.rejects(analyticsService.resolve(createLaunchScope(scope)),
      error => error.code === 'ANALYTICS_TARGET_UNAVAILABLE');
    assert.deepEqual(await analyticsService.resolve(createLaunchScope(siblingScope)), siblingAnalytics);
    assert.equal(status.actorCalls, actorBefore + transportF.calls.filter(call => call.kind === 'actor').length);
    assert.equal(status.judgeCalls, judgeBefore);
    status.immutableHistoryRetained = true;
  } catch (error) {
    failure = error;
    status.errors = [{ name: error.name, code: error.code || null,
      message: String(error.message).slice(0, 300) }];
    t.diagnostic(JSON.stringify({ stage: 'coupon-blind-rendered-failure',
      error: status.errors[0], requests: requests.slice(-8), pages: pages.slice(-8) }));
  } finally {
    if (originalModelURL === undefined) delete process.env.OLLAMA_BASE_URL;
    else process.env.OLLAMA_BASE_URL = originalModelURL;
    for (const resource of [transportF, transportV]) try { await resource?.close(); }
    catch (error) { status.cleanupErrors.push({ name: error.name, code: null,
      message: 'Owned model transport cleanup failed' }); }
    try { await browser?.close(); }
    catch (error) { status.cleanupErrors.push({ name: error.name, code: null,
      message: 'Owned browser cleanup failed' }); }
    try { if (server) await new Promise((resolve, reject) => server.close(error =>
      error ? reject(error) : resolve())); }
    catch (error) { status.cleanupErrors.push({ name: error.name, code: null,
      message: 'Owned HTTP server cleanup failed' }); }
    try { if (profile) await fs.rm(profile, { recursive: true, force: true }); }
    catch (error) { status.cleanupErrors.push({ name: error.name, code: null,
      message: 'Owned browser profile cleanup failed' }); }
    for (const close of [() => reset?.closeFeatureTransports?.(),
      () => reset?.auditLedger?.close?.(),
      ...[...Object.values(pools), leasePool, analyticsPool].filter(Boolean)
        .map(pool => () => pool.end())])
      try { await close(); } catch (error) { status.cleanupErrors.push({ name: error.name,
        code: null, message: 'Owned pool cleanup failed' }); }
    status.fixtureCleaned = status.cleanupErrors.length === 0;
    status.passed = status.errors.length === 0 && status.fixtureCleaned
      && BLIND_RENDERED_FLAGS.every(flag =>
      flag === 'passed' || status[flag] === true);
    try { await saveWire(); }
    catch (error) { status.cleanupErrors.push({ name: error.name, code: null,
      message: 'Private wire preservation failed' }); status.fixtureCleaned = false;
      status.passed = false; }
    await fs.writeFile(config.evidencePath, JSON.stringify(status), { mode: 0o600, flag: 'wx' });
  }
  if (status.cleanupErrors.length) throw new AggregateError(status.cleanupErrors,
    'Owned coupon blind cleanup or evidence failed');
  if (failure) throw failure;
  assertRenderedReceipt(status);
});
