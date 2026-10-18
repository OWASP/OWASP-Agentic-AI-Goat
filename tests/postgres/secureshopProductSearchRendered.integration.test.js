'use strict';

// Opted, disposable V53 browser qualification. The fixture never reads the
// private target value before the physical learner turn and assessment.
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
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { SEARCH, MESSAGE, FLAGS, SCOPE, originalUnion, assertSearchProof,
  assertActorBudget, fixedActorTransportLimit,
  assertRenderedReceipt, waitForRunOrRenderedError, waitForClearedProductSearch,
  observeProductSearchApplication } =
  require('../fixtures/secureshopProductSearchRenderedQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_PRODUCT_SEARCH_BROWSER_';
const GATE = 'SECURESHOP_PRODUCT_SEARCH_BROWSER_NATIVE';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const OBJECTIVE = 'ss_sqli_union';
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const TITLE = 'customer physically obtains a protected synthetic value through original product-search UNION and canonical Judge proof';
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
  assert.equal(path.resolve(env.DVAIA_CURRENT_MAIN_WORKSPACE || ''), ROOT);
  assert.equal(process.cwd(), ROOT);
  const evidencePath = env.SECURESHOP_PRODUCT_SEARCH_BROWSER_EVIDENCE_PATH;
  const recordPath = env.SECURESHOP_PRODUCT_SEARCH_BROWSER_RECORD_PATH;
  const build = env.SECURESHOP_PRODUCT_SEARCH_BROWSER_BUILD;
  const browser = env.PUPPETEER_EXECUTABLE_PATH;
  assert.ok([evidencePath, recordPath, build, browser].every(item => path.isAbsolute(item || '')));
  assert.equal(path.dirname(evidencePath), path.dirname(recordPath));
  assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
  assert.equal(path.resolve(build), path.join(ROOT, 'client/build'));
  assert.match(env.SECURESHOP_PRODUCT_SEARCH_BROWSER_SHA256 || '', HASH);
  assert.match(env.SECURESHOP_PRODUCT_SEARCH_BROWSER_MODEL_DIGEST || '', HASH);
  assert.equal(env.SECURESHOP_PRODUCT_SEARCH_BROWSER_MODEL_DIGEST, MODEL_DIGEST);
  const urls = {}; let nonce, port;
  for (const [store, name] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(env[`${PREFIX}${store}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = /^\/dvaia_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
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
    kind: 'product_search_browser', pid, startTime,
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

function waitResponse(page, method, pathname, timeout = 90000) {
  return page.waitForResponse(response => response.request().method() === method
    && new URL(response.url()).pathname === pathname, { timeout });
}

function headersFrom(request) {
  const headers = request.headers();
  assert.match(headers.authorization || '', /^Bearer [A-Za-z0-9_.-]+$/);
  assert.match(headers['x-dvaia-secureshop-launch'] || '', /^[A-Za-z0-9_-]{43}$/);
  return { authorization: headers.authorization,
    'x-dvaia-secureshop-launch': headers['x-dvaia-secureshop-launch'] };
}

async function protectedGet(origin, pathname, headers, status = 200) {
  const response = await fetch(`${origin}${pathname}`, { headers,
    redirect: 'error', signal: AbortSignal.timeout(10000) });
  assert.equal(response.status, status);
  const raw = await response.text(); assert.ok(Buffer.byteLength(raw) <= 131072);
  return JSON.parse(raw);
}

async function boundedJsonResponse(response, maxBytes = 131072) {
  const status = response.status();
  let timer;
  const body = response.text();
  const raw = status === 200 ? await body : await Promise.race([
    body,
    new Promise((_, reject) => { timer = setTimeout(() =>
      reject(Error(`Original browser HTTP ${status} body unavailable`)), 5000); }),
  ]).finally(() => clearTimeout(timer));
  assert.ok(Buffer.byteLength(raw) <= maxBytes);
  assert.match(response.headers()['content-type'] || '', /^application\/json(?:;|$)/i);
  return { status, raw, sha256: digest(raw), body: JSON.parse(raw) };
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

module.exports.observeOriginalRunResponse = observeOriginalRunResponse;
module.exports.boundedJsonResponse = boundedJsonResponse;

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
  const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: SCOPE, actorCalls: 0, judgeCalls: 0,
    roleTurns: 0, searchCount: 0, genuineCreditCount: 0, errors: [], cleanupErrors: [] });
  let analyticsPool, server, browser, profile, transportV, transportF, reset, failure;
  const originalModelURL = process.env.OLLAMA_BASE_URL;
  const requests = [], pages = [], actorSpans = [], judgePackets = [], judgeResults = [];
  const originalCapture = { runResponses: [] };
  const applicationFailures = [];
  const wirePath = path.join(path.dirname(config.evidencePath), 'product-search-original-wire.json');
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
    const analyticsDatabase = `dvaia_analytics_control_${ownerToken}`;
    const analyticsCluster = `dvaia-owned-analytics-${ownerToken}`;
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
    const suffix = randomUUID().slice(0, 8), username = `search_browser_${suffix}`;
    const password = 'disposable-search-browser-only';
    const owner = await auth.register({ username, password,
      email: `${username}@owned.invalid`, role: 'customer' });
    const peer = await auth.register({ username: `search_peer_${suffix}`, password,
      email: `search-peer-${suffix}@owned.invalid`, role: 'customer' });
    const peerMerchant = await auth.register({ username: `search_merchant_${suffix}`, password,
      email: `search-merchant-${suffix}@owned.invalid`, role: 'merchant' });
    const ownerTenant = await auth.establishTenantContext(owner.context);
    const peerTenantId = randomUUID(), peerSlug = `search_peer_tenant_${suffix}`;
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
    assert.equal(require('../../server/config/secureshopCurriculum').OBJECTIVES
      .find(row => row.id === OBJECTIVE)?.qualification, 'pending');
    assert.equal(objective?.qualification, 'pending');
    assert.equal(objective.enabled, false);
    const enable = { objectiveId: OBJECTIVE, enabled: true,
      expectedRevision: objective.revision };
    await assert.rejects(assessmentCatalog.set(administrator.context, enable),
      { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
    const admitted = await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.assessment_objectives
      SET qualification='native-model' WHERE objective_id=$1 AND qualification='pending'
        AND is_enabled=false AND catalog_active=true
        AND configuration_source='checked_in_default'
        AND source_document->>'qualification'='pending'
      RETURNING objective_id,qualification,is_enabled`, [OBJECTIVE]);
    assert.equal(admitted.rowCount, 1);
    assert.deepEqual(admitted.rows, [{ objective_id: OBJECTIVE,
      qualification: 'native-model', is_enabled: false }]);
    const candidate = (await assessmentCatalog.list(administrator.context)).objectives
      .find(row => row.objectiveId === OBJECTIVE);
    assert.equal(candidate.qualification, 'native-model');
    assert.equal(candidate.enabled, false);
    assert.equal(candidate.revision, objective.revision);
    status.fixtureLocalCandidateAdmission = true;
    t.diagnostic('Fixture-local admission in an owned disposable identity store; checked-in objective remains pending');
    assert.equal((await assessmentCatalog.set(administrator.context,
      enable)).enabled, true);
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
      .createMailActualTransport({ maxHttpCalls: 6, allowMetadata: true });
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
        assertActorBudget(++actorRuns, status.judgeCalls);
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
        assertActorBudget(status.actorCalls, status.judgeCalls);
        return result;
      };
    }
    const couponDependencies = await require('../../server/services/secureshopCouponProduction')
      .prepareCommerceDependencies({ modeAuthority, reviewPool: review,
        launches: reset.launches, mode: 'vuln' });
    const productSearchDependencies = await require('../../server/services/secureshopProductSearchProduction')
      .prepareProductSearchDependencies({ runtime: analyticsRuntime,
        lifecycle: analyticsLifecycle });
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
    const applicationModule = require('../../server/services/secureshopProductSearchApplication');
    const productCompositionPath = require.resolve('../../server/services/secureshopProductSearchComposition');
    assert.equal(require.cache[productCompositionPath], undefined,
      'Product-search application factory must be observed before router construction');
    const originalFactory = applicationModule.createProductSearchApplication;
    applicationModule.createProductSearchApplication = options =>
      observeProductSearchApplication(originalFactory(options), applicationFailures, () => mode);
    let composition;
    try { composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, couponDependencies,
        productSearchDependencies, toolPolicyRepository,
        personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
          .activationPolicy(process.env).requested,
        promptPolicyRepository,
        // Product search uses durable run-snapshot admission. Admin policy
        // rendering is outside this customer cohort and fails closed.
        promptPolicyRenderer: { render() { throw Error('Policy rendering is outside product-search qualification'); } },
        fixtures: [], requiredObjectives: [OBJECTIVE], judge,
        jwtSecret: 'owned-search-browser-persona-secret-at-least-32-bytes',
        agentRuntime: { provider } }); }
    finally { applicationModule.createProductSearchApplication = originalFactory; }
    await composition.repositories.personas.ensureTemplates();
    assert.equal(composition.productSearch?.ready, true);
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
        reviewPool: review, commercePool: commerce });
    const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
      .createRegisteredAdminResetEnvelope({ activeKeyId: 'search-owned',
        keys: new Map([['search-owned', randomBytes(32)]]) });
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
      if (request.path.startsWith('/customer/product-search/')) {
        assert.ok(requests.length < 48);
        requests.push({ method: request.method, path: request.path,
          body: request.method === 'POST' ? structuredClone(request.body) : null });
        if (request.method === 'POST' && request.path === '/customer/product-search/run')
          { assert.ok(++status.roleTurns <= 2, 'exactly two physical product-search turns');
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
      response.status(404).json({ error: 'Outside product-search qualification' }));
    app.use(express.static(config.build, { setHeaders: response =>
      response.set('Access-Control-Allow-Origin', '*') }));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: config.build }));
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-product-search-browser-'));
    browser = await require('puppeteer').launch({ headless: true,
      userDataDir: profile, executablePath: config.browser });
    await recordBrowser(browser, config.recordPath, config.browser,
      process.env.SECURESHOP_PRODUCT_SEARCH_BROWSER_SHA256);
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
      ownerHeaders['x-dvaia-secureshop-launch']);
    const actor = await composition.personaAuth.authenticateBoundToken({ scope,
      token: ownerHeaders.authorization.slice('Bearer '.length) });
    const persona = { id: actor.user.id, role: 'customer' };
    const personaSession = { sessionId: actor.sessionId,
      authorityVersion: actor.authorityVersion };
    const ownerPrincipal = await auth.establishTenantContext(
      await auth.authenticate((await page.cookies(`${origin}/api/secureshop/auth/session`))
        .find(cookie => cookie.name === 'dvaia_shop_session').value));
    assert.equal(ownerPrincipal.ownerId, ownerTenant.ownerId);
    await composition.catalog.prepareTarget({ scope, persona, personaSession });
    const target = await scenes.readExisting(scope);
    assert.ok(target?.targetId);
    let frame = await frameFor(page);
    await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
    const capability = waitResponse(page, 'GET',
      '/api/secureshop/customer/product-search/capabilities', 30000);
    void capability.catch(() => {});
    await frame.select('select[id^="agent-lane-task-customer-"]', 'product-search-lesson');
    frame = await frameFor(page);
    await frame.waitForSelector('[aria-label="Product search lesson"]', { visible: true });
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
      const panel = '[aria-label="Product search lesson"]';
      const textarea = await frame.waitForSelector(`${panel} textarea`, { visible: true });
      await textarea.type(MESSAGE);
      const sessionWait = waitResponse(page, 'POST', '/api/secureshop/customer/product-search/session');
      const runWait = waitResponse(page, 'POST', '/api/secureshop/customer/product-search/run', 180000);
      void sessionWait.catch(() => {}); void runWait.catch(() => {});
      await physicalButton(frame, 'Ask product-search agent', `${panel} button`);
      const session = await boundedJsonResponse(await sessionWait);
      assert.equal(session.status, 200);
      assert.deepEqual(Object.keys(session.body), ['sessionId']);
      assert.match(session.body.sessionId, UUID);
      const run = await boundedJsonResponse(
        await waitForRunOrRenderedError(frame, runWait), 512 * 1024);
      assert.equal(run.status, 200);
      const posted = requests.filter(row => row.method === 'POST'
        && row.path === '/customer/product-search/run').at(-1)?.body;
      assert.ok(posted && posted.sessionId === session.body.sessionId
        && UUID.test(posted.requestId) && posted.message === MESSAGE);
      assert.deepEqual(JSON.parse((await runWait).request().postData()), posted);
      assert.equal(run.body.status, 'completed');
      assert.equal(run.body.sessionId, posted.sessionId);
      assert.equal(run.body.requestId, posted.requestId);
      assert.equal(run.body.stopReason, 'end_turn');
      assert.equal(run.body.provider, 'ollama'); assert.equal(run.body.model, MODEL);
      const savedPath = `/api/secureshop/customer/product-search/operations/${posted.sessionId}/${posted.requestId}`;
      const saved = await protectedGet(origin, savedPath, ownerHeaders);
      assert.deepEqual(saved, { ...run.body, replayed: true });
      assert.ok(saved.searches.length >= 1);
      assert.ok(saved.searches.length <= (currentMode === 'vuln' ? 1 : 5));
      frame = await frameFor(page);
      await frame.waitForFunction(text => document.querySelector(
        '[aria-label="Product-search lesson result"]')?.textContent.includes(text),
      { timeout: 30000 }, saved.text);
      const privateSource = await composition.productSearch.application.readSavedSource(
        ownerContext, { sessionId: posted.sessionId, requestId: posted.requestId });
      assert.equal(privateSource.savedRequest.message, MESSAGE);
      assert.equal(privateSource.turn.text, saved.text);
      assert.equal(privateSource.turn.stopReason, 'end_turn');
      const metadata = privateSource.turn.taskMetadata.productSearch;
      assert.equal(metadata.sourceBinding.searchMode.mode, currentMode);
      assert.equal(metadata.searches.length, saved.searches.length);
      const search = metadata.searches[0];
      for (const selectedSearch of metadata.searches) {
        originalUnion(selectedSearch.search.query);
        assert.deepEqual(selectedSearch.search.filters, {});
        assert.equal(selectedSearch.search.query, selectedSearch.args.query);
        assert.equal(selectedSearch.receipt.operationId, selectedSearch.operationId);
        assert.equal(selectedSearch.receipt.scope.launchId, scope.launchId);
      }
      return { mode: currentMode, session: session.body, run, posted,
        savedPath, saved, privateSource, metadata, search,
        searches: metadata.searches };
    };

    const vulnerable = await physicalTurn('vuln');
    status.physicalCustomerRequest = true;
    status.searchCount = vulnerable.saved.searches.length;
    const vulnSpans = actorSpans.filter(row => row.mode === 'vuln');
    assert.equal(vulnSpans.length, 2);
    assert.ok(vulnSpans.every(row => row.method === 'chat'));
    const actorWires = transportV.calls.filter(row => row.kind === 'actor');
    assert.ok(actorWires.length >= 2 && actorWires.length <= 4);
    const modelOriginal = require('../../server/services/secureshop/providers/ollamaProvider');
    const selectedWire = actorWires.find(row => row.index === vulnSpans[0].wireIndices.at(-1));
    assert.ok(selectedWire);
    const selected = modelOriginal.parseDecision(selectedWire.response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join(''));
    assert.deepEqual(selected, { tool_calls: [{ agent: 'product-search', tool: 'search',
      args: vulnerable.search.args }] });
    assert.deepEqual(vulnSpans[0].result.tool_uses.map(call => ({ name: call.name,
      args: call.args })), [{ name: 'product-search.search', args: vulnerable.search.args }]);
    const firstActorRequest = JSON.parse(actorWires[0].request);
    assert.equal(firstActorRequest.model, MODEL);
    assert.ok(firstActorRequest.messages.some(message =>
      message.role === 'user' && message.content === MESSAGE));
    const finalWire = actorWires.find(row => row.index === vulnSpans[1].wireIndices.at(-1));
    assert.ok(finalWire);
    const parsedFinal = modelOriginal.parseDecision(finalWire.response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join(''));
    assert.deepEqual(parsedFinal, { reply: vulnerable.saved.text });
    assert.equal(vulnSpans[1].result.stop_reason, 'end_turn');
    status.modelSelectedUnion = true;
    const sqlBefore = await sqlRows();
    assert.equal(sqlBefore.length, 1);
    const sql = sqlBefore[0];
    assert.equal(sql.operation_id, vulnerable.search.operationId);
    assert.equal(sql.state, 'completed');
    assert.equal(sql.request_sha256, vulnerable.search.receipt.requestSha256);
    assert.equal(sql.result_sha256, vulnerable.search.receipt.resultSha256);
    assert.deepEqual(sql.receipt, vulnerable.search.receipt);
    assert.deepEqual(vulnerable.saved.searches[0],
      require('../../server/services/secureshopBoundProductSearchGraph')
        .publicObservation(vulnerable.search.search, sql.receipt));
    const privateReference = await analyticsService.readProductSearchReference({
      scope: createLaunchScope(scope), targetId: vulnerable.search.receipt.targetId,
      operationId: vulnerable.search.operationId,
      requestSha256: vulnerable.search.receipt.requestSha256 });
    assertSearchProof({ submitted: vulnerable.search.search.query,
      publicResult: vulnerable.saved.searches[0], privateReceipt: sql.receipt,
      reference: privateReference, mode: 'vuln', disclosedText: vulnerable.saved.text });
    status.originalOwnedSqlReceipt = true;
    status.privateReferenceMatched = true;
    status.modelDisclosedObservedValue = true;
    const sourceReader = require('../../server/database/postgres/secureshopProductUnionEvidenceRepository')
      .createProductUnionEvidenceRepository({ identityPool: identity,
        conversationRepository: reset.conversations,
        readSavedSource: (context, selectors) =>
          composition.productSearch.application.readSavedSource(context, selectors),
        readProductSearchReceipt: (selectors, options) =>
          analyticsService.readProductSearchReceipt(selectors, options),
        readProductSearchReference: (selectors, options) =>
          analyticsService.readProductSearchReference(selectors, options) });
    const original = await sourceReader.readSource(ownerContext,
      { sessionId: vulnerable.posted.sessionId, requestId: vulnerable.posted.requestId });
    assert.deepEqual(original.privateReference, privateReference);
    assert.equal(original.source.turn.text, vulnerable.saved.text);
    assert.equal(original.source.searches.length, 1);
    originalCapture.vulnerable = { request: vulnerable.posted,
      saved: vulnerable.saved, savedRequest: vulnerable.privateSource.savedRequest,
      turn: vulnerable.privateSource.turn, source: original.source,
      sql: sqlBefore, privateReference };

    frame = await frameFor(page);
    const assessmentPath = `/api/secureshop/customer/product-search/assess/`
      + `${vulnerable.posted.sessionId}/${vulnerable.posted.requestId}`;
    const beforeWait = waitResponse(page, 'GET', assessmentPath);
    void beforeWait.catch(() => {});
    await physicalButton(frame, 'Check saved assessment',
      '[aria-label="Product search lesson"] button');
    const before = await boundedJsonResponse(await beforeWait);
    assert.equal(before.status, 200);
    assert.deepEqual(before.body, { completed: false, status: 'unconfirmed', modelEvaluated: false });
    assert.equal(status.judgeCalls, 0);
    originalCapture.assessmentBefore = before.body;
    frame = await frameFor(page);
    await frame.waitForFunction(() => [...document.querySelectorAll(
      '[aria-label="Product search lesson"] button')].some(node =>
      node.textContent.trim() === 'Assess saved search' && !node.disabled),
    { timeout: 30000 });
    const gradedWait = waitResponse(page, 'POST',
      '/api/secureshop/customer/product-search/assess', 180000);
    void gradedWait.catch(() => {});
    await physicalButton(frame, 'Assess saved search',
      '[aria-label="Product search lesson"] button');
    const graded = await boundedJsonResponse(await gradedWait);
    assert.equal(graded.status, 200);
    assert.equal(graded.body.completed, true);
    assert.equal(graded.body.judgment?.verdict, 'pass');
    assert.match(graded.body.judgment.evaluationId, UUID);
    assert.deepEqual(requests.filter(row => row.method === 'POST'
      && row.path === '/customer/product-search/assess').map(row => row.body),
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
    assert.equal(judgment.rubric_version, 'secureshop-product-union-v1');
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
    status.judgeCalls = transportV.calls.filter(call => call.kind === 'judge').length;
    assert.ok(status.judgeCalls >= 1 && status.judgeCalls <= 2);
    status.canonicalJudgePass = true;
    status.genuineCredit = true;
    status.genuineCreditCount = 1;
    originalCapture.assessment = { request: requests.filter(row => row.method === 'POST'
      && row.path === '/customer/product-search/assess').at(-1)?.body,
      response: graded.body, judgment, completions: completionRows,
      contributions: contributionRows, judgePackets, judgeResults };

    const actorBefore = status.actorCalls, judgeBefore = status.judgeCalls;
    const requestBefore = requests.length;
    await page.reload({ waitUntil: 'domcontentloaded' });
    frame = await frameFor(page);
    await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
    await frame.select('select[id^="agent-lane-task-customer-"]', 'product-search-lesson');
    await frame.waitForFunction(text => document.querySelector(
      '[aria-label="Product-search lesson result"]')?.textContent.includes(text),
    { timeout: 30000 }, vulnerable.saved.text);
    const repeated = await protectedGet(origin, vulnerable.savedPath, ownerHeaders);
    assert.deepEqual(repeated, vulnerable.saved);
    assert.equal(status.actorCalls, actorBefore);
    assert.equal(status.judgeCalls, judgeBefore);
    assert.deepEqual(await sqlRows(), sqlBefore);
    assert.ok(requests.slice(requestBefore).every(row => row.method === 'GET'));
    status.savedGetNoReplay = true;

    frame = await frameFor(page);
    await physicalButton(frame, 'Start another search',
      '[aria-label="Product search lesson"] button');
    await waitForClearedProductSearch(frame);
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
      .createMailActualTransport({ maxHttpCalls: fixedActorTransportLimit(status.actorCalls),
        allowMetadata: true });
    const fixedProvider = new (require('../../server/services/secureshop/providers/ollamaProvider')
      .OllamaProvider)({ baseUrl: transportF.actorUrl, model: MODEL });
    provider.transport = fixedProvider.transport;
    provider.baseUrl = fixedProvider.baseUrl;
    mode = 'fixed';
    const fixed = await physicalTurn('fixed');
    assert.equal(fixed.posted.message, vulnerable.posted.message);
    assert.ok(fixed.searches.length >= 1 && fixed.searches.length <= 5);
    assert.equal(new Set(fixed.searches.map(search => search.operationId)).size,
      fixed.searches.length);
    const afterFixed = await sqlRows();
    assert.equal(afterFixed.length, sqlBefore.length + fixed.searches.length);
    const fixedSql = fixed.searches.map((search, index) => {
      assert.equal(search.search.query, vulnerable.search.search.query);
      const row = afterFixed.find(candidate => candidate.operation_id === search.operationId);
      assert.ok(row && row.state === 'completed');
      assert.deepEqual(row.receipt, search.receipt);
      const expected = require('../../server/services/secureshopBoundProductSearchGraph')
        .publicObservation(search.search, row.receipt);
      assert.deepEqual(fixed.saved.searches[index], expected);
      assertSearchProof({ submitted: search.search.query,
        publicResult: fixed.saved.searches[index], privateReceipt: row.receipt,
        protectedValue: privateReference.value, mode: 'fixed',
        disclosedText: fixed.saved.text });
      return row;
    });
    assert.deepEqual(afterFixed.filter(row => row.operation_id !== sqlBefore[0].operation_id)
      .map(row => row.operation_id).sort(), fixedSql.map(row => row.operation_id).sort());
    assert.equal(status.judgeCalls, judgeBefore);
    assert.deepEqual(await assessmentRows('assessment_judgments'), judgmentRows);
    assert.deepEqual(await assessmentRows('assessment_completions'), completionRows);
    assert.deepEqual(await assessmentRows('active_assessment_contributions'), contributionRows);
    originalCapture.fixed = { request: fixed.posted, saved: fixed.saved,
      savedRequest: fixed.privateSource.savedRequest,
      turn: fixed.privateSource.turn, sql: fixedSql };
    status.fixedSamePromptNoDisclosure = true;
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
    assert.notEqual(siblingAnalytics.targetId, sqlBefore[0].target_id);
    const siblingHeaders = { authorization: `Bearer ${siblingReady.persona.token}`,
      'x-dvaia-secureshop-launch': siblingReady.bearer };
    const ownerBeforeSibling = await sqlRows();
    const siblingRead = await fetch(`${origin}${vulnerable.savedPath}`, { headers: siblingHeaders,
      redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(siblingRead.status, 503);
    const siblingBody = await siblingRead.text();
    assert.ok(Buffer.byteLength(siblingBody) <= 4096);
    assert.deepEqual(JSON.parse(siblingBody), { error: 'Product search unavailable' });
    assert.ok(!siblingBody.includes(privateReference.value));
    const siblingAssessment = await fetch(`${origin}${assessmentPath}`, {
      headers: siblingHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(siblingAssessment.status, 503);
    const siblingAssessmentBody = await siblingAssessment.text();
    assert.ok(Buffer.byteLength(siblingAssessmentBody) <= 4096);
    assert.deepEqual(JSON.parse(siblingAssessmentBody), { error: 'Product search unavailable' });
    assert.deepEqual(await sqlRows(), ownerBeforeSibling);
    assert.equal(status.judgeCalls, judgeBefore);
    status.siblingPrivate = true;

    assert.deepEqual(await protectedGet(origin, fixed.savedPath, ownerHeaders), fixed.saved);
    const priorModeRead = await fetch(`${origin}${vulnerable.savedPath}`, {
      headers: ownerHeaders, redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(priorModeRead.status, 503);
    assert.deepEqual(JSON.parse(await priorModeRead.text()),
      { error: 'Product search unavailable' });
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
    for (const pathname of [fixed.savedPath, vulnerable.savedPath, assessmentPath]) {
      const stale = await fetch(`${origin}${pathname}`, { headers: ownerHeaders,
        redirect: 'error', signal: AbortSignal.timeout(10000) });
      assert.equal(stale.status, 401); await stale.arrayBuffer();
    }
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
    t.diagnostic(JSON.stringify({ stage: 'product-search-rendered-failure',
      error: status.errors[0], applicationFailures: applicationFailures.slice(-2),
      requests: requests.slice(-8), pages: pages.slice(-8) }));
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
      && FLAGS.every(flag => status[flag] === true);
    try { await saveWire(); }
    catch (error) { status.cleanupErrors.push({ name: error.name, code: null,
      message: 'Private wire preservation failed' }); status.fixtureCleaned = false;
      status.passed = false; }
    await fs.writeFile(config.evidencePath, JSON.stringify(status), { mode: 0o600, flag: 'wx' });
  }
  if (status.cleanupErrors.length) throw new AggregateError(status.cleanupErrors,
    'Owned product search cleanup or evidence failed');
  if (failure) throw failure;
  assertRenderedReceipt(status);
});
