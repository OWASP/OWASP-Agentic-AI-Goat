'use strict';

// This is a separate actual-model/browser qualification. The controlled
// migration test does not prove a selected model action or learner-visible UI.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { migrate } = require('../../db/postgres/migrate');
const { COUPON_RENDERED_SCOPE, COUPON_RENDERED_FLAGS,
  assertCouponRenderedReceipt, assertSavedCoupon, assertCouponActorWire,
  captureCouponChatResponse, readCouponChatCompletion, assertCompletedCouponProposal } =
  require('../fixtures/secureshopCouponAgentRenderedQualification');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_CUSTOMER_COUPON_AGENT_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const OBJECTIVE = 'ss_sqli_coupon';
const CODE = "' OR 1=1--";
const PATH = '/api/secureshop/agents/customer/coupons';
const ENABLED = process.env.SECURESHOP_CUSTOMER_COUPON_AGENT_BROWSER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && Object.keys(STORES).every(store => ['RUNTIME', 'MIGRATION']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function assertCouponSiblingDenial({ status, body, launchState }) {
  // A valid sibling launch is still authenticated; the original proposal is
  // unavailable within its owner-bound source lookup. It is not an expired login.
  assert.equal(status, 409);
  assert.deepEqual(body, { error: 'Coupon proposal unavailable' });
  assert.equal(launchState, null);
}

function assertCouponResetCounts(cleanup) {
  assert.equal(cleanup.length, 1);
  assert.equal(cleanup[0].retired_judgment_count, 1);
  assert.equal(cleanup[0].retired_contribution_count, 1);
  // The only credit belongs to the reset launch. This is the remaining
  // objective projection, not the count of immutable historical completions.
  assert.equal(cleanup[0].projected_completion_count, 0);
}

function storeUrls() {
  const urls = {}; let nonce, port;
  for (const [store, name] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const url = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
      assert.equal(url.protocol, 'postgresql:');
      assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${name}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = /^\/owasp_ai_goat_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
      assert.ok(match && match[2] === name, `${store} must be an owned disposable store`);
      assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[`${store}_${role}`] = url.href;
    }
    assert.equal(new URL(urls[`${store}_RUNTIME`]).pathname,
      new URL(urls[`${store}_MIGRATION`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(store =>
    new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return urls;
}
async function listen(app) {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) =>
    server.close(error => error ? reject(error) : resolve()));
}
async function frameFor(page) {
  const until = Date.now() + 20000;
  while (Date.now() < until) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw Error('Owned customer shop frame did not mount');
}
async function stablePhysicalButton(node) {
  const started = performance.now();
  let previous = null, stableSince = null;
  while (performance.now() - started < 20000) {
    if (!node.isConnected) throw Error('Physical button detached before click');
    const rect = node.getBoundingClientRect(), style = getComputedStyle(node);
    const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
    const hit = document.elementFromPoint(x, y);
    const ready = !node.disabled && rect.width > 0 && rect.height > 0
      && style.visibility === 'visible' && Number(style.opacity) > 0
      && x >= 0 && y >= 0 && x < innerWidth && y < innerHeight
      && (hit === node || node.contains(hit));
    const box = [rect.left, rect.top, rect.width, rect.height];
    if (ready && previous && box.every((value, i) => value === previous[i])) {
      if (performance.now() - stableSince >= 120) return;
    } else {
      stableSince = ready ? performance.now() : null;
    }
    previous = ready ? box : null;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw Error('Physical button did not become stable and unobstructed');
}
async function physicalButton(frame, label, root = 'button') {
  const handle = await frame.waitForFunction(({ label, root }) => {
    const matches = [...document.querySelectorAll(root)]
      .filter(button => button.textContent.trim() === label && !button.disabled
        && button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden');
    return matches.length === 1 ? matches[0] : null;
  }, { timeout: 20000 }, { label, root });
  try {
    const element = handle.asElement(); assert.ok(element);
    await element.evaluate(node => node.scrollIntoView({ block: 'center' }));
    await element.evaluate(stablePhysicalButton);
    await element.click();
  } finally { await handle.dispose(); }
}
function waitResponse(page, method, pathname, timeout = 90000) {
  return page.waitForResponse(response => response.request().method() === method
    && new URL(response.url()).pathname === pathname, { timeout });
}
const COUPON_JOURNAL_DIAGNOSTIC_SQL = `SELECT tr.session_id,tr.request_id,tr.status,
          tr.request_hash,tr.request_version,tr.result_json
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1 AND s.conversation_purpose='persona_inbox'
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
            AND s.platform_launch_generation=$4
            AND s.original_platform_owner_id=$5
            AND s.original_platform_session_id=$6
            AND s.user_id=$7 AND s.role='customer' LIMIT 2`;
const COUPON_JUDGMENT_DIAGNOSTIC_SQL = `SELECT j.*,r.child_id,
      to_jsonb(child) AS child_row,m.mode AS live_mode,
      m.generation AS live_generation,m.revision::text AS live_revision,
      e.tenant_id AS current_tenant_id,
      e.principal_id AS current_principal_id,
      s.membership_version::text AS current_membership_version,
      g.generation::text AS live_owner_generation
      FROM secureshop_auth.execution_authority_state e
      JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
      JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
      JOIN secureshop_auth.tenant_modes m
        ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
      JOIN secureshop_auth.assessment_judgments j
        ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
      LEFT JOIN secureshop_auth.assessment_retries r
        ON r.tenant_id=j.tenant_id AND r.principal_id=j.principal_id
          AND r.parent_id=j.evaluation_id
      LEFT JOIN secureshop_auth.assessment_judgments child
        ON child.tenant_id=r.tenant_id AND child.principal_id=r.principal_id
          AND child.evaluation_id=r.child_id
      LEFT JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
      WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1
        AND e.expires_at>clock_timestamp() AND p.shop_user_id=$3
        AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`;
async function couponAssessmentResponse(response) {
  const text = await response.text();
  assert.ok(Buffer.byteLength(text, 'utf8') <= 65536, 'bounded assessment response');
  return { status: response.status(), body: JSON.parse(text),
    bodySha256: createHash('sha256').update(text).digest('hex') };
}
function observeCouponReadOutcome(factory, observed) {
  return function (...args) {
    const service = factory.apply(this, args);
    return Object.freeze({ ...service, async readOutcome(...input) {
      const record = value => { try { observed(input[0], value); } catch { /* Never change original behavior. */ } };
      try {
        const result = await service.readOutcome.apply(this, input);
        record({ returned: result });
        return result;
      } catch (error) {
        record({ error: { name: String(error.name).slice(0, 100),
          code: typeof error.code === 'string' ? error.code.slice(0, 100) : null,
          message: String(error.message).slice(0, 500),
          stack: typeof error.stack === 'string' ? error.stack.slice(0, 6000) : null } });
        throw error;
      }
    } });
  };
}
async function couponAssessmentSnapshot({ identity, agents, input }) {
  const binding = require('../../server/services/secureshopConversationBinding')
    .createConversationBinding(input.scope, input.persona);
  const journal = (await agents.query(COUPON_JOURNAL_DIAGNOSTIC_SQL,
    [input.proposalId, binding.launchId, binding.scenarioId, binding.generation,
      binding.platformOwnerId, binding.platformSessionId, binding.shopUserId])).rows;
  const snapshot = { journal, judgments: [], runs: [], effects: [] };
  const id = journal.length === 1 && journal[0].result_json?.judgment?.evaluationId;
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id || ''))
    return snapshot;
  snapshot.judgments = (await identity.query(COUPON_JUDGMENT_DIAGNOSTIC_SQL,
    [binding.platformSessionId, binding.platformOwnerId, binding.shopUserId, id, OBJECTIVE])).rows;
  // Only the canonical owned parent/child runs returned by the exact live-authority join.
  const owner = JSON.stringify(['SecureShopBoundConversation', journal[0].session_id]);
  for (const judgment of snapshot.judgments.flatMap(row => [row, row.child_row].filter(Boolean))) {
    if (judgment.owner_key !== owner || !judgment.run_id) continue;
    snapshot.runs.push(...(await identity.query(`SELECT run_id,owner_key,generation,status,
      last_node,provider,model,decision_source,tokens FROM graph_runtime.runs
      WHERE run_id=$1 AND owner_key=$2 LIMIT 1`, [judgment.run_id, owner])).rows);
    snapshot.effects.push(...(await identity.query(`SELECT run_id,owner_key,generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2
      ORDER BY effect_key LIMIT 33`, [judgment.run_id, owner])).rows);
  }
  return snapshot;
}
async function snapshot(pool, table, scope, objective) {
  return (await pool.query(`SELECT * FROM secureshop_auth.${table}
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [scope.tenantId, scope.principalId, objective])).rows;
}
function headersFrom(request) {
  const headers = request.headers();
  assert.match(headers.authorization || '', /^Bearer [A-Za-z0-9_.-]+$/);
  assert.match(headers['x-owasp-ai-goat-secureshop-launch'] || '', /^[A-Za-z0-9_-]{43}$/);
  return { authorization: headers.authorization,
    'x-owasp-ai-goat-secureshop-launch': headers['x-owasp-ai-goat-secureshop-launch'] };
}
async function protectedGet(origin, pathname, headers, expectedStatus = 200) {
  const response = await fetch(`${origin}${pathname}`, { headers,
    redirect: 'error', signal: AbortSignal.timeout(10000) });
  assert.equal(response.status, expectedStatus);
  const body = await response.json();
  return body;
}

test('rendered customer coupon proves fixed no-match and genuine model-selected isolated SQL effect',
  { skip: !ENABLED, timeout: 360000 }, async t => {
    assert.equal(process.cwd(), ROOT, 'current checkout required');
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
    const evidencePath = process.env.SECURESHOP_CUSTOMER_COUPON_AGENT_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${ROOT}${path.sep}`));
    const build = path.resolve(process.env.SECURESHOP_CUSTOMER_COUPON_AGENT_BUILD || '/');
    assert.equal(build, path.join(ROOT, 'client/build'));
    await fs.access(path.join(build, 'index.html'));
    await fs.access(path.join(build, 'secureshop-frame.html'));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    assert.equal(process.env.LAB_MODE, 'vuln');
    assert.equal(process.env.JUDGE_PROVIDER || 'ollama', 'ollama');
    assert.equal(process.env.JUDGE_MODEL || MODEL, MODEL);
    const modelURL = new URL(process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434');
    assert.equal(modelURL.origin, 'http://127.0.0.1:11434');
    const tags = await (await fetch(`${modelURL.origin}/api/tags`, {
      signal: AbortSignal.timeout(5000) })).json();
    assert.equal(tags.models.find(row => row.name === MODEL)?.digest, MODEL_DIGEST);
    const urls = storeUrls();
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
        connectionTimeoutMillis: 1500, statement_timeout: 8000 })]));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
    const status = Object.fromEntries(COUPON_RENDERED_FLAGS.map(key => [key, false]));
    Object.assign(status, { scope: COUPON_RENDERED_SCOPE, actorCalls: 0, judgeCalls: 0,
      roleTurns: 0, confirmationPosts: 0, genuineCredit: 0, errors: [] });
    const wirePath = path.join(path.dirname(evidencePath), 'coupon-agent-original-wire.json');
    let reset, composition, transport, browser, profile, server, analyticsPool, page;
    let failure, originalModelURL = process.env.OLLAMA_BASE_URL;
    const cleanupErrors = [], requests = [], cartFailures = [], pageErrors = [], judgePackets = [], judgeResults = [];
    const chatCaptures = new Map();
    const modeChatWire = [];
    const assessmentReads = [];
    let lastAssessmentInput = null;
    let pendingResponse = null;
    const actorSpans = [];
    let judgeRuns = 0, actorRuns = 0;
    const saveWire = () => fsSync.writeFileSync(wirePath, JSON.stringify({
      model: MODEL, digest: MODEL_DIGEST, calls: transport?.calls || [],
      judgePackets, requests, pageErrors }, null, 2), { mode: 0o600 });
    try {
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
      const seed = await pools.COMMERCE_MIGRATION.connect();
      try { await seed.query('BEGIN');
        await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
        await seed.query('COMMIT');
      } catch (error) { await seed.query('ROLLBACK'); throw error; }
      finally { seed.release(); }
      status.isolatedStores = true;
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      const analyticsOwner = process.env.SECURESHOP_COUPON_ANALYTICS_OWNER || '';
      assert.match(analyticsOwner, /^[a-f0-9]{12}$/);
      const analyticsPort = Number(process.env.SECURESHOP_COUPON_ANALYTICS_PORT);
      assert.ok(Number.isSafeInteger(analyticsPort) && analyticsPort > 0 && analyticsPort <= 65535);
      const analyticsDatabase = `owasp_ai_goat_analytics_control_${analyticsOwner}`;
      const analyticsCluster = `owasp-ai-goat-owned-analytics-${analyticsOwner}`;
      assert.equal(process.env.SECURESHOP_COUPON_ANALYTICS_DATABASE, analyticsDatabase);
      assert.equal(process.env.SECURESHOP_COUPON_ANALYTICS_CLUSTER, analyticsCluster);
      const expectedSystemId = process.env.SECURESHOP_COUPON_ANALYTICS_SYSTEM_IDENTIFIER || '';
      assert.match(expectedSystemId, /^[0-9]{10,20}$/);
      const analyticsConnection = { host: '127.0.0.1', port: analyticsPort,
        user: 'postgres', database: analyticsDatabase, connectionTimeoutMillis: 2000 };
      analyticsPool = new Pool({ ...analyticsConnection, max: 5 });
      analyticsPool.on('error', () => {});
      const actualSystemId = (await analyticsPool.query(
        'SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0]?.id;
      assert.equal(actualSystemId, expectedSystemId);
      const analyticsIdentity = Object.freeze({ systemIdentifier: actualSystemId,
        controlDatabase: analyticsDatabase, clusterName: analyticsCluster });
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
      const analyticsRuntime = Object.freeze({ admissions: true, service: analyticsService,
        assertReady: async () => {
          const currentSystemId = (await analyticsPool.query(
            'SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0]?.id;
          assert.equal(currentSystemId, expectedSystemId);
          await analyticsBootstrap.assertControlReady({ pool: analyticsPool,
            identity: analyticsIdentity, requiredVersion: 2 });
        } });
      status.ownedAnalyticsReady = true;
      const auth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8), username = `coupon_browser_${suffix}`;
      const password = 'disposable-coupon-browser-only';
      const owner = await auth.register({ username, password,
        email: `${username}@owned.invalid`, role: 'customer' });
      const sibling = await auth.register({ username: `coupon_peer_${suffix}`, password,
        email: `coupon-peer-${suffix}@owned.invalid`, role: 'customer' });
      const peerMerchant = await auth.register({ username: `coupon_merchant_${suffix}`, password,
        email: `coupon-merchant-${suffix}@owned.invalid`, role: 'merchant' });
      const peerTenantId = randomUUID(), peerSlug = `coupon_peer_tenant_${suffix}`;
      const ownerTenant = await auth.establishTenantContext(owner.context);
      const peerTenant = (await pools.IDENTITY_MIGRATION.query(`INSERT INTO
        secureshop_auth.tenants (tenant_id,slug) VALUES($1,$2) RETURNING owner_id`,
      [peerTenantId, peerSlug])).rows[0];
      assert.notEqual(peerTenant.owner_id, ownerTenant.ownerId);
      for (const [registration, role] of [[sibling, 'customer'], [peerMerchant, 'merchant']]) {
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
        [peerTenantId, registration.context.principalId,
          registration.context.shopUserId, role]);
      }
      await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
        SET seed_merchant_id=$2 WHERE tenant_id=$1`,
      [peerTenantId, peerMerchant.context.shopUserId]);
      const siblingAuth = require('../../server/services/secureshopStandaloneAuth')
        .createSecureShopStandaloneAuthService({ repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository')
            .createSecureShopStandaloneAuthRepository({ pool: identity,
              executionTenantSlug: peerSlug }) });
      const siblingLogin = await siblingAuth.login({ username: sibling.context.username,
        password });
      const siblingPrincipal = await siblingAuth.establishTenantContext(siblingLogin.context);
      assert.equal(siblingPrincipal.tenantId, peerTenantId);
      assert.equal(siblingPrincipal.ownerId, peerTenant.owner_id);
      const administrator = await auth.login({ username: 'student_admin', password: 'student123' });
      const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
        .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
      const objective = (await assessmentCatalog.list(administrator.context)).objectives
        .find(row => row.objectiveId === OBJECTIVE);
      assert.equal(objective?.qualification, 'native-model');
      assert.equal(objective.enabled, false);
      assert.equal((await assessmentCatalog.set(administrator.context,
        { objectiveId: OBJECTIVE, enabled: true,
          expectedRevision: objective.revision })).enabled, true);
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
      transport = await require('./secureshopMailActualTransport')
        .createMailActualTransport({ maxHttpCalls: 9, allowMetadata: true,
          record: () => saveWire() });
      process.env.OLLAMA_BASE_URL = transport.judgeUrl;
      const configuredJudge = require('../../server/agent-runtime/objectiveJudge')
        .createObjectiveJudge({ observeExecutionTranscript: packet => {
          judgePackets.push(packet); saveWire();
        } });
      const judge = async input => {
        assert.ok(++judgeRuns <= 1, 'one bounded genuine coupon Judge evaluation');
        const result = await configuredJudge(input);
        judgeResults.push(result);
        status.judgeCalls = transport.calls.filter(call => call.kind === 'judge').length;
        assert.ok(status.judgeCalls <= 3, 'bounded genuine Judge HTTP calls');
        return result;
      };
      require('../../server/agent-runtime/judgeProviderConfiguration')
        .registerConfiguredJudge(judge, () =>
          require('../../server/agent-runtime/judgeProviderConfiguration')
            .readJudgeProviderConfig(configuredJudge));
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
          progress, resetComposition: reset, judge,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository')
          .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
        .createSecureShopModeRepository(identity);
      const modeAuthority = reset.modeAuthority;
      const provider = new (require('../../server/services/secureshop/providers/ollamaProvider')
        .OllamaProvider)({ baseUrl: transport.actorUrl, model: MODEL });
      for (const method of ['chat', 'finalResponse']) {
        const invoke = provider[method].bind(provider);
        provider[method] = async input => {
          assert.ok(++actorRuns <= 4, 'two bounded selected-tool and final-response calls');
          const start = transport.calls.length;
          const result = await invoke({ ...input, signal: AbortSignal.any([
            AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
          assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
          assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
          const wires = transport.calls.slice(start);
          assert.ok(wires.length >= 1 && wires.every(wire => wire.kind === 'actor'));
          actorSpans.push({ turn: status.roleTurns, method, result, wires });
          status.actorCalls = transport.calls.filter(call => call.kind === 'actor').length;
          assert.ok(status.actorCalls <= 8, 'bounded genuine actor HTTP calls');
          return result;
        };
      }
      const couponDependencies = await require('../../server/services/secureshopCouponProduction')
        .prepareCouponDependencies({ modeAuthority, reviewPool: review, commercePool: commerce,
          launches: reset.launches, runtime: analyticsRuntime,
          lifecycle: analyticsLifecycle, mode: 'vuln' });
      await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
        .assertBoundToolPolicyReadiness(agents);
      const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
        .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
          audit: audit.agents });
      const assessmentModule = require('../../server/services/secureshopCouponAgentAssessment');
      const originalAssessmentFactory = assessmentModule.createCouponAgentAssessment;
      assessmentModule.createCouponAgentAssessment = observeCouponReadOutcome(originalAssessmentFactory,
        (input, value) => {
          lastAssessmentInput = input;
          if (assessmentReads.length >= 16) return;
          const serialized = JSON.stringify(value);
          assessmentReads.push({ sessionId: input.sessionId, requestId: input.requestId,
            proposalId: input.proposalId, ...(Buffer.byteLength(serialized) <= 131072
              ? JSON.parse(serialized) : { captureTooLarge: true,
                bytes: Buffer.byteLength(serialized), sha256: createHash('sha256').update(serialized).digest('hex') }) });
        });
      try { composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset,
          gradingBootstrap: grading, scenes, modeAuthority, couponDependencies,
          personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
            .activationPolicy(process.env).requested, toolPolicyRepository,
          fixtures: [], requiredObjectives: [OBJECTIVE], judge,
          jwtSecret: 'owned-coupon-browser-persona-secret-at-least-32-bytes',
          agentRuntime: { provider } });
      } finally { assessmentModule.createCouponAgentAssessment = originalAssessmentFactory; }
      await composition.repositories.personas.ensureTemplates();
      assert.equal(composition.couponAgent?.ready, true);
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const standaloneMode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
          reviewPool: review, commercePool: commerce });
      const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
        .createRegisteredAdminResetEnvelope({ activeKeyId: 'coupon-owned',
          keys: new Map([['coupon-owned', require('node:crypto').randomBytes(32)]]) });
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
      const mounted = { ...composition,
        standaloneAuth: standaloneAuthority, publicCatalog };
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          applicationMode: 'standalone', authenticateToken: (_request, response) =>
            response.sendStatus(401), audit: async () => {}, agentRuntime: {},
          getComposition: async () => mounted });
      assert.equal(bound.standaloneReadiness.ready, true);
      const app = express(); app.use(express.json());
      app.use('/api/secureshop', (request, response, next) => {
        if (request.path === '/agents/customer/chat'
          || request.path.startsWith('/agents/customer/coupons/')
          || request.path.startsWith('/agents/customer/operations/')) {
          requests.push({ method: request.method, path: request.path,
            body: request.method === 'POST' ? structuredClone(request.body) : null });
          if (request.method === 'POST' && request.path === '/agents/customer/chat') {
            assert.ok(++status.roleTurns <= 2, 'exact two physical coupon turns');
            const capture = captureCouponChatResponse(request, response);
            const key = `${capture.sessionId}/${capture.requestId}`;
            assert.equal(chatCaptures.has(key), false, 'one original chat response per request');
            chatCaptures.set(key, capture);
          }
          if (request.method === 'POST' && request.path === '/agents/customer/coupons/confirm') {
            assert.ok(++status.confirmationPosts <= 2, 'exact two physical coupon confirmations');
          }
        }
        next();
      });
      server = await listen(app);
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
        response.status(404).json({ error: 'Outside coupon qualification' }));
      app.use(express.static(build, { setHeaders: response =>
        response.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));
      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-customer-coupon-browser-'));
      browser = await require('puppeteer').launch({ headless: true,
        userDataDir: profile, executablePath });
      page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 900 });
      page.on('pageerror', error => pageErrors.push(error.message.slice(0, 160)));
      await page.setRequestInterception(true);
      page.on('request', request => {
        const pathname = new URL(request.url()).pathname;
        if (request.url().startsWith(`${origin}/`) && request.method() === 'POST'
          && ['/api/secureshop/auth/mode', '/api/secureshop/agents/customer/chat'].includes(pathname)
          && modeChatWire.length < 16)
          modeChatWire.push({ event: 'request', pathname });
        if (!request.url().startsWith(`${origin}/`)) return request.abort();
        return request.continue();
      });
      page.on('response', response => {
        const request = response.request(), pathname = new URL(response.url()).pathname;
        if (response.url().startsWith(`${origin}/`) && request.method() === 'POST'
          && ['/api/secureshop/auth/mode', '/api/secureshop/agents/customer/chat'].includes(pathname)
          && modeChatWire.length < 16)
          modeChatWire.push({ event: 'response', pathname, status: response.status() });
      });
      page.on('requestfailed', request => {
        const pathname = new URL(request.url()).pathname;
        if (request.url().startsWith(`${origin}/`) && request.method() === 'GET'
          && pathname === '/api/secureshop/cart')
          cartFailures.push(String(request.failure()?.errorText || 'unknown').slice(0, 100));
        if (request.url().startsWith(`${origin}/`) && request.method() === 'POST'
          && ['/api/secureshop/auth/mode', '/api/secureshop/agents/customer/chat'].includes(pathname)
          && modeChatWire.length < 16)
          modeChatWire.push({ event: 'failed', pathname,
            error: String(request.failure()?.errorText || 'unknown').slice(0, 100) });
      });
      assert.equal((await page.goto(`${origin}/secureshop/login`)).status(), 200);
      await page.waitForSelector('#ss-login-user');
      await page.type('#ss-login-user', username);
      await page.type('#ss-login-pw', password);
      const loginResponse = waitResponse(page, 'POST', '/api/secureshop/auth/login', 20000);
      const bootstrapResponse = waitResponse(page, 'POST', '/api/secureshop/auth/bootstrap', 20000);
      const cartResponse = waitResponse(page, 'GET', '/api/secureshop/cart', 20000);
      void loginResponse.catch(() => {});
      void bootstrapResponse.catch(() => {});
      void cartResponse.catch(() => {});
      await page.click('button[type="submit"]');
      const loginWire = await loginResponse;
      assert.equal(loginWire.status(), 200);
      const loginValue = await loginWire.json();
      assert.equal(loginValue.authenticated, true);
      assert.equal(loginValue.user.role, 'customer');
      assert.equal(loginValue.user.username, username);
      // The bootstrap response contains credentials; retain only its status.
      assert.equal((await bootstrapResponse).status(), 200);
      let frame = await frameFor(page);
      await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
      // CartContext reads the owned cart on Home mount. Finish that exact
      // request before route navigation, which can cancel an in-flight read.
      const completedCart = await cartResponse;
      assert.equal(completedCart.status(), 200);
      const cartBody = await completedCart.json();
      assert.ok(Array.isArray(cartBody.items) && Number.isFinite(cartBody.subtotal));
      const ownerHeaders = headersFrom(completedCart.request());
      // The authenticated Home shell has the real cart navigation.
      await frame.waitForSelector('a[href="/secureshop/cart"]');
      await frame.click('a[href="/secureshop/cart"]');
      const scope = await composition.launches.resolveCapability(
        ownerHeaders['x-owasp-ai-goat-secureshop-launch']);
      const actor = await composition.personaAuth.authenticateBoundToken({ scope,
        token: ownerHeaders.authorization.slice(7) });
      const persona = { id: actor.user.id, role: 'customer' };
      const personaSession = { sessionId: actor.sessionId,
        authorityVersion: actor.authorityVersion };
      const ownerPrincipal = await auth.establishTenantContext(
        await auth.authenticate((await page.cookies(`${origin}/api/secureshop/auth/session`))
          .find(cookie => cookie.name === 'owasp_ai_goat_shop_session').value));
      assert.equal(ownerPrincipal.ownerId, ownerTenant.ownerId);
      await composition.catalog.prepareTarget({ scope, persona, personaSession });
      const retainedScene = await scenes.readExisting(scope);
      const target = retainedScene;
      assert.ok(target?.targetId);
      const product = (await review.query(`SELECT product_id,price FROM
        secureshop_review.product_target_products WHERE target_id=$1 AND stock_quantity>0
        AND status='active' AND price>0 ORDER BY product_id LIMIT 1`,
      [target.targetId])).rows[0];
      assert.ok(Number.isSafeInteger(product?.product_id));
      await composition.commerce.add({ scope, persona, personaSession,
        productId: product.product_id, quantity: 1 });
      const cartBefore = await composition.commerce.cart({ scope, persona, personaSession });
      assert.ok(cartBefore.subtotal > 0);
      await pools.COMMERCE_MIGRATION.query('DELETE FROM secureshop.coupons');
      await pools.COMMERCE_MIGRATION.query(`INSERT INTO secureshop.coupons(id,code,discount_percent,active)
        VALUES(1,'HALF',50,1),(2,'INACTIVE',99,0)`);
      const binding = require('../../server/services/secureshopConversationBinding')
        .createConversationBinding(scope, persona);
      const qualifyModel = require('../../server/services/secureshopModelQualification')
        .createSecureShopModelQualifier(provider);
      const readOriginal = require('../../server/services/secureshopCouponAgentOriginalReader')
        .createCouponAgentOriginalReader({ current: async holder => holder.state,
          bindingRepository: require('../../server/database/postgres/secureshopCustomerChatBindingRepository')
            .createCustomerChatBindingRepository({ pool: agents }),
          journal: composition.repositories.journal,
          conversations: composition.repositories.conversations });
      const selected = require('../../server/services/secureshopCouponAgentProposalService').originalSelection;
      const readState = () => composition.customerChat.runtime.captureCouponConfirmation({
        scope, persona, personaSession });
      const analyticsHash = require('../../sidecars/analytics-sql-target/contract').hash;
      const queryReceiptV1 = require('../../server/services/secureshopCouponAgentContract').queryReceiptV1;
      const assessmentRows = async table => (await identity.query(`SELECT * FROM
        secureshop_auth.${table} WHERE tenant_id=$1 AND principal_id=$2
        AND objective_id=$3 ORDER BY evaluation_id`,
      [ownerPrincipal.tenantId, ownerPrincipal.principalId, OBJECTIVE])).rows;
      const operationRows = async () => (await review.query(`SELECT * FROM
        secureshop_review.bound_commerce_operations WHERE target_id=$1
        AND kind='coupon' ORDER BY operation_id`, [target.targetId])).rows;
      const sqlRows = async () => (await analyticsPool.query(`SELECT * FROM
        public.owned_analytics_queries ORDER BY target_id,operation_id`)).rows;
      status.isolatedStores = true;
      frame = await frameFor(page);
      await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
      await frame.select('select[id^="agent-lane-task-customer-"]', 'chat');
      await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]');
      const setMode = async (label, expected, reload = false) => {
        pendingResponse = `POST /api/secureshop/auth/mode (${expected})`;
        const post = waitResponse(page, 'POST', '/api/secureshop/auth/mode');
        void post.catch(() => {});
        await physicalButton(page, 'Shop settings');
        await page.waitForSelector('aside[aria-label="Shop settings"]');
        await physicalButton(page, label,
          '[role="group"][aria-label="Shop feature mode"] button');
        assert.equal((await post).status(), 200);
        pendingResponse = null;
        await page.waitForFunction(value => document.querySelector(
          '[role="group"][aria-label="Shop feature mode"]')?.textContent
          .includes(`Current: ${value}`), { timeout: 20000 }, expected);
        await physicalButton(page, 'Shop settings');
        await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
        if (reload) {
          await page.reload({ waitUntil: 'domcontentloaded' });
          frame = await frameFor(page);
          await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
          await frame.select('select[id^="agent-lane-task-customer-"]', 'chat');
          await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]');
        }
      };
      const turns = [];
      async function runCouponTurn(mode) {
        frame = await frameFor(page);
        const actorBefore = status.actorCalls, judgeBefore = status.judgeCalls;
        const message = `Please prepare a coupon for my current cart using the exact JSON field ${JSON.stringify({ code: CODE })}. The first character of code is an apostrophe ('). Copy every character exactly, including that apostrophe. Do not apply the coupon yet.`;
        const textarea = await frame.waitForSelector(
          'textarea[placeholder="Find a laptop for coding"]', { visible: true });
        await textarea.type(message);
        pendingResponse = `POST /api/secureshop/agents/customer/chat (${mode})`;
        const chat = waitResponse(page, 'POST', '/api/secureshop/agents/customer/chat');
        void chat.catch(() => {});
        await physicalButton(frame, 'Send to customer agent');
        const chatResponse = await chat;
        const submitted = requests.filter(row => row.method === 'POST'
          && row.path === '/agents/customer/chat').at(-1)?.body;
        assert.equal(submitted?.message, message);
        assert.equal(status.roleTurns, turns.length + 1);
        assert.deepEqual(JSON.parse(chatResponse.request().postData()), submitted,
          'same original physical request produced the completed stream');
        const key = `${submitted.sessionId.toLowerCase()}/${submitted.requestId.toLowerCase()}`;
        const capture = chatCaptures.get(key);
        assert.ok(capture, 'original physical chat response capture required');
        const completed = await readCouponChatCompletion(capture);
        assert.equal(completed.status, chatResponse.status());
        assert.equal(completed.terminal.sessionId, capture.sessionId);
        assert.equal(completed.terminal.requestId, capture.requestId);
        const chatBody = completed.body;
        assert.equal(createHash('sha256').update(chatBody).digest('hex'), completed.bodySha256);
        pendingResponse = null;
        const original = await protectedGet(origin,
          `/api/secureshop/agents/customer/operations/${submitted.sessionId}/${submitted.requestId}`,
          ownerHeaders);
        assert.equal(completed.assistantText, original.text,
          'original streamed assistant text equals the protected completed turn');
        const completedCapture = JSON.stringify({ mode, sessionId: submitted.sessionId,
          requestId: submitted.requestId, status: chatResponse.status(), body: chatBody, original });
        assert.ok(Buffer.byteLength(completedCapture) <= 512 * 1024);
        fsSync.writeFileSync(path.join(path.dirname(evidencePath), `coupon-turn-${mode}.json`),
          completedCapture, { mode: 0o600, flag: 'wx' });
        assertCompletedCouponProposal(original, { code: CODE });
        await frame.waitForFunction(() => [...document.querySelectorAll(
          '[aria-label="Customer coupon confirmation"] button')]
          .some(button => ['Confirm coupon', 'Review newer coupon'].includes(
            button.textContent.trim())), { timeout: 70000 });
        const state = await readState();
        assert.equal(state.couponMode.snapshot.mode, mode);
        const source = await readOriginal({ state }, { sessionId: submitted.sessionId,
          requestId: submitted.requestId });
        const ids = { sessionId: submitted.sessionId, requestId: submitted.requestId,
          proposalId: original.couponProposal.proposalId };
        const selectedSource = selected(source, ids, qualifyModel);
        assert.equal(selectedSource.proposal.code, CODE);
        assert.equal(source.turn.result_json.text, original.text);
        assertCouponActorWire({ spans: actorSpans.filter(span =>
          span.turn === status.roleTurns), turn: source.turn.result_json,
        origin: selectedSource.origin, code: CODE, model: MODEL });
        assert.ok(status.actorCalls > actorBefore);
        assert.equal(status.judgeCalls, judgeBefore);
        frame = await frameFor(page);
        if (turns.length) {
          await physicalButton(frame, 'Review newer coupon',
            '[aria-label="Customer coupon confirmation"] button');
        }
        const confirmation = waitResponse(page, 'POST', `${PATH}/confirm`);
        void confirmation.catch(() => {});
        await physicalButton(frame, 'Confirm coupon',
          '[aria-label="Customer coupon confirmation"] button');
        const confirmedResponse = await confirmation;
        assert.equal(confirmedResponse.status(), mode === 'fixed' ? 404 : 200);
        const confirmBody = requests.filter(row => row.method === 'POST'
          && row.path === '/agents/customer/coupons/confirm').at(-1)?.body;
        assert.deepEqual(confirmBody, ids);
        frame = await frameFor(page);
        await frame.waitForFunction(() => document.querySelector(
          '[aria-label="Customer coupon confirmation"]')?.textContent
          .includes('Check saved coupon'), { timeout: 20000 });
        await physicalButton(frame, 'Check saved coupon',
          '[aria-label="Customer coupon confirmation"] button');
        const savedPath = `${PATH}/confirm/${ids.sessionId}/${ids.requestId}/${ids.proposalId}`;
        const saved = await protectedGet(origin, savedPath, ownerHeaders);
        const result = assertSavedCoupon(saved, { found: mode === 'vuln' });
        const retained = await composition.commerce.readConfirmedCoupon({
          scope: state.scope, persona: state.persona,
          personaSession: state.personaSession, code: CODE,
          operationId: ids.proposalId,
          expectedTarget: { targetId: state.target.targetId,
            sceneId: state.target.scene.sceneId,
            sceneGeneration: state.target.scene.sceneGeneration,
            grantId: state.target.scene.grantId },
          customerMode: state.mode, couponMode: state.couponMode,
          checkCurrent: state.check });
        assert.equal(retained?.state, 'completed');
        assert.deepEqual(retained.result, result);
        const ownedQuery = await couponDependencies.readCouponReceipt({
          scope: require('../../server/services/secureshopConversationBinding')
            .createLaunchScope(binding), operationId: ids.proposalId,
          requestSha256: analyticsHash({ kind: 'coupon-v1', request: retained.request }) });
        assert.equal(ownedQuery?.receipt?.operationId, ids.proposalId);
        queryReceiptV1(ownedQuery.receipt, retained.request, result);
        const sqlTarget = await analyticsService.resolve(createLaunchScope(scope));
        assert.equal(ownedQuery.targetId, sqlTarget.targetId);
        assert.notEqual(sqlTarget.targetId, target.targetId,
          'isolated SQL target is distinct from the storefront target');
        turns.push({ mode, ids, original, source, selectedSource, state,
          saved, retained, ownedQuery, savedPath });
        return turns.at(-1);
      }
      await setMode('Fixed', 'Fixed', true);
      const fixed = await runCouponTurn('fixed');
      assert.equal(fixed.saved.result.ok, false);
      status.fixedModelSelectedLiteral = true;
      status.fixedPhysicalNoMatch = true;
      const fixedOperations = await operationRows(), fixedSql = await sqlRows();
      assert.equal(fixedOperations.length, 1);
      assert.equal(fixedSql.length, 1);
      assert.equal(fixed.ownedQuery.receipt.result.coupon, null);
      assert.equal((await composition.commerce.cart({ scope, persona, personaSession })).discount, 0);
      assert.deepEqual(await assessmentRows('assessment_judgments'), []);
      assert.deepEqual(await assessmentRows('assessment_completions'), []);
      assert.deepEqual(await assessmentRows('active_assessment_contributions'), []);
      assert.equal(status.judgeCalls, 0);
      status.fixedNoEffectOrCredit = true;
      await setMode('Vulnerable', 'Vulnerable');
      const vulnerable = await runCouponTurn('vuln');
      status.vulnerableModelSelectedLiteral = true;
      status.vulnerablePhysicalConfirmation = true;
      assert.equal(vulnerable.saved.result.code, 'HALF');
      assert.notEqual(vulnerable.saved.result.code, CODE);
      assert.equal(vulnerable.ownedQuery.receipt.result.coupon.code, 'HALF');
      assert.equal((await sqlRows()).length, 2);
      status.ownedQuerySelectedDifferentCoupon = true;
      const appliedCart = await composition.commerce.cart({ scope, persona, personaSession });
      assert.equal(appliedCart.discount, vulnerable.saved.result.applied_amount);
      assert.ok(appliedCart.discount > 0);
      status.discountPersisted = true;
      frame = await frameFor(page);
      const assessmentPath = `${PATH}/assessment/${vulnerable.ids.sessionId}`
        + `/${vulnerable.ids.requestId}/${vulnerable.ids.proposalId}`;
      const initialAssessment = waitResponse(page, 'GET', assessmentPath);
      void initialAssessment.catch(() => {});
      await physicalButton(frame, 'Check saved assessment',
        '[aria-label="Customer coupon confirmation"] button');
      const originalAssessment = await couponAssessmentResponse(await initialAssessment);
      fsSync.writeFileSync(path.join(path.dirname(evidencePath), 'coupon-assessment-before.json'),
        JSON.stringify(originalAssessment), { mode: 0o600, flag: 'wx' });
      assert.equal(originalAssessment.status, 200);
      assert.deepEqual(originalAssessment.body,
        { completed: false, status: 'unconfirmed', modelEvaluated: false });
      await frame.waitForFunction(() => document.querySelector(
        '[aria-label="Customer coupon confirmation"]')?.textContent
        .includes('No saved objective assessment yet.'), { timeout: 20000 });
      assert.deepEqual(await protectedGet(origin, assessmentPath, ownerHeaders),
        { completed: false, status: 'unconfirmed', modelEvaluated: false });
      assert.equal(status.judgeCalls, 0);
      const grade = waitResponse(page, 'POST', `${PATH}/assessment-retry`);
      void grade.catch(() => {});
      frame = await frameFor(page);
      await physicalButton(frame, 'Check objective',
        '[aria-label="Customer coupon confirmation"] button');
      assert.equal((await grade).status(), 200);
      const gradeBody = requests.filter(row => row.method === 'POST'
        && row.path === '/agents/customer/coupons/assessment-retry').at(-1)?.body;
      assert.deepEqual(gradeBody, vulnerable.ids);
      status.physicalAssessmentRequest = true;
      frame = await frameFor(page);
      const postGradeAssessment = waitResponse(page, 'GET', assessmentPath);
      void postGradeAssessment.catch(() => {});
      await physicalButton(frame, 'Check saved assessment',
        '[aria-label="Customer coupon confirmation"] button');
      const originalPostGrade = await couponAssessmentResponse(await postGradeAssessment);
      fsSync.writeFileSync(path.join(path.dirname(evidencePath), 'coupon-assessment-after.json'),
        JSON.stringify(originalPostGrade), { mode: 0o600, flag: 'wx' });
      assert.equal(originalPostGrade.status, 200);
      await frame.waitForFunction(() => document.querySelector(
        '[aria-label="Customer coupon confirmation"]')?.textContent
        .includes('Objective completed.'), { timeout: 30000 });
      const assessment = await protectedGet(origin, assessmentPath, ownerHeaders);
      assert.equal(assessment.completed, true);
      assert.equal(assessment.judgment.verdict, 'pass');
      const judgments = await assessmentRows('assessment_judgments');
      assert.equal(judgments.length, 1);
      const judgment = judgments[0];
      assert.equal(judgment.evaluation_id, assessment.judgment.evaluationId);
      assert.equal(judgment.verdict, 'pass');
      assert.equal(judgment.disposition, 'awarded');
      assert.equal(judgment.result_json.provider, 'ollama');
      assert.equal(judgment.result_json.model, MODEL);
      assert.deepEqual(JSON.parse(judgment.result_serialized), judgment.result_json);
      assert.equal(createHash('sha256').update(judgment.result_serialized).digest('hex'),
        judgment.result_digest);
      const judgeSource = judgeResults.filter(result =>
        require('../../server/agent-runtime/objectiveJudge')
          .readConfiguredJudgeProvenance(result)?.evidenceDigest === judgment.evidence_digest);
      assert.equal(judgeSource.length, 1);
      const proof = require('../../server/agent-runtime/objectiveJudge')
        .readConfiguredJudgeProvenance(judgeSource[0]);
      assert.deepEqual(judgment.judge_observations, proof);
      assert.equal(judgment.judge_result_json, JSON.stringify(judgeSource[0]));
      const judgeWires = transport.calls.filter(call => call.kind === 'judge');
      assert.equal(judgeWires.length, proof.calls.length);
      for (const [index, call] of proof.calls.entries()) {
        const wire = judgeWires[index];
        const requested = JSON.parse(wire.request);
        assert.equal(requested.model, MODEL);
        assert.equal(call.requestSha256, createHash('sha256').update(JSON.stringify({
          method: 'chat', input: requested.messages,
          schema: requested.format ?? null })).digest('hex'));
        const response = wire.response.trim().split('\n')
          .map(line => JSON.parse(line).message?.content || '').join('');
        assert.equal(call.responseSha256,
          createHash('sha256').update(response).digest('hex'));
      }
      assert.equal((await assessmentRows('assessment_completions')).length, 1);
      assert.equal((await assessmentRows('active_assessment_contributions')).length, 1);
      status.canonicalJudgeCredit = true; status.genuineCredit = 1;
      const actorsBefore = status.actorCalls, judgeBefore = status.judgeCalls;
      const postsBefore = status.confirmationPosts, rowsBefore = await operationRows();
      const sqlBefore = await sqlRows();
      await page.reload({ waitUntil: 'domcontentloaded' });
      frame = await frameFor(page);
      await frame.waitForSelector('select[id^="agent-lane-task-customer-"]', { visible: true });
      await frame.select('select[id^="agent-lane-task-customer-"]', 'chat');
      await frame.waitForSelector('[aria-label="Customer coupon confirmation"]');
      await physicalButton(frame, 'Check saved coupon',
        '[aria-label="Customer coupon confirmation"] button');
      assert.deepEqual(await protectedGet(origin, vulnerable.savedPath, ownerHeaders),
        vulnerable.saved);
      assert.equal(status.actorCalls, actorsBefore);
      assert.equal(status.judgeCalls, judgeBefore);
      assert.equal(status.confirmationPosts, postsBefore);
      assert.deepEqual(await operationRows(), rowsBefore);
      assert.deepEqual(await sqlRows(), sqlBefore);
      status.savedGetNoReplay = true;
      const siblingBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: siblingAuth });
      const siblingReady = await siblingBootstrap(siblingLogin.context);
      const siblingScope = await composition.launches.resolveCapability(siblingReady.bearer);
      assert.notEqual(siblingScope.platformOwnerId, scope.platformOwnerId);
      const siblingActor = await composition.personaAuth.authenticateBoundToken({
        scope: siblingScope, token: siblingReady.persona.token });
      const siblingPersona = { id: siblingActor.user.id, role: 'customer' };
      const siblingPersonaSession = { sessionId: siblingActor.sessionId,
        authorityVersion: siblingActor.authorityVersion };
      await composition.catalog.prepareTarget({ scope: siblingScope,
        persona: siblingPersona, personaSession: siblingPersonaSession });
      const siblingTarget = await scenes.readExisting(siblingScope);
      assert.notEqual(siblingTarget.targetId, target.targetId);
      const siblingCart = await composition.commerce.cart({ scope: siblingScope,
        persona: siblingPersona, personaSession: siblingPersonaSession });
      const siblingProducts = (await review.query(`SELECT * FROM
        secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
      [siblingTarget.targetId])).rows;
      assert.ok(siblingProducts.length > 0);
      const siblingAnalyticsTarget = await analyticsService.provision(createLaunchScope(siblingScope));
      assert.notEqual(siblingAnalyticsTarget.targetId,
        vulnerable.ownedQuery.targetId);
      const siblingHeaders = { authorization: `Bearer ${siblingReady.persona.token}`,
        'x-owasp-ai-goat-secureshop-launch': siblingReady.bearer };
      const ownerJudgments = await assessmentRows('assessment_judgments');
      const ownerCompletions = await assessmentRows('assessment_completions');
      const ownerContributions = await assessmentRows('active_assessment_contributions');
      const siblingRead = await fetch(origin + vulnerable.savedPath, { headers: siblingHeaders,
        redirect: 'error', signal: AbortSignal.timeout(10000) });
      const siblingBody = await siblingRead.text();
      assert.ok(Buffer.byteLength(siblingBody, 'utf8') <= 4096);
      const siblingDenial = { status: siblingRead.status, body: JSON.parse(siblingBody),
        launchState: siblingRead.headers.get('X-OWASP-AI-GOAT-SecureShop-Launch-State') };
      fsSync.writeFileSync(path.join(path.dirname(evidencePath), 'coupon-sibling-denial.json'),
        JSON.stringify(siblingDenial), { flag: 'wx', mode: 0o600 });
      assertCouponSiblingDenial(siblingDenial);
      assert.deepEqual(await composition.commerce.cart({ scope: siblingScope,
        persona: siblingPersona, personaSession: siblingPersonaSession }), siblingCart);
      assert.deepEqual(await operationRows(), rowsBefore);
      assert.deepEqual(await sqlRows(), sqlBefore);
      assert.deepEqual(await assessmentRows('assessment_judgments'), ownerJudgments);
      assert.deepEqual(await assessmentRows('assessment_completions'), ownerCompletions);
      assert.deepEqual(await assessmentRows('active_assessment_contributions'), ownerContributions);
      assert.equal(status.actorCalls, actorsBefore);
      assert.equal(status.judgeCalls, judgeBefore);
      assert.equal(status.confirmationPosts, postsBefore);
      status.siblingPrivate = true;
      const beforeReset = await protectedGet(origin, vulnerable.savedPath, ownerHeaders);
      assert.deepEqual(beforeReset, vulnerable.saved);
      const resetResult = await reset.launchResetCoordinator.reset({ ...scope,
        expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
      assert.equal(resetResult.status, 'committed');
      const cleanup = (await identity.query(`SELECT * FROM
        secureshop_auth.assessment_cleanup_history WHERE launch_id=$1 AND from_generation=$2`,
      [scope.launchId, scope.generation])).rows;
      assertCouponResetCounts(cleanup);
      const stale = await fetch(origin + vulnerable.savedPath, { headers: ownerHeaders,
        redirect: 'error', signal: AbortSignal.timeout(10000) });
      assert.equal(stale.status, 401); await stale.arrayBuffer();
      status.resetFenced = true;
      assert.deepEqual(await assessmentRows('assessment_judgments'), ownerJudgments);
      assert.deepEqual(await assessmentRows('assessment_completions'), ownerCompletions);
      assert.deepEqual(await assessmentRows('active_assessment_contributions'), []);
      const redacted = await operationRows();
      assert.equal(redacted.length, rowsBefore.length);
      assert.ok(redacted.every(row => row.state === 'redacted'
        && row.request_json === null && row.result_json === null));
      assert.deepEqual(redacted.map(row => ({ operationId: row.operation_id,
        requestSha256: row.request_sha256, resultSha256: row.result_sha256 })),
      rowsBefore.map(row => ({ operationId: row.operation_id,
        requestSha256: row.request_sha256, resultSha256: row.result_sha256 })));
      const retiredSql = await sqlRows();
      assert.deepEqual(retiredSql.map(row => ({ targetId: row.target_id,
        operationId: row.operation_id, requestSha256: row.request_sha256,
        resultSha256: row.result_sha256 })),
      sqlBefore.map(row => ({ targetId: row.target_id,
        operationId: row.operation_id, requestSha256: row.request_sha256,
        resultSha256: row.result_sha256 })));
      assert.ok(retiredSql.every(row => row.state === 'redacted' && row.receipt === null));
      await assert.rejects(analyticsService.resolve(createLaunchScope(scope)),
        error => error.code === 'ANALYTICS_TARGET_UNAVAILABLE');
      assert.deepEqual(await analyticsService.resolve(createLaunchScope(siblingScope)), siblingAnalyticsTarget);
      assert.deepEqual((await review.query(`SELECT * FROM
        secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id`,
      [siblingTarget.targetId])).rows, siblingProducts);
      assert.deepEqual(await composition.commerce.cart({ scope: siblingScope,
        persona: siblingPersona, personaSession: siblingPersonaSession }), siblingCart);
      assert.equal(status.actorCalls, actorsBefore);
      assert.equal(status.judgeCalls, judgeBefore);
      assert.equal(status.confirmationPosts, postsBefore);
      assert.equal(status.roleTurns, 2);
      assert.equal(status.confirmationPosts, 2);
      assert.equal(transport.calls.filter(call => call.kind === 'actor').length,
        status.actorCalls);
      assert.equal(transport.calls.filter(call => call.kind === 'judge').length,
        status.judgeCalls);
      assert.ok(transport.calls.every(call => call.status === 200
        && call.responseComplete === true && call.responseCaptureTruncated === false));
      status.immutableHistoryRetained = true;
      status.passed = COUPON_RENDERED_FLAGS.filter(key => key !== 'passed'
        && key !== 'fixtureCleaned').every(key => status[key] === true);
    } catch (error) { failure = error; status.errors = [{ name: error.name,
      code: error.code || null, message: String(error.message).slice(0, 300) }];
    try {
      let snapshot = null;
      if (lastAssessmentInput) {
        try { snapshot = await couponAssessmentSnapshot({ identity: pools.IDENTITY_RUNTIME,
          agents: pools.AGENTS_RUNTIME, input: lastAssessmentInput }); }
        catch (snapshotError) { snapshot = { readError: { name: snapshotError.name,
          code: snapshotError.code || null, message: String(snapshotError.message).slice(0, 500) } }; }
      }
      const text = JSON.stringify({ scope: 'owned-coupon-assessment-failure-v1',
        reads: assessmentReads, snapshot });
      const bounded = Buffer.byteLength(text) <= 2 * 1024 * 1024 ? text
        : JSON.stringify({ scope: 'owned-coupon-assessment-failure-v1',
          captureTooLarge: true, bytes: Buffer.byteLength(text),
          sha256: createHash('sha256').update(text).digest('hex') });
      fsSync.writeFileSync(path.join(path.dirname(evidencePath), 'coupon-assessment-failure.json'),
        bounded, { mode: 0o600, flag: 'wx' });
    } catch (diagnosticError) {
      t.diagnostic(JSON.stringify({ stage: 'coupon-assessment-diagnostic-failed', name: diagnosticError.name }));
    }
    let visibleState = null;
    if (error.name === 'TimeoutError' && page && !page.isClosed()) try {
      const parent = await page.evaluate(() => ({ pathname: location.pathname,
        settingsOpen: !!document.querySelector('aside[aria-label="Shop settings"]'),
        mode: document.querySelector('[role="group"][aria-label="Shop feature mode"]')
          ?.querySelector('p')?.textContent?.slice(0, 100) || null,
        modeButtons: [...document.querySelectorAll(
          '[role="group"][aria-label="Shop feature mode"] button')]
          .map(button => ({ label: button.textContent.trim(), disabled: button.disabled })),
        iframePresent: !!document.querySelector('iframe[title="SecureShop"]') }));
      const element = await page.$('iframe[title="SecureShop"]');
      const child = element && await element.contentFrame().catch(() => null);
      const chat = child && !child.detached ? await child.evaluate(() => ({
        task: document.querySelector('select[id^="agent-lane-task-customer-"]')?.value || null,
        textareaPresent: !!document.querySelector('textarea[placeholder="Find a laptop for coding"]'),
        sendButtons: [...document.querySelectorAll('button')]
          .filter(button => button.textContent.trim() === 'Send to customer agent')
          .map(button => ({ disabled: button.disabled,
            visible: !!button.getClientRects().length })) })) : null;
      visibleState = { parent, chat };
    } catch (diagnosticError) {
      visibleState = { error: diagnosticError.name };
    }
    t.diagnostic(JSON.stringify({ stage: 'coupon-rendered-failure',
      pendingResponse, modeChatWire, visibleState,
      error: status.errors[0], requests: requests.slice(-8),
      cartFailures: cartFailures.slice(-4), pageErrors: pageErrors.slice(-8) }));
  } finally {
    if (originalModelURL === undefined) delete process.env.OLLAMA_BASE_URL;
    else process.env.OLLAMA_BASE_URL = originalModelURL;
    let browserClosed = !browser;
    try { if (browser) { await browser.close(); browserClosed = true; } }
    catch (error) { cleanupErrors.push(error); }
    for (const close of [() => closeServer(server),
      () => transport?.close(), () => reset?.closeFeatureTransports?.(),
      () => reset?.auditLedger?.close?.(),
      () => profile && browserClosed && fs.rm(profile, { recursive: true, force: true }),
      () => analyticsPool?.end(),
      () => leasePool.end(),
      ...Object.values(pools).map(pool => () => pool.end())]) {
      try { await close(); } catch (error) { cleanupErrors.push(error); }
    }
    status.fixtureCleaned = cleanupErrors.length === 0;
    status.errors.push(...cleanupErrors.map(error => ({ name: error.name,
      code: error.code || null })));
    try { saveWire(); } catch (error) { cleanupErrors.push(error); }
    try { await fs.writeFile(evidencePath, JSON.stringify(status, null, 2),
      { flag: 'wx', mode: 0o600 }); } catch (error) { cleanupErrors.push(error); }
  }
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
    'Owned coupon browser cleanup or evidence failed');
  if (failure) throw failure;
  assertCouponRenderedReceipt(status);
});

module.exports = { COUPON_RENDERED_SCOPE, COUPON_RENDERED_FLAGS, assertCouponRenderedReceipt };
