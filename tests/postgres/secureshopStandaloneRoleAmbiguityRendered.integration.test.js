'use strict';

// Q03 qualifies ambiguous names in the real detached merchant/admin UI. The
// native launcher supplies only fresh disposable stores and an owned browser.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { SCOPE, FLAGS, validateRoleAmbiguityReceipt } = require('../fixtures/secureshopRoleAmbiguityReceipt');

const ASSERTION = 'standalone merchant and administrator clarify ambiguous names and physically select exact owned targets through real local llama3.1:8b';
const GATE = 'SECURESHOP_ROLE_AMBIGUITY_BROWSER_NATIVE';
const BASE = 'SECURESHOP_ROLE_AMBIGUITY_BROWSER_';
const PREFIX = 'PG_SECURESHOP_ROLE_AMBIGUITY_BROWSER_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const boundedToolArgs = value => Object.fromEntries(Object.entries(value && typeof value === 'object'
  && !Array.isArray(value) ? value : {}).slice(0, 8).map(([key, item]) => [key,
  typeof item === 'string' ? item.slice(0, 160)
    : Number.isSafeInteger(item) || typeof item === 'boolean' || item === null ? item : '[complex]']));
const boundedTurnSummary = value => ({
  status: typeof value?.status === 'string' ? value.status.slice(0, 40) : null,
  stopReason: typeof value?.stopReason === 'string' ? value.stopReason.slice(0, 40) : null,
  cards: Array.isArray(value?.cards) ? value.cards.slice(0, 8).map(card => ({
    kind: String(card?.kind || '').slice(0, 40), title: String(card?.title || '').slice(0, 160),
    detail: String(card?.detail || '').slice(0, 160),
  })) : [],
  hops: Array.isArray(value?.hops) ? value.hops.slice(0, 8).map(hop => ({
    tool: String(hop?.tool || '').slice(0, 80), status: String(hop?.status || '').slice(0, 40),
    error: Boolean(hop?.error),
    errorStatus: hop?.error ? String(hop.error?.code || hop.error?.message || hop.error).slice(0, 120) : null,
    params: boundedToolArgs(hop?.params),
  })) : [],
  proposals: Object.fromEntries(['inventoryProposal', 'pricingProposal', 'listingProposal',
    'listingCreateProposal', 'reviewProposal', 'userAdministrationProposal', 'policyProposal',
    'mcpRegistryProposal', 'systemRestartProposal', 'aclProposal', 'auditJobProposal']
    .map(key => [key, value?.[key] != null])),
});

function admission() {
  assert.equal(process.env[GATE], '1');
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.LIVE_OLLAMA_TEST, '1');
  assert.equal(process.env.LAB_MODE, 'vuln');
  assert.equal(process.env.AI_PROVIDER, 'ollama');
  assert.equal(process.env.OLLAMA_MODEL, 'llama3.1:8b');
  assert.equal(process.env.OLLAMA_BASE_URL, 'http://127.0.0.1:11434');
  const workspace = path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/');
  assert.equal(workspace, process.cwd());
  const build = path.resolve(process.env[`${BASE}BUILD`] || '/');
  assert.equal(build, path.join(workspace, 'client/build'));
  const evidence = path.resolve(process.env[`${BASE}EVIDENCE_PATH`] || '/');
  assert.notEqual(evidence, '/');
  assert.ok(!evidence.startsWith(`${workspace}${path.sep}`));
  const browser = path.resolve(process.env.PUPPETEER_EXECUTABLE_PATH || '/');
  assert.notEqual(browser, '/');
  const urls = {}; let nonce, port;
  for (const [store, suffix] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const source = process.env[`${PREFIX}${store}_${role}_URL`];
      assert.ok(source, `missing disposable ${store} ${role}`);
      const url = new URL(source);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.port, /^[1-9]\d{0,4}$/); assert.ok(Number(url.port) <= 65535);
      assert.equal(url.username, `dvaia_${suffix}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      const match = new RegExp(`^/owasp_ai_goat_test_agent_host_([0-9a-f]{12})_${suffix}$`).exec(url.pathname);
      assert.ok(match, `closed ${store} database required`);
      nonce ??= match[1]; port ??= url.port;
      assert.equal(match[1], nonce); assert.equal(url.port, port);
      urls[`${store}_${role}`] = source;
    }
    assert.equal(new URL(urls[`${store}_RUNTIME`]).pathname,
      new URL(urls[`${store}_MIGRATION`]).pathname);
  }
  assert.equal(new Set(Object.keys(STORES).map(store =>
    new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return { workspace, build, evidence, browser, urls };
}

async function listen(app) {
  return new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
}
async function frameFor(page, role) {
  const until = Date.now() + 30000;
  const selector = role === 'admin' ? '[data-testid="admin-role-assistant"]' : '[data-testid="agent-lane"]';
  let observed = { role, frame: false, url: null, text: null };
  while (Date.now() < until) {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    if (frame && !frame.detached) {
      observed = await frame.evaluate((query, expectedRole) => ({ role: expectedRole, frame: true,
        url: `${location.pathname}${location.search}`.slice(0, 160),
        text: (document.body?.innerText || '').replace(/\s+/g, ' ').slice(0, 240),
        ready: Boolean(document.querySelector(query)),
      }), selector, role).catch(() => ({ role, frame: true, url: null, text: null, ready: false }));
      if (observed.ready) return frame;
    }
    await delay(50);
  }
  observed.parent = await page.evaluate(() => ({
    path: `${location.pathname}${location.search}`.slice(0, 160),
    text: (document.body?.innerText || '').replace(/\s+/g, ' ').slice(0, 240),
    iframe: Boolean(document.querySelector('iframe[title="SecureShop"]')),
  })).catch(() => null);
  throw Error(`${role} assistant frame did not mount: ${JSON.stringify(observed)}`);
}
const opaqueFrameStatic = () => ({
  setHeaders: response => response.set('Access-Control-Allow-Origin', '*'),
});
function createProtectedReset({ identityPool, authService, launches, scenes, resetComposition },
  create = require('../../server/services/secureshopStandaloneReset').createSecureShopStandaloneReset) {
  return create({ identityPool, authService, launches, scenes,
    resetCoordinator: resetComposition.launchResetCoordinator,
    preflight: resetComposition.sceneResetPreflight });
}
async function physical(frame, selector) {
  await frame.waitForFunction(query => {
    const node = document.querySelector(query);
    return node && !node.disabled && node.getClientRects().length > 0;
  }, { timeout: 30000 }, selector);
  const handle = await frame.$(selector); assert.ok(handle);
  try {
    await handle.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
    await frame.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const hit = await handle.evaluate(node => {
      const r = node.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
      return !node.disabled && r.width > 0 && r.height > 0 && x > 0 && y > 0
        && x < innerWidth && y < innerHeight
        && (node === document.elementFromPoint(x, y) || node.contains(document.elementFromPoint(x, y)));
    });
    assert.equal(hit, true, `${selector} must be physically hit-testable`);
    await handle.click();
  } finally { await handle.dispose(); }
}
async function loginRolePage(page, { origin, username, password, role, next }, submit = physical) {
  const observed = { role, parent: null, bootstrapStatus: null,
    bootstrapRole: null, bootstrapCode: null };
  try {
    const response = await page.goto(`${origin}/secureshop/login?next=%2Fsecureshop%2F${next}`);
    assert.equal(response.status(), 200);
    await page.waitForSelector('#ss-login-user');
    await page.type('#ss-login-user', username); await page.type('#ss-login-pw', password);
    const bootstrap = page.waitForResponse(value => {
      const url = new URL(value.url());
      return url.origin === origin && url.pathname === '/api/secureshop/auth/bootstrap'
        && value.request().method() === 'POST';
    }, { timeout: 30000 });
    bootstrap.catch(() => {});
    await submit(page, 'button[type="submit"]');
    const acknowledged = await bootstrap;
    observed.bootstrapStatus = acknowledged.status();
    const body = await acknowledged.json().catch(() => null);
    observed.bootstrapRole = body?.persona?.user?.role || null;
    observed.bootstrapCode = typeof body?.code === 'string' ? body.code.slice(0, 80) : null;
    assert.equal(observed.bootstrapStatus, 200);
    assert.equal(observed.bootstrapRole, role);
    await page.waitForFunction(target => location.pathname === target,
      { timeout: 30000 }, `/secureshop/${next}`);
    return body;
  } catch (error) {
    observed.parent = await page.evaluate(() => ({
      path: `${location.pathname}${location.search}`.slice(0, 160),
      text: (document.body?.innerText || '').replace(/\s+/g, ' ').slice(0, 240),
      iframe: Boolean(document.querySelector('iframe[title="SecureShop"]')),
    })).catch(() => null);
    throw new Error(`${role} authenticated parent bootstrap failed: ${JSON.stringify(observed)}`,
      { cause: error });
  }
}
function composerSelectors(role) {
  if (!['merchant', 'admin'].includes(role)) throw new TypeError('Bound role required');
  const input = `textarea[id^="lane-${role}-assistant-"]`;
  return { input, button: role === 'admin'
    ? '[data-testid="admin-role-composer-slot"] button[type="submit"]'
    : 'form:has(textarea[id^="lane-merchant-assistant-"]) button[type="submit"]' };
}
const merchantProductDetailsAction = card => ({
  selector: `[data-testid="merchant-role-assistant"] button[aria-label="View details for ${card.title}"]`,
  message: 'Show my selected product details.',
  selection: { choiceId: card.choiceId, intent: 'product_details' },
});
async function compose(frame, role, message) {
  const { input: selector, button } = composerSelectors(role);
  await frame.waitForSelector(selector, { visible: true });
  await frame.$eval(selector, node => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(node, '');
    node.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await frame.type(selector, message);
  await physical(frame, button);
}
async function roleTurn({ page, frame, role, posts, action }) {
  const expected = posts.length + 1;
  const responsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname === `/api/secureshop/agents/${role}/assistant/chat`,
  { timeout: 120000 });
  responsePromise.catch(() => {});
  await action();
  assert.equal((await responsePromise).status(), 200);
  const until = Date.now() + 120000;
  while (Date.now() < until) {
    if (posts.length !== expected) { await delay(50); continue; }
    const posted = posts.at(-1);
    assert.ok(UUID.test(posted.body.sessionId) && UUID.test(posted.body.requestId));
    assert.ok(typeof posted.launch === 'string' && /^Bearer \S+$/.test(posted.authorization || ''));
    const response = await fetch(`${posted.origin}/api/secureshop/agents/${role}/assistant/operations/${posted.body.sessionId}/${posted.body.requestId}`,
      { headers: { 'x-owasp-ai-goat-secureshop-launch': posted.launch,
        authorization: posted.authorization } });
    if (response.status === 200) {
      const value = await response.json();
      if (value.status === 'completed') {
        assert.equal(value.stopReason, 'end_turn'); assert.equal(value.replayed, true);
        assert.equal(value.sessionId, posted.body.sessionId);
        assert.equal(value.requestId, posted.body.requestId);
        return { value, posted };
      }
    }
    await delay(100);
  }
  throw Error(`Exact ${role} turn ${expected} did not complete`);
}
async function privateTurn(agents, turn) {
  const result = await agents.query(`SELECT b.role,t.status,t.result_json
    FROM secureshop_agents.role_chat_turn_bindings b
    JOIN secureshop_agents.turn_requests t USING(session_id,request_id)
    WHERE b.session_id=$1 AND b.request_id=$2`,
  [turn.posted.body.sessionId, turn.posted.body.requestId]);
  assert.equal(result.rowCount, 1);
  assert.equal(result.rows[0].status, 'completed');
  assert.equal(result.rows[0].role, turn.posted.role);
  assert.deepEqual(result.rows[0].result_json.hops, turn.value.hops);
  assert.equal(result.rows[0].result_json.text, turn.value.text);
  return result.rows[0].result_json;
}
const count = (pool, sql, args = []) => pool.query(sql, args).then(r => Number(r.rows[0].n));

test(ASSERTION, { skip: process.env[GATE] !== '1', timeout: 540000 }, async t => {
  const a = admission();
  await fs.access(path.join(a.build, 'index.html'));
  await fs.access(path.join(a.build, 'secureshop-frame.html'));
  await fs.access(a.browser);
  await assert.rejects(fs.lstat(a.evidence), { code: 'ENOENT' });
  const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: SCOPE, roleTurns: 0, actorCalls: 0, judgeCalls: 0, errors: [] });
  const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['RUNTIME', 'MIGRATION']
    .map(role => [`${store}_${role}`, new Pool({ connectionString: a.urls[`${store}_${role}`],
      max: role === 'RUNTIME' ? 12 : 3 })])));
  const leasePool = new Pool({ connectionString: a.urls.IDENTITY_RUNTIME, max: 4 });
  let browser, profile, server, composition, reset, actorCalls = 0, judgeCalls = 0;
  let phase = 'disposable-setup';
  const modelDecisions = [], cleanupErrors = [], posts = { merchant: [], admin: [] };
  const operationReceipts = [];
  let lastTurnSummary = null;
  try {
    for (const [store, directory] of [
      ['IDENTITY', 'identity-migrations'], ['AGENTS', 'workshop-migrations/secureshop_agents'],
      ['REVIEW', 'workshop-migrations/secureshop_review'], ['COMMERCE', 'workshop-migrations/secureshop'],
    ]) await migrate(pools[`${store}_MIGRATION`], path.join(a.workspace, 'db/postgres', directory));
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
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
      .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
    const suffix = randomUUID().slice(0, 8), password = 'disposable-q03-password';
    const merchantName = `q03merchant_${suffix}`, peerName = `q03peer_${suffix}`;
    const userPrefix = `q03person_${suffix}`;
    const merchant = await auth.register({ username: merchantName,
      email: `${merchantName}@example.invalid`, password, role: 'merchant' });
    const peer = await auth.register({ username: peerName,
      email: `${peerName}@example.invalid`, password, role: 'merchant' });
    const firstUser = await auth.register({ username: `${userPrefix}a`,
      email: `${userPrefix}a@example.invalid`, password, role: 'customer' });
    const secondUser = await auth.register({ username: `${userPrefix}b`,
      email: `${userPrefix}b@example.invalid`, password, role: 'customer' });
    const admin = await auth.login({ username: 'student_admin', password: 'student123' });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit });
    const judge = async () => { judgeCalls++; throw Error('Q03 cannot invoke Judge'); };
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents,
        progress, resetComposition: reset, judge,
        expectedIdentityDatabase: new URL(a.urls.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(a.urls.AGENTS_RUNTIME).pathname.slice(1) });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository: require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
      reviewPool: review, launches: reset.launches });
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: audit.agents });
    const ollama = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)
      ({ baseUrl: process.env.OLLAMA_BASE_URL, model: 'llama3.1:8b' });
    const wireChat = ollama.transport.chat.bind(ollama.transport);
    ollama.transport.chat = async (...args) => {
      assert.ok(++actorCalls <= 20, 'bounded real Ollama wire requests');
      return wireChat(...args);
    };
    const provider = Object.freeze(Object.fromEntries(['chat', 'finalResponse'].map(method => [method,
      async input => {
        const output = await ollama[method]({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(output.provider, 'ollama'); assert.equal(output.model, 'llama3.1:8b');
        assert.equal(output.mocked, false); assert.notEqual(output.fallback, true);
        modelDecisions.push({ method, stopReason: output.stop_reason || null,
          tools: (output.tool_uses || []).slice(0, 8).map(item => ({
            name: String(item.name || '').slice(0, 80), args: boundedToolArgs(item.args),
          })) });
        return output;
      }])));
    composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        fixtures: [], requiredObjectives: ['ss_stored_browser_execution'],
        jwtSecret: 'disposable-q03-persona-secret-at-least-32-bytes', agentRuntime: { provider }, judge });
    assert.equal(composition.roleAssistants.merchant.ready, true);
    assert.equal(composition.roleAssistants.admin.ready, true);
    await composition.repositories.personas.ensureTemplates();
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const first = await bootstrap(merchant.context), sibling = await bootstrap(peer.context);
    const adminBase = await bootstrap(admin.context);
    // Registration alone creates identity-store principals. The tenant-scoped
    // administrator directory reads admitted bound actors, so admit both
    // registered customers through the same supported bootstrap path first.
    const firstUserBase = await bootstrap(firstUser.context);
    const secondUserBase = await bootstrap(secondUser.context);
    const firstScope = await composition.launches.resolveCapability(first.bearer);
    const siblingScope = await composition.launches.resolveCapability(sibling.bearer);
    const adminScope = await composition.launches.resolveCapability(adminBase.bearer);
    const firstUserScope = await composition.launches.resolveCapability(firstUserBase.bearer);
    const secondUserScope = await composition.launches.resolveCapability(secondUserBase.bearer);
    assert.equal(firstUserScope.platformOwnerId, adminScope.platformOwnerId);
    assert.equal(secondUserScope.platformOwnerId, adminScope.platformOwnerId);
    assert.equal(firstUserBase.persona.user.id, firstUser.user.id);
    assert.equal(secondUserBase.persona.user.id, secondUser.user.id);
    const merchantActor = await composition.personaAuth.authenticateBoundToken({
      scope: firstScope, token: first.persona.token });
    const peerActor = await composition.personaAuth.authenticateBoundToken({
      scope: siblingScope, token: sibling.persona.token });
    const adminActor = await composition.personaAuth.authenticateBoundToken({
      scope: adminScope, token: adminBase.persona.token });
    const ownPersona = { id: merchantActor.user.id, role: 'merchant' };
    const peerPersona = { id: peerActor.user.id, role: 'merchant' };
    const ownSession = { sessionId: merchantActor.sessionId,
      authorityVersion: merchantActor.authorityVersion };
    const peerSession = { sessionId: peerActor.sessionId,
      authorityVersion: peerActor.authorityVersion };
    const firstTarget = await composition.catalog.prepareTarget({ scope: firstScope,
      persona: ownPersona });
    const peerTarget = await composition.catalog.prepareTarget({ scope: siblingScope,
      persona: peerPersona });
    assert.equal(firstTarget.targetId, peerTarget.targetId,
      'sibling product must share the same scene to test merchant filtering');
    await composition.catalog.prepareTarget({ scope: adminScope,
      persona: { id: adminActor.user.id, role: 'admin' } });
    const names = [`Q03 lantern amber ${suffix}`, `Q03 lantern azure ${suffix}`];
    const products = [];
    for (const [index, name] of names.entries()) products.push(await composition.catalog.createMerchantProduct({
      scope: firstScope, persona: ownPersona, personaSession: ownSession,
      listing: { name, description: `Owned ambiguity ${index}`, price: 12.5 + index,
        category: 'fixture', templateSource: '{{source}}', images: [] } }));
    const foreignProduct = await composition.catalog.createMerchantProduct({
      scope: siblingScope, persona: peerPersona, personaSession: peerSession,
      listing: { name: `Q03 lantern peer ${suffix}`, description: 'Excluded sibling merchant',
        price: 14.5, category: 'fixture', templateSource: '{{source}}', images: [] } });
    assert.equal(new Set([...products, foreignProduct].map(p => p.productId)).size, 3);
    const seededSearch = await composition.catalog.listMerchantProducts({ scope: firstScope,
      persona: ownPersona, personaSession: ownSession,
      query: { page: 1, perPage: 5, sort: 'updated_desc', search: 'Q03 lantern', status: 'active' } });
    assert.deepEqual(new Set(seededSearch.products.map(product => product.name)), new Set(names));
    assert.ok(!seededSearch.products.some(product => product.name.includes('peer')));
    const baseline = await Promise.all([
      review.query(`SELECT target_id,product_id,name,retailer_id,price,stock_quantity
        FROM secureshop_review.product_target_products ORDER BY target_id,product_id`),
      review.query(`SELECT target_id,product_id,price,stock_quantity
        FROM secureshop_review.product_target_listing_overlays ORDER BY target_id,product_id`),
      identity.query(`SELECT principal_id,username,role,is_active,authority_version
        FROM secureshop_auth.principals ORDER BY principal_id`),
      identity.query(`SELECT tenant_id,principal_id,role,is_active,membership_version
        FROM secureshop_auth.tenant_memberships ORDER BY tenant_id,principal_id`),
    ]);
    const inventoryBefore = await count(review,
      'SELECT count(*)::int AS n FROM secureshop_review.owned_inventory_operations');
    const adminBefore = await count(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.tenant_admin_operations');
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const protectedReset = createProtectedReset({ identityPool: identity, authService: auth,
      launches: composition.launches, scenes, resetComposition: reset });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity,
        reviewPool: review, commercePool: commerce });
    const mounted = Object.freeze({ ...composition,
      standaloneAuth: Object.freeze({ service: auth, bootstrap, mode: standaloneMode,
        reset: protectedReset, assessmentObjectives: assessmentCatalog }), publicCatalog,
      personaInbox: Object.freeze({ ready: true, router: express.Router() }),
      mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
      ssrf: Object.freeze({ ready: true, router: express.Router() }) });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        authenticateToken: (_request, response) => response.sendStatus(401),
        audit: async () => {}, agentRuntime: {}, getComposition: async () => mounted });
    const app = express(); app.use(express.json());
    server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ service: auth, bootstrap, mode: standaloneMode,
        reset: protectedReset, assessmentObjectives: assessmentCatalog,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', (request, _response, next) => {
      const match = /^\/agents\/(merchant|admin)\/assistant\/chat$/.exec(request.path);
      if (request.method === 'POST' && match) posts[match[1]].push({
        role: match[1], origin, body: structuredClone(request.body),
        launch: request.headers['x-owasp-ai-goat-secureshop-launch'],
        authorization: request.headers.authorization });
      next();
    });
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
      .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
    app.use('/api', (_request, response) => response.status(404).json({ error: 'Outside Q03 qualifier' }));
    app.use(express.static(a.build, opaqueFrameStatic()));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: a.build }));
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-q03-role-ambiguity-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath: a.browser });
    const pages = {};
    for (const [role, username, next] of [
      ['merchant', merchantName, 'merchant'], ['admin', 'student_admin', 'admin'],
    ]) {
      const context = await browser.createBrowserContext();
      const page = await context.newPage(); pages[role] = page;
      await page.setViewport({ width: 1280, height: 900 });
      await page.setRequestInterception(true);
      page.on('request', request => request.url().startsWith(`${origin}/`)
        ? request.continue() : request.abort());
      if (role === 'admin') page.on('response', response => {
        const pathname = new URL(response.url()).pathname;
        const match = /^\/api\/secureshop\/agents\/admin\/assistant\/operations\/([0-9a-f-]{36})\/([0-9a-f-]{36})$/i
          .exec(pathname);
        if (response.request().method() === 'GET' && match && response.status() === 200)
          void response.json().then(value => operationReceipts.push({
            sessionId: match[1].toLowerCase(), requestId: match[2].toLowerCase(), value,
          })).catch(() => {});
      });
      phase = `${role}-authenticated-bootstrap`;
      await loginRolePage(page, { origin, username,
        password: role === 'admin' ? 'student123' : password, role, next });
    }
    let merchantFrame = await frameFor(pages.merchant, 'merchant');
    let adminFrame = await frameFor(pages.admin, 'admin');
    await merchantFrame.waitForSelector('select[id^="agent-lane-task-merchant-"]');
    await merchantFrame.select('select[id^="agent-lane-task-merchant-"]', 'assistant');
    await merchantFrame.waitForSelector('[data-testid="merchant-role-assistant"]');
    await adminFrame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea');
    const merchantCookie = (await pages.merchant.cookies(`${origin}/api/secureshop/auth/session`))
      .find(item => item.name === 'owasp_ai_goat_shop_session');
    const adminCookie = (await pages.admin.cookies(`${origin}/api/secureshop/auth/session`))
      .find(item => item.name === 'owasp_ai_goat_shop_session');
    assert.equal(merchantCookie?.httpOnly, true); assert.equal(adminCookie?.httpOnly, true);
    assert.equal((await auth.authenticate(merchantCookie.value))?.principalId, merchant.context.principalId);
    assert.equal((await auth.authenticate(adminCookie.value))?.principalId, admin.context.principalId);
    status.genuineRoleSessions = true;

    phase = 'merchant-broad-search';
    const merchantSearch = await roleTurn({ page: pages.merchant, frame: merchantFrame,
      role: 'merchant', posts: posts.merchant,
      action: () => compose(merchantFrame, 'merchant', 'Search my products using only the broad text "Q03 lantern". Show every match and ask me to choose.') });
    lastTurnSummary = boundedTurnSummary(merchantSearch.value);
    status.roleTurns++;
    const merchantBrowserScope = await composition.launches.resolveCapability(merchantSearch.posted.launch);
    const merchantBrowserActor = await composition.personaAuth.authenticateBoundToken({
      scope: merchantBrowserScope,
      token: merchantSearch.posted.authorization.slice('Bearer '.length) });
    assert.equal(merchantBrowserActor.user.id, ownPersona.id);
    assert.equal(merchantBrowserActor.user.role, 'merchant');
    const merchantPrivate = await privateTurn(agents, merchantSearch);
    assert.ok(merchantSearch.value.hops.some(hop => hop.tool === 'merchant.catalog_search' && !hop.error));
    const merchantCards = merchantSearch.value.cards.filter(card => card.kind === 'merchant_product');
    assert.deepEqual(new Set(merchantCards.map(card => card.title)), new Set(names));
    assert.equal(merchantCards.length, 2);
    assert.ok(!merchantCards.some(card => card.title.includes('peer')));
    assert.equal(new Set(merchantCards.map(card => card.choiceId)).size, 2);
    const merchantChoices = merchantPrivate.taskMetadata.roleChat.choices;
    assert.deepEqual(new Set(merchantChoices.map(choice => choice.sourceId)),
      new Set(products.map(product => product.productId)));
    assert.ok(!merchantChoices.some(choice => choice.sourceId === foreignProduct.productId));
    await merchantFrame.waitForFunction(expected => {
      const root = document.querySelector('[aria-label="Merchant product choices"]');
      return root && expected.every(title => [...root.querySelectorAll('strong')]
        .some(node => node.textContent === title));
    }, { timeout: 30000 }, names);
    status.merchantAmbiguousChoices = true;
    assert.match(merchantSearch.value.text, /choose|which|select|clarif/i);
    assert.equal(merchantSearch.value.inventoryProposal, null);
    assert.equal(await count(review,
      'SELECT count(*)::int AS n FROM secureshop_review.owned_inventory_operations'), inventoryBefore);
    status.merchantClarificationNoEffect = true;
    phase = 'merchant-physical-choice';
    const selectedProduct = merchantCards.find(card => card.title === names[1]);
    const detailsAction = merchantProductDetailsAction(selectedProduct);
    const merchantSelected = await roleTurn({ page: pages.merchant, frame: merchantFrame,
      role: 'merchant', posts: posts.merchant,
      action: () => physical(merchantFrame, detailsAction.selector) });
    lastTurnSummary = boundedTurnSummary(merchantSelected.value);
    status.roleTurns++; status.merchantPhysicalSelection = true;
    assert.equal(merchantSelected.posted.body.message, detailsAction.message);
    assert.deepEqual(merchantSelected.posted.body.selection, detailsAction.selection);
    const selectedMerchantPrivate = await privateTurn(agents, merchantSelected);
    assert.ok(merchantSelected.value.hops.some(hop => hop.tool === 'merchant.catalog_search'
      && hop.params?.choiceId === selectedProduct.choiceId && !hop.error));
    for (const proposal of ['inventoryProposal', 'pricingProposal', 'listingProposal',
      'listingCreateProposal', 'reviewProposal']) assert.equal(merchantSelected.value[proposal], null,
      `read-only selected product turn cannot create ${proposal}`);
    const privateMerchantChoice = merchantChoices.find(choice => choice.choiceId === selectedProduct.choiceId);
    assert.equal(privateMerchantChoice.sourceId, products[1].productId);
    assert.ok(selectedMerchantPrivate.taskMetadata.roleChat.choices.some(choice =>
      choice.sourceId === products[1].productId && choice.choiceId !== selectedProduct.choiceId
      && choice.snapshotSha256 === privateMerchantChoice.snapshotSha256));
    status.merchantSelectedIdentityBound = true;

    phase = 'admin-broad-search';
    const adminSearch = await roleTurn({ page: pages.admin, frame: adminFrame,
      role: 'admin', posts: posts.admin,
      action: () => compose(adminFrame, 'admin', `Search tenant usernames using only the broad text "${userPrefix}". Show every match and ask me to choose.`) });
    lastTurnSummary = boundedTurnSummary(adminSearch.value);
    status.roleTurns++;
    const adminBrowserScope = await composition.launches.resolveCapability(adminSearch.posted.launch);
    const adminBrowserActor = await composition.personaAuth.authenticateBoundToken({
      scope: adminBrowserScope,
      token: adminSearch.posted.authorization.slice('Bearer '.length) });
    assert.equal(adminBrowserActor.user.id, adminActor.user.id);
    assert.equal(adminBrowserActor.user.role, 'admin');
    const directAdminSearch = await composition.admin.users({ scope: adminBrowserScope,
      persona: { id: adminBrowserActor.user.id, role: 'admin' },
      personaSession: { sessionId: adminBrowserActor.sessionId,
        authorityVersion: adminBrowserActor.authorityVersion },
      query: { page: 1, pageSize: 5, search: userPrefix, role: '', banned: '' } });
    assert.deepEqual(new Set(directAdminSearch.users.map(user => user.username)),
      new Set([`${userPrefix}a`, `${userPrefix}b`]));
    assert.deepEqual(new Set(directAdminSearch.users.map(user => user.id)),
      new Set([firstUser.user.id, secondUser.user.id]));
    const adminPrivate = await privateTurn(agents, adminSearch);
    assert.ok(adminSearch.value.hops.some(hop => hop.tool === 'admin.users_search' && !hop.error));
    const userNames = [`${userPrefix}a`, `${userPrefix}b`];
    const userCards = adminSearch.value.cards.filter(card => card.kind === 'tenant_user');
    assert.equal(userCards.length, 2);
    assert.deepEqual(new Set(userCards.map(card => card.title)), new Set(userNames));
    assert.equal(new Set(userCards.map(card => card.choiceId)).size, 2);
    assert.deepEqual(new Set(adminPrivate.taskMetadata.roleChat.choices.map(choice => choice.sourceId)),
      new Set([firstUser.user.id, secondUser.user.id]));
    await adminFrame.waitForFunction(expected => {
      const root = document.querySelector('[aria-label="Admin user choices"]');
      return root && expected.every(title => [...root.querySelectorAll('strong')]
        .some(node => node.textContent === title));
    }, { timeout: 30000 }, userNames);
    status.adminAmbiguousChoices = true;
    assert.match(adminSearch.value.text, /choose|which|select|clarif/i);
    assert.equal(adminSearch.value.userAdministrationProposal, null);
    assert.equal(await count(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.tenant_admin_operations'), adminBefore);
    status.adminClarificationNoEffect = true;
    const adminWireBeforeReload = actorCalls;
    const adminPostsBeforeReload = posts.admin.length;
    const adminReadsBeforeReload = operationReceipts.filter(row =>
      row.sessionId === adminSearch.posted.body.sessionId
        && row.requestId === adminSearch.posted.body.requestId).length;
    phase = 'admin-acknowledged-reload';
    await pages.admin.reload({ waitUntil: 'domcontentloaded' });
    adminFrame = await frameFor(pages.admin, 'admin');
    await adminFrame.waitForFunction(expected => {
      const root = document.querySelector('[aria-label="Admin user choices"]');
      return root && expected.every(title => [...root.querySelectorAll('strong')]
        .some(node => node.textContent === title));
    }, { timeout: 30000 }, userNames);
    const adminReadDeadline = Date.now() + 30000;
    while (Date.now() < adminReadDeadline && operationReceipts.filter(row =>
      row.sessionId === adminSearch.posted.body.sessionId
        && row.requestId === adminSearch.posted.body.requestId).length <= adminReadsBeforeReload) await delay(25);
    const reloadedAdminRead = operationReceipts.filter(row =>
      row.sessionId === adminSearch.posted.body.sessionId
        && row.requestId === adminSearch.posted.body.requestId).at(-1);
    assert.ok(reloadedAdminRead && operationReceipts.filter(row =>
      row.sessionId === adminSearch.posted.body.sessionId
        && row.requestId === adminSearch.posted.body.requestId).length > adminReadsBeforeReload,
    'admin reload must perform a new protected GET for the exact saved user choices');
    assert.deepEqual(reloadedAdminRead.value, adminSearch.value);
    assert.equal(actorCalls, adminWireBeforeReload);
    assert.equal(posts.admin.length, adminPostsBeforeReload);
    phase = 'admin-physical-preparation';
    const selectedUser = userCards.find(card => card.title === userNames[1]);
    const newRole = `[data-testid="admin-role-assistant"] select[aria-label="New role for ${userNames[1]}"]`;
    await adminFrame.select(newRole, 'merchant');
    const roleButton = `[data-testid="admin-role-assistant"] button[aria-label="Review role change for ${userNames[1]}"]`;
    const prepared = await roleTurn({ page: pages.admin, frame: adminFrame,
      role: 'admin', posts: posts.admin, action: () => physical(adminFrame, roleButton) });
    lastTurnSummary = boundedTurnSummary(prepared.value);
    status.roleTurns++; status.adminPhysicalSelection = true;
    assert.deepEqual(prepared.posted.body.selection,
      { choiceId: selectedUser.choiceId, intent: 'user_role', newRole: 'merchant' });
    const preparedPrivate = await privateTurn(agents, prepared);
    assert.ok(prepared.value.hops.some(hop => hop.tool === 'admin.role_change_prepare'
      && hop.params?.choiceId === selectedUser.choiceId && !hop.error));
    const privateAdminChoice = adminPrivate.taskMetadata.roleChat.choices
      .find(choice => choice.choiceId === selectedUser.choiceId);
    assert.equal(privateAdminChoice.sourceId, secondUser.user.id);
    assert.equal(prepared.value.userAdministrationProposal?.target.userId, secondUser.user.id);
    assert.equal(prepared.value.userAdministrationProposal?.target.username, userNames[1]);
    assert.equal(prepared.value.userAdministrationProposal?.target.choiceId, selectedUser.choiceId);
    assert.equal(prepared.value.userAdministrationProposal?.role, 'merchant');
    assert.equal(prepared.value.userAdministrationProposal?.action, 'set_role');
    assert.equal(preparedPrivate.taskMetadata.roleChat.userAdministrationProposal.target.userId,
      secondUser.user.id);
    status.adminSelectedIdentityBound = true;
    await adminFrame.waitForSelector('section[aria-label="Admin user change review"]');
    assert.equal(await count(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.tenant_admin_operations'), adminBefore);
    const member = (await identity.query(`SELECT role FROM secureshop_auth.tenant_memberships
      WHERE principal_id=$1`, [secondUser.context.principalId])).rows[0];
    assert.equal(member.role, 'customer');
    status.adminProposalNoEffect = true;
    status.exactSavedGet = true;

    phase = 'sibling-and-effect-fences';
    // A merchant choice issued in another real bound session fails before any
    // provider call, even when that sibling's product lives in the same scene.
    const beforeForeignWire = actorCalls;
    const siblingSession = await composition.roleAssistants.merchant.runtime.createSession(
      siblingScope, peerPersona, peerSession);
    await assert.rejects(() => composition.roleAssistants.merchant.runtime.run({
      scope: siblingScope, persona: peerPersona, personaSession: peerSession,
      sessionId: siblingSession.id, requestId: randomUUID(),
      message: 'Use my selected option.', selection: { choiceId: selectedProduct.choiceId },
      stream: { send() {} },
    }), error => error?.code === 'ROLE_CHOICE_STALE');
    assert.equal(actorCalls, beforeForeignWire);
    status.siblingExcluded = true;
    const after = await Promise.all([
      review.query(`SELECT target_id,product_id,name,retailer_id,price,stock_quantity
        FROM secureshop_review.product_target_products ORDER BY target_id,product_id`),
      review.query(`SELECT target_id,product_id,price,stock_quantity
        FROM secureshop_review.product_target_listing_overlays ORDER BY target_id,product_id`),
      identity.query(`SELECT principal_id,username,role,is_active,authority_version
        FROM secureshop_auth.principals ORDER BY principal_id`),
      identity.query(`SELECT tenant_id,principal_id,role,is_active,membership_version
        FROM secureshop_auth.tenant_memberships ORDER BY tenant_id,principal_id`),
    ]);
    assert.deepEqual(after.map(row => row.rows), baseline.map(row => row.rows));
    assert.equal(await count(review,
      'SELECT count(*)::int AS n FROM secureshop_review.owned_inventory_operations'), inventoryBefore);
    assert.equal(await count(identity,
      'SELECT count(*)::int AS n FROM secureshop_auth.tenant_admin_operations'), adminBefore);
    status.noMutation = true;
    assert.equal(judgeCalls, 0); status.zeroJudge = true;
    assert.equal(posts.merchant.length, 2); assert.equal(posts.admin.length, 2);
    assert.equal(status.roleTurns, 4); assert.ok(actorCalls >= 8 && actorCalls <= 20);
    status.passed = true;
  } catch (error) {
    status.errors.push(String(error.code || error.name || 'Error'));
    t.diagnostic(JSON.stringify({ phase, modelDecisions,
      lastTurnSummary,
      roleTurns: status.roleTurns, actorCalls, judgeCalls,
      errorCode: error.code || error.name || 'Error' }));
    throw error;
  } finally {
    status.actorCalls = actorCalls; status.judgeCalls = judgeCalls;
    for (const [label, close] of [
      ['browser', async () => browser?.close()],
      ['server', async () => server && new Promise((resolve, reject) =>
        server.close(error => error ? reject(error) : resolve()))],
      ['browser-assessment', async () => composition?.closeBrowserAssessment?.()],
      ['feature-transport', async () => reset?.closeFeatureTransports?.()],
      ['audit-ledger', async () => reset?.auditLedger?.close?.()],
      ['lease', async () => leasePool.end()],
      ...Object.entries(pools).map(([name, pool]) => [name, async () => pool.end()]),
      ['profile', async () => { if (profile) await fs.rm(profile, { recursive: true, force: true }); }],
    ]) try { await close(); } catch (error) { cleanupErrors.push(`${label}:${error.code || error.name}`); }
    status.fixtureCleaned = cleanupErrors.length === 0;
    if (!status.fixtureCleaned) status.passed = false;
    assert.ok(Buffer.byteLength(JSON.stringify(status), 'utf8') < 4096);
    await fs.writeFile(a.evidence, `${JSON.stringify(status)}\n`, { flag: 'wx', mode: 0o600 });
    if (cleanupErrors.length) throw Error(`Q03 cleanup failed: ${cleanupErrors.join(', ')}`);
  }
  validateRoleAmbiguityReceipt(status);
});

module.exports = { ASSERTION, _internals: { admission, frameFor, physical,
  opaqueFrameStatic, createProtectedReset, loginRolePage, composerSelectors,
  merchantProductDetailsAction, boundedToolArgs, boundedTurnSummary } };
