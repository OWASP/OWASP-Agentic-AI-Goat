'use strict';

// Scoped production HTTP authority proof, not full startup/browser/objective qualification.
// Role supervisors use an honestly mocked provider. Ticket and inventory confirmation require
// genuine model provenance: its separate composition uses the unmodified installed
// Ollama adapter. Only the disposable native launcher may enable this fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { TERMINALS, DENIALS, CUSTOMER_PRE_ADMISSION_TERMINALS,
  CUSTOMER_PRE_ADMISSION_DENIALS, checkoutPreflightDiagnostic } = require('../secureshopTerminalAuthorityMatrix.contract.test');
const PREFIX = 'PG_SECURESHOP_TERMINAL_AUTHORITY_MATRIX_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const NAMES = { IDENTITY: 'identity', AGENTS: 'secureshop_agents', REVIEW: 'secureshop_review', COMMERCE: 'secureshop' };
const ENABLED = process.env.SECURESHOP_TERMINAL_AUTHORITY_MATRIX_NATIVE === '1';
const TITLE = 'Q07 five production confirmation terminals preserve durable effects across 25 authority denials';

function disposableUrls() {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes', 'Explicit disposable launcher required');
  const urls = {}; let nonce, port;
  for (const store of STORES) for (const role of ['RUNTIME', 'MIGRATION']) {
    assert.ok(process.env[`${PREFIX}${store}_${role}_URL`], `Missing ${store}/${role} disposable URL`);
    const url = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
    assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.username, `dvaia_${NAMES[store]}_${role.toLowerCase()}`);
    assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
    const match = new RegExp(`^/dvaia_test_agent_host_([a-f0-9]{12})_${NAMES[store]}$`).exec(url.pathname);
    assert.ok(match, `Owned disposable ${store} required`);
    nonce ??= match[1]; port ??= url.port;
    assert.equal(match[1], nonce); assert.equal(url.port, port);
    urls[`${store}_${role}`] = url.href;
  }
  assert.equal(new Set(STORES.map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return urls;
}
async function migrateAndSeed(pools) {
  for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
    ['AGENTS', 'workshop-migrations/secureshop_agents'], ['REVIEW', 'workshop-migrations/secureshop_review'],
    ['COMMERCE', 'workshop-migrations/secureshop']]) {
    const dir = path.resolve('db/postgres', directory);
    await migrate(pools[`${store}_MIGRATION`], dir);
    assert.deepEqual(await migrate(pools[`${store}_MIGRATION`], dir), [], `${store} migration no-op`);
  }
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
  const client = await pools.COMMERCE_MIGRATION.connect();
  try { await client.query('BEGIN'); await require('../../server/database/postgres/secureshopSeed').seedSecureShop(client); await client.query('COMMIT'); }
  catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}
const TABLES = Object.freeze({
  REVIEW: ['product_target_products', 'product_target_listing_overlays', 'product_target_support_tickets',
    'product_target_support_ticket_receipts', 'owned_merchant_listing_create_receipts', 'owned_inventory_operations',
    'product_target_cart_items', 'product_target_addresses', 'practice_payment_methods',
    'product_target_orders', 'chat_commerce_operations'],
  AGENTS: ['bound_prompt_policy_heads', 'bound_prompt_policy_current', 'bound_prompt_policy_revisions',
    'bound_prompt_policy_operations', 'bound_tool_policy_heads', 'bound_tool_policy_overrides', 'bound_tool_policy_operations'],
});
async function effectSnapshot(pools) {
  const snapshot = {};
  for (const [store, tables] of Object.entries(TABLES)) for (const table of tables) {
    snapshot[table] = (await pools[`${store}_RUNTIME`].query(
      `SELECT to_jsonb(t) AS row FROM ${NAMES[store]}.${table} t ORDER BY to_jsonb(t)::text`)).rows;
  }
  return snapshot;
}
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const receiptTable = { 'customer-ticket': 'product_target_support_ticket_receipts',
  'merchant-listing': 'owned_merchant_listing_create_receipts', 'merchant-inventory': 'owned_inventory_operations',
  'admin-policy': 'bound_prompt_policy_operations', 'admin-acl': 'bound_tool_policy_operations' };
const CUSTOMER_RECEIPT_KINDS = Object.freeze({ cart: 'cart.add', address: 'address.create',
  payment: 'payment.create', checkout: 'checkout.confirm', profile: 'profile.update' });

test(TITLE, { skip: !ENABLED, timeout: 600000 }, async t => {
  assert.equal(path.resolve(__dirname, '../..'), process.cwd(), 'Current checkout only');
  const urls = disposableUrls();
  const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
    [key, new Pool({ connectionString, max: key.endsWith('RUNTIME') ? 12 : 3 })]));
  const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 4 });
  let server, reset, inventory, ticketComposition;
  try {
    await migrateAndSeed(pools);
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
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
      const grading = await require('../../server/services/secureshopGradingBootstrap')
        .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents, progress,
          resetComposition: reset,
          expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
          expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
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
      await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
        .assertBoundToolPolicyReadiness(agents);

    let plan = null, awaitingTerminal = false, providerCalls = 0, judgeCalls = 0;
    const final = () => ({ provider: 'mock', model: 'q07-controlled-no-credit', mocked: true,
      fallback: false, stop_reason: 'end_turn', text: 'Review the saved result.', tool_uses: [] });
    const provider = Object.freeze({
      provider: 'mock', model: 'q07-controlled-no-credit',
      async chat() {
        providerCalls += 1;
        if (awaitingTerminal) { awaitingTerminal = false; return final(); }
        assert.ok(plan?.tool, 'Unexpected controlled model call');
        const { tool: name, args } = plan; plan = null; awaitingTerminal = true;
        return { ...final(), stop_reason: 'tool_use', tool_uses: [{ id: randomUUID(), name, args }] };
      },
      async finalResponse() { providerCalls += 1; awaitingTerminal = false; return { ...final(), responseMode: 'structured_final' }; },
    });
    const judge = async () => { judgeCalls += 1; throw new Error('Q07 never invokes objective Judge'); };
    const promptPolicyRepository = require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
      .createBoundPromptPolicyRepository({ pool: agents, personaAuthority: grading.personaAuthority,
        audit: reset.audit.agents, modeAuthority,
        checkRunBinding: require('../../server/services/secureshopPromptPolicyRunBinding').createPromptPolicyRunBinding({ identityPool: identity }) });
    await promptPolicyRepository.checkReadiness();
    const couponDependencies = await require('../../server/services/secureshopCouponProduction')
      .prepareCommerceDependencies({ reviewPool: review, launches: reset.launches, mode: 'vuln', modeAuthority });
    const common = { identityPool: identity, agentsPool: agents, reviewPool: review, commercePool: commerce,
      resetComposition: reset, gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository, couponDependencies,
      inventoryApplication: () => inventory?.application, fixtures: [], requiredObjectives: ['ss_stored_browser_execution'],
      jwtSecret: 'q07-disposable-persona-signing-secret-at-least-32-bytes', judge };
    const composition = require('../../server/services/secureshopBoundReviewComposition').createSecureShopBoundReviewComposition({
      ...common, agentRuntime: { provider }, promptPolicyRepository, taskPoliciesEnabled: true,
      promptPolicyRenderer: { async render() { throw new Error('Fixed policy confirmation must not invoke renderer'); } },
    });
    await composition.repositories.personas.ensureTemplates();
    const ticketProvider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      baseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434', model: 'llama3.1:8b' });
    ticketComposition = require('../../server/services/secureshopBoundReviewComposition').createSecureShopBoundReviewComposition({
      ...common, agentRuntime: { provider: ticketProvider } });
    const inventoryPolicies = await require('../../server/services/secureshopAgentSnapshotPolicies')
      .createAgentSnapshotPolicyResolver({ personaAuthority: grading.personaAuthority,
        agentsPool: agents, identityPool: identity, auditStore: reset.audit.agents })();
    inventory = await require('../../server/services/secureshopInventoryProduction').createInventoryProduction({
      enabled: true, identityPool: identity, agentsPool: agents, reviewPool: review, resetComposition: reset,
      catalog: composition.catalog, personaAuthority: grading.personaAuthority, provider: ticketProvider,
      promptPolicyRepository: inventoryPolicies, toolPolicyRepository,
      assessmentDependencies: { ...grading.assessmentDependencies, judge },
      authenticatePersona: composition.personaAuth.authenticatePersona, mode: 'vuln', modeAuthority,
      resolveExistingTarget: scope => scenes.readExisting(scope) });
    assert.equal(inventory.ready, true);
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
      launches: composition.launches, personaAuth: composition.personaAuth, authService: auth });
    const standaloneMode = require('../../server/services/secureshopStandaloneMode').createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const resetService = require('../../server/services/secureshopStandaloneReset').createSecureShopStandaloneReset({
      identityPool: identity, authService: auth, launches: composition.launches, scenes,
      resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight });
    const gateway = require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({
      launches: composition.launches, authenticatePersona: composition.personaAuth.authenticatePersona,
      personaAuth: composition.personaAuth, reviewsRouter: composition.router, browserRouter: composition.browserRouter,
      catalog: composition.catalog, commerce: composition.commerce, account: composition.account, admin: composition.admin,
      scenes, inventoryRouter: inventory.router, customerChatRouter: ticketComposition.customerChat.router,
      refundRouter: composition.refund.router,
      ticketAgentRouter: ticketComposition.ticketAgent.router,
      merchantAssistantRouter: composition.roleAssistants.merchant.router, adminAssistantRouter: composition.roleAssistants.admin.router,
    });
    const app = express(); app.use(express.json());
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({ getGateway: () => gateway }));
    server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    const origin = `http://127.0.0.1:${server.address().port}/api/secureshop`;
    const request = async (actor, pathname, body, overrides = {}) => {
      const response = await fetch(origin + pathname, { method: body === undefined ? 'GET' : 'POST',
        headers: { 'content-type': 'application/json', 'x-dvaia-secureshop-launch': actor.boot.bearer,
          authorization: `Bearer ${actor.boot.persona.token}`, ...overrides },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(150000) });
      const text = await response.text(); let data; try { data = JSON.parse(text); } catch { data = text; }
      return { status: response.status, data };
    };
    const suffix = randomUUID().slice(0, 8);
    async function actor(role, label) {
      const login = role === 'admin' ? await auth.login({ username: 'student_admin', password: 'student123' })
        : await auth.register({ username: `q07_${label}_${suffix}`, email: `q07-${label}-${suffix}@example.invalid`, password: 'q07-disposable-password', role });
      const boot = await bootstrap(login.context);
      const scope = await composition.launches.resolveCapability(boot.bearer);
      const verified = await composition.personaAuth.authenticateBoundToken({ scope, token: boot.persona.token });
      const persona = { id: verified.user.id, role };
      const target = await composition.catalog.prepareTarget({ scope, persona });
      return { login, boot, scope, persona, target, personaSession: { sessionId: verified.sessionId, authorityVersion: verified.authorityVersion } };
    }
    const actors = {};
    for (const role of ['customer', 'merchant', 'admin']) {
      actors[role] = {};
      for (const group of ['main', 'revoke', 'stale']) actors[role][group] = await actor(role, `${role.slice(0, 1)}_${group}`);
    }
    // Policy creation uses fixed canonical mode so its real production publish
    // path cannot execute a renderer. This does not change ordinary ACL semantics.
    const adminMode = await standaloneMode.get(actors.admin.main.login.context);
    if (adminMode.mode !== 'fixed') await standaloneMode.set(actors.admin.main.login.context, { mode: 'fixed', expectedRevision: adminMode.revision });

    // Provision only synthetic tenant membership with the migration role. Every
    // execution credential is subsequently issued by the real auth service.
    const tenantId = randomUUID(), tenantSlug = `q07_${suffix}`;
    const provision = await pools.IDENTITY_MIGRATION.connect();
    try {
      await provision.query('BEGIN');
      // A seed merchant can be selected only after its active membership exists.
      // Follow the same insert -> enroll -> select sequence as fresh shop seeding.
      await provision.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)', [tenantId, tenantSlug]);
      for (const role of ['customer', 'merchant', 'admin']) {
        const principal = actors[role].main.login.context;
        await provision.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)`,
        [tenantId, principal.principalId, principal.shopUserId, role]);
      }
      const merchantId = actors.merchant.main.login.context.shopUserId;
      const selected = await provision.query(`UPDATE secureshop_auth.tenants
        SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL
        RETURNING seed_merchant_id`, [tenantId, merchantId]);
      assert.equal(selected.rowCount, 1);
      assert.equal(Number(selected.rows[0].seed_merchant_id), merchantId);
      await provision.query('COMMIT');
    } catch (error) { await provision.query('ROLLBACK'); throw error; }
    finally { provision.release(); }
    const foreignAuth = require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
      repository: require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({ pool: identity, executionTenantSlug: tenantSlug }) });
    const foreignBootstrap = require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
      launches: composition.launches, personaAuth: composition.personaAuth, authService: foreignAuth });
    const foreign = {};
    for (const role of ['customer', 'merchant', 'admin']) {
      const base = actors[role].main.login.context;
      const login = await foreignAuth.login({ username: base.username, password: role === 'admin' ? 'student123' : 'q07-disposable-password' });
      const boot = await foreignBootstrap(login.context), scope = await composition.launches.resolveCapability(boot.bearer);
      const persona = { id: boot.persona.user.id, role }, target = await composition.catalog.prepareTarget({ scope, persona });
      foreign[role] = { login, boot, scope, persona, target };
      assert.notEqual(scope.platformOwnerId, actors[role].main.scope.platformOwnerId);
      assert.notEqual(target.targetId, actors[role].main.target.targetId);
    }
    const identityRepository = require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
    const platformAdapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({
      repository: identityRepository, jwtSecret: common.jwtSecret });
    const passwordHash = await require('bcryptjs').hash('q07-platform-password', 4);
    const platformUser = await identityRepository.createUser({ username: `q07_platform_${suffix}`, email: `q07-platform-${suffix}@example.invalid`, passwordHash });
    const platformSession = await platformAdapter.createSession({ ...platformUser, password: passwordHash }, {});
    assert.ok(await platformAdapter.validateSession(platformSession.token), 'Substitution token has canonical live platform authority');

    const creditSnapshot = async () => ({
      shopJudgments: (await identity.query('SELECT to_jsonb(t) AS row FROM secureshop_auth.assessment_judgments t ORDER BY to_jsonb(t)::text')).rows,
      shopCompletions: (await identity.query('SELECT to_jsonb(t) AS row FROM secureshop_auth.assessment_completions t ORDER BY to_jsonb(t)::text')).rows,
      shopContributions: (await identity.query('SELECT to_jsonb(t) AS row FROM secureshop_auth.assessment_contributions t ORDER BY to_jsonb(t)::text')).rows,
      completions: (await identity.query('SELECT to_jsonb(t) AS row FROM workshop_platform.completions t ORDER BY to_jsonb(t)::text')).rows,
      judgments: (await identity.query('SELECT to_jsonb(t) AS row FROM workshop_platform.objective_judgments t ORDER BY to_jsonb(t)::text')).rows,
    });
    const creditBefore = await creditSnapshot();
    const customerProduct = (await commerce.query(`SELECT id,name,stock_quantity FROM secureshop.products
      WHERE status='active' AND stock_quantity>0 ORDER BY id LIMIT 1`)).rows[0];
    assert.ok(customerProduct, 'Seeded customer product required for current cart/checkout admission');
    assert.ok(Number(customerProduct.stock_quantity) >= 1,
      'Selected current customer product must retain positive stock before checkout preflight');
    const ticketSessions = [];
    const ticketTrace = async () => (await agents.query(`SELECT event_id,session_id,step,kind,provider,result_json
      FROM secureshop_agents.agent_trace WHERE session_id=ANY($1::text[]) ORDER BY id`, [ticketSessions])).rows;
    const inventoryTrace = async () => (await agents.query(`SELECT t.event_id,t.session_id,t.step,t.kind,t.provider,t.result_json
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.conversation_purpose=$1 ORDER BY t.id`,
    [require('../../server/services/secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.inventory])).rows;
    async function turn(owner, terminal, sessionId, tool, args, message, selection) {
      assert.equal(plan, null); assert.equal(awaitingTerminal, false);
      if (terminal.role !== 'customer') plan = { tool, args };
      const prefix = terminal.role === 'customer' ? '/agents/customer' : `/agents/${terminal.role}/assistant`;
      const requestId = randomUUID();
      const reply = await request(owner, `${prefix}/chat`, { sessionId, requestId, message, ...(selection ? { selection } : {}) });
      assert.equal(reply.status, 200, JSON.stringify(reply.data));
      assert.equal(typeof reply.data, 'string'); assert.doesNotMatch(reply.data, /event: error\n/);
      const saved = await request(owner, `${prefix}/operations/${sessionId}/${requestId}`);
      assert.equal(saved.status, 200, JSON.stringify(saved.data)); assert.equal(saved.data.status, 'completed');
      return { ...saved.data, requestId };
    }
    async function prepare(owner, terminal) {
      const prefix = terminal.role === 'customer' ? '/agents/customer' : `/agents/${terminal.role}/assistant`;
      const opened = await request(owner, `${prefix}/session`, {});
      assert.equal(opened.status, 200, JSON.stringify(opened.data)); const sessionId = opened.data.sessionId;
      if (terminal.role === 'customer') ticketSessions.push(sessionId);
      let args, message, selection;
      if (terminal.family === 'customer-ticket') { args = null; message = JSON.stringify({ subject: 'Q07 ordinary delivery question', body: 'Please confirm the delivery schedule for my synthetic practice order.' }); }
      if (terminal.family === 'merchant-listing') { args = { listing: { name: `Q07 listing ${randomUUID()}`, price: 12.5 } }; message = `Create a new listing named ${args.listing.name} priced at 12.5.`; }
      if (terminal.family === 'merchant-inventory') {
        const name = `Q07 stock ${randomUUID()}`;
        const product = await composition.catalog.createMerchantProduct({ scope: owner.scope, persona: owner.persona,
          personaSession: owner.personaSession, listing: { name, description: 'Q07 synthetic inventory', price: 10, category: 'fixture', templateSource: '{{source}}', images: [] } });
        const search = await turn(owner, terminal, sessionId, 'merchant.catalog_search', { search: name }, `Find ${name}`);
        const choice = search.cards.find(row => row.title === name); assert.ok(choice);
        args = { choiceId: choice.choiceId, quantity: 7 }; selection = { choiceId: choice.choiceId }; message = 'Set this selected product stock to 7.';
        owner.lastProductId = product.productId;
      }
      if (terminal.family === 'admin-policy') { args = { name: `q07-${randomUUID()}`, markdown: 'Only summarize the supplied synthetic text.', targets: ['summarizer'] }; message = `Create policy ${args.name} for summarizer with exact markdown: ${args.markdown}`; }
      if (terminal.family === 'admin-acl') {
        const listed = await turn(owner, terminal, sessionId, 'admin.acl_list', {}, 'List tool permissions.');
        const choice = listed.cards.find(row => row.kind === 'admin_acl_permission'); assert.ok(choice, JSON.stringify(listed));
        const allowed = String(choice.detail).includes('Allowed');
        args = { choiceId: choice.choiceId }; selection = { choiceId: choice.choiceId, intent: allowed ? 'acl_deny' : 'acl_allow' };
        message = `${allowed ? 'Deny' : 'Allow'} the selected permission.`;
      }
      const saved = await turn(owner, terminal, sessionId, terminal.prepareTool, args, message, selection);
      const proposal = saved[terminal.proposalKey]; assert.ok(proposal?.proposalId, `${terminal.family} must save a real proposal`);
      return { owner, terminal, ids: { sessionId, requestId: saved.requestId, proposalId: proposal.proposalId }, proposal,
        ...(terminal.family === 'merchant-inventory' ? { productId: owner.lastProductId } : {}) };
    }

    // These helpers deliberately use the production commerce domain to obtain
    // owner-bound operation IDs.  The HTTP calls below then prove that a
    // different credential cannot replay those exact already-admitted IDs.
    const customerContext = owner => ({ scope: owner.scope, persona: owner.persona,
      personaSession: owner.personaSession });
    async function prepareCartOperation(owner) {
      const context = customerContext(owner);
      await composition.catalog.prepareTarget(context);
      const found = await composition.commerce.conversational({ ...context, method: 'search',
        args: { search: customerProduct.name } });
      const index = found.products.findIndex(row => Number(row.product_id) === Number(customerProduct.id));
      assert.ok(index >= 0 && found.cards[index], 'Current customer product choice required');
      const proposal = await composition.commerce.conversational({ ...context, method: 'prepareCart',
        args: { operationId: randomUUID(), action: 'add', choiceId: found.cards[index].choiceId, quantity: 1 } });
      assert.equal(proposal.status, 'prepared');
      return proposal;
    }
    async function prepareCustomerPreAdmission(owner, terminal) {
      const context = customerContext(owner);
      let body, operationId, readPath = null;
      // Cross-store persona authority deliberately replaces a post-admission
      // storage error with an uncertain-outcome boundary. Keep the original
      // failure, but record only a bounded diagnostic for this isolated
      // checkout preflight so a native failure can be diagnosed before cleanup.
      async function checkoutDiagnostic(work) {
        try { return await work(); } catch (error) {
          t.diagnostic('Q07_CHECKOUT_PREFLIGHT ' + JSON.stringify(checkoutPreflightDiagnostic(error)));
          throw error;
        }
      }
      if (terminal.kind === 'cart') {
        const proposal = await prepareCartOperation(owner);
        operationId = proposal.proposalId; body = { proposalId: operationId };
      } else if (terminal.kind === 'address') {
        const form = await composition.conversationalCommerce.addressForm({ ...context,
          args: { action: 'create', choiceId: null } });
        body = { operationId: randomUUID(), action: 'create', choiceId: null,
          expectedSnapshotSha256: form.expectedSnapshotSha256, defaultSetSha256: form.defaultSetSha256,
          fields: { label: 'Q07 authority fixture', line1: '100 Synthetic Way', line2: null,
            city: 'Exampletown', state: 'CA', zip: '94105', phone: null, isDefault: false } };
        operationId = body.operationId;
      } else if (terminal.kind === 'payment') {
        // Read the owner-scoped catalog before creating the exact operation.
        const methods = await composition.conversationalCommerce.paymentMethods({ ...context, args: {} });
        assert.ok(Array.isArray(methods.cards));
        body = { operationId: randomUUID(), scenario: 'declined' }; operationId = body.operationId;
      } else if (terminal.kind === 'checkout') {
        const addressForm = await composition.conversationalCommerce.addressForm({ ...context,
          args: { action: 'create', choiceId: null } });
        const address = await composition.conversationalCommerce.saveAddress({ ...context, args: {
          operationId: randomUUID(), action: 'create', choiceId: null,
          expectedSnapshotSha256: addressForm.expectedSnapshotSha256,
          defaultSetSha256: addressForm.defaultSetSha256,
          fields: { label: 'Q07 checkout address', line1: '200 Synthetic Way', line2: null,
            city: 'Exampletown', state: 'CA', zip: '94105', phone: null, isDefault: false },
        } });
        assert.equal(address.status, 'completed');
        const addressChoices = await composition.conversationalCommerce.addressChoices({ ...context, args: {} });
        const payment = await composition.conversationalCommerce.createPaymentMethod({ ...context,
          args: { operationId: randomUUID(), scenario: 'declined' } });
        assert.equal(payment.version, 1);
        assert.equal(payment.kind, 'payment.create');
        assert.equal(payment.status, 'completed');
        assert.equal(payment.replayed, false);
        assert.ok(Array.isArray(payment.result?.cards) && payment.result.cards.length === 1,
          'Canonical payment creation receipt must expose exactly one selected card under result');
        const cart = await prepareCartOperation(owner);
        const cartReceipt = await composition.conversationalCommerce.confirmCart({ ...context,
          args: { proposalId: cart.proposalId } });
        assert.equal(cartReceipt.status, 'completed');
        assert.equal(cartReceipt.kind, 'cart.add');
        assert.ok(Number.isSafeInteger(cartReceipt.result?.id) && cartReceipt.result.id > 0,
          'Checkout preflight requires a completed current cart addition');
        const currentCart = await composition.commerce.conversational({ ...context, method: 'cartView', args: {} });
        assert.ok(currentCart.items.some(item => Number(item.product_id) === Number(customerProduct.id)
          && Number(item.quantity) >= 1), 'Checkout preflight requires the selected product in the current cart');
        assert.ok(Array.isArray(addressChoices.cards) && addressChoices.cards.length >= 1);
        assert.ok(typeof addressChoices.cards[0].choiceId === 'string');
        assert.equal(typeof payment.result.cards[0].choiceId, 'string');
        const proposal = await checkoutDiagnostic(() => composition.conversationalCommerce.prepareCheckout({ ...context, args: {
          operationId: randomUUID(), addressChoiceId: addressChoices.cards[0].choiceId,
          paymentChoiceId: payment.result.cards[0].choiceId } }));
        assert.equal(proposal.status, 'prepared');
        operationId = proposal.proposalId; body = { proposalId: operationId };
      } else if (terminal.kind === 'profile') {
        const form = await composition.conversationalCommerce.profileForm({ ...context, args: {} });
        body = { operationId: randomUUID(), expectedSnapshotSha256: form.expectedSnapshotSha256,
          fields: form.fields };
        operationId = body.operationId;
      } else {
        const opened = await request(owner, '/agents/customer/refund/session', {});
        assert.equal(opened.status, 200, JSON.stringify(opened.data));
        body = { sessionId: opened.data.sessionId, requestId: randomUUID(),
          message: 'Please refund my synthetic practice order for the saved reason.' };
      }
      if (terminal.kind !== 'refund') readPath = `/customer/commerce/operations/${operationId}`;
      return { terminal, owner, body, operationId, readPath };
    }
    const customerPreAdmissionOutcomes = [];
    const replayReceipt = value => {
      assert.ok(value && Object.getPrototypeOf(value) === Object.prototype,
        'Current owner confirmation must return a JSON receipt object');
      const { scopeKey: _scopeKey, ...receipt } = value;
      assert.equal(typeof receipt.operationId, 'string');
      return { ...receipt, replayed: true };
    };
    async function completeCustomerOperation(row) {
      if (row.terminal.kind === 'refund') return null;
      const before = await effectSnapshot(pools);
      const confirmed = await request(row.owner, row.terminal.path, row.body);
      assert.equal(confirmed.status, 200, `${row.terminal.family} current owner admission: ${JSON.stringify(confirmed.data)}`);
      assert.equal(confirmed.data?.operationId, row.operationId,
        `${row.terminal.family} confirmation must bind the exact owner operation`);
      assert.equal(confirmed.data?.kind, CUSTOMER_RECEIPT_KINDS[row.terminal.kind],
        `${row.terminal.family} confirmation must return its canonical receipt kind`);
      assert.equal(confirmed.data?.status, row.terminal.kind === 'checkout' ? 'declined' : 'completed',
        `${row.terminal.family} confirmation must return its canonical completed receipt`);
      const after = await effectSnapshot(pools);
      assert.notDeepEqual(after, before, `${row.terminal.family} owner operation must have a durable current consequence`);
      const saved = await request(row.owner, row.readPath);
      assert.equal(saved.status, 200, `${row.terminal.family} saved readback`);
      assert.equal(saved.data.operationId, row.operationId);
      assert.equal(saved.data.status, 'completed', `${row.terminal.family} saved operation must be completed`);
      assert.deepEqual(saved.data.receipt, replayReceipt(confirmed.data),
        `${row.terminal.family} saved operation must project the exact confirmed receipt`);
      const replayBefore = await effectSnapshot(pools);
      const replay = await request(row.owner, row.terminal.path, row.body);
      assert.equal(replay.status, 200, `${row.terminal.family} same-ID replay`);
      assert.equal(replay.data?.scopeKey, confirmed.data?.scopeKey,
        `${row.terminal.family} same-ID replay must retain the exact bound scope`);
      assert.deepEqual(replayReceipt(replay.data), replayReceipt(confirmed.data),
        `${row.terminal.family} same-ID replay must project the exact saved receipt`);
      assert.deepEqual(await effectSnapshot(pools), replayBefore,
        `${row.terminal.family} same-ID replay is side-effect free`);
      return { operationId: row.operationId, confirmedStatus: confirmed.data.status,
        savedStatus: saved.data.status, replayStatus: replay.status };
    }
    async function denyCustomerPreAdmission(row, denial, caller, overrides = {}) {
      const before = await effectSnapshot(pools), calls = providerCalls;
      const ticketBefore = await ticketTrace(), inventoryBefore = await inventoryTrace();
      const response = await request(caller, row.terminal.path, row.body, overrides);
      const expected = row.terminal.denials?.[denial]
        || (denial === 'foreign_tenant' ? row.terminal.foreign
          : { status: denial === 'wrong_role' ? 403 : 401 });
      assert.equal(response.status, expected.status,
        `${row.terminal.family}/${denial} must reject at its exact authority boundary: ${JSON.stringify(response.data)}`);
      if (expected.error) assert.deepEqual(response.data, { error: expected.error },
        `${row.terminal.family}/${denial} must not accept a generic or missing-operation response`);
      if (expected.sseError) {
        assert.equal(typeof response.data, 'string');
        assert.match(response.data, new RegExp(`event: error\\ndata: \\{\\"message\\":\\"${expected.sseError}\\"`));
      }
      const after = await effectSnapshot(pools);
      assert.deepEqual(after, before, `${row.terminal.family}/${denial} creates no durable operation, receipt, or effect`);
      assert.equal(providerCalls, calls, `${row.terminal.family}/${denial} precedes controlled provider dispatch`);
      assert.deepEqual(await ticketTrace(), ticketBefore, `${row.terminal.family}/${denial} emits no ticket trace`);
      assert.deepEqual(await inventoryTrace(), inventoryBefore, `${row.terminal.family}/${denial} emits no inventory trace`);
      customerPreAdmissionOutcomes.push({ family: row.terminal.family, denial, status: response.status,
        beforeSha256: digest(before), afterSha256: digest(after), providerCalls: calls });
    }
    const outcomes = [];
    async function deny(row, denial, caller, overrides = {}) {
      const before = await effectSnapshot(pools), calls = providerCalls, modelBefore = await ticketTrace(), inventoryModelBefore = await inventoryTrace();
      const response = await request(caller, row.terminal.confirmPath, row.ids, overrides);
      const ticketForeign = row.terminal.family === 'customer-ticket' && denial === 'foreign_tenant';
      // The ticket route deliberately hides owner-filtered absence behind its
      // exact unavailable DTO. The same original is positively confirmed below,
      // so this cannot pass through a missing proposal or broken service.
      if (ticketForeign) {
        assert.equal(response.status, 503);
        assert.deepEqual(response.data, { error: 'Ticket confirmation unavailable' });
      } else assert.ok([401, 403, 409].includes(response.status), `${row.terminal.family}/${denial}: ${JSON.stringify(response)}`);
      const after = await effectSnapshot(pools);
      assert.deepEqual(after, before, `${row.terminal.family}/${denial}: no durable effect, receipt, policy, ACL or sibling mutation`);
      assert.equal(providerCalls, calls, 'Authority denial precedes controlled provider execution');
      assert.deepEqual(await ticketTrace(), modelBefore, 'Authority denial emits no customer model trace');
      assert.deepEqual(await inventoryTrace(), inventoryModelBefore, 'Authority denial emits no inventory model trace');
      outcomes.push({ family: row.terminal.family, denial, requestId: row.ids.requestId,
        status: response.status, code: response.data?.code || null, beforeSha256: digest(before), afterSha256: digest(after) });
    }
    const stale = [], revoked = [], positives = [];
    for (const terminal of TERMINALS) {
      const row = await prepare(actors[terminal.role].main, terminal);
      const wrong = actors[terminal.role === 'customer' ? 'merchant' : 'customer'].main;
      await deny(row, 'wrong_role', wrong);
      await deny(row, 'foreign_tenant', foreign[terminal.role]);
      await deny(row, 'platform_launch_substitution', row.owner, { 'x-dvaia-secureshop-launch': foreign[terminal.role].boot.bearer });
      await deny(row, 'platform_token_substitution', row.owner, { authorization: `Bearer ${platformSession.token}` });
      const before = await effectSnapshot(pools);
      const result = await request(row.owner, terminal.confirmPath, row.ids);
      assert.equal(result.status, 200, `${terminal.family}: ${JSON.stringify(result.data)}`);
      const after = await effectSnapshot(pools), table = receiptTable[terminal.family];
      const effectRows = rows => terminal.family === 'merchant-inventory'
        ? rows.filter(value => value.row.action === 'set_stock') : rows;
      assert.equal(effectRows(after[table]).length, effectRows(before[table]).length + 1,
        `${terminal.family} one durable legitimate write receipt`);
      assert.notEqual(digest(after), digest(before));
      const durable = effectRows(after[table]).map(value => value.row).find(value =>
        (terminal.family === 'merchant-inventory' ? value.request_id : value.operation_id) === row.ids.proposalId);
      assert.ok(durable, `${terminal.family} receipt binds the exact confirmed proposal`);
      if (terminal.role === 'admin') {
        assert.equal(durable.platform_launch_id, row.owner.scope.launchId);
        assert.equal(durable.persona_id, row.owner.persona.id);
        assert.equal(durable.persona_session_id, row.owner.personaSession.sessionId);
        const effectTable = terminal.family === 'admin-policy' ? 'bound_prompt_policy_current' : 'bound_tool_policy_overrides';
        assert.notDeepEqual(after[effectTable], before[effectTable], `${terminal.family} changes current authority state`);
      } else {
        assert.equal(durable.target_id, row.owner.target.targetId);
        if (terminal.family === 'customer-ticket') {
          const ticket = after.product_target_support_tickets.find(value => value.row.operation_id === row.ids.proposalId)?.row;
          assert.ok(ticket); assert.equal(ticket.shop_user_id, row.owner.persona.id);
          assert.equal(ticket.turn_session_id, row.ids.sessionId); assert.equal(ticket.turn_request_id, row.ids.requestId);
          assert.equal(ticket.subject, row.proposal.subject); assert.equal(ticket.body, row.proposal.body);
        } else if (terminal.family === 'merchant-listing') {
          assert.equal(durable.merchant_id, row.owner.persona.id);
          const product = after.product_target_products.find(value => value.row.target_id === durable.target_id
            && value.row.product_id === durable.product_id)?.row;
          assert.ok(product); assert.equal(product.retailer_id, row.owner.persona.id);
        } else {
          assert.equal(durable.shop_user_id, row.owner.persona.id); assert.equal(durable.state, 'completed');
          const stock = await review.query(`SELECT COALESCE(o.stock_quantity,p.stock_quantity)::int AS stock
            FROM secureshop_review.product_target_products p LEFT JOIN secureshop_review.product_target_listing_overlays o
              ON o.target_id=p.target_id AND o.product_id=p.product_id AND o.archived_at IS NULL
            WHERE p.target_id=$1 AND p.product_id=$2`, [row.owner.target.targetId, row.productId]);
          assert.equal(stock.rows[0].stock, 7);
        }
      }
      positives.push({ family: terminal.family, requestId: row.ids.requestId, proposalId: row.ids.proposalId,
        status: result.status, receiptTable: table, beforeSha256: digest(before), afterSha256: digest(after) });
      revoked.push(await prepare(actors[terminal.role].revoke, terminal));
      stale.push(await prepare(actors[terminal.role].stale, terminal));
    }
    // Current no-model compatibility controls: every customer consequence
    // family starts with an owner-bound request, has an exact saved readback,
    // and proves same-ID replay before any authority substitution. Refund is
    // intentionally only session-prepared here: its first chat dispatch is a
    // model terminal and is outside this pre-admission-only receipt.
    const customerMain = [], customerRevoked = [], customerStale = [], customerCompatibility = [];
    for (const terminal of CUSTOMER_PRE_ADMISSION_TERMINALS) {
      const main = await prepareCustomerPreAdmission(actors.customer.main, terminal);
      const compatibility = await completeCustomerOperation(main);
      if (compatibility) customerCompatibility.push({ family: terminal.family, ...compatibility });
      await denyCustomerPreAdmission(main, 'wrong_role', actors.merchant.main);
      await denyCustomerPreAdmission(main, 'foreign_tenant', foreign.customer);
      await denyCustomerPreAdmission(main, 'platform_launch_substitution', main.owner,
        { 'x-dvaia-secureshop-launch': foreign.customer.boot.bearer });
      customerMain.push(main);
      const revoke = await prepareCustomerPreAdmission(actors.customer.revoke, terminal);
      await completeCustomerOperation(revoke); customerRevoked.push(revoke);
      const staleRow = await prepareCustomerPreAdmission(actors.customer.stale, terminal);
      await completeCustomerOperation(staleRow); customerStale.push(staleRow);
    }
    for (const role of ['customer', 'merchant', 'admin']) {
      const owner = actors[role].revoke;
      await composition.personaAuth.logout({ scope: owner.scope, token: owner.boot.persona.token });
    }
    for (const row of revoked) await deny(row, 'revoked_persona_session', row.owner);
    for (const row of customerRevoked) await denyCustomerPreAdmission(row, 'revoked_persona_session', row.owner);
    const foreignTargetIds = new Set(Object.values(foreign).map(value => value.target.targetId));
    const foreignLaunchIds = new Set(Object.values(foreign).map(value => value.scope.launchId));
    const foreignSnapshot = async () => Object.fromEntries(Object.entries(await effectSnapshot(pools)).map(([key, rows]) =>
      [key, rows.filter(({ row }) => foreignTargetIds.has(row.target_id) || foreignLaunchIds.has(row.platform_launch_id))]));
    const foreignBeforeReset = await foreignSnapshot();
    assert.ok(foreignBeforeReset.product_target_products.length, 'Independent foreign tenant contains real product rows');
    const traceBeforeReset = await ticketTrace(), inventoryTraceBeforeReset = await inventoryTrace();
    const admin = actors.admin.stale;
    const readiness = await resetService.readiness(admin.login.context);
    assert.equal(readiness.available, true);
    const resetReceipt = await resetService.reset(admin.login.context, { launchId: readiness.launchId,
      expectedGeneration: readiness.generation, sceneId: readiness.scene.id,
      confirmation: 'RESET_SHARED_PRACTICE', idempotencyKey: randomUUID() });
    assert.equal(resetReceipt.status, 'committed'); assert.equal(resetReceipt.cleanupComplete, true);
    for (const row of stale) await deny(row, 'stale_generation', row.owner);
    for (const row of customerStale) await denyCustomerPreAdmission(row, 'stale_generation', row.owner);
    assert.deepEqual(await foreignSnapshot(), foreignBeforeReset, 'Authenticated reset and stale denials preserve the independent tenant');
    assert.deepEqual(await creditSnapshot(), creditBefore, 'Ordinary confirmations award no objective credit');
    assert.equal(judgeCalls, 0);
    assert.equal(outcomes.filter(row => DENIALS.includes(row.denial)).length, 25);
    assert.equal(positives.length, 5);
    assert.equal(customerPreAdmissionOutcomes.length,
      CUSTOMER_PRE_ADMISSION_TERMINALS.length * CUSTOMER_PRE_ADMISSION_DENIALS.length);
    assert.equal(customerCompatibility.length, 5, 'Refund remains dispatch-free in this no-model admission slice');
    t.diagnostic('Q07_AUTHORITY_MATRIX ' + JSON.stringify({ version: 1, scope: 'focused-production-http',
      positives, denials: outcomes, objectiveCredit: false, judgeCalls,
      customerPreAdmission: { version: 1, scope: 'current-customer-http-before-provider-or-effect',
        compatibility: customerCompatibility, denials: customerPreAdmissionOutcomes,
        refund: { sessionPrepared: true, dispatch: 'not-invoked' } },
      ticketProvider: { provider: 'ollama', model: 'llama3.1:8b', transport: 'unmodified-production-adapter', preparedTurns: ticketSessions.length,
        supervisorInvocations: traceBeforeReset.filter(row => row.kind === 'llm_call_start').length,
        traceSha256: digest(traceBeforeReset) },
      inventoryProvider: { provider: 'ollama', model: 'llama3.1:8b', transport: 'unmodified-production-adapter', confirmedTurns: 1,
        supervisorInvocations: inventoryTraceBeforeReset.filter(row => row.kind === 'llm_call_start').length,
        traceSha256: digest(inventoryTraceBeforeReset) },
      roleProvider: { provider: 'mock', model: 'q07-controlled-no-credit', calls: providerCalls }, reset: resetReceipt }));
  } finally {
    await inventory?.close?.(); await ticketComposition?.ticketAgent?.close?.();
    await reset?.closeFeatureTransports?.();
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await Promise.all([...Object.values(pools), leasePool].map(pool => pool.end()));
  }
});
