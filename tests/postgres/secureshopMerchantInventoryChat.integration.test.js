'use strict';

// Focused controlled-provider qualification for the merchant inventory proposal
// adapter. This intentionally differs from the rendered inventory/Judge cohort:
// it proves durable proposal/confirmation and recovery authority only.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const http = require('node:http');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const path = require('node:path');
const fs = require('node:fs');
const { Module, createRequire } = require('node:module');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'PG_SECURESHOP_MERCHANT_INVENTORY_CHAT_';
const STORES = Object.freeze(['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE']);
const STORE_NAMES = Object.freeze({
  IDENTITY: 'identity', AGENTS: 'secureshop_agents', REVIEW: 'secureshop_review', COMMERCE: 'secureshop',
});
const ENABLED = process.env.SECURESHOP_MERCHANT_INVENTORY_CHAT_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORES.every(store => ['MIGRATION', 'RUNTIME'].every(role =>
    process.env[`${PREFIX}${store}_${role}_URL`]));

function disposableUrls() {
  const urls = {}; let nonce; let port;
  for (const store of STORES) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const value = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(value.protocol, 'postgresql:');
      assert.equal(value.hostname, '127.0.0.1');
      assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
      assert.equal(value.username, `dvaia_${STORE_NAMES[store]}_${role.toLowerCase()}`);
      const match = new RegExp(`^/dvaia_test_agent_host_([0-9a-f]{12})_${STORE_NAMES[store]}$`).exec(value.pathname);
      assert.ok(match, `closed disposable database name required for ${key}`);
      nonce ??= match[1]; port ??= value.port;
      assert.equal(match[1], nonce); assert.equal(value.port, port);
      urls[key] = value.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(STORES.map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(urls);
}

async function listen(app) {
  return await new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function migrateAndSeed(pools, workspace) {
  for (const [store, directory] of [
    ['IDENTITY', 'identity-migrations'], ['AGENTS', 'workshop-migrations/secureshop_agents'],
    ['REVIEW', 'workshop-migrations/secureshop_review'], ['COMMERCE', 'workshop-migrations/secureshop'],
  ]) {
    const migrationDirectory=path.join(workspace,'db/postgres',directory);
    if(store==='REVIEW') await qualifyListingEditMigration(pools.REVIEW_MIGRATION,pools.REVIEW_RUNTIME,migrationDirectory);
    else await migrate(pools[`${store}_MIGRATION`],migrationDirectory);
  }
  await require('../../server/database/postgres/workshopPlatformSeed')
    .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopAssessmentSeed')
    .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopStandaloneSeed')
    .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
  const seed = await pools.COMMERCE_MIGRATION.connect();
  try {
    await seed.query('BEGIN');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
    await seed.query('COMMIT');
  } catch (error) {
    await seed.query('ROLLBACK'); throw error;
  } finally { seed.release(); }
}
async function qualifyListingEditMigration(migrationPool,runtimePool,directory) {
  const filename=require.resolve('../../db/postgres/migrate'),local=createRequire(filename);
  const asyncFs=require('node:fs/promises');
  const view={...asyncFs,async readdir(dir,...args){const names=await asyncFs.readdir(dir,...args);
    return path.resolve(dir)===path.resolve(directory)?names.filter(name=>!/^\d{4}_.*\.sql$/.test(name)||Number(name.slice(0,4))<=42):names;}};
  const loaded=new Module(filename,module);loaded.filename=filename;
  loaded.require=name=>['node:fs/promises','fs/promises'].includes(name)?view:local(name);
  loaded._compile(fs.readFileSync(filename,'utf8'),filename);
  await loaded.exports.migrate(migrationPool,directory);
  assert.equal((await migrationPool.query("SELECT to_regclass('secureshop_review.owned_merchant_listing_edit_receipts') AS table_name")).rows[0].table_name,null);
  const targetId=randomUUID(),launchId=randomUUID(),scenarioId=randomUUID();
  await migrationPool.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256)
    VALUES($1,$2,$3,1,9997,9998,12,1,$4)`,[targetId,launchId,scenarioId,Buffer.alloc(32,1)]);
  await migrationPool.query(`INSERT INTO secureshop_review.product_target_products(target_id,product_id,
    source_retailer_id,retailer_id,source_product_sha256,name,description,price,images,stock_quantity,status,template_source)
    VALUES($1,71,12,12,$2,'Retained listing edit predecessor','Synthetic populated predecessor',9.25,'[]',5,'active','{{source}}')`,[targetId,Buffer.alloc(32,2)]);
  await migrationPool.query(`INSERT INTO secureshop_review.product_target_listing_overlays(target_id,product_id,
    shop_user_id,name,description,description_html,price,category,image_url,images,stock_quantity,status,template_source)
    SELECT target_id,product_id,retailer_id,name,description,description_html,10.75,category,image_url,images,
      stock_quantity,status,template_source FROM secureshop_review.product_target_products WHERE target_id=$1`,[targetId]);
  const queries={targets:'SELECT * FROM secureshop_review.product_targets ORDER BY target_id',
    products:'SELECT * FROM secureshop_review.product_target_products ORDER BY target_id,product_id',
    overlays:'SELECT * FROM secureshop_review.product_target_listing_overlays ORDER BY target_id,product_id',
    revisions:'SELECT * FROM secureshop_review.owned_listing_catalog_revisions ORDER BY target_id',
    history:'SELECT * FROM secureshop_review.product_target_price_history ORDER BY observation_id',
    ledger:'SELECT * FROM dvaia_migrations.ledger ORDER BY name'};
  const before={};for(const [key,query] of Object.entries(queries))before[key]=(await migrationPool.query(query)).rows;
  const name='0043_owned_merchant_listing_edits.sql';
  assert.deepEqual(await migrate(migrationPool,directory),[name]);
  const after={};for(const [key,query] of Object.entries(queries))after[key]=(await migrationPool.query(query)).rows;
  for(const key of Object.keys(queries))if(key!=='ledger')assert.deepEqual(after[key],before[key],key+' preserved by0043');
  assert.deepEqual(after.ledger.slice(0,-1),before.ledger);assert.equal(after.ledger.at(-1).name,name);
  assert.equal(after.ledger.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(directory,name))).digest('hex'));
  assert.equal((await runtimePool.query('SELECT count(*)::int n FROM secureshop_review.owned_merchant_listing_edit_receipts')).rows[0].n,0);
  assert.deepEqual(await migrate(migrationPool,directory),[]);
  for(const [key,query] of Object.entries(queries))assert.deepEqual((await migrationPool.query(query)).rows,after[key],key+' unchanged on no-op');
  const privileges=(await runtimePool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS read,
    has_table_privilege(current_user,$1,'INSERT') AS insert,has_table_privilege(current_user,$1,'UPDATE') AS update,
    has_table_privilege(current_user,$1,'DELETE') AS remove`,['secureshop_review.owned_merchant_listing_edit_receipts'])).rows[0];
  assert.deepEqual(privileges,{read:true,insert:true,update:false,remove:false});
}
function snapshotRows(pool) {
  return pool.query(`SELECT p.target_id,p.product_id,p.retailer_id,
      COALESCE(o.stock_quantity,p.stock_quantity) AS stock_quantity
    FROM secureshop_review.product_target_products p
    LEFT JOIN secureshop_review.product_target_listing_overlays o
      ON o.target_id=p.target_id AND o.product_id=p.product_id AND o.archived_at IS NULL
    ORDER BY p.target_id,p.product_id,p.retailer_id`)
    .then(result => result.rows);
}
async function inventoryRows(pool, targetId, shopUserId) {
  const filters = shopUserId === undefined ? ['target_id=$1'] : ['target_id=$1', 'shop_user_id=$2'];
  const values = shopUserId === undefined ? [targetId] : [targetId, shopUserId];
  const result = await pool.query(`SELECT operation_id,target_id,shop_user_id,persona_session_id,
      authority_version,request_id,state,action,request_sha256,request_json,result_sha256,result_json
    FROM secureshop_review.owned_inventory_operations
    WHERE ${filters.join(' AND ')} ORDER BY created_at,operation_id`, values);
  return result.rows;
}
function assertProposal(value, { requestId, productId, quantity }) {
  assert.deepEqual(Object.keys(value).sort(), ['message', 'modeCapability', 'product', 'proposalId',
    'scopeKey', 'stockChange', 'version'].sort());
  assert.equal(value.version, 1); assert.equal(value.proposalId, requestId);
  assert.match(value.product.choiceId, /^[0-9a-f-]{36}$/i);
  assert.equal(typeof value.product.name, 'string'); assert.ok(value.product.name);
  assert.deepEqual(value.stockChange, { productId, quantity });
  assert.equal(typeof value.message, 'string'); assert.ok(value.message);
  assert.match(value.scopeKey, /^[a-f0-9]{64}$/);
  assert.equal(value.modeCapability?.featureId, 'inventory');
}
function assertOperation(value, requestId) {
  assert.equal(value?.requestId, requestId);
  assert.equal(value?.status, 'completed');
  assert.ok(Array.isArray(value.operations));
  const mutation = value.operations.find(operation => operation?.action === 'set_stock');
  assert.ok(mutation, 'the saved inventory operation must expose the sole stock receipt');
  return mutation;
}
function postAndDiscardCommittedBody(url, headers, value) {
  const body = Buffer.from(JSON.stringify(value));
  return new Promise((resolve, reject) => {
    let observed200 = false;
    const request = http.request(url, { method: 'POST', headers: { ...headers,
      'content-length': String(body.length) } }, response => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`expected committed 200 before response loss, received ${response.statusCode}`));
        return;
      }
      observed200 = true;
      response.destroy();
      resolve();
    });
    request.setTimeout(10000, () => request.destroy(new Error('bounded lost-ack confirmation timeout')));
    request.once('error', error => {
      if (observed200 && error.code === 'ECONNRESET') return;
      reject(error);
    });
    request.end(body);
  });
}

test('merchant inventory chat and listing edits prepare without effects, confirm once, recover exact receipts, and fence stale or sibling authority',
  { skip: !ENABLED, timeout: 120000 }, async t => {
    const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '');
    assert.equal(workspace, process.cwd(), 'current checkout required; no source copy');
    const urls = disposableUrls();
    const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role =>
      [`${store}_${role}`, new Pool({ connectionString: urls[`${store}_${role}`], max: role === 'RUNTIME' ? 10 : 3 })])));
    const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 3 });
    let server; let reset; let inventory;
    try {
      await migrateAndSeed(pools, workspace);
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

      let roleDecision = 0, roleAwaitingTerminal = false, inventoryDecisionCalls = 0;
      let finalStep = 0, preparedRoleFinals = 0, judgeCalls = 0, selectedChoiceId, selectedProductId;
      const terminal = text => ({ provider: 'ollama', model: 'llama3.1:8b', mocked: false,
        fallback: false, stop_reason: 'end_turn', text, tool_uses: [] });
      const provider = Object.freeze({
        async chat({ system }) {
          const prompt = String(system || '');
          if (prompt.includes('inventory assistant for merchant')) {
            assert.equal(inventoryDecisionCalls, 0, 'confirmation has one controlled inventory decision');
            inventoryDecisionCalls += 1;
            return { provider: 'ollama', model: 'llama3.1:8b', mocked: false,
              fallback: false, stop_reason: 'tool_use', tool_uses: [{ id: 'apply-confirmed-stock',
                name: 'inventory.set_stock', args: { productId: selectedProductId, quantity: 7 } }] };
          }
          assert.match(prompt, /authenticated merchant/);
          if (roleAwaitingTerminal) {
            roleAwaitingTerminal = false;
            return terminal('The requested merchant action is complete.');
          }
          const decision = roleDecision++;
          roleAwaitingTerminal = true;
          if (decision === 0) return { provider: 'ollama', model: 'llama3.1:8b', mocked: false,
            fallback: false, stop_reason: 'tool_use', tool_uses: [{ id: 'find-owned-product',
              name: 'merchant.catalog_search', args: { search: 'inventory fixture' } }] };
          if (decision === 1) return { provider: 'ollama', model: 'llama3.1:8b', mocked: false,
            fallback: false, stop_reason: 'tool_use', tool_uses: [{ id: 'prepare-owned-product',
              name: 'merchant.inventory_prepare', args: { choiceId: selectedChoiceId, quantity: 6 } }] };
          if (decision === 2) return { provider: 'ollama', model: 'llama3.1:8b', mocked: false,
            fallback: false, stop_reason: 'tool_use', tool_uses: [{ id: 'refresh-owned-product',
              name: 'merchant.catalog_search', args: { search: 'inventory fixture stale' } }] };
          if (decision === 3) return { provider: 'ollama', model: 'llama3.1:8b', mocked: false,
            fallback: false, stop_reason: 'tool_use', tool_uses: [{ id: 'prepare-refreshed-product',
              name: 'merchant.inventory_prepare', args: { choiceId: selectedChoiceId, quantity: 7 } }] };
          throw new Error('Unexpected controlled merchant role decision');
        },
        async finalResponse() {
          // Prepared role tools enter the final-response path directly. Consume
          // the pending terminal here so the next turn starts a fresh decision.
          if (roleAwaitingTerminal) { roleAwaitingTerminal = false; preparedRoleFinals += 1; }
          finalStep += 1;
          return { ...terminal('Inventory response.'), responseMode: 'structured_final' };
        },
      });
      const judge = async () => { judgeCalls += 1; throw new Error('Controlled adapter fixture must not invoke Judge'); };
      let composition = require('../../server/services/secureshopBoundReviewComposition')
        .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
          reviewPool: review, commercePool: commerce, resetComposition: reset, gradingBootstrap: grading,
          scenes, modeAuthority, toolPolicyRepository, inventoryApplication: () => inventory?.application,
          fixtures: [], requiredObjectives: ['ss_stored_browser_execution'],
          jwtSecret: 'disposable-inventory-chat-persona-secret-at-least-32-bytes',
          agentRuntime: { provider }, judge });
      await composition.repositories.personas.ensureTemplates();
      const promptPolicyRepository = await require('../../server/services/secureshopAgentSnapshotPolicies')
        .createAgentSnapshotPolicyResolver({ personaAuthority: grading.personaAuthority,
          agentsPool: agents, identityPool: identity, auditStore: reset.audit.agents })();
      inventory = await require('../../server/services/secureshopInventoryProduction')
        .createInventoryProduction({ enabled: true, identityPool: identity, agentsPool: agents,
          reviewPool: review, resetComposition: reset, catalog: composition.catalog,
          personaAuthority: grading.personaAuthority, provider, promptPolicyRepository, toolPolicyRepository, assessmentDependencies: { ...grading.assessmentDependencies, judge },
          authenticatePersona: composition.personaAuth.authenticatePersona, mode: 'vuln', modeAuthority,
          resolveExistingTarget: scope => scenes.readExisting(scope) });
      assert.equal(inventory.ready, true);
      composition = Object.freeze({ ...composition, inventory });
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
        .createSecureShopStandaloneBootstrap({ launches: composition.launches,
          personaAuth: composition.personaAuth, authService: auth });
      const standaloneMode = require('../../server/services/secureshopStandaloneMode')
        .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const mounted = Object.freeze({ ...composition, standaloneAuth: Object.freeze({ service: auth,
        bootstrap, mode: standaloneMode }), personaInbox: Object.freeze({ ready: true, router: express.Router() }),
        mcpTrust: Object.freeze({ ready: true, router: express.Router() }),
        ssrf: Object.freeze({ ready: true, router: express.Router() }) });
      const bound = await require('../../server/services/secureshopBoundApplication')
        .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
          authenticateToken: (_request, response) => response.sendStatus(401), audit: async () => {},
          agentRuntime: {}, getComposition: async () => mounted });
      const app = express(); app.use(express.json());
      let confirmPosts = 0;
      app.use('/api/secureshop', (request, _response, next) => {
        if (request.method === 'POST' && request.path === '/agents/merchant/assistant/inventory/confirm') confirmPosts += 1;
        next();
      });
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
        .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      server = await listen(app);
      const origin = `http://127.0.0.1:${server.address().port}`;

      const suffix = randomUUID().slice(0, 8), password = 'inventory-chat-disposable-password';
      const owner = await auth.register({ username: `inventory_chat_${suffix}`,
        email: `inventory-chat-${suffix}@example.invalid`, password, role: 'merchant' });
      const sibling = await auth.register({ username: `inventory_peer_${suffix}`,
        email: `inventory-peer-${suffix}@example.invalid`, password, role: 'merchant' });
      const ownerBoot = await bootstrap(owner.context), siblingBoot = await bootstrap(sibling.context);
      const ownerScope = await composition.launches.resolveCapability(ownerBoot.bearer);
      const ownerActor = await composition.personaAuth.authenticateBoundToken({ scope: ownerScope,
        token: ownerBoot.persona.token });
      const ownerPersona = { id: ownerActor.user.id, role: 'merchant' };
      const ownerTarget = await composition.catalog.prepareTarget({ scope: ownerScope, persona: ownerPersona });
      const siblingScope = await composition.launches.resolveCapability(siblingBoot.bearer);
      const siblingActor = await composition.personaAuth.authenticateBoundToken({ scope: siblingScope,
        token: siblingBoot.persona.token });
      const siblingPersona = { id: siblingActor.user.id, role: 'merchant' };
      const siblingTarget = await composition.catalog.prepareTarget({ scope: siblingScope, persona: siblingPersona });
      const product = await composition.catalog.createMerchantProduct({ scope: ownerScope, persona: ownerPersona,
        personaSession: { sessionId: ownerActor.sessionId, authorityVersion: ownerActor.authorityVersion },
        listing: { name: `Inventory fixture ${suffix}`, description: 'Owned merchant inventory fixture',
          price: 12.5, category: 'fixture', templateSource: '{{source}}', images: [] } });
      const siblingProduct = await composition.catalog.createMerchantProduct({ scope: siblingScope, persona: siblingPersona,
        personaSession: { sessionId: siblingActor.sessionId, authorityVersion: siblingActor.authorityVersion },
        listing: { name: `Sibling inventory fixture ${suffix}`, description: 'Sibling merchant inventory fixture',
          price: 13.5, category: 'fixture', templateSource: '{{source}}', images: [] } });
      assert.ok(Number.isSafeInteger(product.productId));
      assert.ok(Number.isSafeInteger(siblingProduct.productId));
      assert.notEqual(product.productId, siblingProduct.productId);
      selectedProductId = product.productId;
      const beforePrepare = await snapshotRows(review);
      const ownerStockRow = beforePrepare.find(row => row.target_id === ownerTarget.targetId
        && Number(row.product_id) === product.productId && Number(row.retailer_id) === ownerPersona.id);
      assert.ok(ownerStockRow, 'owned target must expose the created product before the proposal');
      const beforeStock = Number(ownerStockRow.stock_quantity);
      const siblingStockRow = beforePrepare.find(row => row.target_id === siblingTarget.targetId
        && Number(row.product_id) === siblingProduct.productId && Number(row.retailer_id) === siblingPersona.id);
      assert.ok(siblingStockRow, 'the sibling owns a nonvacuous effective inventory row');
      const ownerLedgerBefore = await inventoryRows(review, ownerTarget.targetId, ownerPersona.id);
      const siblingLedgerBefore = await inventoryRows(review, siblingTarget.targetId, siblingPersona.id);
      const isOwnerMutation = row => row.target_id === ownerTarget.targetId
        && Number(row.product_id) === product.productId && Number(row.retailer_id) === ownerPersona.id;
      const untouchedRows = rows => rows.filter(row => !isOwnerMutation(row));
      const headers = Object.freeze({ 'content-type': 'application/json',
        'x-dvaia-secureshop-launch': ownerBoot.bearer, authorization: `Bearer ${ownerBoot.persona.token}` });
      const request = (pathname, options = {}) => fetch(`${origin}/api/secureshop${pathname}`, {
        ...options, headers: { ...headers, ...(options.headers || {}) },
      });
      const sessionResponse = await request('/agents/merchant/assistant/session', {
        method: 'POST', body: '{}' });
      assert.equal(sessionResponse.status, 200); const { sessionId } = await sessionResponse.json();
      assert.match(sessionId, /^[0-9a-f-]{36}$/i);
      const searchId = randomUUID();
      const search = await request('/agents/merchant/assistant/chat', { method: 'POST', body: JSON.stringify({
        sessionId, requestId: searchId, message: 'Find inventory fixture',
      }) });
      assert.equal(search.status, 200); await search.text();
      const searchSaved = await request(`/agents/merchant/assistant/operations/${sessionId}/${searchId}`);
      assert.equal(searchSaved.status, 200); const searchOperation = await searchSaved.json();
      assert.equal(searchOperation.status, 'completed'); assert.equal(searchOperation.inventoryProposal, null);
      const choice = searchOperation.cards.find(card => card.title === `Inventory fixture ${suffix}`);
      assert.ok(choice, 'the proposal starts from an exact durable owned choice'); selectedChoiceId = choice.choiceId;

      const staleRequestId = randomUUID();
      const prepare = await request('/agents/merchant/assistant/chat', { method: 'POST', body: JSON.stringify({
        sessionId, requestId: staleRequestId, message: 'Set the selected stock to 6.',
        selection: { choiceId: choice.choiceId },
      }) });
      assert.equal(prepare.status, 200); await prepare.text();
      const staleResponse = await request(`/agents/merchant/assistant/operations/${sessionId}/${staleRequestId}`);
      assert.equal(staleResponse.status, 200); const staleTurn = await staleResponse.json();
      assertProposal(staleTurn.inventoryProposal, { requestId: staleTurn.inventoryProposal.proposalId,
        productId: product.productId, quantity: 6 });
      assert.deepEqual(await snapshotRows(review), beforePrepare, 'preparing has zero stock effect');
      assert.equal(preparedRoleFinals,1,'the stale inventory proposal used the early terminal path');

      await composition.catalog.updateMerchantProduct({ scope: ownerScope, persona: ownerPersona,
        personaSession: { sessionId: ownerActor.sessionId, authorityVersion: ownerActor.authorityVersion },
        productId: product.productId, patch: { name: `Inventory fixture stale ${suffix}` } });
      const staleConfirm = await request('/agents/merchant/assistant/inventory/confirm', { method: 'POST', body: JSON.stringify({
        sessionId, requestId: staleRequestId, proposalId: staleTurn.inventoryProposal.proposalId,
      }) });
      assert.equal(staleConfirm.status, 409); assert.equal((await staleConfirm.json()).code, 'ROLE_PROPOSAL_STALE');
      assert.deepEqual(await snapshotRows(review), beforePrepare, 'stale confirmation is pre-effect');
      assert.deepEqual(await inventoryRows(review, ownerTarget.targetId, ownerPersona.id), ownerLedgerBefore,
        'stale confirmation creates no durable owner effect');
      assert.deepEqual(await inventoryRows(review, siblingTarget.targetId, siblingPersona.id), siblingLedgerBefore,
        'stale confirmation cannot create a sibling effect');
      assert.equal(confirmPosts, 1, 'the stale confirmation reached its bounded route once');
      const confirmsBeforeLostAck = confirmPosts;

      const refreshedRequestId = randomUUID();
      const refreshedSearch = await request('/agents/merchant/assistant/chat', { method: 'POST', body: JSON.stringify({
        sessionId, requestId: refreshedRequestId, message: 'Find inventory fixture stale',
      }) });
      assert.equal(refreshedSearch.status, 200); await refreshedSearch.text();
      const refreshedSearchOperation = await (await request(`/agents/merchant/assistant/operations/${sessionId}/${refreshedRequestId}`)).json();
      const refreshedChoice = refreshedSearchOperation.cards.find(card => card.title === `Inventory fixture stale ${suffix}`);
      assert.ok(refreshedChoice); selectedChoiceId = refreshedChoice.choiceId;
      const proposalRequestId = randomUUID();
      const freshPrepare = await request('/agents/merchant/assistant/chat', { method: 'POST', body: JSON.stringify({
        sessionId, requestId: proposalRequestId, message: 'Set the selected stock to 7.',
        selection: { choiceId: refreshedChoice.choiceId },
      }) });
      assert.equal(freshPrepare.status, 200); await freshPrepare.text();
      const proposalTurn = await (await request(`/agents/merchant/assistant/operations/${sessionId}/${proposalRequestId}`)).json();
      assertProposal(proposalTurn.inventoryProposal, { requestId: proposalTurn.inventoryProposal.proposalId,
        productId: product.productId, quantity: 7 });
      assert.equal(preparedRoleFinals,2,'both prepared inventory turns consumed their terminal state');

      await postAndDiscardCommittedBody(`${origin}/api/secureshop/agents/merchant/assistant/inventory/confirm`, headers, {
        sessionId, requestId: proposalRequestId, proposalId: proposalTurn.inventoryProposal.proposalId,
      });
      const recovered = await request(`/merchant/inventory/operations/${proposalTurn.inventoryProposal.proposalId}`);
      assert.equal(recovered.status, 200); const recoveredReceipt = await recovered.json();
      const mutation = assertOperation(recoveredReceipt, proposalTurn.inventoryProposal.proposalId);
      assert.deepEqual(mutation.result, { applied: true, productId: product.productId,
        retailerId: ownerPersona.id, before: beforeStock, after: 7 });
      assert.equal(recoveredReceipt.replayed, true);
      assert.equal(confirmPosts, confirmsBeforeLostAck + 1,
        'lost-ack recovery performs no second successful-confirm POST');
      const afterConfirm = await snapshotRows(review);
      const afterOwnerRow = afterConfirm.find(row => row.target_id === ownerTarget.targetId
        && Number(row.product_id) === product.productId && Number(row.retailer_id) === ownerPersona.id);
      assert.equal(Number(afterOwnerRow?.stock_quantity), 7, 'canonical effective stock reflects the confirmed operation');
      assert.deepEqual(untouchedRows(afterConfirm), untouchedRows(beforePrepare),
        'only the exact owner product effective stock may change in the shared tenant target');
      const afterSiblingRow = afterConfirm.find(row => row.target_id === siblingTarget.targetId
        && Number(row.product_id) === siblingProduct.productId && Number(row.retailer_id) === siblingPersona.id);
      assert.deepEqual(afterSiblingRow, siblingStockRow, 'the sibling-owned effective stock is unchanged');
      const ownerLedgerAfter = await inventoryRows(review, ownerTarget.targetId, ownerPersona.id);
      assert.equal(ownerLedgerAfter.length, ownerLedgerBefore.length + 1,
        'one immutable owned inventory receipt is durable for the confirmed proposal');
      const durable = ownerLedgerAfter.at(-1);
      assert.equal(durable.request_id, proposalTurn.inventoryProposal.proposalId);
      assert.equal(durable.target_id, ownerTarget.targetId);
      assert.equal(Number(durable.shop_user_id), ownerPersona.id);
      assert.equal(durable.state, 'completed');
      assert.equal(durable.action, 'set_stock', 'the one durable effect is the approved stock action');
      assert.match(durable.request_sha256, /^[a-f0-9]{64}$/);
      assert.match(durable.result_sha256, /^[a-f0-9]{64}$/);
      assert.ok(durable.request_json && durable.result_json, 'the immutable durable receipt retains request and result');
      assert.equal(createHash('sha256').update(durable.request_json, 'utf8').digest('hex'), durable.request_sha256);
      assert.equal(createHash('sha256').update(durable.result_json, 'utf8').digest('hex'), durable.result_sha256);
      const durableRequest = JSON.parse(durable.request_json);
      const durableReceipt = JSON.parse(durable.result_json);
      assert.equal(durableRequest.action, 'set_stock');
      assert.deepEqual(durableRequest.args, { productId: product.productId, quantity: 7 });
      assert.equal(durableRequest.execution.requestId, proposalTurn.inventoryProposal.proposalId);
      assert.deepEqual(durableReceipt.result, mutation.result,
        'the exact recovered mutation is bound to the saved immutable receipt');
      assert.deepEqual(await inventoryRows(review, siblingTarget.targetId, siblingPersona.id), siblingLedgerBefore,
        'the owner confirmation cannot add sibling receipts');
      assert.equal(roleDecision, 4); assert.equal(preparedRoleFinals,2); assert.equal(inventoryDecisionCalls, 1); assert.equal(judgeCalls, 0);

      const foreignHeaders = Object.freeze({ 'content-type': 'application/json',
        'x-dvaia-secureshop-launch': siblingBoot.bearer, authorization: `Bearer ${siblingBoot.persona.token}` });
      const foreign = (pathname, options = {}) => fetch(`${origin}/api/secureshop${pathname}`, {
        ...options, headers: { ...foreignHeaders, ...(options.headers || {}) },
      });
      const siblingSession = await foreign('/agents/merchant/assistant/session', { method: 'POST', body: '{}' });
      assert.equal(siblingSession.status, 200); const { sessionId: siblingSessionId } = await siblingSession.json();
      const deniedSibling = await foreign('/agents/merchant/assistant/inventory/confirm', { method: 'POST', body: JSON.stringify({
        sessionId: siblingSessionId, requestId: proposalRequestId, proposalId: proposalTurn.inventoryProposal.proposalId,
      }) });
      assert.equal(deniedSibling.status, 409);
      assert.equal((await deniedSibling.json()).code, 'ROLE_PROPOSAL_UNCONFIRMED');
      const deniedSiblingRead = await foreign(`/merchant/inventory/operations/${proposalTurn.inventoryProposal.proposalId}`);
      assert.equal(deniedSiblingRead.status, 200);
      assert.deepEqual(await deniedSiblingRead.json(), {
        status: 'not_found', requestId: proposalTurn.inventoryProposal.proposalId,
      }, 'sibling receives only the exact owner-filtered absence DTO');
      assert.equal(roleDecision, 4, 'sibling denial is pre-provider');
      assert.equal(inventoryDecisionCalls, 1, 'sibling denial is pre-effect');
      assert.deepEqual(await inventoryRows(review, siblingTarget.targetId, siblingPersona.id), siblingLedgerBefore,
        'sibling negatives create no durable receipt');

      // Q32 uses the actual scene/persona-fenced catalog and review transaction.
      // These are controlled native CAS proofs, not a rendered/model edit claim.
      const {listingEditDigest}=require('../../server/services/secureshopListingEditContract');
      const listingSnapshotHash=async(productValue,view)=>{
        const raw=(await review.query(`SELECT p.source_product_sha256,o.archived_at
          FROM secureshop_review.product_target_products p LEFT JOIN secureshop_review.product_target_listing_overlays o
          ON o.target_id=p.target_id AND o.product_id=p.product_id WHERE p.target_id=$1 AND p.product_id=$2`,
          [ownerTarget.targetId,product.productId])).rows[0];assert.ok(raw);
        const stamp=value=>value==null?null:new Date(value).toISOString();
        return listingEditDigest([1,productValue.id,productValue.retailer_id,raw.source_product_sha256.toString('hex'),
          view,productValue.images,productValue.stock_quantity,productValue.status,stamp(productValue.updated_at),stamp(raw.archived_at)]);
      };
      const editContext={scope:ownerScope,persona:ownerPersona,personaSession:{
        sessionId:ownerActor.sessionId,authorityVersion:ownerActor.authorityVersion}};
      const siblingEditContext={scope:siblingScope,persona:siblingPersona,personaSession:{
        sessionId:siblingActor.sessionId,authorityVersion:siblingActor.authorityVersion}};
      const editRows=()=>review.query(`SELECT * FROM secureshop_review.owned_merchant_listing_edit_receipts
        ORDER BY operation_id`).then(result=>result.rows);
      const editAudits=()=>review.query(`SELECT * FROM secureshop_review.bound_audit_events
        WHERE action='listing_edit_confirm' ORDER BY event_id`).then(result=>result.rows);
      const siblingListingBefore=await composition.catalog.getOwnedMerchantProduct({...siblingEditContext,
        productId:siblingProduct.productId});
      const editBefore=await composition.catalog.getOwnedMerchantProduct({...editContext,productId:product.productId});
      const receiptsBefore=await editRows(),auditsBefore=await editAudits();
      const patch={name:`Confirmed listing ${suffix}`,description:'Exact confirmed ordinary listing text',price:14.25};
      const preview=await composition.catalog.previewMerchantListingEdit({...editContext,productId:product.productId,patch});
      assert.equal(preview.version,1);assert.equal(preview.productId,product.productId);
      assert.match(preview.catalogRevision,/^(0|[1-9][0-9]*)$/);
      assert.deepEqual(preview.patch,patch);assert.equal(preview.before.name,editBefore.product.name);
      assert.equal(preview.expectedSnapshotSha256,await listingSnapshotHash(editBefore.product,preview.before));
      assert.equal(preview.after.name,patch.name);assert.equal(preview.after.description,patch.description);
      assert.equal(preview.after.price,patch.price);
      for(const value of [preview.scopeKey,preview.expectedSnapshotSha256,preview.requestSha256])assert.match(value,/^[a-f0-9]{64}$/);
      assert.deepEqual(await composition.catalog.getOwnedMerchantProduct({...editContext,productId:product.productId}),editBefore,
        'listing preview creates no product effect');
      assert.deepEqual(await editRows(),receiptsBefore);assert.deepEqual(await editAudits(),auditsBefore);
      const operationId=randomUUID();
      let confirmed;
      try { confirmed=await composition.catalog.confirmMerchantListingEdit({...editContext,operationId,preview}); }
      catch(error) {
        // Emit structural errors only; never SQL/query values, detail or rows.
        const reviewDirectory=path.join(workspace,'db/postgres/workshop-migrations/secureshop_review');
        const staticMessages=new Set(fs.readdirSync(reviewDirectory).filter(name=>/^\d{4}_.*\.sql$/.test(name))
          .flatMap(name=>[...fs.readFileSync(path.join(reviewDirectory,name),'utf8').matchAll(/RAISE EXCEPTION '([^'%]{1,256})'/g)].map(match=>match[1])));
        const causes=[];let cause=error;
        for(let depth=0;cause&&depth<4;depth++,cause=cause.cause){
          const item={code:/^[A-Z0-9_]{1,80}$/.test(cause.code||'')?cause.code:'UNCLASSIFIED'};
          for(const key of ['schema','table','column','constraint','routine'])if(typeof cause[key]==='string'
            && /^[A-Za-z0-9_.]{1,128}$/.test(cause[key]))item[key]=cause[key];
          const message=typeof cause.message==='string'?cause.message:'';
          if(staticMessages.has(message)||/^permission denied for (?:table|relation|schema|function|sequence) [A-Za-z0-9_."]{1,128}$/.test(message)
            ||/^column "[A-Za-z0-9_.]{1,128}" (?:of relation "[A-Za-z0-9_.]{1,128}" )?does not exist$/.test(message))item.message=message;
          else item.messageSha256=createHash('sha256').update(message).digest('hex');
          causes.push(item);
        }
        t.diagnostic('Listing confirm nested structural failure: '+JSON.stringify(causes));
        throw error;
      }

      assert.deepEqual(Object.keys(confirmed).sort(),['version','operationId','productId','status','scopeKey',
        'catalogRevision','requestSha256','beforeSha256','afterSha256','receiptSha256','replayed'].sort());
      assert.equal(confirmed.version,1);assert.equal(confirmed.operationId,operationId);assert.equal(confirmed.productId,product.productId);
      assert.equal(confirmed.status,'completed');assert.equal(confirmed.scopeKey,preview.scopeKey);
      assert.equal(confirmed.catalogRevision,preview.catalogRevision);assert.equal(confirmed.requestSha256,preview.requestSha256);
      assert.equal(confirmed.beforeSha256,preview.expectedSnapshotSha256);assert.equal(confirmed.replayed,false);
      assert.match(confirmed.afterSha256,/^[a-f0-9]{64}$/);assert.match(confirmed.receiptSha256,/^[a-f0-9]{64}$/);
      const committedRows=await editRows(),committedAudits=await editAudits();
      assert.equal(committedRows.length,receiptsBefore.length+1);assert.equal(committedAudits.length,auditsBefore.length+1);
      const savedRow=committedRows.find(row=>row.operation_id===operationId);assert.ok(savedRow);
      assert.equal(savedRow.target_id,ownerTarget.targetId);assert.equal(Number(savedRow.merchant_id),ownerPersona.id);
      assert.equal(savedRow.persona_session_id,ownerActor.sessionId);assert.equal(savedRow.grant_id,ownerTarget.scene.grantId);
      assert.equal(savedRow.request_sha256.toString('hex'),preview.requestSha256);
      assert.equal(savedRow.receipt_sha256.toString('hex'),confirmed.receiptSha256);
      const auditRow=committedAudits.find(row=>JSON.parse(row.params_json).operationId===operationId);assert.ok(auditRow);
      assert.equal(auditRow.launch_id,ownerScope.launchId);assert.equal(auditRow.original_platform_session_id,ownerScope.platformSessionId);
      assert.equal(auditRow.shop_user_id,ownerPersona.id);assert.equal(auditRow.target,String(product.productId));
      assert.equal(JSON.parse(auditRow.params_json).storage.targetId,ownerTarget.targetId);
      const edited=await composition.catalog.getOwnedMerchantProduct({...editContext,productId:product.productId});
      assert.equal(edited.product.name,patch.name);assert.equal(edited.product.description,patch.description);assert.equal(edited.product.price,patch.price);
      assert.equal(confirmed.afterSha256,await listingSnapshotHash(edited.product,preview.after));
      assert.deepEqual(await composition.catalog.confirmMerchantListingEdit({...editContext,operationId,preview}),{...confirmed,replayed:true});
      assert.deepEqual(await composition.catalog.readMerchantListingEdit({...editContext,operationId}),{...confirmed,replayed:true});
      assert.deepEqual(await editRows(),committedRows);assert.deepEqual(await editAudits(),committedAudits);
      await assert.rejects(composition.catalog.previewMerchantListingEdit({...siblingEditContext,productId:product.productId,patch}),
        {code:'OWNER_MISMATCH'});
      await assert.rejects(composition.catalog.confirmMerchantListingEdit({...siblingEditContext,operationId,preview}),
        {code:'SHOP_AUTH_INVALID'});
      const foreignRead=await composition.catalog.readMerchantListingEdit({...siblingEditContext,operationId});
      assert.equal(foreignRead.status,'not_found');assert.equal(foreignRead.operationId,operationId);
      const stalePreview=await composition.catalog.previewMerchantListingEdit({...editContext,productId:product.productId,
        patch:{description:'Must not apply stale text'}});
      await composition.catalog.updateMerchantProduct({...editContext,productId:product.productId,patch:{price:15.25}});
      const staleRows=await editRows(),staleAudits=await editAudits(),staleProduct=await composition.catalog.getOwnedMerchantProduct({...editContext,productId:product.productId});
      const staleOperationId=randomUUID();
      await assert.rejects(composition.catalog.confirmMerchantListingEdit({...editContext,operationId:staleOperationId,preview:stalePreview}),
        error=>error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN' && error.cause?.code==='LISTING_EDIT_STALE');
      assert.deepEqual(await composition.catalog.readMerchantListingEdit({...editContext,operationId:staleOperationId}),
        {operationId:staleOperationId,status:'not_found',scopeKey:stalePreview.scopeKey});
      assert.deepEqual(await editRows(),staleRows);assert.deepEqual(await editAudits(),staleAudits);
      assert.deepEqual(await composition.catalog.getOwnedMerchantProduct({...editContext,productId:product.productId}),staleProduct);
      assert.deepEqual(await composition.catalog.getOwnedMerchantProduct({...siblingEditContext,productId:siblingProduct.productId}),siblingListingBefore);
      assert.notEqual(ownerScope.launchId,siblingScope.launchId,'registered actors retain distinct launch authority');
      assert.notEqual(ownerScope.platformSessionId,siblingScope.platformSessionId);
      const sharedScene=ownerTarget.scene.sceneId===siblingTarget.scene.sceneId;
      assert.equal(ownerTarget.targetId===siblingTarget.targetId,sharedScene,'scene storage identity must be exact');
      if(sharedScene){
        const ownerStore=await scenes.store(ownerScope),siblingStore=await scenes.store(siblingScope);
        assert.ok(ownerStore?.tenantId&&siblingStore?.tenantId);assert.equal(ownerStore.tenantId,siblingStore.tenantId);
        assert.equal(ownerScope.platformOwnerId,siblingScope.platformOwnerId,'shared scene authority belongs to the same tenant owner');
      }
      const siblingStoredRows=async()=>({
        base:(await review.query(`SELECT * FROM secureshop_review.product_target_products
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3`,
          [siblingTarget.targetId,siblingProduct.productId,siblingPersona.id])).rows,
        overlays:(await review.query(`SELECT * FROM secureshop_review.product_target_listing_overlays
          WHERE target_id=$1 AND product_id=$2 AND shop_user_id=$3`,
          [siblingTarget.targetId,siblingProduct.productId,siblingPersona.id])).rows,
      });
      const siblingStoredBeforeReset=await siblingStoredRows();assert.equal(siblingStoredBeforeReset.base.length,1);
      const resetPreview=await composition.catalog.previewMerchantListingEdit({...editContext,productId:product.productId,
        patch:{description:'Must not apply after reset admission'}});
      await reset.launches.beginReset({launchId:ownerScope.launchId,platformSessionId:ownerScope.platformSessionId,
        platformOwnerId:ownerScope.platformOwnerId,expectedGeneration:ownerScope.generation,idempotencyKey:'q32-listing-reset-denial'});
      await assert.rejects(composition.catalog.confirmMerchantListingEdit({...editContext,operationId:randomUUID(),preview:resetPreview}));
      await assert.rejects(composition.catalog.readMerchantListingEdit({...editContext,operationId}));
      assert.deepEqual(await editRows(),staleRows,'reset admission preserves immutable edit receipts');
      assert.deepEqual(await editAudits(),staleAudits,'reset denial creates no edit audit');
      assert.deepEqual(await siblingStoredRows(),siblingStoredBeforeReset,'reset admission preserves exact sibling-owned birth storage');
      await composition.launches.assertCurrent(siblingScope);
      if(sharedScene){
        assert.equal((await identity.query('SELECT status FROM identity.secureshop_scenes WHERE scene_id=$1',
          [siblingTarget.scene.sceneId])).rows[0].status,'retired');
        await assert.rejects(require('../../server/services/secureshopSceneBinding').withSceneLease(siblingTarget,async()=>{}),
          'a distinct current sibling launch cannot reuse a retired shared-scene grant');
      }else{
        assert.deepEqual(await composition.catalog.getOwnedMerchantProduct({...siblingEditContext,productId:siblingProduct.productId}),siblingListingBefore,
          'an independently selected sibling scene remains callable');
      }
      assert.equal(roleDecision,4);assert.equal(inventoryDecisionCalls,1);assert.equal(judgeCalls,0);

    } finally {
      await inventory?.close?.();
      await reset?.closeFeatureTransports?.();
      await closeServer(server);
      await Promise.all([...Object.values(pools), leasePool].map(pool => pool.end()));
    }
  });
