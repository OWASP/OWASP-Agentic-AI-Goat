'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { readMigrations } = require('../db/postgres/migrate');
const { DEFAULT_OBJECTIVES, assertSecureShopBoundReviewReadiness,
  createSecureShopBoundReviewComposition, createMailActionPolicyCheck,
  createCheckoutAuditReadStore,
  createOptionalSystemConfigComposition, createOptionalSystemDiagnosticComposition,
  createOptionalSystemRebuildComposition, createOptionalSystemRestartComposition } = require(
  '../server/services/secureshopBoundReviewComposition');
const { createSecureShopCleanupComposition } = require('../server/services/secureshopCleanupComposition');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');

const root = path.join(__dirname, '..');
const migrationDirectories = {
  dvaia_identity_runtime: path.join(root, 'db/postgres/identity-migrations'),
  dvaia_secureshop_agents_runtime: path.join(root,
    'db/postgres/workshop-migrations/secureshop_agents'),
  dvaia_secureshop_review_runtime: path.join(root,
    'db/postgres/workshop-migrations/secureshop_review'),
  dvaia_secureshop_runtime: path.join(root, 'db/postgres/workshop-migrations/secureshop'),
};

test('physical merchant mail confirmation rereads the exact current prepare permission',async()=>{
 const context={scope:{launchId:'owned'},persona:{id:6,role:'merchant'},personaSession:{sessionId:'owned'}};
 let enforcement=true,allowed=true,toolKey='merchant.mail_send_prepare';
 const order=[];
 const check=createMailActionPolicyCheck({async readPolicy(input){
  assert.equal(input,context);order.push('policy');return{enforcement,rows:[{toolKey,
   supported:true,roleApplicability:{merchant:true},allowed:{merchant:allowed}}]};}});
 await check({context,action:'send',beforeEffect:async()=>order.push('scene')});
 assert.deepEqual(order,['policy','scene']);
 allowed=false;
 await assert.rejects(check({context,action:'send',beforeEffect:async()=>order.push('effect')}),
  {code:'MAIL_ACTION_POLICY_DENIED'});
 assert.deepEqual(order,['policy','scene','policy']);
 enforcement=false;
 await check({context,action:'send',beforeEffect:async()=>order.push('scene')});
 assert.deepEqual(order.slice(-2),['policy','scene'],
  'enforcement-off retains the intentional denied-by-ACL dispatch behavior');
 toolKey='merchant.mail_reply_prepare';enforcement=true;allowed=true;
 await check({context,action:'reply',beforeEffect:async()=>order.push('scene')});
 await assert.rejects(check({context,action:'send'}),{code:'ACL_TOOL_UNAVAILABLE'});
 await assert.rejects(check({context,action:'unknown'}),{code:'ACL_TOOL_UNAVAILABLE'});
 await assert.rejects(createMailActionPolicyCheck(null)({context,action:'send'}),
  {code:'ACL_TOOL_UNAVAILABLE'});
});

test('optional System composition forwards only the prepared persona authority', async () => {
  const client = Object.freeze({ read() {} });
  const personaAuthority = Object.freeze({ capture() {} });
  const preparedGrading = Object.freeze({ personaAuthority });
  const agentsPool = Object.freeze({ query() {} });
  const audit = Object.freeze({ append() {} });
  const modeAuthority = Object.freeze({ capture() {} });
  const authenticatePersona = () => {};
  let received;
  const value = Object.freeze({ ready: true });
  assert.equal(await createOptionalSystemConfigComposition({}), undefined);
  await assert.rejects(createOptionalSystemConfigComposition({ systemConfigClient: client }),
    { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  const result = await createOptionalSystemConfigComposition({ systemConfigClient: client,
    preparedGrading, agentsPool, audit, authenticatePersona, modeAuthority }, {
    createComposition: async input => { received = input; return value; },
  });
  assert.equal(result, value);
  assert.deepEqual(received, { agentsPool, personaAuthority, audit, client, authenticatePersona, modeAuthority });
});

test('optional System rebuild is default-off and forwards the existing product target dependencies',async()=>{
 assert.equal(await createOptionalSystemRebuildComposition({}),undefined);
 await assert.rejects(createOptionalSystemRebuildComposition({enabled:true}),/Prepared persona authority required/);
 const dependencies={enabled:true,preparedGrading:{personaAuthority:{}},reviewPool:{},launches:{},products:{},audit:{},authenticatePersona(){}};let received;
 const result=await createOptionalSystemRebuildComposition(dependencies,{createComposition:async input=>{received=input;return{ready:true};}});
 assert.equal(received.reviewPool,dependencies.reviewPool);assert.equal(received.launches,dependencies.launches);assert.equal(received.products,dependencies.products);assert.equal(received.personaAuthority,dependencies.preparedGrading.personaAuthority);assert.equal(received.audit,dependencies.audit);assert.deepEqual(result,{ready:true});
});

test('optional System restart resolves the same existing bound product target without broadening authority',async()=>{
 assert.equal(await createOptionalSystemRestartComposition({}),undefined);
 await assert.rejects(createOptionalSystemRestartComposition({systemRestartClient:{}}),/Prepared persona authority required/);
 const personaAuthority={capture(){}},dependencies={systemRestartClient:{health(){},execute(){}},preparedGrading:{personaAuthority},modeAuthority:{capture(){},assertToken(){}},reviewPool:{},launches:{},products:{},audit:{},authenticatePersona(){}};let received,resolverInput;
 const result=await createOptionalSystemRestartComposition(dependencies,{createTargetResolver:input=>{resolverInput=input;return async(raw,options)=>{assert.deepEqual(options,{signal:'signal'});assert.equal(raw.operationId,'op');return{binding:{targetId:'10000000-0000-4000-8000-000000000001'}};};},createComposition:async input=>{received=input;return{ready:true};}});
 assert.equal(received.modeAuthority,dependencies.modeAuthority);assert.equal(result.ready,true);assert.deepEqual(resolverInput,{launches:dependencies.launches,products:dependencies.products,personaAuthority});assert.equal(received.reviewPool,dependencies.reviewPool);assert.equal(received.client,dependencies.systemRestartClient);assert.equal(received.audit,dependencies.audit);assert.deepEqual(await received.resolveTarget({operationId:'op'},{signal:'signal'}),{targetId:'10000000-0000-4000-8000-000000000001'});
});

async function readinessPool(role, { catalog = true, missingRelation = false,
  catalogActive = true, catalogObjectives = ['fixture_objective'],
  privilegeFailure = null, missingProductKind = false, checksumMismatch = false, database = role } = {}) {
  const migrations = await readMigrations(migrationDirectories[role]);
  return {
    async query(sql, args) {
      if (sql.startsWith('SELECT current_user')) return { rows: [{ role, database }] };
      if (sql.startsWith('SELECT name,checksum')) return { rows: migrations.map((row, index) => ({
        name: row.name, checksum: checksumMismatch && index === migrations.length - 1
          ? '0'.repeat(64) : row.checksum,
      })) };
      if (sql.includes('has_table_privilege') || sql.includes('has_function_privilege')) {
        return { rows: args[0].map(value => ({ value, ready: value !== privilegeFailure })) };
      }
      if (sql.includes('FROM unnest')) return { rows: args[0].map(value => ({
        value, ready: missingRelation === true ? false : value !== missingRelation,
      })) };
      if (sql.includes('FROM pg_constraint')) return { rows: args[0].map(conname => ({
        conname, ready: !missingProductKind,
      })).sort((a, b) => a.conname.localeCompare(b.conname)) };
      if (sql.includes('FROM secureshop_auth.assessment_objectives')) return { rows: catalog ? catalogObjectives.map(objective_id=>({objective_id,catalog_active:catalogActive})) : [] };
      throw new Error(`Unexpected readiness query: ${sql}`);
    },
  };
}

async function migrationPool(role, options) {
  const runtimeRole = role.replace('_migration', '_runtime');
  const pool = await readinessPool(runtimeRole, options);
  return { async query(sql, args) {
    if (sql.startsWith('SELECT current_user')) return { rows: [{ role, database: options?.database || runtimeRole }] };
    return pool.query(sql, args);
  } };
}

test('readiness requires exact ledgers, schemas, isolated roles and catalog', async () => {
  const identityPool = await readinessPool('dvaia_identity_runtime');
  const agentsPool = await readinessPool('dvaia_secureshop_agents_runtime');
  const reviewPool = await readinessPool('dvaia_secureshop_review_runtime');
  const commercePool = await readinessPool('dvaia_secureshop_runtime');
  const migrationPools = {
    identity: await migrationPool('dvaia_identity_migration'),
    agents: await migrationPool('dvaia_secureshop_agents_migration'),
    review: await migrationPool('dvaia_secureshop_review_migration'),
    commerce: await migrationPool('dvaia_secureshop_migration'),
  };
  assert.deepEqual(await assertSecureShopBoundReviewReadiness({ identityPool, agentsPool,
    reviewPool, commercePool, migrationPools, requiredObjectives: ['fixture_objective'] }), {
    workshopKey: 'secureshop_agent_security', objectives: ['fixture_objective'],
  });
  await assert.rejects(assertSecureShopBoundReviewReadiness({ identityPool, agentsPool,
    reviewPool, commercePool, migrationPools: { ...migrationPools,
      agents: await migrationPool('dvaia_secureshop_agents_migration', { checksumMismatch: true }) },
    requiredObjectives: ['fixture_objective'] }),
  { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({ identityPool,
    agentsPool, reviewPool: await readinessPool('dvaia_secureshop_review_runtime', {
      missingRelation: true,
    }), commercePool, migrationPools, requiredObjectives: ['fixture_objective'] }),
  { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({
    identityPool: await readinessPool('dvaia_identity_runtime', { missingProductKind: true }),
    agentsPool, reviewPool, commercePool, migrationPools, requiredObjectives: ['fixture_objective'],
  }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({ identityPool,
    agentsPool: await readinessPool('dvaia_secureshop_agents_runtime', {
      missingRelation: 'secureshop_agents.bound_persona_templates',
    }), reviewPool, commercePool, migrationPools, requiredObjectives: ['fixture_objective'] }),
  { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({
    identityPool: await readinessPool('dvaia_identity_runtime', {
      missingRelation: 'identity.student_deletion_secureshop_resets',
    }), agentsPool, reviewPool, commercePool, migrationPools,
    requiredObjectives: ['fixture_objective'],
  }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({
    identityPool: await readinessPool('dvaia_identity_runtime', { catalog: false }),
    agentsPool, reviewPool, commercePool, migrationPools, requiredObjectives: ['fixture_objective'],
  }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({
    identityPool: await readinessPool('dvaia_identity_runtime', { database: 'shared' }),
    agentsPool: await readinessPool('dvaia_secureshop_agents_runtime', { database: 'shared' }),
    reviewPool, commercePool, migrationPools, requiredObjectives: ['fixture_objective'],
  }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
});

test('readiness rejects missing product retrieval or derived revision relations', async () => {
  for (const table of ['retrieval_config', 'retrieval_documents', 'retrieval_ingest_receipts', 'retrieval_cleanup_receipts',
    'manual_runtime_receipts', 'embedding_revisions', 'embedding_vectors', 'embedding_heads', 'embedding_cleanup_receipts', 'embedding_preimages', 'manual_preimages']) {
    await assert.rejects(assertSecureShopBoundReviewReadiness({
      identityPool: await readinessPool('dvaia_identity_runtime'),
      agentsPool: await readinessPool('dvaia_secureshop_agents_runtime'),
      reviewPool: await readinessPool('dvaia_secureshop_review_runtime', {
        missingRelation: `secureshop_review.product_target_${table}`,
      }),
      commercePool: await readinessPool('dvaia_secureshop_runtime'),
      migrationPools: {
        identity: await migrationPool('dvaia_identity_migration'),
        agents: await migrationPool('dvaia_secureshop_agents_migration'),
        review: await migrationPool('dvaia_secureshop_review_migration'),
        commerce: await migrationPool('dvaia_secureshop_migration'),
      },
      requiredObjectives: ['fixture_objective'],
    }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  }
});

test('readiness rejects missing listing receipts even with an applied migration ledger', async () => {
 for (const relation of ['owned_merchant_listing_edit_receipts','owned_merchant_listing_create_receipts']) await assert.rejects(assertSecureShopBoundReviewReadiness({
  identityPool:await readinessPool('dvaia_identity_runtime'),agentsPool:await readinessPool('dvaia_secureshop_agents_runtime'),
  reviewPool:await readinessPool('dvaia_secureshop_review_runtime',{missingRelation:`secureshop_review.${relation}`}),
  commercePool:await readinessPool('dvaia_secureshop_runtime'),migrationPools:{
   identity:await migrationPool('dvaia_identity_migration'),agents:await migrationPool('dvaia_secureshop_agents_migration'),
   review:await migrationPool('dvaia_secureshop_review_migration'),commerce:await migrationPool('dvaia_secureshop_migration')},
  requiredObjectives:['fixture_objective']}),{code:'SECURESHOP_BOUND_REVIEW_UNAVAILABLE'});
});

test('readiness rejects missing effective grants and excess embedding runtime authority', async () => {
  const appendArgs = 'uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,text,integer,jsonb';
  for (const privilegeFailure of [
    ...['manual_runtime_receipts', 'embedding_revisions', 'embedding_vectors', 'embedding_heads',
      'embedding_cleanup_receipts', 'embedding_preimages', 'manual_preimages'].map(name => `secureshop_review.product_target_${name}`),
    `secureshop_review.append_product_manual_retrieval_attested(${appendArgs},bytea)`,
    'secureshop_review.manual_runtime_receipt_digest(uuid,bytea,bytea)',
    'secureshop_review.capture_product_manual_preimage(uuid,uuid,jsonb)',
    'secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb)',
    'secureshop_review.product_embedding_source_digest(uuid,bigint)',
    `secureshop_review.append_product_manual_retrieval(${appendArgs})`,
    'secureshop_review.cleanup_retired_product_embeddings(uuid)',
  ]) {
    await assert.rejects(assertSecureShopBoundReviewReadiness({
      identityPool: await readinessPool('dvaia_identity_runtime'),
      agentsPool: await readinessPool('dvaia_secureshop_agents_runtime'),
      reviewPool: await readinessPool('dvaia_secureshop_review_runtime', { privilegeFailure }),
      commercePool: await readinessPool('dvaia_secureshop_runtime'),
      migrationPools: {
        identity: await migrationPool('dvaia_identity_migration'),
        agents: await migrationPool('dvaia_secureshop_agents_migration'),
        review: await migrationPool('dvaia_secureshop_review_migration'),
        commerce: await migrationPool('dvaia_secureshop_migration'),
      }, requiredObjectives: ['fixture_objective'],
    }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE',
      message: 'SecureShop embedding runtime privileges are not ready' });
  }
});

test('default readiness includes the always-mounted browser objective without widening explicit fixtures', async () => {
  assert.deepEqual([...DEFAULT_OBJECTIVES], [
    'ss_loop_observation', 'ss_content_persist', 'ss_content_followed',
    'ss_stored_browser_execution',
  ]);
  const pools = {
    identityPool: await readinessPool('dvaia_identity_runtime', {
      catalogObjectives: [...DEFAULT_OBJECTIVES],
    }),
    agentsPool: await readinessPool('dvaia_secureshop_agents_runtime'),
    reviewPool: await readinessPool('dvaia_secureshop_review_runtime'),
    commercePool: await readinessPool('dvaia_secureshop_runtime'),
  };
  const migrationPools = {
    identity: await migrationPool('dvaia_identity_migration'),
    agents: await migrationPool('dvaia_secureshop_agents_migration'),
    review: await migrationPool('dvaia_secureshop_review_migration'),
    commerce: await migrationPool('dvaia_secureshop_migration'),
  };
  const ready = await assertSecureShopBoundReviewReadiness({ ...pools, migrationPools });
  assert.deepEqual(ready.objectives, [...DEFAULT_OBJECTIVES].sort());

  await assert.rejects(assertSecureShopBoundReviewReadiness({ ...pools,
    identityPool: await readinessPool('dvaia_identity_runtime', {
      catalogObjectives: DEFAULT_OBJECTIVES.filter(id => id !== 'ss_stored_browser_execution'),
    }), migrationPools }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  await assert.rejects(assertSecureShopBoundReviewReadiness({ ...pools,
    identityPool: await readinessPool('dvaia_identity_runtime', {
      catalogActive: false, catalogObjectives: [...DEFAULT_OBJECTIVES],
    }), migrationPools }), { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });

  const explicit = await assertSecureShopBoundReviewReadiness({ ...pools,
    identityPool: await readinessPool('dvaia_identity_runtime'), migrationPools,
    requiredObjectives: ['fixture_objective'] });
  assert.deepEqual(explicit.objectives, ['fixture_objective']);
});

function methodMap(names, extra = {}) {
  return Object.freeze({ ...Object.fromEntries(names.map(name => [name, async () => ({})])), ...extra });
}

test('V01 composition audit reader executes the protected join behind the current launch fence', async () => {
  const storage = { launchId: '10000000-0000-4000-8000-000000000001',
    scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
    platformOwnerId: 4, platformSessionId: 5,
    targetId: '30000000-0000-4000-8000-000000000001' };
  const execution = { launchId: '40000000-0000-4000-8000-000000000001',
    scenarioId: '50000000-0000-4000-8000-000000000001', generation: 2,
    platformOwnerId: 4, platformSessionId: 6 };
  const scene = { sceneId: '60000000-0000-4000-8000-000000000001',
    sceneGeneration: 3, grantId: '70000000-0000-4000-8000-000000000001' };
  const target = createSceneBinding(storage, { ...scene, execution, withLease: work => work() });
  const eventId = '80000000-0000-4000-8000-000000000001';
  const paramsJson = JSON.stringify({ total: 17.25, shippingAddress: 'Owned synthetic address',
    paymentMethod: 'synthetic_card', storageTargetId: storage.targetId,
    sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration });
  let checks = 0, connections = 0, selects = 0, stale = false;
  const client = { async query(sql) {
    if (sql.includes('assert_scene_execution_grant')) return { rows: [{ allowed: true }] };
    if (sql.includes('FROM secureshop_review.bound_audit_events e')) {
      selects += 1;
      return { rows: [{ event_id: eventId, ts: '2026-10-15T01:02:03.000000Z',
        actor: 'customer', action: 'checkout', outcome: 'completed', target: '9',
        source_kind: 'order', source_id: '9', params_json: paramsJson,
        order_total: '17.25', payment_method: 'synthetic_card',
        shipping_address: 'Owned synthetic address' }] };
    }
    return { rows: [] };
  }, release() {} };
  const reviewPool = { async query() { return { rows: [] }; }, async connect() {
    connections += 1; return client;
  } };
  const launches = { async assertCurrent(value) {
    checks += 1;
    assert.deepEqual(value, execution);
    if (stale) throw Object.assign(new Error('stale launch'), { code: 'STALE_LAUNCH' });
  } };
  const store = createCheckoutAuditReadStore({ reviewPool, launches });
  const result = await store.checkoutForOrder(target, 11,
    { status: 'completed', order: { id: 9, total: 17.25 } });
  assert.equal(result.eventId, eventId);
  assert.deepEqual(result.observation, { eventId, timestamp: '2026-10-15T01:02:03.000000Z',
    actor: 'customer', action: 'checkout', outcome: 'completed', orderId: 9, total: 17.25 });
  assert.equal(checks, 3); assert.equal(connections, 1); assert.equal(selects, 1);
  stale = true;
  await assert.rejects(store.checkoutForOrder(target, 11,
    { status: 'completed', order: { id: 9, total: 17.25 } }), { code: 'STALE_LAUNCH' });
  assert.equal(checks, 4); assert.equal(connections, 1); assert.equal(selects, 1,
    'stale launch is denied before the protected store connection or read');
});

test('composition exposes the one coordinator and accepts only a branded prepared grading bootstrap', async t => {
  const pool = { query: async () => ({ rows: [] }), connect: async () => ({
    query: async () => ({ rows: [] }), release() {}, on() {}, removeListener() {},
  }) };
  const launchScope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',
    generation:1,platformOwnerId:4,platformSessionId:5};
  const launches = methodMap(['assertCurrent', 'reserveReviewsTarget', 'readExistingReviewsTarget', 'reserveProductsTarget',
    'reservePersonaInboxTarget', 'beginReset', 'commitReset'],{resolveCapability:async()=>launchScope});
  const cleanupAuthority = methodMap(['getOperation', 'checkTarget', 'checkReviewTarget', 'checkProductTarget',
    'listTargets', 'assertResolved', 'finalizeReconciliation']);
  const conversationRepository = methodMap(['acquireBoundSession', 'activateBoundSession',
    'abandonBoundSession', 'getBoundSession', 'appendMessage', 'getMessages', 'getTokens',
    'addTokens', 'appendTraces', 'getTrace', 'getTraceEvents', 'latestTrace', 'personaLatestTrace']);
  const journal = methodMap(['lookupGeneralRequest', 'lookupReviewModerationRequest', 'claim', 'complete', 'markUncertain', 'readBoundRequest', 'readAuditRequest']);
  const reviewRepository = methodMap(['provision', 'listReviews', 'listPending', 'submitReview',
    'decide', 'cleanup', 'readCleanupReceipt', 'readSubmission', 'captureReviewAdmissionTime', 'readDecisionReceipt',
    'readSceneTarget', 'provisionScene']);
  const productRepository = methodMap(['open', 'provision', 'list', 'get', 'cleanup', 'readCleanupReceipt']);
  const catalog = methodMap(['listProducts', 'getProduct', 'listMerchantProducts', 'getOwnedMerchantProduct', 'createMerchantProduct',
    'updateMerchantProduct', 'archiveMerchantProduct', 'hasProduct', 'prepareTarget']);
  const account = methodMap(['profile', 'updateProfile', 'addresses', 'createAddress',
    'updateAddress', 'deleteAddress']);
  const runCoordinator = methodMap(['run', 'reset']);
  const audit = { agents: methodMap(['append', 'recent']), review: methodMap(['append', 'recent']),
    reader: methodMap(['recent']), async cleanup() {} };
  const resetComposition = createSecureShopCleanupComposition({ identityPool: pool,
    agentsPool: pool, reviewPool: pool, leasePool: pool, launches, cleanupAuthority,
    conversationRepository, journal, reviewRepository, productRepository, runCoordinator, audit });
  let listingsLookups = 0;
  const composition = createSecureShopBoundReviewComposition({ identityPool: pool,
    agentsPool: pool, reviewPool: pool, resetComposition, catalog, account,
    getListingsApplication() { listingsLookups++; throw new Error('Listings is assembled after role assistants'); },
    agentRuntime: { manifest: { getForRole() { throw new Error('global manifest must remain unused'); },
      buildExternalMcpPromptBlock() { throw new Error('global MCP prompt must remain unused'); } },
    provider: { chat: async () => ({}), finalResponse: async () => ({}) } },
    authenticatePersona(_req, _res, next) { next(); }, fixtures: [],
    requiredObjectives: ['fixture_objective'],
    judge: async () => ({ verdict: 'fail', criteria: [], explanation: 'fixture' }),
    reviewCardRenderer: { sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      async renderReviewCard(review) { return `<article>${review.body}</article>`; } },
    browserQualification: { async qualify() { return { executed: false }; }, async close() {} },
  });
  assert.equal(listingsLookups, 0, 'composition must not eagerly resolve its later Listings dependency');
  assert.equal(composition.runCoordinator, runCoordinator);
  assert.equal(typeof composition.productAssist.summary, 'function');
  assert.equal(typeof composition.productAssist.similar, 'function');
  assert.equal(composition.launchResetCoordinator, resetComposition.launchResetCoordinator);
  assert.equal(composition.createStudentDeletionCleanup, resetComposition.createStudentDeletionCleanup);
  assert.equal(typeof composition.browserRouter, 'function');
  assert.equal(composition.launchResetCoordinator.recover instanceof Function, true);
  assert.equal(composition.ownerResetService.resetOwner instanceof Function, true);
  const deletionRepository = { listSecureShopResetIds: async () => [] };
  assert.equal(typeof composition.createStudentDeletionCleanup(deletionRepository), 'function');
  assert.equal(Object.isFrozen(composition), true);
  assert.equal(Object.isFrozen(composition.repositories), true);
  const personaAuthority={async resolve(){return{id:1,role:'merchant',authority_version:'1'};},async read(){return{id:1,role:'merchant',authority_version:'1'};},capture(){return{assertRemoteAdmission:async()=>{},withCrossStoreEffect:async work=>work({}),withPersonaEffect:async work=>work({})};}};
  const personaBindings=methodMap(['capture','initial','inherit','commit','check','projectRecoverable'],{assertReady:async()=>({ready:true})});
  const progress={getGeneration:async()=>0},agentsPool={query:pool.query,connect:pool.connect};
  const gradingBootstrap=await require('../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({identityPool:pool,agentsPool,progress,resetComposition,assertAuthorityReady:async()=>true},{createAuthority:()=>personaAuthority,createBindings:()=>personaBindings,createCore:input=>require('../server/services/objectiveGradingCore').createObjectiveGradingCore(input,{createObjectiveJudgmentRepository:()=>methodMap(['listRecoverable','beginEvaluation','recordVerdict','getEvaluation','beginRetry','assertRecoveryAuthority']),createObjectiveCompletionService:()=>({}),createObjectiveRegradeService:()=>async()=>{}})});
  const rawCalls=[];
  const rawIneligible=operationId=>({operationId,completed:false,status:'ineligible',modelEvaluated:false});
  const rawListingAssessment={
    async runAttempt(input){rawCalls.push(['assess',input]);return rawIneligible(input.operationId);},
    async readOutcome(input){rawCalls.push(['read',input]);return rawIneligible(input.operationId);},
  };
  const toolPolicyRepository=methodMap(['admitTool','readPolicy','mutate','readOperation']);
  let diagnosticLookups=0;
  const preparedOptions={ identityPool: pool,
    agentsPool, reviewPool: pool, commercePool:pool, resetComposition, gradingBootstrap, catalog, account,
    scenes:{async readExisting(){return null},async readRetained(){return null},async withProvisionLease(work){return work()}},
    toolPolicyRepository,rawListingAssessment,
    getSystemDiagnostic(){diagnosticLookups++;throw Error('Diagnostic service is assembled after role assistants');},
    modeAuthority:require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({
      launches,progress:{async getEvaluationScope(){return{mode:'fixed',generation:0,modeStamp:'fixture'};}},
    }),
    jwtSecret:'owned-prepared-grading-secret-at-least-32-bytes',
    agentRuntime: { manifest: { getForRole() { return []; } }, provider: { chat: async () => ({}), finalResponse: async () => ({}) } },
    authenticatePersona(req,_res,next){req.ssUser={id:6,role:'merchant'};
      req.ssPersonaSession={sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'2'};next();},fixtures:[],requiredObjectives:['fixture_objective'],
    judge:async()=>({verdict:'fail',criteria:[],explanation:'fixture'}),
    reviewCardRenderer:{sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),async renderReviewCard(review){return`<article>${review.body}</article>`;}},
    browserQualification:{async qualify(){return{executed:false};},async close(){}},
  };
  // Exercise the real parent constructor/options snapshot, observing only its SSRF
  // factory boundary. The child adapter ownership is tested in SsrfCandidate.
  const vm=require('node:vm'),fs=require('node:fs'),{createRequire}=require('node:module');
  const filename=require.resolve('../server/services/secureshopBoundReviewComposition');
  const localRequire=createRequire(filename),observed=[],testModule={exports:{}};
  let ssrfClosed=0,adapterClosed=0;
  const policyAdapter={readComponent(){return {id:'owned-policy-renderer'};},async qualifyPolicyOutput(){return {executed:false};},
    async close(){adapterClosed++;}};
  vm.runInThisContext(`(function(require,module,exports,__dirname,__filename){${fs.readFileSync(filename,'utf8')}
    module.exports.testSnapshot=snapshotProductionOptions;module.exports.testSameInputs=sameInputs;})`,{filename})(name=>{
    if(name==='./secureshopSsrfComposition')return {createSecureShopSsrfComposition(input){observed.push(input);
      return Object.freeze({ready:false,async close(){ssrfClosed++;}});}};
    return localRequire(name);
  },testModule,testModule.exports,path.dirname(filename),filename);
  const savedOptions=testModule.exports.testSnapshot({policyOutputBrowserQualification:policyAdapter});
  assert.equal(savedOptions.configured.policyOutputBrowserQualification,policyAdapter);
  assert.equal(savedOptions.identity.policyOutputBrowserQualification,policyAdapter);
  assert.equal(testModule.exports.testSameInputs(savedOptions.identity,
    {...savedOptions.identity,policyOutputBrowserQualification:{...policyAdapter}}),false);
  const policyComposition=testModule.exports.createSecureShopBoundReviewComposition({
    ...savedOptions.configured,...preparedOptions,agentRuntime:preparedOptions.agentRuntime,
    fixtures:[],requiredObjectives:['fixture_objective'],ssrfFeature:true});
  assert.equal(observed.length,1);assert.equal(observed[0].enabled,true);
  assert.equal(observed[0].policyOutputBrowserQualification,policyAdapter);
  await Promise.all([policyComposition.closeBrowserAssessment(),policyComposition.closeBrowserAssessment()]);
  assert.equal(ssrfClosed,1);assert.equal(adapterClosed,0,'injected browser remains host-owned');
  await policyAdapter.close();assert.equal(adapterClosed,1,'host performs the single injected-adapter close');
  const searchEchoFactory=require('../server/services/secureshopSearchEchoBrowserAssessment');
  const originalSearchEchoFactory=searchEchoFactory.createSearchEchoBrowserAssessment;
  const searchEchoVersions=[];
  t.mock.method(searchEchoFactory,'createSearchEchoBrowserAssessment',input=>{
    searchEchoVersions.push(input.evidenceVersion);
    return originalSearchEchoFactory(input);
  });
  const prepared=createSecureShopBoundReviewComposition(preparedOptions);
  assert.equal(typeof prepared.accountAvatar?.upload, 'function',
    'JSON-only direct avatar must compose without optional V06 asset origin or capability');
  assert.equal(typeof prepared.accountAvatar?.read, 'function');
  assert.equal(prepared.avatarUpload, undefined);
  assert.equal(prepared.roleAssistants.admin.userLookupAssessment.objectiveId,'ss_user_lookup_sensitive_disclosure');
  assert.equal(typeof prepared.roleAssistants.admin.userLookupAssessment.readOutcome,'function');
  const preparedV8=createSecureShopBoundReviewComposition({...preparedOptions,searchEchoEvidenceVersion:8});
  const preparedV9=createSecureShopBoundReviewComposition({...preparedOptions,searchEchoEvidenceVersion:9});
  assert.equal(prepared.searchEcho.ready,true);
  assert.equal(preparedV8.searchEcho.ready,true);
  assert.equal(preparedV9.searchEcho.ready,true);
  assert.deepEqual(searchEchoVersions,[2,8,9],'trusted composition forwards the exact default or explicit assessment version');
  for(const version of [1,3,7,10,'8',null])assert.throws(()=>createSecureShopBoundReviewComposition({
    ...preparedOptions,searchEchoEvidenceVersion:version}),/search echo assessment evidence version/);
  assert.deepEqual(searchEchoVersions,[2,8,9],'invalid versions never reach assessment construction');
  t.after(()=>Promise.all([prepared.closeBrowserAssessment(),preparedV8.closeBrowserAssessment(),preparedV9.closeBrowserAssessment()]));
  assert.equal(prepared.runCoordinator,runCoordinator);
  assert.equal(prepared.repositories.personas.candidatePersonaAuthority,personaAuthority);
  assert.equal(prepared.customerChat?.ready,true,
    'prepared direct composition must wire canonical policy admission before offering commerce chat');
  assert.equal(prepared.agencyRole?.ready,true,
    'prepared composition must wire the customer role assessment with its source reader');
  assert.equal(typeof prepared.agencyRole.assessment.readOutcome,'function');
  assert.equal(prepared.idorLesson?.ready,true);
  for(const name of ['prepare','readCards','readRequest','readAssessment','retryAssessment'])
    assert.equal(typeof prepared.idorLesson.runtime[name],'function');
  assert.equal(prepared.roleAssistants.merchant?.ready,true);
  assert.equal(diagnosticLookups,0,'assessment construction must not resolve the later diagnostic service');
  assert.equal(prepared.roleAssistants.admin?.ready,true);
  for(const method of ['runAttempt','readOutcome','assertRetainedPacket'])
    assert.equal(typeof prepared.roleAssistants.admin.systemDiagnosticAssessment[method],'function');
  const app=express();app.use(express.json());app.use('/api/secureshop',prepared.roleAssistants.merchant.router);
  const server=app.listen(0);
  try{
    const operationId='40000000-0000-4000-8000-000000000001';
    const base=`http://127.0.0.1:${server.address().port}/api/secureshop/agents/merchant/assistant/listing-create`;
    const headers={'x-owasp-ai-goat-secureshop-launch':'a'.repeat(43),'content-type':'application/json'};
    const assessed=await fetch(`${base}/assess`,{method:'POST',headers,body:JSON.stringify({operationId})});
    assert.equal(assessed.status,200);assert.equal(assessed.headers.get('cache-control'),'no-store');
    assert.deepEqual(await assessed.json(),rawIneligible(operationId));
    const read=await fetch(`${base}/assessment/${operationId}`,{headers});
    assert.equal(read.status,200);assert.deepEqual(await read.json(),rawIneligible(operationId));
    const forged=await fetch(`${base}/assess`,{method:'POST',headers,
      body:JSON.stringify({operationId,scope:{platformOwnerId:999}})});
    assert.equal(forged.status,400);
    const unauthorized=await fetch(`${base}/assessment/${operationId}`,{
      headers:{'content-type':'application/json'}});
    assert.equal(unauthorized.status,404);
    assert.equal(rawCalls.length,2);
    assert.deepEqual(rawCalls.map(([kind,input])=>[kind,input.operationId]),[['assess',operationId],['read',operationId]]);
    for(const [,input] of rawCalls){assert.deepEqual(input.scope,launchScope);
      assert.deepEqual(input.persona,{id:6,role:'merchant'});
      assert.deepEqual(input.personaSession,{sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'2'});
      assert.equal(typeof input.signal?.aborted,'boolean');}
  }finally{await new Promise(resolve=>server.close(resolve));}
  assert.throws(()=>createSecureShopBoundReviewComposition({identityPool:pool,agentsPool,
    reviewPool:pool,resetComposition,gradingBootstrap:Object.freeze({...gradingBootstrap}),catalog,account,
    agentRuntime:{provider:{chat:async()=>({})}}}),/Prepared persona grading bootstrap required/);
});

test('direct MCP trust construction uses the default owned bundle without startup effects', () => {
  let queries = 0;
  let providerCalls = 0;
  const pool = { async query() { queries += 1; return { rows: [] }; }, async connect() {
    return { async query() { queries += 1; return { rows: [] }; }, release() {}, on() {}, removeListener() {} };
  } };
  const launches = methodMap(['assertCurrent', 'resolveCapability', 'reserveReviewsTarget', 'readExistingReviewsTarget',
    'reserveProductsTarget', 'reserveMcpTarget', 'beginReset', 'commitReset']);
  const cleanupAuthority = methodMap(['getOperation', 'checkTarget', 'checkReviewTarget',
    'checkProductTarget', 'listTargets', 'assertResolved', 'finalizeReconciliation']);
  const conversationRepository = methodMap(['acquireBoundSession', 'activateBoundSession',
    'abandonBoundSession', 'getBoundSession', 'appendMessage', 'getMessages', 'getTokens',
    'addTokens', 'appendTraces', 'getTrace', 'latestTrace']);
  const journal = methodMap(['lookupGeneralRequest', 'lookupReviewModerationRequest', 'lookupMcpRequest', 'claim', 'complete', 'markUncertain']);
  const reviewRepository = methodMap(['provision', 'listReviews', 'listPending', 'submitReview',
    'decide', 'cleanup', 'readCleanupReceipt', 'readSubmission', 'captureReviewAdmissionTime']);
  const productRepository = methodMap(['open', 'provision', 'list', 'get', 'cleanup', 'readCleanupReceipt']);
  const catalog = methodMap(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
    'updateMerchantProduct', 'archiveMerchantProduct', 'hasProduct', 'prepareTarget']);
  const account = methodMap(['profile', 'updateProfile', 'addresses', 'createAddress',
    'updateAddress', 'deleteAddress']);
  const runCoordinator = methodMap(['run', 'reset']);
  const common = { identityPool: pool, agentsPool: pool, reviewPool: pool, leasePool: pool,
    launches, cleanupAuthority, conversationRepository, journal, reviewRepository,
    productRepository, runCoordinator, catalog, account, mcpTrustFeature: true,
    agentRuntime: { provider: { async chat() { providerCalls += 1; return {}; },
      async finalResponse() { providerCalls += 1; return {}; } } },
    authenticatePersona(_req, _res, next) { next(); }, fixtures: [],
    judge: async () => ({ verdict: 'fail', criteria: [], explanation: 'fixture' }),
    reviewCardRenderer: { sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      async renderReviewCard(review) { return `<article>${review.body}</article>`; } },
    browserQualification: { async qualify() { return { executed: false }; }, async close() {} },
  };
  assert.throws(() => createSecureShopBoundReviewComposition(common), {
    code: 'SECURESHOP_CLEANUP_UNAVAILABLE',
  });
  const composition = createSecureShopBoundReviewComposition({ ...common,
    mcpTrustFixtureRoot: path.join(root, '.owned-mcp-trust-fixture') });
  assert.equal(composition.mcpTrust.ready, true);
  assert.equal(typeof composition.mcpTrust.router, 'function');
  assert.equal(typeof composition.launchResetCoordinator.reset, 'function');
  assert.equal(queries, 0);
  assert.equal(providerCalls, 0);
});

test('composition rejects missing authority rather than constructing a partial runtime', () => {
  assert.throws(() => createSecureShopBoundReviewComposition({}), {
    code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE',
  });
});

test('V01 and V06 canonical assessments bind publication scope to shop tenant mode',async()=>{
  const source=await require('node:fs/promises').readFile(
    path.join(root,'server/services/secureshopBoundReviewComposition.js'),'utf8');
  for(const [start,end] of [['let avatarUpload, accountAvatar, uploadRepository','let productSearch;'],
    ['let checkoutAuditLesson;','const refundRepository']]){
    const block=source.slice(source.indexOf(start),source.indexOf(end));
    assert.ok(block.length>0);assert.doesNotMatch(block,/publicationModes:\s*workshopProgress/);
    assert.match(block,/publicationModes:\s*require\('\.\.\/database\/postgres\/secureshopModeRepository'\)\.createSecureShopModeRepository\(identityPool\)/);
  }
  assert.match(source,/accountAvatar=require\('\.\/secureshopBoundAccountAvatar'\)/);
  assert.ok(source.indexOf('accountAvatar=require') < source.indexOf('if (uploadAssetOrigin !== undefined'),
    'direct JSON avatar service must not require the optional V06 asset origin');
});

test('close waits for pending initialization and releases every temporary readiness pool', async () => {
  const compositionPath = path.join(root, 'server/services/secureshopBoundReviewComposition.js');
  const script = String.raw`
    'use strict';
    const assert = require('node:assert/strict');
    const Module = require('node:module');
    const target = ${JSON.stringify(compositionPath)};
    const originalLoad = Module._load;
    let release;
    const blocked = new Promise(resolve => { release = resolve; });
    const ended = [];
    const stores = {
      IDENTITY: ['dvaia_identity_runtime', 'identity_owned'],
      SECURESHOP_AGENTS: ['dvaia_secureshop_agents_runtime', 'agents_owned'],
      SECURESHOP_REVIEW: ['dvaia_secureshop_review_runtime', 'review_owned'],
      SECURESHOP: ['dvaia_secureshop_runtime', 'commerce_owned'],
    };
    function runtimePool(store) {
      const [role, database] = stores[store];
      return { async query(sql, args) {
          if (sql.startsWith('SELECT current_user')) return { rows: [{ role, database }] };
          if (sql.includes('FROM unnest')) return { rows: args[0].map(value => ({ value, ready: true })) };
          if (sql.includes('FROM pg_constraint')) return { rows: args[0].map(conname => ({
            conname, ready: true,
          })) };
          if (sql.includes('FROM secureshop_auth.assessment_objectives')) return { rows: [] };
        throw new Error('unexpected runtime query');
      } };
    }
    const runtime = Object.fromEntries(Object.keys(stores).map(store => [store, runtimePool(store)]));
    function migrationPool(store) {
      const [runtimeRole, database] = stores[store];
      const role = runtimeRole.replace('_runtime', '_migration');
      return { async query(sql) {
        if (sql.startsWith('SELECT current_user')) return { rows: [{ role, database }] };
        if (sql.startsWith('SELECT name,checksum')) {
          if (store === 'IDENTITY') await blocked;
          return { rows: [{ name: '001_owned.sql', checksum: 'a'.repeat(64) }] };
        }
        throw new Error('unexpected migration query');
      }, async end() { ended.push(store); } };
    }
    Module._load = function(request, parent, isMain) {
      if (parent?.filename === target && request === '../../db/postgres/migrate') {
        return { readMigrations: async () => [{ name: '001_owned.sql', checksum: 'a'.repeat(64) }] };
      }
      if (parent?.filename === target && request === '../database/postgres') {
        return { createPool(_env, key) {
          const store = key.includes('AGENTS') ? 'SECURESHOP_AGENTS'
            : key.includes('REVIEW') ? 'SECURESHOP_REVIEW'
            : key.startsWith('SECURESHOP_') ? 'SECURESHOP' : 'IDENTITY';
          return migrationPool(store);
        } };
      }
      if (parent?.filename === target && request === './postgresIdentityAdapter') {
        return { getPostgresIdentityAdapter: () => ({ pool: runtime.IDENTITY }) };
      }
      if (parent?.filename === target && request === '../database/postgres/secureshopPools') {
        return { getAgentsPool: () => runtime.SECURESHOP_AGENTS,
          getCommercePool: () => runtime.SECURESHOP };
      }
      if (parent?.filename === target && request === '../database/postgres/secureshopReviewDb') {
        return { getSecureShopReviewPool: () => runtime.SECURESHOP_REVIEW };
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
    process.env.SS_PERSONA_INBOX_READY = 'false';
    for (const key of ['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL',
      'SECURESHOP_AGENTS_DATABASE_URL', 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL',
      'SECURESHOP_REVIEW_DATABASE_URL', 'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL']) {
      process.env[key] = 'postgresql://owned.invalid/test';
    }
    process.env.SECURESHOP_DATABASE_URL = 'postgresql://owned.invalid/test';
    process.env.SECURESHOP_MIGRATION_DATABASE_URL = 'postgresql://owned.invalid/test';
    process.env.JWT_SECRET = 'owned-test-secret-at-least-thirty-two-bytes';
    (async () => {
      const composition = require(target);
      const initializing = composition.getSecureShopBoundReviewComposition({
        agentRuntime: {}, authenticatePersona() {}, fixtures: [], requiredObjectives: ['owned'],
        personaInboxFeature: false,
      });
      const closing = composition.closeSecureShopBoundReviewComposition();
      release();
      await assert.rejects(initializing, { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
      await closing;
      assert.deepEqual(ended.sort(), Object.keys(stores).sort());
      assert.throws(() => composition.getSecureShopBoundRunCoordinator(), {
        code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE',
      });
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  await promisify(execFile)(process.execPath, ['-e', script], { timeout: 10000 });
});

test('shared grading rejects foreign pools and unready persona promotion before store work',()=>{
  let queries=0;const pool={query:async()=>{queries++;return{rows:[]};},connect:async()=>{throw Error('Unexpected connection');}};
  const {createObjectiveGradingCore}=require('../server/services/objectiveGradingCore');
  const makeCore=(identityPool,personaBindings)=>createObjectiveGradingCore({identityPool,progress:{getGeneration:async()=>0},...(personaBindings?{personaBindings}:{})},{
    createObjectiveJudgmentRepository:()=>({listRecoverable:async()=>[]}),createObjectiveCompletionService:()=>({}),createObjectiveRegradeService:()=>async()=>{},
  });
  const options={identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool,agentRuntime:{provider:{chat:async()=>({})}}};
  assert.throws(()=>createSecureShopBoundReviewComposition({...options,gradingCore:makeCore({...pool})}),/pool/i);
  assert.throws(()=>createSecureShopBoundReviewComposition({...options,gradingCore:makeCore(pool,{capture(){}})}),/Persona grading production readiness unavailable/);
  assert.equal(queries,0);
});


test('task policy composition refuses unsupported readiness or substituted consumers', () => {
  for (const options of [ {taskPoliciesEnabled:'true'}, {taskPoliciesEnabled:true},
    {taskPoliciesEnabled:true,promptPolicyRepository:{},productAssist:{}} ]) {
    assert.throws(() => createSecureShopBoundReviewComposition(options),
      {code:'SECURESHOP_BOUND_REVIEW_UNAVAILABLE'});
  }
});

test('Analytics and prompt policies compose without advertising an unsupported editable task', () => {
  const { attachAnalyticsComposition } = require('../server/services/secureshopBoundReviewComposition');
  const { createBoundPromptPoliciesRouter } = require('../server/routes/secureshop/boundPromptPolicies');
  const promptPolicies = { list() {}, render() {}, remove() {}, operation() {} };
  const analytics = Object.freeze({ application: {} });
  for (const targets of [undefined, Object.freeze(['summarizer', 'review-moderator'])]) {
    const original = Object.freeze({ promptPolicies,
      ...(targets ? { promptPolicyTaskTargets: targets } : {}) });
    const composed = attachAnalyticsComposition(original, analytics);
    assert.equal(composed.analytics, analytics);
    assert.equal(composed.promptPolicies, promptPolicies);
    assert.equal(composed.promptPolicyTaskTargets, targets);
    assert.ok(Object.isFrozen(composed));
    assert.doesNotThrow(() => createBoundPromptPoliciesRouter({ service: composed.promptPolicies,
      authenticatePersona() {}, supportedTaskTargets: composed.promptPolicyTaskTargets }));
  }
  assert.throws(() => createBoundPromptPoliciesRouter({ service: promptPolicies,
    authenticatePersona() {}, supportedTaskTargets: ['analytics'] }), /task targets invalid/);
});

test('optional diagnostic composition forwards prepared persona and feature mode authorities', async () => {
  const client = Object.freeze({ read() {} });
  const personaAuthority = Object.freeze({ capture() {} });
  const preparedGrading = Object.freeze({ personaAuthority });
  const modeAuthority = Object.freeze({ capture() {}, assertToken() {} });
  const agentsPool = Object.freeze({ query() {} });
  const audit = Object.freeze({ append() {} });
  const authenticatePersona = () => {};
  let received;
  const value = Object.freeze({ ready: true });
  assert.equal(await createOptionalSystemDiagnosticComposition({}), undefined);
  await assert.rejects(createOptionalSystemDiagnosticComposition({ systemDiagnosticClient: client }),
    { code: 'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  const result = await createOptionalSystemDiagnosticComposition({ systemDiagnosticClient: client,
    preparedGrading, agentsPool, audit, authenticatePersona, modeAuthority }, {
    createComposition: async input => { received = input; return value; },
  });
  assert.equal(result, value);
  assert.deepEqual(received, { agentsPool, personaAuthority, modeAuthority, audit, client, authenticatePersona });
});


test('readiness rejects each missing practice relation even with an exact migration ledger', async () => {
  for (const name of ['practice_preferences','practice_selections','practice_operations','practice_publications']) {
    await assert.rejects(assertSecureShopBoundReviewReadiness({
      identityPool: await readinessPool('dvaia_identity_runtime', { missingRelation: `secureshop_auth.${name}` }),
      agentsPool: await readinessPool('dvaia_secureshop_agents_runtime'),
      reviewPool: await readinessPool('dvaia_secureshop_review_runtime'),
      commercePool: await readinessPool('dvaia_secureshop_runtime'),
      migrationPools: {
        identity: await migrationPool('dvaia_identity_migration'), agents: await migrationPool('dvaia_secureshop_agents_migration'),
        review: await migrationPool('dvaia_secureshop_review_migration'), commerce: await migrationPool('dvaia_secureshop_migration'),
      }, requiredObjectives: ['fixture_objective'],
    }), { code:'SECURESHOP_BOUND_REVIEW_UNAVAILABLE' });
  }
});
