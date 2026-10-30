'use strict';

// Storage and forward-migration qualification only. Branded scene capabilities,
// persona coordinates and mode tokens below are controlled test inputs. This is
// not browser authentication, genuine model/Judge credit or a full reset flow.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createAgentsMigrationView } = require('../helpers/secureshopAgentsMigrationView');
const { createSceneBinding } = require('../../server/services/secureshopSceneBinding');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopTicketRepository } = require('../../server/database/postgres/secureshopTicketRepository');
const { assertBoundToolPolicyReadiness } = require('../../server/database/postgres/secureshopBoundToolPolicyReadiness');
const Ticket = require('../../server/services/secureshopTicketContract');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_TICKET_REPOSITORY_';
const REVIEW = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_review');
const REVIEW_NAME = '0049_bound_support_ticket_receipts.sql';
const AGENTS_NAME = '0088_customer_ticket_prepare_registry_successor.sql';
const STORES = Object.freeze({ REVIEW_FRESH: 'secureshop_review', REVIEW_POPULATED: 'secureshop_review',
  AGENTS_FRESH: 'secureshop_agents', AGENTS_POPULATED: 'secureshop_agents' });
const enabled = process.env.SECURESHOP_TICKET_REPOSITORY_NATIVE === '1' && process.env.PG_TEST_DISPOSABLE === 'yes';
const digest = value => createHash('sha256').update(value).digest('hex');
const stale = () => Object.assign(new Error('Controlled retired authority'), { code: 'SHOP_SCENE_STALE' });
const scope = (owner = 101) => ({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: owner, platformSessionId: owner + 1000 });
const ledger = async pool => (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;

function admittedUrls() {
  assert.equal(path.resolve(process.cwd()), ROOT);
  assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
  const owner = process.env[`${PREFIX}OWNER`];
  assert.match(owner, /^[a-f0-9]{12}$/);
  const urls = {}, names = new Set(); let port;
  for (const [store, family] of Object.entries(STORES)) {
    for (const role of ['RUNTIME', 'MIGRATION']) {
      const key = `${store}_${role}`, url = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.username, `dvaia_${family}_${role.toLowerCase()}`);
      assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
      assert.equal(url.pathname, `/owasp_ai_goat_test_ticket_${owner}_${store.toLowerCase()}`);
      assert.match(url.port, /^[1-9][0-9]{0,4}$/); assert.ok(Number(url.port) <= 65535);
      port ??= url.port; assert.equal(url.port, port);
      urls[key] = url.href;
    }
    const name = new URL(urls[`${store}_RUNTIME`]).pathname;
    assert.equal(name, new URL(urls[`${store}_MIGRATION`]).pathname);
    assert.ok(!names.has(name)); names.add(name);
  }
  return urls;
}

async function reviewView(through, directories) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ticket-migrations-'));
  directories.push(directory);
  for (const entry of await readMigrations(REVIEW)) {
    if (Number(entry.name.slice(0, 4)) <= through) {
      await fs.symlink(path.join(REVIEW, entry.name), path.join(directory, entry.name));
    }
  }
  return directory;
}

const reviewSnapshot = async pool => ({
  targets: (await pool.query('SELECT * FROM secureshop_review.product_targets ORDER BY target_id')).rows,
  products: (await pool.query('SELECT * FROM secureshop_review.product_target_products ORDER BY target_id,product_id')).rows,
  grants: (await pool.query('SELECT * FROM secureshop_review.scene_execution_grants ORDER BY grant_id')).rows,
});
const ticketSnapshot = async (pool, targetId) => ({
  tickets: (await pool.query('SELECT * FROM secureshop_review.product_target_support_tickets WHERE target_id=$1 ORDER BY ticket_id', [targetId])).rows,
  receipts: (await pool.query('SELECT * FROM secureshop_review.product_target_support_ticket_receipts WHERE target_id=$1 ORDER BY ticket_id', [targetId])).rows,
});

function controlledAuthority() {
  const tokens = new WeakSet(), retired = new Set();
  const checkCurrent = async value => { if (retired.has(value.launchId)) throw stale(); };
  const modeAuthority = { assertToken(token) { if (!tokens.has(token)) throw stale(); return token; } };
  function token(execution, mode = 'vuln') {
    const value = Object.freeze({ snapshot: Object.freeze({ version: 1, featureId: 'support_tickets',
      policyVersion: 'owned-ticket-render-v1', mode, generation: 0, modeStamp: `controlled:${mode}:0`,
      scope: execution }), assertCurrent: () => checkCurrent(execution),
      assertCurrentAtEffect: () => checkCurrent(execution) });
    tokens.add(value); return value;
  }
  return { checkCurrent, modeAuthority, token, retire: value => retired.add(value.launchId) };
}

async function provision(pool, authority, owner) {
  const birth = scope(owner), targetId = randomUUID(), sceneId = randomUUID();
  const products = createSecureShopBoundProductRepository(pool, {
    checkCurrent: authority.checkCurrent,
    checkCleanup: async () => { throw Error('Full reset is outside this storage-only fixture'); },
  });
  await products.provision({ ...birth, targetId }, { ownMerchantId: 12, products: [{
    id: 7, sourceRetailerId: 1, retailerId: 12, name: 'Disposable ticket context',
    description: 'Synthetic source', descriptionHtml: '<p>Synthetic source</p>', price: 1,
    category: 'fixture', imageUrl: null, images: [], stockQuantity: 10, status: 'active',
    templateSource: '{{source}}', createdAt: null, updatedAt: null,
  }] });
  return { birth, targetId, sceneId };
}

async function grant(pool, authority, target, role, shopUserId, execution = target.birth) {
  const grantId = randomUUID();
  await pool.query(`INSERT INTO secureshop_review.scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
     original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)`, [grantId,target.sceneId,target.targetId,
    execution.launchId,execution.scenarioId,execution.generation,execution.platformOwnerId,execution.platformSessionId]);
  const retainedScene = createSceneBinding({ ...target.birth, targetId: target.targetId }, {
    sceneId: target.sceneId, sceneGeneration: 1, grantId, execution,
    withLease: async work => { await authority.checkCurrent(execution); const result = await work();
      await authority.checkCurrent(execution); return result; },
  });
  return { scope: execution, retainedScene, persona: { id: shopUserId, role },
    personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, modeToken: authority.token(execution),
    withEffect: async work => { await authority.checkCurrent(execution); const result = await work();
      await authority.checkCurrent(execution); return result; } };
}

function confirmation(context, subject = 'Controlled support request', body = '<b>Owned synthetic ticket</b>') {
  const originalMessage = JSON.stringify({ subject, body });
  const sourceOrigin = { turnSessionId: randomUUID(), turnRequestId: randomUUID(),
    toolKey: Ticket.TOOL, invocationStep: 1, callId: 'controlled-storage-proposal' };
  const ticketProposal = Ticket.prepare({ subject, body, message: originalMessage, sourceOrigin });
  const scene = context.retainedScene.scene;
  const source = Ticket.source({ execution: context.scope,
    customer: { shopUserId: context.persona.id, personaSessionId: context.personaSession.sessionId,
      authorityVersion: context.personaSession.authorityVersion },
    scene: { sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration,
      targetId: context.retainedScene.targetId, grantId: scene.grantId,
      birth: Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
        .map(key => [key, context.retainedScene[key]])) },
    turn: { sessionId: sourceOrigin.turnSessionId, requestId: sourceOrigin.turnRequestId, runId: randomUUID() },
    proposalId: ticketProposal.proposalId });
  return { ...context, source, ticketProposal, originalMessage, sourceOrigin, requestSha256: digest(originalMessage) };
}

async function verifyTickets(runtime, migration, target, sibling, authority) {
  const repo = createSecureShopTicketRepository({ pool: runtime, checkCurrent: authority.checkCurrent,
    modeAuthority: authority.modeAuthority });
  const customer = await grant(runtime, authority, target, 'customer', 201);
  const currentAdmin = await grant(runtime, authority, target, 'admin', 202, scope(target.birth.platformOwnerId));
  const peer = await grant(runtime, authority, sibling, 'customer', 301);
  const peerAdmin = await grant(runtime, authority, sibling, 'admin', 302, scope(sibling.birth.platformOwnerId));
  assert.notEqual(customer.scope.launchId, currentAdmin.scope.launchId);
  assert.notEqual(customer.retainedScene.scene.grantId, currentAdmin.retainedScene.scene.grantId);
  const input = confirmation(customer), peerInput = confirmation(peer, 'Sibling ticket', 'Sibling synthetic body');
  const [first, replay] = await Promise.all([repo.confirm(input), repo.confirm(input)]);
  assert.deepEqual(replay, first);
  assert.equal(first.operationId, input.ticketProposal.proposalId);
  assert.equal(first.receiptSha256.length, 64);
  assert.equal(Object.keys(first).length, 11);
  assert.deepEqual(await repo.readSavedCustomer({ ...customer, source: input.source }), first);
  let retained = await ticketSnapshot(runtime, target.targetId);
  assert.equal(retained.tickets.length, 1); assert.equal(retained.receipts.length, 1);
  assert.deepEqual(await repo.confirm(input), first);
  assert.deepEqual(await ticketSnapshot(runtime, target.targetId), retained);
  await assert.rejects(repo.confirm({ ...input, requestSha256: 'f'.repeat(64) }), { code: 'TICKET_OPERATION_CONFLICT' });
  await assert.rejects(repo.confirm({ ...input, source: { ...input.source,
    scene: { ...input.source.scene, grantId: currentAdmin.retainedScene.scene.grantId } } }), { code: 'TICKET_SOURCE_INVALID' });
  await assert.rejects(repo.readSavedCustomer({ ...peer, source: input.source }), { code: 'TICKET_SOURCE_INVALID' });
  await assert.rejects(repo.confirm({ ...input, modeToken: structuredClone(input.modeToken.snapshot) }));

  // More than one page executes both SQL parameter layouts and timestamp/ID
  // keyset ordering. Every row is created through the real repository.
  for (let index = 0; index < 21; index++) await repo.confirm(confirmation(customer,
    `Pagination ticket ${index}`, `Owned page row ${index}`));
  retained = await ticketSnapshot(runtime, target.targetId);
  assert.equal(retained.tickets.length, 22); assert.equal(retained.receipts.length, 22);
  const ordered = (await runtime.query(`SELECT ticket_id::text AS "ticketId",
    to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "createdAt"
    FROM secureshop_review.product_target_support_tickets WHERE target_id=$1
    ORDER BY created_at DESC,ticket_id DESC`, [target.targetId])).rows;
  const page = await repo.listForAdmin(currentAdmin, { limit: 20 });
  assert.deepEqual(page.tickets.map(row => row.ticketId), ordered.slice(0,20).map(row => row.ticketId));
  assert.equal(page.nextCursor, Buffer.from(JSON.stringify([ordered[19].createdAt,ordered[19].ticketId])).toString('base64url'));
  assert.deepEqual(JSON.parse(Buffer.from(page.nextCursor,'base64url').toString('utf8')),
    [ordered[19].createdAt,ordered[19].ticketId]);
  const tail = await repo.listForAdmin(currentAdmin, { limit: 20, cursor: page.nextCursor });
  assert.deepEqual(tail.tickets.map(row => row.ticketId), ordered.slice(20).map(row => row.ticketId));
  assert.equal(tail.nextCursor, null);
  const single = await repo.listForAdmin(currentAdmin, { limit: 1 });
  assert.equal(single.tickets.length, 1); assert.equal(single.tickets[0].ticketId, ordered[0].ticketId);
  assert.equal(single.nextCursor, Buffer.from(JSON.stringify([ordered[0].createdAt,ordered[0].ticketId])).toString('base64url'));
  assert.equal((await repo.listForAdmin(currentAdmin, { limit: 1, cursor: single.nextCursor })).tickets[0].ticketId, ordered[1].ticketId);
  await assert.rejects(repo.listForAdmin(currentAdmin, { cursor: `${page.nextCursor}=` }), { code: 'TICKET_CURSOR_INVALID' });
  await assert.rejects(repo.listForAdmin(currentAdmin, { limit: 21 }), { code: 'TICKET_PAGE_INVALID' });
  // The source customer's execution may be retired while the independent
  // current admin grant still authorizes reading the durable original source.
  authority.retire(customer.scope);
  await assert.rejects(repo.readSavedCustomer({ ...customer, source: input.source }), { code: 'SHOP_SCENE_STALE' });
  const detail = await repo.readForAdmin(currentAdmin, { ticketId: first.ticketId });
  assert.equal(detail.body, input.ticketProposal.body); assert.equal(detail.subject, input.ticketProposal.subject);
  assert.equal(detail.receiptSha256, first.receiptSha256);
  assert.deepEqual((await repo.listForAdmin(currentAdmin)).tickets.map(row => row.ticketId), ordered.slice(0,20).map(row => row.ticketId));
  assert.deepEqual(detail.modeCapability, { version: 1, featureId: 'support_tickets',
    policyVersion: 'owned-ticket-render-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'support_tickets' } });
  const fixedAdmin = { ...currentAdmin, modeToken: authority.token(currentAdmin.scope, 'fixed') };
  const fixedDetail = await repo.readForAdmin(fixedAdmin, { ticketId: first.ticketId });
  assert.deepEqual(fixedDetail, { ...detail, modeCapability: { ...detail.modeCapability, effectiveMode: 'fixed' } });
  const assessment = await repo.readForAssessment(fixedAdmin, { ticketId: first.ticketId });
  assert.deepEqual(assessment.source, input.source); assert.deepEqual(assessment.result, first);
  assert.deepEqual(assessment.proposal, input.ticketProposal);
  assert.equal(assessment.sourceModeSnapshot.mode, 'vuln');
  assert.equal(assessment.detail.modeCapability.effectiveMode, 'fixed');
  assert.deepEqual(assessment.consumer.execution, currentAdmin.scope);
  assert.equal(assessment.consumer.scene.grantId, currentAdmin.retainedScene.scene.grantId);
  assert.notEqual(assessment.consumer.scene.grantId, assessment.source.scene.grantId);
  assert.equal(Object.hasOwn(detail, 'source'), false);
  assert.equal(await repo.readForAssessment(peerAdmin, { ticketId: first.ticketId }), null);
  assert.equal(await repo.readForAdmin(peerAdmin, { ticketId: first.ticketId }), null);
  await assert.rejects(repo.listForAdmin(customer), { code: 'TICKET_AUTHORITY_INVALID' });
  const forgedGrant = createSceneBinding({ ...target.birth, targetId: target.targetId }, {
    sceneId: target.sceneId, sceneGeneration: 1, grantId: customer.retainedScene.scene.grantId,
    execution: currentAdmin.scope, withLease: async work => work(),
  });
  await assert.rejects(repo.readForAdmin({ ...currentAdmin, retainedScene: forgedGrant },
    { ticketId: first.ticketId }), { code: 'SHOP_SCENE_STALE' });
  assert.deepEqual(await ticketSnapshot(runtime, target.targetId), retained);
  const peerResult = await repo.confirm(peerInput), siblingBefore = await ticketSnapshot(runtime, sibling.targetId);

  for (const table of ['product_target_support_tickets','product_target_support_ticket_receipts']) {
    await assert.rejects(runtime.query(`DELETE FROM secureshop_review.${table} WHERE target_id=$1`, [target.targetId]), { code: '42501' });
    await assert.rejects(migration.query(`DELETE FROM secureshop_review.${table} WHERE target_id=$1`, [target.targetId]), { code: '55000' });
  }
  // Exercise the actual reset storage boundary and 0049 retirement trigger.
  // Full authenticated LaunchResetCoordinator execution is a separate fixture.
  await runtime.query("UPDATE secureshop_review.product_targets SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=$1", [target.targetId]);
  assert.deepEqual(await ticketSnapshot(runtime, target.targetId), retained);
  const retired = (await runtime.query('SELECT * FROM secureshop_review.product_target_support_ticket_retirements WHERE target_id=$1', [target.targetId])).rows;
  assert.equal(retired.length, 22);
  assert.deepEqual(retired.map(row => String(row.ticket_id)).sort(), retained.tickets.map(row => String(row.ticket_id)).sort());
  for (const work of [() => repo.confirm(input), () => repo.readSavedCustomer({ ...customer, source: input.source }),
    () => repo.listForAdmin(currentAdmin), () => repo.readForAdmin(currentAdmin, { ticketId: first.ticketId }),
    () => repo.readForAssessment(currentAdmin, { ticketId: first.ticketId })]) {
    await assert.rejects(work(), { code: 'SHOP_SCENE_STALE' });
  }
  authority.retire(customer.scope); authority.retire(currentAdmin.scope);
  await assert.rejects(repo.readSavedCustomer({ ...customer, source: input.source }), { code: 'SHOP_SCENE_STALE' });
  assert.deepEqual(await ticketSnapshot(runtime, sibling.targetId), siblingBefore);
  assert.deepEqual(await repo.readSavedCustomer({ ...peer, source: peerInput.source }), peerResult);
  assert.equal((await repo.readForAdmin(peerAdmin, { ticketId: peerResult.ticketId })).body, peerInput.ticketProposal.body);
}

test('ticket storage qualifies fresh and populated0049/0088 with immutable replay, independent admin grants and retirement fences',
  { skip: !enabled, timeout: 240000 }, async t => {
    const urls = admittedUrls(), directories = [];
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: 3, connectionTimeoutMillis: 1500,
        statement_timeout: 8000, lock_timeout: 3000 })]));
    t.after(async () => {
      const results = await Promise.allSettled(Object.values(pools).map(pool => pool.end()));
      await Promise.all(directories.map(directory => fs.rm(directory, { recursive: true, force: true })));
      assert.ok(results.every(result => result.status === 'fulfilled'), 'every owned pool must close');
    });
    const oldReview = await reviewView(48, directories), currentReview = await reviewView(49, directories);
    const oldAgents = createAgentsMigrationView(87), currentAgents = createAgentsMigrationView(88);
    const reviewFiles = await readMigrations(currentReview), agentsFiles = await currentAgents.readMigrations(currentAgents.directory);
    assert.equal(reviewFiles.at(-1).name, REVIEW_NAME); assert.equal(agentsFiles.at(-1).name, AGENTS_NAME);
    await migrate(pools.REVIEW_POPULATED_MIGRATION, oldReview);
    await oldAgents.migrate(pools.AGENTS_POPULATED_MIGRATION, oldAgents.directory);
    const authority = controlledAuthority();
    const targets = {};
    targets.POPULATED = { own: await provision(pools.REVIEW_POPULATED_RUNTIME, authority, 101),
      sibling: await provision(pools.REVIEW_POPULATED_RUNTIME, authority, 102) };
    const beforeReview = await reviewSnapshot(pools.REVIEW_POPULATED_RUNTIME);
    const historyId = `ticket-predecessor-${randomUUID()}`;
    await pools.AGENTS_POPULATED_MIGRATION.query(`INSERT INTO secureshop_agents.agent_sessions
      (id,user_id,role,messages_json) VALUES($1,201,'customer',$2)`,
    [historyId,JSON.stringify([{ role: 'user', content: 'Controlled preserved pre-0088 history' }])]);
    const beforeAgents = (await pools.AGENTS_POPULATED_MIGRATION.query('SELECT * FROM secureshop_agents.agent_sessions ORDER BY id')).rows;
    const oldReviewLedger = await ledger(pools.REVIEW_POPULATED_MIGRATION), oldAgentLedger = await ledger(pools.AGENTS_POPULATED_MIGRATION);
    assert.deepEqual(await migrate(pools.REVIEW_POPULATED_MIGRATION, currentReview), [REVIEW_NAME]);
    assert.deepEqual(await currentAgents.migrate(pools.AGENTS_POPULATED_MIGRATION, currentAgents.directory), [AGENTS_NAME]);
    assert.deepEqual(await reviewSnapshot(pools.REVIEW_POPULATED_RUNTIME), beforeReview);
    assert.deepEqual((await pools.AGENTS_POPULATED_MIGRATION.query('SELECT * FROM secureshop_agents.agent_sessions ORDER BY id')).rows, beforeAgents);
    assert.deepEqual((await ledger(pools.REVIEW_POPULATED_MIGRATION)).slice(0,-1), oldReviewLedger);
    assert.deepEqual((await ledger(pools.AGENTS_POPULATED_MIGRATION)).slice(0,-1), oldAgentLedger);
    assert.deepEqual(await migrate(pools.REVIEW_FRESH_MIGRATION, currentReview), reviewFiles.map(row => row.name));
    assert.deepEqual(await currentAgents.migrate(pools.AGENTS_FRESH_MIGRATION, currentAgents.directory), agentsFiles.map(row => row.name));
    targets.FRESH = { own: await provision(pools.REVIEW_FRESH_RUNTIME, authority, 103),
      sibling: await provision(pools.REVIEW_FRESH_RUNTIME, authority, 104) };
    for (const variant of ['FRESH','POPULATED']) {
      const review = pools[`REVIEW_${variant}_RUNTIME`], migration = pools[`REVIEW_${variant}_MIGRATION`];
      assert.equal((await review.query('SELECT current_user AS role')).rows[0].role, 'dvaia_secureshop_review_runtime');
      await assertBoundToolPolicyReadiness(pools[`AGENTS_${variant}_RUNTIME`]);
      await verifyTickets(review, migration, targets[variant].own, targets[variant].sibling, authority);
      const retained = await ticketSnapshot(review, targets[variant].own.targetId);
      assert.deepEqual(await migrate(migration, currentReview), []);
      assert.deepEqual(await currentAgents.migrate(pools[`AGENTS_${variant}_MIGRATION`], currentAgents.directory), []);
      assert.deepEqual(await ticketSnapshot(review, targets[variant].own.targetId), retained);
      assert.deepEqual(await ledger(migration), reviewFiles.map(({ name,checksum }) => ({ name,checksum })));
      assert.deepEqual(await ledger(pools[`AGENTS_${variant}_MIGRATION`]), agentsFiles.map(({ name,checksum }) => ({ name,checksum })));
    }
  });
