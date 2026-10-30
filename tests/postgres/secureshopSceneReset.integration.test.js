'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const express = require('express');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createSecureShopTicketRepository } = require('../../server/database/postgres/secureshopTicketRepository');
const Ticket = require('../../server/services/secureshopTicketContract');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopSceneRepository } = require('../../server/database/postgres/secureshopSceneRepository');
const { createSecureShopScenes } = require('../../server/services/secureshopScenes');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundReviewRepository } = require('../../server/database/postgres/secureshopBoundReviewRepository');
const { createSecureShopBoundProductRetrievalRepository } = require('../../server/database/postgres/secureshopBoundProductRetrievalRepository');
const { createSecureShopSceneResetPreflight } = require('../../server/services/secureshopSceneResetPreflight');
const { createSecureShopCleanupComposition } = require('../../server/services/secureshopCleanupComposition');
const { createSecureShopStandaloneReset } = require('../../server/services/secureshopStandaloneReset');
const { createSecureShopStandaloneAuthRouter } = require('../../server/routes/secureshopStandaloneAuth');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_SCENE_RESET_';
const STORES = { IDENTITY: 'identity', AGENTS: 'secureshop_agents', REVIEW: 'secureshop_review' };
const SCOPE = 'Controlled disposable three-store aggregate scene reset and receipt recovery; no model or browser qualification';
const FLAGS = ['freshMigration', 'populatedMigrationPreserved', 'secondRunNoop',
  'crossBirthCurrentGrant', 'multipleTargetsCommitted', 'privateReceiptsHistory',
  'replayStable', 'siblingPreserved', 'interruptedMirrorRecovered',
  'ambiguousMappingDenied', 'directCommitDenied', 'protectedHttpResetRecovery'];
const enabled = process.env.SECURESHOP_SCENE_RESET_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['RUNTIME', 'MIGRATION'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const directory = store => path.join(ROOT, 'db/postgres', store === 'IDENTITY'
  ? 'identity-migrations' : `workshop-migrations/${STORES[store]}`);

function url(store, role) {
  const value = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
  assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  assert.equal(value.username, `dvaia_${STORES[store]}_${role.toLowerCase()}`);
  for (const key of ['password', 'search', 'hash']) assert.equal(value[key], '');
  return value.href;
}
// Discover a historical prefix in memory while reading original SQL bytes.
function historical(directoryPath, ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename), loaded = new Module(filename, module);
  loaded.filename = filename;
  const original = require('node:fs/promises');
  loaded.require = name => name === 'node:fs/promises' ? {
    ...original, async readdir(selected, ...args) {
      const names = await original.readdir(selected, ...args);
      return path.resolve(selected) === directoryPath
        ? names.filter(name => !/^\d{4}_.*\.sql$/.test(name) || Number(name.slice(0, 4)) <= ceiling) : names;
    },
  } : local(name);
  loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

test('aggregate scene reset commits distinct birth targets and resumes exact interrupted review claims',
  { skip: !enabled, timeout: 220000 }, async t => {
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    assert.equal(process.cwd(), ROOT);
    const evidence = process.env.SECURESHOP_SCENE_RESET_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidence));
    assert.ok(!path.resolve(evidence).startsWith(`${ROOT}${path.sep}`));
    const pools = Object.fromEntries(Object.keys(STORES).flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
      const connectionString = url(store, role);
      return [`${store}_${role}`, new Pool({ connectionString, max: role === 'RUNTIME' ? 8 : 2,
        statement_timeout: 20000, lock_timeout: 5000 })];
    })));
    const leasePool = new Pool({ connectionString: url('IDENTITY', 'RUNTIME'), max: 4 });
    const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
    let composition, httpServer, phase = 'admission', failure;
    try {
      for (const store of Object.keys(STORES)) {
        const a = new URL(url(store, 'RUNTIME')), b = new URL(url(store, 'MIGRATION'));
        assert.equal(a.pathname, b.pathname); assert.equal(a.port, b.port);
      }
      assert.equal(new Set(Object.keys(STORES).map(store => new URL(url(store, 'RUNTIME')).pathname)).size, 3);
      assert.equal(new Set(Object.keys(STORES).map(store => new URL(url(store, 'RUNTIME')).port)).size, 1);
      const identity = pools.IDENTITY_RUNTIME, review = pools.REVIEW_RUNTIME;
      const identityMigration = pools.IDENTITY_MIGRATION, reviewMigration = pools.REVIEW_MIGRATION;
      phase = 'historical-prefix';
      await historical(directory('IDENTITY'), 146)(identityMigration, directory('IDENTITY'));
      await historical(directory('REVIEW'), 35)(reviewMigration, directory('REVIEW'));
      await migrate(pools.AGENTS_MIGRATION, directory('AGENTS'));
      for (const [pool, filename, probe] of [
        [identityMigration, path.join(directory('IDENTITY'), '0147_secureshop_scene_target_cleanup.sql'),
          'identity.secureshop_scene_target_retirements'],
        [reviewMigration, path.join(directory('REVIEW'), '0036_multi_target_cleanup_receipts.sql'),
          'secureshop_review.product_cleanup_receipts'],
      ]) {
        const client = await pool.connect();
        try {
          await client.query('BEGIN'); await client.query(await fs.readFile(filename, 'utf8'));
          assert.ok((await client.query('SELECT to_regclass($1) AS relation', [probe])).rows[0].relation);
          await client.query('ROLLBACK');
        } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
        finally { client.release(); }
      }
      status.freshMigration = true;
      // Current authentication writes the 0148 session lineage column and reads
      // current practice selection state, so finish identity DDL before login.
      assert.deepEqual(await historical(directory('IDENTITY'), 147)(identityMigration, directory('IDENTITY')),
        ['0147_secureshop_scene_target_cleanup.sql']);
      await migrate(identityMigration, directory('IDENTITY'));

      const standalone = slug => createSecureShopStandaloneAuthService({
        repository: createSecureShopStandaloneAuthRepository({ pool: identity,
          ...(slug ? { executionTenantSlug: slug } : {}) }),
        hashPassword: value => require('bcryptjs').hash(value, 4),
      });
      const auth = standalone(), suffix = randomUUID().slice(0, 8), password = 'disposable aggregate scene reset';
      async function account(label, isolated = false) {
        const username = `${label}_${suffix}`;
        const registered = await auth.register({ username, email: `${username}@example.invalid`, password, role: 'customer' });
        let service = auth;
        if (isolated) {
          const tenantId = randomUUID(), slug = `${label}_${suffix}`;
          await identityMigration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)', [tenantId, slug]);
          await identityMigration.query(`INSERT INTO secureshop_auth.tenant_memberships
            (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
          [tenantId, registered.context.principalId, registered.context.shopUserId]);
          service = standalone(slug);
        }
        // Membership changes invalidate the earlier registration authority.
        const login = await service.login({ username, password });
        return { username, service, context: await service.establishTenantContext(login.context) };
      }
      const launches = createSecureShopLaunchRepository(identity);
      const scenes = createSecureShopScenes({ repository: createSecureShopSceneRepository({ pool: identity, launches }), reviewPool: review, launches });
      const checkCurrent = value => launches.assertCurrent(value);
      const checkCleanup = async () => { throw Object.assign(new Error('Canonical reset authority required'), { code: 'RESET_CLEANUP_AUTHORITY_REQUIRED' }); };
      const products = createSecureShopBoundProductRepository(review, { checkCurrent, checkCleanup });
      const reviews = createSecureShopBoundReviewRepository(review, { checkCurrent, checkCleanup,
        checkRetirement: async () => { throw Error('Only canonical reset may retire reviews'); },
      });
      const retrieval = createSecureShopBoundProductRetrievalRepository(review, { checkCurrent, checkCleanup });
      const product = { id: 7, sourceRetailerId: 1, retailerId: 12, name: 'Aggregate synthetic product',
        description: 'Immutable owned source', descriptionHtml: '<p>Immutable owned source</p>', price: 12.5,
        category: 'fixture', imageUrl: null, images: [], stockQuantity: 20, status: 'active',
        templateSource: '{{source}}', createdAt: null, updatedAt: null };
      async function launch(context) {
        return (await launches.issueOrRenew({ platformOwnerId: context.ownerId, platformSessionId: context.sessionId,
          expiresAt: new Date(Date.now() + 30 * 60000).toISOString(), shopPrincipal: context })).binding;
      }
      async function provision(scope) {
        const reservation = await launches.reserveProductsTarget({ ...scope, expectedGeneration: scope.generation });
        const birth = { ...scope, targetId: reservation.targetId };
        await products.provision(birth, { ownMerchantId: 12, products: [product] });
        const reviewReservation = await launches.reserveReviewsTarget({ ...scope, expectedGeneration: scope.generation });
        const reviewBirth = { ...scope, targetId: reviewReservation.targetId };
        await reviews.provision(reviewBirth, { reviews: [{ productId: 7, authorId: 11, body: 'Immutable aggregate review', rating: 4 }] });
        await retrieval.provision(birth, { embeddingModel: 'controlled-native', embeddingDimension: 384,
          documents: [{ sourceKind: 'product', sourceId: 7, chunkIndex: 0, text: 'Owned retrieval source', embedding: [1, ...Array(383).fill(0)] }] });
        const candidates = await scenes.list(scope);
        const rows = (await identity.query('SELECT scene_id FROM identity.secureshop_scenes WHERE product_target_id=$1', [birth.targetId])).rows;
        assert.equal(rows.length, 1); assert.ok(candidates.some(value => value.id === rows[0].scene_id));
        await scenes.select(scope, rows[0].scene_id);
        const branded = await scenes.resolve(scope);
        assert.equal(branded.targetId, birth.targetId);
        const boundReview = await reviews.readSceneTarget(branded);
        assert.equal(boundReview.targetId, reviewBirth.targetId);
        return { birth, reviewBirth, sceneId: rows[0].scene_id };
      }
      phase = 'populated-scenes';
      const owner = await account('aggregate');
      const firstScope = await launch(owner.context), first = await provision(firstScope);
      const secondLogin = await auth.login({ username: owner.username, password });
      const secondContext = await auth.establishTenantContext(secondLogin.context);
      const second = await provision(await launch(secondContext));
      assert.equal(first.birth.platformOwnerId, second.birth.platformOwnerId);
      const siblingOwner = await account('aggregate_sibling', true);
      const siblingScope = await launch(siblingOwner.context), sibling = await provision(siblingScope);
      assert.notEqual(siblingScope.platformOwnerId, firstScope.platformOwnerId);
      const ambiguousOwner = await account('aggregate_ambiguous', true);
      const ambiguousScope = await launch(ambiguousOwner.context), ambiguous = await provision(ambiguousScope);
      // Faithful imported pre-0147 debt: the scene was retired without a
      // claimant. Current reset triggers cannot produce this historical shape.
      // Seed only this isolated scene through migration authority; retain every
      // guard and immutable receipt, and never alter ticket target lifecycle.
      assert.equal((await identityMigration.query(`UPDATE identity.secureshop_scenes
        SET status='retired',is_default=false WHERE scene_id=$1
          AND original_platform_owner_id=$2 AND status='active'`,
      [ambiguous.sceneId, ambiguousScope.platformOwnerId])).rowCount, 1);
      const legacyScene = async () => {
        const scene = (await identity.query(`SELECT s.status,c.target_id AS claim
          FROM identity.secureshop_scenes s
          LEFT JOIN identity.secureshop_scene_target_retirements c ON c.scene_id=s.scene_id
          WHERE s.scene_id=$1 AND s.original_platform_owner_id=$2`,
        [ambiguous.sceneId, ambiguousScope.platformOwnerId])).rows;
        const mapping = (await review.query(`SELECT m.review_target_id AS target,r.lifecycle
          FROM secureshop_review.scene_review_targets m
          JOIN secureshop_review.review_targets r ON r.target_id=m.review_target_id
          WHERE m.scene_id=$1 AND m.product_target_id=$2 AND m.original_platform_owner_id=$3`,
        [ambiguous.sceneId, ambiguous.birth.targetId, ambiguousScope.platformOwnerId])).rows;
        assertUnclaimedLegacyScene(scene, mapping, ambiguous.reviewBirth.targetId);
      };
      await legacyScene();
      const ambiguousReset = await launches.beginReset({ ...ambiguousScope,
        expectedGeneration: ambiguousScope.generation, idempotencyKey: randomUUID() });
      const latestLogin = await auth.login({ username: owner.username, password });
      const currentScope = await launch(await auth.establishTenantContext(latestLogin.context));
      for (const item of [first, second]) {
        await scenes.select(currentScope, item.sceneId);
        const current = await scenes.resolve(currentScope);
        assert.equal(current.targetId, item.birth.targetId);
        assert.equal(current.scene.execution.launchId, currentScope.launchId);
        assert.notEqual(current.launchId, currentScope.launchId);
        assert.equal((await reviews.readSceneTarget(current)).targetId, item.reviewBirth.targetId);
      }
      status.crossBirthCurrentGrant = true;
      async function retained() {
        const result = {};
        for (const table of ['identity.secureshop_scenes', 'identity.secureshop_scene_execution_grants',
          'identity.secureshop_target_reservations']) result[table] = (await identity.query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text`)).rows;
        for (const table of ['secureshop_review.product_targets', 'secureshop_review.product_target_products',
          'secureshop_review.review_targets', 'secureshop_review.reviews', 'secureshop_review.scene_review_targets'])
          result[table] = (await reviewMigration.query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text`)).rows;
        return result;
      }
      const populatedBefore = await retained();
      phase = 'forward-migrations';
      assert.deepEqual(await migrate(identityMigration, directory('IDENTITY')), []);
      assert.deepEqual(await historical(directory('REVIEW'), 36)(reviewMigration, directory('REVIEW')), ['0036_multi_target_cleanup_receipts.sql']);
      assert.deepEqual(await retained(), populatedBefore); status.populatedMigrationPreserved = true;
      // Preserve the historical transition above, then explicitly admit the
      // current canonical heads before exercising new ticket storage.
      for (const store of Object.keys(STORES)) {
        const migrationPool = pools[`${store}_MIGRATION`];
        await migrate(migrationPool, directory(store));
        assert.deepEqual((await migrationPool.query(
          'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
        (await readMigrations(directory(store))).map(({ name, checksum }) => ({ name, checksum })));
        assert.deepEqual(await migrate(migrationPool, directory(store)), []);
      }
      assert.deepEqual(await retained(), populatedBefore); status.secondRunNoop = true;
      composition = createSecureShopCleanupComposition({ identityPool: identity, agentsPool: pools.AGENTS_RUNTIME,
        reviewPool: review, leasePool, launches });
      const tickets = createSecureShopTicketRepository({ pool: review, checkCurrent,
        modeAuthority: composition.modeAuthority });
      async function ticket(scope, sceneId, shopUserId) {
        scope = createLaunchScope(scope);
        await scenes.select(scope, sceneId);
        const retainedScene = await scenes.resolve(scope);
        const modeToken = await composition.modeAuthority.capture(scope, 'support_tickets');
        // Proposal/persona-session coordinates are controlled storage inputs;
        // launch, selected-scene lease, mode and reset authority are real.
        const context = { scope, retainedScene, persona: { id: shopUserId, role: 'customer' },
          personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, modeToken,
          withEffect: async work => { await checkCurrent(scope); const value = await work();
            await checkCurrent(scope); return value; } };
        const subject = 'Retained reset ticket', body = 'Owned synthetic reset body';
        const originalMessage = JSON.stringify({ subject, body });
        const sourceOrigin = { turnSessionId: randomUUID(), turnRequestId: randomUUID(),
          toolKey: Ticket.TOOL, invocationStep: 1, callId: 'controlled-reset-storage' };
        const ticketProposal = Ticket.prepare({ subject, body, message: originalMessage, sourceOrigin });
        const source = Ticket.source({ execution: scope,
          customer: { shopUserId, authorityVersion: context.personaSession.authorityVersion,
            personaSessionId: context.personaSession.sessionId },
          scene: { sceneId, sceneGeneration: retainedScene.scene.sceneGeneration,
            targetId: retainedScene.targetId, grantId: retainedScene.scene.grantId,
            birth: Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
              .map(key => [key, retainedScene[key]])) },
          turn: { sessionId: sourceOrigin.turnSessionId, requestId: sourceOrigin.turnRequestId, runId: randomUUID() },
          proposalId: ticketProposal.proposalId });
        const input = { ...context, source, ticketProposal, originalMessage, sourceOrigin,
          requestSha256: createHash('sha256').update(originalMessage).digest('hex') };
        const result = await tickets.confirm(input);
        assert.deepEqual(await tickets.confirm(input), result);
        return { input, result };
      }
      const ownedTickets = [];
      for (const item of [first, second]) ownedTickets.push(await ticket(currentScope, item.sceneId, owner.context.shopUserId));
      const peerTicket = await ticket(siblingScope, sibling.sceneId, siblingOwner.context.shopUserId);
      await review.query(`INSERT INTO secureshop_review.product_target_profile_overlays
        (target_id,shop_user_id,email,full_name) VALUES($1,$2,$3,$4)`,
      [sibling.birth.targetId, siblingOwner.context.shopUserId, 'sibling@example.invalid', 'Retained sibling profile']);
      async function ticketState() {
        const result = {};
        for (const [key, table] of Object.entries({ tickets: 'product_target_support_tickets',
          receipts: 'product_target_support_ticket_receipts', retirements: 'product_target_support_ticket_retirements',
          profiles: 'product_target_profile_overlays' })) {
          result[key] = (await review.query(`SELECT to_jsonb(t) AS row FROM secureshop_review.${table} t
            ORDER BY to_jsonb(t)::text`)).rows.map(value => value.row);
        }
        return result;
      }
      const ticketBefore = await ticketState();
      assert.equal(ticketBefore.tickets.length, 3); assert.equal(ticketBefore.receipts.length, 3);
      assert.deepEqual(ticketBefore.retirements, []); assert.equal(ticketBefore.profiles.length, 1);
      const resetKey = randomUUID();
      let started;
      phase = 'multi-target-reset';
      const reset = await composition.launchResetCoordinator.reset({ ...currentScope,
        expectedGeneration: currentScope.generation, idempotencyKey: resetKey }, {
        async withAdmission(begin) {
          started = await begin();
          await assert.rejects(launches.commitReset({ ...currentScope, resetId: started.resetId,
            expectedGeneration: started.toGeneration }), { code: 'CLEANUP_REQUIRED' });
          status.directCommitDenied = true;
          return started;
        },
      });
      assert.equal(reset.status, 'committed'); assert.equal(reset.targets, 4);
      assert.equal(reset.binding.generation, currentScope.generation + 1);
      const flags = (await identity.query(`SELECT reconciliation_required,conversation_reconciliation_required,
        progress_reconciliation_required FROM identity.secureshop_launch_resets WHERE reset_id=$1`, [reset.resetId])).rows[0];
      assert.deepEqual(flags, { reconciliation_required: false, conversation_reconciliation_required: false, progress_reconciliation_required: false });
      status.multipleTargetsCommitted = true;
      async function histories(resetId) {
        return (await identity.query(`SELECT * FROM identity.secureshop_target_cleanup_history
          WHERE operation_id=$1 ORDER BY target_kind,target_id`, [resetId])).rows;
      }
      const history = await histories(reset.resetId); assert.equal(history.length, 4);
      const receipts = [];
      for (const item of [first, second]) for (const [kind, birth, repository] of [
        ['products', item.birth, composition.products], ['reviews', item.reviewBirth, composition.reviews],
      ]) {
        const receipt = await repository.readCleanupReceipt(birth, { operationId: reset.resetId });
        const row = history.find(value => value.target_id === birth.targetId && value.target_kind === kind);
        assert.ok(row); assert.equal(row.launch_id, birth.launchId);
        assert.equal(row.original_platform_session_id, birth.platformSessionId);
        assert.equal(row.target_receipt_sha256.toString('hex'), receipt.receiptSha256);
        assert.notEqual(row.launch_id, currentScope.launchId);
        await assert.rejects(repository.readCleanupReceipt({ ...birth, platformOwnerId: siblingScope.platformOwnerId },
          { operationId: reset.resetId }));
        receipts.push(receipt);
      }
      assert.equal(new Set(receipts.map(value => value.receiptSha256)).size, 4);
      status.privateReceiptsHistory = true;
      async function privateReceipts(operationId) {
        const result = {};
        for (const table of ['review_cleanup_receipts', 'product_cleanup_receipts',
          'product_account_cleanup_receipts', 'product_listing_cleanup_receipts',
          'product_target_refund_cleanup_receipts', 'product_target_retrieval_cleanup_receipts']) {
          result[table] = (await reviewMigration.query(`SELECT to_jsonb(t) AS row
            FROM secureshop_review.${table} t WHERE operation_id=$1 ORDER BY target_id`, [operationId])).rows;
          assert.equal(result[table].length, 2, table);
          assert.equal(new Set(result[table].map(value => value.row.target_id)).size, 2, table);
        }
        return result;
      }
      const ticketAfter = await ticketState();
      assertTicketRetirement(ticketBefore, ticketAfter, [first.birth.targetId, second.birth.targetId]);
      for (const value of ownedTickets) {
        await assert.rejects(tickets.readSavedCustomer(value.input), { code: 'STALE_LAUNCH' });
        await assert.rejects(tickets.confirm(value.input), { code: 'STALE_LAUNCH' });
      }
      assert.deepEqual(await tickets.readSavedCustomer(peerTicket.input), peerTicket.result);
      const receiptsBeforeReplay = await privateReceipts(reset.resetId);
      const replay = await composition.launchResetCoordinator.reset({ ...currentScope,
        expectedGeneration: currentScope.generation, idempotencyKey: resetKey });
      assert.deepEqual(replay, reset); assert.deepEqual(await histories(reset.resetId), history);
      assert.deepEqual(await privateReceipts(reset.resetId), receiptsBeforeReplay);
      assert.deepEqual(await ticketState(), ticketAfter, 'reset replay and denied confirmations add no ticket effect');
      status.replayStable = true;
      const siblingAfter = await retained();
      for (const [table, before] of Object.entries(populatedBefore)) {
        const pick = rows => rows.filter(value => value.row.original_platform_owner_id === siblingScope.platformOwnerId
          || value.row.target_id === sibling.birth.targetId || value.row.target_id === sibling.reviewBirth.targetId);
        assert.deepEqual(pick(siblingAfter[table]), pick(before));
      }
      await launches.assertCurrent(siblingScope); status.siblingPreserved = true;
      phase = 'interrupted-review-mirror';
      const fresh = await provision(reset.binding);
      const interrupted = await launches.beginReset({ ...reset.binding, expectedGeneration: reset.binding.generation,
        idempotencyKey: randomUUID() });
      let interruptedOnce = false;
      const interruptedPool = { connect: () => identity.connect(), async query(sql, args) {
        if (!interruptedOnce && sql.includes('identity.ensure_secureshop_scene_review_retirement')) {
          interruptedOnce = true; throw Object.assign(new Error('Controlled interruption after mirror commit'), { code: 'CLEANUP_REQUIRED' });
        }
        return identity.query(sql, args);
      } };
      const interruptedPreflight = createSecureShopSceneResetPreflight({ identityPool: interruptedPool, reviewPool: review });
      await assert.rejects(interruptedPreflight.withOwnerLease(currentScope.platformOwnerId,
        lease => lease.reconcileRetired(interrupted.resetId)), { code: 'CLEANUP_REQUIRED' });
      assert.equal(interruptedOnce, true);
      assert.equal((await identity.query('SELECT count(*)::int n FROM identity.secureshop_scene_review_targets WHERE scene_id=$1', [fresh.sceneId])).rows[0].n, 1);
      assert.equal((await identity.query("SELECT count(*)::int n FROM identity.secureshop_scene_target_retirements WHERE scene_id=$1 AND target_kind='reviews'", [fresh.sceneId])).rows[0].n, 0);
      const recovered = await composition.launchResetCoordinator.resumeExisting(interrupted.resetId, reset.binding);
      assert.equal(recovered.status, 'committed'); assert.equal(recovered.targets, 2);
      assert.equal((await identity.query("SELECT count(*)::int n FROM identity.secureshop_scene_target_retirements WHERE scene_id=$1 AND target_kind='reviews'", [fresh.sceneId])).rows[0].n, 1);
      assert.equal((await histories(interrupted.resetId)).length, 2); status.interruptedMirrorRecovered = true;
      phase = 'ambiguous-legacy-denial';
      await legacyScene();
      const ambiguousBefore = await retained();
      await assert.rejects(composition.launchResetCoordinator.recover(ambiguousReset.resetId), { code: 'CLEANUP_REQUIRED' });
      assert.deepEqual(await retained(), ambiguousBefore);
      assert.deepEqual(await histories(ambiguousReset.resetId), []);
      assert.equal((await identity.query('SELECT status FROM identity.secureshop_launch_resets WHERE reset_id=$1', [ambiguousReset.resetId])).rows[0].status, 'fenced');
      assert.equal((await identity.query('SELECT count(*)::int n FROM identity.secureshop_scene_target_retirements WHERE scene_id=$1', [ambiguous.sceneId])).rows[0].n, 0);
      status.ambiguousMappingDenied = true;
      phase = 'protected-http-reset-recovery';
      const adminPrincipalId = randomUUID(), adminUsername = `reset_admin_${suffix}`;
      const defaultTenant = (await identityMigration.query(`SELECT tenant_id FROM secureshop_auth.tenants
        WHERE slug='default'`)).rows[0];
      assert.ok(defaultTenant?.tenant_id);
      const adminRow = (await identityMigration.query(`INSERT INTO secureshop_auth.principals
        (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
        RETURNING shop_user_id`, [adminPrincipalId,adminUsername,`${adminUsername}@example.invalid`,
        await require('bcryptjs').hash(password, 4)])).rows[0];
      await identityMigration.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
      [defaultTenant.tenant_id,adminPrincipalId,adminRow.shop_user_id]);
      const protectedReset = createSecureShopStandaloneReset({ identityPool: identity,
        authService: auth, launches, scenes, resetCoordinator: composition.launchResetCoordinator,
        preflight: composition.sceneResetPreflight });
      const app = express(); app.use(express.json());
      app.use('/api/secureshop/auth', createSecureShopStandaloneAuthRouter({ service: auth,
        bootstrap: async () => { throw new Error('Bootstrap is outside this reset fixture'); },
        reset: protectedReset, allowedOrigins: ['http://localhost:3000'] }));
      httpServer = await new Promise(resolve => {
        const server = app.listen(0, '127.0.0.1', () => resolve(server));
      });
      const base = `http://127.0.0.1:${httpServer.address().port}/api/secureshop/auth`;
      const post = (route, body, cookie) => fetch(base + route, { method: 'POST',
        headers: { Origin: 'http://localhost:3000', 'Content-Type': 'application/json',
          ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(body) });
      const get = (route, cookie) => fetch(base + route,
        { headers: cookie ? { Cookie: cookie } : {} });
      const loginAdmin = async () => {
        const response = await post('/login', { username: adminUsername, password });
        assert.equal(response.status, 200);
        assert.equal((await response.json()).user.role, 'admin');
        const cookie = response.headers.get('set-cookie')?.split(';')[0];
        assert.match(cookie, /^owasp_ai_goat_shop_session=[A-Za-z0-9_-]{43}$/);
        const basePrincipal = await auth.authenticate(cookie.slice('owasp_ai_goat_shop_session='.length));
        assert.equal(basePrincipal.principalId, adminPrincipalId);
        return { cookie, context: await auth.establishTenantContext(basePrincipal) };
      };
      const firstAdmin = await loginAdmin();
      const adminScope = await launch(firstAdmin.context);
      const adminScene = await provision(adminScope);
      // Controlled ticket storage input on the exact selected target that the
      // real authenticated administrator will reset through the HTTP route.
      const httpTicket = await ticket(adminScope, adminScene.sceneId, owner.context.shopUserId);
      assert.equal(httpTicket.input.retainedScene.targetId, adminScene.birth.targetId);
      assert.equal(httpTicket.input.scope.launchId, adminScope.launchId);
      assert.deepEqual(await tickets.readSavedCustomer(httpTicket.input), httpTicket.result);
      assert.equal((await get('/reset-readiness', firstAdmin.cookie)).status, 200);
      const ready = await (await get('/reset-readiness', firstAdmin.cookie)).json();
      assert.deepEqual({ launchId: ready.launchId, generation: ready.generation, sceneId: ready.scene.id },
        { launchId: adminScope.launchId, generation: adminScope.generation, sceneId: adminScene.sceneId });
      const customerCookie = `owasp_ai_goat_shop_session=${secondLogin.token}`;
      assert.equal((await get('/reset-readiness', customerCookie)).status, 403);
      const protectedKey = randomUUID();
      const resetInput = { launchId: ready.launchId, expectedGeneration: ready.generation,
        idempotencyKey: protectedKey, sceneId: ready.scene.id,
        confirmation: 'RESET_SHARED_PRACTICE' };
      assert.equal((await post('/reset', { ...resetInput, confirmation: 'RESET' }, firstAdmin.cookie)).status, 400);
      const httpTicketBefore = await ticketState();
      assert.equal(httpTicketBefore.tickets.filter(row => row.target_id === adminScene.birth.targetId).length, 1);
      const firstHttp = await post('/reset', resetInput, firstAdmin.cookie);
      assert.equal(firstHttp.status, 200);
      const firstReceipt = await firstHttp.json();
      assert.equal(firstReceipt.status, 'committed'); assert.equal(firstReceipt.cleanupComplete, true);
      assert.equal((await histories(firstReceipt.resetId)).length, 2);
      const httpTicketAfter = await ticketState();
      assertTicketRetirement(httpTicketBefore, httpTicketAfter, [adminScene.birth.targetId]);
      await assert.rejects(tickets.readSavedCustomer(httpTicket.input), { code: 'STALE_LAUNCH' });
      await assert.rejects(tickets.confirm(httpTicket.input), { code: 'STALE_LAUNCH' });
      assert.deepEqual(await tickets.readSavedCustomer(peerTicket.input), peerTicket.result);
      await launches.assertCurrent(siblingScope);
      const replayHttp = await post('/reset', resetInput, firstAdmin.cookie);
      assert.equal(replayHttp.status, 200);
      assert.deepEqual(await replayHttp.json(), firstReceipt);
      assert.deepEqual(await ticketState(), httpTicketAfter,
        'authenticated reset replay and denied confirmation preserve tickets, receipts, retirements and sibling profile');
      assert.deepEqual(await tickets.readSavedCustomer(peerTicket.input), peerTicket.result);
      assert.equal((await histories(firstReceipt.resetId)).length, 2);
      const afterHttp = await launches.readActiveMetadata({ platformOwnerId: firstAdmin.context.ownerId,
        platformSessionId: firstAdmin.context.sessionId });
      assert.equal(afterHttp.generation, adminScope.generation + 1);
      const laterScene = await provision(afterHttp);
      const interruptedAdmin = await launches.beginReset({ ...afterHttp,
        expectedGeneration: afterHttp.generation, idempotencyKey: randomUUID() });
      assert.equal((await identity.query(`SELECT count(*)::int n FROM identity.secureshop_scene_target_retirements
        WHERE scene_id=$1 AND target_kind='products'`, [laterScene.sceneId])).rows[0].n, 1);
      assert.equal((await post('/logout', {}, firstAdmin.cookie)).status, 200);
      assert.equal((await get('/reset-readiness', firstAdmin.cookie)).status, 401);
      const secondAdmin = await loginAdmin();
      const recoveryRead = await get('/reset-recovery', secondAdmin.cookie);
      assert.equal(recoveryRead.status, 200);
      const pending = (await recoveryRead.json()).pending;
      assert.equal(pending.resetId, interruptedAdmin.resetId);
      assert.equal(pending.scene.id, laterScene.sceneId);
      assert.equal(pending.sameExecution, false);
      assert.equal(pending.cleanupComplete, false);
      assert.equal((await post('/reset-recovery', { resetId: randomUUID() }, secondAdmin.cookie)).status, 404);
      const recoveryPost = await post('/reset-recovery', { resetId: pending.resetId }, secondAdmin.cookie);
      assert.equal(recoveryPost.status, 200);
      const recoveredHttp = await recoveryPost.json();
      assert.equal(recoveredHttp.resetId, interruptedAdmin.resetId);
      assert.equal(recoveredHttp.cleanupComplete, true);
      assert.equal(recoveredHttp.activated, false);
      assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launches
        WHERE launch_id=$1`, [afterHttp.launchId])).rows[0].status !== 'active', true);
      assert.notEqual((await launch(secondAdmin.context)).launchId, afterHttp.launchId);
      status.protectedHttpResetRecovery = true;
      assert.ok(FLAGS.every(flag => status[flag] === true));
    } catch (error) { failure = error; t.diagnostic(JSON.stringify({ phase, code: error.code || null })); }
    const cleanup = await Promise.allSettled([httpServer && new Promise(resolve => httpServer.close(resolve)),
      composition?.closeFeatureTransports(), leasePool.end(), ...Object.values(pools).map(pool => pool.end())]);
    const cleanupComplete = cleanup.every(result => result.status === 'fulfilled');
    await fs.writeFile(evidence, JSON.stringify({ scope: SCOPE, passed: !failure && cleanupComplete,
      ...status, cleanupComplete }, null, 2), { flag: 'wx', mode: 0o600 });
    assert.equal(cleanupComplete, true);
    if (failure) throw failure;
  });

// Used by the native flow and controlled mutation regressions. Original ticket
// and confirmation rows are immutable; only exact owner retirement rows appear.
function assertTicketRetirement(before, after, targetIds) {
  assert.deepEqual(after.tickets, before.tickets);
  assert.deepEqual(after.receipts, before.receipts);
  assert.deepEqual(after.profiles, before.profiles);
  const priorIds = new Set(before.retirements.map(row => row.ticket_id));
  assert.equal(priorIds.size, before.retirements.length);
  assert.deepEqual(after.retirements.filter(row => priorIds.has(row.ticket_id)), before.retirements);
  const newRetirements = after.retirements.filter(row => !priorIds.has(row.ticket_id));
  const expected = before.tickets.filter(row => targetIds.includes(row.target_id));
  assert.equal(expected.length, targetIds.length);
  assert.equal(newRetirements.length, expected.length);
  for (const ticket of expected) {
    assert.equal(priorIds.has(ticket.ticket_id), false);
    const rows = newRetirements.filter(row => row.ticket_id === ticket.ticket_id);
    assert.equal(rows.length, 1);
    for (const key of ['target_id','birth_launch_id','birth_scenario_id','birth_generation',
      'birth_platform_owner_id','birth_platform_session_id']) assert.deepEqual(rows[0][key], ticket[key]);
    assert.ok(Number.isFinite(Date.parse(rows[0].retired_at)));
  }
}
function assertUnclaimedLegacyScene(scene, mapping, reviewTargetId) {
  assert.deepEqual(scene, [{ status: 'retired', claim: null }]);
  assert.deepEqual(mapping, [{ target: reviewTargetId, lifecycle: 'active' }]);
}
module.exports = { assertTicketRetirement, assertUnclaimedLegacyScene };
