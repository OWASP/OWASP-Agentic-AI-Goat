'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');
const { createSecureShopConversationLifecycleRepository, buildReceipt,
  digestSessionIds } = require('../../server/database/postgres/secureshopConversationLifecycleRepository');
const { initializeIdentityRepository,
  createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { createSecureShopConversationCleanupCheckpointRepository } = require('../../server/database/postgres/secureshopConversationCleanupCheckpointRepository');
const { createSecureShopConversationLifecycle } = require('../../server/services/secureshopConversationLifecycle');
const { createBoundTurns } = require('../../server/services/secureshopBoundTurns');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');

const PREFIX = 'PG_SECURESHOP_LIFECYCLE_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}_MIGRATION_URL`] && process.env[`${PREFIX}_RUNTIME_URL`];
const compositionEnabled = enabled && process.env[`${PREFIX}_IDENTITY_MIGRATION_URL`]
  && process.env[`${PREFIX}_IDENTITY_RUNTIME_URL`];
function binding(overrides = {}) {
  return { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 101, platformSessionId: 102, shopUserId: 103, role: 'customer', ...overrides };
}
async function apply(pool, relative) {
  await pool.query(await fs.readFile(path.join(__dirname, relative), 'utf8'));
}

test('native generation retirement fences admission and replays an exact immutable receipt', {
  skip: !enabled, timeout: 30000,
}, async () => {
  const migrationUrl = new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
  const runtimeUrl = new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
  for (const url of [migrationUrl, runtimeUrl]) {
    assert.ok(['127.0.0.1','localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(migrationUrl.pathname, runtimeUrl.pathname);
  const migration = new Pool({ connectionString: migrationUrl.href, max: 1 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 4 });
  let identityMigration;
  let identityRuntime;
  let identityLeases;
  try {
    for (const relative of [
      '../../db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
      '../../db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
      '../../docs/modernization/drafts/secureshop-turn-admission.sql',
      '../../docs/modernization/drafts/secureshop-conversation-generation-retirement.sql',
    ]) await apply(migration, relative);
    const queue = async (_id, action) => action();
    const conversations = createBoundConversationsRepository({ pool: runtime, queue });
    const turns = createTurnRequestsRepository({ pool: runtime });
    const lifecycle = createSecureShopConversationLifecycleRepository({ pool: runtime });
    const owned = binding(), sessionId = randomUUID(), resetId = randomUUID();
    const acquired = await conversations.acquireBoundSession({ id: sessionId, binding: owned });
    assert.equal(acquired.state, 'pending');
    assert.equal(await conversations.activateBoundSession(sessionId, owned), true);
    const requestId = randomUUID();
    const claim = await turns.claim({ sessionId, requestId, binding: owned, message: 'perform one owned action' });
    assert.equal(claim.status, 'claimed');
    const scope = { resetId, binding: owned };
    assert.deepEqual(await lifecycle.beginRetirement(scope), { resetId, status: 'pending' });
    await assert.rejects(runtime.query(`UPDATE secureshop_agents.conversation_generation_retirements
      SET status='completed',completed_at=clock_timestamp() WHERE reset_id=$1`, [resetId]),
    { code: '23514' });
    assert.deepEqual(await lifecycle.listRetirableSessions(scope), [{ sessionId, state: 'active' }]);
    await assert.rejects(conversations.acquireBoundSession({ id: randomUUID(), binding: owned }),
      { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(conversations.createPendingBoundSession({ id: randomUUID(), binding: owned }),
      { code: '55000' });
    await assert.rejects(lifecycle.completeRetirement(scope), { code: 'RETIREMENT_INCOMPLETE' });
    assert.deepEqual(await lifecycle.retireSession({ ...scope, sessionId }),
      { sessionId, replayed: false, uncertainTurns: 1 });
    assert.deepEqual(await lifecycle.retireSession({ ...scope, sessionId }),
      { sessionId, replayed: true, uncertainTurns: 0 });
    const terminal = (await runtime.query(`SELECT s.binding_state,t.status FROM secureshop_agents.agent_sessions s
      JOIN secureshop_agents.turn_requests t ON t.session_id=s.id WHERE s.id=$1 AND t.request_id=$2`,
    [sessionId, requestId])).rows[0];
    assert.deepEqual(terminal, { binding_state: 'abandoned', status: 'uncertain' });
    const completed = await lifecycle.completeRetirement(scope);
    assert.equal(completed.replayed, false);
    assert.equal(completed.receipt.sessionCount, 1);
    assert.equal(completed.receipt.uncertainTurnCount, 1);
    assert.deepEqual(await lifecycle.readRetirementReceipt(scope), completed.receipt);
    assert.deepEqual(await lifecycle.completeRetirement(scope), { receipt: completed.receipt, replayed: true });
    await assert.rejects(lifecycle.beginRetirement({ resetId, binding: { ...owned, platformOwnerId: 999 } }),
      { code: 'RETIREMENT_SCOPE_MISMATCH' });
    await assert.rejects(lifecycle.beginRetirement({ resetId: randomUUID(), binding: owned }),
      { code: 'RETIREMENT_SCOPE_MISMATCH' });
    await assert.rejects(runtime.query(`UPDATE secureshop_agents.conversation_generation_retirements
      SET session_count=2 WHERE reset_id=$1`, [resetId]), { code: 'P0001' });
    await assert.rejects(migration.query(`DELETE FROM secureshop_agents.conversation_generation_retirements
      WHERE reset_id=$1`, [resetId]), { code: 'P0001' });

    // Competing begin/admission calls serialize on the same launch lock. An
    // admission that wins first is included in retirement; one that loses is rejected.
    const next = binding({ generation: 2, launchId: owned.launchId, scenarioId: owned.scenarioId,
      platformOwnerId: owned.platformOwnerId, platformSessionId: owned.platformSessionId });
    const nextReset = randomUUID(), competingId = randomUUID();
    const raced = await Promise.allSettled([
      lifecycle.beginRetirement({ resetId: nextReset, binding: next }),
      conversations.acquireBoundSession({ id: competingId, binding: next }),
    ]);
    assert.equal(raced[0].status, 'fulfilled');
    if (raced[1].status === 'fulfilled') {
      assert.equal(raced[1].value.id, competingId);
      const listed = await lifecycle.listRetirableSessions({ resetId: nextReset, binding: next });
      assert.deepEqual(listed, [{ sessionId: competingId, state: 'pending' }]);
      await lifecycle.retireSession({ resetId: nextReset, binding: next, sessionId: competingId });
    } else assert.equal(raced[1].reason.code, 'CONVERSATION_UNAVAILABLE');
    const nextReceipt = await lifecycle.completeRetirement({ resetId: nextReset, binding: next });
    assert.equal(nextReceipt.receipt.sessionCount, raced[1].status === 'fulfilled' ? 1 : 0);
    await assert.rejects(conversations.acquireBoundSession({ id: randomUUID(), binding: next }),
      { code: 'CONVERSATION_UNAVAILABLE' });

    // A recovery path can pre-create pending state before reset begins. Its
    // activation and beginRetirement still serialize on the database trigger's
    // launch lock, and the winner cannot leave a usable row after retirement.
    const third = binding({ generation: 3, launchId: owned.launchId, scenarioId: owned.scenarioId,
      platformOwnerId: owned.platformOwnerId, platformSessionId: owned.platformSessionId });
    const thirdId = randomUUID(), thirdReset = randomUUID();
    await conversations.createPendingBoundSession({ id: thirdId, binding: third });
    const activationRace = await Promise.allSettled([
      lifecycle.beginRetirement({ resetId: thirdReset, binding: third }),
      conversations.activateBoundSession(thirdId, third),
    ]);
    assert.equal(activationRace[0].status, 'fulfilled');
    if (activationRace[1].status === 'fulfilled') {
      assert.equal(activationRace[1].value, true);
    } else assert.equal(activationRace[1].reason.code, '55000');
    await lifecycle.retireSession({ resetId: thirdReset, binding: third, sessionId: thirdId });
    await lifecycle.completeRetirement({ resetId: thirdReset, binding: third });
    assert.equal((await runtime.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',
      [thirdId])).rows[0].binding_state, 'abandoned');
    assert.equal(await conversations.activateBoundSession(thirdId, third), false);

    // Even a self-consistent journal digest is not proof when it disagrees with
    // the retained authoritative session set.
    const fourth = binding({ generation: 4, launchId: owned.launchId, scenarioId: owned.scenarioId,
      platformOwnerId: owned.platformOwnerId, platformSessionId: owned.platformSessionId });
    const fourthReset = randomUUID();
    await lifecycle.beginRetirement({ resetId: fourthReset, binding: fourth });
    const completedAt = (await runtime.query('SELECT clock_timestamp() AS now')).rows[0].now;
    const forged = buildReceipt({ resetId: fourthReset, ...fourth }, { completedAt,
      sessionCount: 1, uncertainTurnCount: 0, sessionSetSha256: digestSessionIds([randomUUID()]) });
    await runtime.query(`UPDATE secureshop_agents.conversation_generation_retirements
      SET status='completed',session_count=$2,uncertain_turn_count=$3,session_set_sha256=$4,
        receipt_sha256=$5,completed_at=$6 WHERE reset_id=$1`, [fourthReset, forged.sessionCount,
      forged.uncertainTurnCount, Buffer.from(forged.sessionSetSha256, 'hex'),
      Buffer.from(forged.receiptSha256, 'hex'), forged.completedAt]);
    await assert.rejects(lifecycle.readRetirementReceipt({ resetId: fourthReset, binding: fourth }),
      { code: 'INVALID_RETIREMENT_RECEIPT' });

    // PostgreSQL takes a row lock before a BEFORE UPDATE trigger runs. Prove
    // completion does not invert that row -> advisory order by trying it while
    // an active-row update is already waiting inside the admission trigger.
    const fifth = binding({ generation: 5, launchId: owned.launchId, scenarioId: owned.scenarioId,
      platformOwnerId: owned.platformOwnerId, platformSessionId: owned.platformSessionId });
    const fifthId = randomUUID(), fifthReset = randomUUID();
    await conversations.createPendingBoundSession({ id: fifthId, binding: fifth });
    assert.equal(await conversations.activateBoundSession(fifthId, fifth), true);
    await lifecycle.beginRetirement({ resetId: fifthReset, binding: fifth });
    const lockHolder = await runtime.connect();
    const updater = await runtime.connect();
    let blockedUpdate;
    try {
      await lockHolder.query('BEGIN');
      await lockHolder.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
        [`secureshop-conversation-admission:${fifth.launchId}`]);
      blockedUpdate = updater.query(`UPDATE secureshop_agents.agent_sessions
        SET token_budget_used=token_budget_used+1 WHERE id=$1`, [fifthId])
        .then(result => ({ result }), error => ({ error }));
      const waitDeadline = Date.now() + 3000;
      let rowOwned = false;
      while (Date.now() < waitDeadline) {
        const probe = await runtime.connect();
        try {
          await probe.query('BEGIN');
          await probe.query('SELECT id FROM secureshop_agents.agent_sessions WHERE id=$1 FOR UPDATE NOWAIT',
            [fifthId]);
          await probe.query('ROLLBACK');
        } catch (error) {
          await probe.query('ROLLBACK').catch(() => {});
          if (error.code === '55P03') {
            rowOwned = true;
            break;
          }
          throw error;
        } finally {
          probe.release();
        }
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal(rowOwned, true, 'active-row update must own the row while waiting inside its trigger');
      const heldRepository = createSecureShopConversationLifecycleRepository({
        pool: { connect: async () => ({ query: (...args) => lockHolder.query(...args), release() {} }),
          query: (...args) => runtime.query(...args) },
      });
      const completion = heldRepository.completeRetirement({ resetId: fifthReset, binding: fifth });
      const settled = await Promise.race([
        completion.then(() => 'fulfilled', error => error.code),
        new Promise(resolve => setTimeout(() => resolve('blocked'), 500)),
      ]);
      assert.equal(settled, 'RETIREMENT_INCOMPLETE');
      await completion.catch(() => {});
      const updateOutcome = await blockedUpdate;
      assert.equal(updateOutcome.error?.code, '55000');
    } finally {
      await lockHolder.query('ROLLBACK').catch(() => {});
      await updater.query('ROLLBACK').catch(() => {});
      lockHolder.release();
      updater.release();
      if (blockedUpdate) await blockedUpdate.catch(() => {});
    }
    await lifecycle.retireSession({ resetId: fifthReset, binding: fifth, sessionId: fifthId });
    await lifecycle.completeRetirement({ resetId: fifthReset, binding: fifth });

    if (compositionEnabled) {
      const identityMigrationUrl = new URL(process.env[`${PREFIX}_IDENTITY_MIGRATION_URL`]);
      const identityRuntimeUrl = new URL(process.env[`${PREFIX}_IDENTITY_RUNTIME_URL`]);
      for (const url of [identityMigrationUrl, identityRuntimeUrl]) {
        assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
        assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
      }
      assert.equal(identityMigrationUrl.pathname, identityRuntimeUrl.pathname);
      assert.notEqual(identityRuntimeUrl.pathname, runtimeUrl.pathname);
      identityMigration = new Pool({ connectionString: identityMigrationUrl.href, max: 1 });
      identityRuntime = new Pool({ connectionString: identityRuntimeUrl.href, max: 3 });
      identityLeases = new Pool({ connectionString: identityRuntimeUrl.href, max: 2 });
      await initializeIdentityRepository(identityRuntime, identityMigration);
      const identities = createIdentityRepository(identityRuntime);
      const launches = createSecureShopLaunchRepository(identityRuntime);
      const passwordHash = await bcrypt.hash('conversation-lifecycle-fixture', 4);
      const user = await identities.createUser({ username: `lifecycle-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@lifecycle.invalid`, passwordHash });
      const platformSession = await identities.createSession({ userId: user.id, token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(), expectedPasswordHash: passwordHash });
      const launch = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: platformSession.id, expiresAt: new Date(Date.now() + 3600000).toISOString() });
      const trusted = { platformOwnerId: user.id, platformSessionId: platformSession.id };
      const liveScope = launch.binding;
      const persona = { id: 501, role: 'customer' };
      const liveBinding = { ...liveScope, shopUserId: persona.id, role: persona.role };
      const liveSessionId = randomUUID();
      await conversations.acquireBoundSession({ id: liveSessionId, binding: liveBinding });
      assert.equal(await conversations.activateBoundSession(liveSessionId, liveBinding), true);
      const ledger = createPostgresRunLedger(identityRuntime, { leasePool: identityLeases });
      const coordinator = createRunCoordinator({ family: 'SecureShopBoundConversation', ledger,
        defaultTimeoutMs: 10000 });
      const conversationService = createBoundConversationService({ conversations, launches });
      const boundTurns = createBoundTurns({ conversations: conversationService, coordinator });
      const ownerKey = JSON.stringify(['SecureShopBoundConversation', liveSessionId]);
      const preRequestId = randomUUID();
      const harmless = await boundTurns.run(liveSessionId, liveScope, persona,
        { idempotencyKey: preRequestId }, boundary => boundary.effectWithReceipt('harmless-read',
          async () => ({ observed: true })));
      assert.deepEqual(harmless.value, { observed: true });
      assert.deepEqual(harmless.receipt, { version: 1, ownerKey, generation: '0',
        runId: harmless.receipt.runId, effectKey: `${preRequestId}:harmless-read`, status: 'completed' });
      assert.match(harmless.receipt.runId, /^[0-9a-f-]{36}$/);

      const heldRequestId = randomUUID();
      await turns.claim({ sessionId: liveSessionId, requestId: heldRequestId,
        binding: liveBinding, message: 'hold one admitted lifecycle turn' });
      let enteredResolve;
      let releaseResolve;
      const entered = new Promise(resolve => { enteredResolve = resolve; });
      const release = new Promise(resolve => { releaseResolve = resolve; });
      let lateEffects = 0;
      const held = boundTurns.run(liveSessionId, liveScope, persona,
        { idempotencyKey: heldRequestId }, async boundary => {
          enteredResolve(boundary.identity);
          await release;
          return boundary.effect('late-write', async () => { lateEffects += 1; });
        }).then(value => ({ value }), error => ({ error }));
      const heldIdentity = await entered;
      assert.equal(heldIdentity.ownerKey, ownerKey);
      // Simulate records left by a crashed process only after this real holder
      // has begun. A normal begin() already reconciles older residual records.
      const orphanRunId = randomUUID();
      const siblingOwnerKey = JSON.stringify(['SecureShopBoundConversation', randomUUID()]);
      const siblingRunId = randomUUID();
      await identityRuntime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [siblingOwnerKey]);
      await identityRuntime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
        VALUES($1,$2,$3,'running'),($4,$5,0,'running')`, [orphanRunId, ownerKey,
        heldIdentity.durableGeneration, siblingRunId, siblingOwnerKey]);
      await identityRuntime.query(`INSERT INTO graph_runtime.effects
        (owner_key,generation,effect_key,run_id,status) VALUES
        ($1,$2,'crashed-effect',$3,'started'),($4,0,'sibling-effect',$5,'started')`,
      [ownerKey, heldIdentity.durableGeneration, orphanRunId, siblingOwnerKey, siblingRunId]);
      const reset = await launches.beginReset({ ...trusted, launchId: liveScope.launchId,
        expectedGeneration: liveScope.generation, idempotencyKey: 'conversation-lifecycle-reset' });
      const service = createSecureShopConversationLifecycle({ repository: lifecycle,
        turns: boundTurns, cleanupAuthority: createSecureShopResetCleanupAuthorityRepository(identityRuntime) });
      let retirementSettled = false;
      const retiring = service.retireGeneration(reset.resetId)
        .then(value => { retirementSettled = true; return value; }, error => {
          retirementSettled = true; throw error;
        });
      await new Promise(resolve => setTimeout(resolve, 75));
      assert.equal(retirementSettled, false, 'retirement must retain the lease while admitted work drains');
      assert.deepEqual((await identityRuntime.query(`SELECT r.status AS run_status,e.status AS effect_status
        FROM graph_runtime.runs r JOIN graph_runtime.effects e USING(run_id)
        WHERE r.run_id=$1`, [orphanRunId])).rows[0],
      { run_status: 'running', effect_status: 'started' },
      'orphan facts must not terminalize before the held owner lease drains');
      releaseResolve();
      const heldOutcome = await held;
      assert.equal(heldOutcome.error?.name, 'AbortError');
      assert.equal(lateEffects, 0);
      const serviceReceipt = await retiring;
      assert.equal(serviceReceipt.resetId, reset.resetId);
      assert.equal(serviceReceipt.launchId, liveScope.launchId);
      assert.equal(serviceReceipt.fromGeneration, liveScope.generation);
      assert.equal(serviceReceipt.platformOwnerId, user.id);
      assert.equal(serviceReceipt.platformSessionId, platformSession.id);
      assert.equal(serviceReceipt.sessionCount, 1);
      assert.equal(serviceReceipt.uncertainTurnCount, 1);
      assert.deepEqual(await service.readReceipt(reset.resetId), serviceReceipt);
      assert.deepEqual(await service.retireGeneration(reset.resetId), serviceReceipt);
      const persisted = (await runtime.query(`SELECT s.binding_state,t.status
        FROM secureshop_agents.agent_sessions s JOIN secureshop_agents.turn_requests t ON t.session_id=s.id
        WHERE s.id=$1 AND t.request_id=$2`, [liveSessionId, heldRequestId])).rows[0];
      assert.deepEqual(persisted, { binding_state: 'abandoned', status: 'uncertain' });
      const graphOwner = (await identityRuntime.query(
        'SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1', [ownerKey])).rows[0];
      assert.equal(graphOwner.generation, '1');
      assert.equal((await identityRuntime.query(`SELECT count(*)::integer AS count FROM graph_runtime.runs
        WHERE owner_key=$1 AND status='running'`, [ownerKey])).rows[0].count, 0);
      const effects = (await identityRuntime.query(`SELECT run_id::text,owner_key,generation::text,effect_key,status
        FROM graph_runtime.effects WHERE owner_key=$1 ORDER BY effect_key`, [ownerKey])).rows;
      const expectedEffects = [
        { run_id: orphanRunId, owner_key: ownerKey, generation: '0',
          effect_key: 'crashed-effect', status: 'uncertain' },
        { run_id: harmless.receipt.runId, owner_key: ownerKey, generation: '0',
          effect_key: `${preRequestId}:harmless-read`, status: 'completed' },
      ].sort((left, right) => left.effect_key.localeCompare(right.effect_key));
      assert.deepEqual(effects, expectedEffects);
      assert.deepEqual((await identityRuntime.query(`SELECT r.status AS run_status,e.status AS effect_status
        FROM graph_runtime.runs r JOIN graph_runtime.effects e USING(run_id)
        WHERE r.run_id=$1`, [orphanRunId])).rows[0],
      { run_status: 'interrupted', effect_status: 'uncertain' });
      assert.deepEqual((await identityRuntime.query(`SELECT r.status AS run_status,e.status AS effect_status
        FROM graph_runtime.runs r JOIN graph_runtime.effects e USING(run_id)
        WHERE r.run_id=$1`, [siblingRunId])).rows[0],
      { run_status: 'running', effect_status: 'started' });

      // A pre-migration committed reset remains active after the additive
      // upgrade, but its new debt flag blocks commit replay until the private
      // agents receipt is verified. The migration does not retroactively
      // pretend the old reset was fenced.
      assert.equal((await launches.commitReset({ ...trusted, resetId: reset.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset.toGeneration })).generation, 2);
      await apply(identityMigration,
        '../../docs/modernization/drafts/secureshop-conversation-cleanup-checkpoint.sql');
      assert.deepEqual((await identityRuntime.query(`SELECT r.status,r.conversation_reconciliation_required,
          l.status AS launch_status FROM identity.secureshop_launch_resets r
          JOIN identity.secureshop_launches l USING(launch_id) WHERE r.reset_id=$1`, [reset.resetId])).rows[0],
      { status: 'committed', conversation_reconciliation_required: true, launch_status: 'active' });
      await assert.rejects(launches.commitReset({ ...trusted, resetId: reset.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset.toGeneration }), { code: 'CLEANUP_REQUIRED' });

      const cleanupAuthority = createSecureShopResetCleanupAuthorityRepository(identityRuntime);
      let privateReads = 0;
      const checkpoint = reader => createSecureShopConversationCleanupCheckpointRepository(identityRuntime, {
        getOperation: resetId => cleanupAuthority.getOperation(resetId),
        readRetirementReceipt: reader || (async resetId => {
          privateReads += 1;
          return service.readReceipt(resetId);
        }),
      });
      assert.equal((await checkpoint().finalize(reset.resetId)).replayed, false);
      assert.equal((await checkpoint().finalize(reset.resetId)).replayed, true);
      assert.equal(privateReads, 2, 'finalizer replay privately rereads authoritative receipt');
      assert.equal((await launches.commitReset({ ...trusted, resetId: reset.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset.toGeneration })).generation, 2);

      const reset2 = await launches.beginReset({ ...trusted, launchId: liveScope.launchId,
        expectedGeneration: 2, idempotencyKey: 'conversation-checkpoint-2' });
      const receipt2 = await service.retireGeneration(reset2.resetId);
      await assert.rejects(launches.commitReset({ ...trusted, resetId: reset2.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset2.toGeneration }), { code: 'CLEANUP_REQUIRED' });
      const corruptions = [
        value => ({ ...value, receiptSha256: '0'.repeat(64) }),
        value => ({ ...value, platformOwnerId: value.platformOwnerId + 1 }),
        value => ({ ...value, resetId: randomUUID() }),
        value => ({ ...value, fromGeneration: value.fromGeneration + 1 }),
      ];
      for (const corrupt of corruptions) {
        await assert.rejects(checkpoint(async () => corrupt(receipt2)).finalize(reset2.resetId),
          { code: 'INVALID_CONVERSATION_RECEIPT' });
      }
      assert.equal((await identityRuntime.query(`SELECT count(*)::integer AS count FROM
        identity.secureshop_conversation_cleanup_history WHERE reset_id=$1`, [reset2.resetId])).rows[0].count, 0);

      // Native storage accepts the bounded launch aggregate above 256, while
      // repository validation rejects anything above 256*256 before writing.
      const receipt300 = buildReceipt({ resetId: reset2.resetId, launchId: liveScope.launchId,
        scenarioId: liveScope.scenarioId, generation: 2, platformOwnerId: user.id,
        platformSessionId: platformSession.id }, { completedAt: receipt2.completedAt, sessionCount: 2,
        uncertainTurnCount: 300, sessionSetSha256: receipt2.sessionSetSha256 });
      assert.equal((await checkpoint(async () => receipt300).finalize(reset2.resetId))
        .checkpoint.uncertainTurnCount, 300);
      assert.equal((await launches.commitReset({ ...trusted, resetId: reset2.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset2.toGeneration })).generation, 3);

      const reset3 = await launches.beginReset({ ...trusted, launchId: liveScope.launchId,
        expectedGeneration: 3, idempotencyKey: 'conversation-checkpoint-3' });
      const receipt3 = await service.retireGeneration(reset3.resetId);
      const tooMany = buildReceipt({ resetId: reset3.resetId, launchId: liveScope.launchId,
        scenarioId: liveScope.scenarioId, generation: 3, platformOwnerId: user.id,
        platformSessionId: platformSession.id }, { completedAt: receipt3.completedAt, sessionCount: 2,
        uncertainTurnCount: 65537, sessionSetSha256: receipt3.sessionSetSha256 });
      await assert.rejects(checkpoint(async () => tooMany).finalize(reset3.resetId),
        { code: 'INVALID_CONVERSATION_RECEIPT' });
      assert.equal((await identityRuntime.query(`SELECT conversation_reconciliation_required FROM
        identity.secureshop_launch_resets WHERE reset_id=$1`, [reset3.resetId])).rows[0]
        .conversation_reconciliation_required, true);

      // Concurrent finalizers converge on one immutable history record.
      const racedFinalizers = await Promise.all([
        checkpoint(async () => receipt3).finalize(reset3.resetId),
        checkpoint(async () => receipt3).finalize(reset3.resetId),
      ]);
      assert.deepEqual(racedFinalizers.map(value => value.replayed).sort(), [false, true]);
      assert.equal((await identityRuntime.query(`SELECT count(*)::integer AS count FROM
        identity.secureshop_conversation_cleanup_history WHERE reset_id=$1`, [reset3.resetId])).rows[0].count, 1);
      assert.equal((await launches.commitReset({ ...trusted, resetId: reset3.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset3.toGeneration })).generation, 4);

      const history = (await identityRuntime.query(`SELECT * FROM identity.secureshop_conversation_cleanup_history
        WHERE reset_id=$1`, [reset3.resetId])).rows[0];
      await assert.rejects(identityRuntime.query(`INSERT INTO identity.secureshop_conversation_cleanup_history
        (reset_id,launch_id,scenario_id,from_generation,original_platform_owner_id,
         original_platform_session_id,receipt_version,receipt_sha256,session_count,
         uncertain_turn_count,session_set_sha256,target_completed_at,verified_at)
        VALUES($1,$2,$3,$4,$5,$6,1,$7,0,0,$8,clock_timestamp()+interval '1 hour',
          clock_timestamp()+interval '2 hour')`, [reset3.resetId, history.launch_id, history.scenario_id,
        history.from_generation, history.original_platform_owner_id, history.original_platform_session_id,
        history.receipt_sha256, history.session_set_sha256]), { code: 'P0001' });
      await assert.rejects(identityRuntime.query(`UPDATE identity.secureshop_conversation_cleanup_history
        SET session_count=0 WHERE reset_id=$1`, [reset3.resetId]), { code: '42501' });
      await assert.rejects(identityMigration.query(`DELETE FROM identity.secureshop_conversation_cleanup_history
        WHERE reset_id=$1`, [reset3.resetId]), { code: '55000' });

      // Commit and checkpoint use the same launch -> reset lock order. Commit
      // cannot pass the trigger before history exists; after finalization an
      // exact retry succeeds without duplicating the immutable checkpoint.
      const reset4 = await launches.beginReset({ ...trusted, launchId: liveScope.launchId,
        expectedGeneration: 4, idempotencyKey: 'conversation-checkpoint-race' });
      const receipt4 = await service.retireGeneration(reset4.resetId);
      const insertValues = [reset4.resetId, liveScope.launchId, liveScope.scenarioId, 4,
        user.id, platformSession.id, Buffer.from(receipt4.receiptSha256, 'hex'),
        Buffer.from(receipt4.sessionSetSha256, 'hex')];
      const directInsert = `INSERT INTO identity.secureshop_conversation_cleanup_history
        (reset_id,launch_id,scenario_id,from_generation,original_platform_owner_id,
         original_platform_session_id,receipt_version,receipt_sha256,session_count,
         uncertain_turn_count,session_set_sha256,target_completed_at)
        VALUES($1,$2,$3,$4,$5,$6,1,$7,0,0,$8,$9)`;
      await assert.rejects(identityRuntime.query(directInsert,
        [...insertValues, new Date(Date.now() + 3600000).toISOString()]), { code: 'P0001' });
      const wrongScope = [...insertValues];
      wrongScope[4] = user.id + 1;
      await assert.rejects(identityRuntime.query(directInsert,
        [...wrongScope, receipt4.completedAt]), { code: 'P0001' });
      const finalizeCommitRace = await Promise.allSettled([
        checkpoint().finalize(reset4.resetId),
        launches.commitReset({ ...trusted, resetId: reset4.resetId,
          launchId: liveScope.launchId, expectedGeneration: reset4.toGeneration }),
      ]);
      assert.equal(finalizeCommitRace[0].status, 'fulfilled');
      if (finalizeCommitRace[1].status === 'rejected') {
        assert.equal(finalizeCommitRace[1].reason.code, 'CLEANUP_REQUIRED');
      }
      assert.equal((await launches.commitReset({ ...trusted, resetId: reset4.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset4.toGeneration })).generation, 5);

      // Conversation verification does not clear or bypass independently
      // unresolved target cleanup.
      const target = await launches.reserveFilesTarget({ ...trusted, launchId: liveScope.launchId,
        expectedGeneration: 5 });
      const reset5 = await launches.beginReset({ ...trusted, launchId: liveScope.launchId,
        expectedGeneration: 5, idempotencyKey: 'conversation-checkpoint-target-debt' });
      await service.retireGeneration(reset5.resetId);
      await checkpoint().finalize(reset5.resetId);
      assert.deepEqual((await identityRuntime.query(`SELECT reconciliation_required,
          conversation_reconciliation_required FROM identity.secureshop_launch_resets WHERE reset_id=$1`,
      [reset5.resetId])).rows[0],
      { reconciliation_required: true, conversation_reconciliation_required: false });
      assert.equal((await identityRuntime.query(`SELECT count(*)::integer AS count FROM
        identity.secureshop_target_reservations WHERE target_id=$1`, [target.targetId])).rows[0].count, 1);
      await assert.rejects(launches.commitReset({ ...trusted, resetId: reset5.resetId,
        launchId: liveScope.launchId, expectedGeneration: reset5.toGeneration }), { code: 'CLEANUP_REQUIRED' });
    }
  } finally {
    await Promise.allSettled([identityLeases?.end(), identityRuntime?.end(), identityMigration?.end(),
      runtime.end(), migration.end()]);
  }
});
