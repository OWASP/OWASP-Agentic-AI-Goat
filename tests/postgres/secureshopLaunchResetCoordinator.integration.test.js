'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');
const { createSecureShopConversationLifecycleRepository } = require('../../server/database/postgres/secureshopConversationLifecycleRepository');
const { createSecureShopConversationCleanupCheckpointRepository } = require('../../server/database/postgres/secureshopConversationCleanupCheckpointRepository');
const { createSecureShopProgressCleanupCheckpointRepository, WORKSHOP_KEY } = require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository');
const { createObjectiveJudgmentRepository } = require('../../server/database/postgres/objectiveJudgmentRepository');
const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createBoundTurns } = require('../../server/services/secureshopBoundTurns');
const { createSecureShopConversationLifecycle } = require('../../server/services/secureshopConversationLifecycle');
const { createSecureShopReviewResetCoordinator } = require('../../server/services/secureshopReviewResetCoordinator');
const { createSecureShopLaunchResetCoordinator } = require('../../server/services/secureshopLaunchResetCoordinator');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');

const PREFIX = 'PG_SECURESHOP_LAUNCH_RESET_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env[`${PREFIX}_IDENTITY_MIGRATION_URL`] && process.env[`${PREFIX}_IDENTITY_RUNTIME_URL`]
  && process.env[`${PREFIX}_AGENTS_MIGRATION_URL`] && process.env[`${PREFIX}_AGENTS_RUNTIME_URL`];
async function sql(pool, relative) {
  await pool.query(await fs.readFile(path.join(__dirname, relative), 'utf8'));
}

test('native launch reset composes all durable stages, replay, recovery, and catalog fail-closed', {
  skip: !enabled, timeout: 30000,
}, async () => {
  const urls = Object.fromEntries(['IDENTITY_MIGRATION','IDENTITY_RUNTIME','AGENTS_MIGRATION','AGENTS_RUNTIME']
    .map(key => [key, new URL(process.env[`${PREFIX}_${key}_URL`])]));
  for (const url of Object.values(urls)) {
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(urls.IDENTITY_MIGRATION.pathname, urls.IDENTITY_RUNTIME.pathname);
  assert.equal(urls.AGENTS_MIGRATION.pathname, urls.AGENTS_RUNTIME.pathname);
  assert.notEqual(urls.IDENTITY_RUNTIME.pathname, urls.AGENTS_RUNTIME.pathname);
  const identityMigration = new Pool({ connectionString: urls.IDENTITY_MIGRATION.href, max: 1 });
  const identity = new Pool({ connectionString: urls.IDENTITY_RUNTIME.href, max: 6 });
  const leases = new Pool({ connectionString: urls.IDENTITY_RUNTIME.href, max: 2 });
  const agentsMigration = new Pool({ connectionString: urls.AGENTS_MIGRATION.href, max: 1 });
  const agents = new Pool({ connectionString: urls.AGENTS_RUNTIME.href, max: 5 });
  try {
    await initializeIdentityRepository(identity, identityMigration);
    for (const draft of ['secureshop-instance-objective-contributions.sql',
      'secureshop-target-reconciliation.sql',
      'secureshop-conversation-cleanup-checkpoint.sql', 'secureshop-progress-cleanup-checkpoint.sql']) {
      await sql(identityMigration, `../../docs/modernization/drafts/${draft}`);
    }
    for (const migration of ['../../db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
      '../../db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
      '../../docs/modernization/drafts/secureshop-turn-admission.sql',
      '../../docs/modernization/drafts/secureshop-conversation-generation-retirement.sql']) {
      await sql(agentsMigration, migration);
    }
    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const cleanupAuthority = createSecureShopResetCleanupAuthorityRepository(identity);
    const conversationRows = createBoundConversationsRepository({ pool: agents,
      queue: async (_id, action) => action() });
    const turnRows = createTurnRequestsRepository({ pool: agents });
    const lifecycleRows = createSecureShopConversationLifecycleRepository({ pool: agents });
    const ledger = createPostgresRunLedger(identity, { leasePool: leases });
    const coordinator = createRunCoordinator({ family: 'SecureShopBoundConversation', ledger });
    const conversationService = createBoundConversationService({ conversations: conversationRows, launches });
    const turns = createBoundTurns({ conversations: conversationService, coordinator });
    const lifecycle = createSecureShopConversationLifecycle({ repository: lifecycleRows, turns, cleanupAuthority });
    const conversationCheckpoint = createSecureShopConversationCleanupCheckpointRepository(identity, {
      getOperation: resetId => cleanupAuthority.getOperation(resetId),
      readRetirementReceipt: resetId => lifecycle.readReceipt(resetId),
    });
    const progressCheckpoint = createSecureShopProgressCleanupCheckpointRepository(identity);
    const receipts = createObjectiveJudgmentRepository(identity);
    const progress = createWorkshopProgressRepository(identity);
    const targetCoordinator = createSecureShopReviewResetCoordinator({ launches, cleanupAuthority,
      reviewRepository: { async cleanup() { throw new Error('unexpected review target'); } },
      reconciler: { async reconcile() { throw new Error('unexpected reconciliation'); } } });
    const resetCoordinator = createSecureShopLaunchResetCoordinator({ launches, cleanupAuthority,
      conversationLifecycle: lifecycle, conversationCheckpoint, targetCoordinator, progressCheckpoint });
    const passwordHash = await bcrypt.hash('launch-reset-owned-fixture', 4);
    const owner = async label => {
      const user = await identities.createUser({ username: `${label}-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@launch-reset.invalid`, passwordHash });
      const session = await identities.createSession({ userId: user.id, token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(), expectedPasswordHash: passwordHash });
      const launch = await launches.issueOrRenew({ platformOwnerId: user.id, platformSessionId: session.id,
        expiresAt: new Date(Date.now() + 3600000).toISOString() });
      return { user, session, launch, trusted: { platformOwnerId: user.id, platformSessionId: session.id } };
    };
    const addConversation = async (subject, personaId) => {
      const binding = { ...subject.launch.binding, shopUserId: personaId, role: 'customer' };
      const sessionId = randomUUID();
      await conversationRows.acquireBoundSession({ id: sessionId, binding });
      assert.equal(await conversationRows.activateBoundSession(sessionId, binding), true);
      const requestId = randomUUID();
      await turnRows.claim({ sessionId, requestId, binding, message: 'retained reset turn' });
      return { sessionId, requestId };
    };

    // The catalog is deliberately absent in current production metadata. The
    // aggregate must stop at progress and leave the launch uncommitted.
    const absent = await owner('catalog-absent');
    const absentTurn = await addConversation(absent, 701);
    await assert.rejects(resetCoordinator.reset({ ...absent.trusted,
      launchId: absent.launch.binding.launchId, expectedGeneration: 1,
      idempotencyKey: 'catalog-absent-reset' }), { code: 'CATALOG_UNAVAILABLE' });
    const absentReset = (await identity.query(`SELECT r.reset_id,r.status,r.reconciliation_required,
        r.conversation_reconciliation_required,r.progress_reconciliation_required,l.status AS launch_status
      FROM identity.secureshop_launch_resets r JOIN identity.secureshop_launches l USING(launch_id)
      WHERE r.launch_id=$1`, [absent.launch.binding.launchId])).rows[0];
    assert.deepEqual({ status: absentReset.status, targets: absentReset.reconciliation_required,
      conversations: absentReset.conversation_reconciliation_required,
      progress: absentReset.progress_reconciliation_required, launch: absentReset.launch_status },
    { status: 'fenced', targets: false, conversations: false, progress: true, launch: 'resetting' });
    assert.deepEqual((await agents.query(`SELECT s.binding_state,t.status FROM secureshop_agents.agent_sessions s
      JOIN secureshop_agents.turn_requests t ON t.session_id=s.id WHERE s.id=$1 AND t.request_id=$2`,
    [absentTurn.sessionId, absentTurn.requestId])).rows[0],
    { binding_state: 'abandoned', status: 'uncertain' });

    // Activate only the fixture catalog required by the draft progress stage.
    await identityMigration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,ordinal,catalog_active)
      VALUES($1,$1,'SecureShop Agent Security',900,true)`, [WORKSHOP_KEY]);
    await identityMigration.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,ordinal,catalog_active,is_enabled)
      VALUES($1,'owned-reset-proof','Owned reset proof',1,true,true)`, [WORKSHOP_KEY]);

    const subject = await owner('all-stages');
    const subjectTurn = await addConversation(subject, 702);
    const siblingPlatformSession = await identities.createSession({ userId: subject.user.id,
      token: randomUUID(), expiresAt: new Date(Date.now() + 3600000).toISOString(),
      expectedPasswordHash: passwordHash });
    const siblingLaunch = await launches.issueOrRenew({ platformOwnerId: subject.user.id,
      platformSessionId: siblingPlatformSession.id,
      expiresAt: new Date(Date.now() + 3600000).toISOString() });
    assert.notEqual(siblingLaunch.binding.launchId, subject.launch.binding.launchId);
    assert.notEqual(siblingLaunch.binding.scenarioId, subject.launch.binding.scenarioId);
    await identity.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation,started_at)
      VALUES($1,$2,4,clock_timestamp())`, [subject.user.id, WORKSHOP_KEY]);
    const subjectBinding = { ...subject.launch.binding, ...subject.trusted };
    const siblingBinding = { ...siblingLaunch.binding, platformOwnerId: subject.user.id,
      platformSessionId: siblingPlatformSession.id };
    const award = async binding => {
      const evaluation = { userId: subject.user.id, evaluationId: randomUUID(),
        workshopKey: WORKSHOP_KEY, objectiveId: 'owned-reset-proof', family: 'SecureShop',
        scenario: 'aggregate-reset', rubricVersion: 'instance-v1', evidenceDigest: 'a'.repeat(64),
        runId: randomUUID(), mode: null, instanceScope: binding };
      await receipts.beginEvaluation(evaluation);
      return receipts.recordVerdict({ userId: subject.user.id, evaluationId: evaluation.evaluationId,
        result: { family: evaluation.family, scenario: evaluation.scenario,
          objectiveId: evaluation.objectiveId, rubricVersion: evaluation.rubricVersion,
          evidenceDigest: evaluation.evidenceDigest, runId: evaluation.runId, mode: null,
          verdict: 'pass', criteria: [{ id: 'effect', satisfied: true, evidenceRefs: ['receipt'] }],
          explanation: 'Owned aggregate fixture.', provider: 'fixture', model: 'fixture', usage: null } });
    };
    await award(subjectBinding);
    await award(siblingBinding);
    for (const [binding, delta] of [[subjectBinding, 2], [siblingBinding, 3]]) {
      await progress.recordSecureShopActivity({ userId: subject.user.id, activityKey: 'agent_turn',
        activityDelta: delta, contributionId: randomUUID(), expectedGeneration: 4,
        instanceScope: binding });
    }
    const timeStart = Date.now();
    for (const [binding, seconds] of [[subjectBinding, 23], [siblingBinding, 17]]) {
      await progress.recordHeartbeat({ userId: subject.user.id, workshopKey: WORKSHOP_KEY,
        now: timeStart, expectedGeneration: 4, instanceScope: binding });
      await progress.recordHeartbeat({ userId: subject.user.id, workshopKey: WORKSHOP_KEY,
        now: timeStart + seconds * 1000, expectedGeneration: 4, instanceScope: binding });
    }
    const input = { ...subject.trusted, launchId: subject.launch.binding.launchId,
      expectedGeneration: 1, idempotencyKey: 'all-stages-reset' };
    const first = await resetCoordinator.reset(input);
    assert.equal(first.status, 'committed');
    assert.equal(first.fromGeneration, 1);
    assert.equal(first.toGeneration, 2);
    assert.equal(first.targets, 0);
    assert.equal(first.binding.generation, 2);
    assert.deepEqual((await agents.query(`SELECT s.binding_state,t.status FROM secureshop_agents.agent_sessions s
      JOIN secureshop_agents.turn_requests t ON t.session_id=s.id WHERE s.id=$1 AND t.request_id=$2`,
    [subjectTurn.sessionId, subjectTurn.requestId])).rows[0],
    { binding_state: 'abandoned', status: 'uncertain' });
    const checkpoint = (await identity.query(`SELECT r.status,r.reconciliation_required,
        r.conversation_reconciliation_required,r.progress_reconciliation_required,l.status AS launch_status,
        (SELECT count(*)::integer FROM identity.secureshop_conversation_cleanup_history c WHERE c.reset_id=r.reset_id) AS conversations,
        (SELECT count(*)::integer FROM identity.secureshop_progress_cleanup_history p WHERE p.reset_id=r.reset_id) AS progress
      FROM identity.secureshop_launch_resets r JOIN identity.secureshop_launches l USING(launch_id)
      WHERE r.reset_id=$1`, [first.resetId])).rows[0];
    assert.deepEqual(checkpoint, { status: 'committed', reconciliation_required: false,
      conversation_reconciliation_required: false, progress_reconciliation_required: false,
      launch_status: 'active', conversations: 1, progress: 1 });
    assert.deepEqual((await identity.query(`SELECT generation,
        (SELECT count(*)::integer FROM workshop_platform.completions c WHERE c.user_id=s.user_id AND c.workshop_key=s.workshop_key) AS completions,
        (SELECT count(*)::integer FROM workshop_platform.activity_counters a WHERE a.user_id=s.user_id AND a.workshop_key=s.workshop_key) AS activity,
        (SELECT count(*)::integer FROM workshop_platform.time_tracking t WHERE t.user_id=s.user_id AND t.workshop_key=s.workshop_key) AS time
      FROM workshop_platform.user_state s WHERE user_id=$1 AND workshop_key=$2`,
    [subject.user.id, WORKSHOP_KEY])).rows[0], { generation: 4, completions: 1, activity: 1, time: 2 });
    assert.equal((await progress.getWorkshopProgress(subject.user.id, WORKSHOP_KEY)).timeSpentSeconds, 17);
    assert.equal((await identity.query(`SELECT activity_count FROM workshop_platform.activity_counters
      WHERE user_id=$1 AND workshop_key=$2 AND activity_key='agent_turn'`,
    [subject.user.id, WORKSHOP_KEY])).rows[0].activity_count, 3);
    // The sibling launch and each of its canonical contributions survive.
    assert.deepEqual((await identity.query(`SELECT status,generation FROM identity.secureshop_launches
      WHERE launch_id=$1`, [siblingLaunch.binding.launchId])).rows[0],
    { status: 'active', generation: '1' });
    assert.deepEqual(await resetCoordinator.reset(input), first);
    assert.deepEqual((await identity.query(`SELECT
        (SELECT count(*)::integer FROM identity.secureshop_conversation_cleanup_history WHERE reset_id=$1) AS conversations,
        (SELECT count(*)::integer FROM identity.secureshop_progress_cleanup_history WHERE reset_id=$1) AS progress`,
    [first.resetId])).rows[0], { conversations: 1, progress: 1 });

    // Once the catalog exists, the earlier partial reset is recoverable without
    // reactivating its launch or synthesizing a second reset generation.
    const recovered = await resetCoordinator.recover(absentReset.reset_id);
    assert.deepEqual(recovered, { resetId: absentReset.reset_id, status: 'fenced',
      resolved: true, activated: false, targets: 0 });
    assert.equal((await identity.query(`SELECT l.status FROM identity.secureshop_launches l
      WHERE launch_id=$1`, [absent.launch.binding.launchId])).rows[0].status, 'resetting');
  } finally {
    await Promise.allSettled([leases.end(), identity.end(), identityMigration.end(),
      agents.end(), agentsMigration.end()]);
  }
});
