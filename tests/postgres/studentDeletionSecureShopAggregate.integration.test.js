'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { initializeSecureShopReviewDb } = require('../../server/database/postgres/secureshopReviewDb');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createStudentDeletionRepository } = require('../../server/database/postgres/studentDeletionRepository');
const { createSecureShopStudentDeletionCleanup } = require('../../server/services/secureshopStudentDeletionCleanup');
const { createSecureShopOwnerResetRepository } = require('../../server/database/postgres/secureshopOwnerResetRepository');
const { createSecureShopOwnerResetService } = require('../../server/services/secureshopOwnerResetService');
const { createSecureShopBoundReviewComposition, DEFAULT_OBJECTIVES } = require('../../server/services/secureshopBoundReviewComposition');
const { createObjectiveJudgmentRepository } = require('../../server/database/postgres/objectiveJudgmentRepository');

const PREFIX = 'PG_STUDENT_DELETION_AGGREGATE_';
const KEYS = ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'AGENTS_MIGRATION_URL',
  'AGENTS_RUNTIME_URL', 'REVIEW_MIGRATION_URL', 'REVIEW_RUNTIME_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && KEYS.every(key => process.env[PREFIX + key]);
function url(key) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  return value.href;
}

test('student deletion recovers real bound conversations, reviews, and instance progress without reactivation', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const workspace = path.resolve(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^dvaia-student-deletion-aggregate-/);
  const identityMigration = new Pool({ connectionString: url('IDENTITY_MIGRATION_URL'), max: 2 });
  const identity = new Pool({ connectionString: url('IDENTITY_RUNTIME_URL'), max: 10 });
  const leases = new Pool({ connectionString: url('IDENTITY_RUNTIME_URL'), max: 3 });
  const agentsMigration = new Pool({ connectionString: url('AGENTS_MIGRATION_URL'), max: 2 });
  const agents = new Pool({ connectionString: url('AGENTS_RUNTIME_URL'), max: 8 });
  const reviewMigration = new Pool({ connectionString: url('REVIEW_MIGRATION_URL'), max: 2 });
  const reviews = new Pool({ connectionString: url('REVIEW_RUNTIME_URL'), max: 8 });
  try {
    await initializeIdentityRepository(identity, identityMigration);
    await initializeSecureShopAgentsDb({ runtimePool: agents, migrationPool: agentsMigration });
    await initializeSecureShopReviewDb(reviews, reviewMigration);
    await agentsMigration.query(await fs.readFile(path.join(workspace,
      'docs/modernization/drafts/secureshop-bound-persona-sessions.sql'), 'utf8'));
    await identityMigration.query(await fs.readFile(path.join(workspace,
      'docs/modernization/drafts/student-deletion-journal.sql'), 'utf8'));
    await identityMigration.query(await fs.readFile(path.join(workspace,
      'docs/modernization/drafts/secureshop-owner-reset.sql'), 'utf8'));
    await identityMigration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,ordinal,catalog_active)
      VALUES('secureshop_agent_security','secureshop_agent_security','SecureShop Agent Security',900,true)
      ON CONFLICT(workshop_key) DO UPDATE SET catalog_active=true`);
    for (const [ordinal, objective] of DEFAULT_OBJECTIVES.entries()) {
      await identityMigration.query(`INSERT INTO workshop_platform.objectives
        (workshop_key,objective_id,label,ordinal,catalog_active,is_enabled)
        VALUES('secureshop_agent_security',$1,$2,$3,true,true)
        ON CONFLICT(workshop_key,objective_id) DO UPDATE
          SET catalog_active=true,is_enabled=true`, [objective, objective, ordinal + 1]);
    }

    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const passwordHash = await bcrypt.hash('connected deletion fixture', 4);
    async function owner(label, role = 'student') {
      const user = await identities.createUser({ username: `${label}-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@aggregate.invalid`, passwordHash });
      if (role === 'admin') await identityMigration.query(
        "UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1", [user.id]);
      const session = await identities.createSession({ userId: user.id, token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
      const issued = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt: new Date(Date.now() + 3600000) });
      return { user, session, issued };
    }
    const admin = await owner('aggregate-admin', 'admin');
    const subject = await owner('aggregate-subject');
    const sibling = await owner('aggregate-sibling');
    const loggedOutSession = await identities.createSession({ userId: subject.user.id, token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const loggedOut = await launches.issueOrRenew({ platformOwnerId: subject.user.id,
      platformSessionId: loggedOutSession.id, expiresAt: new Date(Date.now() + 3600000) });
    const provider = { config: { provider: 'fixture', model: 'unused' }, async chat() {
      throw new Error('model calls are outside deletion qualification');
    } };
    const manifest = { getForRole: () => [], buildExternalMcpPromptBlock: () => '' };
    const composition = createSecureShopBoundReviewComposition({ identityPool: identity,
      agentsPool: agents, reviewPool: reviews, leasePool: leases, launches,
      agentRuntime: { provider, manifest }, authenticatePersona(_req, _res, next) { next(); },
      fixtures: [{ productId: 7, authorId: 2, body: 'Owned cleanup fixture.', rating: 3 }],
      judge: async () => ({ verdict: 'fail', criteria: [], explanation: 'unused' }) });
    const persona = Object.freeze({ id: 77, role: 'merchant' });
    async function addPersonaSession(scope, shopUserId = persona.id) {
      const sessionId = randomUUID();
      await agents.query(`INSERT INTO secureshop_agents.bound_persona_sessions
        (session_id,jti_sha256,platform_launch_id,platform_scenario_id,
         platform_launch_generation,original_platform_owner_id,original_platform_session_id,
         shop_user_id,role,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '1 hour')`,
      [sessionId,createHash('sha256').update(randomUUID()).digest(),scope.launchId,scope.scenarioId,
        scope.generation,scope.platformOwnerId,scope.platformSessionId,shopUserId,persona.role]);
      return sessionId;
    }
    const activeScope = subject.issued.binding;
    const loggedOutScope = loggedOut.binding;
    const siblingScope = sibling.issued.binding;
    const activeTarget = await composition.runtime.application.resolveTarget(activeScope);
    const siblingTarget = await composition.runtime.application.resolveTarget(siblingScope);
    assert.equal((await reviews.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',
      [activeTarget.targetId])).rows[0].n, 1);
    const activeConversation = await composition.runtime.conversations.create(activeScope, persona);
    const retiredConversation = await composition.runtime.conversations.create(loggedOutScope, persona);
    const siblingConversation = await composition.runtime.conversations.create(siblingScope, persona);
    await Promise.all([addPersonaSession(activeScope),addPersonaSession(loggedOutScope),
      addPersonaSession(siblingScope)]);

    const receipts = createObjectiveJudgmentRepository(identity);
    await identity.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation,started_at)
      VALUES($1,'secureshop_agent_security',1,clock_timestamp()),
            ($2,'secureshop_agent_security',1,clock_timestamp())`, [subject.user.id, sibling.user.id]);
    async function award(owner, scope, objective) {
      const evaluationId = randomUUID();
      const input = { userId: owner.user.id, evaluationId, workshopKey: 'secureshop_agent_security',
        objectiveId: objective, family: 'SecureShop', scenario: 'deletion-fixture', rubricVersion: 'fixture-v1',
        evidenceDigest: 'a'.repeat(64), runId: randomUUID(), mode: 'vuln', instanceScope: scope };
      await receipts.beginEvaluation(input);
      await receipts.recordVerdict({ userId: owner.user.id, evaluationId, result: {
        family: input.family, scenario: input.scenario, objectiveId: input.objectiveId,
        rubricVersion: input.rubricVersion, evidenceDigest: input.evidenceDigest, runId: input.runId,
        mode: 'vuln', verdict: 'pass', criteria: [{ id: 'effect', satisfied: true, evidenceRefs: ['fixture'] }],
        explanation: 'Owned connected cleanup fixture.', provider: 'fixture', model: 'fixture', usage: null } });
    }
    await award(subject, activeScope, DEFAULT_OBJECTIVES[0]);
    await award(subject, loggedOutScope, DEFAULT_OBJECTIVES[1]);
    await award(sibling, siblingScope, DEFAULT_OBJECTIVES[0]);
    await identity.query(`UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),
      revoke_reason='ordinary_logout' WHERE id=$1`, [loggedOutSession.id]);

    let entered, release;
    const inside = new Promise(resolve => { entered = resolve; });
    const held = new Promise(resolve => { release = resolve; });
    const running = composition.runtime.turns.run(activeConversation.id, activeScope, persona,
      { idempotencyKey: 'held-deletion-turn' }, async execution => {
        entered();
        await new Promise(resolve => execution.signal.addEventListener('abort', resolve, { once: true }));
        await held;
        await execution.check();
      });
    const rejectedRun = assert.rejects(running, { name: 'AbortError' });
    await inside;
    const jobs = createStudentDeletionRepository(identity,
      { steps: ['revoke_runs', 'secureshop', 'identity'] });
    const admitted = await jobs.admit({ requesterId: admin.user.id, subjectId: subject.user.id });
    const lease = await jobs.claim(admitted.jobId); assert.ok(lease);
    const cleanup = createSecureShopStudentDeletionCleanup({ repository: jobs,
      launchResetCoordinator: composition.launchResetCoordinator });
    const scope = { subjectId: subject.user.id, jobId: admitted.jobId, leaseToken: lease.leaseToken,
      check: () => jobs.renew({ jobId: admitted.jobId, leaseToken: lease.leaseToken }),
      signal: new AbortController().signal };
    let settled = false;
    const cleaning = cleanup(scope).finally(() => { settled = true; });
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const status = (await identity.query(`SELECT count(*)::integer n FROM graph_runtime.runs
        WHERE owner_key=$1 AND status='running'`,
      [JSON.stringify(['SecureShopBoundConversation', activeConversation.id])])).rows[0].n;
      if (status === 0) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(settled, false, 'cleanup drains the admitted callback before returning');
    release(); await rejectedRun;
    assert.deepEqual(await cleaning, { completed: true, resetCount: 2 });
    assert.deepEqual(await cleanup(scope), { completed: true, resetCount: 2 });

    assert.equal((await reviews.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',
      [activeTarget.targetId])).rows[0].n, 0);
    assert.equal((await reviews.query('SELECT count(*)::integer n FROM secureshop_review.review_cleanup_receipts WHERE target_id=$1',
      [activeTarget.targetId])).rows[0].n, 1);
    assert.equal((await reviews.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',
      [siblingTarget.targetId])).rows[0].n, 1);
    const states = (await agents.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
      WHERE id=ANY($1::text[]) ORDER BY id`, [[activeConversation.id, retiredConversation.id,
      siblingConversation.id]])).rows;
    assert.equal(states.find(row => row.id === activeConversation.id).binding_state, 'abandoned');
    assert.equal(states.find(row => row.id === retiredConversation.id).binding_state, 'abandoned');
    assert.equal(states.find(row => row.id === siblingConversation.id).binding_state, 'active');
    assert.equal((await agents.query(`SELECT count(*)::integer n
      FROM secureshop_agents.bound_persona_sessions WHERE original_platform_owner_id=$1
        AND revoked_at IS NULL`, [subject.user.id])).rows[0].n, 0);
    assert.equal((await agents.query(`SELECT count(*)::integer n
      FROM secureshop_agents.bound_persona_sessions WHERE original_platform_owner_id=$1
        AND revoked_at IS NULL`, [sibling.user.id])).rows[0].n, 1);
    assert.equal((await identity.query(`SELECT count(*)::integer n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='secureshop_agent_security'`, [subject.user.id])).rows[0].n, 0);
    assert.equal((await identity.query(`SELECT count(*)::integer n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='secureshop_agent_security'`, [sibling.user.id])).rows[0].n, 1);
    assert.deepEqual((await identity.query(`SELECT status FROM identity.secureshop_launches
      WHERE launch_id=ANY($1::uuid[]) ORDER BY launch_id`,
    [[subject.issued.binding.launchId, loggedOut.binding.launchId]])).rows.map(row => row.status),
    ['revoked', 'revoked']);
    assert.equal((await identity.query(`SELECT count(*)::integer n FROM identity.secureshop_target_reservations
      WHERE target_kind='files' AND original_platform_owner_id=$1`, [subject.user.id])).rows[0].n, 0);

    // The same aggregate also performs an owner-wide workshop reset without
    // deactivating the platform identity or its valid session.
    const untouched = await owner('aggregate-untouched');
    const untouchedTarget = await composition.runtime.application.resolveTarget(untouched.issued.binding);
    const untouchedConversation = await composition.runtime.conversations.create(untouched.issued.binding, persona);
    await addPersonaSession(untouched.issued.binding);
    await award(untouched, untouched.issued.binding, DEFAULT_OBJECTIVES[2]);
    const siblingLoggedOutSession = await identities.createSession({ userId: sibling.user.id,
      token: randomUUID(), expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const siblingLoggedOut = await launches.issueOrRenew({ platformOwnerId: sibling.user.id,
      platformSessionId: siblingLoggedOutSession.id, expiresAt: new Date(Date.now() + 3600000) });
    const siblingRacedSession = await identities.createSession({ userId: sibling.user.id,
      token: randomUUID(), expiresAt: new Date(Date.now() + 3600000), expectedPasswordHash: passwordHash });
    const siblingRaced = await launches.issueOrRenew({ platformOwnerId: sibling.user.id,
      platformSessionId: siblingRacedSession.id, expiresAt: new Date(Date.now() + 3600000) });
    const siblingRetiredConversation = await composition.runtime.conversations
      .create(siblingLoggedOut.binding, persona);
    await Promise.all([addPersonaSession(siblingLoggedOut.binding),addPersonaSession(siblingRaced.binding)]);
    await award(sibling, siblingLoggedOut.binding, DEFAULT_OBJECTIVES[1]);
    await identity.query(`UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),
      revoke_reason='ordinary_logout' WHERE id=$1`, [siblingLoggedOutSession.id]);
    let ownerEntered, ownerRelease;
    const ownerInside = new Promise(resolve => { ownerEntered = resolve; });
    const ownerHeld = new Promise(resolve => { ownerRelease = resolve; });
    const ownerRun = composition.runtime.turns.run(siblingConversation.id, siblingScope, persona,
      { idempotencyKey: 'held-owner-reset-turn' }, async execution => {
        ownerEntered();
        await new Promise(resolve => execution.signal.addEventListener('abort', resolve, { once: true }));
        await ownerHeld;
        await execution.check();
      });
    const ownerRunRejected = assert.rejects(ownerRun, { name: 'AbortError' });
    await ownerInside;
    const ownerRows = createSecureShopOwnerResetRepository(identity);
    const reservedOwnerReset = await ownerRows.begin({ ownerId: sibling.user.id });
    assert.equal(reservedOwnerReset.launches.length, 3);
    await identity.query(`UPDATE identity.user_sessions SET is_active=0,revoked_at=clock_timestamp(),
      revoke_reason='concurrent_logout' WHERE id=$1`, [siblingRacedSession.id]);
    const ownerReset = createSecureShopOwnerResetService({ repository: ownerRows,
      launchResetCoordinator: composition.launchResetCoordinator, launches });
    let ownerSettled = false;
    const ownerCleaning = ownerReset.resetOwner(sibling.user.id).finally(() => { ownerSettled = true; });
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(ownerSettled, false);
    ownerRelease(); await ownerRunRejected;
    assert.deepEqual(await ownerCleaning, { operationId: reservedOwnerReset.operationId,
      completed: true, launchCount: 3 });
    assert.deepEqual((await identity.query(`SELECT is_active FROM identity.users WHERE id=$1`,
      [sibling.user.id])).rows[0], { is_active: 1 });
    assert.deepEqual((await identity.query(`SELECT is_active FROM identity.user_sessions WHERE id=$1`,
      [sibling.session.id])).rows[0], { is_active: 1 });
    assert.deepEqual((await identity.query(`SELECT status,generation FROM identity.secureshop_launches
      WHERE launch_id=$1`, [sibling.issued.binding.launchId])).rows[0], { status: 'active', generation: '2' });
    assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launches
      WHERE launch_id=$1`, [siblingLoggedOut.binding.launchId])).rows[0].status, 'revoked');
    assert.equal((await identity.query(`SELECT status FROM identity.secureshop_launches
      WHERE launch_id=$1`, [siblingRaced.binding.launchId])).rows[0].status, 'revoked');
    assert.equal((await agents.query(`SELECT count(*)::integer n
      FROM secureshop_agents.bound_persona_sessions WHERE original_platform_owner_id=$1
        AND revoked_at IS NULL`, [sibling.user.id])).rows[0].n, 0);
    assert.equal((await reviews.query(`SELECT count(*)::integer n FROM secureshop_review.reviews
      WHERE target_id=$1`, [siblingTarget.targetId])).rows[0].n, 0);
    assert.equal((await identity.query(`SELECT count(*)::integer n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='secureshop_agent_security'`, [sibling.user.id])).rows[0].n, 0);
    const ownerStates = (await agents.query(`SELECT id,binding_state FROM secureshop_agents.agent_sessions
      WHERE id=ANY($1::text[])`, [[siblingConversation.id,siblingRetiredConversation.id]])).rows;
    assert.ok(ownerStates.every(row => row.binding_state === 'abandoned'));
    assert.equal((await reviews.query(`SELECT count(*)::integer n FROM secureshop_review.reviews
      WHERE target_id=$1`, [untouchedTarget.targetId])).rows[0].n, 1);
    assert.equal((await identity.query(`SELECT count(*)::integer n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='secureshop_agent_security'`, [untouched.user.id])).rows[0].n, 1);
    assert.equal((await agents.query(`SELECT binding_state FROM secureshop_agents.agent_sessions
      WHERE id=$1`, [untouchedConversation.id])).rows[0].binding_state, 'active');
    assert.equal((await agents.query(`SELECT count(*)::integer n
      FROM secureshop_agents.bound_persona_sessions WHERE original_platform_owner_id=$1
        AND revoked_at IS NULL`, [untouched.user.id])).rows[0].n, 1);
    t.diagnostic('Connected proof covers real review target, conversations, launch persona sessions, and instance progress; no filesystem target was provisioned, so file retirement remains separately qualified rather than inferred here. Revoked persona rows remain immutable audit history and are not proof of terminal identity deletion.');
  } finally {
    await Promise.allSettled([leases.end(), identity.end(), identityMigration.end(), agents.end(),
      agentsMigration.end(), reviews.end(), reviewMigration.end()]);
  }
});
