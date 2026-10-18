'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const STORES = ['IDENTITY', 'FRESH', 'REVIEW', 'COMMERCE'];
const WORKSHOP = 'secureshop_agent_security';
const enabled = process.env.PERSONA_ASSEMBLED_CORE_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORES.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`PERSONA_${store}_${role}_URL`]));

function checked(store, role) {
  const value = new URL(process.env[`PERSONA_${store}_${role}_URL`]);
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname,
    /^\/dvaia_test_persona_[a-f0-9]+_(commerce|fresh|review|identity|identityfresh)$/);
  return value.href;
}

test('assembled BoundReview writes controlled failures through one startup-owned grading core', {
  skip: !enabled,
  timeout: 180000,
}, async t => {
  const workspace = fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || '');
  assert.equal(fs.realpathSync(process.cwd()), workspace);
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const pool = new Pool({ connectionString: checked(store, role), max: role === 'RUNTIME' ? 5 : 2,
      statement_timeout: 10000, application_name: `assembled-core-${store.toLowerCase()}-${role.toLowerCase()}` });
    return [`${store}_${role}`, pool];
  })));
  const leasePool = new Pool({ connectionString: checked('IDENTITY', 'RUNTIME'), max: 3,
    statement_timeout: 10000, application_name: 'assembled-core-leases' });
  t.after(async () => {
    const settled = await Promise.allSettled([...Object.values(pools), leasePool].map(pool => pool.end()));
    const failures = settled.filter(row => row.status === 'rejected').map(row => row.reason);
    if (failures.length) throw new AggregateError(failures, 'assembled-core pool shutdown failed');
  });

  const { migrate } = require('../../db/postgres/migrate');
  await migrate(pools.IDENTITY_MIGRATION, path.join(workspace, 'db/postgres/identity-migrations'));
  await migrate(pools.FRESH_MIGRATION,
    path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents'));
  await migrate(pools.REVIEW_MIGRATION,
    path.join(workspace, 'db/postgres/workshop-migrations/secureshop_review'));
  await migrate(pools.COMMERCE_MIGRATION,
    path.join(workspace, 'db/postgres/workshop-migrations/secureshop'));
  await require('../../server/database/postgres/workshopPlatformSeed')
    .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  const seedClient = await pools.COMMERCE_MIGRATION.connect();
  await seedClient.query('BEGIN');
  try {
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seedClient);
    await seedClient.query('COMMIT');
  } catch (error) {
    await seedClient.query('ROLLBACK');
    throw error;
  } finally { seedClient.release(); }

  const { DEFAULT_OBJECTIVES, createSecureShopBoundReviewComposition }
    = require('../../server/services/secureshopBoundReviewComposition');
  const RUN_OBJECTIVES = ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed'];
  const INBOX_OBJECTIVES = Object.values(
    require('../../server/services/secureshopPersonaInboxAssessment').OBJECTIVES);
  await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.exercises
    SET catalog_active=true,is_visible=true WHERE workshop_key=$1`, [WORKSHOP]);
  await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives
    SET catalog_active=true,is_enabled=true
    WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`,
  [WORKSHOP, [...DEFAULT_OBJECTIVES, ...INBOX_OBJECTIVES]]);
  assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*) AS n
    FROM workshop_platform.objectives WHERE workshop_key=$1
      AND objective_id=ANY($2::text[]) AND catalog_active AND is_enabled`,
  [WORKSHOP, DEFAULT_OBJECTIVES])).rows[0].n), DEFAULT_OBJECTIVES.length);

  const progress = require('../../server/database/postgres/workshopProgressRepository')
    .createWorkshopProgressRepository(pools.IDENTITY_RUNTIME);
  const resetComposition = require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
    identityPool:pools.IDENTITY_RUNTIME, agentsPool:pools.FRESH_RUNTIME, reviewPool:pools.REVIEW_RUNTIME, leasePool });
  const gradingBootstrap = await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
    identityPool:pools.IDENTITY_RUNTIME, agentsPool:pools.FRESH_RUNTIME, progress, resetComposition,
    expectedIdentityDatabase:new URL(checked('IDENTITY','RUNTIME')).pathname.slice(1),
    expectedAgentsDatabase:new URL(checked('FRESH','RUNTIME')).pathname.slice(1) });
  const gradingCore = gradingBootstrap.gradingCore;
  let judgeCalls = 0;
  const judge = async packet => {
    judgeCalls += 1;
    const prepared = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet);
    return Object.freeze({ family: packet.rubric.family, scenario: packet.rubric.scenario,
      objectiveId: packet.rubric.objectiveId, rubricVersion: packet.rubric.version,
      evidenceDigest: prepared.evidenceDigest, runId: packet.execution.runId,
      mode: packet.rubric.mode, verdict: 'fail', criteria: [],
      explanation: 'Controlled assembly fixture: no actual model or qualifying effect.',
      provider: 'fixture', model: 'controlled-fail', usage: null });
  };
  const provider = Object.freeze({
    async chat() { return Object.freeze({ stop_reason: 'end_turn', text: 'No pending work.',
      provider: 'fixture', model: 'controlled-no-model', mocked: true }); },
    async finalResponse() { return Object.freeze({ stop_reason: 'end_turn', text: 'No pending work.',
      provider: 'fixture', model: 'controlled-no-model', mocked: true }); },
  });
  const composition = createSecureShopBoundReviewComposition({
    identityPool: pools.IDENTITY_RUNTIME, agentsPool: pools.FRESH_RUNTIME,
    reviewPool: pools.REVIEW_RUNTIME, commercePool: pools.COMMERCE_RUNTIME, leasePool,
    gradingBootstrap, resetComposition, agentRuntime: Object.freeze({ provider }), judge,
    jwtSecret: 'owned-assembled-core-secret-at-least-32-bytes',
    personaInboxFeature: true,
    reviewCardRenderer: Object.freeze({ sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      async renderReviewCard(review) { return `<article>${review.body}</article>`; } }),
    browserQualification: Object.freeze({ async qualify() { throw new Error('browser not in scope'); },
      async close() {} }),
  });
  t.after(() => composition.closeBrowserAssessment());
  await composition.repositories.personas.ensureTemplates();
  assert.equal(composition.personaInbox.ready, true);
  assert.equal(composition.mcpTrust.ready, false);
  assert.equal(composition.ssrf.ready, false);

  const identities = require('../../server/database/postgres/identityRepository')
    .createIdentityRepository(pools.IDENTITY_RUNTIME);
  const passwordHash = await bcrypt.hash('assembled-core-owned', 4);
  const user = await identities.createUser({ username: `assembled-${randomUUID().slice(0, 8)}`,
    email: `${randomUUID()}@assembled.invalid`, passwordHash });
  const expiresAt = new Date(Date.now() + 600000).toISOString();
  const session = await identities.createSession({ userId: user.id, token: randomUUID(), expiresAt,
    expectedPasswordHash: passwordHash });
  const issued = await composition.launches.issueOrRenew({ platformOwnerId: user.id,
    platformSessionId: session.id, expiresAt });
  const scope = require('../../server/services/secureshopConversationBinding')
    .createLaunchScope(issued.binding);
  const login = await composition.personaAuth.login({ scope, username: 'student_merchant',
    password: 'student123' });
  const verified = await composition.personaAuth.authenticateBoundToken({ scope, token: login.token });
  const result = await composition.runtime.moderation.moderateReviews({ scope,
    persona: login.user, personaSession: { sessionId: verified.sessionId,
      authorityVersion: verified.authorityVersion }, requestId: randomUUID(), limit: 1 });
  assert.equal(result.replayed, false);

  const judgments = await gradingCore.listJudgments(user.id);
  assert.deepEqual(judgments.map(row => row.objectiveId).sort(), RUN_OBJECTIVES.slice().sort());
  assert.equal(judgeCalls, RUN_OBJECTIVES.length);
  const runIds = [...new Set(judgments.map(row => row.runId))];
  assert.equal(runIds.length, 1);
  assert.match(runIds[0], /^[0-9a-f-]{36}$/i);
  for (const row of judgments) {
    assert.equal(row.runId, runIds[0]);
    assert.equal(row.verdict, 'fail');
    assert.equal(row.disposition, 'not_pass');
    const receipt = await gradingCore.receipts.getEvaluation({ userId: user.id,
      evaluationId: row.evaluationId });
    assert.equal(receipt.result.provider, 'fixture');
    assert.equal(receipt.result.model, 'controlled-fail');
  }
  assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*) AS n
    FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2`,
  [user.id, WORKSHOP])).rows[0].n), 0);
  assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*) AS n
    FROM workshop_platform.objective_contributions WHERE user_id=$1`, [user.id])).rows[0].n), 0);

  const inboxStatus = await composition.personaInbox.application.status({ scope,
    persona: login.user, personaSession: { sessionId: verified.sessionId,
      authorityVersion: verified.authorityVersion } });
  assert.equal(inboxStatus.ready, true);
  const ownedMessage = inboxStatus.messages.find(row => row.ownerShopRole === login.user.role);
  assert.ok(Number.isSafeInteger(ownedMessage?.messageId));
  const inboxResult = await composition.personaInbox.application.run({ scope,
    persona: login.user, personaSession: { sessionId: verified.sessionId,
      authorityVersion: verified.authorityVersion }, requestId: randomUUID(),
    messageId: ownedMessage.messageId });
  assert.equal(inboxResult.replayed, false);
  const assembledJudgments = await gradingCore.listJudgments(user.id);
  assert.deepEqual(assembledJudgments.map(row => row.objectiveId).sort(),
    [...RUN_OBJECTIVES, ...INBOX_OBJECTIVES].sort());
  assert.equal(judgeCalls, RUN_OBJECTIVES.length + INBOX_OBJECTIVES.length);
  const required = await pools.IDENTITY_RUNTIME.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments WHERE user_id=$1 AND persona_authority_required=true',[user.id]);
  assert.equal(required.rows[0].n,6);
  const bound = await pools.IDENTITY_RUNTIME.query('SELECT DISTINCT persona_session_id,authority_version::text FROM workshop_platform.persona_evaluation_bindings WHERE user_id=$1',[user.id]);
  assert.deepEqual(bound.rows,[{persona_session_id:verified.sessionId,authority_version:verified.authorityVersion}]);
  const inboxRows = assembledJudgments.filter(row => INBOX_OBJECTIVES.includes(row.objectiveId));
  assert.equal(new Set(inboxRows.map(row => row.runId)).size, 1);
  assert.ok(inboxRows.every(row => row.verdict === 'fail' && row.disposition === 'not_pass'));
  assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*) AS n
    FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2`,
  [user.id, WORKSHOP])).rows[0].n), 0);
  assert.equal(Number((await pools.IDENTITY_RUNTIME.query(`SELECT count(*) AS n
    FROM workshop_platform.objective_contributions WHERE user_id=$1`, [user.id])).rows[0].n), 0);
  t.diagnostic(JSON.stringify({ checkpoint: 'assembled-shared-grading-core',
    enabledPath: 'bound-review-moderation', runId: runIds[0],
    judgments: judgments.map(row => ({ objectiveId: row.objectiveId, verdict: row.verdict,
      disposition: row.disposition })),
    optionalPath: 'persona-inbox-controlled-no-tool', inboxRunId: inboxRows[0].runId,
    judgeCalls, completions: 0, contributions: 0,
    limitations: ['controlled provider', 'controlled Judge', 'prepared persona bootstrap enabled',
      'inbox run has no qualifying access effect', 'optional MCP/SSRF disabled',
      'no installed-state claim'] }));
});
