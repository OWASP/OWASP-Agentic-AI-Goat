'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initializeIdentityRepository, createIdentityRepository }
  = require('../../server/database/postgres/identityRepository');
const { createSecureShopLaunchRepository }
  = require('../../server/database/postgres/secureshopLaunchRepository');
const { createObjectiveJudgmentRepository }
  = require('../../server/database/postgres/objectiveJudgmentRepository');
const { createWorkshopProgressRepository }
  = require('../../server/database/postgres/workshopProgressRepository');
const { initializeSecureShopReviewDb }
  = require('../../server/database/postgres/secureshopReviewDb');
const { createSecureShopBoundReviewRepository }
  = require('../../server/database/postgres/secureshopBoundReviewRepository');
const { initializeSecureShopAgentsDb }
  = require('../../server/database/postgres/secureshopAgentsDb');
const { createBoundConversationsRepository }
  = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository }
  = require('../../server/database/postgres/secureshopTurnRequestsRepository');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createBoundTurns } = require('../../server/services/secureshopBoundTurns');
const { createSecureShopBoundReviewApplication }
  = require('../../server/services/secureshopBoundReviewApplication');
const { createSecureShopStoredBrowserAssessment }
  = require('../../server/services/secureshopStoredBrowserAssessment');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../../server/agent-runtime/providers/langchainProvider');
const { createXssBrowserQualification } = require('../../server/services/xssBrowserQualification');
const { loadSecureShopReviewCardRenderer }
  = require('../../server/services/secureshopReviewCardRenderer');
const { runSessionExclusive } = require('../../server/services/secureshop/sessionStore');

const PREFIX = 'PG_SECURESHOP_STORED_BROWSER_';
const URL_KEYS = ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'REVIEW_MIGRATION_URL',
  'REVIEW_RUNTIME_URL', 'AGENTS_MIGRATION_URL', 'AGENTS_RUNTIME_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && URL_KEYS.every(key => process.env[PREFIX + key]);
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVE = 'ss_stored_browser_execution';
const PAYLOAD = '<img src="invalid://owned-browser-proof" onerror="alert(\'owned-browser-proof\')">';

function checkedUrl(key) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
test('native launch-bound ReviewCard browser execution earns one actual-Judge completion and reset wins the race', {
  skip: !enabled, timeout: 180000,
}, async t => {
  const workspace = path.resolve(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-secureshop-stored-browser-/);
  const identityMigration = new Pool({ connectionString: checkedUrl('IDENTITY_MIGRATION_URL'), max: 2 });
  const identity = new Pool({ connectionString: checkedUrl('IDENTITY_RUNTIME_URL'), max: 10 });
  const leases = new Pool({ connectionString: checkedUrl('IDENTITY_RUNTIME_URL'), max: 4,
    application_name: 'secureshop-stored-browser-leases' });
  const reviewMigration = new Pool({ connectionString: checkedUrl('REVIEW_MIGRATION_URL'), max: 2 });
  const review = new Pool({ connectionString: checkedUrl('REVIEW_RUNTIME_URL'), max: 8 });
  const agentsMigration = new Pool({ connectionString: checkedUrl('AGENTS_MIGRATION_URL'), max: 2 });
  const agents = new Pool({ connectionString: checkedUrl('AGENTS_RUNTIME_URL'), max: 8 });
  const cleanupErrors = [];
  const browser = createXssBrowserQualification({ idleCloseMs: 1000 });
  try {
    await initializeIdentityRepository(identity, identityMigration);
    await initializeSecureShopReviewDb(review, reviewMigration);
    await initializeSecureShopAgentsDb({ runtimePool: agents, migrationPool: agentsMigration });
    await identityMigration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,challenge_description,ordinal,catalog_active,is_visible)
      VALUES($1,'secureshop-agent-security','SecureShop Agent Security',
        'Owned stored-browser qualification fixture',900,true,true)`, [WORKSHOP]);
    await identityMigration.query(`INSERT INTO workshop_platform.objectives
      (workshop_key,objective_id,label,category,ordinal,catalog_active,is_enabled)
      VALUES($1,$2,'Execute a stored review in ReviewCard','browser-sink',1,true,true)`,
    [WORKSHOP, OBJECTIVE]);

    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const receipts = createObjectiveJudgmentRepository(identity);
    const progress = createWorkshopProgressRepository(identity);
    const passwordHash = await bcrypt.hash('owned-browser-assessment', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    async function owner(label) {
      const user = await identities.createUser({ username: `${label}-${randomUUID().slice(0, 8)}`,
        email: `${randomUUID()}@browser.invalid`, passwordHash });
      const session = await identities.createSession({ userId: user.id, token: randomUUID(),
        expiresAt, expectedPasswordHash: passwordHash });
      const launch = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt });
      await identity.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
        VALUES($1,$2,'vuln')`, [user.id, WORKSHOP]);
      return { user, session, launch, scope: Object.freeze({ ...launch.binding,
        platformOwnerId: user.id, platformSessionId: session.id }) };
    }
    const awarded = await owner('browser-awarded');
    const resetRace = await owner('browser-reset');
    const sibling = await owner('browser-sibling');
    const cleanupOperations = new Set();
    const reviewRepository = createSecureShopBoundReviewRepository(review, {
      enableLearnerSubmissions: true, checkCurrent: value => launches.assertCurrent(value),
      checkRetirement: async () => { throw new Error('standalone retirement unavailable'); },
      checkCleanup: async input => {
        if (!cleanupOperations.has(input.operationId)) throw new Error('cleanup authority unavailable');
      },
    });
    const application = createSecureShopBoundReviewApplication({ launches,
      repository: reviewRepository, checkCurrent: value => launches.assertCurrent(value),
      validateProduct: async ({ productId }) => productId === 7, fixtures: [] });
    const conversationRows = createBoundConversationsRepository({ pool: agents,
      queue: runSessionExclusive });
    const conversations = createBoundConversationService({ conversations: conversationRows, launches });
    const journal = createTurnRequestsRepository({ pool: agents });
    const ledger = createPostgresRunLedger(identity, { leasePool: leases });
    const coordinator = createRunCoordinator({ family: `SecureShopStoredBrowser:${randomUUID()}`, ledger });
    const turns = createBoundTurns({ conversations, coordinator });
    const renderer = loadSecureShopReviewCardRenderer({ root: path.join(workspace,
      'client/build/secureshop-review-renderer') });
    const model = 'llama3.1:8b';
    const baseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    const nativeJudge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
      baseURL: baseUrl, model }) });
    let browserCalls = 0, judgeCalls = 0;
    const countedBrowser = { async qualify(...args) { browserCalls++;
      return browser.qualify(...args); } };
    const countedJudge = async packet => { judgeCalls++; return nativeJudge(packet); };
    const assessment = createSecureShopStoredBrowserAssessment({ conversations, turns, journal,
      application, reviewRepository, receipts, progress, judge: countedJudge,
      browserQualification: countedBrowser, renderReviewCard: renderer.renderReviewCard,
      componentSourceDigest: renderer.sourceSha256,
      componentArtifactDigest: renderer.artifactSha256 });
    const customer = Object.freeze({ id: 76, role: 'customer' });
    async function submit(subject, body = PAYLOAD) {
      return application.submitReview({ scope: subject.scope, persona: customer,
        submissionId: randomUUID(), productId: 7, authorId: 999, body, rating: 1 });
    }
    const stored = await submit(awarded);
    const requestId = randomUUID();
    const [first, concurrent] = await Promise.all([
      assessment.runAttempt({ scope: awarded.scope, persona: customer,
        requestId, productId: 7, reviewId: stored.id }),
      assessment.runAttempt({ scope: awarded.scope, persona: customer,
        requestId, productId: 7, reviewId: stored.id }),
    ]);
    assert.equal(first.completed, true); assert.equal(concurrent.completed, true);
    assert.deepEqual([first.replayed, concurrent.replayed].sort(), [false, true]);
    assert.equal(browserCalls, 1); assert.equal(judgeCalls, 1);
    const judgment = (await identity.query(`SELECT * FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND objective_id=$2`, [awarded.user.id, OBJECTIVE])).rows[0];
    assert.equal(judgment.verdict, 'pass'); assert.equal(judgment.result_json.provider, 'ollama');
    const contribution = (await identity.query(`SELECT * FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND objective_id=$2`, [awarded.user.id, OBJECTIVE])).rows[0];
    assert.equal(contribution.platform_launch_id, awarded.scope.launchId);
    const packet = JSON.parse((await identity.query(`SELECT packet FROM workshop_platform.grade_packets
      WHERE user_id=$1 AND evaluation_id=$2`, [awarded.user.id, contribution.evaluation_id])).rows[0].packet);
    const proof = packet.evidence.find(row => row.id === 'stored_browser_receipt').content;
    assert.equal(proof.component.id, 'SecureShop.ReviewCard');
    assert.equal(proof.component.sourceSha256, renderer.sourceSha256);
    assert.equal(proof.component.artifactSha256, renderer.artifactSha256);
    assert.equal(proof.source.reviewId, stored.id); assert.equal(proof.source.bodySha256,
      createHash('sha256').update(PAYLOAD).digest('hex'));
    assert.equal(proof.execution.effectReceipt.status, 'completed');
    assert.equal(proof.execution.effectReceipt.runId, judgment.run_id);
    assert.equal(proof.browser.targetEventExecuted, true);
    assert.equal(proof.browser.targetEffectObserved, true);
    assert.equal(Number((await identity.query(`SELECT count(*)::int AS count FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`,
    [awarded.user.id, WORKSHOP, OBJECTIVE])).rows[0].count), 1);

    const raceSubmission = await submit(resetRace);
    let observedResolve, releaseBrowser;
    const observed = new Promise(resolve => { observedResolve = resolve; });
    const held = new Promise(resolve => { releaseBrowser = resolve; });
    const raceBrowser = { async qualify(...args) {
      const result = await browser.qualify(...args); observedResolve(); await held; return result;
    } };
    const raceAssessment = createSecureShopStoredBrowserAssessment({ conversations, turns, journal,
      application, reviewRepository, receipts, progress, judge: countedJudge,
      browserQualification: raceBrowser, renderReviewCard: renderer.renderReviewCard,
      componentSourceDigest: renderer.sourceSha256,
      componentArtifactDigest: renderer.artifactSha256 });
    const pending = raceAssessment.runAttempt({ scope: resetRace.scope, persona: customer,
      requestId: randomUUID(), productId: 7, reviewId: raceSubmission.id });
    await observed;
    const raceTarget = await application.resolveTarget(resetRace.scope);
    const resetId = randomUUID(); cleanupOperations.add(resetId);
    const cleanup = await reviewRepository.cleanup(raceTarget, { operationId: resetId });
    assert.equal(cleanup.deletedReviewCount, 1);
    releaseBrowser();
    await assert.rejects(pending, error => ['REVIEW_TARGET_UNAVAILABLE', 'CONVERSATION_UNAVAILABLE']
      .includes(error?.code));
    assert.equal(Number((await identity.query(`SELECT count(*)::int AS count FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`,
    [resetRace.user.id, WORKSHOP, OBJECTIVE])).rows[0].count), 0);
    assert.equal(Number((await identity.query(`SELECT count(*)::int AS count FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND objective_id=$2`, [resetRace.user.id, OBJECTIVE])).rows[0].count), 0);

    const siblingSubmission = await submit(sibling, 'Ordinary owner-isolated feedback.');
    const siblingTarget = await application.resolveTarget(sibling.scope);
    assert.equal((await reviewRepository.readSubmission(siblingTarget, siblingSubmission.id)).body,
      'Ordinary owner-isolated feedback.');
    assert.equal(Number((await identity.query(`SELECT count(*)::int AS count FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2`, [sibling.user.id, WORKSHOP])).rows[0].count), 0);
    t.diagnostic(JSON.stringify({ scope: 'actual ReviewCard component render, isolated Chromium, actual local 8B Judge, owned native PostgreSQL identity/review/agents',
      positive: { verdict: judgment.verdict, provider: judgment.result_json.provider,
        effectKey: proof.execution.effectReceipt.effectKey, browserCalls, judgeCalls },
      resetRace: { deletedReviews: cleanup.deletedReviewCount, completionCount: 0 },
      limitation: 'component-level build artifact qualification; full parent/iframe rendering is not claimed' }));
  } finally {
    for (const close of [() => browser.close(), () => agents.end(), () => agentsMigration.end(),
      () => review.end(), () => reviewMigration.end(), () => leases.end(),
      () => identity.end(), () => identityMigration.end()]) {
      try { await close(); } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
      'SecureShop stored browser qualification cleanup failed');
  }
});
