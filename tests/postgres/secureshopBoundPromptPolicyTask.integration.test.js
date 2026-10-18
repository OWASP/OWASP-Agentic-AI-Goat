'use strict';

// Native-only task-policy qualification. The launcher supplies four fresh
// stores and PERSONA_* URLs; this suite never uses an installed database.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');

const enabled = process.env.PERSONA_PROMPT_POLICY_TASK_NATIVE === '1';
test('owned prompt-policy v2 task targets use real persona sessions and controlled receipts', {
  skip: !enabled,
  timeout: 240000
}, async t => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
  const pools = [];
  const pool = (store, role) => {
    const url = new URL(process.env[`PERSONA_${store}_${role}_URL`]);
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/dvaia_test_persona_[a-f0-9]+_(identity|fresh|commerce)$/);
    const value = new Pool({ connectionString: url.href, max: 2, statement_timeout: 8000 });
    pools.push(value); return value;
  };
  t.after(async () => { await Promise.all(pools.map(value => value.end())); });
  const identity = pool('IDENTITY', 'RUNTIME');
  const identityMigration = pool('IDENTITY', 'MIGRATION');
  const agents = pool('FRESH', 'RUNTIME');
  const agentsMigration = pool('FRESH', 'MIGRATION');
  const commerce = pool('COMMERCE', 'RUNTIME');
  const commerceMigration = pool('COMMERCE', 'MIGRATION');
  const { migrate } = require('../../db/postgres/migrate');
  const migrationDir = 'db/postgres/workshop-migrations/secureshop_agents';
  const identityDir = 'db/postgres/identity-migrations';
  const canonicalPolicyMigration = path.join(migrationDir, '0027_bound_prompt_policies.sql');
  const candidatePolicyMigration = 'docs/modernization/drafts/secureshop-bound-prompt-policies/0027_bound_prompt_policies.candidate.sql';
  assert.deepEqual(fs.readFileSync(canonicalPolicyMigration), fs.readFileSync(candidatePolicyMigration));
  await migrate(identityMigration, identityDir);
  await migrate(commerceMigration, 'db/postgres/workshop-migrations/secureshop');
  await require('../../server/database/postgres/secureshopSeed').seedSecureShop(commerceMigration);
  await migrate(agentsMigration, migrationDir);
  assert.deepEqual(await migrate(agentsMigration, migrationDir), []);

  const users = require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  const launches = require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
  const authority = require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({
    pool: agents, checkCurrent: scope => launches.assertCurrent(scope)
  });
  const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({
    commercePool: commerce, agentsPool: agents, personaAuthority: authority,
    auditStore: require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({ store: 'agents', pool: agents })
  });
  await personas.ensureTemplates();
  const auth = require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({
    repository: personas, personaAuthority: authority, launches,
    jwtSecret: 'task-policy-native-fixture-secret-at-least-32-bytes'
  });
  async function owner() {
    const token = randomUUID(), passwordHash = await require('bcryptjs').hash('owned-only', 4);
    const user = await users.createUser({ username: `task-${token.slice(0, 8)}`, email: `${token}@example.invalid`, passwordHash });
    const expiresAt = new Date(Date.now() + 600000).toISOString();
    const session = await users.createSession({ userId: user.id, token, expiresAt, expectedPasswordHash: passwordHash });
    const issued = await launches.issueOrRenew({ platformOwnerId: user.id, platformSessionId: session.id, expiresAt });
    const scope = require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
    return { scope, ownerId: user.id };
  }
  const ownerBinding = await owner();
  const login = await auth.login({ scope: ownerBinding.scope, username: 'student_admin', password: 'student123' });
  const verified = await auth.authenticateBoundToken({ scope: ownerBinding.scope, token: login.token });
  const context = {
    scope: ownerBinding.scope,
    persona: login.user,
    personaSession: { sessionId: verified.sessionId, authorityVersion: verified.authorityVersion }
  };
  const audit = require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({ store: 'agents', pool: agents });
  const checkRunBinding = require('../../server/services/secureshopPromptPolicyRunBinding').createPromptPolicyRunBinding({ identityPool: identity });
  const repository = require('../../server/database/postgres/secureshopBoundPromptPolicyRepository').createBoundPromptPolicyRepository({ pool: agents, personaAuthority: authority, audit, checkRunBinding });
  const conversations = require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({ pool: agents, queue: async (_id, work) => work() });
  const ledger = require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity, { leasePool: identity });
  const coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family: 'SecureShopBoundConversation', ledger });
  const binding = require('../../server/services/secureshopConversationBinding');
  async function liveRun(actor, work) {
    const conversationBinding = binding.createConversationBinding(actor.scope, actor.persona);
    const acquired = await conversations.acquireBoundSession({ id: randomUUID(), binding: conversationBinding });
    if (acquired.state !== 'active') assert.equal(await conversations.activateBoundSession(acquired.id, conversationBinding), true);
    return coordinator.run(acquired.id, {}, execution => work(execution.runId));
  }
  const contract = require('../../server/services/secureshopPromptPolicyContract');
  const task = require('../../server/services/secureshopPromptPolicyTaskMutation');
  const request = { contractVersion: 2, operationId: randomUUID(), name: 'task-policy', markdown: 'CONTROLLED TASK POLICY', targets: ['summarizer', 'review-moderator'] };
  const adminInput = { ...context, action: 'upsert', expectedVersion: '1', request };
  assert.equal((await repository.beginRender(adminInput)).state, 'admitted');
  const projection = task.renderRequest(request);
  const renderResult = {
    version: 1, operationId: projection.operationId, requestSha256: contract.requestDigest(projection),
    isolation: contract.ISOLATION, rendered: request.markdown,
    renderedSha256: createHash('sha256').update(request.markdown).digest('hex'),
    exitCode: 0, timedOut: false, truncated: false, drained: true
  };
  const receipt = await repository.publish({ ...adminInput, renderResult });
  assert.equal(receipt.policyRequestSha256, task.taskMutationDigest(request));
  const mixedRequest = { contractVersion: 2, operationId: randomUUID(), name: 'mixed-role-task-policy', markdown: 'CONTROLLED MIXED POLICY', targets: ['customer', 'summarizer'] };
  const mixedInput = { ...context, action: 'upsert', expectedVersion: '2', request: mixedRequest };
  await repository.beginRender(mixedInput);
  const mixedProjection = task.renderRequest(mixedRequest);
  await repository.publish({ ...mixedInput, renderResult: {
    ...renderResult, operationId: mixedRequest.operationId, requestSha256: contract.requestDigest(mixedProjection),
    rendered: mixedRequest.markdown, renderedSha256: createHash('sha256').update(mixedRequest.markdown).digest('hex')
  }});

  // A second owner is populated before the first owner is retired. Its role-
  // wide v1 row is the sibling-preservation witness for cleanup.
  const siblingOwner = await owner();
  const siblingLogin = await auth.login({ scope: siblingOwner.scope, username: 'student_admin', password: 'student123' });
  const siblingSession = await auth.authenticateBoundToken({ scope: siblingOwner.scope, token: siblingLogin.token });
  const siblingContext = {
    scope: siblingOwner.scope, persona: siblingLogin.user,
    personaSession: { sessionId: siblingSession.sessionId, authorityVersion: siblingSession.authorityVersion }
  };
  const siblingRequest = { operationId: randomUUID(), name: 'sibling-role-policy', markdown: 'SIBLING_ROLE_POLICY', targets: ['customer'] };
  const siblingInput = { ...siblingContext, action: 'upsert', expectedVersion: '1', request: siblingRequest };
  await repository.beginRender(siblingInput);
  await repository.publish({ ...siblingInput, renderResult: {
    ...renderResult, operationId: siblingRequest.operationId,
    requestSha256: contract.requestDigest(siblingRequest), rendered: siblingRequest.markdown,
    renderedSha256: createHash('sha256').update(siblingRequest.markdown).digest('hex')
  }});
  const siblingBeforeCleanup = await repository.list(siblingContext);
  assert.equal(siblingBeforeCleanup.policies.length, 1);

  const customerLogin = await auth.login({ scope: ownerBinding.scope, username: 'student_customer', password: 'student123' });
  const customer = await auth.authenticateBoundToken({ scope: ownerBinding.scope, token: customerLogin.token });
  const customerContext = { ...context, persona: customerLogin.user, personaSession: { sessionId: customer.sessionId, authorityVersion: customer.authorityVersion } };
  let runId;
  let summary;
  await liveRun(customerContext, async currentRunId => {
    runId = currentRunId;
    summary = await repository.admitRunSnapshot({ ...customerContext, runId, policyContractVersion: 2, recipient: 'summarizer' });
    assert.ok(summary.policies.some(row => row.rendered === request.markdown));
    await assert.rejects(repository.admitRunSnapshot({ ...customerContext, runId, policyContractVersion: 2, recipient: null }), { code: 'OPERATION_CONFLICT' });
    const restartedRepository = require('../../server/database/postgres/secureshopBoundPromptPolicyRepository').createBoundPromptPolicyRepository({ pool: agents, personaAuthority: authority, audit, checkRunBinding });
    assert.equal((await restartedRepository.admitRunSnapshot({ ...customerContext, runId, policyContractVersion: 2, recipient: 'summarizer' })).sha256, summary.sha256);
  });
  await liveRun(customerContext, async siblingRunId => {
    const sibling = await repository.admitRunSnapshot({ ...customerContext, runId: siblingRunId, policyContractVersion: 2, recipient: null });
    assert.equal(sibling.policies.length, 1);
    assert.equal(sibling.policies[0].rendered, mixedRequest.markdown);
  });
  await liveRun(customerContext, async legacyRunId => {
    const legacy = await repository.admitRunSnapshot({ ...customerContext, runId: legacyRunId });
    assert.equal(legacy.policies.length, 1);
    assert.equal(legacy.policies[0].rendered, mixedRequest.markdown);
  });
  const merchantLogin = await auth.login({ scope: ownerBinding.scope, username: 'student_merchant', password: 'student123' });
  const merchant = await auth.authenticateBoundToken({ scope: ownerBinding.scope, token: merchantLogin.token });
  const merchantContext = { ...context, persona: merchantLogin.user, personaSession: { sessionId: merchant.sessionId, authorityVersion: merchant.authorityVersion } };
  await liveRun(merchantContext, async merchantRunId => {
    const review = await repository.admitRunSnapshot({ ...merchantContext, runId: merchantRunId, policyContractVersion: 2, recipient: 'review-moderator' });
    assert.ok(review.policies.some(row => row.rendered === request.markdown));
  });
  await liveRun(merchantContext, async merchantSiblingRunId => {
    const merchantSibling = await repository.admitRunSnapshot({ ...merchantContext, runId: merchantSiblingRunId, policyContractVersion: 2, recipient: null });
    assert.equal(merchantSibling.policies.length, 0);
  });
  await personas.revokeOwnedSession({ scope: ownerBinding.scope, shopUserId: customerLogin.user.id, sessionId: customer.sessionId });
  await liveRun({ ...customerContext, personaSession: { sessionId: customer.sessionId, authorityVersion: customer.authorityVersion } }, async revokedRunId => {
    await assert.rejects(repository.admitRunSnapshot({ ...customerContext, runId: revokedRunId, policyContractVersion: 2, recipient: 'summarizer' }), { code: 'SHOP_AUTH_INVALID' });
  });
  await agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), ownerBinding.scope.launchId, ownerBinding.scope.scenarioId, ownerBinding.scope.generation, ownerBinding.scope.platformOwnerId, ownerBinding.scope.platformSessionId]);
  const redacted = (await agents.query('SELECT payload_json FROM secureshop_agents.bound_prompt_policy_snapshots WHERE run_id=$1', [runId])).rows[0];
  assert.equal(redacted.payload_json, null);
  await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)', [ownerBinding.scope.platformOwnerId, randomUUID()]);
  assert.deepEqual(await repository.list(siblingContext), siblingBeforeCleanup);
});
