'use strict';

// Disposable native qualification for 0090/0091.  It is deliberately skipped
// unless the coordinator supplies the private MAIL_* cohort URLs.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createAgentsMigrationView } = require('../helpers/secureshopAgentsMigrationView');

const PREFIX = 'MAIL_';
const required = ['IDENTITY_RUNTIME_URL','IDENTITY_MIGRATION_URL','AGENTS_RUNTIME_URL',
  'AGENTS_MIGRATION_URL','COMMERCE_RUNTIME_URL','COMMERCE_MIGRATION_URL',
  'FRESH_RUNTIME_URL','FRESH_MIGRATION_URL'];
const enabled = process.env.MAIL_NATIVE === '1' && required.every(key => process.env[PREFIX + key]);
const copyMailBinding = (binding, changes) => require('../../server/services/secureshopMailSceneBinding').copy(binding, { ...binding, ...changes });
const ROOT = require('node:path').resolve(__dirname, '../..');
const AGENTS_DIR = require('node:path').join(ROOT, 'db/postgres/workshop-migrations/secureshop_agents');
function phase(label) {
  console.info(`[mail-native] ${label}`);
}

function pool(key) {
  const url = new URL(process.env[PREFIX + key + '_URL']);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  const family = { IDENTITY: 'identity', AGENTS: 'secureshop_agents',
    COMMERCE: 'secureshop', FRESH: 'secureshop_conversation' }[key.split('_')[0]];
  assert.ok(family, `unsupported mail cohort database key: ${key}`);
  assert.match(url.pathname, new RegExp(`^/dvaia_test_agent_host_[0-9a-f]{12}_${family}$`));
  const result = new Pool({ connectionString: url.href, max: 8, connectionTimeoutMillis: 10000, statement_timeout: 10000 });
  result.__cohortDatabaseName = url.pathname;
  return result;
}
function scopeFrom(binding) { return require('../../server/services/secureshopConversationBinding').createLaunchScope(binding); }
const sha256 = value => createHash('sha256').update(value).digest('hex');

async function attachMailScene(agents, binding) {
  const sceneId = randomUUID(), grantId = randomUUID(), sceneGeneration = 1;
  const s = binding.scope;
  await agents.query(`INSERT INTO secureshop_agents.mail_scene_targets
    (scene_id,scene_generation,target_id,original_platform_owner_id,birth_launch_id,birth_scenario_id,birth_generation,birth_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
  [sceneId, sceneGeneration, binding.targetId, s.platformOwnerId, s.launchId, s.scenarioId, s.generation, s.platformSessionId]);
  await agents.query(`INSERT INTO secureshop_agents.mail_scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
  [grantId, sceneId, sceneGeneration, binding.targetId, s.launchId, s.scenarioId, s.generation, s.platformOwnerId, s.platformSessionId]);
  const sceneBinding = require('../../server/services/secureshopSceneBinding').createSceneBinding(
    { ...s, targetId: binding.targetId }, { sceneId, sceneGeneration, grantId, execution: s,
      withLease: async work => work() });
  // mailScene.attach consumes the flat launch birth record. Re-wrap the
  // resulting trusted scene capability with the persona/operation DTO only
  // after the scene brand has been established.
  const born = require('../../server/services/secureshopMailSceneBinding').attach(
    { ...s, targetId: binding.targetId }, sceneBinding);
  return require('../../server/services/secureshopMailSceneBinding').copy(born, { ...binding });
}

async function createOwner({ identity, launches, auth, bundle, fixtures, templates, label }) {
  const key = randomUUID();
  const passwordHash = await bcrypt.hash('owned-only', 4);
  const user = await require('../../server/database/postgres/identityRepository').createIdentityRepository(identity)
    .createUser({ username: `${label}-${key.slice(0, 8)}`, email: `${key}@example.invalid`, passwordHash });
  const session = await require('../../server/database/postgres/identityRepository').createIdentityRepository(identity)
    .createSession({ userId: user.id, token: randomUUID(), expiresAt: new Date(Date.now() + 600000).toISOString(), expectedPasswordHash: passwordHash });
  const issued = await launches.issueOrRenew({ platformOwnerId: user.id, platformSessionId: session.id, expiresAt: new Date(Date.now() + 600000).toISOString() });
  const scope = scopeFrom(issued.binding);
  const login = await auth.login({ scope, username: 'student_merchant', password: 'student123' });
  const verified = await auth.authenticateBoundToken({ scope, token: login.token });
  const target = await launches.reservePersonaInboxTarget({ ...scope, expectedGeneration: scope.generation });
  await bundle.repository.provision({ ...scope, targetId: target.targetId }, { fixtures, mode: 'advisory' });
  const merchant = templates.find(row => row.role === 'merchant');
  return { scope, targetId: target.targetId, persona: { id: merchant.id, role: 'merchant' },
    personaSession: { sessionId: verified.sessionId, authorityVersion: verified.authorityVersion },
    mode: 'vuln', operationId: randomUUID() };
}

async function setupAgents({ agents, commerce, identity, identityMigration, commerceMigration, agentsMigration,
  agentsDirectory = AGENTS_DIR, agentsMigrate = migrate }) {
  await migrate(identityMigration, 'db/postgres/identity-migrations');
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
  await migrate(commerceMigration, 'db/postgres/workshop-migrations/secureshop');
  await require('../../server/database/postgres/secureshopSeed').seedSecureShop(commerceMigration);
  await agentsMigrate(agentsMigration, agentsDirectory);
  const launches = require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
  const checkCurrent = scope => launches.assertCurrent(scope);
  const authority = require('../../server/database/postgres/secureshopBoundPersonaAuthority')
    .createSecureShopBoundPersonaAuthority({ pool: agents, checkCurrent });
  const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository')
    .createSecureShopBoundPersonaRepository({ commercePool: commerce, agentsPool: agents, personaAuthority: authority,
      auditStore: require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({ store: 'agents', pool: agents }) });
  await personas.ensureTemplates();
  const templates = await personas.listPersonas();
  const auth = require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({
    repository: personas, personaAuthority: authority, launches, jwtSecret: randomBytes(32).toString('hex') });
  const cleanupAuthority = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository')
    .createSecureShopResetCleanupAuthorityRepository(identity);
  const bundle = require('../../server/services/secureshopPersonaInboxComposition')
    .createSecureShopPersonaInboxRepositoryBundle({ agentsPool: agents, launches, cleanupAuthority });
  const fixtures = require('../../server/services/secureshopPersonaInboxComposition').mapPersonaInboxFixtures(templates);
  return { launches, authority, templates, auth, bundle, fixtures, checkCurrent };
}

const native = test('0090/0091 disposable PostgreSQL qualification: fresh, populated, replay, reset, sibling and grants', {
  skip: !enabled, timeout: 180000,
}, async t => {
  phase('cohort pools: creating');
  const identity = pool('IDENTITY_RUNTIME'), identityMigration = pool('IDENTITY_MIGRATION');
  const agents = pool('AGENTS_RUNTIME'), agentsMigration = pool('AGENTS_MIGRATION');
  const commerce = pool('COMMERCE_RUNTIME'), commerceMigration = pool('COMMERCE_MIGRATION');
  const fresh = pool('FRESH_RUNTIME'), freshMigration = pool('FRESH_MIGRATION');
  const databaseNames = [identity, identityMigration, agents, agentsMigration, commerce,
    commerceMigration, fresh, freshMigration].map(value => value.__cohortDatabaseName);
  assert.equal(new Set(databaseNames).size, 4, 'cohort must use four distinct disposable databases');
  t.after(async () => {
    phase('cleanup: closing cohort pools');
    const results = await Promise.allSettled([identity, identityMigration, agents, agentsMigration,
      commerce, commerceMigration, fresh, freshMigration].map(value => value.end()));
    assert.ok(results.every(result => result.status === 'fulfilled'), 'all native cohort pools must close');
    phase('cleanup: cohort pools closed');
  });

  phase('fresh: read migration ledger');
  const full = await readMigrations(AGENTS_DIR);
  // The fresh cohort also models a store which already recorded the original
  // 0091 checksum before the 0093 repair existed.  Keep a valid non-IDOR row
  // while executing the immutable 0091 SQL, then let the real loader apply
  // 0092/0093 and prove the repaired purpose can be admitted afterward.
  const through90 = createAgentsMigrationView(90);
  phase('fresh: migrate through 0090');
  assert.deepEqual(await through90.migrate(freshMigration, through90.directory),
    full.filter(row => Number(row.name.slice(0, 4)) <= 90).map(row => row.name));
  const historicalMailSession = randomUUID();
  await freshMigration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,
     user_id,role,conversation_purpose)
    VALUES ($1,'launch_bound','pending',$2,$3,1,1,1,1,'customer','secureshop_mail_reply')`,
  [historicalMailSession, randomUUID(), randomUUID()]);
  const historical0091 = full.find(row => row.name === '0091_mail_summary_conversation_purpose.sql');
  const historicalClient = await freshMigration.connect();
  try {
    phase('fresh: execute historical 0091 transaction');
    await historicalClient.query('BEGIN');
    await historicalClient.query('SELECT pg_advisory_xact_lock(1886610804, 1)');
    await historicalClient.query(historical0091.sql);
    await historicalClient.query('INSERT INTO dvaia_migrations.ledger (name,checksum) VALUES ($1,$2)',
      [historical0091.name, historical0091.checksum]);
    await historicalClient.query('COMMIT');
  } catch (error) {
    await historicalClient.query('ROLLBACK');
    throw error;
  } finally {
    historicalClient.release();
  }
  assert.equal((await freshMigration.query(
    'SELECT conversation_purpose FROM secureshop_agents.agent_sessions WHERE id=$1',
    [historicalMailSession])).rows[0].conversation_purpose, 'secureshop_mail_reply');
  assert.deepEqual(await migrate(freshMigration, AGENTS_DIR), full.filter(row => Number(row.name.slice(0, 4)) > 91).map(row => row.name));
  const repairedIdorSession = randomUUID();
  phase('fresh: repaired 0093 admission verified');
  await freshMigration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,
     user_id,role,conversation_purpose)
    VALUES ($1,'launch_bound','pending',$2,$3,1,2,2,1,'customer','secureshop_idor_lesson')`,
  [repairedIdorSession, randomUUID(), randomUUID()]);
  assert.deepEqual((await freshMigration.query(
    'SELECT conversation_purpose FROM secureshop_agents.agent_sessions WHERE id IN ($1,$2) ORDER BY id',
    [historicalMailSession, repairedIdorSession])).rows.map(row => row.conversation_purpose).sort(),
  ['secureshop_idor_lesson', 'secureshop_mail_reply']);
  assert.deepEqual(await migrate(freshMigration, AGENTS_DIR), []);
  const freshLedger = (await freshMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  assert.deepEqual(freshLedger, full.map(({ name, checksum }) => ({ name, checksum })));
  assert.equal((await fresh.query('SELECT to_regclass($1) AS name', ['secureshop_agents.lab_mail_inline_bindings'])).rows[0].name,
    'secureshop_agents.lab_mail_inline_bindings');

  // The populated cohort gets an ordinary pre-feature receipt before the two
  // forward migrations; its rows must survive both migration and no-op runs.
  // Start the populated cohort immediately before 0086.  This makes the
  // historical IDOR purpose row a real input to the 0091 execution adapter,
  // rather than merely checking the final constraint after 0093.
  const prefix = createAgentsMigrationView(85);
  phase('populated: setup through 0085');
  const setup = await setupAgents({ agents, commerce, identity, identityMigration, commerceMigration, agentsMigration,
    agentsDirectory: prefix.directory, agentsMigrate: prefix.migrate });
  const owner = await createOwner({ ...setup, identity, label: 'inline' });
  const sibling = await createOwner({ ...setup, identity, label: 'sibling' });
  phase('populated: owner and sibling provisioned');
  const throughIdorPurpose = createAgentsMigrationView(86);
  phase('populated: migrate through 0086');
  assert.deepEqual(await throughIdorPurpose.migrate(agentsMigration, throughIdorPurpose.directory),
    full.filter(row => Number(row.name.slice(0, 4)) > 85 && Number(row.name.slice(0, 4)) <= 86).map(row => row.name));
  const retainedIdorSession = randomUUID();
  await agentsMigration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,
     user_id,role,conversation_purpose)
    VALUES ($1,'launch_bound','pending',$2,$3,$4,$5,$6,$7,'customer','secureshop_idor_lesson')`,
  [retainedIdorSession, owner.scope.launchId, owner.scope.scenarioId, owner.scope.generation,
    owner.scope.platformOwnerId, owner.scope.platformSessionId, setup.templates.find(row => row.role === 'customer').id]);
  const beforePurposeMigration = (await agentsMigration.query(
    'SELECT conversation_purpose,binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',
    [retainedIdorSession])).rows[0];
  assert.deepEqual(beforePurposeMigration, { conversation_purpose: 'secureshop_idor_lesson', binding_state: 'pending' });
  const throughMailPurpose = createAgentsMigrationView(91);
  phase('populated: migrate through 0091');
  const appliedThroughMailPurpose = await throughMailPurpose.migrate(agentsMigration, throughMailPurpose.directory);
  assert.deepEqual(appliedThroughMailPurpose, full.filter(row => Number(row.name.slice(0, 4)) > 86 && Number(row.name.slice(0, 4)) <= 91).map(row => row.name));
  assert.deepEqual((await agentsMigration.query(
    'SELECT conversation_purpose,binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',
    [retainedIdorSession])).rows[0], beforePurposeMigration,
  '0091 execution must retain the populated 0086 IDOR purpose before 0093');
  const mail = require('../../server/database/postgres/secureshopBoundMailRepository').createBoundMailRepository({
    pool: agents, personaAuthority: setup.authority,
    checkCleanup: input => require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository')
      .createSecureShopResetCleanupAuthorityRepository(identity).checkTarget({ ...input, targetKind: 'persona_inbox', fromGeneration: input.generation }) });
  const merchant = setup.templates.find(row => row.role === 'merchant');
  const customer = setup.templates.find(row => row.role === 'customer');
  const message = { from: merchant.email, to: customer.email, subject: 'ordinary retained mail', body_markdown: 'ordinary body' };
  const teachingPayload = require('../../server/database/postgres/secureshopBoundMailRepository').prepareSend({
    from: merchant.email, to: merchant.email, subject: 'inline teaching mail', body_markdown: 'inline teaching body' });
  const ordinary = await mail.send(owner, message);
  phase('populated: ordinary mail receipt created');
  const before = (await agents.query('SELECT operation_id,target_id,action,request_sha256 FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1', [owner.targetId])).rows;
  const siblingBefore = (await agentsMigration.query('SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1', [sibling.targetId])).rows[0].n;

  // Finish the populated migration view and prove both fresh and populated
  // ledgers are exact and second-run no-ops.
  assert.deepEqual(await migrate(agentsMigration, AGENTS_DIR), full.filter(row => Number(row.name.slice(0, 4)) > 91).map(row => row.name));
  assert.deepEqual(await migrate(agentsMigration, AGENTS_DIR), []);
  assert.deepEqual((await agentsMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
    full.map(({ name, checksum }) => ({ name, checksum })));
  assert.deepEqual((await agentsMigration.query(
    'SELECT conversation_purpose,binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',
    [retainedIdorSession])).rows[0], beforePurposeMigration,
  'the final current tip must preserve the populated historical purpose row');
  assert.deepEqual((await agents.query('SELECT operation_id,target_id,action,request_sha256 FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1', [owner.targetId])).rows, before);

  const attachedOwner = await attachMailScene(agents, owner);
  phase('populated: scene attached; saving inline binding');
  const scene = require('../../server/services/secureshopMailSceneBinding').productScene(attachedOwner);
  assert.ok(scene?.scene?.grantId);
  const inline = require('../../server/database/postgres/secureshopMailInlineBindingRepository')
    .createSecureShopMailInlineBindingRepository({ pool: agents, personaAuthority: setup.authority,
      verifyPendingReservation: async (_binding, reservation) => reservation });
  const reservation = { issuanceId: randomUUID(), listenerTargetId: randomUUID(), nonceSha256: randomBytes(32).toString('hex'),
    path: '/inline/ordinary.png', resourceKind: 'mail_inline_image_v1', urlSha256: randomBytes(32).toString('hex') };
  const bound = await inline.saveTeachingMessage(copyMailBinding(attachedOwner, { operationId: randomUUID() }), { reservation, payload: teachingPayload });
  assert.equal(bound.send.replayed, false);
  assert.equal(bound.binding.targetId, owner.targetId);
  assert.deepEqual(await inline.readBound(copyMailBinding(attachedOwner, { operationId: randomUUID() }), {
    messageId: bound.binding.messageId, messageSha256: bound.binding.messageSha256, recipientId: bound.binding.recipientId }), bound.binding);

  const replay = await inline.saveTeachingMessage(copyMailBinding(attachedOwner, { operationId: bound.binding.sendOperationId }), { reservation, payload: teachingPayload });
  assert.equal(replay.send.replayed, true);
  await assert.rejects(inline.saveTeachingMessage(copyMailBinding(attachedOwner, { operationId: bound.binding.sendOperationId }), {
    reservation: { ...reservation, path: '/substituted.png' }, payload: teachingPayload }));
  await assert.rejects(inline.saveTeachingMessage(copyMailBinding(attachedOwner, { persona: { ...attachedOwner.persona, role: null } }), { reservation, payload: teachingPayload }));

  const summaryRequestId = randomUUID();
  const invocationBinding = copyMailBinding(attachedOwner, { operationId: summaryRequestId });
  const targetReceiptBase = { version: 1, issuanceId: bound.binding.issuanceId,
    sendOperationId: bound.binding.sendOperationId, targetId: bound.binding.targetId,
    listenerTargetId: bound.binding.listenerTargetId, nonceSha256: bound.binding.nonceSha256,
    path: bound.binding.path, resourceKind: bound.binding.resourceKind, urlSha256: bound.binding.urlSha256,
    method: 'GET', status: 200, responseSha256: sha256('owned-inline-response') };
  const invocation = { version: 1, source: { readOperationId: randomUUID(), receiptSha256: sha256('read-receipt'), bodyHtmlSha256: sha256('body-html') },
    targetReceipt: { ...targetReceiptBase, receiptSha256: sha256(JSON.stringify(targetReceiptBase)) },
    // Fresh graph-runtime owners start at durable generation zero. This is
    // distinct from the platform launch generation, which starts at one.
    runId: randomUUID(), ownerKey: 'native-v55', generation: '0', sessionId: randomUUID(),
    summaryRequestId, callId: 'fetch', effectKey: 'inline-image', binding: bound.binding,
    parsedResultSha256: sha256('parsed'), observationSha256: sha256('observation') };
  const recorded = await inline.recordInvocation(invocationBinding, invocation);
  phase('populated: invocation recorded and replay checked');
  assert.deepEqual(await inline.readInvocation(invocationBinding, { summaryRequestId }), recorded);
  assert.deepEqual(await inline.recordInvocation(invocationBinding, invocation), recorded);
  await assert.rejects(inline.recordInvocation(invocationBinding, { ...invocation, effectKey: 'substituted-effect' }));
  const secondSummary = randomUUID();
  await assert.rejects(inline.recordInvocation(copyMailBinding(attachedOwner, { operationId: secondSummary }),
    { ...invocation, summaryRequestId: secondSummary }));
  await assert.rejects(inline.readInvocation(copyMailBinding(invocationBinding,
    { persona: { ...invocationBinding.persona, role: null } }), { summaryRequestId }));
  await assert.rejects(inline.readInvocation(copyMailBinding(invocationBinding,
    { personaSession: { ...invocationBinding.personaSession, sessionId: randomUUID() } }), { summaryRequestId }));

  const retainedInlineEvidence = async () => ({
    bindings: (await agentsMigration.query('SELECT * FROM secureshop_agents.lab_mail_inline_bindings WHERE issuance_id=$1',
      [bound.binding.issuanceId])).rows,
    invocations: (await agentsMigration.query('SELECT * FROM secureshop_agents.lab_mail_inline_http_invocations WHERE issuance_id=$1',
      [bound.binding.issuanceId])).rows,
  });
  const immutableBeforeReset = await retainedInlineEvidence();
  assert.equal(immutableBeforeReset.bindings.length, 1);
  assert.equal(immutableBeforeReset.invocations.length, 1);
  const reset = await setup.launches.beginReset({ ...owner.scope, expectedGeneration: owner.scope.generation, idempotencyKey: randomUUID() });
  phase('populated: reset begun');
  const cleanup = await setup.bundle.repository.cleanup({ ...owner.scope, targetId: owner.targetId }, { operationId: reset.resetId });
  phase('populated: reset cleanup completed');
  assert.equal(cleanup.deletedMessageCount >= 1, true);
  assert.equal((await agentsMigration.query('SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1', [owner.targetId])).rows[0].n, 0);
  assert.equal((await agentsMigration.query('SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1', [sibling.targetId])).rows[0].n, siblingBefore);
  await assert.rejects(inline.readInvocation(invocationBinding, { summaryRequestId }));
  assert.deepEqual(await retainedInlineEvidence(), immutableBeforeReset,
    'reset must retain every immutable binding and HTTP invocation column unchanged');
  const retainedReceipts = (await agents.query('SELECT operation_id,target_id,action,request_sha256 FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1', [owner.targetId])).rows;
  assert.deepEqual(new Set(retainedReceipts.map(row => row.operation_id)), new Set(before.map(row => row.operation_id).concat(bound.binding.sendOperationId)));

  await assert.rejects(agents.query('SELECT * FROM secureshop_agents.lab_mail_inline_bindings'), { code: '42501' });
  await assert.rejects(agents.query('SELECT * FROM secureshop_agents.lab_mail_inline_http_invocations'), { code: '42501' });
  await assert.rejects(agents.query('INSERT INTO secureshop_agents.lab_mail_inline_bindings DEFAULT VALUES'), { code: '42501' });
  await assert.rejects(agents.query('INSERT INTO secureshop_agents.lab_mail_inline_http_invocations DEFAULT VALUES'), { code: '42501' });
  const role = (await agents.query(`SELECT has_function_privilege(current_user, 'secureshop_agents.save_bound_mail_inline(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,jsonb,uuid,uuid,bytea,text,text,bytea)', 'EXECUTE') AS save, has_table_privilege(current_user, 'secureshop_agents.lab_mail_inline_bindings', 'SELECT') AS table_read`)).rows[0];
  assert.equal(role.save, true); assert.equal(role.table_read, false);
  assert.equal(ordinary.replayed, false);

  // Exercise a real binding row in the independently migrated fresh cohort as
  // well; the populated assertions above deliberately cover upgrade safety.
  const freshSetup = await setupAgents({ agents: fresh, commerce, identity, identityMigration,
    commerceMigration, agentsMigration: freshMigration });
  phase('fresh: runtime setup completed');
  const freshOwner = await createOwner({ ...freshSetup, identity, label: 'fresh-inline' });
  const attachedFreshOwner = await attachMailScene(fresh, freshOwner);
  const freshInline = require('../../server/database/postgres/secureshopMailInlineBindingRepository')
    .createSecureShopMailInlineBindingRepository({ pool: fresh, personaAuthority: freshSetup.authority,
      verifyPendingReservation: async (_binding, value) => value });
  const freshReservation = { issuanceId: randomUUID(), listenerTargetId: randomUUID(), nonceSha256: randomBytes(32).toString('hex'),
    path: '/inline/fresh.png', resourceKind: 'mail_inline_image_v1', urlSha256: randomBytes(32).toString('hex') };
  const freshBound = await freshInline.saveTeachingMessage(copyMailBinding(attachedFreshOwner, { operationId: randomUUID() }),
    { reservation: freshReservation, payload: teachingPayload });
  phase('fresh: inline binding saved');
  assert.equal(freshBound.send.replayed, false);
  assert.equal((await freshMigration.query('SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_inline_bindings WHERE issuance_id=$1',
    [freshBound.binding.issuanceId])).rows[0].n, 1);
});

void native;
