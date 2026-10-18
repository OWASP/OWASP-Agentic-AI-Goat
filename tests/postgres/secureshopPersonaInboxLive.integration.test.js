'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const express = require('express');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopResetCleanupAuthorityRepository } = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { createSecureShopTargetReconciliationRepository } = require('../../server/database/postgres/secureshopTargetReconciliationRepository');
const { createSecureShopPersonaInboxRepository } = require('../../server/database/postgres/secureshopPersonaInboxRepository');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');
const { createSecureShopConversationLifecycleRepository } = require('../../server/database/postgres/secureshopConversationLifecycleRepository');
const { createSecureShopConversationCleanupCheckpointRepository } = require('../../server/database/postgres/secureshopConversationCleanupCheckpointRepository');
const { createSecureShopProgressCleanupCheckpointRepository } = require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../../server/agent-runtime/providers/langchainProvider');
const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createBoundTurns } = require('../../server/services/secureshopBoundTurns');
const { createBoundAgentRunner } = require('../../server/services/secureshopBoundAgentRunner');
const { createSecureShopConversationLifecycle } = require('../../server/services/secureshopConversationLifecycle');
const { createSecureShopReviewResetCoordinator } = require('../../server/services/secureshopReviewResetCoordinator');
const { createSecureShopLaunchResetCoordinator } = require('../../server/services/secureshopLaunchResetCoordinator');
const { createSecureShopPersonaInboxTools } = require('../../server/services/secureshopPersonaInboxTools');
const { createSecureShopPersonaInboxRequestAuthority } = require('../../server/services/secureshopPersonaInboxRequestAuthority');
const { createSecureShopPersonaInboxExecutionConfig } = require('../../server/services/secureshopPersonaInboxExecutionConfig');
const { OBJECTIVES } = require('../../server/services/secureshopPersonaInboxAssessment');
const { createSecureShopPersonaInboxPriorAdvisoryReader } = require('../../server/services/secureshopPersonaInboxPriorAdvisoryReader');
const { createSecureShopPersonaInboxComposition } = require('../../server/services/secureshopPersonaInboxComposition');
const { actionSha } = require('../../server/services/secureshopPersonaInboxEvidence');
const { runSessionExclusive } = require('../../server/services/secureshop/sessionStore');

const PREFIX = 'PG_SECURESHOP_PERSONA_INBOX_LIVE_';
const KEYS = ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'AGENTS_MIGRATION_URL', 'AGENTS_RUNTIME_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && KEYS.every(key => process.env[PREFIX + key]);
const WORKSHOP = 'secureshop_agent_security';
const objectiveIds = Object.freeze(Object.values(OBJECTIVES));
const uuid = crypto.randomUUID;
const sha = value => crypto.createHash('sha256').update(value).digest();
const parse = value => { try { return JSON.parse(value); } catch { return null; } };

function checked(key) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  return value.href;
}
function templates() {
  return [
    { id: 2101, username: 'live_customer', role: 'customer', email: 'customer@live.invalid' },
    { id: 2102, username: 'live_merchant', role: 'merchant', email: 'merchant@live.invalid' },
    { id: 2103, username: 'live_admin', role: 'admin', email: 'admin@live.invalid' },
  ];
}
function fixtures() {
  return [
    { fixtureKey: 'customer-note', owner: { id: 2101, role: 'customer' }, subject: 'Delivery preference', body: 'Please leave the package with the front desk after 4 PM.' },
    { fixtureKey: 'merchant-note', owner: { id: 2102, role: 'merchant' }, subject: 'Inventory handoff', body: 'The blue headphone shipment is assigned to aisle C for tomorrow.' },
    { fixtureKey: 'admin-note', owner: { id: 2103, role: 'admin' }, subject: 'Support rotation', body: 'The weekend support rotation begins Saturday at 09:00.' },
  ];
}
function scopeOf(owner) {
  return Object.freeze({ ...owner.issued.binding, platformOwnerId: owner.user.id,
    platformSessionId: owner.session.id });
}

test('mounted production persona-inbox composition uses actual 8B actor and Judge then resets only its launch', {
  skip: !enabled, timeout: 240000,
}, async t => {
  const workspace = path.resolve(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^dvaia-secureshop-persona-inbox-live-/);
  const identityMigration = new Pool({ connectionString: checked('IDENTITY_MIGRATION_URL'), max: 2 });
  const identity = new Pool({ connectionString: checked('IDENTITY_RUNTIME_URL'), max: 10 });
  const leases = new Pool({ connectionString: checked('IDENTITY_RUNTIME_URL'), max: 3,
    application_name: 'persona-inbox-live-lease' });
  const agentsMigration = new Pool({ connectionString: checked('AGENTS_MIGRATION_URL'), max: 2 });
  const agents = new Pool({ connectionString: checked('AGENTS_RUNTIME_URL'), max: 8 });
  let server;
  try {
    await initializeIdentityRepository(identity, identityMigration);
    await seedWorkshopPlatform(identityMigration);
    await initializeSecureShopAgentsDb({ runtimePool: agents, migrationPool: agentsMigration });
    assert.equal((await identityMigration.query(`SELECT name FROM dvaia_migrations.ledger
      ORDER BY name DESC LIMIT 1`)).rows[0]?.name, '0043_dpi_evidence_guidance.sql');
    assert.equal((await agentsMigration.query(`SELECT name FROM dvaia_migrations.ledger
      ORDER BY name DESC LIMIT 1`)).rows[0]?.name, '0009_secureshop_bound_persona_renewal.sql');
    const ledgerCounts = {
      identity: Number((await identityMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n),
      agents: Number((await agentsMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n),
    };
    await identityMigration.query(await fs.readFile(path.join(workspace,
      'docs/modernization/drafts/secureshop-persona-inbox-identity.sql'), 'utf8'));
    await agentsMigration.query(await fs.readFile(path.join(workspace,
      'docs/modernization/drafts/secureshop-persona-inbox-agents.sql'), 'utf8'));
    assert.deepEqual({
      identity: Number((await identityMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n),
      agents: Number((await agentsMigration.query('SELECT count(*)::int AS n FROM dvaia_migrations.ledger')).rows[0].n),
    }, ledgerCounts, 'unregistered candidate drafts must not alter production migration ledgers');
    await identityMigration.query(`UPDATE workshop_platform.exercises
      SET catalog_active=true,is_visible=true WHERE workshop_key=$1`, [WORKSHOP]);
    await identityMigration.query(`UPDATE workshop_platform.objectives
      SET catalog_active=true,is_enabled=true WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`,
    [WORKSHOP, objectiveIds]);
    assert.equal((await identityMigration.query(`SELECT count(*)::int AS n FROM workshop_platform.objectives
      WHERE workshop_key=$1 AND objective_id=ANY($2::text[]) AND catalog_active AND is_enabled`,
    [WORKSHOP, objectiveIds])).rows[0].n, 3);

    for (const persona of templates()) {
      await agentsMigration.query(`INSERT INTO secureshop_agents.bound_persona_templates
        (username,shop_user_id,email,password_hash,role,full_name,source_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [persona.username, persona.id, persona.email,
        '$2b$04$abcdefghijklmnopqrstuuJ8qf49DeIxL6Bq8u8gD9zlM5JXbJPO', persona.role,
        `Live ${persona.role}`, sha(JSON.stringify(persona))]);
    }

    const identities = createIdentityRepository(identity);
    const launches = createSecureShopLaunchRepository(identity);
    const passwordHash = await bcrypt.hash('persona-inbox-live', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    const makeOwner = async (label, user = null) => {
      user ||= await identities.createUser({ username: `${label}-${uuid().slice(0, 8)}`,
        email: `${uuid()}@persona-live.invalid`, passwordHash });
      const session = await identities.createSession({ userId: user.id, token: uuid(), expiresAt,
        expectedPasswordHash: passwordHash });
      const issued = await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: session.id, expiresAt });
      await identity.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
        VALUES($1,$2,'vuln') ON CONFLICT(user_id,workshop_key) DO NOTHING`, [user.id, WORKSHOP]);
      return { user, session, issued };
    };
    const owner = await makeOwner('persona-live-owner');
    const sibling = await makeOwner('persona-live-sibling');
    assert.notEqual(sibling.user.id, owner.user.id);
    assert.notEqual(sibling.session.id, owner.session.id);
    assert.notEqual(sibling.issued.binding.launchId, owner.issued.binding.launchId);
    assert.notEqual(sibling.issued.binding.scenarioId, owner.issued.binding.scenarioId);
    const scopes = [scopeOf(owner), scopeOf(sibling)];
    const targets = new Map();
    for (const scope of scopes) {
      const target = Object.freeze({ targetId: uuid(), ...scope });
      await identity.query(`INSERT INTO identity.secureshop_target_reservations
        (target_id,launch_id,generation,target_kind,original_platform_owner_id)
        VALUES($1,$2,$3,'persona_inbox',$4)`, [target.targetId, target.launchId,
        target.generation, target.platformOwnerId]);
      targets.set(scope.launchId, target);
    }
    const resolveTarget = async binding => {
      const target = targets.get(binding.launchId);
      if (!target) throw Object.assign(new Error('Persona inbox target unavailable'),
        { code: 'PERSONA_INBOX_TARGET_UNAVAILABLE' });
      return target;
    };
    const checkCurrent = value => launches.assertCurrent(value);
    const cleanupAuthority = createSecureShopResetCleanupAuthorityRepository(identity);
    const transitions = new Set();
    const repository = createSecureShopPersonaInboxRepository(agents, {
      checkCurrent,
      async checkAclTransition(input) {
        if (!transitions.has(`${input.targetId}:${input.expectedVersion}:${input.mode}`)) {
          throw Object.assign(new Error('ACL transition unavailable'), { code: 'ACL_TRANSITION_UNAVAILABLE' });
        }
      },
      checkCleanup: input => cleanupAuthority.checkTarget({ ...input, targetKind: 'persona_inbox',
        fromGeneration: input.generation }),
    });
    for (const target of targets.values()) await repository.provision(target, { fixtures: fixtures() });

    const conversationRows = createBoundConversationsRepository({ pool: agents, queue: runSessionExclusive });
    const conversationService = createBoundConversationService({ conversations: conversationRows, launches });
    const journal = createTurnRequestsRepository({ pool: agents });
    const ledger = createPostgresRunLedger(identity, { leasePool: leases });
    const coordinator = createRunCoordinator({ family: `SecureShopPersonaInbox:${uuid()}`, ledger });
    const turns = createBoundTurns({ conversations: conversationService, coordinator });
    const model = 'llama3.1:8b';
    const baseUrl = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    const actor = new OllamaProvider({ baseUrl, model });
    const nativeJudge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
      baseURL: baseUrl, model }) });
    let judgeCalls = 0;
    const judge = async packet => { judgeCalls += 1; return nativeJudge(packet); };
    const priorReader = createSecureShopPersonaInboxPriorAdvisoryReader({ pool: identity, checkCurrent });
    const config = createSecureShopPersonaInboxExecutionConfig();
    const requestAuthority = createSecureShopPersonaInboxRequestAuthority();
    const makeRunner = () => createBoundAgentRunner({ turns, conversations: conversationService,
      repository: conversationRows, journal, provider: actor, manifest: config.manifest,
      buildBasePrompt: config.buildBasePrompt, buildPolicyBlock: config.buildPolicyBlock,
      checkToolAcl: config.checkToolAcl,
      createToolPool: () => Object.freeze({ async callTool() {
        throw Object.assign(new Error('Scoped external tool unavailable'), { code: 'SCOPED_TOOL_UNAVAILABLE' });
      } }),
      createLocalTools: (binding, context, token) => {
        const allowed=requestAuthority.resolve(token,context);
        return createSecureShopPersonaInboxTools({ repository,
        trustedScope: binding, trustedPersona: { id: binding.shopUserId, role: binding.role },
        checkCurrent, resolveTarget, allowedMessageId:allowed.messageId,
        authorizedTargetId:allowed.targetId });
      },
      limits: { maxSteps: 8, maxParallelTools: 2 },
    });
    const siblingRunner = makeRunner();
    const persona = Object.freeze({ id: 2102, role: 'merchant' });
    const siblingSession = await conversationService.create(scopeOf(sibling), persona);
    const ownerTarget = targets.get(owner.issued.binding.launchId);
    for (const ownPersona of templates().map(value => ({ id: value.id, role: value.role }))) {
      const ownMessage = (await repository.list(ownerTarget))
        .find(row => row.ownerShopUserId === ownPersona.id && row.ownerShopRole === ownPersona.role);
      assert.ok(ownMessage, `durable ${ownPersona.role} persona owns one neutral fixture`);
      const ownRead = await repository.read(ownerTarget, ownPersona,
        { messageId: ownMessage.messageId, operationId: uuid() });
      assert.equal(ownRead.crossPersona, false);
      assert.equal(ownRead.aclDecision, 'allow');
      assert.equal(ownRead.disclosed, true);
    }
    const adminMessage = (await repository.list(ownerTarget)).find(row => row.ownerShopRole === 'admin');
    assert.ok(adminMessage);

    assert.deepEqual(createSecureShopPersonaInboxComposition({ enabled: false }), { ready: false });
    const feature = createSecureShopPersonaInboxComposition({ enabled: true, identityPool: identity,
      provider: actor, judge, personaRepository: { listPersonas: async () => templates() },
      authenticatePersona(req, res, next) {
        if (req.get('authorization') !== 'Bearer live-merchant'
            || req.ssLaunch?.launchId !== owner.issued.binding.launchId) {
          return res.status(403).json({ error: 'Shop persona unavailable' });
        }
        req.ssUser = { id: persona.id, role: persona.role }; return next();
      },
      resetComposition: { personaInbox: {
        repository,
        async authorizeAclTransition(value) {
          const grant = `${value.targetId}:${value.expectedVersion}:${value.mode}`;
          transitions.add(grant); return () => transitions.delete(grant);
        },
      }, launches, conversationService, turns, journal, conversations: conversationRows },
    });
    const app = express(); app.use(express.json()); app.use('/api/secureshop', feature.router);
    server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    const base = `http://127.0.0.1:${server.address().port}/api/secureshop/v2/persona-inbox`;
    const headers = { 'x-dvaia-secureshop-launch': owner.issued.bearer,
      authorization: 'Bearer live-merchant', 'content-type': 'application/json' };
    const readinessResponse = await fetch(`${base}/readiness`, { headers });
    assert.equal(readinessResponse.status, 200);
    const readiness = await readinessResponse.json();
    assert.equal(readiness.ready, true); assert.equal(readiness.capabilities.enforceAcl, true);
    assert.ok(readiness.messages.some(row => row.messageId === adminMessage.messageId));
    assert.equal((await fetch(`${base}/readiness`, { headers: { ...headers,
      'x-dvaia-secureshop-launch': sibling.issued.bearer } })).status, 403,
    'a persona credential is never portable to a sibling owner launch');

    const assertProjectedAccesses = async (result, requestId, expectedMode) => {
      assert.equal(result.stopReason, 'end_turn');
      assert.ok(result.accesses.length >= 1 && result.accesses.length <= 8);
      const sessionIds = (await agents.query(`SELECT id FROM secureshop_agents.agent_sessions
        WHERE platform_launch_id=$1 AND platform_launch_generation=$2 ORDER BY created_at,id`,
      [ownerTarget.launchId, ownerTarget.generation])).rows.map(row => row.id);
      assert.equal(sessionIds.length, 1);
      const traces = (await agents.query(`SELECT event_id,session_id,kind,actor,step,agent_ns,tool_name,
          params_json,result_json,provider FROM secureshop_agents.agent_trace
        WHERE session_id=$1 ORDER BY ts,event_id`, [sessionIds[0]])).rows;
      assert.equal(traces.at(-1)?.kind, 'terminal');
      const priorTerminal = traces.slice(0, -1).findLastIndex(row => row.kind === 'terminal');
      const runTraces = traces.slice(priorTerminal + 1);
      const matchedLocals = [];
      const projectedEventIds = new Set();
      for (const access of result.accesses) {
        assert.equal(projectedEventIds.has(access.event_id), false);
        projectedEventIds.add(access.event_id);
        assert.equal(access.message_id, adminMessage.messageId);
        assert.equal(access.owner_persona_id, adminMessage.ownerShopUserId);
        assert.equal(access.owner_role, adminMessage.ownerShopRole);
        assert.equal(access.acl.mode, expectedMode);
        assert.equal(access.acl.decision, 'deny');
        assert.equal(access.acl.cross_persona, true);
        assert.equal(access.acl.disclosed, expectedMode === 'advisory');
        const source = await repository.readAccessEvent(ownerTarget, access.event_id);
        assert.equal(source.eventId, access.event_id);
        assert.equal(source.operationId, access.event_id);
        assert.equal(source.targetId, ownerTarget.targetId);
        assert.equal(source.launchId, ownerTarget.launchId);
        assert.equal(source.scenarioId, ownerTarget.scenarioId);
        assert.equal(source.generation, ownerTarget.generation);
        assert.equal(source.platformOwnerId, ownerTarget.platformOwnerId);
        assert.equal(source.platformSessionId, ownerTarget.platformSessionId);
        assert.equal(source.messageId, access.message_id);
        assert.equal(source.callerShopUserId, persona.id);
        assert.equal(source.callerShopRole, persona.role);
        assert.equal(source.ownerShopUserId, access.owner_persona_id);
        assert.equal(source.ownerShopRole, access.owner_role);
        assert.equal(source.subject, access.subject);
        assert.equal(source.body, access.body);
        assert.equal(source.bodySha256, access.body_sha256);
        assert.equal(source.aclVersion, access.acl.version);
        assert.equal(source.aclMode, access.acl.mode);
        assert.equal(source.aclDecision, access.acl.decision);
        assert.equal(source.crossPersona, access.acl.cross_persona);
        assert.equal(source.disclosed, access.acl.disclosed);
        const local = runTraces.filter(row => row.kind === 'local_tool_result'
          && row.agent_ns === 'persona-inbox' && row.tool_name === 'read_message'
          && parse(parse(row.result_json)?.content?.[0]?.text)?.event_id === access.event_id);
        assert.equal(local.length, 1, `event ${access.event_id} must have one persisted tool result`);
        matchedLocals.push(local[0]);
      }
      assert.equal(runTraces.filter(row => row.kind === 'local_tool_result'
        && row.agent_ns === 'persona-inbox' && row.tool_name === 'read_message').length,
      result.accesses.length, 'every persisted read result must be a projected successful access');
      assert.equal(runTraces.filter(row => row.kind === 'model_decision' && row.provider === 'ollama')
        .flatMap(row => parse(row.params_json)?.toolCalls || [])
        .filter(call => call.name === 'persona-inbox.read_message').length,
      result.accesses.length, 'every model-selected read must have a projected successful access');
      for (const step of new Set(matchedLocals.map(row => row.step))) {
        const stepLocals = matchedLocals.filter(row => row.step === step);
        const calls = runTraces.filter(row => row.kind === 'model_decision' && row.step === step
          && row.provider === 'ollama').flatMap(row => parse(row.params_json)?.toolCalls || [])
          .filter(call => call.name === 'persona-inbox.read_message'
            && call.args?.message_id === adminMessage.messageId);
        assert.equal(calls.length, stepLocals.length,
          `step ${step} must persist one exact model call per projected event`);
        for (const call of calls) {
          assert.equal(typeof call.id, 'string'); assert.ok(call.id.length > 0);
          const effectKey = `${requestId}:${JSON.stringify([step, call.id,
            'persona-inbox.read_message'])}`;
          const effects = (await identity.query(`SELECT e.status,r.status AS run_status
            FROM graph_runtime.effects e JOIN graph_runtime.runs r ON r.run_id=e.run_id
            WHERE e.effect_key=$1`, [effectKey])).rows;
          assert.deepEqual(effects, [{ status: 'completed', run_status: 'completed' }]);
        }
      }
      return { sessionId: sessionIds[0], traces: runTraces };
    };
    const replaySnapshot = async () => {
      const [identityCounts, agentCounts] = await Promise.all([identity.query(`SELECT
      (SELECT count(*)::int FROM graph_runtime.runs) AS runs,
      (SELECT count(*)::int FROM graph_runtime.effects) AS effects,
      (SELECT count(*)::int FROM workshop_platform.objective_judgments WHERE user_id=$1) AS judgments,
      (SELECT count(*)::int FROM workshop_platform.objective_contributions WHERE user_id=$1) AS contributions`,
      [owner.user.id]), agents.query(`SELECT
      (SELECT count(*)::int FROM secureshop_agents.agent_sessions WHERE platform_launch_id=$1) AS sessions,
      (SELECT count(*)::int FROM secureshop_agents.agent_trace WHERE session_id IN
        (SELECT id FROM secureshop_agents.agent_sessions WHERE platform_launch_id=$1)) AS traces,
      (SELECT count(*)::int FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$2) AS accesses`,
      [ownerTarget.launchId, ownerTarget.targetId])]);
      return { ...identityCounts.rows[0], ...agentCounts.rows[0] };
    };

    const advisoryRequest = uuid();
    const advisoryResponse = await fetch(`${base}/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: advisoryRequest, message_id: adminMessage.messageId }) });
    assert.equal(advisoryResponse.status, 200);
    const advisoryResult = await advisoryResponse.json();
    t.diagnostic(JSON.stringify({ checkpoint: 'advisory-http', requestId: advisoryRequest,
      accesses: advisoryResult.accesses?.map(row => ({ eventId: row.event_id,
        messageId: row.message_id, mode: row.acl?.mode, decision: row.acl?.decision,
        crossPersona: row.acl?.cross_persona, disclosed: row.acl?.disclosed })) }));
    await assertProjectedAccesses(advisoryResult, advisoryRequest, 'advisory');
    const beforeReplay = await replaySnapshot(); const judgeCallsBeforeReplay = judgeCalls;
    const advisoryReplay = await (await fetch(`${base}/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: advisoryRequest, message_id: adminMessage.messageId }) })).json();
    assert.equal(advisoryReplay.replayed, true);
    assert.deepEqual(advisoryReplay.accesses, advisoryResult.accesses);
    assert.deepEqual(await replaySnapshot(), beforeReplay);
    assert.equal(judgeCalls, judgeCallsBeforeReplay);
    const firstEvents = (await agents.query(`SELECT acl_mode,acl_decision,cross_persona,disclosed
      FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1 ORDER BY created_at`,
    [ownerTarget.targetId])).rows;
    assert.ok(firstEvents.some(row => row.acl_mode === 'advisory' && row.acl_decision === 'deny'
      && row.cross_persona === true && row.disclosed === true));
    const firstContributions = (await identity.query(`SELECT objective_id FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 ORDER BY objective_id`,
    [owner.user.id, ownerTarget.launchId])).rows.map(row => row.objective_id);
    assert.deepEqual(firstContributions, [OBJECTIVES.advisory, OBJECTIVES.cross].sort());
    t.diagnostic(JSON.stringify({ checkpoint: 'advisory', requestId: advisoryRequest,
      accesses: advisoryResult.accesses.length, contributions: firstContributions }));

    const enforceResponse = await fetch(`${base}/enforce`, { method: 'POST', headers, body: '{}' });
    assert.equal(enforceResponse.status, 200);
    assert.equal((await enforceResponse.json()).acl.mode, 'enforced');
    const enforcedRequest = uuid();
    assert.notEqual(enforcedRequest, advisoryRequest,
      'the same business action in a later ACL version uses a distinct journal request');
    const enforcedResponse = await fetch(`${base}/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: enforcedRequest, message_id: adminMessage.messageId }) });
    assert.equal(enforcedResponse.status, 200);
    const enforcedResult = await enforcedResponse.json();
    t.diagnostic(JSON.stringify({ checkpoint: 'enforced-http', requestId: enforcedRequest,
      accesses: enforcedResult.accesses?.map(row => ({ eventId: row.event_id,
        messageId: row.message_id, mode: row.acl?.mode, decision: row.acl?.decision,
        crossPersona: row.acl?.cross_persona, disclosed: row.acl?.disclosed })) }));
    await assertProjectedAccesses(enforcedResult, enforcedRequest, 'enforced');
    const enforcedEvents = (await agents.query(`SELECT message_id,caller_shop_user_id,owner_shop_user_id,
      acl_mode,acl_decision,cross_persona,disclosed,body_sha256
      FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1 AND acl_mode='enforced'`,
    [ownerTarget.targetId])).rows;
    assert.ok(enforcedEvents.length >= 1);
    for (const event of enforcedEvents) assert.deepEqual(event, { message_id: adminMessage.messageId,
      caller_shop_user_id: persona.id, owner_shop_user_id: adminMessage.ownerShopUserId,
      acl_mode: 'enforced', acl_decision: 'deny', cross_persona: true,
      disclosed: false, body_sha256: null });
    t.diagnostic(JSON.stringify({ checkpoint: 'enforced', requestId: enforcedRequest,
      accesses: enforcedResult.accesses.length, disclosed: false }));

    const contributions = (await identity.query(`SELECT objective_id,evaluation_id,platform_launch_generation
      FROM workshop_platform.objective_contributions WHERE user_id=$1 AND platform_launch_id=$2 ORDER BY objective_id`,
    [owner.user.id, ownerTarget.launchId])).rows;
    assert.deepEqual(contributions.map(row => row.objective_id), [...objectiveIds].sort());
    const canonicalAction = actionSha({ targetId: ownerTarget.targetId, messageId: adminMessage.messageId,
      callerShopUserId: persona.id, callerShopRole: persona.role,
      ownerShopUserId: adminMessage.ownerShopUserId, ownerShopRole: adminMessage.ownerShopRole });
    const priorBeforeReset = await priorReader({ ...ownerTarget, shopUserId: persona.id, role: persona.role },
      { targetId: ownerTarget.targetId, messageId: adminMessage.messageId,
        actionSha256: canonicalAction });
    assert.equal(priorBeforeReset?.objectiveId, OBJECTIVES.advisory);
    const judgments = (await identity.query(`SELECT objective_id,verdict,result_json,run_id
      FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id=ANY($2::text[])
      ORDER BY created_at`, [owner.user.id, objectiveIds])).rows;
    for (const objectiveId of objectiveIds) {
      const accepted = judgments.find(row => row.objective_id === objectiveId && row.verdict === 'pass');
      assert.ok(accepted, `${objectiveId} must receive an independent actual Judge pass`);
      assert.equal(accepted.result_json.provider, 'ollama');
      assert.equal(accepted.result_json.model, model);
    }
    assert.ok(judgeCalls >= 3);
    const acceptedRun = objectiveId => judgments.find(row => row.objective_id === objectiveId
      && row.verdict === 'pass').run_id;
    const gradedCalls = [];
    for (const [objectiveId, expectedRequest] of [[OBJECTIVES.cross, advisoryRequest],
      [OBJECTIVES.advisory, advisoryRequest], [OBJECTIVES.enforced, enforcedRequest]]) {
      const contribution = contributions.find(row => row.objective_id === objectiveId);
      const packetText = (await identity.query(`SELECT packet FROM workshop_platform.grade_packets
        WHERE user_id=$1 AND evaluation_id=$2`, [owner.user.id, contribution.evaluation_id])).rows[0]?.packet;
      const packet = JSON.parse(packetText);
      const chainRows = packet.evidence.filter(row => row.id === 'persona_inbox_chain'
        && row.source === 'server_observation');
      assert.equal(chainRows.length, 1);
      const chain = chainRows[0].content;
      assert.equal(chain.requestId, expectedRequest);
      assert.equal(chain.targetId, ownerTarget.targetId);
      assert.equal(chain.messageId, adminMessage.messageId);
      assert.equal(chain.modelCall.tool, 'persona-inbox.read_message');
      assert.equal(chain.modelCall.args.message_id, adminMessage.messageId);
      assert.equal(typeof chain.modelCall.callId, 'string');
      assert.ok(chain.modelCall.callId.length > 0);
      assert.equal(chain.effectReceipt.status, 'completed');
      assert.equal(chain.effectReceipt.runId, acceptedRun(objectiveId));
      assert.equal(chain.effectReceipt.effectKey,
        `${expectedRequest}:${JSON.stringify([chain.modelCall.step, chain.modelCall.callId,
          'persona-inbox.read_message'])}`);
      gradedCalls.push({ requestId: expectedRequest, step: chain.modelCall.step,
        callId: chain.modelCall.callId, args: chain.modelCall.args });
    }
    const ownerSessions = (await agents.query(`SELECT id FROM secureshop_agents.agent_sessions
      WHERE platform_launch_id=$1 AND platform_launch_generation=1 ORDER BY created_at,id`,
    [ownerTarget.launchId])).rows.map(row => row.id);
    assert.equal(ownerSessions.length, 1, 'bound acquisition and exact replay reuse one conversation');
    const ownerTraces = (await agents.query(`SELECT event_id,session_id,kind,actor,params_json,result_json,provider
      FROM secureshop_agents.agent_trace WHERE session_id=ANY($1::uuid[]) ORDER BY ts,event_id`, [ownerSessions])).rows;
    assert.ok(ownerTraces.some(row => row.kind === 'model_decision' && row.provider === 'ollama'
      && JSON.parse(row.params_json)?.toolCalls?.some(call => call.name === 'persona-inbox.read_message')));
    assert.ok(ownerTraces.some(row => row.kind === 'local_tool_result'
      && JSON.parse(row.result_json)?.content?.[0]?.text.includes('"mode":"enforced"')));
    for (const expected of gradedCalls) {
      assert.ok(ownerTraces.some(row => row.kind === 'model_decision' && row.provider === 'ollama'
        && JSON.parse(row.params_json)?.toolCalls?.some(call => call.id === expected.callId
          && call.name === 'persona-inbox.read_message'
          && call.args?.message_id === expected.args.message_id)),
      `persisted model decision missing graded call ${expected.callId} for ${expected.requestId}`);
    }
    assert.equal(ownerTraces.filter(row => row.kind === 'terminal').length, 2);

    const siblingRequest = uuid();
    const siblingTarget=targets.get(sibling.issued.binding.launchId);
    const siblingMessage=(await repository.list(siblingTarget))[0];
    const siblingAuthority=requestAuthority.issue({binding:{...scopeOf(sibling),shopUserId:persona.id,role:persona.role},
      sessionId:siblingSession.id,requestId:siblingRequest,targetId:siblingTarget.targetId,
      messageId:siblingMessage.messageId});
    let siblingResult;
    try { siblingResult = await siblingRunner.run({ sessionId: siblingSession.id, requestId: siblingRequest,
      scope: scopeOf(sibling), persona, localToolAuthority:siblingAuthority.token,
      message: 'Use persona-inbox.list_messages to list the private inbox identifiers and subjects. Do not read a body.',
    }); } finally { siblingAuthority.revoke(); }
    assert.equal(siblingResult.stopReason, 'end_turn');
    const siblingTraceBefore = Number((await agents.query(`SELECT count(*)::int AS n
      FROM secureshop_agents.agent_trace WHERE session_id=$1`, [siblingSession.id])).rows[0].n);
    assert.ok(siblingTraceBefore >= 3);
    assert.equal((await repository.list(targets.get(sibling.issued.binding.launchId))).length, 3);
    t.diagnostic(JSON.stringify({ checkpoint: 'sibling', requestId: siblingRequest,
      modelSteps: siblingResult.steps, traces: siblingTraceBefore }));

    const lifecycleRows = createSecureShopConversationLifecycleRepository({ pool: agents });
    const lifecycle = createSecureShopConversationLifecycle({ repository: lifecycleRows, turns, cleanupAuthority });
    const conversationCheckpoint = createSecureShopConversationCleanupCheckpointRepository(identity, {
      getOperation: resetId => cleanupAuthority.getOperation(resetId),
      readRetirementReceipt: resetId => lifecycle.readReceipt(resetId),
    });
    const progressCheckpoint = createSecureShopProgressCleanupCheckpointRepository(identity);
    const reconciler = createSecureShopTargetReconciliationRepository(identity, {
      checkAuthority: input => cleanupAuthority.checkTarget(input),
      readCleanupReceipt: async input => Object.freeze({
        ...await repository.readCleanupReceipt({ targetId: input.targetId, launchId: input.launchId,
          scenarioId: input.scenarioId, generation: input.fromGeneration,
          platformOwnerId: input.platformOwnerId, platformSessionId: input.platformSessionId },
        { operationId: input.operationId }), kind: 'persona_inbox',
      }),
    });
    const targetCoordinator = createSecureShopReviewResetCoordinator({ launches, cleanupAuthority,
      reviewRepository: { async cleanup() { throw new Error('unexpected review cleanup'); } }, reconciler,
      personaInboxCleanup: repository });
    const resetCoordinator = createSecureShopLaunchResetCoordinator({ launches, cleanupAuthority,
      conversationLifecycle: lifecycle, conversationCheckpoint, targetCoordinator, progressCheckpoint });
    const resetInput = { launchId: ownerTarget.launchId, platformOwnerId: owner.user.id,
      platformSessionId: owner.session.id, expectedGeneration: 1, idempotencyKey: `persona-live-${uuid()}` };
    const reset = await resetCoordinator.reset(resetInput);
    assert.equal(reset.status, 'committed');
    assert.equal(reset.fromGeneration, 1);
    assert.equal(reset.toGeneration, 2);
    assert.equal(reset.targets, 1);
    assert.deepEqual(await resetCoordinator.reset(resetInput), reset);
    const cleanup = (await identity.query(`SELECT target_kind,operation_id FROM identity.secureshop_target_cleanup_history
      WHERE target_id=$1`, [ownerTarget.targetId])).rows[0];
    assert.deepEqual(cleanup, { target_kind: 'persona_inbox', operation_id: reset.resetId });
    assert.deepEqual((await identity.query(`SELECT
        (SELECT count(*)::int FROM identity.secureshop_conversation_cleanup_history WHERE reset_id=$1) AS conversations,
        (SELECT count(*)::int FROM identity.secureshop_progress_cleanup_history WHERE reset_id=$1) AS progress`,
    [reset.resetId])).rows[0], { conversations: 1, progress: 1 });
    assert.equal((await identity.query(`SELECT count(*)::int AS n FROM identity.secureshop_target_reservations
      WHERE target_id=$1 AND launch_id=$2 AND original_platform_owner_id=$3`,
    [targets.get(sibling.issued.binding.launchId).targetId, sibling.issued.binding.launchId,
      sibling.user.id])).rows[0].n, 1);
    assert.equal((await agents.query(`SELECT count(*)::int AS n FROM secureshop_agents.persona_inbox_messages
      WHERE target_id=$1`, [ownerTarget.targetId])).rows[0].n, 0);
    assert.equal((await agents.query(`SELECT count(*)::int AS n FROM secureshop_agents.agent_sessions
      WHERE id=ANY($1::uuid[]) AND binding_state='abandoned'`, [ownerSessions])).rows[0].n, 1);
    assert.equal((await agents.query(`SELECT count(*)::int AS n FROM secureshop_agents.agent_trace
      WHERE session_id=ANY($1::uuid[])`, [ownerSessions])).rows[0].n, ownerTraces.length,
    'retired traces remain immutable historical evidence');
    assert.equal((await fetch(`${base}/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: uuid(), message_id: adminMessage.messageId }) })).status, 401);
    await assert.rejects(priorReader({ ...ownerTarget, shopUserId: persona.id, role: persona.role },
      { targetId: ownerTarget.targetId, messageId: adminMessage.messageId,
        actionSha256: canonicalAction }), { code: 'STALE_LAUNCH' });

    assert.equal((await repository.list(targets.get(sibling.issued.binding.launchId))).length, 3);
    assert.equal((await agents.query(`SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1`,
      [siblingSession.id])).rows[0].binding_state, 'active');
    assert.equal(Number((await agents.query(`SELECT count(*)::int AS n FROM secureshop_agents.agent_trace
      WHERE session_id=$1`, [siblingSession.id])).rows[0].n), siblingTraceBefore);
    assert.equal((await identity.query(`SELECT count(*)::int AS n FROM workshop_platform.objective_contributions
      WHERE user_id=$1`, [sibling.user.id])).rows[0].n, 0);
    assert.equal((await identity.query(`SELECT count(*)::int AS n FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=2`,
    [owner.user.id, ownerTarget.launchId])).rows[0].n, 0);
    assert.equal((await identity.query(`SELECT count(*)::int AS n FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=1`,
    [owner.user.id, ownerTarget.launchId])).rows[0].n, 3,
    'reset preserves the three immutable historical contributions');
    assert.equal((await identity.query(`SELECT count(*)::int AS n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key=$2`, [owner.user.id, WORKSHOP])).rows[0].n, 0);
    t.diagnostic(JSON.stringify({ checkpoint: 'reset', resetId: reset.resetId,
      fromGeneration: reset.fromGeneration, toGeneration: reset.toGeneration,
      cleanupKind: cleanup.target_kind, siblingTraces: siblingTraceBefore }));

    t.diagnostic(JSON.stringify({ scope: 'unwired persona-inbox candidate; actual direct Ollama actor and Judge; owned identity/agents stores',
      advisory: { requestId: advisoryRequest, contributions: firstContributions },
      enforced: { requestId: enforcedRequest, objective: OBJECTIVES.enforced },
      judgeCalls, traces: { owner: ownerTraces.length, sibling: siblingTraceBefore },
      reset: { resetId: reset.resetId, cleanupKind: cleanup.target_kind, generation: reset.binding.generation } }));
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await Promise.allSettled([leases.end(), identity.end(), identityMigration.end(), agents.end(), agentsMigration.end()]);
  }
});
