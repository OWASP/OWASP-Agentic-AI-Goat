'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const express = require('express');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { seedSecureShop } = require('../../server/database/postgres/secureshopSeed');
const { createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../../server/agent-runtime/providers/langchainProvider');
const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');
const { createSecureShopBoundReviewComposition, assertPersonaInboxReadiness } = require(
  '../../server/services/secureshopBoundReviewComposition');
const { createSecureShopBoundGateway } = require('../../server/routes/secureshop/boundGateway');
const { OBJECTIVES } = require('../../server/services/secureshopPersonaInboxAssessment');

const PREFIX = 'PG_SECURESHOP_PERSONA_INBOX_AUTH_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && STORES.every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
const WORKSHOP = 'secureshop_agent_security';
const objectiveIds = Object.freeze(Object.values(OBJECTIVES));
const parse = value => { try { return JSON.parse(value); } catch { return null; } };
const safeError = error => Object.freeze({ name: error?.name || 'Error', code: error?.code || null,
  message: String(error?.message || error).replace(/https?:\/\/\S+/g, '[url]').slice(0, 320) });
function traceShape(row) {
  const params = parse(row.params_json); const result = parse(row.result_json);
  return Object.freeze({ id: Number(row.id), sessionId: row.session_id, kind: row.kind, step: row.step,
    provider: row.provider, tool: row.agent_ns && row.tool_name ? `${row.agent_ns}.${row.tool_name}` : null,
    calls: Array.isArray(params?.toolCalls) ? params.toolCalls.slice(0, 8).map(call => Object.freeze({
      id: typeof call?.id === 'string' ? call.id.slice(0, 128) : null,
      name: typeof call?.name === 'string' ? call.name.slice(0, 128) : null,
      messageId: Number.isSafeInteger(call?.args?.message_id) ? call.args.message_id : null,
    })) : [], result: Object.freeze({ isError: result?.isError === true,
      code: parse(result?.content?.[0]?.text)?.code || null,
      eventId: parse(result?.content?.[0]?.text)?.event_id || null,
      messageId: parse(result?.content?.[0]?.text)?.message_id || null }) });
}

function checked(name) {
  const value = new URL(process.env[`${PREFIX}${name}_URL`]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
async function json(response, status = 200) {
  assert.equal(response.status, status);
  return response.json();
}
async function assertLedger(pool, directory) {
  const expected = await readMigrations(directory);
  const actual = (await pool.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  assert.deepEqual(actual, expected.map(row => ({ name: row.name, checksum: row.checksum })));
}

test('production gateway binds actual persona JWT to mounted actual 8B inbox effects and reset', {
  skip: !enabled, timeout: 300000,
}, async t => {
  const workspace = path.resolve(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || '');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-secureshop-persona-inbox-auth-/);
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION', 'RUNTIME'].map(role => {
    const max = store === 'IDENTITY' && role === 'RUNTIME' ? 12 : 5;
    return [`${store}_${role}`, new Pool({ connectionString: checked(`${store}_${role}`), max })];
  })));
  const leasePool = new Pool({ connectionString: checked('IDENTITY_RUNTIME'), max: 4,
    application_name: 'persona-inbox-auth-live-lease' });
  let server; let composition;
  const failureScope = { requests: [] };
  try {
    await migrate(pools.IDENTITY_MIGRATION, path.join(workspace, 'db/postgres/identity-migrations'));
    await migrate(pools.AGENTS_MIGRATION,
      path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents'));
    await migrate(pools.REVIEW_MIGRATION,
      path.join(workspace, 'db/postgres/workshop-migrations/secureshop_review'));
    await migrate(pools.COMMERCE_MIGRATION,
      path.join(workspace, 'db/postgres/workshop-migrations/secureshop'));
    await Promise.all([
      assertLedger(pools.IDENTITY_MIGRATION, path.join(workspace, 'db/postgres/identity-migrations')),
      assertLedger(pools.AGENTS_MIGRATION,
        path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents')),
      assertLedger(pools.REVIEW_MIGRATION,
        path.join(workspace, 'db/postgres/workshop-migrations/secureshop_review')),
      assertLedger(pools.COMMERCE_MIGRATION,
        path.join(workspace, 'db/postgres/workshop-migrations/secureshop')),
    ]);
    await seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
    await pools.COMMERCE_MIGRATION.query('BEGIN');
    try { await seedSecureShop(pools.COMMERCE_MIGRATION); await pools.COMMERCE_MIGRATION.query('COMMIT'); }
    catch (error) { await pools.COMMERCE_MIGRATION.query('ROLLBACK'); throw error; }
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.exercises
      SET catalog_active=true,is_visible=true WHERE workshop_key=$1`, [WORKSHOP]);
    await pools.IDENTITY_MIGRATION.query(`UPDATE workshop_platform.objectives
      SET catalog_active=true,is_enabled=true WHERE workshop_key=$1 AND objective_id=ANY($2::text[])`,
    [WORKSHOP, objectiveIds]);
    assert.equal((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int AS n
      FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=ANY($2::text[])
      AND catalog_active AND is_enabled`, [WORKSHOP, objectiveIds])).rows[0].n, 3);
    assert.equal(await assertPersonaInboxReadiness({ identityPool: pools.IDENTITY_RUNTIME,
      agentsPool: pools.AGENTS_RUNTIME,
      migrationPools: { identity: pools.IDENTITY_MIGRATION, agents: pools.AGENTS_MIGRATION } }), true);

    const model = 'llama3.1:8b';
    const baseURL = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
    const actor = new OllamaProvider({ baseUrl: baseURL, model });
    const actualJudge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
      baseURL, model }) });
    let judgeCalls = 0;
    composition = createSecureShopBoundReviewComposition({ identityPool: pools.IDENTITY_RUNTIME,
      agentsPool: pools.AGENTS_RUNTIME, reviewPool: pools.REVIEW_RUNTIME,
      commercePool: pools.COMMERCE_RUNTIME, leasePool,
      agentRuntime: Object.freeze({ provider: actor }),
      jwtSecret: 'owned-persona-auth-live-secret-at-least-32-bytes', personaInboxFeature: true,
      judge: async packet => { judgeCalls += 1; return actualJudge(packet); },
      reviewCardRenderer: Object.freeze({ sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
        async renderReviewCard(review) { return `<article>${review.body}</article>`; } }),
      browserQualification: Object.freeze({ async qualify() { throw new Error('unexpected browser call'); },
        async close() {} }),
    });
    assert.equal(composition.personaInbox.ready, true);
    const app = express(); app.use(express.json());
    app.use('/api/secureshop', createSecureShopBoundGateway({ launches: composition.launches,
      authenticatePersona: composition.personaAuth.authenticatePersona,
      personaAuth: composition.personaAuth, reviewsRouter: composition.router,
      browserRouter: composition.browserRouter, personaInboxRouter: composition.personaInbox.router,
      catalog: composition.catalog, commerce: composition.commerce, account: composition.account }));
    server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    const base = `http://127.0.0.1:${server.address().port}/api/secureshop`;

    const identities = createIdentityRepository(pools.IDENTITY_RUNTIME);
    const passwordHash = await bcrypt.hash('persona-inbox-auth-platform', 4);
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    const ownerUser = await identities.createUser({ username: `persona-auth-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@persona-auth.invalid`, passwordHash });
    failureScope.ownerUserId = ownerUser.id;
    const ownerPlatformSession = await identities.createSession({ userId: ownerUser.id, token: randomUUID(),
      expiresAt, expectedPasswordHash: passwordHash });
    const issued = await composition.launches.issueOrRenew({ platformOwnerId: ownerUser.id,
      platformSessionId: ownerPlatformSession.id, expiresAt });
    failureScope.launchId = issued.binding.launchId;
    const launch = { 'x-owasp-ai-goat-secureshop-launch': issued.bearer };
    const login = await json(await fetch(`${base}/v2/auth/login`, { method: 'POST', headers: {
      ...launch, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'student_merchant', password: 'student123' }) }));
    assert.equal(login.user.username, 'student_merchant'); assert.equal(login.user.role, 'merchant');
    const headers = { ...launch, authorization: `Bearer ${login.token}`, 'content-type': 'application/json' };
    const readiness = await json(await fetch(`${base}/v2/persona-inbox/readiness`, { headers }));
    assert.equal(readiness.ready, true); assert.equal(readiness.capabilities.enforceAcl, true);
    const adminMessage = readiness.messages.find(row => row.ownerShopRole === 'admin');
    assert.ok(adminMessage);
    const target = (await pools.IDENTITY_RUNTIME.query(`SELECT target_id,launch_id,generation,
      original_platform_owner_id FROM identity.secureshop_target_reservations
      WHERE launch_id=$1 AND target_kind='persona_inbox'`, [issued.binding.launchId])).rows;
    assert.equal(target.length, 1);
    const targetId = target[0].target_id;
    failureScope.targetId = targetId;
    assert.equal(Number(target[0].generation), issued.binding.generation);
    assert.equal(Number(target[0].original_platform_owner_id), ownerUser.id);

    const assertAccessChains = async (result, requestId, mode, expectedTerminalCount) => {
      assert.equal(result.stopReason, 'end_turn');
      assert.ok(result.accesses.length >= 1 && result.accesses.length <= 8);
      const sessions = (await pools.AGENTS_RUNTIME.query(`SELECT id FROM secureshop_agents.agent_sessions
        WHERE platform_launch_id=$1 AND platform_launch_generation=$2 ORDER BY created_at,id`,
      [issued.binding.launchId, issued.binding.generation])).rows;
      assert.equal(sessions.length, 1);
      const allTraces = (await pools.AGENTS_RUNTIME.query(`SELECT id,kind,step,agent_ns,tool_name,
          params_json,result_json,provider FROM secureshop_agents.agent_trace
        WHERE session_id=$1 ORDER BY id`, [sessions[0].id])).rows;
      assert.equal(allTraces.filter(row => row.kind === 'terminal').length, expectedTerminalCount);
      assert.equal(allTraces.at(-1)?.kind, 'terminal');
      const priorTerminal = allTraces.slice(0, -1).findLastIndex(row => row.kind === 'terminal');
      const traces = allTraces.slice(priorTerminal + 1);
      assert.equal(traces.filter(row => row.kind === 'terminal').length, 1);
      const effects = (await pools.IDENTITY_RUNTIME.query(`SELECT e.effect_key,e.status,r.status AS run_status
        FROM graph_runtime.effects e JOIN graph_runtime.runs r ON r.run_id=e.run_id
        WHERE e.effect_key LIKE $1 ORDER BY e.effect_key`, [`${requestId}:%`])).rows;
      const readEffects = effects.map(row => {
        const identity = parse(row.effect_key.slice(requestId.length + 1));
        return { ...row, identity };
      }).filter(row => Array.isArray(row.identity) && row.identity[2] === 'persona-inbox.read_message');
      assert.equal(readEffects.length, result.accesses.length);
      for (const effect of readEffects) {
        assert.equal(effect.status, 'completed'); assert.equal(effect.run_status, 'completed');
        const [step, callId] = effect.identity;
        const calls = traces.filter(row => row.kind === 'model_decision' && row.step === step
          && row.provider === 'ollama').flatMap(row => parse(row.params_json)?.toolCalls || [])
          .filter(call => call.id === callId && call.name === 'persona-inbox.read_message'
            && call.args?.message_id === adminMessage.messageId);
        assert.equal(calls.length, 1, `effect ${effect.effect_key} must match one persisted Ollama call`);
      }
      const locals = [];
      const ids = new Set();
      for (const access of result.accesses) {
        assert.equal(ids.has(access.event_id), false); ids.add(access.event_id);
        assert.equal(access.message_id, adminMessage.messageId);
        assert.equal(access.owner_persona_id, adminMessage.ownerShopUserId);
        assert.equal(access.owner_role, adminMessage.ownerShopRole);
        assert.equal(access.acl.mode, mode); assert.equal(access.acl.decision, 'deny');
        assert.equal(access.acl.cross_persona, true);
        assert.equal(access.acl.disclosed, mode === 'advisory');
        const rows = (await pools.AGENTS_RUNTIME.query(`SELECT e.event_id,e.operation_id,e.message_id,
            e.caller_shop_user_id,e.caller_shop_role,e.resource_owner_shop_user_id,e.resource_owner_shop_role,
            e.acl_version,e.acl_mode,e.acl_decision,e.cross_persona,e.disclosed,
            encode(e.body_sha256,'hex') AS body_sha256,m.subject,
            CASE WHEN e.disclosed THEN m.body ELSE NULL END AS body,t.launch_id,t.scenario_id,t.generation,
            t.original_platform_owner_id,t.original_platform_session_id
          FROM secureshop_agents.persona_inbox_access_events e
          JOIN secureshop_agents.persona_inbox_targets t USING(target_id)
          JOIN secureshop_agents.persona_inbox_messages m USING(target_id,message_id)
          WHERE e.target_id=$1 AND e.event_id=$2`, [targetId, access.event_id])).rows;
        assert.equal(rows.length, 1); const source = rows[0];
        assert.equal(source.event_id, access.event_id); assert.equal(source.operation_id, access.event_id);
        assert.equal(source.launch_id, issued.binding.launchId);
        assert.equal(source.scenario_id, issued.binding.scenarioId);
        assert.equal(Number(source.generation), issued.binding.generation);
        assert.equal(Number(source.original_platform_owner_id), ownerUser.id);
        assert.equal(Number(source.original_platform_session_id), ownerPlatformSession.id);
        assert.equal(Number(source.message_id), access.message_id);
        assert.equal(Number(source.caller_shop_user_id), login.user.id);
        assert.equal(source.caller_shop_role, login.user.role);
        assert.equal(Number(source.resource_owner_shop_user_id), access.owner_persona_id);
        assert.equal(source.resource_owner_shop_role, access.owner_role);
        assert.equal(source.subject, access.subject); assert.equal(source.body, access.body);
        assert.equal(source.body_sha256, access.body_sha256);
        assert.equal(Number(source.acl_version), access.acl.version);
        assert.equal(source.acl_mode, access.acl.mode); assert.equal(source.acl_decision, access.acl.decision);
        assert.equal(source.cross_persona, access.acl.cross_persona);
        assert.equal(source.disclosed, access.acl.disclosed);
        const local = traces.filter(row => row.kind === 'local_tool_result'
          && row.agent_ns === 'persona-inbox' && row.tool_name === 'read_message'
          && parse(parse(row.result_json)?.content?.[0]?.text)?.event_id === access.event_id);
        assert.equal(local.length, 1); locals.push(local[0]);
      }
      for (const step of new Set(locals.map(row => row.step))) {
        const stepLocals = locals.filter(row => row.step === step);
        assert.equal(readEffects.filter(row => row.identity[0] === step).length, stepLocals.length,
          `step ${step} must bind one completed request effect per projected event`);
      }
    };

    await pools.COMMERCE_RUNTIME.query(`UPDATE secureshop.shop_users SET role='customer',
      password='mutated-shared-source' WHERE username='student_merchant'`);
    const whoami = await json(await fetch(`${base}/v2/auth/whoami`, { headers }));
    assert.equal(whoami.user.username, 'student_merchant'); assert.equal(whoami.user.role, 'merchant');
    const relogin = await json(await fetch(`${base}/v2/auth/login`, { method: 'POST', headers: {
      ...launch, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'student_merchant', password: 'student123' }) }));
    assert.equal(relogin.user.role, 'merchant', 'authentication uses the immutable persona snapshot');

    const advisoryRequest = randomUUID();
    failureScope.requests.push(advisoryRequest);
    const advisory = await json(await fetch(`${base}/v2/persona-inbox/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: advisoryRequest, message_id: adminMessage.messageId }) }));
    t.diagnostic(JSON.stringify({ checkpoint: 'actual-auth-advisory', requestId: advisoryRequest,
      accesses: advisory.accesses?.map(row => ({ eventId: row.event_id, messageId: row.message_id,
        mode: row.acl?.mode, decision: row.acl?.decision, disclosed: row.acl?.disclosed })) }));
    await assertAccessChains(advisory, advisoryRequest, 'advisory', 1);
    const durableCounts = async () => {
      const [identityCounts, agentCounts] = await Promise.all([
        pools.IDENTITY_RUNTIME.query(`SELECT
          (SELECT count(*)::int FROM graph_runtime.runs) AS runs,
          (SELECT count(*)::int FROM graph_runtime.effects) AS effects,
          (SELECT count(*)::int FROM workshop_platform.objective_judgments WHERE user_id=$1) AS judgments,
          (SELECT count(*)::int FROM workshop_platform.objective_contributions WHERE user_id=$1) AS contributions`,
        [ownerUser.id]),
        pools.AGENTS_RUNTIME.query(`SELECT
          (SELECT count(*)::int FROM secureshop_agents.persona_inbox_access_events) AS events,
          (SELECT count(*)::int FROM secureshop_agents.agent_trace) AS traces,
          (SELECT count(*)::int FROM secureshop_agents.agent_sessions) AS sessions`),
      ]);
      return { ...identityCounts.rows[0], ...agentCounts.rows[0], judgeCalls };
    };
    const beforeReplay = await durableCounts();
    const replay = await json(await fetch(`${base}/v2/persona-inbox/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: advisoryRequest, message_id: adminMessage.messageId }) }));
    assert.equal(replay.replayed, true); assert.deepEqual(replay.accesses, advisory.accesses);
    assert.deepEqual(await durableCounts(), beforeReplay);

    assert.equal((await json(await fetch(`${base}/v2/persona-inbox/enforce`, { method: 'POST',
      headers, body: '{}' }))).acl.mode, 'enforced');
    const enforcedRequest = randomUUID();
    failureScope.requests.push(enforcedRequest);
    const enforced = await json(await fetch(`${base}/v2/persona-inbox/read`, { method: 'POST', headers,
      body: JSON.stringify({ request_id: enforcedRequest, message_id: adminMessage.messageId }) }));
    t.diagnostic(JSON.stringify({ checkpoint: 'actual-auth-enforced', requestId: enforcedRequest,
      accesses: enforced.accesses?.map(row => ({ eventId: row.event_id, messageId: row.message_id,
        mode: row.acl?.mode, decision: row.acl?.decision, disclosed: row.acl?.disclosed })) }));
    await assertAccessChains(enforced, enforcedRequest, 'enforced', 2);
    assert.ok(enforced.accesses.every(row => row.body === null && row.body_sha256 === null));
    const contributionRows = (await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,evaluation_id,
        platform_launch_generation
      FROM workshop_platform.objective_contributions WHERE user_id=$1 AND platform_launch_id=$2
      ORDER BY objective_id`, [ownerUser.id, issued.binding.launchId])).rows;
    const contributions = contributionRows.map(row => row.objective_id);
    assert.deepEqual(contributions, [...objectiveIds].sort()); assert.ok(judgeCalls >= 3);
    assert.ok(contributionRows.every(row => Number(row.platform_launch_generation) === 1));
    const judgments = (await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,evaluation_id,verdict,result_json,run_id
      FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id=ANY($2::text[])`,
    [ownerUser.id, objectiveIds])).rows;
    for (const objectiveId of objectiveIds) {
      const accepted = judgments.find(row => row.objective_id === objectiveId && row.verdict === 'pass');
      assert.ok(accepted, `${objectiveId} requires an independent Judge pass`);
      assert.equal(accepted.result_json.provider, 'ollama'); assert.equal(accepted.result_json.model, model);
    }
    for (const [objectiveId, requestId] of [[OBJECTIVES.cross, advisoryRequest],
      [OBJECTIVES.advisory, advisoryRequest], [OBJECTIVES.enforced, enforcedRequest]]) {
      const contribution = contributionRows.find(row => row.objective_id === objectiveId);
      const packetText = (await pools.IDENTITY_RUNTIME.query(`SELECT packet
        FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2`,
      [ownerUser.id, contribution.evaluation_id])).rows[0]?.packet;
      const packet = JSON.parse(packetText);
      const chains = packet.evidence.filter(row => row.id === 'persona_inbox_chain'
        && row.source === 'server_observation');
      assert.equal(chains.length, 1); const chain = chains[0].content;
      assert.equal(chain.requestId, requestId); assert.equal(chain.targetId, targetId);
      assert.equal(chain.messageId, adminMessage.messageId);
      assert.equal(chain.modelCall.tool, 'persona-inbox.read_message');
      assert.equal(chain.modelCall.args.message_id, adminMessage.messageId);
      assert.equal(chain.effectReceipt.status, 'completed');
      assert.equal(chain.effectReceipt.runId, judgments.find(row => row.evaluation_id === contribution.evaluation_id
        && row.objective_id === objectiveId && row.verdict === 'pass').run_id);
      assert.equal(chain.effectReceipt.effectKey,
        `${requestId}:${JSON.stringify([chain.modelCall.step, chain.modelCall.callId,
          'persona-inbox.read_message'])}`);
    }
    const traces = (await pools.AGENTS_RUNTIME.query(`SELECT t.kind,t.provider,t.params_json,t.result_json
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.platform_launch_id=$1 ORDER BY t.id`,
    [issued.binding.launchId])).rows;
    assert.ok(traces.some(row => row.kind === 'model_decision' && row.provider === 'ollama'
      && JSON.parse(row.params_json)?.toolCalls?.some(call => call.name === 'persona-inbox.read_message')));
    assert.ok(traces.some(row => row.kind === 'local_tool_result'
      && JSON.parse(row.result_json)?.content?.[0]?.text.includes('"mode":"enforced"')));

    const siblingUser = await identities.createUser({ username: `persona-auth-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@persona-auth.invalid`, passwordHash });
    const siblingPlatformSession = await identities.createSession({ userId: siblingUser.id, token: randomUUID(),
      expiresAt, expectedPasswordHash: passwordHash });
    const siblingLaunch = await composition.launches.issueOrRenew({ platformOwnerId: siblingUser.id,
      platformSessionId: siblingPlatformSession.id, expiresAt });
    const siblingHeader = { 'x-owasp-ai-goat-secureshop-launch': siblingLaunch.bearer };
    const siblingLogin = await json(await fetch(`${base}/v2/auth/login`, { method: 'POST', headers: {
      ...siblingHeader, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'student_merchant', password: 'student123' }) }));
    assert.equal((await fetch(`${base}/v2/persona-inbox/readiness`, { headers: { ...siblingHeader,
      authorization: `Bearer ${login.token}` } })).status, 401);
    const siblingHeaders = { ...siblingHeader, authorization: `Bearer ${siblingLogin.token}` };
    assert.equal((await json(await fetch(`${base}/v2/persona-inbox/readiness`, {
      headers: siblingHeaders }))).messages.length, 3);

    await json(await fetch(`${base}/v2/auth/logout`, { method: 'POST', headers, body: '{}' }));
    assert.equal((await fetch(`${base}/v2/persona-inbox/readiness`, { headers })).status, 401);
    const reset = await composition.launchResetCoordinator.reset({ launchId: issued.binding.launchId,
      platformOwnerId: ownerUser.id, platformSessionId: ownerPlatformSession.id,
      expectedGeneration: issued.binding.generation, idempotencyKey: `persona-auth-${randomUUID()}` });
    assert.equal(reset.status, 'committed'); assert.equal(reset.targets, 1);
    assert.deepEqual((await pools.IDENTITY_RUNTIME.query(`SELECT objective_id,evaluation_id,
        platform_launch_generation FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=1 ORDER BY objective_id`,
    [ownerUser.id, issued.binding.launchId])).rows, contributionRows,
    'reset preserves exact immutable generation-one contribution identities');
    assert.equal((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int AS n
      FROM workshop_platform.objective_contributions WHERE user_id=$1 AND platform_launch_id=$2
      AND platform_launch_generation=2`, [ownerUser.id, issued.binding.launchId])).rows[0].n, 0);
    assert.equal((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int AS n
      FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2`,
    [ownerUser.id, WORKSHOP])).rows[0].n, 0);
    const cleanup = (await pools.IDENTITY_RUNTIME.query(`SELECT target_kind,operation_id
      FROM identity.secureshop_target_cleanup_history WHERE target_id=$1`, [targetId])).rows;
    assert.deepEqual(cleanup, [{ target_kind: 'persona_inbox', operation_id: reset.resetId }]);
    assert.equal((await fetch(`${base}/v2/persona-inbox/readiness`, { headers: {
      ...launch, authorization: `Bearer ${relogin.token}` } })).status, 401);
    const siblingAfter = await json(await fetch(`${base}/v2/persona-inbox/readiness`, {
      headers: siblingHeaders }));
    assert.equal(siblingAfter.ready, true); assert.equal(siblingAfter.messages.length, 3);
    assert.equal((await pools.IDENTITY_RUNTIME.query(`SELECT count(*)::int AS n
      FROM workshop_platform.objective_contributions WHERE user_id=$1`, [siblingUser.id])).rows[0].n, 0);
    t.diagnostic(JSON.stringify({ checkpoint: 'actual-auth-mounted', advisoryRequest, enforcedRequest,
      judgeCalls, objectives: contributions, resetId: reset.resetId, siblingLaunch: siblingLaunch.binding.launchId }));
  } catch (error) {
    const diagnostic = { checkpoint: 'actual-auth-private-failure', error: safeError(error),
      scope: { ownerUserId: failureScope.ownerUserId || null, launchId: failureScope.launchId || null,
        targetId: failureScope.targetId || null, requestIds: [...failureScope.requests] } };
    const diagnostics = [];
    if (failureScope.requests.length) diagnostics.push(['effects', pools.IDENTITY_RUNTIME.query(`SELECT
        e.effect_key,e.status,e.run_id,r.status AS run_status,r.generation
      FROM graph_runtime.effects e JOIN graph_runtime.runs r USING(run_id)
      WHERE ${failureScope.requests.map((_, index) => `e.effect_key LIKE $${index + 1}`).join(' OR ')}
      ORDER BY e.updated_at,e.effect_key LIMIT 64`, failureScope.requests.map(value => `${value}:%`))]);
    if (failureScope.ownerUserId) diagnostics.push(['grades', pools.IDENTITY_RUNTIME.query(`SELECT
        j.evaluation_id,j.objective_id,j.verdict,j.disposition,j.run_id,
        j.result_json->>'provider' AS provider,j.result_json->>'model' AS model,
        p.packet
      FROM workshop_platform.objective_judgments j
      LEFT JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      WHERE j.user_id=$1 ORDER BY j.created_at,j.evaluation_id LIMIT 32`, [failureScope.ownerUserId])]);
    if (failureScope.launchId) diagnostics.push(['traces', pools.AGENTS_RUNTIME.query(`SELECT
        t.id,t.session_id,t.kind,t.step,t.agent_ns,t.tool_name,t.params_json,t.result_json,t.provider
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.platform_launch_id=$1 ORDER BY t.id LIMIT 128`, [failureScope.launchId])]);
    if (failureScope.targetId) diagnostics.push(['accesses', pools.AGENTS_RUNTIME.query(`SELECT
        event_id,operation_id,message_id,caller_shop_user_id,caller_shop_role,
        resource_owner_shop_user_id,resource_owner_shop_role,acl_version,acl_mode,
        acl_decision,cross_persona,disclosed
      FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1
      ORDER BY created_at,event_id LIMIT 64`, [failureScope.targetId])]);
    const settled = await Promise.allSettled(diagnostics.map(([, query]) => query));
    settled.forEach((result, index) => {
      const name = diagnostics[index][0];
      if (result.status === 'rejected') diagnostic[name] = { error: safeError(result.reason) };
      else if (name === 'traces') diagnostic[name] = result.value.rows.map(traceShape);
      else if (name === 'grades') diagnostic[name] = result.value.rows.map(row => {
        const packet = parse(row.packet); return { evaluationId: row.evaluation_id,
          objectiveId: row.objective_id, verdict: row.verdict, disposition: row.disposition,
          runId: row.run_id, provider: row.provider, model: row.model,
          packetShape: packet && typeof packet === 'object' ? Object.keys(packet).sort() : null,
          evidenceIds: Array.isArray(packet?.evidence) ? packet.evidence.slice(0, 32).map(item => item?.id || null) : [] };
      }); else diagnostic[name] = result.value.rows;
    });
    t.diagnostic(JSON.stringify(diagnostic));
    throw error;
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    if (composition) await composition.closeBrowserAssessment();
    await Promise.allSettled([leasePool.end(), ...Object.values(pools).map(pool => pool.end())]);
  }
});
