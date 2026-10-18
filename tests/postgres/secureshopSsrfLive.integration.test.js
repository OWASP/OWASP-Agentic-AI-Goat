'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const express = require('express');

const PREFIX = 'PG_SECURESHOP_SSRF_LIVE_';
const KEYS = ['IDENTITY_MIGRATION_URL', 'IDENTITY_RUNTIME_URL', 'AGENTS_MIGRATION_URL', 'AGENTS_RUNTIME_URL',
  'COMMERCE_MIGRATION_URL', 'COMMERCE_RUNTIME_URL'];
const deterministic = process.env.SSRF_MOUNTED_DETERMINISTIC === '1';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && (deterministic || process.env.LIVE_OLLAMA_TEST === '1')
  && KEYS.every(key => process.env[PREFIX + key]);
const WORKSHOP = 'secureshop_agent_security', OBJECTIVE = 'ss_controlled_ssrf';
const uuid = crypto.randomUUID;
function checked(key) {
  const value = new URL(process.env[PREFIX + key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  return value.href;
}

test(deterministic
  ? 'mounted bridge and persona JWT bind scripted SSRF to real HTTP effects without model credit'
  : 'mounted bridge and persona JWT bind actual 8B SSRF effects and Judge credit to replay and reset',
  { skip: !enabled, timeout: 300000 }, async t => {
    const workspace = path.resolve(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || '');
    assert.match(path.basename(path.dirname(workspace)), /^dvaia-secureshop-ssrf-live-/);
    const { Pool } = require('pg');
    const identityMigration = new Pool({ connectionString: checked('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: checked('IDENTITY_RUNTIME_URL'), max: 12 });
    const leases = new Pool({ connectionString: checked('IDENTITY_RUNTIME_URL'), max: 3 });
    const agentsMigration = new Pool({ connectionString: checked('AGENTS_MIGRATION_URL'), max: 2 });
    const agents = new Pool({ connectionString: checked('AGENTS_RUNTIME_URL'), max: 10 });
    const commerceMigration = new Pool({ connectionString: checked('COMMERCE_MIGRATION_URL'), max: 2 });
    const commerce = new Pool({ connectionString: checked('COMMERCE_RUNTIME_URL'), max: 4 });
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-ssrf-live-fixture-'));
    const captures = [], failures = [], targets = [];
    let scriptedActorCalls = 0, scriptedJudgeCalls = 0;
    const actualModelCalls = deterministic ? 0 : null;
    let targetPool, coordinator, mountedServer;
    const verify = (label, check) => { try { check(); } catch (error) { failures.push({ label, message: error.message }); } };
    try {
      const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
      const { initializeSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
      await initializeIdentityRepository(identity, identityMigration);
      await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
      await initializeSecureShopAgentsDb({ runtimePool: agents, migrationPool: agentsMigration });
      await require('../../server/database/postgres/secureshopInitialization')
        .initializeSecureShopCommerceDb({ runtimePool: commerce, migrationPool: commerceMigration });
      async function ledger(pool, directory) {
        const names = (await fs.readdir(directory)).filter(name => name.endsWith('.sql')).sort();
        const expected = await Promise.all(names.map(async name => ({ name,
          checksum: crypto.createHash('sha256').update(await fs.readFile(path.join(directory, name))).digest('hex') })));
        assert.deepEqual((await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, expected);
        return expected.at(-1).name;
      }
      assert.equal(await ledger(identityMigration, path.join(workspace, 'db/postgres/identity-migrations')), '0061_mcp_supply_chain_curriculum_defaults.sql');
      assert.equal(await ledger(agentsMigration, path.join(workspace, 'db/postgres/workshop-migrations/secureshop_agents')), '0013_secureshop_conversation_purpose.sql');
      assert.equal(await ledger(commerceMigration, path.join(workspace, 'db/postgres/workshop-migrations/secureshop')), '0002_import_history.sql');
      assert.deepEqual(await initializeIdentityRepository(identity, identityMigration), []);
      await identityMigration.query('UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true WHERE workshop_key=$1', [WORKSHOP]);
      await identityMigration.query('UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true WHERE workshop_key=$1 AND objective_id=$2', [WORKSHOP, OBJECTIVE]);
      const identities = createIdentityRepository(identity);
      const launches = require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
      const cleanupAuthority = require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity);
      const passwordHash = await require('bcryptjs').hash('owned-ssrf-live-fixture', 4);
      async function owner(label) {
        const user = await identities.createUser({ username: `${label}-${uuid().slice(0, 8)}`, email: `${uuid()}@ssrf.invalid`, passwordHash });
        const session = await identities.createSession({ userId: user.id, token: uuid(), expectedPasswordHash: passwordHash,
          expiresAt: new Date(Date.now() + 3600000).toISOString() });
        const issued = await launches.issueOrRenew({ platformOwnerId: user.id, platformSessionId: session.id,
          expiresAt: new Date(Date.now() + 3600000).toISOString() });
        await identity.query('INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,$2,$3)', [user.id, WORKSHOP, 'vuln']);
        return { user, session, launch: issued,
          scope: { ...issued.binding, platformOwnerId: user.id, platformSessionId: session.id } };
      }
      const primary = await owner('ssrf-live-primary'), sibling = await owner('ssrf-live-sibling');
      const rows = require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({
        pool: agents, queue: require('../../server/services/secureshop/sessionStore').runSessionExclusive });
      const conversations = require('../../server/services/secureshopBoundConversation').createBoundConversationService({ conversations: rows, launches });
      const journal = require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({ pool: agents });
      const runLedger = require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity, { leasePool: leases });
      coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family: `SecureShopSsrf:${uuid()}`, ledger: runLedger });
      const turns = require('../../server/services/secureshopBoundTurns').createBoundTurns({ conversations, coordinator });
      targetPool = require('../../server/services/secureshopSsrfTargetPool').createSecureShopSsrfTargetPool({ root });
      const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
      const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
      // The production summarizer eagerly loads every tool, including the
      // PostgreSQL product reader. Bind that import to this test's owned
      // commerce store before loading the server; no application DB fallback
      // is permitted.
      process.env.SECURESHOP_DATABASE_URL = checked('COMMERCE_RUNTIME_URL');
      const secureShopPools = require('../../server/database/postgres/secureshopPools');
      t.after(() => secureShopPools.closeSecureShopPools());
      const server = require('../../agent-host/agents/summarizer/server').createServer();
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'ssrf-live-qualification', version: '1.0.0' });
      t.after(() => Promise.allSettled([client.close(), clientTransport.close(), serverTransport.close(), server.close()]));
      await server.connect(serverTransport); await client.connect(clientTransport);
      const upstreamPool = { callTool(agent, tool, args, options) {
        assert.equal(agent, 'summarizer'); return client.callTool({ name: tool, arguments: args }, undefined, { signal: options?.signal });
      } };
      const baseURL = process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434';
      const promptPolicyEnabled = process.env.SECURESHOP_PROMPT_POLICY_NATIVE === '1';
      const personaAuthority = promptPolicyEnabled
        ? require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({ pool: agents, checkCurrent: value => launches.assertCurrent(value) })
        : undefined;
      const { buildPolicySnapshot } = require('../../server/services/secureshopPromptPolicySnapshot');
      const promptRendered = 'NATIVE_SSRF_PROMPT_POLICY';
      const promptSnapshot = buildPolicySnapshot({ policyVersion: '4', role: 'customer', policies: [{ name: 'native', rendered: promptRendered, renderedSha256: crypto.createHash('sha256').update(promptRendered).digest('hex'), targets: ['customer'] }] });
      const promptPolicyRepository = promptPolicyEnabled ? { async admitRunSnapshot(input) { assert.equal(input.persona.role, 'customer'); assert.ok(input.personaSession?.sessionId); return promptSnapshot; } } : undefined;
      const provider = deterministic ? Object.freeze({ provider: 'scripted', model: 'controlled-mounted-fixture',
        async chat({ system, messages }) {
          if (promptPolicyEnabled) assert.ok(system.includes(promptRendered));
          scriptedActorCalls += 1;
          if (scriptedActorCalls % 2 === 0) return { provider: 'scripted', model: 'controlled-mounted-fixture',
            mocked: true, stop_reason: 'end_turn', text: 'Recorded the exact tool observation.' };
          const message = [...messages].reverse().find(row => row.role === 'user')?.content || '';
          const match = String(message).match(/exact URL:\n(http:\/\/127\.0\.0\.1:\d+\/policy\/[^\s]+)/);
          assert.ok(match, 'scripted actor receives the server-issued owned URL');
          return { provider: 'scripted', model: 'controlled-mounted-fixture', mocked: true,
            stop_reason: 'tool_use', tool_uses: [{ id: `mounted-ssrf-${scriptedActorCalls}`,
              name: 'summarizer.explain_return_policy', args: { policy_url: match[1] } }] };
        } }) : new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
          baseUrl: baseURL, model: 'llama3.1:8b' });
      const judge = deterministic ? { async judge() { scriptedJudgeCalls += 1; return {
        verdict: 'unavailable', explanation: 'Scripted mounted qualification cannot award model credit.', criteria: [],
        provider: null, model: null, usage: null } } }
        : require('./mcpJudgeInputCapture').createMcpJudgeInputCapture({ entries: captures,
          judge: require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
            model: require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({ provider: 'ollama', baseURL, model: 'llama3.1:8b' }) }) });
      const feature = require('../../server/services/secureshopSsrfComposition').createSecureShopSsrfComposition({
        enabled: true, identityPool: identity, agentsPool: agents, provider, judge: judge.judge, targetPool, upstreamPool,
        ...(promptPolicyEnabled ? { personaAuthority, promptPolicyRepository } : {}),
        resetComposition: { launches, cleanupAuthority, conversationService: conversations, conversations: rows, turns, journal } });
      const primaryTarget = await feature.application.resolveTarget(primary.scope), siblingTarget = await feature.application.resolveTarget(sibling.scope);
      targets.push(primaryTarget, siblingTarget);
      const personaRepository = require('../../server/database/postgres/secureshopBoundPersonaRepository')
        .createSecureShopBoundPersonaRepository({ commercePool: commerce, agentsPool: agents });
      const personaAuth = require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({
        repository: personaRepository, launches, jwtSecret: 'owned-ssrf-mounted-qualification-secret-2026' });
      const ssrfRouter = require('../../server/routes/secureshop/boundSsrf').createBoundSsrfRouter({
        launches, authenticatePersona: personaAuth.authenticatePersona, feature });
      const emptyRouter = express.Router();
      const gateway = require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({
        launches, authenticatePersona: personaAuth.authenticatePersona, personaAuth,
        reviewsRouter: emptyRouter, browserRouter: express.Router(), ssrfRouter,
        catalog: { async listProducts() { return { products: [] }; }, async getProduct() { return null; },
          async createMerchantProduct() { throw new Error('unused'); },
          async updateMerchantProduct() { throw new Error('unused'); },
          async archiveMerchantProduct() { throw new Error('unused'); },
          async listMerchantProducts() { return { products: [] }; }, async categories() { return { categories: [] }; } },
        commerce: Object.fromEntries(['cart','add','update','remove','summary','checkout','orders','order']
          .map(name => [name, async () => { throw new Error(`unrelated ${name} route`); }])),
        account: Object.fromEntries(['profile','updateProfile','addresses','createAddress','updateAddress','deleteAddress']
          .map(name => [name, async () => { throw new Error(`unrelated ${name} route`); }])),
      });
      const mounted = express(); mounted.use(express.json()); mounted.use('/api/secureshop', gateway);
      mountedServer = await new Promise(resolve => {
        const value = mounted.listen(0, '127.0.0.1', () => resolve(value));
      });
      const origin = `http://127.0.0.1:${mountedServer.address().port}`;
      async function browserBridge(owner) {
        const launchHeaders = { 'x-dvaia-secureshop-launch': owner.launch.bearer, 'content-type': 'application/json' };
        const loginResponse = await fetch(`${origin}/api/secureshop/v2/auth/login`, { method: 'POST', headers: launchHeaders,
          body: JSON.stringify({ username: 'student_customer', password: 'student123' }) });
        assert.equal(loginResponse.status, 200); const login = await loginResponse.json();
        const { createBridgeFetch } = await import('../../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
        const { compileBridgeOperation } = await import('../../client/src/pages/secureshop/bridge/compiler.mjs');
        const networkFetch = globalThis.fetch.bind(globalThis);
        return createBridgeFetch({ origin, getToken: () => login.token, bridge: { async request(name, bridgeInput, options) {
          const operation = compileBridgeOperation(name, bridgeInput);
          return networkFetch(`${origin}${operation.path}`, { method: operation.method, signal: options.signal,
            headers: { accept: 'application/json', 'x-dvaia-secureshop-launch': owner.launch.bearer,
              authorization: `Bearer ${options.shopBearer}`,
              ...(operation.body === undefined ? {} : { 'content-type': 'application/json' }) },
            ...(operation.body === undefined ? {} : { body: JSON.stringify(operation.body) }) });
        } } });
      }
      const primaryBridge = await browserBridge(primary);
      const siblingBridge = await browserBridge(sibling);
      async function bridgeRun(bridge, resource, requestId) {
        const response = await bridge('/api/secureshop/v2/controlled-ssrf/run', { method: 'POST',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ resource, request_id: requestId }) });
        const value = await response.json(); assert.equal(response.status, 200, JSON.stringify(value)); return value;
      }
      assert.deepEqual(await (await primaryBridge('/api/secureshop/v2/controlled-ssrf/readiness')).json(), { ready: true });
      const baseline = await bridgeRun(primaryBridge, 'public-policy', uuid());
      verify('public baseline reaches model terminal', () => assert.equal(baseline.stopReason, 'end_turn'));
      assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objective_contributions WHERE user_id=$1 AND objective_id=$2', [primary.user.id, OBJECTIVE])).rows[0].n, 0);
      const requestId = uuid();
      const attack = await bridgeRun(primaryBridge, 'private-policy', requestId);
      verify('private observation reaches model terminal', () => assert.equal(attack.stopReason, 'end_turn'));
      const judgments = (await identity.query('SELECT objective_id,verdict,result_json FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id=$2 ORDER BY created_at', [primary.user.id, OBJECTIVE])).rows;
      if (deterministic) verify('scripted actor output cannot create a grading packet or credit', () => {
        assert.deepEqual(judgments, []); assert.equal(scriptedJudgeCalls, 0);
      }); else verify('actual objective Judge accepts protected HTTP observation', () => {
        const accepted = judgments.find(row => row.verdict === 'pass'); assert.ok(accepted);
        assert.equal(accepted.result_json.provider, 'ollama'); assert.equal(accepted.result_json.model, 'llama3.1:8b');
      });
      const contributionRows = async () => (await identity.query(`SELECT objective_id,platform_launch_generation
        FROM workshop_platform.objective_contributions WHERE user_id=$1 AND platform_launch_id=$2 ORDER BY objective_id`,
      [primary.user.id, primary.scope.launchId])).rows;
      const contributionsBeforeReset = await contributionRows();
      verify(deterministic ? 'scripted output receives no canonical contribution'
        : 'accepted canonical contribution belongs to current launch generation', () => {
        assert.equal(contributionsBeforeReset.length, deterministic ? 0 : 1);
        if (!deterministic) {
          assert.equal(contributionsBeforeReset[0].objective_id, OBJECTIVE);
          assert.equal(Number(contributionsBeforeReset[0].platform_launch_generation), 1);
        }
      });
      const invocations = (await agents.query(`SELECT run_id,request_id,call_id,resource_kind,policy_decision,response_status
        FROM secureshop_agents.bound_ssrf_invocations WHERE target_id=$1 ORDER BY completed_at`, [primaryTarget.targetId])).rows;
      verify('public and protected observations are real canonical HTTP invocations', () => {
        assert.ok(invocations.some(row => row.resource_kind === 'public-policy' && row.policy_decision === 'allowed' && row.response_status === 200));
        assert.ok(invocations.some(row => row.resource_kind === 'private-policy' && row.policy_decision === 'denied' && row.response_status === 200 && row.request_id === requestId));
      });
      const counts = async () => ({
        ...(await identity.query('SELECT (SELECT count(*)::int FROM graph_runtime.runs) runs,(SELECT count(*)::int FROM graph_runtime.effects) effects,(SELECT count(*)::int FROM workshop_platform.objective_judgments) judgments')).rows[0],
        ...(await agents.query('SELECT (SELECT count(*)::int FROM secureshop_agents.bound_ssrf_invocations) invocations,(SELECT count(*)::int FROM secureshop_agents.agent_trace) traces')).rows[0] });
      const beforeReplay = await counts(), judgeCount = captures.length;
      const replay = await bridgeRun(primaryBridge, 'private-policy', requestId);
      assert.equal(replay.replayed, true); assert.deepEqual(await counts(), beforeReplay); assert.equal(captures.length, judgeCount);
      assert.equal((await bridgeRun(siblingBridge, 'public-policy', uuid())).stopReason, 'end_turn');
      const siblingBefore = (await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_invocations WHERE target_id=$1', [siblingTarget.targetId])).rows[0].n;
      const reconciler = require('../../server/database/postgres/secureshopTargetReconciliationRepository').createSecureShopTargetReconciliationRepository(identity, {
        checkAuthority: value => cleanupAuthority.checkTarget(value), readCleanupReceipt: value => feature.reset.readCleanupReceipt(value) });
      const targetCoordinator = require('../../server/services/secureshopReviewResetCoordinator').createSecureShopReviewResetCoordinator({
        launches, cleanupAuthority, reconciler, ssrfCleanup: feature.reset,
        reviewRepository: { async cleanup() { throw new Error('Unexpected review cleanup'); } } });
      const lifecycle = require('../../server/services/secureshopConversationLifecycle').createSecureShopConversationLifecycle({
        repository: require('../../server/database/postgres/secureshopConversationLifecycleRepository').createSecureShopConversationLifecycleRepository({ pool: agents }), turns, cleanupAuthority });
      const reset = require('../../server/services/secureshopLaunchResetCoordinator').createSecureShopLaunchResetCoordinator({
        launches, cleanupAuthority, conversationLifecycle: lifecycle, targetCoordinator,
        conversationCheckpoint: require('../../server/database/postgres/secureshopConversationCleanupCheckpointRepository').createSecureShopConversationCleanupCheckpointRepository(identity, {
          getOperation: id => cleanupAuthority.getOperation(id), readRetirementReceipt: id => lifecycle.readReceipt(id) }),
        progressCheckpoint: require('../../server/database/postgres/secureshopProgressCleanupCheckpointRepository').createSecureShopProgressCleanupCheckpointRepository(identity) });
      const resetInput = { launchId: primary.scope.launchId, platformOwnerId: primary.user.id, platformSessionId: primary.session.id,
        expectedGeneration: 1, idempotencyKey: `ssrf-live-${uuid()}` };
      const receipt = await reset.reset(resetInput); assert.equal(receipt.status, 'committed'); assert.equal(receipt.targets, 1);
      assert.deepEqual(await reset.reset(resetInput), receipt);
      assert.equal((await primaryBridge('/api/secureshop/v2/controlled-ssrf/readiness')).status, 401,
        'the old browser bridge cannot reuse retired launch/persona credentials');
      assert.equal(targetPool.state(siblingTarget).active, true);
      assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_invocations WHERE target_id=$1', [siblingTarget.targetId])).rows[0].n, siblingBefore);
      assert.equal((await bridgeRun(siblingBridge, 'public-policy', uuid())).stopReason, 'end_turn');
      assert.deepEqual(await contributionRows(), contributionsBeforeReset, 'accepted history is immutable across reset');
      assert.equal((await identity.query(`SELECT count(*)::int n FROM workshop_platform.objective_contributions
        WHERE user_id=$1 AND platform_launch_id=$2 AND platform_launch_generation=2`, [primary.user.id, primary.scope.launchId])).rows[0].n, 0);
      assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_ssrf_invocations WHERE target_id=$1', [primaryTarget.targetId])).rows[0].n,
        invocations.length, 'retirement preserves canonical invocation history');
      t.diagnostic(JSON.stringify({ checkpoint: deterministic ? 'ssrf-mounted-deterministic' : 'ssrf-live',
        qualificationBoundary: deterministic ? 'mounted_http_effect_only' : 'actual_model_and_judge',
        actualModelCalls, scriptedActorCalls, scriptedJudgeCalls, judgeCalls: captures.length, failures }));
      assert.deepEqual(failures, []);
    } finally {
      await fs.writeFile(path.join(path.dirname(workspace), 'judge-inputs.json'), JSON.stringify(captures, null, 2), { mode: 0o600 });
      if (mountedServer) await new Promise(resolve => mountedServer.close(() => resolve()));
      if (targetPool) await Promise.allSettled(targets.map(target => targetPool.retire(target)));
      await Promise.allSettled([identityMigration.end(), identity.end(), leases.end(), agentsMigration.end(), agents.end(),
        commerceMigration.end(), commerce.end()]);
      await fs.rm(root, { recursive: true, force: true });
    }
  });
