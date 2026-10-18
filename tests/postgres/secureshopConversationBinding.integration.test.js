'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createSecureShopAgentsDb } = require('../../server/database/postgres/secureshopAgentsDb');
const { createSecureShopCustomerRepository } = require('../../server/database/postgres/secureshopCustomerRepository');
const { createSecureShopMerchantRepository } = require('../../server/database/postgres/secureshopMerchantRepository');
const { createSecureShopAdminRepository } = require('../../server/database/postgres/secureshopAdminRepository');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createBoundGraphStore } = require('../../server/services/secureshopBoundGraphStore');
const { createSupervisorGraph } = require('../../server/agent-runtime/secureshopSupervisorGraph');

const PREFIX = 'PG_SECURESHOP_CONVERSATION_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[`${PREFIX}_MIGRATION_URL`])
  && Boolean(process.env[`${PREFIX}_RUNTIME_URL`]);

function boundRow(overrides = {}) {
  return {
    id: randomUUID(),
    userId: 17,
    role: 'customer',
    launchId: randomUUID(),
    scenarioId: randomUUID(),
    generation: 7,
    ownerId: 41,
    platformSessionId: 83,
    state: 'pending',
    ...overrides,
  };
}

function rowBinding(row) {
  return Object.freeze({
    launchId: row.launchId,
    scenarioId: row.scenarioId,
    generation: row.generation,
    platformOwnerId: row.ownerId,
    platformSessionId: row.platformSessionId,
    shopUserId: row.userId,
    role: row.role,
  });
}

async function insertBound(pool, row) {
  return pool.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,'launch_bound',$4,$5,$6,$7,$8,$9)`, [
    row.id,
    row.userId,
    row.role,
    row.state,
    row.launchId,
    row.scenarioId,
    row.generation,
    row.ownerId,
    row.platformSessionId,
  ]);
}

test('native SecureShop conversation binding upgrades legacy rows and enforces immutable lifecycle', {
  skip: !enabled,
  timeout: 60000,
}, async (t) => {
  const urls = ['MIGRATION', 'RUNTIME'].map((suffix) => new URL(process.env[`${PREFIX}_${suffix}_URL`]));
  for (const url of urls) {
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(urls[0].pathname, urls[1].pathname);

  const migration = new Pool({ connectionString: process.env[`${PREFIX}_MIGRATION_URL`], max: 1 });
  const runtime = new Pool({ connectionString: process.env[`${PREFIX}_RUNTIME_URL`], max: 2 });
  t.after(async () => Promise.all([migration.end(), runtime.end()]));
  assert.equal((await migration.query("SELECT to_regnamespace('secureshop_agents') AS present")).rows[0].present, null);

  const baseSql = await fs.readFile(path.join(
    __dirname,
    '../../db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
  ), 'utf8');
  const draftSql = await fs.readFile(path.join(
    __dirname,
    '../../db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
  ), 'utf8');
  await migration.query(baseSql);
  await runtime.query("INSERT INTO secureshop_agents.agent_sessions(id,user_id,role) VALUES('legacy-before',5,'historical-role')");
  await t.test('legacy repository predicates execute before the binding columns exist', async () => {
    const commerceStub = {
      async query() {
        return { rows: [{ total_users: 0, total_products: 0, total_orders: 0,
          total_revenue: 0, admin_count: 0, banned_count: 0 }], fields: [] };
      },
    };
    const agents = createSecureShopAgentsDb(runtime);
    const customer = createSecureShopCustomerRepository(commerceStub, runtime);
    const merchant = createSecureShopMerchantRepository({ commercePool: commerceStub, agentsPool: runtime });
    const admin = createSecureShopAdminRepository(commerceStub, runtime);
    assert.deepEqual(await agents.getSession('legacy-before'), {
      id: 'legacy-before', userId: 5, role: 'historical-role',
    });
    await agents.appendMessage('legacy-before', { role: 'user', content: 'pre-migration' });
    await agents.addTokens('legacy-before', 2);
    await agents.appendTraces([{ event_id: 'pre-binding-trace', session_id: 'legacy-before',
      step: 1, actor: 'supervisor', kind: 'pre-migration' }]);
    assert.equal((await agents.getMessages('legacy-before'))[0].content, 'pre-migration');
    assert.equal(await agents.getTokens('legacy-before'), 2);
    assert.equal((await agents.getTrace('legacy-before')).length, 1);
    assert.equal((await customer.latestTrace({ userId: 5, role: 'historical-role', limit: 1 })).length, 1);
    assert.equal((await customer.sessionTrace('legacy-before')).length, 1);
    assert.equal((await merchant.latestMerchantTrace({ userId: 5, role: 'historical-role', limit: 1 })).length, 1);
    assert.equal((await merchant.merchantTrace('legacy-before')).length, 1);
    assert.equal((await admin.latestTrace({ userId: 5, role: 'historical-role', limit: 1 })).length, 1);
    assert.equal((await admin.trace('legacy-before')).length, 1);
    assert.equal((await admin.kpis()).active_sessions, 1);
  });
  await migration.query(draftSql);

  await t.test('populated upgrade and later default inserts remain legacy-compatible', async () => {
    await runtime.query("INSERT INTO secureshop_agents.agent_sessions(id,user_id,role) VALUES('legacy-after',6,'merchant')");
    const rows = (await runtime.query(`SELECT id,user_id,role,authority_mode,binding_state,
      platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id
      FROM secureshop_agents.agent_sessions WHERE id LIKE 'legacy-%' ORDER BY id`)).rows;
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.equal(row.authority_mode, 'legacy');
      assert.equal(row.binding_state, 'active');
      for (const field of ['platform_launch_id', 'platform_scenario_id', 'platform_launch_generation',
        'original_platform_owner_id', 'original_platform_session_id']) assert.equal(row[field], null);
    }
    await runtime.query("UPDATE secureshop_agents.agent_sessions SET user_id=9,role='legacy-updated',messages_json='[{}]',token_budget_used=-1 WHERE id='legacy-before'");
    assert.deepEqual((await runtime.query("SELECT user_id,role,messages_json,token_budget_used FROM secureshop_agents.agent_sessions WHERE id='legacy-before'")).rows[0], {
      user_id: 9,
      role: 'legacy-updated',
      messages_json: '[{}]',
      token_budget_used: -1,
    });
    await assert.rejects(
      runtime.query("UPDATE secureshop_agents.agent_sessions SET authority_mode='launch_bound' WHERE id='legacy-before'"),
      /immutable/,
    );
  });

  await t.test('bound rows require one complete exact coordinate set and pending initial state', async () => {
    const valid = boundRow();
    await insertBound(runtime, valid);
    const stored = (await runtime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1', [valid.id])).rows[0];
    assert.equal(stored.authority_mode, 'launch_bound');
    assert.equal(stored.binding_state, 'pending');
    assert.equal(stored.platform_launch_id, valid.launchId);
    assert.equal(stored.platform_scenario_id, valid.scenarioId);
    assert.equal(stored.platform_launch_generation, '7');
    assert.equal(stored.original_platform_owner_id, 41);
    assert.equal(stored.original_platform_session_id, 83);

    for (const invalid of [
      { id: 'not-a-uuid' },
      { launchId: null },
      { scenarioId: null },
      { generation: null },
      { generation: 0 },
      { generation: 9007199254740992 },
      { ownerId: null },
      { ownerId: 0 },
      { platformSessionId: null },
      { platformSessionId: 0 },
      { userId: 0 },
      { role: 'student' },
    ]) {
      await assert.rejects(insertBound(runtime, boundRow(invalid)));
    }
    await assert.rejects(insertBound(runtime, boundRow({ state: 'active' })), /must begin pending/);
    await assert.rejects(insertBound(runtime, boundRow({ state: 'abandoned' })), /must begin pending/);
    await assert.rejects(runtime.query(`INSERT INTO secureshop_agents.agent_sessions
      (id,user_id,role,authority_mode,binding_state,platform_launch_id)
      VALUES($1,1,'customer','launch_bound','pending',$2)`, [randomUUID(), randomUUID()]));
    const prefilled = boundRow();
    await assert.rejects(runtime.query(`INSERT INTO secureshop_agents.agent_sessions
      (id,user_id,role,messages_json,authority_mode,binding_state,platform_launch_id,
       platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
      VALUES($1,$2,$3,'[{}]','launch_bound','pending',$4,$5,$6,$7,$8)`, [
      prefilled.id, prefilled.userId, prefilled.role, prefilled.launchId, prefilled.scenarioId,
      prefilled.generation, prefilled.ownerId, prefilled.platformSessionId,
    ]));
  });

  await t.test('all durable launch and persona coordinates are immutable', async () => {
    const row = boundRow();
    await insertBound(runtime, row);
    const changes = [
      ['id', randomUUID()],
      ['user_id', 18],
      ['role', 'admin'],
      ['platform_launch_id', randomUUID()],
      ['platform_scenario_id', randomUUID()],
      ['platform_launch_generation', 8],
      ['original_platform_owner_id', 42],
      ['original_platform_session_id', 84],
      ['authority_mode', 'legacy'],
      ['created_at', new Date(0).toISOString()],
    ];
    for (const [column, value] of changes) {
      await assert.rejects(
        runtime.query(`UPDATE secureshop_agents.agent_sessions SET ${column}=$2 WHERE id=$1`, [row.id, value]),
        /immutable/,
      );
    }
    await assert.rejects(runtime.query('DELETE FROM secureshop_agents.agent_sessions WHERE id=$1', [row.id]), /retained/);
  });

  await t.test('native repository requires the exact binding for activation and abandonment', async () => {
    const row = boundRow({ role: 'merchant', userId: 29 });
    const binding = rowBinding(row);
    const repository = createBoundConversationsRepository({
      pool: runtime,
      queue: async (_id, operation) => operation(),
    });
    assert.deepEqual(await repository.createPendingBoundSession({ id: row.id, binding }), { id: row.id });
    assert.deepEqual(await repository.getBoundSession(row.id), { id: row.id, state: 'pending', binding });
    assert.equal(await repository.activateBoundSession(row.id, { ...binding, generation: 8 }), false);
    assert.equal(await repository.activateBoundSession(row.id, binding), true);
    assert.deepEqual(await repository.getBoundSession(row.id), { id: row.id, state: 'active', binding });
    assert.equal(await repository.abandonBoundSession(row.id, binding), true);
    assert.deepEqual(await repository.getBoundSession(row.id), { id: row.id, state: 'abandoned', binding });
    assert.equal(await repository.activateBoundSession(row.id, binding), false);
    assert.equal(await repository.getBoundSession('legacy-after'), null);
  });

  await t.test('cross-pool acquisition converges and enforces retained launch capacity', async (subtest) => {
    const poolA = new Pool({ connectionString: process.env[`${PREFIX}_RUNTIME_URL`], max: 2 });
    const poolB = new Pool({ connectionString: process.env[`${PREFIX}_RUNTIME_URL`], max: 2 });
    subtest.after(async () => Promise.all([poolA.end(), poolB.end()]));
    const repositoryA = createBoundConversationsRepository({ pool: poolA, queue: async (_id, operation) => operation() });
    const repositoryB = createBoundConversationsRepository({ pool: poolB, queue: async (_id, operation) => operation() });
    const first = boundRow({ role: 'customer', userId: 101 });
    const binding = rowBinding(first);
    const competingId = randomUUID();
    const acquired = await Promise.all([
      repositoryA.acquireBoundSession({ id: first.id, binding }),
      repositoryB.acquireBoundSession({ id: competingId, binding }),
    ]);
    assert.equal(acquired.filter((result) => result.created).length, 1);
    assert.equal(new Set(acquired.map((result) => result.id)).size, 1);
    const winner = acquired[0].id;
    assert.equal((await runtime.query(`SELECT count(*)::int AS n
      FROM secureshop_agents.agent_sessions WHERE platform_launch_id=$1`, [binding.launchId])).rows[0].n, 1);

    assert.equal(await repositoryA.activateBoundSession(winner, binding), true);
    assert.deepEqual(await repositoryB.acquireBoundSession({ id: randomUUID(), binding }), {
      id: winner, state: 'active', created: false,
    });
    assert.equal(await repositoryA.abandonBoundSession(winner, binding), true);
    await assert.rejects(
      repositoryB.acquireBoundSession({ id: randomUUID(), binding }),
      { code: 'CONVERSATION_UNAVAILABLE' },
    );

    const nextGeneration = Object.freeze({ ...binding, generation: binding.generation + 1 });
    const next = await repositoryA.acquireBoundSession({ id: randomUUID(), binding: nextGeneration });
    assert.equal(next.created, true);
    assert.equal(next.state, 'pending');
    assert.notEqual(next.id, winner);

    const errorLaunch = Object.freeze({ ...binding, launchId: randomUUID(), scenarioId: randomUUID() });
    await assert.rejects(repositoryA.acquireBoundSession({ id: winner, binding: errorLaunch }));
    const afterError = await repositoryB.acquireBoundSession({ id: randomUUID(), binding: errorLaunch });
    assert.equal(afterError.created, true, 'failed insertion must release the launch admission lock');

    const filler = Array.from({ length: 254 }, (_, index) => {
      const row = boundRow({
        launchId: binding.launchId,
        scenarioId: randomUUID(),
        generation: 1000 + index,
        ownerId: 1000 + index,
        platformSessionId: 2000 + index,
        userId: 3000 + index,
        role: ['customer', 'merchant', 'admin'][index % 3],
      });
      return { row, binding: rowBinding(row) };
    });
    const parameters = [];
    const tuples = filler.map(({ row }, rowIndex) => {
      const offset = rowIndex * 9;
      parameters.push(row.id, row.userId, row.role, row.launchId, row.scenarioId,
        row.generation, row.ownerId, row.platformSessionId, row.state);
      return `($${offset + 1},$${offset + 2},$${offset + 3},'launch_bound',$${offset + 9},`
        + `$${offset + 4},$${offset + 5},$${offset + 6},$${offset + 7},$${offset + 8})`;
    });
    await runtime.query(`INSERT INTO secureshop_agents.agent_sessions
      (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
       platform_launch_generation,original_platform_owner_id,original_platform_session_id)
      VALUES ${tuples.join(',')}`, parameters);
    assert.equal(await repositoryA.activateBoundSession(filler[0].row.id, filler[0].binding), true);
    const retained = (await runtime.query(`SELECT count(*)::int AS total,
      count(DISTINCT user_id)::int AS personas,
      count(DISTINCT platform_launch_generation)::int AS generations,
      array_agg(DISTINCT binding_state ORDER BY binding_state) AS states
      FROM secureshop_agents.agent_sessions WHERE authority_mode='launch_bound' AND platform_launch_id=$1`,
    [binding.launchId])).rows[0];
    assert.equal(retained.total, 256);
    assert.ok(retained.personas > 250);
    assert.ok(retained.generations > 250);
    assert.deepEqual(retained.states, ['abandoned', 'active', 'pending']);

    assert.deepEqual(await repositoryB.acquireBoundSession({ id: randomUUID(), binding: nextGeneration }), {
      id: next.id, state: 'pending', created: false,
    }, 'an exact retry remains idempotent at the launch-wide ceiling');
    await assert.rejects(repositoryA.acquireBoundSession({ id: randomUUID(), binding: {
      ...binding,
      scenarioId: randomUUID(),
      generation: 9000,
      shopUserId: 9000,
      role: 'merchant',
    } }), { code: 'CONVERSATION_CAPACITY' });
  });

  await t.test('bound message access requires an active conversation and its exact binding', async () => {
    const repository = createBoundConversationsRepository({
      pool: runtime,
      queue: async (_id, operation) => operation(),
    });
    const row = boundRow();
    const binding = rowBinding(row);
    const wrong = { ...binding, platformOwnerId: binding.platformOwnerId + 1 };
    const message = { role: 'user', content: 'owned launch message' };
    await repository.createPendingBoundSession({ id: row.id, binding });

    for (const operation of [
      () => repository.appendMessage(row.id, binding, message),
      () => repository.getMessages(row.id, binding),
      () => repository.addTokens(row.id, binding, 1),
      () => repository.getTokens(row.id, binding),
      () => repository.appendMessage(row.id, wrong, message),
      () => repository.getMessages(row.id, wrong),
      () => repository.addTokens(row.id, wrong, 1),
      () => repository.getTokens(row.id, wrong),
    ]) await assert.rejects(operation(), { code: 'CONVERSATION_UNAVAILABLE' });

    assert.equal(await repository.activateBoundSession(row.id, binding), true);
    await assert.rejects(repository.appendMessage(row.id, wrong, message), { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(repository.getMessages(row.id, wrong), { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(repository.addTokens(row.id, wrong, 1), { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(repository.getTokens(row.id, wrong), { code: 'CONVERSATION_UNAVAILABLE' });
    await repository.appendMessage(row.id, binding, message);
    assert.deepEqual(await repository.getMessages(row.id, binding), [message]);
    assert.equal(await repository.getTokens(row.id, binding), 0);
    await repository.addTokens(row.id, binding, 7);
    assert.equal(await repository.getTokens(row.id, binding), 7);

    assert.equal(await repository.abandonBoundSession(row.id, binding), true);
    await assert.rejects(repository.appendMessage(row.id, binding, message), { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(repository.getMessages(row.id, binding), { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(repository.addTokens(row.id, binding, 1), { code: 'CONVERSATION_UNAVAILABLE' });
    await assert.rejects(repository.getTokens(row.id, binding), { code: 'CONVERSATION_UNAVAILABLE' });
  });

  await t.test('bound trace writes are authorized, idempotent, conflict-aware, and batch-atomic', async () => {
    const repository = createBoundConversationsRepository({
      pool: runtime,
      queue: async (_id, operation) => operation(),
    });
    const row = boundRow({ role: 'admin', userId: 46 });
    const binding = rowBinding(row);
    const wrong = { ...binding, generation: binding.generation + 1 };
    const original = {
      event_id: `bound-trace-${randomUUID()}`,
      session_id: row.id,
      step: 1,
      actor: 'supervisor',
      kind: 'model_decision',
      agent_ns: null,
      tool_name: null,
      params_json: '{"decision":"tool_use"}',
      result_json: null,
      latency_ms: 3,
      tokens_in: 4,
      tokens_out: 5,
      provider: 'fixture',
      policy_violation: null,
    };
    await repository.createPendingBoundSession({ id: row.id, binding });
    await assert.rejects(repository.appendTraces(row.id, binding, [original]), {
      code: 'CONVERSATION_UNAVAILABLE',
    });
    await assert.rejects(
      repository.appendTraces(row.id, binding, [{ ...original, session_id: randomUUID() }]),
      TypeError,
    );
    assert.equal(await repository.activateBoundSession(row.id, binding), true);
    await assert.rejects(repository.appendTraces(row.id, wrong, [original]), {
      code: 'CONVERSATION_UNAVAILABLE',
    });

    await repository.appendTraces(row.id, binding, [original]);
    await repository.appendTraces(row.id, binding, [{ ...original }]);
    assert.equal((await runtime.query(
      'SELECT count(*)::int AS n FROM secureshop_agents.agent_trace WHERE event_id=$1',
      [original.event_id],
    )).rows[0].n, 1);

    await assert.rejects(
      repository.appendTraces(row.id, binding, [{ ...original, kind: 'altered-decision' }]),
      { code: 'TRACE_CONFLICT' },
    );
    assert.equal((await runtime.query(
      'SELECT kind FROM secureshop_agents.agent_trace WHERE event_id=$1',
      [original.event_id],
    )).rows[0].kind, original.kind);

    const rolledBack = { ...original, event_id: `bound-trace-${randomUUID()}`, step: 2, kind: 'tool_call' };
    await assert.rejects(repository.appendTraces(row.id, binding, [
      rolledBack,
      { ...original, result_json: '{"changed":true}' },
    ]), { code: 'TRACE_CONFLICT' });
    assert.equal((await runtime.query(
      'SELECT count(*)::int AS n FROM secureshop_agents.agent_trace WHERE event_id=$1',
      [rolledBack.event_id],
    )).rows[0].n, 0, 'a new earlier row rolls back when a later replay conflicts');
    assert.equal((await runtime.query(
      'SELECT result_json FROM secureshop_agents.agent_trace WHERE event_id=$1',
      [original.event_id],
    )).rows[0].result_json, null);

    assert.equal(await repository.abandonBoundSession(row.id, binding), true);
    await assert.rejects(repository.appendTraces(row.id, binding, [{
      ...original,
      event_id: `bound-trace-${randomUUID()}`,
    }]), { code: 'CONVERSATION_UNAVAILABLE' });
  });

  await t.test('trace reads filter the whole binding before descending limit', async () => {
    const repository = createBoundConversationsRepository({
      pool: runtime,
      queue: async (_id, operation) => operation(),
    });
    const ownedA = boundRow({ userId: 55, role: 'admin' });
    const binding = rowBinding(ownedA);
    const ownedB = boundRow({
      userId: ownedA.userId,
      role: ownedA.role,
      launchId: ownedA.launchId,
      scenarioId: ownedA.scenarioId,
      generation: ownedA.generation,
      ownerId: ownedA.ownerId,
      platformSessionId: ownedA.platformSessionId,
    });
    const foreign = boundRow({
      userId: ownedA.userId,
      role: ownedA.role,
      launchId: ownedA.launchId,
      scenarioId: ownedA.scenarioId,
      generation: ownedA.generation,
      ownerId: ownedA.ownerId + 1,
      platformSessionId: ownedA.platformSessionId + 1,
    });
    for (const row of [ownedA, ownedB, foreign]) {
      const current = rowBinding(row);
      await repository.createPendingBoundSession({ id: row.id, binding: current });
      assert.equal(await repository.activateBoundSession(row.id, current), true);
    }
    await runtime.query(
      "INSERT INTO secureshop_agents.agent_sessions(id,user_id,role) VALUES('legacy-same-persona',55,'admin')",
    );

    const insertTrace = async (sessionId, kind) => Number((await runtime.query(`INSERT INTO secureshop_agents.agent_trace
      (session_id,step,actor,kind) VALUES($1,1,'supervisor',$2) RETURNING id`, [sessionId, kind])).rows[0].id);
    const ownedOldId = await insertTrace(ownedA.id, 'owned-old');
    const ownedSecondId = await insertTrace(ownedA.id, 'owned-second');
    const ownedLatestId = await insertTrace(ownedB.id, 'owned-latest');
    const foreignId = await insertTrace(foreign.id, 'foreign-newer');
    const legacyId = await insertTrace('legacy-same-persona', 'legacy-newest');
    assert.ok(legacyId > foreignId && foreignId > ownedLatestId
      && ownedLatestId > ownedSecondId && ownedSecondId > ownedOldId);

    const ownConversation = await repository.getTrace(ownedA.id, binding, 100);
    assert.deepEqual(ownConversation.map((row) => Number(row.id)), [ownedOldId, ownedSecondId]);
    assert.deepEqual(await repository.getTrace(ownedA.id, { ...binding, generation: binding.generation + 1 }, 100), []);
    assert.deepEqual(await repository.getTrace(foreign.id, binding, 100), []);
    assert.deepEqual(await repository.getTrace('legacy-same-persona', binding, 100), []);

    const latest = await repository.latestTrace(binding, 1);
    assert.deepEqual(latest.map((row) => Number(row.id)), [ownedLatestId]);
    assert.equal(latest[0].kind, 'owned-latest');
    for (const field of ['params_json', 'result_json', 'event_id']) {
      assert.equal(Object.hasOwn(latest[0], field), false, `latest trace omits ${field}`);
    }
  });

  await t.test('real bound graph store persists one native local-tool decision loop', async () => {
    const conversations = createBoundConversationsRepository({
      pool: runtime,
      queue: async (_id, operation) => operation(),
    });
    const scope = Object.freeze({
      launchId: randomUUID(),
      scenarioId: randomUUID(),
      generation: 12,
      platformOwnerId: 92,
      platformSessionId: 193,
    });
    const persona = Object.freeze({ id: 81, role: 'admin' });
    let authorityChecks = 0;
    const launches = {
      async assertCurrent(current) {
        authorityChecks += 1;
        assert.deepEqual(current, scope);
        return current;
      },
    };
    const service = createBoundConversationService({ conversations, launches });
    const created = await service.create(scope, persona);
    const graphStore = createBoundGraphStore({
      sessionId: created.id,
      scope,
      persona,
      service,
      repository: conversations,
      tokenBudget: 10000,
    });
    const marker = `BOUND_GRAPH_${randomUUID()}`;
    const responses = [
      {
        stop_reason: 'tool_use',
        tool_uses: [{ id: 'native-local-call', name: 'fixture.read', args: { path: 'owned.txt' } }],
        provider: 'deterministic',
        model: 'native-fixture',
        mocked: false,
      },
      {
        stop_reason: 'end_turn',
        text: `Observed ${marker}`,
        provider: 'deterministic',
        model: 'native-fixture',
        mocked: false,
      },
    ];
    const graph = createSupervisorGraph({
      ...graphStore,
      buildBasePrompt: () => 'Use the declared local fixture tool and answer from its observation.',
      buildPolicyBlock: async () => '',
      checkToolAcl: async () => ({ action: 'dispatch', policyViolation: null }),
    });
    const result = await service.runExclusive(created.id, scope, persona, () => graph(
      created.id,
      'Read the owned fixture and report its marker.',
      {
        provider: { async chat() { return responses.shift(); } },
        pool: { async callTool() { throw new Error('remote MCP must not run'); } },
        manifest: {
          getForRole: () => [{ agent: 'fixture', tool: 'read', description: 'Read the owned test fixture.',
            inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } }],
        },
        role: persona.role,
        callerRole: persona.role,
        callerId: persona.id,
        ownerId: scope.platformOwnerId,
        localTools: {
          'fixture.read': async (args) => {
            assert.deepEqual(args, { path: 'owned.txt' });
            return { content: [{ type: 'text', text: marker }] };
          },
        },
      },
      { maxSteps: 3, maxParallelTools: 1 },
    ));
    assert.equal(result.stopReason, 'end_turn');
    assert.equal(result.hops.length, 1);
    assert.equal(result.hops[0].tool, 'fixture.read');
    assert.equal(result.text, `Observed ${marker}`);

    const messages = await service.getMessages(created.id, scope, persona);
    assert.deepEqual(messages.map((message) => message.role), ['user', 'assistant', 'tool', 'assistant']);
    assert.equal(messages[1].tool_calls[0].function.name, 'fixture.read');
    assert.equal(messages[2].tool_call_id, 'native-local-call');
    assert.equal(messages[2].content, marker);
    assert.equal(messages[3].content, `Observed ${marker}`);
    const binding = rowBinding({
      launchId: scope.launchId,
      scenarioId: scope.scenarioId,
      generation: scope.generation,
      ownerId: scope.platformOwnerId,
      platformSessionId: scope.platformSessionId,
      userId: persona.id,
      role: persona.role,
    });
    assert.ok(await conversations.getTokens(created.id, binding) > 0);
    const trace = await service.getTrace(created.id, scope, persona, 100);
    assert.ok(trace.some((event) => event.kind === 'local_tool_result'));
    assert.equal(trace.at(-1).kind, 'terminal');
    assert.ok(trace.findIndex((event) => event.kind === 'local_tool_call')
      < trace.findIndex((event) => event.kind === 'local_tool_result'));
    assert.ok(authorityChecks > 3);

    const legacy = createSecureShopAgentsDb(runtime);
    assert.equal(await legacy.getSession(created.id), null);
    await assert.rejects(legacy.getMessages(created.id), /unknown session/);
    assert.equal(await legacy.getTokens(created.id), 0);
    assert.deepEqual(await legacy.getTrace(created.id), []);
  });

  await t.test('all legacy repositories exclude launch-bound sessions before mutation and limits', async () => {
    const legacy = createSecureShopAgentsDb(runtime);
    const commerceStub = {
      async query() {
        return { rows: [{ total_users: 0, total_products: 0, total_orders: 0,
          total_revenue: 0, admin_count: 0, banned_count: 0 }], fields: [] };
      },
    };
    const customer = createSecureShopCustomerRepository(commerceStub, runtime);
    const merchant = createSecureShopMerchantRepository({ commercePool: commerceStub, agentsPool: runtime });
    const admin = createSecureShopAdminRepository(commerceStub, runtime);
    const bound = createBoundConversationsRepository({ pool: runtime, queue: async (_id, operation) => operation() });
    const row = boundRow({ userId: 77, role: 'merchant' });
    const binding = rowBinding(row);
    await bound.createPendingBoundSession({ id: row.id, binding });
    assert.equal(await bound.activateBoundSession(row.id, binding), true);
    await bound.addTokens(row.id, binding, 4);
    const legacyId = 'legacy-repository-session';
    await legacy.createSession(legacyId, row.userId, row.role);
    await legacy.appendMessage(legacyId, { role: 'user', content: 'legacy-visible' });
    await legacy.addTokens(legacyId, 3);
    await legacy.appendTraces([
      { event_id: 'legacy-repository-trace', session_id: legacyId, step: 1,
        actor: 'supervisor', kind: 'legacy-visible' },
      { event_id: 'bound-mutation-must-skip', session_id: row.id, step: 1,
        actor: 'supervisor', kind: 'must-not-insert' },
    ]);
    const legacyTraceId = Number((await runtime.query(
      "SELECT id FROM secureshop_agents.agent_trace WHERE event_id='legacy-repository-trace'",
    )).rows[0].id);
    const boundTraceId = Number((await runtime.query(`INSERT INTO secureshop_agents.agent_trace
      (event_id,session_id,step,actor,kind) VALUES('bound-newer-than-legacy',$1,1,'supervisor','bound-hidden') RETURNING id`,
    [row.id])).rows[0].id);
    assert.ok(boundTraceId > legacyTraceId);
    assert.equal((await runtime.query(
      "SELECT count(*)::int AS n FROM secureshop_agents.agent_trace WHERE event_id='bound-mutation-must-skip'",
    )).rows[0].n, 0);

    assert.deepEqual(await legacy.getSession(legacyId), { id: legacyId, userId: row.userId, role: row.role });
    assert.equal(await legacy.getSession(row.id), null);
    assert.deepEqual(await legacy.getMessages(legacyId), [{ role: 'user', content: 'legacy-visible' }]);
    await assert.rejects(legacy.getMessages(row.id), /unknown session/);
    assert.equal(await legacy.getTokens(legacyId), 3);
    assert.equal(await legacy.getTokens(row.id), 0);
    await assert.rejects(legacy.appendMessage(row.id, { role: 'user', content: 'blocked' }), /unknown session/);
    await legacy.addTokens(row.id, 100);
    assert.equal(await bound.getTokens(row.id, binding), 4);
    assert.deepEqual((await legacy.getTrace(legacyId)).map((trace) => Number(trace.id)), [legacyTraceId]);
    assert.deepEqual(await legacy.getTrace(row.id), []);

    for (const rows of [
      await customer.latestTrace({ userId: row.userId, role: row.role, limit: 1 }),
      await merchant.latestMerchantTrace({ userId: row.userId, role: row.role, limit: 1 }),
      await admin.latestTrace({ userId: row.userId, role: row.role, limit: 1 }),
    ]) assert.deepEqual(rows.map((trace) => Number(trace.id)), [legacyTraceId]);
    assert.deepEqual(await customer.sessionTrace(row.id), []);
    assert.deepEqual(await merchant.merchantTrace(row.id), []);
    assert.deepEqual(await admin.trace(row.id), []);

    const expectedLegacyActive = (await runtime.query(`SELECT count(*)::int AS n
      FROM secureshop_agents.agent_sessions s
      WHERE s.updated_at>now()-interval '15 minutes'
        AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'`)).rows[0].n;
    assert.equal((await admin.kpis()).active_sessions, expectedLegacyActive);
  });

  await t.test('latest trace repositories filter persona owner and role before limiting crowded sibling rows', async () => {
    const legacy = createSecureShopAgentsDb(runtime);
    const commerceStub = { async query() { return { rows: [], fields: [] }; } };
    const readers = [
      { name: 'customer', read: createSecureShopCustomerRepository(commerceStub, runtime).latestTrace,
        omitted: ['params_json', 'result_json', 'tokens_in', 'tokens_out', 'event_id', 'session_role'] },
      { name: 'merchant', read: createSecureShopMerchantRepository({ commercePool: commerceStub, agentsPool: runtime }).latestMerchantTrace,
        omitted: ['tokens_in', 'tokens_out', 'event_id', 'session_role'] },
      { name: 'admin', read: createSecureShopAdminRepository(commerceStub, runtime).latestTrace,
        omitted: ['params_json', 'result_json', 'event_id'] },
    ];
    for (const [index, role] of ['customer', 'merchant', 'admin'].entries()) {
      const owner = 910001 + index;
      const ownedSession = `crowded-owned-${role}`;
      const siblingSession = `crowded-sibling-${role}`;
      await legacy.createSession(ownedSession, owner, role);
      await legacy.createSession(siblingSession, owner + 100, role);
      const ownIds = [];
      for (let step = 0; step < 3; step++) {
        const inserted = await runtime.query(`INSERT INTO secureshop_agents.agent_trace
          (event_id,session_id,step,actor,kind,params_json,result_json,tokens_in,tokens_out,ts)
          VALUES($1,$2,$3,'supervisor','owned-crowded',$4,$5,11,12,$6) RETURNING id`, [
          `crowded-own-${role}-${step}`, ownedSession, step,
          JSON.stringify({ marker: 'owned-params' }), JSON.stringify({ marker: 'owned-result' }),
          new Date(Date.UTC(2026, 0, 1, 0, 0, step)),
        ]);
        ownIds.push(Number(inserted.rows[0].id));
      }
      // Every sibling event is newer than every owned event. A global LIMIT
      // before owner admission would return no owned rows at limit=2.
      for (let step = 0; step < 30; step++) {
        await runtime.query(`INSERT INTO secureshop_agents.agent_trace
          (event_id,session_id,step,actor,kind,ts)
          VALUES($1,$2,$3,'supervisor','sibling-crowded',$4)`, [
          `crowded-other-${role}-${step}`, siblingSession, step,
          new Date(Date.UTC(2026, 0, 2, 0, 0, step)),
        ]);
      }
      for (const reader of readers) {
        const rows = await reader.read({ userId: owner, role, limit: 2 });
        assert.deepEqual(rows.map(row => Number(row.id)), [ownIds[2], ownIds[1]], reader.name);
        assert.ok(rows.every(row => row.session_id === ownedSession && row.kind === 'owned-crowded'));
        for (const row of rows) {
          for (const field of reader.omitted) assert.equal(Object.hasOwn(row, field), false,
            `${reader.name} latest projection omits ${field}`);
          if (reader.name === 'merchant') {
            assert.deepEqual(JSON.parse(row.params_json), { marker: 'owned-params' });
            assert.deepEqual(JSON.parse(row.result_json), { marker: 'owned-result' });
          }
          if (reader.name === 'admin') assert.equal(row.session_role, role);
        }
        const otherRole = role === 'customer' ? 'merchant' : 'customer';
        assert.deepEqual(await reader.read({ userId: owner, role: otherRole, limit: 2 }), [],
          `${reader.name} denies mismatched role`);
      }
    }
  });

  await t.test('pending activates once, active content can change, and abandonment cannot revive', async () => {
    const row = boundRow();
    await insertBound(runtime, row);
    await assert.rejects(runtime.query(
      "UPDATE secureshop_agents.agent_sessions SET messages_json='[{}]' WHERE id=$1",
      [row.id],
    ), /Inactive.*immutable/);
    await runtime.query("UPDATE secureshop_agents.agent_sessions SET binding_state='active' WHERE id=$1", [row.id]);
    await runtime.query(`UPDATE secureshop_agents.agent_sessions
      SET messages_json='[{"role":"user","content":"hello"}]',token_budget_used=5 WHERE id=$1`, [row.id]);
    await assert.rejects(runtime.query(
      "UPDATE secureshop_agents.agent_sessions SET binding_state='pending' WHERE id=$1",
      [row.id],
    ), /transition is invalid/);
    await runtime.query("UPDATE secureshop_agents.agent_sessions SET binding_state='abandoned' WHERE id=$1", [row.id]);
    for (const state of ['active', 'pending']) {
      await assert.rejects(runtime.query(
        'UPDATE secureshop_agents.agent_sessions SET binding_state=$2 WHERE id=$1',
        [row.id, state],
      ), /transition is invalid/);
    }
    await assert.rejects(runtime.query(
      'UPDATE secureshop_agents.agent_sessions SET token_budget_used=token_budget_used+1 WHERE id=$1',
      [row.id],
    ), /Inactive.*immutable/);
  });

  await t.test('pending may be abandoned after setup failure but never activated later', async () => {
    const row = boundRow();
    await insertBound(runtime, row);
    await runtime.query("UPDATE secureshop_agents.agent_sessions SET binding_state='abandoned' WHERE id=$1", [row.id]);
    await assert.rejects(runtime.query(
      "UPDATE secureshop_agents.agent_sessions SET binding_state='active' WHERE id=$1",
      [row.id],
    ), /transition is invalid/);
    assert.equal((await runtime.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1', [row.id])).rows[0].binding_state, 'abandoned');
  });
});
