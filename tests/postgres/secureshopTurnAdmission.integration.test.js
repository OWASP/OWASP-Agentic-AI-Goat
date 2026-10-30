'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');

const PREFIX = 'PG_SECURESHOP_TURN_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[`${PREFIX}_MIGRATION_URL`])
  && Boolean(process.env[`${PREFIX}_RUNTIME_URL`]);

async function insertBoundParent(pool, state = 'active') {
  const row = {
    id: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, ownerId: 41, platformSessionId: 51,
  };
  await pool.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id)
    VALUES($1,61,'customer','launch_bound','pending',$2,$3,$4,$5,$6)`, [
    row.id, row.launchId, row.scenarioId, row.generation, row.ownerId, row.platformSessionId,
  ]);
  if (state !== 'pending') {
    await pool.query('UPDATE secureshop_agents.agent_sessions SET binding_state=$2 WHERE id=$1', [row.id, state]);
  }
  return row.id;
}

async function insertTurn(pool, sessionId, overrides = {}) {
  const row = {
    requestId: randomUUID(),
    requestHash: 'a'.repeat(64),
    claimId: randomUUID(),
    ...overrides,
  };
  await pool.query(`INSERT INTO secureshop_agents.turn_requests
    (session_id,request_id,request_hash,claim_id)
    VALUES($1,$2,$3,$4)`, [sessionId, row.requestId, row.requestHash, row.claimId]);
  return row;
}

async function createRepositoryParent(pool, overrides = {}) {
  const binding = {
    launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 141, platformSessionId: 151,
    shopUserId: 161, role: 'customer',
    ...overrides,
  };
  const sessionId = randomUUID();
  await pool.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,'launch_bound','pending',$4,$5,$6,$7,$8)`, [
    sessionId, binding.shopUserId, binding.role, binding.launchId, binding.scenarioId,
    binding.generation, binding.platformOwnerId, binding.platformSessionId,
  ]);
  await pool.query("UPDATE secureshop_agents.agent_sessions SET binding_state='active' WHERE id=$1", [sessionId]);
  return { sessionId, binding: Object.freeze(binding) };
}

test('native SecureShop turn admission retains immutable claims and one-way terminal state', {
  skip: !enabled,
  timeout: 30000,
}, async (t) => {
  const migrationUrl = new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
  const runtimeUrl = new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
  for (const url of [migrationUrl, runtimeUrl]) {
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  }
  assert.equal(migrationUrl.pathname, runtimeUrl.pathname);

  const migration = new Pool({ connectionString: migrationUrl.href, max: 1 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 2 });
  t.after(async () => Promise.all([migration.end(), runtime.end()]));
  assert.equal((await migration.query("SELECT to_regnamespace('secureshop_agents') AS present")).rows[0].present, null);

  for (const relative of [
    '../../db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
    '../../db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
    '../../docs/modernization/drafts/secureshop-turn-admission.sql',
  ]) {
    await migration.query(await fs.readFile(path.join(__dirname, relative), 'utf8'));
  }

  const active = await insertBoundParent(runtime, 'active');
  const otherActive = await insertBoundParent(runtime, 'active');
  const requests = createTurnRequestsRepository({ pool: runtime });

  await t.test('only an active launch-bound parent admits a started request', async () => {
    const started = await insertTurn(runtime, active);
    assert.deepEqual((await runtime.query(`SELECT status,result_json,finished_at,
      request_hash,request_version,claim_id::text FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`, [active, started.requestId])).rows[0], {
      status: 'started', result_json: null, finished_at: null,
      request_hash: started.requestHash, request_version: 1, claim_id: started.claimId,
    });
    await assert.rejects(runtime.query(`INSERT INTO secureshop_agents.turn_requests
      (session_id,request_id,request_hash,request_version,claim_id)
      VALUES($1,$2,$3,2,$4)`, [active, randomUUID(), 'f'.repeat(64), randomUUID()]), { code: '23514' });

    const legacy = randomUUID();
    await runtime.query('INSERT INTO secureshop_agents.agent_sessions(id,user_id,role) VALUES($1,1,\'customer\')', [legacy]);
    const pending = await insertBoundParent(runtime, 'pending');
    const abandoned = await insertBoundParent(runtime, 'abandoned');
    for (const parent of [legacy, pending, abandoned]) {
      await assert.rejects(insertTurn(runtime, parent), /active bound conversation/);
    }
  });

  await t.test('admission waits for a concurrent parent retirement and then fails closed', async () => {
    const retiring = await insertBoundParent(runtime, 'active');
    const holder = await runtime.connect();
    let insertion;
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT id FROM secureshop_agents.agent_sessions WHERE id=$1 FOR UPDATE', [retiring]);
      insertion = insertTurn(runtime, retiring);
      const settledEarly = await Promise.race([
        insertion.then(() => 'resolved', () => 'rejected'),
        new Promise(resolve => setTimeout(() => resolve('pending'), 75)),
      ]);
      assert.equal(settledEarly, 'pending', 'turn admission must wait behind the parent lifecycle lock');
      await holder.query("UPDATE secureshop_agents.agent_sessions SET binding_state='abandoned' WHERE id=$1", [retiring]);
      await holder.query('COMMIT');
      await assert.rejects(insertion, /active bound conversation/);
      assert.equal((await runtime.query(`SELECT count(*)::int AS count
        FROM secureshop_agents.turn_requests WHERE session_id=$1`, [retiring])).rows[0].count, 0);
    } finally {
      await holder.query('ROLLBACK').catch(() => {});
      holder.release();
      if (insertion) await insertion.catch(() => {});
    }
  });

  await t.test('request identity and creation timestamp cannot change', async () => {
    const original = await insertTurn(runtime, active, { requestHash: 'b'.repeat(64) });
    const mutations = [
      { sql: 'session_id=$3', value: otherActive },
      { sql: 'request_id=$3', value: randomUUID() },
      { sql: 'request_hash=$3', value: 'c'.repeat(64) },
      { sql: 'request_version=$3', value: 2 },
      { sql: 'claim_id=$3', value: randomUUID() },
      { sql: "created_at=created_at + interval '1 second'" },
    ];
    for (const mutation of mutations) {
      const params = mutation.value === undefined
        ? [active, original.requestId]
        : [active, original.requestId, mutation.value];
      await assert.rejects(runtime.query(`UPDATE secureshop_agents.turn_requests SET ${mutation.sql}
        WHERE session_id=$1 AND request_id=$2`, params), /identity and terminal state are immutable/);
    }
    const stored = (await runtime.query(`SELECT session_id,request_id::text,request_hash,claim_id::text,status
      FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [active, original.requestId])).rows[0];
    assert.deepEqual(stored, {
      session_id: active, request_id: original.requestId, request_hash: original.requestHash,
      claim_id: original.claimId, status: 'started',
    });
  });

  await t.test('completed requests require an object result and finish timestamp, then remain terminal', async () => {
    for (const setClause of [
      "status='completed',finished_at=clock_timestamp()",
      "status='completed',result_json='[]'::jsonb,finished_at=clock_timestamp()",
      "status='completed',result_json='{}'::jsonb",
    ]) {
      const candidate = await insertTurn(runtime, active);
      await assert.rejects(runtime.query(`UPDATE secureshop_agents.turn_requests SET ${setClause}
        WHERE session_id=$1 AND request_id=$2`, [active, candidate.requestId]));
      assert.equal((await runtime.query(`SELECT status FROM secureshop_agents.turn_requests
        WHERE session_id=$1 AND request_id=$2`, [active, candidate.requestId])).rows[0].status, 'started');
    }
    const oversized = await insertTurn(runtime, active);
    await assert.rejects(runtime.query(`UPDATE secureshop_agents.turn_requests
      SET status='completed',result_json=$3::jsonb,finished_at=clock_timestamp()
      WHERE session_id=$1 AND request_id=$2`, [
      active, oversized.requestId, JSON.stringify({ data: 'x'.repeat(262145) }),
    ]), { code: '23514' });

    const completed = await insertTurn(runtime, active);
    const result = { ok: true, text: 'bounded result' };
    await runtime.query(`UPDATE secureshop_agents.turn_requests
      SET status='completed',result_json=$3::jsonb,finished_at=clock_timestamp()
      WHERE session_id=$1 AND request_id=$2`, [active, completed.requestId, JSON.stringify(result)]);
    const stored = (await runtime.query(`SELECT status,result_json,finished_at IS NOT NULL AS finished
      FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [active, completed.requestId])).rows[0];
    assert.deepEqual(stored, { status: 'completed', result_json: result, finished: true });
    await assert.rejects(runtime.query(`UPDATE secureshop_agents.turn_requests SET status='uncertain',
      result_json=NULL,finished_at=clock_timestamp() WHERE session_id=$1 AND request_id=$2`,
    [active, completed.requestId]), /identity and terminal state are immutable/);
  });

  await t.test('uncertain requests require no result and a finish timestamp, then remain terminal', async () => {
    for (const setClause of [
      "status='uncertain',result_json='{}'::jsonb,finished_at=clock_timestamp()",
      "status='uncertain'",
    ]) {
      const candidate = await insertTurn(runtime, active);
      await assert.rejects(runtime.query(`UPDATE secureshop_agents.turn_requests SET ${setClause}
        WHERE session_id=$1 AND request_id=$2`, [active, candidate.requestId]));
    }
    const uncertain = await insertTurn(runtime, active);
    await runtime.query(`UPDATE secureshop_agents.turn_requests
      SET status='uncertain',finished_at=clock_timestamp()
      WHERE session_id=$1 AND request_id=$2`, [active, uncertain.requestId]);
    assert.deepEqual((await runtime.query(`SELECT status,result_json,finished_at IS NOT NULL AS finished
      FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [active, uncertain.requestId])).rows[0], { status: 'uncertain', result_json: null, finished: true });
    await assert.rejects(runtime.query(`UPDATE secureshop_agents.turn_requests SET finished_at=clock_timestamp()
      WHERE session_id=$1 AND request_id=$2`, [active, uncertain.requestId]),
    /identity and terminal state are immutable/);
  });

  await t.test('history cannot be deleted and a duplicate request cannot claim a second identity', async () => {
    const original = await insertTurn(runtime, active, { requestHash: 'd'.repeat(64) });
    await assert.rejects(runtime.query(`DELETE FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`, [active, original.requestId]), { code: '42501' });
    await assert.rejects(migration.query(`DELETE FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`, [active, original.requestId]), /cannot be deleted/);
    await assert.rejects(insertTurn(runtime, active, {
      requestId: original.requestId,
      requestHash: 'e'.repeat(64),
      claimId: randomUUID(),
    }), { code: '23505' });
    assert.equal(Number((await runtime.query(`SELECT count(*)::int AS count
      FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [active, original.requestId])).rows[0].count), 1);
  });

  await t.test('repository converges concurrent claims and rejects message or full-binding mismatches', async () => {
    const parent = await createRepositoryParent(runtime);
    const requestId = randomUUID();
    const message = "Read ../config exactly; preserve 'raw' bytes";
    const claims = await Promise.all(Array.from({ length: 20 }, () => requests.claim({
      sessionId: parent.sessionId, requestId, binding: parent.binding, message,
    })));
    const created = claims.filter(row => row.status === 'claimed');
    const retries = claims.filter(row => row.status === 'started');
    assert.equal(created.length, 1);
    assert.equal(retries.length, 19);
    assert.equal(new Set(claims.map(row => row.claimId)).size, 1);
    assert.equal(new Set(claims.map(row => row.requestId)).size, 1);
    assert.equal(Number((await runtime.query(`SELECT count(*)::int AS count
      FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [parent.sessionId, requestId])).rows[0].count), 1);

    await assert.rejects(requests.claim({
      sessionId: parent.sessionId, requestId, binding: parent.binding, message: `${message}!`,
    }), { code: 'TURN_REQUEST_CONFLICT' });

    const mismatches = [
      { launchId: randomUUID() }, { scenarioId: randomUUID() }, { generation: 2 },
      { platformOwnerId: 142 }, { platformSessionId: 152 },
      { shopUserId: 162 }, { role: 'merchant' },
    ];
    for (const mismatch of mismatches) {
      await assert.rejects(requests.claim({
        sessionId: parent.sessionId, requestId: randomUUID(),
        binding: { ...parent.binding, ...mismatch }, message,
      }), { code: 'CONVERSATION_UNAVAILABLE' });
    }
  });

  await t.test('repository completes only the exact claim and replays its stored result without another row', async () => {
    const parent = await createRepositoryParent(runtime, { role: 'merchant', shopUserId: 171 });
    const requestId = randomUUID();
    const message = 'List the current catalog';
    const claim = await requests.claim({ sessionId: parent.sessionId, requestId, binding: parent.binding, message });
    assert.equal(claim.status, 'claimed');
    await assert.rejects(requests.complete({
      sessionId: parent.sessionId, requestId, binding: parent.binding,
      claimId: randomUUID(), result: { text: 'forged' },
    }), { code: 'TURN_CLAIM_UNAVAILABLE' });
    const result = { text: 'catalog observation', stopReason: 'end_turn', steps: 2 };
    assert.equal(await requests.complete({
      sessionId: parent.sessionId, requestId, binding: parent.binding,
      claimId: claim.claimId, result,
    }), undefined);
    const replay = await requests.claim({
      sessionId: parent.sessionId, requestId, binding: parent.binding, message,
    });
    assert.deepEqual(replay, { status: 'completed', requestId, claimId: claim.claimId, result });
    assert.equal(Number((await runtime.query(`SELECT count(*)::int AS count
      FROM secureshop_agents.turn_requests WHERE session_id=$1`, [parent.sessionId])).rows[0].count), 1);
    await assert.rejects(requests.complete({
      sessionId: parent.sessionId, requestId, binding: parent.binding,
      claimId: claim.claimId, result,
    }), { code: 'TURN_CLAIM_UNAVAILABLE' });
  });

  await t.test('repository records uncertain as terminal and rejects oversized completion without changing started', async () => {
    const parent = await createRepositoryParent(runtime, { role: 'admin', shopUserId: 181 });
    const uncertainId = randomUUID();
    const uncertain = await requests.claim({
      sessionId: parent.sessionId, requestId: uncertainId,
      binding: parent.binding, message: 'Perform one uncertain operation',
    });
    assert.equal(await requests.markUncertain({
      sessionId: parent.sessionId, requestId: uncertainId,
      binding: parent.binding, claimId: uncertain.claimId,
    }), true);
    assert.equal(await requests.markUncertain({
      sessionId: parent.sessionId, requestId: uncertainId,
      binding: parent.binding, claimId: uncertain.claimId,
    }), false);
    assert.deepEqual(await requests.claim({
      sessionId: parent.sessionId, requestId: uncertainId,
      binding: parent.binding, message: 'Perform one uncertain operation',
    }), { status: 'uncertain', requestId: uncertainId, claimId: uncertain.claimId });
    await assert.rejects(requests.complete({
      sessionId: parent.sessionId, requestId: uncertainId,
      binding: parent.binding, claimId: uncertain.claimId, result: { late: true },
    }), { code: 'TURN_CLAIM_UNAVAILABLE' });

    const oversizedId = randomUUID();
    const oversized = await requests.claim({
      sessionId: parent.sessionId, requestId: oversizedId,
      binding: parent.binding, message: 'Return a bounded result',
    });
    await assert.rejects(requests.complete({
      sessionId: parent.sessionId, requestId: oversizedId,
      binding: parent.binding, claimId: oversized.claimId,
      result: { data: 'x'.repeat(262145) },
    }), { code: 'TURN_RESULT_TOO_LARGE' });
    assert.deepEqual((await runtime.query(`SELECT status,result_json,finished_at
      FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [parent.sessionId, oversizedId])).rows[0], { status: 'started', result_json: null, finished_at: null });
  });

  await t.test('repository capacity counts retained requests in every state and permits exact retry at the ceiling', async () => {
    const parent = await createRepositoryParent(runtime, { shopUserId: 191 });
    const admitted = [];
    for (let index = 0; index < 256; index++) {
      const requestId = randomUUID();
      const message = `capacity request ${index}`;
      admitted.push({ requestId, message, ...(await requests.claim({
        sessionId: parent.sessionId, requestId, binding: parent.binding, message,
      })) });
    }
    await requests.complete({
      sessionId: parent.sessionId, requestId: admitted[0].requestId,
      binding: parent.binding, claimId: admitted[0].claimId, result: { index: 0 },
    });
    assert.equal(await requests.markUncertain({
      sessionId: parent.sessionId, requestId: admitted[1].requestId,
      binding: parent.binding, claimId: admitted[1].claimId,
    }), true);
    assert.deepEqual((await runtime.query(`SELECT status,count(*)::int AS count
      FROM secureshop_agents.turn_requests WHERE session_id=$1
      GROUP BY status ORDER BY status`, [parent.sessionId])).rows, [
      { status: 'completed', count: 1 },
      { status: 'started', count: 254 },
      { status: 'uncertain', count: 1 },
    ]);
    assert.deepEqual(await requests.claim({
      sessionId: parent.sessionId, requestId: admitted[0].requestId,
      binding: parent.binding, message: admitted[0].message,
    }), {
      status: 'completed', requestId: admitted[0].requestId,
      claimId: admitted[0].claimId, result: { index: 0 },
    });
    await assert.rejects(requests.claim({
      sessionId: parent.sessionId, requestId: randomUUID(),
      binding: parent.binding, message: 'capacity request 256',
    }), { code: 'TURN_CAPACITY' });
    assert.equal(Number((await runtime.query(`SELECT count(*)::int AS count
      FROM secureshop_agents.turn_requests WHERE session_id=$1`, [parent.sessionId])).rows[0].count), 256);
  });
});
