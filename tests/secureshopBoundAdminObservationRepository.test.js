'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundConversationsRepository } = require('../server/database/postgres/secureshopBoundConversationsRepository');

const scope = Object.freeze({
  launchId: 'a0000000-0000-4000-8000-000000000001',
  scenarioId: 'b0000000-0000-4000-8000-000000000002',
  generation: 3,
  platformOwnerId: 41,
  platformSessionId: 42,
});

function fixture(rows = []) {
  const calls = [];
  const pool = {
    async query(sql, params) {
      calls.push({ sql, params });
      return { rows };
    },
  };
  return {
    calls,
    repository: createBoundConversationsRepository({ pool, queue: async (_id, operation) => operation() }),
  };
}

test('latest observed providers are derived from the latest model decision in the exact launch', async () => {
  const rows = [{ role: 'admin', active_provider: 'openai', last_observed_at: '2026-09-19T12:00:00Z' }];
  const { repository, calls } = fixture(rows);

  assert.equal(await repository.latestObservedProviders({ ...scope, shopUserId: 99, role: 'admin' }), rows);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].params, [scope.launchId, scope.scenarioId, 3, 41, 42]);
  assert.match(calls[0].sql, /SELECT DISTINCT ON \(s\.role\) s\.role,t\.provider AS active_provider,t\.ts AS last_observed_at/);
  assert.match(calls[0].sql, /JOIN secureshop_agents\.agent_sessions s ON s\.id=t\.session_id/);
  assert.match(calls[0].sql, /s\.authority_mode='launch_bound' AND s\.binding_state='active'/);
  for (const coordinate of ['platform_launch_id', 'platform_scenario_id', 'platform_launch_generation',
    'original_platform_owner_id', 'original_platform_session_id']) {
    assert.match(calls[0].sql, new RegExp(`s\\.${coordinate}=\\$\\d`));
  }
  assert.doesNotMatch(calls[0].sql, /s\.user_id=|s\.role=\$/);
  assert.match(calls[0].sql, /t\.kind='model_decision'/);
  assert.match(calls[0].sql, /NULLIF\(BTRIM\(t\.provider\),'\'\) IS NOT NULL/);
  assert.match(calls[0].sql, /ORDER BY s\.role,t\.ts DESC,t\.id DESC/);
  assert.doesNotMatch(calls[0].sql, /agent_provider_state|llm_call_start|error/);
});

test('latest observed providers validate the complete launch scope before reading', async () => {
  const { repository, calls } = fixture();
  await assert.rejects(repository.latestObservedProviders({ ...scope, platformSessionId: 0 }), /Invalid platformSessionId/);
  assert.equal(calls.length, 0);
});

test('admin latest trace uses the safe metadata projection across every conversation purpose', async () => {
  const rows = [{ id: 8, session_id: 'session', session_role: 'admin', kind: 'model_decision' }];
  const { repository, calls } = fixture(rows);
  const binding = { ...scope, shopUserId: 7, role: 'admin' };

  assert.equal(await repository.adminLatestTrace(binding, 37), rows);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].params, [scope.launchId, scope.scenarioId, 3, 41, 42, 7, 'admin', 37]);
  assert.match(calls[0].sql, /SELECT t\.id,t\.session_id,s\.role AS session_role,t\.step,t\.actor,t\.kind,t\.agent_ns,t\.tool_name,t\.latency_ms,t\.tokens_in,t\.tokens_out,t\.provider,t\.ts/);
  assert.match(calls[0].sql, /s\.authority_mode='launch_bound' AND s\.binding_state='active'/);
  for (const coordinate of ['platform_launch_id', 'platform_scenario_id', 'platform_launch_generation',
    'original_platform_owner_id', 'original_platform_session_id', 'user_id', 'role']) {
    assert.match(calls[0].sql, new RegExp(`s\\.${coordinate}=\\$\\d`));
  }
  assert.match(calls[0].sql, /ORDER BY t\.ts DESC,t\.id DESC LIMIT \$8/);
  assert.doesNotMatch(calls[0].sql, /conversation_purpose|params_json|result_json|messages_json/);
});

test('admin latest trace rejects non-admin bindings and limits outside 1 through 200', async () => {
  const { repository, calls } = fixture();
  await assert.rejects(repository.adminLatestTrace({ ...scope, shopUserId: 7, role: 'customer' }), /Admin conversation binding required/);
  for (const limit of [0, 201, 1.5]) {
    await assert.rejects(repository.adminLatestTrace({ ...scope, shopUserId: 7, role: 'admin' }, limit), /Invalid admin trace limit/);
  }
  await assert.rejects(repository.adminLatestTrace({ ...scope, shopUserId: 0, role: 'admin' }), /Invalid shop persona/);
  assert.equal(calls.length, 0);
});
