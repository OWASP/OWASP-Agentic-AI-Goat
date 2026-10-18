'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundPersonaRepository } = require(
  '../server/database/postgres/secureshopBoundPersonaRepository');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091', generation: 9,
  platformOwnerId: 91, platformSessionId: 901 });

function repositoryWith(query) {
  return createSecureShopBoundPersonaRepository({ commercePool: { async query() {
    throw new Error('active-session aggregate must not read the commerce store');
  } }, agentsPool: { query, async connect() {
    throw new Error('active-session aggregate must not allocate a transaction client');
  } } });
}

test('admin active-session aggregate is read-only and bound to the complete launch scope', async () => {
  const calls = [];
  const repository = repositoryWith(async (sql, args) => {
    calls.push([sql, args]);
    return { rows: [{ count: 3 }] };
  });

  assert.equal(await repository.countActiveSessions({ scope }), 3);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0][1], [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId]);
  assert.match(calls[0][0], /^SELECT count\(\*\)::integer AS count/);
  assert.doesNotMatch(calls[0][0], /\b(?:INSERT|UPDATE|DELETE)\b/);
  for (const predicate of ['s.platform_launch_id=$1', 's.platform_scenario_id=$2',
    's.platform_launch_generation=$3', 's.original_platform_owner_id=$4',
    's.original_platform_session_id=$5', 's.revoked_at IS NULL',
    's.expires_at>clock_timestamp()',
    "s.last_seen_at>=clock_timestamp()-interval '15 minutes'",
    's.credential_version=COALESCE', 'c.platform_launch_id=$1',
    'c.platform_scenario_id=$2', 'c.platform_launch_generation=$3',
    'c.original_platform_owner_id=$4', 'c.original_platform_session_id=$5',
    'c.shop_user_id=s.shop_user_id', '),1)']) {
    assert.ok(calls[0][0].includes(predicate), `missing bounded predicate: ${predicate}`);
  }
});

test('admin active-session aggregate accepts zero and PostgreSQL integer text projections', async () => {
  for (const [stored, expected] of [[0, 0], ['16', 16]]) {
    const repository = repositoryWith(async () => ({ rows: [{ count: stored }] }));
    assert.equal(await repository.countActiveSessions({ scope }), expected);
  }
});

test('admin active-session aggregate rejects invalid scope before querying', async () => {
  let calls = 0;
  const repository = repositoryWith(async () => { calls++; return { rows: [{ count: 0 }] }; });
  await assert.rejects(repository.countActiveSessions({ scope: { ...scope, platformOwnerId: 0 } }),
    { name: 'TypeError', message: 'Invalid platformOwnerId' });
  await assert.rejects(repository.countActiveSessions({ scope: { ...scope, scenarioId: 'foreign' } }),
    { name: 'TypeError', message: 'Invalid scenarioId' });
  assert.equal(calls, 0);
});

test('admin active-session aggregate fails closed on malformed count projections', async () => {
  for (const rows of [[], [{ count: null }], [{ count: -1 }], [{ count: 1.5 }],
    [{ count: 'not-a-count' }]]) {
    const repository = repositoryWith(async () => ({ rows }));
    await assert.rejects(repository.countActiveSessions({ scope }),
      { code: 'SHOP_PERSONA_ACTIVE_SESSION_COUNT_INVALID' });
  }
});
