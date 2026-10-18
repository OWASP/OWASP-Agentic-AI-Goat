'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSecureShopBoundPersonaRepository } = require(
  '../server/database/postgres/secureshopBoundPersonaRepository');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000074',
  scenarioId: '20000000-0000-4000-8000-000000000074', generation: 7,
  platformOwnerId: 74, platformSessionId: 704 });
const current = '30000000-0000-4000-8000-000000000074';
const other = '40000000-0000-4000-8000-000000000074';

test('session inventory binds every launch coordinate and persona before projecting UI metadata', async () => {
  const calls = [];
  const agentsPool = { async query(sql, args) {
    calls.push([sql, args]);
    return { rows: [{ id: current, user_agent: 'Controlled Browser', ip: '127.0.0.1',
      created_at: new Date('2026-09-18T00:00:00Z'), last_seen_at: new Date('2026-09-18T00:01:00Z'),
      is_current: true }] };
  }, async connect() { throw new Error('list must not allocate a transaction client'); } };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} }, agentsPool });
  assert.deepEqual(await repository.listSessions({ scope, shopUserId: 12, currentSessionId: current }), [{
    id: current, user_agent: 'Controlled Browser', ip: '127.0.0.1',
    created_at: new Date('2026-09-18T00:00:00Z'), last_seen_at: new Date('2026-09-18T00:01:00Z'),
    is_current: true,
  }]);
  assert.deepEqual(calls[0][1], [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId, 12, current]);
  for (const predicate of ['platform_launch_id=$1', 'platform_scenario_id=$2',
    'platform_launch_generation=$3', 'original_platform_owner_id=$4',
    'original_platform_session_id=$5', 'shop_user_id=$6', 'revoked_at IS NULL',
    'expires_at>clock_timestamp()', 'LIMIT 20']) assert.match(calls[0][0], new RegExp(predicate.replace('$', '\\$')));
});

test('session revocation uses UUID plus the complete server-derived authority tuple', async () => {
  const calls = [];
  const client = { async query(sql, args) { calls.push([sql, args]); return { rows: [], rowCount: 1 }; },
    release() { calls.push(['release']); } };
  const agentsPool = { async query() { throw new Error('revocation must use the launch-locked client'); },
    async connect() { calls.push(['connect']); return client; } };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} }, agentsPool });
  assert.equal(await repository.revokeOwnedSession({ scope, shopUserId: 12, sessionId: other }), true);
  assert.deepEqual(calls.map(call => call[0]), ['connect', 'BEGIN',
    'SELECT pg_advisory_xact_lock(hashtextextended($1,0))', calls[3][0], 'COMMIT', 'release']);
  assert.deepEqual(calls[3][1], [other, scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId, 12]);
  for (const predicate of ['session_id=$1', 'platform_launch_id=$2', 'platform_scenario_id=$3',
    'platform_launch_generation=$4', 'original_platform_owner_id=$5',
    'original_platform_session_id=$6', 'shop_user_id=$7', 'revoked_at IS NULL',
    'expires_at>clock_timestamp()']) assert.match(calls[3][0], new RegExp(predicate.replace('$', '\\$')));
});

test('session touch takes the launch admission lock before the row update', async () => {
  const calls = [];
  const client = { async query(sql, args) { calls.push([sql, args]);
    if (sql.startsWith('UPDATE secureshop_agents.bound_persona_sessions')) return { rows: [{
      session_id: current, shop_user_id: 12, username: 'student_merchant', role: 'merchant',
      email: 'merchant@example.test', full_name: null, phone: null,
      expires_at: new Date('2026-09-19T00:00:00Z'), created_at: new Date('2026-09-18T00:00:00Z'),
      last_seen_at: new Date('2026-09-18T00:01:00Z'), ip: null, user_agent: null,
    }] };
    return { rows: [] };
  }, release() { calls.push(['release']); } };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() { throw new Error('touch must use a transaction client'); },
      async connect() { calls.push(['connect']); return client; } } });
  const row = await repository.readSession({ scope, jti: 'owned-session-jti' });
  assert.equal(row.session_id, current);
  assert.deepEqual(calls.map(call => call[0]), ['connect', 'BEGIN',
    'SELECT pg_advisory_xact_lock(hashtextextended($1,0))', calls[3][0], 'COMMIT', 'release']);
  assert.match(calls[3][0], /^UPDATE secureshop_agents\.bound_persona_sessions/);
  assert.match(calls[3][0], /credential_version=COALESCE/);
  assert.match(calls[3][0], /bound_persona_credentials/);
  assert.equal(calls[2][1][0], `secureshop-conversation-admission:${scope.launchId}`);
});

test('session methods reject noncanonical identity inputs before storage', async () => {
  let calls = 0;
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() { calls++; return { rows: [] }; }, async connect() {} } });
  await assert.rejects(repository.listSessions({ scope, shopUserId: true, currentSessionId: current }),
    { code: 'SHOP_PERSONA_USER_INVALID' });
  await assert.rejects(repository.listSessions({ scope, shopUserId: 12,
    currentSessionId: current.toUpperCase().replace('A', 'A') + 'x' }),
  { code: 'SHOP_PERSONA_SESSION_INVALID' });
  await assert.rejects(repository.revokeOwnedSession({ scope, shopUserId: 12, sessionId: '1' }),
    { code: 'SHOP_PERSONA_SESSION_INVALID' });
  assert.equal(calls, 0);
});

test('password replacement locks launch then persona, advances one version and revokes other sessions', async () => {
  const oldHash = '$2b$10$' + 'a'.repeat(53);
  const nextHash = '$2b$10$' + 'b'.repeat(53);
  const calls = [];
  const client = { async query(sql, args) {
    calls.push([sql, args]);
    if (sql.includes('SELECT t.password_hash AS template_hash')) return { rows: [{
      template_hash: oldHash, password_hash: null, credential_version: null,
    }] };
    if (sql.startsWith('UPDATE secureshop_agents.bound_persona_sessions\n          SET credential_version')) {
      return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 1 };
  }, release() { calls.push(['release']); } };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() { throw new Error('password mutation must use transaction client'); },
      async connect() { calls.push(['connect']); return client; } } });
  assert.deepEqual(await repository.changePassword({ scope, shopUserId: 12,
    currentSessionId: current, expectedHash: oldHash, nextHash }), { credentialVersion: 2 });
  assert.deepEqual(calls.slice(0, 4).map(row => row[0]), ['connect', 'BEGIN',
    'SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
    'SELECT pg_advisory_xact_lock(hashtextextended($1,0))']);
  assert.equal(calls[2][1][0], `secureshop-conversation-admission:${scope.launchId}`);
  assert.equal(calls[3][1][0], `secureshop-persona-credential:${scope.launchId}:12`);
  const upsert = calls.find(row => typeof row[0] === 'string'
    && row[0].includes('INSERT INTO secureshop_agents.bound_persona_credentials'));
  assert.deepEqual(upsert[1].slice(0, 6), [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId, 12]);
  assert.equal(upsert[1][7], 2);
  const sessionWrites = calls.filter(row => typeof row[0] === 'string'
    && row[0].startsWith('UPDATE secureshop_agents.bound_persona_sessions'));
  assert.equal(sessionWrites.length, 2);
  assert.match(sessionWrites[0][0], /SET credential_version=\$1/);
  assert.match(sessionWrites[1][0], /session_id<>\$7/);
});

test('credential cleanup reconciliation requires the immutable receipt and zero remaining overlays', async () => {
  const calls = [];
  const client = { async query(sql) {
    calls.push(sql);
    if (sql.includes('bound_persona_credential_cleanup_receipts')) return { rows: [{
      deleted_credential_count: 1, receipt_sha256: 'a'.repeat(64),
      completed_at: new Date('2026-09-18T00:00:00Z'),
    }] };
    if (sql.includes('count(*)::integer')) return { rows: [{ count: 0 }] };
    return { rows: [] };
  }, release() {} };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() {}, async connect() { return client; } } });
  assert.deepEqual(await repository.readCredentialCleanupReceipt(scope), {
    deletedCredentialCount: 1, receiptSha256: 'a'.repeat(64),
    completedAt: '2026-09-18T00:00:00.000Z',
  });
  assert.ok(calls.findIndex(sql => sql.includes('pg_advisory_xact_lock'))
    < calls.findIndex(sql => sql.includes('bound_persona_credential_cleanup_receipts')));
});

test('API-key rotation locks launch then persona and scopes every lookup coordinate', async () => {
  const calls = [];
  const first = 'sk_ss_live_' + '1'.repeat(32);
  const second = 'sk_ss_live_' + '2'.repeat(32);
  const client = { async query(sql, args) {
    calls.push([sql, args]);
    if (sql.includes('FROM secureshop_agents.bound_actor_identities')) {
      return { rows: [{ role: 'customer' }] };
    }
    if (sql.includes('SELECT api_key_version')) return { rows: calls.some(row =>
      typeof row[0] === 'string' && row[0].includes('INSERT INTO secureshop_agents.bound_persona_api_keys'))
      ? [{ api_key_version: 1 }] : [] };
    if (sql.includes('INSERT INTO secureshop_agents.bound_persona_api_keys')
        || sql.includes('UPDATE secureshop_agents.bound_persona_api_keys')) return { rows: [{
      api_key_plaintext: args[6], api_key_version: args[8],
      created_at: new Date('2026-09-18T00:00:00Z'),
      rotated_at: new Date('2026-09-18T00:01:00Z'),
    }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release() { calls.push(['release']); } };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() { throw new Error('API key mutation must use transaction client'); },
      async connect() { calls.push(['connect']); return client; } } });
  assert.equal((await repository.rotateApiKey({ scope, shopUserId: 12, nextKey: first })).version, 1);
  assert.equal((await repository.rotateApiKey({ scope, shopUserId: 12, nextKey: second })).version, 2);
  const locks = calls.filter(row => row[0] === 'SELECT pg_advisory_xact_lock(hashtextextended($1,0))');
  assert.deepEqual(locks.slice(0, 2).map(row => row[1][0]), [
    `secureshop-conversation-admission:${scope.launchId}`,
    `secureshop-persona-api-key:${scope.launchId}:12`,
  ]);
  const mutations = calls.filter(row => typeof row[0] === 'string'
    && (row[0].includes('INSERT INTO secureshop_agents.bound_persona_api_keys')
      || row[0].includes('UPDATE secureshop_agents.bound_persona_api_keys')));
  assert.deepEqual(mutations.map(row => row[1].slice(0, 6)), [
    [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId,
      scope.platformSessionId, 12],
    [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId,
      scope.platformSessionId, 12],
  ]);
  const identities = calls.filter(row => typeof row[0] === 'string'
    && row[0].includes('FROM secureshop_agents.bound_actor_identities'));
  assert.equal(identities.length, 2);
  for (const [sql, args] of identities) {
    assert.match(sql, /shop_user_id=\$1 AND secureshop_agents\.bound_actor_in_owner\(shop_user_id,\$2\)/);
    assert.deepEqual(args, [12, scope.platformOwnerId]);
  }
  const versions = calls.filter(row => typeof row[0] === 'string' && row[0].includes('SELECT api_key_version'));
  assert.equal(versions.length, 2);
  for (const [sql, args] of versions) {
    assert.deepEqual(args, [scope.launchId, scope.scenarioId, scope.generation,
      scope.platformOwnerId, scope.platformSessionId, 12]);
    for (const predicate of ['platform_launch_id=$1', 'platform_scenario_id=$2',
      'platform_launch_generation=$3', 'original_platform_owner_id=$4',
      'original_platform_session_id=$5', 'shop_user_id=$6', 'FOR UPDATE']) {
      assert.ok(sql.includes(predicate));
    }
  }
  assert.match(mutations[0][0], /^INSERT INTO/);
  assert.match(mutations[1][0], /^UPDATE/);
  assert.ok(Buffer.isBuffer(mutations[0][1][7]));
  assert.equal(mutations[0][1][7].length, 32);
  assert.deepEqual(mutations.map(row => row[1][7]),
    [first, second].map(value => createHash('sha256').update(value).digest()));
  assert.deepEqual(mutations.map(row => row[1][8]), [1, 2]);
});

test('API-key authentication cannot use a digest outside the trusted launch tuple', async () => {
  const calls = [];
  const key = 'sk_ss_live_' + '3'.repeat(32);
  const client = { async query(sql, args) {
    calls.push([sql, args]);
    if (sql.includes('JOIN secureshop_agents.bound_actor_identities')) return { rows: [{
      id: 12, username: 'student_customer', email: 'customer@example.test', role: 'customer',
      full_name: null, phone: null, api_key_version: 4,
    }] };
    return { rows: [] };
  }, release() {} };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() {}, async connect() { return client; } } });
  assert.deepEqual(await repository.authenticateApiKey({ scope, presentedKey: key }), {
    id: 12, username: 'student_customer', email: 'customer@example.test', role: 'customer',
    full_name: null, phone: null, apiKeyVersion: 4,
  });
  const lookup = calls.find(row => typeof row[0] === 'string'
    && row[0].includes('JOIN secureshop_agents.bound_actor_identities'));
  assert.deepEqual(lookup[1].slice(0, 5), [scope.launchId, scope.scenarioId, scope.generation,
    scope.platformOwnerId, scope.platformSessionId]);
  assert.ok(Buffer.isBuffer(lookup[1][5]));
  assert.deepEqual(lookup[1][5], createHash('sha256').update(key).digest());
  assert.equal(lookup[1].length, 7);
  assert.equal(lookup[1][6], scope.platformOwnerId);
  assert.match(lookup[0], /bound_actor_in_owner\(t\.shop_user_id,\$7\)/);
  for (const predicate of ['platform_launch_id=$1', 'platform_scenario_id=$2',
    'platform_launch_generation=$3', 'original_platform_owner_id=$4',
    'original_platform_session_id=$5', 'api_key_sha256=$6']) {
    assert.match(lookup[0], new RegExp(predicate.replace('$', '\\$')));
  }
});

test('API-key cleanup reconciliation requires a receipt and zero remaining keys', async () => {
  const calls = [];
  const client = { async query(sql) {
    calls.push(sql);
    if (sql.includes('bound_persona_api_key_cleanup_receipts')) return { rows: [{
      deleted_api_key_count: 1, receipt_sha256: 'b'.repeat(64),
      completed_at: new Date('2026-09-18T00:00:00Z'),
    }] };
    if (sql.includes('count(*)::integer')) return { rows: [{ count: 0 }] };
    return { rows: [] };
  }, release() {} };
  const repository = createSecureShopBoundPersonaRepository({ commercePool: { async query() {} },
    agentsPool: { async query() {}, async connect() { return client; } } });
  assert.deepEqual(await repository.readApiKeyCleanupReceipt(scope), {
    deletedApiKeyCount: 1, receiptSha256: 'b'.repeat(64),
    completedAt: '2026-09-18T00:00:00.000Z',
  });
  assert.ok(calls.findIndex(sql => sql.includes('pg_advisory_xact_lock'))
    < calls.findIndex(sql => sql.includes('bound_persona_api_key_cleanup_receipts')));
});

test('held revoke rechecks original actor on the same transaction client before sibling update',async()=>{
 let release,entered;const waiting=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});let actorLive=true,updates=0,connections=0;const calls=[];
 const client={query:async(sql,args)=>{calls.push(sql);if(sql.includes('secureshop-conversation-admission')||args?.[0]===`secureshop-conversation-admission:${scope.launchId}`){entered();await held;}if(sql.startsWith('SELECT 1 FROM secureshop_agents.bound_persona_sessions'))return{rowCount:actorLive?1:0,rows:[]};if(sql.startsWith('UPDATE secureshop_agents.bound_persona_sessions')){updates++;return{rowCount:1,rows:[]};}return{rows:[],rowCount:1};},release(){}};
 const authority={resolve:async(c,_scope,_owner,expected)=>{assert.equal(c,client);assert.deepEqual(expected,{role:'merchant',version:'7'});return{role:'merchant'};}};
 const repository=createSecureShopBoundPersonaRepository({commercePool:{query:async()=>{}},agentsPool:{query:async()=>{throw Error('Must use admitted client');},connect:async()=>{connections++;return client;}},personaAuthority:authority});
 const operation=repository.revokeOwnedSession({scope,shopUserId:12,sessionId:other,actingCredential:{sessionId:current,role:'merchant',authorityVersion:'7'}});await waiting;actorLive=false;release();await assert.rejects(operation,{code:'SHOP_AUTH_INVALID'});assert.equal(updates,0);assert.equal(connections,1);assert.ok(calls.includes('ROLLBACK'));assert.ok(!calls.includes('COMMIT'));
});
test('same-client actor admission allows self revoke without requiring the revoked credential after effect',async()=>{
 let checked=0,updates=0;const client={query:async sql=>{if(sql.startsWith('SELECT 1 FROM secureshop_agents.bound_persona_sessions')){checked++;return{rowCount:updates?0:1};}if(sql.startsWith('UPDATE secureshop_agents.bound_persona_sessions'))updates++;return{rowCount:1,rows:[]};},release(){}};
 const repository=createSecureShopBoundPersonaRepository({commercePool:{query:async()=>{}},agentsPool:{query:async()=>{},connect:async()=>client},personaAuthority:{resolve:async()=>({role:'merchant'})}});
 assert.equal(await repository.revokeOwnedSession({scope,shopUserId:12,sessionId:current,actingCredential:{sessionId:current,role:'merchant',authorityVersion:'1'}}),true);assert.equal(checked,1);assert.equal(updates,1);
});
