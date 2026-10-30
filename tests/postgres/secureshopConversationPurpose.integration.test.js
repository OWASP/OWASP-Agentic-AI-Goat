'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createAgentsMigrationView } = require('../helpers/secureshopAgentsMigrationView');
const view10 = createAgentsMigrationView(10), view13 = createAgentsMigrationView(13);
const { createBoundConversationsRepository } = require(
  '../../server/database/postgres/secureshopBoundConversationsRepository');
const { createSecureShopConversationLifecycleRepository } = require(
  '../../server/database/postgres/secureshopConversationLifecycleRepository');
const { SECURESHOP_CONVERSATION_PURPOSES } = require(
  '../../server/services/secureshopConversationPurpose');

const PREFIX = 'PG_SECURESHOP_CONVERSATION_PURPOSE_';
const VARIANTS = ['FRESH', 'POPULATED'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && VARIANTS.every(variant => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${variant}_${role}_URL`]));
const ROOT = path.join(__dirname, '../..');
const REGISTERED = path.join(ROOT, 'db/postgres/workshop-migrations/secureshop_agents');
const STAGED = Object.freeze([
  '0011_secureshop_mcp_trust.sql',
  '0012_secureshop_controlled_ssrf.sql',
  '0013_secureshop_conversation_purpose.sql',
]);
const PURPOSES = Object.freeze(Object.values(SECURESHOP_CONVERSATION_PURPOSES));

function ownedUrl(name) {
  const value = new URL(process.env[name]);
  assert.ok(['127.0.0.1', 'localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
function binding() {
  return Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 101, platformSessionId: 102, shopUserId: 103, role: 'customer' });
}
const queue = async (_id, action) => action();


test('agents0013 preserves general conversations and isolates durable histories by purpose', {
  skip: !enabled,
  timeout: 60000,
}, async t => {
  const pools = {};
  for (const variant of VARIANTS) for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${variant}_${role}`;
    pools[key] = new Pool({ connectionString: ownedUrl(`${PREFIX}${key}_URL`), max: 8 });
  }
  t.after(async () => Promise.allSettled(Object.values(pools).map(pool => pool.end())));
  assert.notEqual(new URL(ownedUrl(`${PREFIX}FRESH_RUNTIME_URL`)).pathname,
    new URL(ownedUrl(`${PREFIX}POPULATED_RUNTIME_URL`)).pathname);

  const freshDirectory = view13.directory;
  await view13.migrate(pools.FRESH_MIGRATION, freshDirectory);
  assert.deepEqual(await view13.migrate(pools.FRESH_MIGRATION, freshDirectory), []);
  const expectedFresh = await view13.readMigrations(freshDirectory);
  const actualFresh = (await pools.FRESH_MIGRATION.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  assert.deepEqual(actualFresh, expectedFresh.map(row => ({ name: row.name, checksum: row.checksum })));
  assert.deepEqual(actualFresh.slice(-3).map(row => row.name), STAGED);

  const prefixDirectory = view10.directory;
  await view10.migrate(pools.POPULATED_MIGRATION, prefixDirectory);
  assert.deepEqual(await view10.migrate(pools.POPULATED_MIGRATION, prefixDirectory), []);
  const owned = binding();
  const legacyRepository = createBoundConversationsRepository({ pool: pools.POPULATED_RUNTIME, queue });
  const generalId = randomUUID();
  assert.deepEqual(await legacyRepository.acquireBoundSession({ id: generalId, binding: owned }),
    { id: generalId, state: 'pending', created: true });
  assert.equal(await legacyRepository.activateBoundSession(generalId, owned), true);
  const generalMessage = Object.freeze({ role: 'user', content: 'retained general teaching history' });
  await legacyRepository.appendMessage(generalId, owned, generalMessage);
  assert.deepEqual(await legacyRepository.getBoundSession(generalId), {
    id: generalId, state: 'active', binding: owned,
  }, 'the pre-0013 DTO must not expose a field that its schema cannot support');

  assert.deepEqual(await view13.migrate(pools.POPULATED_MIGRATION, prefixDirectory), STAGED);
  assert.deepEqual(await view13.migrate(pools.POPULATED_MIGRATION, prefixDirectory), []);

  // Construct a new repository as a process restart would. The old instance
  // deliberately cached the absence of the forward capability.
  let repository = createBoundConversationsRepository({ pool: pools.POPULATED_RUNTIME, queue });
  assert.deepEqual(await repository.getBoundSession(generalId), {
    id: generalId, state: 'active', binding: owned, purpose: 'general',
  });
  assert.deepEqual(await repository.getMessages(generalId, owned, 'general'), [generalMessage]);

  for (const variant of VARIANTS) {
    const migration = pools[`${variant}_MIGRATION`];
    const snapshot = async () => {
      const result = {};
      for (const table of ['agent_sessions','conversation_generation_retirements']) {
        result[table] = (await migration.query(`SELECT to_jsonb(r) AS row FROM secureshop_agents.${table} r ORDER BY to_jsonb(r)::text`)).rows;
      }
      return result;
    };
    const before = await snapshot();
    const prior = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    const full = await readMigrations(REGISTERED);
    assert.deepEqual(await migrate(migration, REGISTERED), full.filter(row => Number(row.name.slice(0,4)) > 13).map(row => row.name));
    assert.deepEqual(await migrate(migration, REGISTERED), []);
    const after = (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(after, full.map(({name,checksum}) => ({name,checksum})));
    assert.deepEqual(after.slice(0,prior.length), prior);
    assert.deepEqual(await snapshot(), before);
  }

  repository = createBoundConversationsRepository({ pool: pools.POPULATED_RUNTIME, queue });
  const sessions = new Map([['general', generalId]]);
  for (const purpose of PURPOSES.filter(value => value !== 'general' && value !== 'persona_inbox')) {
    const proposed = randomUUID();
    const acquired = await repository.acquireBoundSession({ id: proposed, binding: owned, purpose });
    assert.deepEqual(acquired, { id: proposed, state: 'pending', created: true });
    assert.equal(await repository.activateBoundSession(proposed, owned, purpose), true);
    sessions.set(purpose, proposed);
  }

  const concurrentIds = [randomUUID(), randomUUID()];
  const concurrent = await Promise.all(concurrentIds.map(id => repository.acquireBoundSession({
    id, binding: owned, purpose: 'persona_inbox',
  })));
  assert.equal(new Set(concurrent.map(value => value.id)).size, 1);
  assert.equal(concurrent.filter(value => value.created).length, 1);
  assert.equal(concurrent.filter(value => !value.created).length, 1);
  const personaInboxId = concurrent[0].id;
  assert.ok(concurrentIds.includes(personaInboxId));
  assert.equal(await repository.activateBoundSession(personaInboxId, owned, 'persona_inbox'), true);
  sessions.set('persona_inbox', personaInboxId);

  for (const purpose of PURPOSES.filter(value => value !== 'general')) {
    await repository.appendMessage(sessions.get(purpose), owned,
      { role: 'user', content: `history:${purpose}` }, purpose);
  }
  assert.deepEqual(await repository.getMessages(sessions.get('mcp_rogue_registration'), owned,
    'mcp_rogue_registration'), [{ role: 'user', content: 'history:mcp_rogue_registration' }]);
  assert.deepEqual(await repository.getMessages(sessions.get('mcp_rug_pull'), owned, 'mcp_rug_pull'),
    [{ role: 'user', content: 'history:mcp_rug_pull' }]);
  await assert.rejects(repository.getMessages(sessions.get('mcp_rogue_registration'), owned,
    'mcp_rug_pull'), { code: 'CONVERSATION_UNAVAILABLE' });
  await assert.rejects(pools.POPULATED_RUNTIME.query(
    'UPDATE secureshop_agents.agent_sessions SET conversation_purpose=$2 WHERE id=$1',
    [sessions.get('mcp_rogue_registration'), 'mcp_rug_pull']), { code: '55000' });

  repository = createBoundConversationsRepository({ pool: pools.POPULATED_RUNTIME, queue });
  for (const purpose of PURPOSES) {
    const replay = await repository.acquireBoundSession({ id: randomUUID(), binding: owned, purpose });
    assert.deepEqual(replay, { id: sessions.get(purpose), state: 'active', created: false });
    const messages = await repository.getMessages(replay.id, owned, purpose);
    assert.equal(messages[0].content, purpose === 'general'
      ? 'retained general teaching history' : `history:${purpose}`);
  }

  const lifecycle = createSecureShopConversationLifecycleRepository({ pool: pools.POPULATED_RUNTIME });
  const resetId = randomUUID();
  const reset = { resetId, binding: owned };
  assert.deepEqual(await lifecycle.beginRetirement(reset), { resetId, status: 'pending' });
  const retirable = await lifecycle.listRetirableSessions(reset);
  assert.equal(retirable.length, PURPOSES.length);
  assert.deepEqual(new Set(retirable.map(row => row.sessionId)), new Set(sessions.values()));
  for (const row of retirable) {
    assert.deepEqual(await lifecycle.retireSession({ ...reset, sessionId: row.sessionId }),
      { sessionId: row.sessionId, replayed: false, uncertainTurns: 0 });
  }
  const completed = await lifecycle.completeRetirement(reset);
  assert.equal(completed.replayed, false);
  assert.equal(completed.receipt.sessionCount, PURPOSES.length);
  assert.deepEqual(await lifecycle.completeRetirement(reset), {
    receipt: completed.receipt, replayed: true,
  });
  for (const purpose of PURPOSES) {
    await assert.rejects(repository.acquireBoundSession({ id: randomUUID(), binding: owned, purpose }),
      { code: 'CONVERSATION_UNAVAILABLE' });
  }

});
