'use strict';

// Storage/migration proof only. Synthetic history rows are not model execution,
// platform authentication, tool effects, or objective credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { createAgentsMigrationView } = require('../helpers/secureshopAgentsMigrationView');
const { createBoundConversationsRepository } =
  require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } =
  require('../../server/services/secureshopConversationPurpose');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_IDOR_PURPOSE_';
const NAME = '0086_idor_lesson_conversation_purpose.sql';
const VARIANTS = ['FRESH', 'POPULATED'];
const enabled = process.env.SECURESHOP_IDOR_PURPOSE_MIGRATION_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes';
const queue = async (_id, work) => work();

function admittedUrls() {
  assert.equal(path.resolve(process.cwd()), ROOT);
  assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
  const owner = process.env[`${PREFIX}OWNER`];
  assert.match(owner, /^[a-f0-9]{12}$/);
  const values = {}; let port;
  for (const variant of VARIANTS) for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${variant}_${role}`;
    const url = new URL(process.env[`${PREFIX}${key}_URL`]);
    assert.equal(url.protocol, 'postgresql:');
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.username, `dvaia_secureshop_agents_${role.toLowerCase()}`);
    assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
    assert.equal(url.pathname, `/owasp_ai_goat_test_idor_purpose_${owner}_${variant.toLowerCase()}`);
    assert.match(url.port, /^[1-9][0-9]{0,4}$/); assert.ok(Number(url.port) <= 65535);
    port ??= url.port; assert.equal(url.port, port);
    values[key] = url.href;
  }
  assert.notEqual(new URL(values.FRESH_RUNTIME).pathname,
    new URL(values.POPULATED_RUNTIME).pathname);
  return values;
}

const scope = () => ({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: 101, platformSessionId: 102, shopUserId: 103, role: 'customer' });
const snapshot = async pool => (await pool.query(`SELECT to_jsonb(s) AS row
  FROM secureshop_agents.agent_sessions s ORDER BY id`)).rows;
const ledger = async pool => (await pool.query(`SELECT name,checksum
  FROM dvaia_migrations.ledger ORDER BY name`)).rows;

test('agents0086 qualifies fresh, populated0085 and no-op purpose admission without changing prior history',
  { skip: !enabled, timeout: 180000 }, async t => {
    const urls = admittedUrls();
    const pools = Object.fromEntries(Object.entries(urls).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: 3, connectionTimeoutMillis: 1500,
        statement_timeout: 8000, lock_timeout: 3000 })]));
    t.after(async () => {
      const results = await Promise.allSettled(Object.values(pools).map(pool => pool.end()));
      assert.ok(results.every(result => result.status === 'fulfilled'), 'all owned pools must close');
    });
    const prior = createAgentsMigrationView(85), current = createAgentsMigrationView(86);
    const oldFiles = await prior.readMigrations(prior.directory);
    const files = await current.readMigrations(current.directory);
    assert.deepEqual(files.slice(0, oldFiles.length), oldFiles);
    assert.deepEqual(files.slice(oldFiles.length).map(row => row.name), [NAME]);

    assert.deepEqual(await current.migrate(pools.FRESH_MIGRATION, current.directory),
      files.map(row => row.name));
    assert.deepEqual(await current.migrate(pools.FRESH_MIGRATION, current.directory), []);
    assert.deepEqual(await ledger(pools.FRESH_MIGRATION),
      files.map(({ name, checksum }) => ({ name, checksum })));

    assert.deepEqual(await prior.migrate(pools.POPULATED_MIGRATION, prior.directory),
      oldFiles.map(row => row.name));
    const owned = scope(), oldPurposes = Object.values(PURPOSES).filter(value => value !== PURPOSES.idorLesson);
    const repository = createBoundConversationsRepository({ pool: pools.POPULATED_RUNTIME, queue });
    const sessions = new Map();
    for (const purpose of oldPurposes) {
      const id = randomUUID();
      assert.deepEqual(await repository.acquireBoundSession({ id, binding: owned, purpose }),
        { id, state: 'pending', created: true });
      assert.equal(await repository.activateBoundSession(id, owned, purpose), true);
      await repository.appendMessage(id, owned,
        { role: 'user', content: `Controlled retained history: ${purpose}` }, purpose);
      sessions.set(purpose, id);
    }
    const legacyId = `legacy-purpose-${randomUUID()}`;
    await pools.POPULATED_MIGRATION.query(`INSERT INTO secureshop_agents.agent_sessions
      (id,user_id,role,messages_json) VALUES($1,103,'customer',$2)`,
    [legacyId, JSON.stringify([{ role: 'user', content: 'Retained legacy general history' }])]);
    await assert.rejects(repository.acquireBoundSession({ id: randomUUID(), binding: owned,
      purpose: PURPOSES.idorLesson }), { code: '23514' });
    const before = await snapshot(pools.POPULATED_MIGRATION);
    const oldLedger = await ledger(pools.POPULATED_MIGRATION);
    assert.deepEqual(await current.migrate(pools.POPULATED_MIGRATION, current.directory), [NAME]);
    assert.deepEqual(await snapshot(pools.POPULATED_MIGRATION), before);
    const upgradedLedger = await ledger(pools.POPULATED_MIGRATION);
    assert.deepEqual(upgradedLedger.slice(0, oldLedger.length), oldLedger);
    assert.deepEqual(upgradedLedger, files.map(({ name, checksum }) => ({ name, checksum })));

    for (const variant of VARIANTS) {
      const runtime = pools[`${variant}_RUNTIME`], migration = pools[`${variant}_MIGRATION`];
      const identity = (await runtime.query('SELECT current_user AS role')).rows[0];
      assert.equal(identity.role, 'dvaia_secureshop_agents_runtime');
      const restarted = createBoundConversationsRepository({ pool: runtime, queue });
      const binding = variant === 'POPULATED' ? owned : scope();
      const id = randomUUID();
      assert.deepEqual(await restarted.acquireBoundSession({ id, binding, purpose: PURPOSES.idorLesson }),
        { id, state: 'pending', created: true });
      assert.equal(await restarted.activateBoundSession(id, binding, PURPOSES.idorLesson), true);
      const message = { role: 'user', content: 'Controlled IDOR lesson history' };
      await restarted.appendMessage(id, binding, message, PURPOSES.idorLesson);
      assert.deepEqual(await restarted.acquireBoundSession({ id: randomUUID(), binding,
        purpose: PURPOSES.idorLesson }), { id, state: 'active', created: false });
      assert.deepEqual(await restarted.getMessages(id, binding, PURPOSES.idorLesson), [message]);
      await assert.rejects(restarted.getMessages(id, binding, PURPOSES.general),
        { code: 'CONVERSATION_UNAVAILABLE' });
      await assert.rejects(runtime.query(`UPDATE secureshop_agents.agent_sessions
        SET conversation_purpose='general' WHERE id=$1`, [id]), { code: '55000' });
      await assert.rejects(migration.query(`INSERT INTO secureshop_agents.agent_sessions
        (id,user_id,role,conversation_purpose) VALUES($1,103,'customer',$2)`,
      [`legacy-idor-${randomUUID()}`, PURPOSES.idorLesson]), { code: '23514' });
      const beforeNoop = await snapshot(migration);
      assert.deepEqual(await current.migrate(migration, current.directory), []);
      assert.deepEqual(await snapshot(migration), beforeNoop);
      assert.deepEqual(await ledger(migration), upgradedLedger);
    }
    for (const purpose of oldPurposes) assert.deepEqual(await repository.getMessages(
      sessions.get(purpose), owned, purpose),
    [{ role: 'user', content: `Controlled retained history: ${purpose}` }]);
  });
