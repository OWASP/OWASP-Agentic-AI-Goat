'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundAccount } = require('../server/services/secureshopBoundAccount');
const { createSecureShopBoundAccountRepository } = require(
  '../server/database/postgres/secureshopBoundAccountRepository');

const target = Object.freeze({ targetId: '30000000-0000-4000-8000-000000000061',
  launchId: '10000000-0000-4000-8000-000000000061',
  scenarioId: '20000000-0000-4000-8000-000000000061', generation: 2,
  platformOwnerId: 61, platformSessionId: 601 });
const context = Object.freeze({ scope: Object.freeze({ launchId: target.launchId,
  scenarioId: target.scenarioId, generation: target.generation,
  platformOwnerId: target.platformOwnerId, platformSessionId: target.platformSessionId }),
persona: Object.freeze({ id: 41, role: 'customer' }) });

test('account service composes overlays without mutating the canonical persona', async () => {
  const canonical = Object.freeze({ id: 41, username: 'student_customer', role: 'customer',
    email: 'canonical@example.test', full_name: 'Canonical Name', phone: null });
  const calls = [];
  const repository = {
    async readProfile(value, owner) { calls.push(['read', value, owner]); return null; },
    async updateProfile(value, owner, profile) { calls.push(['update', value, owner, profile]);
      return { email: profile.email, full_name: profile.fullName, phone: profile.phone }; },
    async listAddresses(value, owner) { calls.push(['list', value, owner]); return []; },
    async saveAddress(value, owner, id, address) { calls.push(['save', value, owner, id, address]);
      return { id: id || 7, ...address }; },
    async deleteAddress(value, owner, id) { calls.push(['delete', value, owner, id]); return 1; },
  };
  const service = createSecureShopBoundAccount({ repository,
    personaRepository: { async readPersona(id) { assert.equal(id, 41); return canonical; } },
    catalog: { async prepareTarget(input) { assert.equal(input.scope, context.scope);
      assert.equal(input.persona, context.persona); return target; } } });
  assert.deepEqual(await service.profile(context), canonical);
  const updated = await service.updateProfile({ ...context, fullName: 'Overlay Name',
    email: 'overlay@example.test', phone: '555' });
  assert.deepEqual(updated, { ...canonical, full_name: 'Overlay Name',
    email: 'overlay@example.test', phone: '555' });
  assert.deepEqual(canonical, { id: 41, username: 'student_customer', role: 'customer',
    email: 'canonical@example.test', full_name: 'Canonical Name', phone: null });
  await service.addresses(context);
  await service.createAddress({ ...context, address: { line1: '1 Main', isDefault: false } });
  await service.updateAddress({ ...context, addressId: 7,
    address: { line1: '2 Main', isDefault: true } });
  await service.deleteAddress({ ...context, addressId: 7 });
  assert.ok(calls.every(call => call[2] === 41));
  assert.ok(calls.every(call => call[1] === target));
});

test('account service rejects a persona not backed by the immutable catalog', async () => {
  const repository = Object.fromEntries(['readProfile','updateProfile','listAddresses','saveAddress','deleteAddress']
    .map(name => [name, async () => { throw new Error(name); }]));
  const service = createSecureShopBoundAccount({ repository,
    personaRepository: { async readPersona() { return { id: 42, role: 'customer' }; } },
    catalog: { async prepareTarget() { return target; } } });
  await assert.rejects(service.profile(context), { code: 'OWNER_MISMATCH' });
});

test('account profile resolves a standalone actor only in the current owner scope', async () => {
  const actor = { id: 1000000001, username: 'independent_customer', role: 'customer', email: 'shop@example.test' };
  const repository = Object.fromEntries(['readProfile','updateProfile','listAddresses','saveAddress','deleteAddress']
    .map(name => [name, async () => null]));
  const service = createSecureShopBoundAccount({ repository,
    personaRepository: { async readPersona(id, scope) {
      assert.equal(id, actor.id);
      return scope?.platformOwnerId === context.scope.platformOwnerId ? actor : null;
    } }, catalog: { async prepareTarget() { return target; } } });
  assert.equal((await service.profile({ ...context, persona: actor })).id, actor.id);
  await assert.rejects(service.profile({ scope: { ...context.scope, platformOwnerId: 999 }, persona: actor }),
    { code: 'OWNER_MISMATCH' });
});

function repositoryFixture() {
  const events = [];
  const rows = [];
  let nextId = 1;
  let releaseLock = Promise.resolve();
  const clients = [];
  function makeClient() {
    let unlock = () => {};
    const client = { async query(sql, args) {
      if (sql === 'BEGIN') return { rows: [] };
      if (sql === 'COMMIT' || sql === 'ROLLBACK') { unlock(); events.push(sql); return { rows: [] }; }
      if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
      if (sql.includes('pg_advisory_xact_lock')) {
        events.push('lock-wait'); const previous = releaseLock;
        let resolve; releaseLock = new Promise(done => { resolve = done; }); unlock = resolve;
        await previous; events.push('lock-acquired'); return { rows: [] };
      }
      if (sql.includes('count(*)::integer')) return { rows: [{ count: rows.length }] };
      if (sql.startsWith('UPDATE secureshop_review.product_target_addresses\n          SET is_default=false')) {
        for (const row of rows) if (row.shop_user_id === args[1]) row.is_default = false;
        return { rows: [], rowCount: rows.length };
      }
      if (sql.includes('INSERT INTO secureshop_review.product_target_addresses')) {
        const row = { target_id: args[0], shop_user_id: args[1], address_id: nextId++, label: args[2],
          line1: args[3], line2: args[4], city: args[5], state: args[6], zip: args[7], phone: args[8],
          is_default: args[9], created_at: '2026-09-18T00:00:00Z' };
        rows.push(row); events.push(`insert-${row.address_id}`); return { rows: [row], rowCount: 1 };
      }
      throw new Error(`unexpected query: ${sql}`);
    }, release() {} };
    clients.push(client); return client;
  }
  return { pool: { async query() { throw new Error('transaction required'); },
    async connect() { return makeClient(); } }, rows, events, clients };
}

test('address writes serialize on target and persona before enforcing one default', async () => {
  const fixture = repositoryFixture();
  const repository = createSecureShopBoundAccountRepository(fixture.pool, { checkCurrent: async () => {} });
  const first = repository.saveAddress(target, 41, null, { label: 'Home', line1: '1 Main',
    line2: null, city: null, state: null, zip: null, phone: null, isDefault: true });
  const second = repository.saveAddress(target, 41, null, { label: 'Work', line1: '2 Main',
    line2: null, city: null, state: null, zip: null, phone: null, isDefault: true });
  const results = await Promise.all([first, second]);
  assert.deepEqual(results.map(row => row.id), [1, 2]);
  assert.deepEqual(fixture.events, ['lock-wait', 'lock-wait', 'lock-acquired', 'insert-1', 'COMMIT',
    'lock-acquired', 'insert-2', 'COMMIT']);
  assert.equal(fixture.rows.filter(row => row.is_default).length, 1);
  assert.equal(fixture.rows.find(row => row.is_default).address_id, 2);
});

test('foreign address update returns null before clearing the owned default', async () => {
  const queries = [];
  const client = { async query(sql, args) {
    queries.push([sql, args]);
    if (['BEGIN','COMMIT','ROLLBACK'].includes(sql)) return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('SELECT address_id')) return { rows: [], rowCount: 0 };
    throw new Error(`unexpected query: ${sql}`);
  }, release() {} };
  const repository = createSecureShopBoundAccountRepository({ query() {}, async connect() { return client; } },
    { checkCurrent: async () => {} });
  assert.equal(await repository.saveAddress(target, 41, 99, { label: null, line1: '1 Main', line2: null,
    city: null, state: null, zip: null, phone: null, isDefault: true }), null);
  assert.equal(queries.some(([sql]) => sql.includes('SET is_default=false')), false);
  assert.match(queries.find(([sql]) => sql.includes('SELECT address_id'))[0],
    /target_id=\$1 AND shop_user_id=\$2 AND address_id=\$3/);
});
