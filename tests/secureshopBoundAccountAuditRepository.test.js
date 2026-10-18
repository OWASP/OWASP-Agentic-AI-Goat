'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundAccountRepository } = require(
  '../server/database/postgres/secureshopBoundAccountRepository');
const { createSecureShopBoundAccount } = require('../server/services/secureshopBoundAccount');

const scope = Object.freeze({
  targetId: '30000000-0000-4000-8000-000000000071',
  launchId: '10000000-0000-4000-8000-000000000071',
  scenarioId: '20000000-0000-4000-8000-000000000071',
  generation: 3, platformOwnerId: 71, platformSessionId: 701,
});
const persona = Object.freeze({ id: 41, role: 'merchant' });

function poolFor(query) {
  return { async query() { throw new Error('effect must use its transaction'); },
    async connect() { return { query, release() {} }; } };
}
function common(sql) {
  if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return { rows: [] };
  if (sql.includes('FROM secureshop_review.product_targets')) {
    return { rows: [{ lifecycle: 'active' }], rowCount: 1 };
  }
  if (sql.includes('pg_advisory_xact_lock')) return { rows: [], rowCount: 1 };
  return null;
}
function storedAddress(id, fields) {
  return { address_id: id, label: fields.label, line1: fields.line1, line2: fields.line2,
    city: fields.city, state: fields.state, zip: fields.zip, phone: fields.phone,
    is_default: fields.isDefault, created_at: '2026-09-19T00:00:00.000Z' };
}

test('profile and address effects append exact scoped events in their owning transactions', async () => {
  const events = [];
  let nextAddressId = 11;
  const clientQuery = async (sql, args) => {
    const known = common(sql); if (known) return known;
    if (sql.includes('product_target_profile_overlays')) {
      return { rows: [{ email: args[2], full_name: args[3], phone: args[4] }], rowCount: 1 };
    }
    if (sql.includes('count(*)::integer')) return { rows: [{ count: 0 }], rowCount: 1 };
    if (sql.includes('SELECT address_id')) return { rows: [{ address_id: args[2] }], rowCount: 1 };
    if (sql.includes('SET is_default=false')) return { rows: [], rowCount: 1 };
    if (sql.includes('INSERT INTO secureshop_review.product_target_addresses')) {
      return { rows: [storedAddress(nextAddressId++, { label: args[2], line1: args[3],
        line2: args[4], city: args[5], state: args[6], zip: args[7], phone: args[8],
        isDefault: args[9] })], rowCount: 1 };
    }
    if (sql.includes('UPDATE secureshop_review.product_target_addresses')) {
      return { rows: [storedAddress(args[10], { label: args[2], line1: args[3],
        line2: args[4], city: args[5], state: args[6], zip: args[7], phone: args[8],
        isDefault: args[9] })], rowCount: 1 };
    }
    if (sql.includes('DELETE FROM secureshop_review.product_target_addresses')) {
      return { rows: [], rowCount: 1 };
    }
    throw new Error(`unexpected query: ${sql}`);
  };
  const transactionClients = [];
  const basePool = poolFor(clientQuery);
  const pool = { ...basePool, async connect() {
    const client = await basePool.connect(); transactionClients.push(client); return client;
  } };
  const repository = createSecureShopBoundAccountRepository(pool, {
    checkCurrent: async () => {},
    auditStore: { async append(client, event) { events.push({ client, event }); } },
  });

  await repository.updateProfile(scope, 41, { email: 'merchant@example.test',
    fullName: 'Merchant\nforged-action=admin', phone: '555\r\noutcome=completed' }, persona);
  const fields = { label: 'Home\nactor=admin', line1: '1 Main\r\naction=refund', line2: null,
    city: 'Seattle', state: 'WA', zip: '98101', phone: '555', isDefault: false };
  const created = await repository.saveAddress(scope, 41, null, fields, persona);
  await repository.saveAddress(scope, 41, created.id, { ...fields, line1: '2 Main' }, persona);
  await repository.deleteAddress(scope, 41, created.id, persona);

  assert.deepEqual(events.map(({ event }) => event.action),
    ['profile_update', 'address_create', 'address_update', 'address_delete']);
  assert.deepEqual(events.map(({ event }) => event.sourceKind),
    ['profile', 'address', 'address', 'address']);
  for (let index = 0; index < events.length; index += 1) {
    const { client, event } = events[index];
    assert.equal(client, transactionClients[index]);
    assert.deepEqual(event.scope, scope);
    assert.deepEqual(event.persona, persona);
    assert.equal(event.actor, 'merchant');
    assert.equal(event.outcome, 'completed');
  }
  assert.equal(events[0].event.target, '41');
  assert.equal(events[1].event.target, String(created.id));
  assert.equal(JSON.parse(events[0].event.paramsJson).fullName, 'Merchant\nforged-action=admin');
  assert.equal(JSON.parse(events[1].event.paramsJson).line1, '1 Main\r\naction=refund');
});

test('absent address updates and deletes do not append completed events', async () => {
  const events = [];
  const repository = createSecureShopBoundAccountRepository(poolFor(async (sql) => {
    const known = common(sql); if (known) return known;
    if (sql.includes('SELECT address_id')) return { rows: [], rowCount: 0 };
    if (sql.includes('DELETE FROM secureshop_review.product_target_addresses')) {
      return { rows: [], rowCount: 0 };
    }
    throw new Error(`unexpected query: ${sql}`);
  }), { checkCurrent: async () => {}, auditStore: { async append(_client, event) { events.push(event); } } });
  const fields = { label: null, line1: 'Missing', line2: null, city: null,
    state: null, zip: null, phone: null, isDefault: false };
  assert.equal(await repository.saveAddress(scope, 41, 99, fields, persona), null);
  assert.equal(await repository.deleteAddress(scope, 41, 99, persona), 0);
  assert.deepEqual(events, []);
});

test('an audit append failure rolls back the profile effect', async () => {
  let stored = null;
  let before = null;
  const queries = [];
  const repository = createSecureShopBoundAccountRepository(poolFor(async (sql, args) => {
    queries.push(sql);
    if (sql === 'BEGIN') { before = stored; return { rows: [] }; }
    if (sql === 'ROLLBACK') { stored = before; return { rows: [] }; }
    if (sql === 'COMMIT') return { rows: [] };
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows: [{ lifecycle: 'active' }] };
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
    if (sql.includes('product_target_profile_overlays')) {
      stored = { email: args[2], full_name: args[3], phone: args[4] };
      return { rows: [stored], rowCount: 1 };
    }
    throw new Error(`unexpected query: ${sql}`);
  }), { checkCurrent: async () => {}, auditStore: { async append() { throw new Error('journal unavailable'); } } });
  await assert.rejects(repository.updateProfile(scope, 41, { email: 'rollback@example.test',
    fullName: 'Rollback', phone: null }, persona), /journal unavailable/);
  assert.equal(stored, null);
  assert.ok(queries.includes('ROLLBACK'));
  assert.equal(queries.includes('COMMIT'), false);
});

test('audit-enabled mutations require the canonical role and matching shop user id', async () => {
  let connected = false;
  const repository = createSecureShopBoundAccountRepository({ query() {}, async connect() {
    connected = true; throw new Error('must reject before transaction');
  } }, { checkCurrent: async () => {}, auditStore: { async append() {} } });
  const profile = { email: 'valid@example.test', fullName: null, phone: null };
  assert.throws(() => repository.updateProfile(scope, 41, profile), { code: 'INVALID_ARGUMENT' });
  assert.throws(() => repository.updateProfile(scope, 41, profile, { id: 42, role: 'merchant' }),
    { code: 'INVALID_ARGUMENT' });
  assert.throws(() => repository.updateProfile(scope, 41, profile, { id: 41, role: 'owner' }),
    { code: 'INVALID_ARGUMENT' });
  assert.equal(connected, false);
});

test('account service forwards its canonical persona to every mutation', async () => {
  const supplied = [];
  const repository = {
    async readProfile() { return null; }, async listAddresses() { return []; },
    async updateProfile(...args) { supplied.push(args.at(-1));
      return { email: 'm@example.test', full_name: null, phone: null }; },
    async saveAddress(...args) { supplied.push(args.at(-1)); return { id: 8 }; },
    async deleteAddress(...args) { supplied.push(args.at(-1)); return 1; },
  };
  const canonical = Object.freeze({ id: 41, role: 'merchant', username: 'merchant',
    email: 'canonical@example.test' });
  const service = createSecureShopBoundAccount({ repository,
    personaRepository: { async readPersona() { return canonical; } },
    catalog: { async prepareTarget() { return scope; } } });
  const input = { scope, persona };
  await service.updateProfile({ ...input, email: 'm@example.test', fullName: null, phone: null });
  await service.createAddress({ ...input, address: {} });
  await service.updateAddress({ ...input, addressId: 8, address: {} });
  await service.deleteAddress({ ...input, addressId: 8 });
  assert.equal(supplied.length, 4);
  assert.ok(supplied.every(value => value.id === canonical.id && value.role === canonical.role));
});
