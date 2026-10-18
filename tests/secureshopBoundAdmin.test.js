'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundAdmin } = require('../server/services/secureshopBoundAdmin');
const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2,
  platformOwnerId: 71, platformSessionId: 701 });
const rows = [
  { id: 11, role: 'customer', username: 'student_customer' },
  { id: 12, role: 'merchant', username: 'student_merchant' },
  { id: 13, role: 'admin', username: 'student_admin' },
];
function fixture() {
  const checks = []; const reads = []; let stale = false;
  const service = createSecureShopBoundAdmin({
    launches: { async assertCurrent(value) { checks.push(value); if (stale) throw new Error('stale launch'); } },
    personas: { async listPersonas() { return rows; } },
    account: { async profile(input) {
      reads.push(input); const row = rows.find(r => r.id === input.persona.id);
      return { ...row, email: `owner-${input.scope.platformOwnerId}@example.test`,
        full_name: `Scoped ${row.role}`, phone: null, password: 'must-not-project', api_key: 'must-not-project' };
    } },
  });
  return { service, reads, checks, stale() { stale = true; } };
}
const input = { scope, persona: { id: 13, role: 'admin' } };
test('admin users projects available launch accounts and exact owned profiles, never credentials', async () => {
  const f = fixture(); const result = await f.service.users(input);
  assert.equal(result.total, 3);
  assert.deepEqual(result.users.map(row => row.id), [11, 12, 13]);
  assert.ok(result.users.every(row => row.email === 'owner-71@example.test'));
  assert.ok(result.users.every(row => !Object.hasOwn(row, 'password') && !Object.hasOwn(row, 'api_key')));
  assert.equal(f.checks.length, 2);
  assert.ok(f.reads.every(row => JSON.stringify(row.scope) === JSON.stringify(scope)));
  const other = await f.service.users({ ...input, scope: { ...scope, platformOwnerId: 72, platformSessionId: 702 } });
  assert.ok(other.users.every(row => row.email === 'owner-72@example.test'));
});
test('filters operate on current profile overlay before stable pagination', async () => {
  const f = fixture();
  const result = await f.service.users({ ...input, query: { search: 'Scoped', page: 2, pageSize: 1 } });
  assert.equal(result.total, 3); assert.equal(result.pages, 3); assert.equal(result.users[0].id, 12);
  assert.equal((await f.service.users({ ...input, query: { role: 'merchant' } })).users[0].id, 12);
  assert.equal((await f.service.users({ ...input, query: { banned: 'true' } })).total, 0);
});
test('non-admin and mismatched admin identities cannot read profile rows', async () => {
  const f = fixture();
  for (const persona of [{ id: 11, role: 'customer' }, { id: 99, role: 'admin' }]) {
    await assert.rejects(f.service.users({ ...input, persona }), { code: 'OWNER_MISMATCH' });
  }
  assert.equal(f.reads.length, 0);
});
test('invalid pagination and structured filters are rejected before reads', async () => {
  const f = fixture();
  for (const query of [{ page: 0 }, { pageSize: 101 }, { search: [] }, { role: 'platform_admin' }, { banned: 'yes' }]) {
    await assert.rejects(f.service.users({ ...input, query }), { code: 'INVALID_ARGUMENT' });
  }
  assert.equal(f.reads.length, 0);
});
test('generation retirement during profile reading rejects the whole projection', async () => {
  let checks = 0;
  const service = createSecureShopBoundAdmin({
    launches: { async assertCurrent() { if (++checks === 2) throw new Error('stale launch'); } },
    personas: { async listPersonas() { return rows; } },
    account: { async profile({ persona }) { return rows.find(row => row.id === persona.id); } },
  });
  await assert.rejects(service.users(input), /stale launch/);
});

test('admin KPIs compose owned totals, available accounts and separately scoped active sessions', async () => {
  const calls = [];
  const target = { ...scope, targetId: '30000000-0000-4000-8000-000000000001' };
  const service = createSecureShopBoundAdmin({
    launches: { async assertCurrent(value) { assert.deepEqual(value, scope); calls.push('check'); } },
    personas: { async listPersonas() { return rows; }, async countActiveSessions({ scope: value }) {
      assert.deepEqual(value, scope); return 2;
    } },
    account: { async profile({ persona }) { return rows.find(row => row.id === persona.id); } },
    catalog: { async prepareTarget(value) { assert.deepEqual(value.scope, scope); return target; } },
    commerceRepository: { async adminSummary(value) { assert.equal(value, target);
      return { total_products: 5, total_orders: 2, total_revenue: 29.95, revenue_basis: 'gross_order_total' };
    } },
  });
  assert.deepEqual(await service.kpis(input), { total_users: 3, admin_count: 1, banned_count: 0,
    active_sessions: 2, total_products: 5, total_orders: 2, total_revenue: 29.95, revenue_basis: 'gross_order_total' });
  assert.equal(calls.length, 3);
  await assert.rejects(service.kpis({ ...input, persona: { id: 11, role: 'customer' } }), { code: 'OWNER_MISMATCH' });
});

test('protected admin directory authorizes the admin observation without impersonating targets', async () => {
  const session = { sessionId: '30000000-0000-4000-8000-000000000013', authorityVersion: '4' };
  const calls = []; let revoked = false;
  const binding = { ...scope, personaId: 13, role: 'admin', ...session };
  const target = { ...scope, targetId: '30000000-0000-4000-8000-000000000001' };
  const service = createSecureShopBoundAdmin({
    launches: { async assertCurrent() {} }, personas: { async listPersonas() {
      return rows.map(row => row.id === 13 ? { ...row, role: 'customer' } : row);
    } },
    account: { async profile() { throw new Error('target personas must not be impersonated'); } },
    personaAuthority: { async capture(input) { calls.push(['capture', input]); return {
      binding, async assertRemoteAdmission() { calls.push(['check']); if (revoked) throw Object.assign(new Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); },
      async withCrossStoreEffect(work) { return work(); },
    }; } },
    catalog: { async prepareTarget(input) { calls.push(['target', input.persona, input.personaEffect]); return target; } },
    administrationRepository: { async readEffectivePersona({ shopUserId }) {
      calls.push(['state', shopUserId]); return { role: shopUserId === 11 ? 'merchant' : rows.find(r => r.id === shopUserId).role,
        banned_at: shopUserId === 12 ? '2026-09-20T00:00:00.000Z' : null, version: '2' };
    } },
    accountRepository: { async readProfile(value, shopUserId) { assert.equal(value, target);
      calls.push(['profile', shopUserId]); return { email: `user-${shopUserId}@example.test`, full_name: shopUserId === 11 ? null : `User ${shopUserId}`, phone: null }; } },
  });
  const mutable = { scope: { ...scope }, persona: { ...input.persona }, personaSession: { ...session } };
  const pending = service.users(mutable);
  mutable.persona.id = 11; mutable.persona.role = 'customer';
  mutable.personaSession.authorityVersion = '99'; mutable.scope.platformOwnerId = 999;
  const result = await pending;
  assert.deepEqual(result.users.map(row => [row.id, row.role, row.banned_at !== null]),
    [[11, 'merchant', false], [12, 'merchant', true], [13, 'admin', false]]);
  assert.equal(result.users[0].full_name, null, 'an explicit cleared overlay must not fall back to template identity');
  assert.equal(calls.filter(([name]) => name === 'capture').length, 1);
  assert.equal(calls.find(([name]) => name === 'capture')[1].personaId, 13);
  assert.equal(calls.find(([name]) => name === 'capture')[1].authorityVersion, '4');
  assert.equal(calls.find(([name]) => name === 'target')[1].id, 13);
  assert.equal(calls.filter(([name]) => name === 'profile').length, 3);
  assert.equal((await service.users({ ...input, personaSession: session, query: { role: 'banned' } })).total, 1);
  revoked = true;
  await assert.rejects(service.users({ ...input, personaSession: session }), { code: 'SHOP_AUTH_INVALID' });
});

test('protected admin observations reject missing and substituted credential snapshots before reads', async () => {
  let reads = 0;
  const service = createSecureShopBoundAdmin({
    launches: { async assertCurrent() {} }, personas: { async listPersonas() { reads++; return rows; } },
    account: { async profile() {} }, catalog: { async prepareTarget() {} },
    accountRepository: { async readProfile() {} }, administrationRepository: { async readEffectivePersona() {} },
    personaAuthority: { async capture() { return { binding: { ...scope, personaId: 13, role: 'admin',
      sessionId: '30000000-0000-4000-8000-000000000013', authorityVersion: '9' },
    async assertRemoteAdmission() {}, async withCrossStoreEffect(work) { return work(); } }; } },
    readAdapter: { async runtimeHealth() { reads++; return {}; } },
  });
  await assert.rejects(service.runtimeHealth(input), { code: 'SHOP_AUTH_INVALID' });
  await assert.rejects(service.runtimeHealth({ ...input, personaSession: {
    sessionId: '30000000-0000-4000-8000-000000000013', authorityVersion: '8' } }), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(reads, 0);
});

test('admin observations use launch scope and admin binding with a final retirement fence', async () => {
  const calls = []; let retired = false;
  const service = createSecureShopBoundAdmin({
    launches: { async assertCurrent() { if (retired) throw new Error('retired'); } },
    personas: { async listPersonas() { return rows; } },
    account: { async profile() { throw new Error('observations must not provision product targets'); } },
    conversations: {
      async latestObservedProviders(value) { assert.deepEqual(value, scope); calls.push('providers');
        return [{ role: 'customer', active_provider: 'controlled-fixture' }]; },
      async adminLatestTrace(binding, limit) { assert.equal(binding.shopUserId, 13);
        assert.equal(binding.role, 'admin'); assert.equal(binding.platformOwnerId, scope.platformOwnerId);
        assert.equal(limit, 5); calls.push('trace'); retired = true; return []; },
    },
  });
  assert.equal((await service.providers(input))[0].active_provider, 'controlled-fixture');
  await assert.rejects(service.providers({ ...input, persona: { id: 11, role: 'customer' } }), { code: 'OWNER_MISMATCH' });
  await assert.rejects(service.latestTrace({ ...input, limit: 5 }), /retired/);
  assert.deepEqual(calls, ['providers', 'trace']);
});

test('audit reads all current-launch personas only for canonical admin and fences final retirement', async()=>{
  let retired=false, reads=0;
  const service=createSecureShopBoundAdmin({
    launches:{async assertCurrent(){if(retired)throw Error('retired');}},
    personas:{async listPersonas(){return rows;}},account:{async profile(){throw Error('not needed');}},
    auditRepository:{async recent(value,query){reads++;assert.deepEqual(value,scope);assert.equal(query.limit,10);retired=true;return {count:0,events:[]};}},
  });
  await assert.rejects(service.audit({...input,persona:{id:11,role:'customer'},query:{limit:10}}),{code:'OWNER_MISMATCH'});
  assert.equal(reads,0);
  await assert.rejects(service.audit({...input,query:{limit:10}}),/retired/);assert.equal(reads,1);
});
