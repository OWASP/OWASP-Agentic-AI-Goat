'use strict';

// Controlled assembly contracts only. No store, browser, executor or model starts.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const filename = path.join(__dirname, 'postgres/secureshopStandaloneListingsRendered.integration.test.js');
const source = fs.readFileSync(filename, 'utf8');
const realRequire = createRequire(filename);

function load(env = {}, entry = false) {
  let allocations = 0;
  const registered = [];
  const module = { exports: {} };
  function require(name) {
    if (name === 'node:test') return (...args) => registered.push(args);
    if (name === 'pg') return { Pool: class { constructor() { allocations++; throw Error('Resource allocation forbidden'); } } };
    return realRequire(name);
  }
  require.main = entry ? module : {};
  vm.compileFunction(source, ['require', 'module', 'process', '__dirname'], { filename })(
    require, module, { env, cwd: () => '/' }, path.dirname(filename));
  return { ...module.exports, registered, allocations: () => allocations };
}

test('importing the assembly registers no default test and allocates nothing', () => {
  const fixture = load();
  assert.equal(typeof fixture.runStandaloneListingsQualification, 'function');
  assert.deepEqual(fixture.registered, []);
  assert.equal(fixture.allocations(), 0);
});

test('direct default execution remains explicitly gated and resource-free when disabled', async () => {
  const fixture = load({}, true);
  assert.equal(fixture.registered.length, 1);
  assert.equal(fixture.registered[0][1].skip, true);
  assert.equal(fixture.registered[0][1].timeout, 540000);
  await assert.rejects(fixture.registered[0][2](), /Explicit disposable native cohort/);
  assert.equal(fixture.allocations(), 0);
});

test('scenario options cannot omit isolation, expand objectives or collide with an existing cohort', async () => {
  const options = { exercise: async () => { throw Error('Must not enter'); },
    objectiveIds: ['ss_listing_prototype_mutation', 'ss_listing_external_entity'], receiptPath: '/private/receipt.json' };
  const scenarios = [
    [{}, options, /'1'/],
    [{ SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE: '1' }, options, /'yes'/],
    [{ SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes' }, options, /'1'/],
    [{ SECURESHOP_STANDALONE_LISTINGS_NATIVE: '1' }, options, /also activate/],
    [{}, { ...options, objectiveIds: ['ss_listing_internal_fetch'] }],
    [{}, { ...options, extra: true }],
  ];
  for (const [env, input, expected] of scenarios) {
    const fixture = load(env);
    await assert.rejects(fixture.runStandaloneListingsQualification(input), expected);
    assert.equal(fixture.allocations(), 0);
  }
});

test('scenario remains within the one existing cleanup boundary and cannot publish cleanup success', () => {
  const start = source.indexOf('    try {\n      status.isolatedStores = true;');
  const callback = source.indexOf('const result = await exercise(');
  const catchStart = source.indexOf('    } catch (error) {\n      failure = error;', callback);
  const finalizer = source.indexOf('    finally {', catchStart);
  const finalCheck = source.indexOf('    if (failure) throw failure;', finalizer);
  assert(start > 0 && callback > start && catchStart > callback && finalizer > catchStart && finalCheck > finalizer);
  assert(source.slice(callback, catchStart).includes("Object.hasOwn(result, 'fixtureCleaned'), false"));
  const cleanup = source.slice(finalizer, finalCheck);
  for (const text of ['restoreFetch?.()', 'browser.close()', 'closeServer(server)',
    'closeFeatureTransports()', 'pool.end()', 'fs.rm(profile', 'status.fixtureCleaned = cleanupErrors.length === 0']) {
    assert(cleanup.includes(text), text);
  }
  assert(cleanup.indexOf('status.fixtureCleaned =') < cleanup.indexOf('fs.writeFile(receiptPath'));
});

test('import sibling enrolls a distinct tenant before fresh authentication and uses its exact scoped service', async () => {
  const fixture = load(), calls = [];
  const principal = { principalId: 'peer-principal', shopUserId: 1000000001 };
  const base = { session: 'fresh' }, tenant = { tenantId: 'peer-tenant', principalId: principal.principalId };
  const service = {
    async authenticate(token) { calls.push('authenticate'); assert.equal(token, 'fresh-token'); return base; },
    async establishTenantContext(input) { calls.push('context'); assert.equal(input, base); return tenant; },
  };
  const result = await fixture.createImportSiblingTenant({
    migration: { async query(sql, values) { calls.push({ sql, values }); return { rowCount: 1 }; } },
    auth: { async login(input) { calls.push('login'); assert.deepEqual(input, { username: 'peer', password: 'private' }); return { token: 'fresh-token' }; } },
    repositoryFactory(options) { calls.push('repository'); assert.deepEqual(options, { executionTenantSlug: 'peer-slug' }); return 'scoped'; },
    authFactory(repository) { calls.push('service'); assert.equal(repository, 'scoped'); return service; },
    principal, username: 'peer', password: 'private', tenantId: 'peer-tenant', slug: 'peer-slug',
  });
  assert.match(calls[0].sql, /INSERT INTO secureshop_auth.tenants/);
  assert.deepEqual(calls[0].values, ['peer-tenant', 'peer-slug']);
  assert.match(calls[1].sql, /INSERT INTO secureshop_auth.tenant_memberships/);
  assert.deepEqual(calls[1].values, ['peer-tenant', principal.principalId, principal.shopUserId, 'merchant']);
  assert.match(calls[2].sql, /SET seed_merchant_id=\$2/);
  assert.deepEqual(calls[2].values, ['peer-tenant', principal.shopUserId]);
  assert.deepEqual(calls.slice(3), ['login', 'repository', 'service', 'authenticate', 'context']);
  assert.equal(result.service, service); assert.equal(result.base, base); assert.equal(result.tenant, tenant);
});

test('import sibling rejects a returned default tenant or substituted principal', async () => {
  const fixture = load();
  for (const tenant of [{ tenantId: 'default', principalId: 'peer' }, { tenantId: 'isolated', principalId: 'foreign' }]) {
    await assert.rejects(fixture.createImportSiblingTenant({
      migration: { async query() { return { rowCount: 1 }; } },
      auth: { async login() { return { token: 'fresh' }; } },
      repositoryFactory: () => ({}),
      authFactory: () => ({ authenticate: async () => ({}), establishTenantContext: async () => tenant }),
      principal: { principalId: 'peer', shopUserId: 1000000001 },
      username: 'peer', password: 'private', tenantId: 'isolated', slug: 'isolated',
    }));
  }
});
