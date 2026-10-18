'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startManagedListings } = require('../scripts/lib/start-managed-listings');

const root = '/controlled/workspace';
const home = '/controlled/home';
const environment = { SS_ENABLE: 'true' };
const id = 'a'.repeat(64);

test('absent or disabled Listings record leaves Docker untouched', async () => {
  const calls = [];
  const verifyExisting = async options => { calls.push(options); throw Error('unexpected Docker verification'); };
  for (const configuration of [null, { enabled: false }]) {
    const result = await startManagedListings({ root, home, platform: 'darwin', environment,
      loadConfiguration: () => configuration, verifyExisting });
    assert.deepEqual(result, { requested: false, enabled: false });
  }
  assert.deepEqual(calls, []);
});

test('enabled Listings delegates exact retained start and requires verified health', async () => {
  const configuration = Object.freeze({ enabled: true });
  let observed;
  const result = await startManagedListings({ root, home, platform: 'darwin', environment,
    loadConfiguration: input => { assert.deepEqual(input, { root, home }); return configuration; },
    verifyExisting: async input => { observed = input; return { ready: true, enabled: true, containerId: id }; } });
  assert.deepEqual(observed, { root, home, platform: 'darwin', environment, configuration, startStopped: true });
  assert.deepEqual(result, { requested: true, ready: true, enabled: true, containerId: id });
  for (const invalid of [undefined, { ready: false, enabled: true, containerId: id },
    { ready: true, enabled: false, containerId: id }, { ready: true, enabled: true, containerId: 'bad' }]) {
    await assert.rejects(startManagedListings({ root, home, platform: 'darwin', environment,
      loadConfiguration: () => configuration, verifyExisting: async () => invalid }),
    { code: 'LISTINGS_START_NOT_READY' });
  }
  const failure = Object.assign(Error('retained manager unavailable'), { code: 'LISTINGS_INSTALL_READINESS_FAILED' });
  await assert.rejects(startManagedListings({ root, home, platform: 'darwin', environment,
    loadConfiguration: () => configuration, verifyExisting: async () => { throw failure; } }), failure);
});

test('unsupported host skips absence but refuses enabled retained Listings', async () => {
  let calls = 0;
  const verifyExisting = async () => { calls++; };
  assert.deepEqual(await startManagedListings({ root, home, platform: 'win32', environment,
    loadConfiguration: () => null, verifyExisting }), { requested: false, enabled: false });
  await assert.rejects(startManagedListings({ root, home, platform: 'win32', environment,
    loadConfiguration: () => ({ enabled: true }), verifyExisting }), { code: 'LISTINGS_START_PLATFORM_UNQUALIFIED' });
  assert.equal(calls, 0);
});

test('supported launcher selects Listings after plan and before backend child startup', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../scripts/start-application.js'), 'utf8');
  const plan = source.indexOf("if (args.includes('--plan'))");
  const windowsListings = source.indexOf("await require('./lib/start-managed-listings').startManagedListings(");
  const windowsStartup = source.indexOf('await windowsStartup({ environment: process.env');
  const listings = source.lastIndexOf("await require('./lib/start-managed-listings').startManagedListings(");
  const backend = source.indexOf('const supervisor = createApplicationSupervisor({ workspace: root');
  assert.ok(plan >= 0 && windowsListings > plan && windowsStartup > windowsListings);
  assert.ok(listings > windowsStartup && backend > listings);
});
