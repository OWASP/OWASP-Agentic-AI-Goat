'use strict';

// Controlled PostgreSQL-shaped smoke coverage. This file must remain safe to
// run from the main checkout: no application database, model, browser, or
// network service is opened.
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const priorExportInternals = process.env.EXPORT_INTERNALS;
process.env.EXPORT_INTERNALS = '1';
const originalLoad = Module._load;
const forbidden = /(?:^|\/)(?:authDb|solutionVisibilityRegistry)(?:\.js)?$|^(?:sqlite3|better-sqlite3)$/;
Module._load = function guardedLoad(request, parent, isMain) {
  if (forbidden.test(request)) throw Object.assign(new Error(`Legacy CSRF fixture import forbidden: ${request}`), {
    code: 'CSRF_SMOKE_LEGACY_IMPORT',
  });
  return originalLoad.call(this, request, parent, isMain);
};

const sandboxPath = path.resolve(__dirname, '../server/services/csrfVictimSandbox.js');
delete require.cache[sandboxPath];
const { CsrfVictimSandbox, TAB_IDS, ALL_OBJECTIVES } = require(sandboxPath);

test.after(() => {
  Module._load = originalLoad;
  delete require.cache[sandboxPath];
  if (priorExportInternals === undefined) delete process.env.EXPORT_INTERNALS;
  else process.env.EXPORT_INTERNALS = priorExportInternals;
});

function postgresStateStore() {
  const rows = new Map();
  const events = [];
  return {
    rows,
    events,
    async getVictimState(ownerKey) {
      events.push(['get', ownerKey]);
      const value = rows.get(ownerKey);
      return value === undefined ? null : structuredClone(value);
    },
    async saveVictimState(ownerKey, state) {
      events.push(['save', ownerKey]);
      rows.set(ownerKey, structuredClone(state));
    },
    async deleteVictimState(ownerKey) {
      events.push(['delete', ownerKey]);
      rows.delete(ownerKey);
    },
  };
}

async function loadedSandbox(ownerKey, persistence) {
  const sandbox = new CsrfVictimSandbox(ownerKey, { persistence });
  sandbox._load();
  await sandbox.ready();
  return sandbox;
}

test('PostgreSQL-shaped CSRF persistence keeps owner effects isolated and hydrates exact state', async () => {
  const persistence = postgresStateStore();
  const first = await loadedSandbox('owner:17:session:31', persistence);
  assert.deepEqual(TAB_IDS, ['get', 'post', 'xss', 'indirect']);
  assert.equal(ALL_OBJECTIVES.length, 12);
  const effect = first.forge('get', 'direct_get', 'change_email', { email: 'attacker@evil.example' });
  assert.equal(effect.blocked, false);
  assert.equal(effect.executed, true);
  assert.equal(first.getTabState('get').profile.email, 'attacker@evil.example');
  await first.flush();
  const restored = await loadedSandbox('owner:17:session:31', persistence);
  assert.equal(restored.getTabState('get').profile.email, 'attacker@evil.example');
  const sibling = await loadedSandbox('owner:18:session:52', persistence);
  assert.equal(sibling.getTabState('get').profile.email, 'alex.rivera@personalmail.com');
  assert.deepEqual(persistence.events.slice(0, 4), [
    ['get', 'owner:17:session:31'], ['save', 'owner:17:session:31'],
    ['get', 'owner:17:session:31'], ['get', 'owner:18:session:52'],
  ]);
});

test('CSRF defenses block cross-site requests but retain the intentional same-origin XSS sink', async () => {
  const sandbox = await loadedSandbox('owner:mode', postgresStateStore());
  sandbox.setDefenses('get', true);
  const fixed = sandbox.forge('get', 'direct_get', 'change_email', { email: 'blocked@evil.example' });
  assert.equal(fixed.blocked, true);
  assert.equal(sandbox.getTabState('get').profile.email, 'alex.rivera@personalmail.com');
  sandbox.setDefenses('xss', true);
  const intentional = sandbox.forge('xss', 'xss', 'change_email', { email: 'same-origin@evil.example' });
  assert.equal(intentional.blocked, false);
  assert.equal(intentional.executed, true);
  assert.match(intentional.note, /SAME-ORIGIN/);
  assert.equal(sandbox.getTabState('xss').profile.email, 'same-origin@evil.example');
});

test('tab reset preserves sibling effects while full owner reset deletes only that owner state', async () => {
  const persistence = postgresStateStore();
  const sandbox = await loadedSandbox('owner:reset', persistence);
  sandbox.forge('get', 'direct_get', 'change_email', { email: 'get@evil.example' });
  sandbox.forge('post', 'direct_post', 'transfer', { amount: 500, to: 'attacker' });
  sandbox.getState();
  await sandbox.flush();
  sandbox.resetTab('get');
  await sandbox.flush();
  assert.equal(sandbox.getTabState('get').profile.email, 'alex.rivera@personalmail.com');
  assert.equal(sandbox.getTabState('post').account.balance, 42000);
  sandbox.reset();
  await sandbox.flush();
  assert.equal(persistence.rows.has('owner:reset'), false);
  assert.deepEqual(persistence.events.at(-1), ['delete', 'owner:reset']);
});

test('legacy SQLite and registry imports are denied before module entry', () => {
  for (const request of ['sqlite3', 'better-sqlite3', '../server/database/authDb', '../server/config/solutionVisibilityRegistry']) {
    assert.throws(() => require(request), { code: 'CSRF_SMOKE_LEGACY_IMPORT' });
  }
});
