'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');

test('mode request guard rejects stale mount and poll without touching interaction state', () => {
  const { createReconciliationGuard } = require('../client/src/services/revisionPoller');
  const guard = createReconciliationGuard();
  const state = { mode: 'fixed', messages: ['kept'], progress: 3, selection: 'objective-2' };
  const mount = guard.begin('mode');
  const poll = guard.begin('mode');
  const toggle = guard.begin('mode');
  assert.throws(() => guard.commit('mode', mount, () => { state.mode = 'vuln'; }), (error) => error.code === 'STALE_RECONCILIATION');
  assert.throws(() => guard.commit('mode', poll, () => { state.mode = 'vuln'; }), (error) => error.code === 'STALE_RECONCILIATION');
  guard.commit('mode', toggle, () => { state.mode = 'vuln'; });
  assert.deepEqual(state, { mode: 'vuln', messages: ['kept'], progress: 3, selection: 'objective-2' });
});

test('toggle followed by poll scheduling keeps the canonical toggle response user-silent', () => {
  const { createReconciliationGuard } = require('../client/src/services/revisionPoller');
  const guard = createReconciliationGuard();
  const state = { mode: 'fixed', messages: ['kept'], errors: [] };
  const toggle = guard.beginForeground('mode');
  const poll = guard.beginBackground('mode');
  assert.equal(poll, null);
  guard.commit('mode', toggle, () => { state.mode = 'vuln'; });
  guard.endForeground('mode', toggle);
  assert.deepEqual(state, { mode: 'vuln', messages: ['kept'], errors: [] });
});

test('five clients mount, toggle, and poll canonical mode with request guards', () => {
  for (const [file, workshopKey, modeEndpoint] of [
    ['client/src/pages/workshops/SQLWorkshop.js', 'sql_injection_workshop', '/api/workshop/sql/mode'],
    ['client/src/pages/workshops/NoSQLWorkshop.js', 'nosql_injection_workshop', '/api/workshop/nosql/mode'],
    ['client/src/pages/workshops/SensitiveInfoWorkshop.js', 'sensitive_info_disclosure', '/api/workshop/sensitive-info/mode'],
    ['client/src/pages/workshops/SupplyChainWorkshop.js', 'supply_chain_rce', '/mode'],
    ['client/src/pages/challenges/ExcessiveAgencyBolaLab.js', 'excessive_agency', '/mode'],
  ]) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    assert.match(source, /useChangePolling/);
    assert.ok(source.includes(`['${workshopKey}']`));
    assert.ok(source.includes(modeEndpoint));
    assert.match(source, /begin\('mode'\)/);
    assert.match(source, /commit\('mode'/);
    assert.match(source, /beginRequiredBackground\('mode'\)/);
    assert.match(source, /beginForeground\('mode'\)/);
    assert.match(source, /endForeground\('mode'/);
  }
});

test('client chat payloads cannot choose server execution mode or identity', () => {
  for (const file of ['SQLWorkshop.js', 'NoSQLWorkshop.js', 'SensitiveInfoWorkshop.js', 'SupplyChainWorkshop.js']) {
    const source = fs.readFileSync(path.join(root, 'client/src/pages/workshops', file), 'utf8');
    assert.doesNotMatch(source, /axios\.post\([^\n]*\/chat[^\n]*\{[^}]*\bmode\s*:/s);
    assert.doesNotMatch(source, /axios\.post\([^\n]*\/chat[^\n]*\{[^}]*\buserId\s*:/s);
  }
});
