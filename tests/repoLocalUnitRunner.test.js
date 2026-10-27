'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {selectFiles, childEnvironment} = require('../scripts/test-repo-local-unit');

test('repo-local runner admits only explicit controlled top-level unit files', () => {
  assert.deepEqual(selectFiles(['tests/secureshopQ05Q08Inventory.contract.test.js']),
    ['tests/secureshopQ05Q08Inventory.contract.test.js']);
  assert.throws(() => selectFiles([]), /Explicit focused/);
  assert.throws(() => selectFiles(['tests/postgres/secureshopManualRagRendered.integration.test.js']),
    /test.js|top-level/);
  assert.throws(() => selectFiles(['tests/api.test.js']), /Server-required/);
  assert.throws(() => selectFiles(['tests/secureshopUserLookupAssessmentRoute.test.js']),
    /Server-required/);
});

test('repo-local child has a single writable runtime and no inherited database credentials', () => {
  if (process.platform !== 'darwin') return;
  const root = path.resolve(__dirname, '..');
  const directory = path.join(root, 'tasks/tmp/focused-unit.contract');
  const env = childEnvironment(directory);
  assert.equal(env.DVAIA_ISOLATED_TEST_WORKSPACE, root);
  assert.equal(env.AI_PROVIDER, 'mock');
  assert.equal(env.DATABASE_URL, undefined);
  assert.equal(env.PGPASSWORD, undefined);
  assert.equal(env.HOME, undefined);
  assert.ok(directory.startsWith(path.join(root, 'tasks/tmp')));
});
