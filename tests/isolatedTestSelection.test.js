'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { selectIsolatedTests } = require('../scripts/lib/isolated-test-selection');

test('focused selection accepts explicit test files and rejects escapes and unsupported modes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-test-selection-'));
  try {
    fs.mkdirSync(path.join(root, 'tests'));
    fs.writeFileSync(path.join(root, 'tests', 'safe.test.js'), '');
    fs.writeFileSync(path.join(root, 'outside.test.js'), '');
    fs.symlinkSync(path.join(root, 'outside.test.js'), path.join(root, 'tests', 'escape.test.js'));
    assert.equal(selectIsolatedTests(root, 'unit', []), null);
    assert.deepEqual(selectIsolatedTests(root, 'unit', ['tests/safe.test.js', 'tests/safe.test.js']), ['tests/safe.test.js']);
    for (const input of ['tests/../outside.test.js', '/tmp/safe.test.js', '--test-name-pattern=x', 'tests/*.test.js', 'tests/escape.test.js']) {
      assert.throws(() => selectIsolatedTests(root, 'unit', [input]));
    }
    assert.throws(() => selectIsolatedTests(root, 'postgres', ['tests/safe.test.js']));
    assert.throws(() => selectIsolatedTests(root, 'secureshop', ['tests/safe.test.js']));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('native operator cannot enter focused unit selection', () => {
  assert.throws(() => selectIsolatedTests('/unused', 'unit', ['tests/setupLocalProcessIdentity.test.js']), /test:native-operator/);
  assert.throws(() => selectIsolatedTests('/unused', 'unit', ['tests/legacyRamRagMaintenanceOperator.test.js']), /test:native-operator/);
  assert.throws(() => selectIsolatedTests('/unused', 'unit', ['tests/legacyRamRagOperator.test.js']), /test:native-operator/);
});

test('native browser suites cannot enter focused unit selection', () => {
  const nativeSecureShop = require('../scripts/lib/native-secureshop-suites');
  for (const {file} of Object.values(require('../scripts/lib/native-browser-suites')).flat()) {
    const expected = nativeSecureShop.nativeBrowser.some(row => row.file === file)
      ? /run-secureshop-agent-host-transport-main\.py --cohort vuln/
      : /test:native-browser/;
    assert.throws(() => selectIsolatedTests('/unused', 'unit', [file]), expected);
  }
});

test('native verifier lifecycle cannot enter focused unit selection', () => {
  assert.throws(() => selectIsolatedTests('/unused', 'unit', ['tests/transformers43QualificationRunner.test.js']), /node --test --test-timeout=15000 tests\/transformers43QualificationRunner\.test\.js/);
});

test('each registered native SecureShop resource test rejects controlled focused dispatch', () => {
  const registry = require('../scripts/lib/native-secureshop-suites');
  for (const { file } of registry.deferredNative) {
    for (const mode of ['unit', 'secureshop']) {
      assert.throws(() => selectIsolatedTests('/unused', mode, [file]), /run-secureshop-agent-host-transport-main\.py --cohort vuln/);
    }
  }
});

test('SecureShop discovery defers exact resource files and retains controlled proofs', () => {
  const registry = require('../scripts/lib/native-secureshop-suites');
  const root = path.resolve(__dirname, '..');
  registry.validateRegistry(root);
  const known = [...registry.schemaFirst, ...registry.nativeCohort, ...registry.fixtureContract].map(row => row.file);
  const extra = 'tests/secureshop/unit/unrelated.test.js';
  const result = registry.partitionSecureShopTests([...known, extra]);
  assert.deepEqual(new Set(result.deferred.map(row => row.file)), new Set(registry.deferredNative.map(row => row.file)));
  assert.deepEqual(new Set(result.files), new Set([...registry.controlledOnly, ...registry.disabledActualModel, ...registry.fixtureContract].map(row => row.file).concat(extra)));
  assert.equal(result.files.length + result.deferred.length, known.length + 1);
  for (const row of result.deferred) assert.equal(row.launcher, registry.launcher);
  assert.equal(registry.nativeCohort.some(row => row.file === registry.fixtureContract[0].file), false);
  assert.equal(registry.schemaFirst.every(row => !registry.nativeCohort.some(native => native.file === row.file)), true);
  const browserFiles = new Set(Object.values(require('../scripts/lib/native-browser-suites')).flat().map(row => row.file));
  assert.deepEqual(registry.deferredNative.filter(row => browserFiles.has(row.file)), [...registry.nativeBrowser]);
  assert.equal(result.deferred.filter(row => row.file === registry.nativeBrowser[0].file).length, 1);
});

test('closed SecureShop registration rejects new unclassified files before dispatch', t => {
  const registry = require('../scripts/lib/native-secureshop-suites');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'closed-secureshop-registry-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const row of [...registry.schemaFirst, ...registry.nativeCohort, ...registry.fixtureContract]) {
    fs.mkdirSync(path.dirname(path.join(root, row.file)), { recursive: true });
    fs.writeFileSync(path.join(root, row.file), '');
  }
  registry.validateRegistry(root);
  fs.writeFileSync(path.join(root, 'tests/secureshop/vuln/new-resource.test.js'), '');
  assert.throws(() => registry.validateRegistry(root), /inventory changed/);
});
