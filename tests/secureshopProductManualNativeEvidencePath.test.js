'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { assertNativeEvidencePath } = require('./fixtures/secureshopNativeEvidencePath');

test('V16/V26 receipt and browser records require the exact fresh owned run', t => {
  const root = '/owned/current-checkout';
  const run = path.join(root, 'tasks/qualification/run-abc123');
  const dockerHost = `unix://${root}/.qualification/goat-q/docker.sock`;
  const valid = new Set([
    'product-similar-evidence.json', 'product-similar-browser.json',
    'manual-rag-evidence.json', 'manual-rag-browser.json',
  ]);
  let existing = null;
  t.mock.method(fs, 'realpathSync', value => value);
  t.mock.method(fs, 'lstatSync', value => {
    if (path.dirname(value) === run && path.basename(value) !== 'run-abc123') {
      if (value !== existing) throw Object.assign(Error('fresh'), { code: 'ENOENT' });
      return { uid: process.getuid(), mode: 0o600,
        isDirectory: () => false, isSocket: () => false, isSymbolicLink: () => false };
    }
    return { uid: process.getuid(), mode: 0o700,
      isDirectory: () => !value.endsWith('docker.sock'),
      isSocket: () => value.endsWith('docker.sock'), isSymbolicLink: () => false };
  });
  for (const basename of valid) {
    const file = path.join(run, basename);
    const options = { root, dockerHost, basename };
    assert.equal(assertNativeEvidencePath(file, options), file);
    assert.throws(() => assertNativeEvidencePath(path.join(run, 'wrong.json'), options));
    assert.throws(() => assertNativeEvidencePath(file,
      { ...options, dockerHost: 'unix:///legacy/docker.sock' }));
    existing = file;
    assert.throws(() => assertNativeEvidencePath(file, options));
    existing = null;
  }
});
