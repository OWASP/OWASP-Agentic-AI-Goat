'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtempSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const helper = join(__dirname, '..', 'scripts', 'register-native-owner-handle.py');
function grantFile(overrides = {}) {
  const path = join(mkdtempSync(join(tmpdir(), 'owasp-ai-goat-owner-handle-')), 'grant.json');
  writeFileSync(path, JSON.stringify({ grantId: 'grant-one', owner: '/root/test', status: 'consumed',
    allowedLaunches: 1, consumerPid: 12345, ownerHandle: null, ...overrides }));
  return path;
}
function register(path, extra = []) {
  return execFileSync('python3', [helper, '--grant-file', path, '--grant-id', 'grant-one',
    '--owner', '/root/test', '--owner-handle', '67890', '--wait-seconds', '0', ...extra], { encoding: 'utf8' });
}

test('owner-handle helper atomically binds and idempotently preserves the exact consumed grant', () => {
  const path = grantFile();
  assert.deepEqual(JSON.parse(register(path)), { grantId: 'grant-one', owner: '/root/test',
    consumerPid: 12345, ownerHandle: 67890 });
  register(path);
  assert.equal(JSON.parse(readFileSync(path)).ownerHandle, 67890);
});

test('owner-handle helper rejects mismatched, unconsumed, malformed and conflicting grants', () => {
  for (const path of [grantFile({ status: 'granted' }), grantFile({ consumerPid: null }),
    grantFile({ ownerHandle: 99999 }), grantFile({ allowedLaunches: 2 })]) {
    const result = spawnSync('python3', [helper, '--grant-file', path, '--grant-id', 'grant-one',
      '--owner', '/root/test', '--owner-handle', '67890', '--wait-seconds', '0'], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.notEqual(JSON.parse(readFileSync(path)).ownerHandle, 67890);
  }
});
