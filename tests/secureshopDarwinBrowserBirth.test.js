'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { captureBrowserRecord } = require('./fixtures/secureshopDarwinBrowserBirth');

const ROOT = path.resolve(__dirname, '..');
const executablePath = process.execPath;
const executableSha256 = 'a'.repeat(64);

test('legacy path preserves exact ps journal and current path requires libproc birth', () => {
  const calls = [];
  const legacy = captureBrowserRecord({ root: ROOT, kind: 'manual_rag_browser',
    pid: 412, executablePath, executableSha256, env: {},
    run: (...args) => { calls.push(args); return 'Mon Jan  1 00:00:00 2024\n'; } });
  assert.equal(legacy.schemaVersion, 1);
  assert.equal(calls[0][0], 'ps');
  const script = path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py');
  const birth = { pid: 412, parentPid: process.pid, uid: process.getuid(),
    pgid: 411, sessionId: 411, birth: [1234, 506], executablePath };
  const env = { SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: script,
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: executablePath };
  const current = captureBrowserRecord({ root: ROOT, kind: 'manual_rag_browser',
    pid: 412, executablePath, executableSha256, env,
    run: (bin, args) => { assert.equal(bin, executablePath);
      assert.deepEqual(args.slice(0, 3), [script, '--pid', '412']);
      return JSON.stringify(birth); } });
  assert.equal(current.schemaVersion, 2);
  assert.deepEqual(current.processes[0].birth, [1234, 506]);
  assert.throws(() => captureBrowserRecord({ root: ROOT, kind: 'manual_rag_browser',
    pid: 412, executablePath, executableSha256, env,
    run: () => JSON.stringify({ ...birth, parentPid: process.pid + 1 }) }), /Expected values/);
});
