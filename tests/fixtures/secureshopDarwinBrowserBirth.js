'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function captureBrowserRecord({ root, kind, pid, executablePath, executableSha256,
  env = process.env, run = execFileSync }) {
  assert.ok(Number.isSafeInteger(pid) && pid > 1);
  assert.ok(path.isAbsolute(executablePath) && fs.realpathSync(executablePath) === executablePath);
  assert.match(executableSha256, /^[a-f0-9]{64}$/);
  const inspector = env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT;
  if (inspector === undefined) {
    const startTime = run('ps', ['-p', String(pid), '-o', 'lstart='],
      { encoding: 'utf8', timeout: 10000 }).trim().replace(/\s+/g, ' ');
    assert.equal(startTime.split(' ').length, 5);
    return { schemaVersion: 1, processes: [{ kind, pid, startTime,
      executablePath, executableSha256 }] };
  }
  const expected = path.join(root, 'tests/postgres/secureshop_darwin_browser_birth.py');
  const python = env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON;
  assert.equal(inspector, expected);
  assert.ok(typeof python === 'string' && path.isAbsolute(python)
    && fs.realpathSync(python) === python);
  const output = run(python, [inspector, '--pid', String(pid), '--parent', String(process.pid),
    '--executable', executablePath], { encoding: 'utf8', timeout: 10000,
    maxBuffer: 4096, env });
  assert.ok(typeof output === 'string' && output.length < 4096);
  const birth = JSON.parse(output);
  assert.deepEqual(Object.keys(birth).sort(),
    ['birth', 'executablePath', 'parentPid', 'pgid', 'pid', 'sessionId', 'uid'].sort());
  assert.equal(birth.pid, pid);
  assert.equal(birth.parentPid, process.pid);
  assert.equal(birth.uid, process.getuid());
  assert.ok(Number.isSafeInteger(birth.pgid) && birth.pgid > 1);
  assert.equal(birth.sessionId, birth.pgid);
  assert.ok(Array.isArray(birth.birth) && birth.birth.length === 2);
  for (const value of birth.birth) assert.ok(Number.isSafeInteger(value) && value >= 0);
  assert.ok(birth.birth[0] > 0 && birth.birth[1] < 1000000);
  assert.equal(birth.executablePath, executablePath);
  return { schemaVersion: 2, processes: [{ kind, ...birth, executableSha256 }] };
}

module.exports = { captureBrowserRecord };
