'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

test('focused unit child can write only its private repository runtime', () => {
  const runtime = process.env.DVAIA_REPO_LOCAL_UNIT_RUNTIME;
  assert.ok(runtime && runtime.startsWith(path.resolve(__dirname, '../tasks/tmp') + path.sep));
  const target = path.join(runtime, 'boundary-probe.txt');
  fs.writeFileSync(target, 'owned runtime probe\n', {flag: 'wx', mode: 0o600});
  assert.equal(fs.readFileSync(target, 'utf8'), 'owned runtime probe\n');
  // Opening an existing source file for writing does not change its bytes, but
  // proves that the process cannot acquire source-write authority.
  assert.throws(() => fs.openSync(path.join(__dirname, '../scripts/test-repo-local-unit.js'), 'r+'),
    error => ['EPERM', 'EACCES'].includes(error.code));
});

test('focused unit child cannot connect to local services', async () => {
  const error = await new Promise(resolve => {
    const socket = net.createConnection({host: '127.0.0.1', port: 1});
    socket.once('error', resolve);
    socket.once('connect', () => {socket.destroy(); resolve(null);});
  });
  assert.ok(error, 'network connection must be denied');
  assert.ok(['EPERM', 'EACCES'].includes(error.code), `sandbox denial expected, got ${error.code}`);
});
