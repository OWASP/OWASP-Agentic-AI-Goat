'use strict';
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');

function parseProcessRows(value) {
  assert.equal(typeof value, 'string');
  const rows = value.trim().split(/\r?\n/).filter(Boolean).map(line => {
    const fields = line.trim().split(/\s+/);
    assert.equal(fields.length, 3, 'Browser process roster must have three fields');
    assert.ok(fields.every(field => /^\d+$/.test(field)), 'Browser process roster must be numeric');
    const [pid, pgid, uid] = fields.map(Number);
    assert.ok([pid, pgid].every(Number.isSafeInteger) && pid > 0 && pgid > 0,
      'Browser process identities must be positive safe integers');
    assert.ok(Number.isSafeInteger(uid) && uid >= 0, 'Browser process UID must be a safe integer');
    return { pid, pgid, uid };
  });
  assert.equal(rows.length, 2, 'Parent and browser process identities are required');
  assert.equal(new Set(rows.map(row => row.pid)).size, 2, 'Process identities must be unique');
  return rows;
}

function captureBrowserProcessIdentity(browserPid, {
  workerPid = process.pid,
  uid = process.getuid?.(),
  read = (pids) => execFileSync('/bin/ps', ['-o', 'pid=,pgid=,uid=', '-p', pids.join(',')], {
    encoding: 'utf8', timeout: 2000, maxBuffer: 65536,
  }),
} = {}) {
  assert.ok(Number.isSafeInteger(workerPid) && workerPid > 0);
  assert.ok(Number.isSafeInteger(browserPid) && browserPid > 0 && browserPid !== workerPid);
  assert.ok(Number.isSafeInteger(uid) && uid >= 0, 'Current process UID is required');
  const rows = parseProcessRows(read([workerPid, browserPid]));
  const parent = rows.find(row => row.pid === workerPid);
  const browser = rows.find(row => row.pid === browserPid);
  assert.ok(parent && browser, 'Exact worker and browser process identities are required');
  assert.equal(parent.uid, uid, 'Qualification worker has a foreign UID');
  assert.equal(browser.uid, uid, 'Browser process has a foreign UID');
  assert.equal(browser.pgid, parent.pgid, 'Browser must share the qualification process group');
  assert.notEqual(parent.pgid, browser.pid, 'Browser cannot lead the qualification process group');
  return Object.freeze({
    pid: browser.pid,
    pgid: browser.pgid,
    sessionId: parent.pgid,
    uid: browser.uid,
    qualificationPid: parent.pgid,
    qualificationPgid: parent.pgid,
    qualificationSessionId: parent.pgid,
    workerPid: parent.pid,
  });
}

module.exports = { captureBrowserProcessIdentity, parseProcessRows };
