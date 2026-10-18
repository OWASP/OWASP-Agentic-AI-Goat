'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { captureBrowserProcessIdentity, parseProcessRows } = require('./fixtures/browserProcessOwnership');

test('browser identity is bound to the exact parent group, session, and uid', () => {
  const uid = process.getuid();
  const leader = process.pid - 1;
  const read = () => `${process.pid} ${leader} ${uid}\n9001 ${leader} ${uid}\n`;
  assert.deepEqual(captureBrowserProcessIdentity(9001, { uid, read }), {
    pid: 9001, pgid: leader, sessionId: leader, uid,
    qualificationPid: leader, qualificationPgid: leader, qualificationSessionId: leader, workerPid: process.pid,
  });
  for (const output of [
    `${process.pid} ${leader} ${uid}\n9001 43 ${uid}\n`,
    `${process.pid} ${leader} ${uid}\n9001 ${leader} ${uid + 1}\n`,
    `${process.pid} ${leader} ${uid}\n`,
    `${process.pid} ${leader} ${uid}\n9001 bad ${uid}\n`,
  ]) assert.throws(() => captureBrowserProcessIdentity(9001, { uid, read: () => output }));
});

test('real harmless child binds the test worker to its qualification group leader', {timeout:15000}, async (t) => {
  const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore', detached: false });
  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited=once(child,'exit');
    child.kill('SIGKILL');
    let timer;
    try {await Promise.race([exited,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned child exit deadline')),5000);})]);}
    finally {clearTimeout(timer);}
  });
  const identity = captureBrowserProcessIdentity(child.pid);
  assert.equal(identity.pid, child.pid);
  assert.equal(identity.workerPid, process.pid);
  assert.notEqual(identity.qualificationPid, identity.pid);
  assert.equal(identity.pgid, identity.qualificationPgid);
  assert.equal(identity.sessionId, identity.qualificationSessionId);
  assert.equal(identity.uid, process.getuid());
});

test('process row parser rejects duplicate, extra, and unsafe identities', () => {
  assert.throws(() => parseProcessRows('1 2 3\n1 2 3\n'));
  assert.throws(() => parseProcessRows('1 2 3 4\n6 2 3\n'));
  assert.throws(() => parseProcessRows('0 2 3\n6 2 3\n'));
});
