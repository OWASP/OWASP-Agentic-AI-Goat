'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'fixtures/secureshopOwnedPolicyRendererAdmission.js'), 'utf8');
function command(invoke) {
  const start = source.indexOf('  const execute = async (file, args, callOptions = {}) => {');
  const end = source.indexOf('  const p = await installer.plan', start);
  assert.ok(start >= 0 && end > start);
  return Function('assert','invoke','workspace','admission','process', source.slice(start,end) + '\nreturn execute;')(
    assert, invoke, '/owned/repo', {dockerExecutable:'/owned/docker'}, {env:{OWNED:'yes'}});
}
test('policy profile exact SSH and original commands preserve bounded invocation', async () => {
  const calls = [];
  const execute = command(async (...args) => { calls.push(args); return {stdout:'ok'}; });
  for (const file of ['/usr/bin/ssh','ssh','sudo','docker']) {
    assert.equal((await execute(file,['owned'])).exitCode,0);
  }
  assert.deepEqual(calls.map(row=>row[0]), ['/usr/bin/ssh','ssh','sudo','/owned/docker']);
  for (const [,argv,options] of calls) {
    assert.deepEqual(argv,['owned']); assert.equal(options.timeout,25000);
    assert.equal(options.maxBuffer,1048576); assert.equal(options.cwd,'/owned/repo');
  }
});
test('policy profile rejects arbitrary executable paths before invocation', async () => {
  let calls = 0;
  const execute = command(async () => { calls++; });
  for (const file of ['/tmp/ssh','/usr/local/bin/ssh','/usr/bin/ssh-extra','/usr/bin/sudo','sh','']) {
    await assert.rejects(execute(file,[]));
  }
  assert.equal(calls,0);
});
test('policy profile invocation failure keeps original sanitized error', async () => {
  const execute = command(async () => { throw Error('private failure'); });
  await assert.rejects(execute('/usr/bin/ssh',[]), error =>
    error.code === 'POLICY_RENDER_INSPECTION_UNAVAILABLE' && !error.message.includes('private failure'));
});
