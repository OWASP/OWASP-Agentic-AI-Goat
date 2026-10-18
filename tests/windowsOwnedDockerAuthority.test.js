'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const filename = path.resolve(__dirname, '../scripts/local-docker-authority.js');

function harness() {
  const descriptors = new WeakMap(), calls = [], writes = [];
  const descriptor = { kind: 'owned-windows-lab', workspaceId: 'abcdef123456',
    installationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', vmId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    bindingSha256: 'c'.repeat(64), host: 'owned-hyperv:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', daemonId: 'owned-daemon' };
  let observed = 'owned-daemon', retained = null, dockerError;
  const session = { async bindDaemon() { calls.push('bind'); return descriptor; },
    async assertCurrent() { calls.push('current'); },
    async executeDocker(args) { calls.push(args); if (dockerError) throw dockerError; return JSON.stringify(observed); } };
  descriptors.set(session, descriptor);
  const requireReal = createRequire(filename), module = { exports: {} };
  vm.runInThisContext(`(function(require,module,exports,__filename,__dirname){${fs.readFileSync(filename, 'utf8')}\n})`, { filename })(name => {
    if (name === './lib/windows-owned-lab') return { describeOwnedLab(value) {
      if (!descriptors.has(value)) throw Error('not branded'); return descriptors.get(value);
    } };
    return requireReal(name);
  }, module, module.exports, filename, path.dirname(filename));
  const api = module.exports;
  const storage = { async readLocalDockerAuthority() { return retained; },
    async writeLocalDockerAuthority(value) { writes.push(value); } };
  const options = { directory: 'C:\\private', workspaceId: descriptor.workspaceId, platform: 'win32',
    ownedLabSession: session, storage, execute() { throw Error('host Docker must not run'); } };
  return { api, options, session, calls, writes, descriptor,
    retain(value) { retained = value; }, observe(value) { observed = value; }, failDocker(value) { dockerError = value; } };
}

test('owned Windows authority binds VM and daemon, persists, dispatches guest Docker only', async () => {
  const h = harness();
  const result = await h.api.resolveDockerAuthority({ ...h.options, persist: true });
  assert.equal(result.persisted, true); assert.equal(h.writes.length, 1);
  assert.equal(result.authority.version, 2); assert.equal(result.authority.vmId, h.descriptor.vmId);
  assert.deepEqual(await h.api.executeBoundDocker({ authority: result.authority, args: ['inspect', 'owned-container'] }),
    { stdout: '"owned-daemon"', stderr: '' });
  assert.deepEqual(h.calls.at(-1), ['inspect', 'owned-container']);
});

test('forged sessions, wrong platform and workspace are denied before mutation', async () => {
  for (const change of [{ ownedLabSession: {} }, { platform: 'linux' }, { workspaceId: '111111111111' }]) {
    const h = harness();
    await assert.rejects(h.api.resolveDockerAuthority({ ...h.options, ...change }));
    assert.equal(h.writes.length, 0); assert.deepEqual(h.calls, []);
  }
});

test('retained foreign authority is not replaced, even when supplied a valid new guest', async () => {
  const h = harness();
  h.retain({ version: 1, workspaceId: h.options.workspaceId, host: 'npipe:////./pipe/docker_engine', daemonId: 'foreign', source: 'active-context', platform: 'win32' });
  await assert.rejects(h.api.resolveDockerAuthority({ ...h.options, persist: true }), /differs/);
  assert.equal(h.writes.length, 0);
});

test('unbound serialized authority cannot invoke Docker without an admitted session', async () => {
  const h = harness(), { authority } = await h.api.resolveDockerAuthority(h.options);
  await assert.rejects(h.api.executeBoundDocker({ authority: { ...authority }, args: ['start', 'owned'] }));
  await assert.rejects(h.api.inspectDockerDaemon({ authority: { ...authority } }));
});

test('retained matching authority is reused and daemon replacement is denied', async () => {
  const h = harness(), first = await h.api.resolveDockerAuthority(h.options);
  h.retain(first.authority);
  const next = await h.api.resolveDockerAuthority({ ...h.options, persist: true });
  assert.equal(next.persisted, true); assert.equal(h.writes.length, 0);
  h.observe('replaced');
  await assert.rejects(h.api.verifyDockerAuthority({ authority: next.authority }), /different daemon/);
});

test('Docker absence retains its sanitized numeric failure for fresh provisioning', async () => {
  const h = harness(), { authority } = await h.api.resolveDockerAuthority(h.options);
  h.failDocker(Object.assign(Error('Owned guest Docker command failed'), { code: 1, exitCode: 1 }));
  await assert.rejects(h.api.executeBoundDocker({ authority, args: ['inspect', 'absent'] }), { code: 1 });
});

test('owned transport is not a generally accepted Docker endpoint and binding affects digest', () => {
  const h = harness();
  assert.throws(() => h.api.assertLocalDockerHost(h.descriptor.host, 'win32'));
  const base = { version: 2, source: 'owned-hyperv', platform: 'win32', ...h.descriptor };
  assert.notEqual(h.api.authorityDigest(base), h.api.authorityDigest({ ...base, bindingSha256: 'd'.repeat(64) }));
});
