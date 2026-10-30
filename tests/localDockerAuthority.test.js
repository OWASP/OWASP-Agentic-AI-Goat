'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const {
  authorityDigest,
  resolveLocalDockerHost,
  resolveDockerAuthority,
  readLocalDockerAuthority,
  writeLocalDockerAuthority,
} = require('../scripts/local-docker-authority');

async function temporary(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-docker-authority-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

test('local Docker selection accepts Docker Desktop and Colima Unix sockets', async () => {
  assert.deepEqual(await resolveLocalDockerHost({
    platform: 'darwin', environment: { DOCKER_HOST: 'unix:///Users/test/.docker/run/docker.sock' },
  }), { host: 'unix:///Users/test/.docker/run/docker.sock', source: 'environment-host' });

  const calls = [];
  const selected = await resolveLocalDockerHost({
    platform: 'darwin', environment: { DOCKER_CONTEXT: 'colima-default', DOCKER_HOST: '' },
    execute: async (command, args, options) => {
      calls.push({ command, args, env: options.env });
      return { stdout: '"unix:///Users/test/.colima/default/docker.sock"\n' };
    },
  });
  assert.deepEqual(selected, { host: 'unix:///Users/test/.colima/default/docker.sock', source: 'environment-context' });
  assert.deepEqual(calls[0].args, ['context', 'inspect', 'colima-default', '--format', '{{json .Endpoints.docker.Host}}']);
  assert.equal(calls[0].env.DOCKER_HOST, undefined);
  assert.equal(calls[0].env.DOCKER_CONTEXT, undefined);
});

test('remote and ambiguous ambient Docker authority is rejected before daemon access', async () => {
  let called = false;
  const execute = async () => { called = true; };
  await assert.rejects(resolveLocalDockerHost({ environment: { DOCKER_HOST: 'tcp://remote.invalid:2375' }, execute }),
    /local Unix socket.*remote Docker endpoints are refused/);
  await assert.rejects(resolveLocalDockerHost({
    environment: { DOCKER_HOST: 'unix:///var/run/docker.sock', DOCKER_CONTEXT: 'default' }, execute,
  }), /both set/);
  await assert.rejects(resolveLocalDockerHost({
    platform: 'linux', environment: { DOCKER_CONTEXT: 'remote' },
    execute: async () => ({ stdout: '"ssh://operator@remote.invalid"' }),
  }), /local Unix socket.*remote Docker endpoints are refused/);
  assert.equal(called, false);
});

test('active local context is resolved once and daemon identity is persisted privately', async t => {
  const directory = await temporary(t);
  const calls = [];
  const execute = async (_command, args, options) => {
    calls.push({ args, env: options.env });
    if (args[0] === 'context' && args[1] === 'show') return { stdout: 'desktop-linux\n' };
    if (args[0] === 'context' && args[1] === 'inspect') return { stdout: '"unix:///Users/test/.docker/run/docker.sock"\n' };
    if (args[0] === '--host' && args[2] === 'info') return { stdout: '"daemon-desktop"\n' };
    assert.fail(`unexpected Docker call: ${args.join(' ')}`);
  };
  const result = await resolveDockerAuthority({
    directory, workspaceId: 'workspace123', platform: 'darwin', environment: {}, execute, persist: true,
  });
  assert.equal(result.persisted, true);
  assert.equal(result.authority.daemonId, 'daemon-desktop');
  assert.match(authorityDigest(result.authority), /^[a-f0-9]{64}$/);
  assert.equal((await fs.stat(path.join(directory, 'local-docker.json'))).mode & 0o777, 0o600);
  assert.equal(calls.at(-1).env.DOCKER_HOST, undefined);
  assert.equal(calls.at(-1).env.DOCKER_CONTEXT, undefined);

  const reused = await resolveDockerAuthority({
    directory, workspaceId: 'workspace123', platform: 'darwin', environment: {
      DOCKER_HOST: 'tcp://ambient.invalid:2375', DOCKER_CONTEXT: 'remote',
    }, execute: async (_command, args, options) => {
      assert.deepEqual(args.slice(0, 3), ['--host', 'unix:///Users/test/.docker/run/docker.sock', 'info']);
      assert.equal(options.env.DOCKER_HOST, undefined);
      assert.equal(options.env.DOCKER_CONTEXT, undefined);
      return { stdout: '"daemon-desktop"' };
    },
  });
  assert.equal(reused.persisted, true);
});

test('private authority rejects symlinks, permissive files, workspace drift and daemon replacement', async t => {
  const directory = await temporary(t);
  const authority = { version: 1, workspaceId: 'workspace123', host: 'unix:///var/run/docker.sock',
    daemonId: 'daemon-one', source: 'active-context', platform: 'linux' };
  await writeLocalDockerAuthority({ directory, authority });
  const filename = path.join(directory, 'local-docker.json');
  await fs.chmod(filename, 0o644);
  await assert.rejects(readLocalDockerAuthority({ directory, workspaceId: 'workspace123', platform: 'linux' }), /private file/);
  await fs.chmod(filename, 0o600);
  await assert.rejects(readLocalDockerAuthority({ directory, workspaceId: 'another', platform: 'linux' }), /does not match/);
  await assert.rejects(resolveDockerAuthority({
    directory, workspaceId: 'workspace123', platform: 'linux', environment: {},
    execute: async () => ({ stdout: '"daemon-two"' }),
  }), /different daemon/);

  const target = path.join(directory, 'authority-target.json');
  await fs.rename(filename, target);
  await fs.symlink(target, filename);
  await assert.rejects(readLocalDockerAuthority({ directory, workspaceId: 'workspace123', platform: 'linux' }), /private file/);
});
