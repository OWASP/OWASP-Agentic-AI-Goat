'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const {
  assertCompleteUploadAssetConfiguration,
  prepareUploadAssetEnvironment,
  selectUploadAssetPort,
} = require('../scripts/lib/setup-upload-asset-environment');

const origins = 'http://localhost:3000,http://127.0.0.1:3000';
const ipv6 = (port = 49160, enabled = 'true') => ({
  SS_BOUND_UPLOAD_ASSETS_ENABLED: enabled,
  SS_UPLOAD_ASSET_HOST: '::1',
  SS_UPLOAD_ASSET_PORT: String(port),
  SS_UPLOAD_ASSET_PUBLIC_ORIGIN: `http://[::1]:${port}`,
  SS_UPLOAD_ASSET_CAPABILITY_SECRET: 's'.repeat(48),
  SS_ALLOWED_ORIGINS: origins,
});

async function privateDirectory(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-upload-asset-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

test('executing setup probes assigned IPv6 loopback, closes it and retains one private secret', async t => {
  const directory = await privateDirectory(t);
  const first = await prepareUploadAssetEnvironment({ environment: { SS_ALLOWED_ORIGINS: origins }, directory });
  assert.equal(first.state, 'created');
  assert.equal(first.probed, true);
  assert.equal(first.configuration.SS_UPLOAD_ASSET_HOST, '::1');
  assert.match(first.configuration.SS_UPLOAD_ASSET_PUBLIC_ORIGIN, /^http:\/\/\[::1\]:\d+$/);
  assert.equal(first.configuration.SS_UPLOAD_ASSET_CAPABILITY_SECRET.length, 96);
  const file = await fs.stat(first.secretFile);
  assert.equal(file.mode & 0o777, 0o600);
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.once('error', reject)
    .listen({ host: '::1', port: Number(first.configuration.SS_UPLOAD_ASSET_PORT), ipv6Only: true }, resolve));
  await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));

  const second = await prepareUploadAssetEnvironment({ environment: { SS_ALLOWED_ORIGINS: origins }, directory });
  assert.equal(second.configuration.SS_UPLOAD_ASSET_CAPABILITY_SECRET,
    first.configuration.SS_UPLOAD_ASSET_CAPABILITY_SECRET);
  assert.equal(second.secretCreated, false);
});

test('setup plan is socket-free and creates no private capability state', async t => {
  const directory = await privateDirectory(t);
  let sockets = 0;
  const result = await prepareUploadAssetEnvironment({ environment: {}, directory, execute: false }, {
    createServer() { sockets += 1; throw Error('must not bind'); },
  });
  assert.equal(result.state, 'planned');
  assert.equal(result.probed, false);
  assert.equal(sockets, 0);
  assert.deepEqual(await fs.readdir(directory), []);
});

test('complete IPv6 and supported legacy IPv4 tuples are preserved without probing or rotating secrets', async () => {
  let sockets = 0;
  for (const environment of [ipv6(), {
    ...ipv6(), SS_UPLOAD_ASSET_HOST: '127.0.0.2',
    SS_UPLOAD_ASSET_PUBLIC_ORIGIN: 'http://127.0.0.2:49160',
  }]) {
    const result = await prepareUploadAssetEnvironment({ environment, directory: '/unused' }, {
      createServer() { sockets += 1; throw Error('must not bind'); },
    });
    assert.equal(result.state, 'preserved');
    assert.deepEqual(result.configuration, Object.fromEntries(Object.entries(environment)
      .filter(([key]) => key !== 'SS_ALLOWED_ORIGINS')));
    assert.deepEqual(result.additions, {});
  }
  assert.equal(sockets, 0);
});

test('explicit disabled intent is preserved while partial and invalid tuples fail without secret disclosure', async () => {
  const disabled = await prepareUploadAssetEnvironment({
    environment: { SS_BOUND_UPLOAD_ASSETS_ENABLED: 'false' }, directory: '/unused',
  }, { createServer() { assert.fail('disabled setup must not bind'); } });
  assert.equal(disabled.state, 'preserved-disabled');
  assert.deepEqual(disabled.configuration, { SS_BOUND_UPLOAD_ASSETS_ENABLED: 'false' });

  const privateValue = 'do-not-print-this-private-value'.repeat(2);
  for (const environment of [
    { SS_BOUND_UPLOAD_ASSETS_ENABLED: 'true', SS_UPLOAD_ASSET_CAPABILITY_SECRET: privateValue },
    { ...ipv6(), SS_UPLOAD_ASSET_CAPABILITY_SECRET: privateValue, SS_ALLOWED_ORIGINS: 'http://[::1]:3000' },
    { ...ipv6(49160, 'false'), SS_UPLOAD_ASSET_PORT: '' },
  ]) {
    assert.throws(() => assertCompleteUploadAssetConfiguration(environment), error => {
      assert.match(error.code, /^UPLOAD_ASSET_CONFIGURATION_(?:PARTIAL|INVALID)$/);
      assert.doesNotMatch(`${error.message}\n${JSON.stringify(error)}`, new RegExp(privateValue));
      return true;
    });
  }
});

test('invalid address and close failures reject instead of leaving the setup probe pending', async () => {
  class ControlledServer extends EventEmitter {
    constructor(address, closeError) { super(); this.value = address; this.closeError = closeError; this.listening = true; }
    listen(options, callback) {
      assert.deepEqual(options, { host: '::1', port: 0, exclusive: true, ipv6Only: true });
      queueMicrotask(callback);
      return this;
    }
    address() { return this.value; }
    close(callback) { this.listening = false; queueMicrotask(() => callback(this.closeError)); }
  }
  await assert.rejects(selectUploadAssetPort({ createServer: () => new ControlledServer(null, null) }),
    { code: 'UPLOAD_ASSET_LOOPBACK_UNAVAILABLE' });
  await assert.rejects(selectUploadAssetPort({ createServer: () => new ControlledServer({ port: 50000 }, Error('close failed')) }),
    { code: 'UPLOAD_ASSET_LOOPBACK_UNAVAILABLE' });
});

