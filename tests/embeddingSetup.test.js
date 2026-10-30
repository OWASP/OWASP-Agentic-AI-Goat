'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { ensureEmbeddingModel } = require('../scripts/setup-application');
const { verifyEmbeddingRuntime } = require('../scripts/verify-embedding-runtime');

test('embedding setup uses bounded system-trusted model verification with an explicit cache', async t => {
  const cache = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-embedding-command-')));
  t.after(() => fs.rm(cache, { recursive: true, force: true }));
  let called = false;
  const result = await ensureEmbeddingModel({ root: '/owned/app', cacheDirectory: cache, env: {},
    runCommand: async (command, args, cwd, env, options) => {
      called = true;
      assert.equal(command, process.execPath);
      assert.deepEqual(args, ['--use-system-ca', '/owned/app/scripts/verify-embedding-runtime.js', '--cache-dir', cache]);
      assert.equal(cwd, '/owned/app'); assert.equal(env.XENOVA_CACHE, cache);
      assert.equal(options.timeoutMs, 600000);
      assert.notEqual(env.NODE_TLS_REJECT_UNAUTHORIZED, '0');
    } });
  assert.equal(called, true); assert.equal(result.dimensions, 384);
  for (const options of [{ cacheDirectory: 'relative' }, { cacheDirectory: cache, env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' } }]) {
    await assert.rejects(ensureEmbeddingModel({ ...options, runCommand: async () => assert.fail('unsafe configuration started') }));
  }
  await assert.rejects(ensureEmbeddingModel({ cacheDirectory: cache, env: {},
    runCommand: async () => { throw Error('network secret detail'); } }), /could not be verified/);
});

test('embedding qualification rejects invalid vectors, disposes the pipeline and restores cache scope', async t => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-embedding-setup-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const previous = process.env.XENOVA_CACHE;
  for (const vector of [new Float32Array(384).fill(0.25), [], new Float32Array(384),
    new Float32Array(384).fill(NaN), new Float64Array(384).fill(0.25), new Array(384).fill(0.25)]) {
    let disposed = false, initialized = false;
    const action = verifyEmbeddingRuntime({ cacheDirectory: root, createStore: () => ({
      async init() { initialized = true; assert.equal(process.env.XENOVA_CACHE, root); },
      async embedText() { assert.equal(initialized, true); return vector; },
      embedder: { async dispose() { disposed = true; } },
    }) });
    if (vector instanceof Float32Array && vector[0] === 0.25) assert.equal((await action).dimensions, 384);
    else await assert.rejects(action, /invalid/);
    assert.equal(disposed, true);
    assert.equal(process.env.XENOVA_CACHE, previous);
  }
});

test('setup persists canonical cache paths and refuses alias changes during verification', async t => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-embedding-alias-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const first = path.join(root, 'first'), second = path.join(root, 'second'), alias = path.join(root, 'alias');
  await fs.mkdir(first); await fs.mkdir(second); await fs.symlink(first, alias, 'dir');
  const verified = await ensureEmbeddingModel({ root, cacheDirectory: alias, env: {},
    runCommand: async (_command, args) => assert.equal(args.at(-1), first) });
  assert.equal(verified.cacheDirectory, first);
  await assert.rejects(ensureEmbeddingModel({ root, cacheDirectory: alias, env: {},
    runCommand: async () => { await fs.unlink(alias); await fs.symlink(second, alias, 'dir'); } }), /could not be verified/);
});
