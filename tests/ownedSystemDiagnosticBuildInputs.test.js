'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const build = require('./postgres/ownedSystemDiagnosticBuildInputs');
const system = require('./postgres/ownedSystemConfigPrivateBuild');
const I = build._internals;
const clone = value => structuredClone(value);

// Reads the actual checkout only; all mutations below are injected observations.
// No replica, temp tree, child, network or filesystem write is needed.
function observedIO({ stat, names, realpath, read, afterOpen } = {}) {
  const opened = [], closed = [];
  const io = {
    async realpath(name) { const value = await fs.realpath(name); return realpath ? realpath(name, value) : value; },
    async lstat(name) { const value = await fs.lstat(name); return stat ? stat(name, value, false) : value; },
    async readdir(name) { const value = await fs.readdir(name); return names ? names(name, value) : value; },
    async open(name, flags) {
      assert.ok(flags & require('node:fs').constants.O_NOFOLLOW);
      assert.ok(flags & require('node:fs').constants.O_NONBLOCK);
      const handle = await fs.open(name, flags); opened.push(name);
      return {
        async stat() { const value = await handle.stat(); return stat ? stat(name, value, true) : value; },
        async read(buffer, offset, length, position) {
          const result = await handle.read(buffer, offset, length, position);
          if (read) read(name, buffer, offset, result.bytesRead);
          if (afterOpen) afterOpen(name);
          return result;
        },
        async close() { await handle.close(); closed.push(name); },
      };
    },
  };
  return { io, opened, closed };
}
const sourceFile = path.join(I.ROOT, I.SOURCE, 'diagnostic-init.c');

test('exact original Python diagnostic recipe and generated entry are retained', async () => {
  const provider = await fs.readFile(path.join(I.ROOT, I.PROVIDER), 'utf8');
  assert.equal(I.sha(provider), I.PROVIDER_SHA);
  const recipe = /dockerfile='''FROM node@'''\+BASE\+'''([\s\S]*?)'''/.exec(provider);
  assert.ok(recipe); assert.equal(I.DOCKERFILE, 'FROM node@' + I.BASE + recipe[1]);
  const entry = /\(context\/'diagnostic-listener-entry.js'\)\.write_text\(("[^\n]+")\)/.exec(provider);
  assert.ok(entry); assert.equal(I.ENTRY, JSON.parse(entry[1]));
  assert.equal(build.RECIPE.target, 'original-v03-diagnostic');
  assert.deepEqual(build.RECIPE.entrypoint, ['/usr/local/bin/node', '/qualification/diagnostic-listener-entry.js']);
  assert.match(I.ENTRY, /maxConcurrent:1/);
  assert.match(provider, /def require_private_runtime_admission\(\):[\s\S]*?raise RuntimeError\('V24_PRIVATE_RUNTIME_NOT_ADMITTED'\)/);
});

test('closed recipe rejects config aliases, arbitrary context, entry, packages and authority', () => {
  for (const change of [{ target: 'v24-system' }, { target: 'v03' }, { base: 'sha256:' + '0'.repeat(64) },
    { platform: 'linux/amd64' }, { sourceRoot: '.' }, { packages: ['bubblewrap'] }, { user: '0' },
    { entrypoint: ['/bin/sh'] }, { dockerfile: I.DOCKERFILE + '\n' }, { dockerfileSha256: '0'.repeat(64) },
    { generatedEntry: { ...build.RECIPE.generatedEntry, source: I.ENTRY.replace('maxConcurrent:1', 'maxConcurrent:2') } },
    { executionApproved: true }, { version: true }]) {
    assert.throws(() => build.validateRecipe({ ...clone(build.RECIPE), ...change }), /DIAGNOSTIC_RECIPE_CHANGED/);
  }
  for (const value of [null, true, [], {}]) assert.throws(() => build.validateRecipe(value), /DIAGNOSTIC_RECIPE_CHANGED/);
  assert.throws(() => system.validateRecipe(build.RECIPE), /SYSTEM_RECIPE_CHANGED/);
});

test('real capture binds full original source and generated layout without granting authority', async () => {
  const result = await build.captureDiagnosticBuildInputs(I.ROOT);
  assert.deepEqual(result.context.files.map(row => row.name), I.CONTEXT_FILES);
  assert.equal(result.context.files.length, 55);
  assert.equal(result.buildContext.files, 57);
  assert.equal(result.buildContext.sourcePrefix, 'owned-system');
  assert.equal(result.buildContext.bytes, result.context.bytes + Buffer.byteLength(I.ENTRY) + Buffer.byteLength(I.DOCKERFILE));
  assert.equal(result.recipeProvider.sha256, I.PROVIDER_SHA);
  for (const key of ['executionApproved', 'buildComplete', 'runtimeAvailable']) assert.equal(result[key], false);
  assert.deepEqual(result.pending, ['diagnostic-target-apt-authentication', 'private-diagnostic-image-build',
    'private-diagnostic-runtime-handoff', 'original-v03-owner-admission']);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.context.files[0]) && Object.isFrozen(build.RECIPE.generatedEntry));
  assert.equal(await build.verifyDiagnosticBuildInputs(I.ROOT, result), true);
  await assert.rejects(build.verifyDiagnosticBuildInputs(I.ROOT, { ...result, inputSha256: '0'.repeat(64) }), /DIAGNOSTIC_INPUTS_CHANGED/);
  for (const key of ['executionApproved', 'buildComplete', 'runtimeAvailable'])
    await assert.rejects(build.verifyDiagnosticBuildInputs('/unread', { ...result, [key]: true }), /DIAGNOSTIC_INPUTS_NOT_AUTHORITY/);
});

test('foreign root fails before opening source', async () => {
  const state = observedIO();
  await assert.rejects(I.capture(state.io, '/foreign', build.RECIPE), /DIAGNOSTIC_REPOSITORY_ROOT/);
  assert.equal(state.opened.length, 0);
});

test('extra, missing and hidden members fail closed and every opened descriptor closes', async () => {
  for (const mode of ['extra', 'missing', 'hidden']) {
    const state = observedIO({ names(name, rows) {
      return name !== path.join(I.ROOT, I.SOURCE) ? rows : mode === 'missing' ? rows.slice(1) : [...rows, mode === 'hidden' ? '.env' : 'unknown'];
    } });
    await assert.rejects(I.capture(state.io, I.ROOT, build.RECIPE), /SYSTEM_CONTEXT_MEMBERS/);
    assert.deepEqual(state.closed, state.opened);
  }
});

test('symlink escape, hardlink, unsafe mode and oversized source are denied', async () => {
  for (const change of [{ nlink: 2 }, { mode: 0o100666 }, { size: I.LIMITS.fileBytes + 1 }]) {
    const state = observedIO({ stat(name, row) { return name === sourceFile ? Object.assign(row, change) : row; } });
    await assert.rejects(I.capture(state.io, I.ROOT, build.RECIPE), /SYSTEM_SOURCE_FILE/);
    assert.deepEqual(state.closed, state.opened);
  }
  const state = observedIO({ realpath(name, value) { return name === sourceFile ? '/foreign' : value; } });
  await assert.rejects(I.capture(state.io, I.ROOT, build.RECIPE), /SYSTEM_SOURCE_PATH/);
  assert.deepEqual(state.closed, state.opened);
});

test('provider mutation and mutation after capture cannot enter a mixed snapshot', async () => {
  for (const scenario of ['provider', 'earlier', 'birth']) {
    let late = false;
    const state = observedIO({
      read(name, buffer, offset, count) {
        if (count && (scenario === 'provider' && name.endsWith(I.PROVIDER)
          || scenario === 'earlier' && late && name === sourceFile)) buffer[offset] ^= 1;
      },
      afterOpen(name) { if (name.endsWith('/worker.js')) late = true; },
      stat(name, row, handle) { if (scenario === 'birth' && name === sourceFile && handle) row.ino++; return row; },
    });
    await assert.rejects(I.capture(state.io, I.ROOT, build.RECIPE), /DIAGNOSTIC_PROVIDER_CHANGED|SYSTEM_SOURCE_CHANGED/);
    assert.deepEqual(state.closed, state.opened);
  }
});

test('read failure preserves original exception and closes the descriptor', async () => {
  const primary = new Error('controlled read failure');
  const state = observedIO({ read(name) { if (name === sourceFile) throw primary; } });
  await assert.rejects(I.capture(state.io, I.ROOT, build.RECIPE), error => error === primary);
  assert.deepEqual(state.closed, state.opened);
});

test('regular-to-FIFO substitution cannot block open and is rejected before reading', async () => {
  let sourceReads = 0;
  const state = observedIO({
    stat(name, row, handle) { if (name === sourceFile && handle) { row.mode = 0o010600; row.isFile = () => false; } return row; },
    read(name) { if (name === sourceFile) sourceReads++; },
  });
  await assert.rejects(I.capture(state.io, I.ROOT, build.RECIPE), /SYSTEM_SOURCE_CHANGED/);
  assert.equal(sourceReads, 0); assert.deepEqual(state.closed, state.opened);
});

test('shared primitive remains fixed-context only and public module exposes no live operation', async () => {
  assert.deepEqual(Object.keys(build).sort(), ['RECIPE', '_internals', 'captureDiagnosticBuildInputs', 'validateRecipe', 'verifyDiagnosticBuildInputs'].sort());
  const before = await system._internals.captureContext(fs, I.ROOT);
  const after = (await build.captureDiagnosticBuildInputs(I.ROOT)).context;
  assert.deepEqual(before, after);
});
