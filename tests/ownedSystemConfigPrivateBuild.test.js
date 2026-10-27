'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const build = require('./postgres/ownedSystemConfigPrivateBuild');
const I = build._internals;

// Test-only reading of the one literal recipe. Production accepts the pure
// Python exporter DTO and verifies the reviewed original recipe/provider hashes.
async function originalRecipe() {
  const source = await fs.readFile(path.join(I.ROOT, I.PROVIDER), 'utf8');
  const match = /def original_dockerfile\(\):\n  return '''FROM node@'''\+BASE\+'''([\s\S]*?)'''/.exec(source);
  assert.ok(match);
  const dockerfile = 'FROM node@' + I.BASE + match[1];
  return { version: 1, target: 'v24-system', base: I.BASE, platform: 'linux/arm64', sourceRoot: I.SOURCE,
    dockerfile, dockerfileSha256: I.sha(dockerfile), packages: [...I.PACKAGES], user: '10001:10001', entrypoint: [...I.ENTRYPOINT] };
}

async function memorySource() {
  let inode = 1;
  const nodes = new Map(), handles = [], reads = [];
  function add(name, bytes = null) {
    const directory = bytes === null;
    const row = { bytes: directory ? null : Buffer.from(bytes), ino: inode++, dev: 1, nlink: 1,
      mode: directory ? 0o40755 : 0o100644, mtimeMs: 1, ctimeMs: 1, symbolic: false };
    nodes.set(name, row); return row;
  }
  add(I.ROOT); add(path.join(I.ROOT, I.SOURCE)); add(path.join(I.ROOT, I.SOURCE, 'upload-preview-runtime'));
  add(path.join(I.ROOT, I.PROVIDER), await fs.readFile(path.join(I.ROOT, I.PROVIDER)));
  for (const file of I.CONTEXT_FILES) add(path.join(I.ROOT, I.SOURCE, file), 'x');
  const stat = row => ({ ...row, size: row.bytes?.length || 0,
    isFile: () => row.bytes !== null && !row.symbolic, isDirectory: () => row.bytes === null && !row.symbolic,
    isSymbolicLink: () => row.symbolic });
  const io = {
    async realpath(name) { if (!nodes.has(name)) throw Error('ENOENT'); return nodes.get(name).redirect || name; },
    async lstat(name) { if (!nodes.has(name)) throw Error('ENOENT'); return stat(nodes.get(name)); },
    async readdir(name) { return [...nodes.keys()].filter(key => path.dirname(key) === name).map(key => path.basename(key)); },
    async open(name, flags) {
      assert.ok(flags & require('node:fs').constants.O_NOFOLLOW);
      const row = nodes.get(name), handle = { closed: false, name,
        async stat() { return stat(row); },
        async read(buffer, offset, length, position) {
          reads.push(name); const bytesRead = row.bytes.copy(buffer, offset, position, position + length);
          if (io.afterRead) await io.afterRead(name, row);
          return { bytesRead };
        },
        async close() { this.closed = true; },
      };
      handles.push(handle); return handle;
    },
  };
  return { io, nodes, handles, reads, add };
}

test('original Python recipe bytes, base and one stage are exact; exported structures are immutable', async () => {
  const recipe = await originalRecipe();
  assert.equal(recipe.dockerfileSha256, I.RECIPE_SHA);
  const validated = build.validateRecipe(recipe);
  assert.equal(validated.base, 'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5');
  assert.match(validated.dockerfile, /COPY \. \/qualification\/owned-system\n/);
  assert.match(validated.dockerfile, /gcc libc6-dev bubblewrap &&/);
  assert.ok(Object.isFrozen(validated) && Object.isFrozen(validated.packages));
  recipe.packages.push('foreign'); assert.deepEqual(validated.packages, ['gcc', 'libc6-dev', 'bubblewrap']);
});

test('recipe mutations cannot select another target, base, Dockerfile, context, user or package list', async () => {
  const recipe = await originalRecipe();
  for (const change of [{ version: true }, { target: 'v23-registry' }, { base: 'sha256:' + 'e'.repeat(64) },
    { platform: 'linux/amd64' }, { sourceRoot: '.' }, { user: '0' }, { packages: ['bubblewrap', 'gcc', 'libc6-dev'] },
    { entrypoint: ['sh'] }, { dockerfile: recipe.dockerfile + '\n' }, { dockerfileSha256: '0'.repeat(64) },
    { runtimeAvailable: true }]) assert.throws(() => build.validateRecipe({ ...recipe, ...change }), /SYSTEM_RECIPE_CHANGED/);
  for (const value of [null, true, [], {}]) assert.throws(() => build.validateRecipe(value), /SYSTEM_RECIPE_CHANGED/);
});

test('real read-only source capture covers the complete original context and remains only input evidence', async () => {
  const packet = await build.captureSystemBuildInputs(I.ROOT, await originalRecipe());
  assert.equal(packet.context.files.length, 55);
  assert.deepEqual(packet.context.files.map(row => row.name), I.CONTEXT_FILES);
  assert.equal(packet.context.directories.length, 2);
  assert.equal(packet.context.bytes, packet.context.files.reduce((sum, row) => sum + row.bytes, 0));
  assert.equal(packet.recipeProvider.sha256, I.PROVIDER_SHA);
  assert.equal(packet.executionApproved, false); assert.equal(packet.buildComplete, false); assert.equal(packet.runtimeAvailable, false);
  assert.deepEqual(packet.pending, ['shared-original-base-apt-authentication', 'private-image-build', 'private-system-runtime-handoff']);
  assert.ok(Object.isFrozen(packet.context.files[0]));
  assert.equal(await build.verifySystemBuildInputs(I.ROOT, packet), true);
  await assert.rejects(build.verifySystemBuildInputs(I.ROOT, { ...packet, inputSha256: '0'.repeat(64) }), /SYSTEM_INPUTS_CHANGED/);
  await assert.rejects(build.verifySystemBuildInputs('/unread', { ...packet, executionApproved: true }), /SYSTEM_INPUTS_NOT_AUTHORITY/);
});

test('controlled capture reads bounded originals only and closes every descriptor', async () => {
  const state = await memorySource(), packet = await I.capture(state.io, I.ROOT, await originalRecipe());
  assert.equal(packet.context.bytes, 55);
  assert.equal(state.handles.length, 112); assert.ok(state.handles.every(row => row.closed));
  assert.equal(typeof state.io.writeFile, 'undefined');
  assert.equal(packet.recipeProvider.path, I.PROVIDER);
});

test('unknown, missing and hidden context files fail before their bytes are read', async () => {
  for (const change of ['extra', 'missing', 'hidden', 'nested']) {
    const state = await memorySource(), base = path.join(I.ROOT, I.SOURCE);
    if (change === 'missing') state.nodes.delete(path.join(base, 'system-init.c'));
    else state.add(path.join(base, change === 'hidden' ? '.env' : change === 'nested' ? 'upload-preview-runtime/unknown' : 'unexpected'), 'never-read');
    await assert.rejects(I.capture(state.io, I.ROOT, await originalRecipe()), /SYSTEM_CONTEXT_MEMBERS/);
    assert.ok(state.reads.every(name => !/unexpected|unknown|\.env$/.test(name)));
    assert.ok(state.handles.every(row => row.closed));
  }
});

test('symlink, hardlink, privileged modes, oversized files and foreign roots are rejected', async () => {
  for (const mutation of [row => { row.redirect = '/outside'; }, row => { row.symbolic = true; },
    row => { row.nlink = 2; }, row => { row.mode = 0o104644; }, row => { row.mode = 0o100666; },
    row => { row.bytes = Buffer.alloc(I.LIMITS.fileBytes + 1); }]) {
    const state = await memorySource(); mutation(state.nodes.get(path.join(I.ROOT, I.SOURCE, 'http-listener.js')));
    await assert.rejects(I.capture(state.io, I.ROOT, await originalRecipe()), /SYSTEM_SOURCE_(PATH|FILE)/);
    assert.ok(state.handles.every(row => row.closed));
  }
  const state = await memorySource();
  await assert.rejects(I.capture(state.io, '/other-checkout', await originalRecipe()), /SYSTEM_REPOSITORY_ROOT/);
  assert.equal(state.handles.length, 0);
  state.nodes.get(path.join(I.ROOT, I.SOURCE)).redirect = '/outside';
  await assert.rejects(I.capture(state.io, I.ROOT, await originalRecipe()), /SYSTEM_SOURCE_PATH/);
});

test('changed provider, file replacement/growth and directory changes retain failure and close descriptors', async () => {
  for (const scenario of ['provider', 'replace', 'grow', 'directory', 'read-throws']) {
    const state = await memorySource(), name = path.join(I.ROOT, I.SOURCE, 'system-init.c');
    if (scenario === 'provider') state.nodes.get(path.join(I.ROOT, I.PROVIDER)).bytes = Buffer.from('not-the-reviewed-export');
    else state.io.afterRead = (current, row) => {
      if (current !== name) return;
      if (scenario === 'replace') row.ino++;
      if (scenario === 'grow') row.bytes = Buffer.concat([row.bytes, Buffer.from('x')]);
      if (scenario === 'directory') state.add(path.join(I.ROOT, I.SOURCE, 'late-file'), 'x');
      if (scenario === 'read-throws') throw Error('CONTROLLED_READ_FAILURE');
    };
    await assert.rejects(I.capture(state.io, I.ROOT, await originalRecipe()), /SYSTEM_(RECIPE_PROVIDER_CHANGED|SOURCE_CHANGED)|CONTROLLED_READ_FAILURE/);
    assert.ok(state.handles.every(row => row.closed));
  }
});

test('aggregate source size is bounded separately from individual files', async () => {
  const state = await memorySource();
  for (const file of I.CONTEXT_FILES) state.nodes.get(path.join(I.ROOT, I.SOURCE, file)).bytes = Buffer.alloc(400000);
  await assert.rejects(I.capture(state.io, I.ROOT, await originalRecipe()), /SYSTEM_CONTEXT_LIMIT/);
  assert.ok(state.handles.every(row => row.closed));
});

test('an earlier file changed during later capture cannot enter a mixed source snapshot', async () => {
  const state = await memorySource(); let changed = false;
  state.io.afterRead = name => {
    if (!changed && name === path.join(I.ROOT, I.SOURCE, 'worker.js')) {
      state.nodes.get(path.join(I.ROOT, I.SOURCE, I.CONTEXT_FILES[0])).bytes = Buffer.from('later mutation');
      changed = true;
    }
  };
  await assert.rejects(I.capture(state.io, I.ROOT, await originalRecipe()), /SYSTEM_SOURCE_CHANGED/);
  assert.ok(changed); assert.ok(state.handles.every(row => row.closed));
});
