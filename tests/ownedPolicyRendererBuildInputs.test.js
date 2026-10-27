'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const inputs = require('./postgres/ownedPolicyRendererBuildInputs');
const installer = require('../scripts/install/secureshop-owned-policy-renderer');
const { ROOT, SOURCE, FILES, PROVIDER, CONTRACT, capture, readOriginal, recipeFromDockerfile, manifestFromCaptured } = inputs._internals;
const sha = data => crypto.createHash('sha256').update(data).digest('hex');

test('captures exact original installer context and unchanged two-stage Dockerfile without execution authority', async () => {
  const packet = await inputs.capturePolicyRendererBuildInputs(ROOT);
  assert.deepEqual(packet.sourceManifest, installer.sourceManifest(ROOT));
  assert.equal(packet.context.files.length, 11);
  assert.equal(packet.recipe.dockerfile, await fs.readFile(path.join(ROOT, SOURCE, 'Dockerfile'), 'utf8'));
  assert.deepEqual(packet.recipe.stages.map(s => [s.name, s.packages]), [
    ['build', ['gcc', 'libc6-dev']], ['runtime', ['bubblewrap']]]);
  for (const row of packet.context.files) {
    const original = await fs.readFile(path.join(ROOT, packet.context.root, row.name));
    assert.deepEqual(Buffer.from(row.base64, 'base64'), original);
    assert.equal(row.sha256, sha(original)); assert.equal(row.bytes, original.length);
    assert(Object.isFrozen(row));
  }
  assert(Object.isFrozen(packet.recipe.stages[0].packages));
  assert.throws(() => { packet.context.files[0].base64 = ''; }, TypeError);
  assert.equal(packet.executionApproved, false); assert.equal(packet.metadataAuthenticated, false);
  assert.equal(packet.buildComplete, false); assert.equal(packet.runtimeAvailable, false);
  assert.equal(await inputs.verifyPolicyRendererBuildInputs(ROOT, packet), true);
});

test('original base, install stage, unrelated Dockerfile bytes and package order drift all fail closed', async () => {
  const original = await fs.readFile(path.join(ROOT, SOURCE, 'Dockerfile'), 'utf8');
  for (const changed of [original.replace('ec7758', 'ac7758'), original.replace('gcc libc6-dev', 'libc6-dev gcc'),
    original.replace('bubblewrap', 'bubblewrap curl'), original + '\n']) {
    assert.throws(() => recipeFromDockerfile(changed), { code: 'RENDERER_DOCKERFILE_CHANGED' });
  }
});

test('captured packet cannot be promoted or silently change original source or stages', async () => {
  const packet = await inputs.capturePolicyRendererBuildInputs(ROOT);
  for (const key of ['executionApproved', 'metadataAuthenticated', 'buildComplete', 'runtimeAvailable']) {
    await assert.rejects(inputs.verifyPolicyRendererBuildInputs(ROOT, { ...packet, [key]: true }), { code: 'RENDERER_INPUTS_NOT_AUTHORITY' });
  }
  for (const change of [p => { p.recipe.stages[0].packages.push('curl'); },
    p => { p.context.files[0].base64 = ''; }, p => { p.sourceManifest.sha256 = '0'.repeat(64); },
    p => { p.inputSha256 = '0'.repeat(64); }]) {
    const copy = structuredClone(packet); change(copy);
    await assert.rejects(inputs.verifyPolicyRendererBuildInputs(ROOT, copy), { code: 'RENDERER_INPUTS_CHANGED' });
  }
});

test('foreign checkout rejected before any filesystem/manifest access', async () => {
  await assert.rejects(capture(new Proxy({}, { get() { throw Error('unexpected IO'); } }), ROOT + '-copy'),
    { code: 'RENDERER_REPOSITORY_ROOT' });
});

test('captured manifest preserves exact installer rules/order and canonical contract equality', async () => {
  const packet = await inputs.capturePolicyRendererBuildInputs(ROOT);
  const files = packet.context.files, contract = packet.canonicalContract;
  assert.deepEqual(manifestFromCaptured(files, contract), installer.sourceManifest(ROOT));
  assert.throws(() => manifestFromCaptured(files.slice(1), contract), { code: 'RENDERER_MANIFEST_CHANGED' });
  const changed = structuredClone(files);
  changed[1].base64 = Buffer.from('**\n!policy-render/**\n').toString('base64');
  assert.throws(() => manifestFromCaptured(changed, contract), { code: 'POLICY_RENDER_BUILD_CONTEXT_INVALID' });
  assert.throws(() => manifestFromCaptured(files, { ...contract, sha256: '0'.repeat(64) }), { code: 'POLICY_RENDER_CONTRACT_DRIFT' });
});

test('bounded original reader rejects symlink, hardlink, privileged mode and oversized file before open', async () => {
  const filename = path.join(ROOT, SOURCE, FILES[0]);
  const actual = await fs.lstat(filename);
  for (const delta of [{ isSymbolicLink: () => true }, { nlink: 2 }, { mode: 0o100666 }, { size: 1048577 }]) {
    const io = { realpath: fs.realpath, lstat: async () => Object.assign(Object.create(actual), delta),
      open() { throw Error('unexpected open'); } };
    await assert.rejects(readOriginal(io, filename), { code: 'RENDERER_SOURCE_FILE' });
  }
  await assert.rejects(readOriginal({ realpath: async () => filename + '-other' }, filename), { code: 'RENDERER_SOURCE_PATH' });
});

// Real original files remain read-only. These doubles change only observations,
// not checkout bytes, and prove every opened handle is joined on rejection.
function observedIO({ corrupt, drift } = {}) {
  let opened = 0, closed = 0, corrupted = false;
  return { counts: () => ({ opened, closed }), io: { realpath: fs.realpath, lstat: fs.lstat,
    async open(filename, flags) {
      const h = await fs.open(filename, flags); opened++; let stats = 0;
      return { async stat() { const st = await h.stat(); stats++;
        return drift && filename.endsWith(drift) && stats > 1 ? Object.assign(Object.create(st), { ino: st.ino + 1 }) : st; },
      async read(buffer, offset, length, position) { const r = await h.read(buffer, offset, length, position);
        if (corrupt && !corrupted && filename.endsWith(corrupt) && position === 0 && r.bytesRead) { buffer[0] ^= 1; corrupted = true; }
        return r; }, async close() { await h.close(); closed++; } };
    } } };
}
test('source hash, installer hash and moving-file identity fail closed with handles closed', async () => {
  for (const [config, code] of [[{ corrupt: '/worker.js' }, 'RENDERER_SOURCE_CHANGED'],
    [{ corrupt: PROVIDER }, 'RENDERER_PROVIDER_CHANGED'], [{ drift: '/Dockerfile' }, 'RENDERER_SOURCE_CHANGED']]) {
    const probe = observedIO(config);
    await assert.rejects(capture(probe.io, ROOT), { code });
    assert.equal(probe.counts().opened, probe.counts().closed);
  }
});

// Execute the actual module/capture entry with a filesystem seam, not a second
// implementation of sourceManifest. Installer loading and unbounded readers
// are deliberately unavailable. Only one controlled file is staged at a time;
// original checkout files remain untouched and are never copied wholesale.
async function composedCapture(io) {
  const filename = path.join(ROOT, 'tests/postgres/ownedPolicyRendererBuildInputs.js');
  const source = await fs.readFile(filename, 'utf8'), requireActual = createRequire(filename);
  const module = { exports: {} };
  const evaluate = vm.runInThisContext('(function(module,exports,__dirname,require){\n' + source + '\n})', { filename });
  evaluate(module, module.exports, path.dirname(filename), function(name) {
      if (name.includes('secureshop-owned-policy-renderer')) throw Error('unsafe installer delegation');
      if (name === 'node:fs/promises') return io;
      if (name === 'node:fs') return { constants: require('node:fs').constants };
      return requireActual(name);
    });
  return module.exports.capturePolicyRendererBuildInputs(ROOT);
}
test('actual entry needs no installer path reader and reproduces the original manifest exactly', async () => {
  const io = { realpath: fs.realpath, lstat: fs.lstat, open: fs.open };
  const packet = await composedCapture(io);
  assert.deepEqual(JSON.parse(JSON.stringify(packet.sourceManifest)), installer.sourceManifest(ROOT));
});

async function stagedCapture(t, relative, arrange, onOpen) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'renderer-input-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const selected = path.join(ROOT, relative), staged = path.join(directory, 'input');
  await arrange(staged, directory, selected);
  if (!(await fs.lstat(staged)).isSymbolicLink()) await fs.chmod(staged, 0o644);
  let opened = 0, closed = 0, selectedOpens = 0;
  const io = { async realpath(name) {
    const real = await fs.realpath(name === selected ? staged : name);
    return name === selected && real === staged ? selected : real;
  }, lstat: name => fs.lstat(name === selected ? staged : name),
  async open(name, flags) {
    const h = await fs.open(name === selected ? staged : name, flags); opened++;
    if (name === selected) { selectedOpens++; await onOpen?.(staged, directory); }
    return { stat: () => h.stat(), read: (...args) => h.read(...args), async close() { await h.close(); closed++; } };
  } };
  try { return await composedCapture(io); }
  finally { assert.equal(opened, closed); t.diagnostic(`selected opens: ${selectedOpens}`); }
}

for (const relative of [SOURCE + '/Dockerfile.dockerignore', CONTRACT]) {
  test(`actual entry rejects symlink/oversize before reading ${relative}`, async t => {
    await t.test('symlink', async t => {
      await assert.rejects(stagedCapture(t, relative, async (staged, directory) => {
        const target = path.join(directory, 'target'); await fs.writeFile(target, 'not original'); await fs.symlink(target, staged);
      }), { code: 'RENDERER_SOURCE_PATH' });
    });
    await t.test('oversize', async t => {
      await assert.rejects(stagedCapture(t, relative, async staged => {
        await fs.writeFile(staged, Buffer.alloc(1048577));
      }), { code: 'RENDERER_SOURCE_FILE' });
    });
    await t.test('rename after open', async t => {
      await assert.rejects(stagedCapture(t, relative, async (staged, directory, selected) => {
        await fs.writeFile(staged, await fs.readFile(selected));
      }, async (staged, directory) => {
        await fs.rename(staged, path.join(directory, 'retired'));
        await fs.writeFile(staged, 'replacement');
      }), { code: 'RENDERER_SOURCE_CHANGED' });
    });
  });
}
test('actual entry rejects invalid ignore rules and changed canonical contract bytes', async t => {
  await t.test('ignore', async t => {
    await assert.rejects(stagedCapture(t, SOURCE + '/Dockerfile.dockerignore', staged => fs.writeFile(staged, '**\n!policy-render/**\n')),
      { code: 'POLICY_RENDER_BUILD_CONTEXT_INVALID' });
  });
  await t.test('canonical contract', async t => {
    await assert.rejects(stagedCapture(t, CONTRACT, staged => fs.writeFile(staged, 'changed contract')),
      { code: 'POLICY_RENDER_CONTRACT_DRIFT' });
  });
});
