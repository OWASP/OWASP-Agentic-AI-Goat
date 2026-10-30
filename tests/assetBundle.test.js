'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  captureAssetBundle, verifyAssetBundle, isAssetBundleProof, QUIESCENCE_POLICY,
  MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_MANIFEST_BYTES,
} = require('../db/postgres/asset-bundle');

async function workspace() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-asset-bundle-'));
}

async function sourceWithPayload(root) {
  const source = path.join(root, 'source');
  await fs.mkdir(path.join(source, 'nested'), { recursive: true });
  await fs.writeFile(path.join(source, 'nested', 'opaque-ref.bin'), Buffer.from([0, 255, 10, 0, 35, 46, 46, 47]));
  await fs.writeFile(path.join(source, 'plain.txt'), 'exact bytes\n');
  return source;
}

test('captures explicit opaque references into deterministic private paths and returns branded proof', async () => {
  const root = await workspace();
  try {
    const source = await sourceWithPayload(root);
    const first = await captureAssetBundle({ sourceRoot: source, relativePaths: ['nested/opaque-ref.bin', 'plain.txt'], destinationRoot: path.join(root, 'bundle-a') });
    const second = await captureAssetBundle({ sourceRoot: source, relativePaths: ['nested/opaque-ref.bin', 'plain.txt'], destinationRoot: path.join(root, 'bundle-b') });
    const reordered = await captureAssetBundle({ sourceRoot: source, relativePaths: ['plain.txt', 'nested/opaque-ref.bin'], destinationRoot: path.join(root, 'bundle-c') });
    assert.equal(isAssetBundleProof(first), true);
    assert.equal(isAssetBundleProof({ ...first }), false);
    assert.equal(Object.getOwnPropertySymbols(first).length, 0);
    assert.equal(first.manifestDigest, second.manifestDigest);
    assert.equal(first.manifestDigest, reordered.manifestDigest);
    assert.deepEqual(first.files, [
      { sourcePath: 'nested/opaque-ref.bin', bundlePath: 'files/00000000.bin', bytes: 8, sha256: '3570d65b8b380219eb611ff0f5a4f815777cfb84dd5516a80a833483310a95a4' },
      { sourcePath: 'plain.txt', bundlePath: 'files/00000001.bin', bytes: 12, sha256: '6a77ce4ad94636f6120bb985066c1d75ce65b73f264a35f9d5ac910e252f0355' },
    ]);
    assert.equal(Object.isFrozen(first.files), true);
    assert.equal(Object.isFrozen(first.files[0]), true);
    assert.equal((await fs.readFile(path.join(root, 'bundle-a', 'files', '00000000.bin')))[1], 255);
    assert.equal((await fs.readFile(path.join(root, 'bundle-a', 'manifest.json'))).toString().includes(source), false);
    assert.equal((await fs.stat(path.join(root, 'bundle-a'))).mode & 0o777, 0o700);
    assert.equal((await fs.stat(path.join(root, 'bundle-a', 'files'))).mode & 0o777, 0o700);
    assert.equal((await verifyAssetBundle(first.bundleRoot)).manifestDigest, first.manifestDigest);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('rejects unsafe, duplicate, symlink, and nonregular source references before creating a bundle', async () => {
  const root = await workspace();
  try {
    const source = await sourceWithPayload(root);
    await fs.mkdir(path.join(source, 'directory'));
    await fs.symlink(path.join(source, 'plain.txt'), path.join(source, 'link.txt'));
    await fs.mkdir(path.join(source, 'real-dir'));
    await fs.symlink(path.join(source, 'real-dir'), path.join(source, 'dir-link'));
    const cases = [
      ['../escape', 'UNSAFE_ASSET_PATH'],
      ['/absolute', 'UNSAFE_ASSET_PATH'],
      ['C:/absolute', 'UNSAFE_ASSET_PATH'],
      ['nested\\opaque-ref.bin', 'UNSAFE_ASSET_PATH'],
      ['nested/\0bad', 'UNSAFE_ASSET_PATH'],
      ['plain.txt', 'DUPLICATE_ASSET_REFERENCE'],
      ['link.txt', 'ASSET_SOURCE_SYMLINK'],
      ['directory', 'ASSET_SOURCE_NOT_REGULAR'],
      ['dir-link/file', 'ASSET_SOURCE_SYMLINK'],
    ];
    for (const [relativePath, code] of cases) {
      const relativePaths = code === 'DUPLICATE_ASSET_REFERENCE' ? [relativePath, relativePath] : [relativePath];
      await assert.rejects(captureAssetBundle({ sourceRoot: source, relativePaths, destinationRoot: path.join(root, `reject-${cases.indexOf(cases.find(item => item[0] === relativePath))}`) }), { code });
    }
    const sourceLink = path.join(root, 'source-link');
    await fs.symlink(source, sourceLink);
    await assert.rejects(captureAssetBundle({ sourceRoot: sourceLink, relativePaths: ['plain.txt'], destinationRoot: path.join(root, 'root-link') }), { code: 'ASSET_SOURCE_ROOT_NOT_DIRECTORY' });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('refuses destination overwrite and rejects an incomplete bundle state', async () => {
  const root = await workspace();
  try {
    const source = await sourceWithPayload(root);
    const destination = path.join(root, 'bundle');
    await fs.mkdir(destination);
    await assert.rejects(captureAssetBundle({ sourceRoot: source, relativePaths: ['plain.txt'], destinationRoot: destination }), { code: 'ASSET_DESTINATION_EXISTS' });
    await fs.rm(destination, { recursive: true });
    await fs.mkdir(destination);
    await fs.writeFile(path.join(destination, 'INCOMPLETE'), 'partial');
    await assert.rejects(verifyAssetBundle(destination), { code: 'INCOMPLETE_ASSET_BUNDLE' });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('bounds sparse files before allocation and leaves an incomplete marker after a partial capture', async () => {
  const root = await workspace();
  try {
    const source = await sourceWithPayload(root);
    const oversized = path.join(source, 'oversized.bin');
    const handle = await fs.open(oversized, 'w');
    await handle.truncate(MAX_FILE_BYTES + 1);
    await handle.close();
    const oversizedDestination = path.join(root, 'oversized-bundle');
    await assert.rejects(captureAssetBundle({ sourceRoot: source, relativePaths: ['oversized.bin'], destinationRoot: oversizedDestination }), { code: 'ASSET_FILE_TOO_LARGE' });
    await assert.rejects(fs.stat(oversizedDestination), { code: 'ENOENT' });
    const tooMany = Array.from({ length: 10_001 }, (_, index) => `missing-${index}`);
    await assert.rejects(captureAssetBundle({ sourceRoot: source, relativePaths: tooMany, destinationRoot: path.join(root, 'too-many') }), { code: 'ASSET_FILE_COUNT_LIMIT' });
    const totalSource = path.join(root, 'total-source');
    await fs.mkdir(totalSource);
    for (let index = 0; index < 9; index += 1) {
      const file = await fs.open(path.join(totalSource, `${index}.bin`), 'w');
      await file.truncate(index === 8 ? 1 : MAX_FILE_BYTES);
      await file.close();
    }
    const totalDestination = path.join(root, 'total-bundle');
    await assert.rejects(captureAssetBundle({ sourceRoot: totalSource, relativePaths: Array.from({ length: 9 }, (_, index) => `${index}.bin`), destinationRoot: totalDestination }), { code: 'ASSET_TOTAL_BYTES_LIMIT' });
    await assert.rejects(fs.stat(totalDestination), { code: 'ENOENT' });
    const partialSource = path.join(root, 'partial-source');
    await fs.mkdir(partialSource);
    await fs.writeFile(path.join(partialSource, 'a.bin'), 'first');
    const partialDestination = path.join(root, 'partial-bundle');
    await assert.rejects(captureAssetBundle({ sourceRoot: partialSource, relativePaths: ['a.bin', 'b.bin'], destinationRoot: partialDestination }), { code: 'ASSET_SOURCE_MISSING' });
    assert.equal(await fs.stat(partialDestination).then(() => true, error => error.code !== 'ENOENT'), false);
    await fs.mkdir(path.join(partialDestination, 'files'), { recursive: true });
    await fs.writeFile(path.join(partialDestination, 'INCOMPLETE'), 'partial');
    await fs.writeFile(path.join(partialDestination, 'files', '00000000.bin'), 'first');
    await assert.rejects(verifyAssetBundle(partialDestination), { code: 'INCOMPLETE_ASSET_BUNDLE' });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('verification is bounded to the exact manifest and detects tampered bytes, metadata, and entries', async () => {
  const root = await workspace();
  try {
    const source = await sourceWithPayload(root);
    const destination = path.join(root, 'bundle');
    const proof = await captureAssetBundle({ sourceRoot: source, relativePaths: ['plain.txt'], destinationRoot: destination });
    await fs.writeFile(path.join(destination, 'unexpected'), 'extra');
    await assert.rejects(verifyAssetBundle(destination), { code: 'UNEXPECTED_ASSET_BUNDLE_ENTRY' });
    await fs.rm(path.join(destination, 'unexpected'));
    await fs.appendFile(path.join(destination, 'files', '00000000.bin'), 'tamper');
    await assert.rejects(verifyAssetBundle(destination), { code: 'ASSET_BUNDLE_HASH_MISMATCH' });
    await fs.writeFile(path.join(destination, 'files', '00000000.bin'), 'exact bytes\n');
    const manifestPath = path.join(destination, 'manifest.json');
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    manifest.extra = true;
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await assert.rejects(verifyAssetBundle(destination), { code: 'UNKNOWN_ASSET_MANIFEST_FIELDS' });
    assert.equal(isAssetBundleProof(proof), true);
    assert.equal(proof.manifestDigest.length, 64);
    assert.ok(MAX_TOTAL_BYTES > MAX_FILE_BYTES);
    assert.ok(MAX_MANIFEST_BYTES < MAX_TOTAL_BYTES);
    const oversizedManifest = { ...manifest };
    delete oversizedManifest.extra;
    oversizedManifest.padding = 'x'.repeat(MAX_MANIFEST_BYTES);
    await fs.writeFile(manifestPath, `${JSON.stringify(oversizedManifest, null, 2)}\n`);
    await assert.rejects(verifyAssetBundle(destination), { code: 'ASSET_MANIFEST_BYTES_LIMIT' });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('requires canonical manifest bytes and rejects bundle symlinks', async () => {
  const root = await workspace();
  try {
    const source = await sourceWithPayload(root);
    const destination = path.join(root, 'bundle');
    await captureAssetBundle({ sourceRoot: source, relativePaths: ['plain.txt'], destinationRoot: destination });
    const manifestPath = path.join(destination, 'manifest.json');
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    await fs.writeFile(manifestPath, JSON.stringify(manifest));
    await assert.rejects(verifyAssetBundle(destination), { code: 'NONCANONICAL_ASSET_MANIFEST' });
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const filePath = path.join(destination, 'files', '00000000.bin');
    const bytes = await fs.readFile(filePath);
    await fs.unlink(filePath);
    await fs.symlink(path.join(root, 'source', 'plain.txt'), filePath);
    await assert.rejects(verifyAssetBundle(destination));
    await fs.unlink(filePath);
    await fs.writeFile(filePath, bytes, { flag: 'wx', mode: 0o600 });
    assert.equal((await verifyAssetBundle(destination)).manifestDigest.length, 64);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('exports the quiescence precondition as part of the proof contract', () => {
  assert.match(QUIESCENCE_POLICY, /quiesce/);
  assert.match(QUIESCENCE_POLICY, /symlink-race immunity/);
});

test('bounded descriptor reader never reads or allocates beyond the initial size plus sentinel', async () => {
  const {readBounded}=require('../db/postgres/asset-bundle');
  const requests=[];
  // Simulates an indefinitely growing file; no EOF and no filesystem/global patches.
  const handle={async read(buffer,offset,length,position){requests.push({capacity:buffer.length,length,position});const bytesRead=Math.min(3,length);buffer.fill(65,offset,offset+bytesRead);return{bytesRead};}};
  const bytes=await readBounded(handle,7);
  assert.equal(bytes.length,8);
  assert.deepEqual(requests.map(r=>r.position),[0,3,6]);
  assert.ok(requests.every(r=>r.capacity===8&&r.position+r.length<=8));
  assert.equal((await readBounded(handle,0)).length,1);
  assert.equal((await readBounded({read:async()=>({bytesRead:0})},7)).length,0);
});
