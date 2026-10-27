'use strict';

// Original System build-input phase only. Import is inert; capture reads the
// existing checkout without copying it. No APT verifier, process launcher,
// private image/runtime handoff, or build authorization is implemented here.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const ROOT = path.resolve(__dirname, '../..');
const SOURCE = 'sidecars/sandbox-runner/owned-system';
const PROVIDER = 'tests/postgres/system_config_owned_executor.py';
const PROVIDER_SHA = '37518fc3ba319ac37554caad2e84cec3e0f23b11e7b53d1055ba60561823abee';
const BASE = 'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5';
const RECIPE_SHA = '7e5f852b304d69bd76b446cb4edcf8da4760a9d9064fd7c1bc8fbf9a4209cc5b';
const LIMITS = Object.freeze({ fileBytes: 1024 ** 2, contextBytes: 16 * 1024 ** 2, files: 128 });
// The historical caller supplies this whole directory as its Docker context,
// including other System fixtures. Do not narrow it to the listener imports or
// the different local-package-manifest recipe. Extra files require review.
const CONTEXT_FILES = Object.freeze([
  'CLIENT_PROTOCOL.md', 'DIAGNOSTIC_DESIGN.md', 'Dockerfile.local', 'Dockerfile.local.amd64.candidate',
  'LOCAL_PACKAGE.md', 'README.md', 'config-reader.js', 'contract.js', 'diagnostic-contract.js',
  'diagnostic-executor.js', 'diagnostic-http-handler.js', 'diagnostic-http-listener.js',
  'diagnostic-http-native-qualification.js', 'diagnostic-init.c', 'diagnostic-native-attack.c',
  'diagnostic-native-qualification.js', 'diagnostic-receipt.js', 'diagnostic-result.js',
  'diagnostic-supervisor.c', 'diagnostic-wire.js', 'executor.js', 'health-contract.js',
  'health-metrics.js', 'http-handler.js', 'http-listener.js', 'http-native-qualification.js',
  'local-listener-entry.js', 'local-package-amd64.candidate.json', 'local-package-manifest.json',
  'native-qualification.js', 'process-supervisor.c', 'receipt.js', 'restart-command-executor.js',
  'restart-contract.js', 'restart-http-handler.js', 'restart-http-listener.js', 'restart-init.c',
  'restart-manager.js', 'restart-service-child.c', 'restart-supervisor.c', 'restart-systemctl',
  'restart-target.js', 'restart-wire.js', 'system-init.c', 'upload-preview-contract.js',
  'upload-preview-dependencies.js', 'upload-preview-executor.js', 'upload-preview-http-handler.js',
  'upload-preview-http-listener.js', 'upload-preview-init.c', 'upload-preview-native-qualification.js',
  'upload-preview-runtime/package-lock.json', 'upload-preview-runtime/package.json',
  'upload-preview-worker.js', 'worker.js',
].sort());
const ENTRYPOINT = Object.freeze(['/usr/local/bin/node', '/qualification/owned-system/http-listener.js']);
const PACKAGES = Object.freeze(['gcc', 'libc6-dev', 'bubblewrap']);
const fail = code => Object.assign(new Error(code), { code });
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}

function validateRecipe(recipe) {
  if (!recipe || !isDeepStrictEqual(Object.keys(recipe).sort(), ['version', 'target', 'base', 'platform',
    'sourceRoot', 'dockerfile', 'dockerfileSha256', 'packages', 'user', 'entrypoint'].sort())
    || recipe.version !== 1 || recipe.target !== 'v24-system' || recipe.base !== BASE
    || recipe.platform !== 'linux/arm64' || recipe.sourceRoot !== SOURCE || recipe.user !== '10001:10001'
    || !isDeepStrictEqual(recipe.packages, PACKAGES) || !isDeepStrictEqual(recipe.entrypoint, ENTRYPOINT)
    || typeof recipe.dockerfile !== 'string' || Buffer.byteLength(recipe.dockerfile) > 8192
    || recipe.dockerfileSha256 !== RECIPE_SHA || sha(recipe.dockerfile) !== RECIPE_SHA) throw fail('SYSTEM_RECIPE_CHANGED');
  return freeze(JSON.parse(JSON.stringify(recipe)));
}

function sameStat(a, b) {
  return ['dev', 'ino', 'size', 'mode', 'nlink', 'mtimeMs', 'ctimeMs'].every(key => a[key] === b[key]);
}
async function canonicalDirectory(io, name) {
  if (await io.realpath(name) !== name) throw fail('SYSTEM_SOURCE_PATH');
  const info = await io.lstat(name);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o7022)) throw fail('SYSTEM_SOURCE_DIRECTORY');
  return info;
}
async function regular(io, name) {
  if (await io.realpath(name) !== name) throw fail('SYSTEM_SOURCE_PATH');
  const lexical = await io.lstat(name);
  if (!lexical.isFile() || lexical.isSymbolicLink() || lexical.nlink !== 1
    || ![0o444, 0o555, 0o644, 0o755].includes(lexical.mode & 0o7777)
    || !Number.isSafeInteger(lexical.size) || lexical.size < 1 || lexical.size > LIMITS.fileBytes)
    throw fail('SYSTEM_SOURCE_FILE');
  const handle = await io.open(name, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || !sameStat(lexical, before)) throw fail('SYSTEM_SOURCE_CHANGED');
    // Fixed-sized buffer bounds a concurrent growth attempt before the final
    // identity/size recheck. Never readFile an unbounded moving source.
    const data = Buffer.alloc(before.size + 1); let offset = 0;
    while (offset < data.length) {
      const { bytesRead } = await handle.read(data, offset, data.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== before.size || !sameStat(before, await handle.stat())
      || !sameStat(before, await io.lstat(name)) || await io.realpath(name) !== name)
      throw fail('SYSTEM_SOURCE_CHANGED');
    return { bytes: offset, sha256: sha(data.subarray(0, offset)), mode: before.mode & 0o777 };
  } finally { await handle.close(); }
}

// Shared read-only context primitive, not target or build admission. Both
// original System recipes use this exact, closed source directory membership.
async function captureContext(io, root) {
  if (root !== ROOT) throw fail('SYSTEM_REPOSITORY_ROOT');
  await canonicalDirectory(io, root);
  const base = path.join(root, SOURCE), files = [], directories = [];
  let total = 0;
  async function walk(name, relative) {
    const before = await canonicalDirectory(io, name), names = (await io.readdir(name)).sort();
    const expected = [...new Set(CONTEXT_FILES.filter(file => file.startsWith(relative))
      .map(file => file.slice(relative.length).split('/')[0]))].sort();
    if (!isDeepStrictEqual(names, expected)) throw fail('SYSTEM_CONTEXT_MEMBERS');
    directories.push({ name: relative ? relative.slice(0, -1) : '.', mode: before.mode & 0o777 });
    for (const child of names) {
      const full = path.join(name, child), local = relative + child;
      if (CONTEXT_FILES.includes(local)) {
        const row = await regular(io, full); total += row.bytes;
        if (total > LIMITS.contextBytes || files.length >= LIMITS.files) throw fail('SYSTEM_CONTEXT_LIMIT');
        files.push({ name: local, ...row });
      } else await walk(full, local + '/');
    }
    if (!sameStat(before, await io.lstat(name)) || await io.realpath(name) !== name
      || !isDeepStrictEqual(names, (await io.readdir(name)).sort())) throw fail('SYSTEM_SOURCE_CHANGED');
  }
  await walk(base, '');
  if (!isDeepStrictEqual(files.map(file => file.name), CONTEXT_FILES)) throw fail('SYSTEM_CONTEXT_MEMBERS');
  // Detect changes to an earlier file while later members were being captured.
  // The eventual build still needs source-before/after verification; this is
  // bounded input evidence, not a filesystem lock or immutable runtime lease.
  for (const { name, ...expected } of files) {
    if (!isDeepStrictEqual(expected, await regular(io, path.join(base, name)))) throw fail('SYSTEM_SOURCE_CHANGED');
  }
  return { sourceRoot: SOURCE, files, directories, bytes: total };
}

async function capture(io, root, recipe) {
  recipe = validateRecipe(recipe);
  if (root !== ROOT) throw fail('SYSTEM_REPOSITORY_ROOT');
  await canonicalDirectory(io, root);
  const provider = await regular(io, path.join(root, PROVIDER));
  if (provider.sha256 !== PROVIDER_SHA) throw fail('SYSTEM_RECIPE_PROVIDER_CHANGED');
  const context = await captureContext(io, root);
  if (!isDeepStrictEqual(provider, await regular(io, path.join(root, PROVIDER)))) throw fail('SYSTEM_RECIPE_PROVIDER_CHANGED');
  const inputs = { version: 1, kind: 'original-v24-system-build-inputs', recipe,
    recipeProvider: { path: PROVIDER, ...provider }, context };
  return freeze({ ...inputs, inputSha256: sha(JSON.stringify(inputs)), executionApproved: false,
    buildComplete: false, runtimeAvailable: false,
    pending: ['shared-original-base-apt-authentication', 'private-image-build', 'private-system-runtime-handoff'] });
}

async function captureSystemBuildInputs(root, recipe) { return capture(fs, root, recipe); }
async function verifySystemBuildInputs(root, plan) {
  if (!plan || plan.executionApproved !== false || plan.buildComplete !== false || plan.runtimeAvailable !== false)
    throw fail('SYSTEM_INPUTS_NOT_AUTHORITY');
  const current = await captureSystemBuildInputs(root, plan.recipe);
  if (!isDeepStrictEqual(plan, current)) throw fail('SYSTEM_INPUTS_CHANGED');
  return true;
}

module.exports = { captureSystemBuildInputs, verifySystemBuildInputs, validateRecipe,
  _internals: { ROOT, SOURCE, PROVIDER, PROVIDER_SHA, BASE, RECIPE_SHA, PACKAGES, ENTRYPOINT,
    CONTEXT_FILES, LIMITS, capture, captureContext, regular, sha } };
