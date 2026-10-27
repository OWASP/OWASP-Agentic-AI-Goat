'use strict';

// Original renderer inputs only. No metadata authentication, build, managed
// record, image capability, or runtime admission is supplied by this module.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { targetSpecification } = require('./ownedPolicySystemBuild');
const ROOT = path.resolve(__dirname, '../..');
const SOURCE = 'sidecars/sandbox-runner/policy-render';
const PROVIDER = 'scripts/install/secureshop-owned-policy-renderer.js';
const CONTRACT = 'server/services/secureshopPromptPolicyContract.js';
const PROVIDER_SHA = 'd89d8c52b4c558e1fcaceb7ac5cde330808d84cd9881ea5e1fa8fa0177f52465';
const DOCKERFILE_SHA = '90286fe0d653f378430e2710acd6acbf575f3e57e078de6ee5ac165a897bdac0';
const BASE = 'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
const FILES = Object.freeze(['Dockerfile', 'Dockerfile.dockerignore', 'listener.js', 'executor.js',
  'http-handler.js', 'worker.js', 'process-supervisor.c', 'policy-init.c',
  'secureshopPromptPolicyContract.js', 'assets/nunjucks-3.2.4.js', 'assets/NUNJUCKS-LICENSE.txt']);
// Exact rule ordering from the pinned installer. Its path-based sourceManifest
// must not run here: all inputs, including ignore and canonical contract, go
// through the same bounded nofollow capture before these pure rules run.
const BUILD_CONTEXT_RULES = Object.freeze(['**', '!policy-render/', 'policy-render/**',
  ...FILES.filter(name => !name.startsWith('assets/')).map(name => '!policy-render/' + name),
  '!policy-render/assets/', 'policy-render/assets/**',
  ...FILES.filter(name => name.startsWith('assets/')).map(name => '!policy-render/' + name)]);
const LIMITS = Object.freeze({ fileBytes: 1024 ** 2, contextBytes: 11 * 1024 ** 2, files: 11 });
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fail = code => Object.assign(new Error(code), { code });
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function sameStat(a, b) {
  return ['dev', 'ino', 'size', 'mode', 'nlink', 'mtimeMs', 'ctimeMs'].every(k => a[k] === b[k]);
}
async function readOriginal(io, filename) {
  if (await io.realpath(filename) !== filename) throw fail('RENDERER_SOURCE_PATH');
  const before = await io.lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
    || ![0o444, 0o555, 0o644, 0o755].includes(before.mode & 0o7777)
    || !Number.isSafeInteger(before.size) || before.size < 1 || before.size > LIMITS.fileBytes)
    throw fail('RENDERER_SOURCE_FILE');
  const handle = await io.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (!sameStat(before, await handle.stat())) throw fail('RENDERER_SOURCE_CHANGED');
    const data = Buffer.alloc(before.size + 1); let offset = 0;
    while (offset < data.length) {
      const { bytesRead } = await handle.read(data, offset, data.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== before.size || !sameStat(before, await handle.stat())
      || !sameStat(before, await io.lstat(filename)) || await io.realpath(filename) !== filename)
      throw fail('RENDERER_SOURCE_CHANGED');
    const bytes = data.subarray(0, offset);
    // Strings keep the captured bytes immutable; no mutable Buffer authority.
    return Object.freeze({ bytes: offset, sha256: sha(bytes), mode: before.mode & 0o777, base64: bytes.toString('base64') });
  } finally { await handle.close(); }
}
function recipeFromDockerfile(dockerfile) {
  if (typeof dockerfile !== 'string' || sha(dockerfile) !== DOCKERFILE_SHA) throw fail('RENDERER_DOCKERFILE_CHANGED');
  const stages = [...dockerfile.matchAll(/^RUN apt-get update && apt-get install -y --no-install-recommends ([^\n]+) \\\n    && rm -rf \/var\/lib\/apt\/lists\/\*$/gm)]
    .map((match, i) => ({ name: i === 0 ? 'build' : 'runtime', packages: match[1].split(' '), command: match[0].slice(4) }));
  if (!isDeepStrictEqual(stages.map(s => s.packages), [['gcc', 'libc6-dev'], ['bubblewrap']])) throw fail('RENDERER_APT_STAGES_CHANGED');
  const spec = targetSpecification('v24-policy');
  if (spec.base !== BASE || spec.sourceRoot !== SOURCE + '/'
    || !isDeepStrictEqual(spec.entrypoint, ['/usr/local/bin/node', '/app/policy-render/listener.js'])
    || !isDeepStrictEqual(spec.packages, ['bubblewrap', 'gcc', 'libc6-dev'])
    || !isDeepStrictEqual(spec.installPackages, ['gcc', 'libc6-dev', 'bubblewrap'])) throw fail('RENDERER_TARGET_CHANGED');
  return freeze({ version: 1, target: 'v24-policy', base: BASE, platform: 'linux/arm64',
    contextRoot: 'sidecars/sandbox-runner', dockerfilePath: 'policy-render/Dockerfile',
    dockerfile, dockerfileSha256: DOCKERFILE_SHA, stages, user: '10001:10001', entrypoint: [...spec.entrypoint] });
}
function manifestFromCaptured(files, contract) {
  if (!isDeepStrictEqual(files.map(row => row.name), FILES.map(name => 'policy-render/' + name))) throw fail('RENDERER_MANIFEST_CHANGED');
  const ignore = Buffer.from(files[1].base64, 'base64').toString('utf8').split(/\r?\n/)
    .map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  if (!isDeepStrictEqual(ignore, BUILD_CONTEXT_RULES)) throw fail('POLICY_RENDER_BUILD_CONTEXT_INVALID');
  const hashes = {};
  for (let i = 0; i < FILES.length; i++) hashes[SOURCE + '/' + FILES[i]] = files[i].sha256;
  if (hashes[SOURCE + '/secureshopPromptPolicyContract.js'] !== contract.sha256) throw fail('POLICY_RENDER_CONTRACT_DRIFT');
  return freeze({ files: hashes, sha256: sha(JSON.stringify(hashes)) });
}
async function capture(io, root) {
  if (root !== ROOT) throw fail('RENDERER_REPOSITORY_ROOT');
  if (await io.realpath(root) !== root) throw fail('RENDERER_SOURCE_PATH');
  const provider = await readOriginal(io, path.join(root, PROVIDER));
  if (provider.sha256 !== PROVIDER_SHA) throw fail('RENDERER_PROVIDER_CHANGED');
  const files = []; let total = 0;
  for (const name of FILES) {
    const row = await readOriginal(io, path.join(root, SOURCE, name));
    total += row.bytes;
    if (total > LIMITS.contextBytes) throw fail('RENDERER_CONTEXT_LIMIT');
    files.push(Object.freeze({ name: 'policy-render/' + name, ...row }));
  }
  Object.freeze(files);
  const contract = await readOriginal(io, path.join(root, CONTRACT));
  const first = manifestFromCaptured(files, contract);
  const recipe = recipeFromDockerfile(Buffer.from(files[0].base64, 'base64').toString('utf8'));
  // Recapture all bytes underlying the installer-equivalent manifest. This is
  // bounded evidence, not a filesystem lock; a future build must verify again.
  for (let i = 0; i < FILES.length; i++) {
    const { name, ...row } = files[i];
    if (!isDeepStrictEqual(row, await readOriginal(io, path.join(root, SOURCE, FILES[i])))) throw fail('RENDERER_SOURCE_CHANGED');
  }
  if (!isDeepStrictEqual(contract, await readOriginal(io, path.join(root, CONTRACT)))) throw fail('RENDERER_SOURCE_CHANGED');
  if (!isDeepStrictEqual(provider, await readOriginal(io, path.join(root, PROVIDER)))) throw fail('RENDERER_PROVIDER_CHANGED');
  const inputs = { version: 1, kind: 'original-v24-policy-renderer-build-inputs', recipe,
    sourceManifest: first, provider: { path: PROVIDER, sha256: provider.sha256 },
    canonicalContract: { path: CONTRACT, ...contract },
    context: { root: recipe.contextRoot, files, bytes: total } };
  return freeze({ ...inputs, inputSha256: sha(JSON.stringify(inputs)), executionApproved: false,
    metadataAuthenticated: false, buildComplete: false, runtimeAvailable: false,
    pending: ['renderer-two-stage-authenticated-metadata', 'private-renderer-image-build', 'private-renderer-runtime-handoff'] });
}
async function capturePolicyRendererBuildInputs(root) { return capture(fs, root); }
async function verifyPolicyRendererBuildInputs(root, packet) {
  if (!packet || packet.executionApproved !== false || packet.metadataAuthenticated !== false
    || packet.buildComplete !== false || packet.runtimeAvailable !== false) throw fail('RENDERER_INPUTS_NOT_AUTHORITY');
  if (!isDeepStrictEqual(packet, await capturePolicyRendererBuildInputs(root))) throw fail('RENDERER_INPUTS_CHANGED');
  return true;
}
module.exports = { capturePolicyRendererBuildInputs, verifyPolicyRendererBuildInputs,
  _internals: { ROOT, SOURCE, PROVIDER, CONTRACT, PROVIDER_SHA, DOCKERFILE_SHA, BASE, FILES, LIMITS,
    capture, readOriginal, recipeFromDockerfile, manifestFromCaptured } };
