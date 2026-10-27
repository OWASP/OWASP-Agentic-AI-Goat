'use strict';

// Target-specific producer only. Import does not acquire artifacts or launch
// anything. The shared lifecycle owns authentication, deadlines and retirement;
// this descriptor is source integrity evidence, never a live handoff.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { capturePricingPackage, PRICING_PACKAGE_FILES } = require('../../server/services/secureshopPricingPackage');
const closure = require('./ownedMcpDependencyClosure');
const TARGET = 'original-pricing';
const BASE = 'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
const DOCKERFILE = 'sidecars/sandbox-runner/owned-pricing-http/Dockerfile.local';
const DOCKERFILE_SHA256 = '0a68e3115ad0268bd6fbf8eed1871b2604f256be3b080694f48b45b97bc6f4a5';
const STAGES = Object.freeze([
  Object.freeze({ name: 'build', packages: Object.freeze(['gcc', 'libc6-dev', 'libseccomp-dev']) }),
  Object.freeze({ name: 'runtime', packages: Object.freeze(['bubblewrap', 'libseccomp2']) }),
]);
const ENTRYPOINT = Object.freeze(['node', 'sidecars/sandbox-runner/owned-pricing-http/http-listener.js']);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fail = code => Object.assign(new Error(code), { code });
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function capturePricingTarget(root) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root
    || fs.realpathSync(root) !== root) throw fail('PRICING_BUILD_ROOT');
  const before = capturePricingPackage(root);
  if (PRICING_PACKAGE_FILES.length !== 14 || before.files[DOCKERFILE] !== DOCKERFILE_SHA256) throw fail('PRICING_BUILD_SOURCE');
  const files = PRICING_PACKAGE_FILES.map(name => {
    const filename = path.join(root, name);
    if (fs.realpathSync(filename) !== filename) throw fail('PRICING_BUILD_SOURCE');
    const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const first = fs.fstatSync(fd);
      if (!first.isFile() || first.nlink !== 1 || first.size > 1024 ** 2) throw fail('PRICING_BUILD_SOURCE');
      const bytes = fs.readFileSync(fd), last = fs.fstatSync(fd);
      if (first.dev !== last.dev || first.ino !== last.ino || first.size !== last.size
        || first.mtimeMs !== last.mtimeMs || first.ctimeMs !== last.ctimeMs
        || bytes.length !== first.size || sha(bytes) !== before.files[name]) throw fail('PRICING_BUILD_SOURCE_CHANGED');
      return Object.freeze({ name, bytes });
    } finally { fs.closeSync(fd); }
  });
  if (!equal(capturePricingPackage(root), before)) throw fail('PRICING_BUILD_SOURCE_CHANGED');
  return Object.freeze({ version: 1, target: TARGET, platform: 'linux/arm64', baseImageDigest: BASE,
    packageDigest: before.sha256, dockerfile: DOCKERFILE, files: Object.freeze(files),
    fileSha256: before.files, aptStages: STAGES, npm: null, entrypoint: ENTRYPOINT, user: '10001:10001' });
}

function verifyPricingTarget(root, descriptor) {
  const expected = capturePricingTarget(root);
  if (!descriptor || !equal(Object.keys(descriptor).sort(), Object.keys(expected).sort())) throw fail('PRICING_BUILD_DESCRIPTOR');
  for (const key of Object.keys(expected)) {
    if (key === 'files') continue;
    if (!equal(descriptor[key], expected[key])) throw fail('PRICING_BUILD_DESCRIPTOR');
  }
  if (!Array.isArray(descriptor.files) || descriptor.files.length !== expected.files.length) throw fail('PRICING_BUILD_DESCRIPTOR');
  for (let index = 0; index < expected.files.length; index++) {
    const actual = descriptor.files[index], wanted = expected.files[index];
    if (!actual || !equal(Object.keys(actual).sort(), ['bytes', 'name']) || actual.name !== wanted.name
      || !Buffer.isBuffer(actual.bytes) || !actual.bytes.equals(wanted.bytes)) throw fail('PRICING_BUILD_DESCRIPTOR');
  }
  return true;
}

function pricingArtifactPlan({ stages, baseImageDigest = BASE } = {}) {
  if (baseImageDigest !== BASE || closure.BASE !== BASE
    || !equal(STAGES.map(row => row.packages), [closure.STAGES.build, closure.STAGES.runtime])) throw fail('PRICING_BUILD_BASE_OR_STAGES');
  // Reuse the existing exact APT selection/package join, URL rules, digest
  // validation and byte caps. No empty or substituted npm lock is constructed.
  const artifacts = closure._internals.debArtifacts(stages);
  closure._internals.validateArtifacts(artifacts);
  return { version: 1, target: TARGET, baseImageDigest: BASE, npm: null,
    artifacts, metadataAuthenticated: false, buildApproved: false, qualificationComplete: false };
}

function assertPricingArtifacts(plan) {
  if (!plan || plan.version !== 1 || plan.target !== TARGET || plan.baseImageDigest !== BASE || plan.npm !== null
    || plan.metadataAuthenticated !== false || plan.buildApproved !== false || plan.qualificationComplete !== false
    || !Array.isArray(plan.artifacts) || plan.artifacts.some(row => row.kind !== 'deb')) throw fail('PRICING_BUILD_ARTIFACT_PLAN');
  closure._internals.validateArtifacts(plan.artifacts);
}

async function acquirePricingArtifacts({ plan, ...options }) {
  assertPricingArtifacts(plan);
  // The shared routine returns byte integrity only. Authentication remains a
  // separate original APT replay against retained signed metadata/keyring.
  return closure.acquireArtifacts({ ...options, artifacts: plan.artifacts });
}

function pricingArtifactReader(directory, receipt) {
  if (!receipt || !Array.isArray(receipt.artifacts) || receipt.artifacts.some(row => row.kind !== 'deb')) throw fail('PRICING_BUILD_ARTIFACT_RECEIPT');
  return closure.artifactReader(directory, receipt);
}

module.exports = { TARGET, BASE, STAGES, DOCKERFILE, DOCKERFILE_SHA256,
  capturePricingTarget, verifyPricingTarget, pricingArtifactPlan, acquirePricingArtifacts, pricingArtifactReader };
