'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { performance } = require('node:perf_hooks');

const ROOT = path.resolve(__dirname, '../..');
const V25 = 'original-v25-pricing-manual-owner-grant-v1';
let admittedV25 = null;
const exact = (value, keys) => assert.deepEqual(Object.keys(value).sort(), keys.sort());
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function privateDirectory(name) {
  const stat = fs.lstatSync(name);
  assert(stat.isDirectory() && !stat.isSymbolicLink());
  assert.equal(stat.uid, process.getuid());
  assert.equal(stat.mode & 0o777, 0o700);
  assert.equal(fs.realpathSync(name), name);
  return stat;
}

function sameDirectory(name, expected) {
  const actual = privateDirectory(name);
  for (const key of ['dev', 'ino', 'uid']) assert.equal(actual[key], expected[key]);
  assert.equal(actual.mode & 0o777, expected.mode);
}

function readDescriptor(name, expectedSha256) {
  const before = fs.lstatSync(name);
  assert(before.isFile() && !before.isSymbolicLink() && before.nlink === 1);
  assert.equal(before.uid, process.getuid());
  assert.equal(before.mode & 0o777, 0o600);
  assert(before.size > 0 && before.size <= 4096);
  const fd = fs.openSync(name, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const held = fs.fstatSync(fd);
    assert.equal(held.dev, before.dev); assert.equal(held.ino, before.ino);
    const bytes = Buffer.alloc(before.size + 1);
    assert.equal(fs.readSync(fd, bytes, 0, bytes.length, 0), before.size);
    assert.equal(digest(bytes.subarray(0, before.size)), expectedSha256);
    const after = fs.fstatSync(fd), named = fs.lstatSync(name);
    for (const key of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']) {
      assert.equal(after[key], before[key]); assert.equal(named[key], before[key]);
    }
    return JSON.parse(bytes.subarray(0, before.size).toString('utf8'));
  } finally { fs.closeSync(fd); }
}

async function admitV25FromInheritedOwner() {
  assert.equal(admittedV25, null, 'V25 grant may be consumed only once');
  const env = process.env;
  for (const [key, value] of Object.entries({
    SECURESHOP_PRICING_V25_MANUAL_NATIVE: '1', PERSONA_PRICING_NATIVE: '1',
    PERSONA_PRICING_ACTUAL: '1', PERSONA_PRICING_MANUAL_ONLY: '1',
    PERSONA_PRICING_ACTUAL_REMAINING: '0', PERSONA_PRICING_CANONICAL: '1',
    PERSONA_PRICING_COHORT: 'baseline', PG_TEST_DISPOSABLE: 'yes',
    OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE: ROOT
  })) assert.equal(env[key], value);
  assert.equal(process.cwd(), ROOT);
  const readyText = env.SECURESHOP_PRICING_V25_READY_FD;
  assert.match(readyText || '', /^[1-9]\d*$/);
  const ready = Number(readyText);
  assert(Number.isSafeInteger(ready) && ready > 2);
  const readyStat = fs.fstatSync(ready);
  assert(readyStat.isFIFO()); assert.equal(readyStat.uid, process.getuid());
  const origin = performance.now();
  try { assert.equal(fs.writeSync(ready, Buffer.from('R')), 1); }
  finally { fs.closeSync(ready); delete env.SECURESHOP_PRICING_V25_READY_FD; }
  const grant = await require('./inheritedFifoGrant').readInheritedFifoGrant(
    env, 'SECURESHOP_PRICING_V25_ADMISSION_FD', 'Pricing V25');
  assert(grant && typeof grant === 'object' && !Array.isArray(grant));
  exact(grant, ['version', 'target', 'runId', 'ownerId', 'launcherPid', 'workerPid',
    'workspace', 'ownerPlanSha256', 'snapshotSha256', 'directory', 'descriptorPath',
    'descriptorSha256', 'outputRoot', 'outputIdentity', 'remainingMs', 'executorIdentity']);
  assert.equal(grant.version, 1); assert.equal(grant.target, V25);
  assert.match(grant.runId, /^[a-f0-9]{32}$/);
  assert.match(grant.ownerId, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.equal(grant.launcherPid, process.ppid); assert.equal(grant.workerPid, process.pid);
  assert.equal(grant.workspace, ROOT);
  for (const key of ['ownerPlanSha256', 'snapshotSha256', 'descriptorSha256'])
    assert.match(grant[key], /^[a-f0-9]{64}$/);
  assert(Number.isSafeInteger(grant.remainingMs) && grant.remainingMs > 0 && grant.remainingMs <= 840000);
  assert(Buffer.byteLength(JSON.stringify(grant)) <= 4096);
  const run = path.join(ROOT, 'tasks/qualification', 'pricing-private-' + grant.runId);
  const directory = path.join(run, 'cohort'), outputRoot = path.join(directory, 'output');
  assert.equal(grant.directory, directory); assert.equal(grant.descriptorPath, path.join(directory, 'private-executor.json'));
  assert.equal(grant.outputRoot, outputRoot); assert.equal(env.OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT, outputRoot);
  privateDirectory(run); privateDirectory(directory);
  exact(grant.outputIdentity, ['dev', 'ino', 'uid', 'mode']);
  for (const key of ['dev', 'ino', 'uid', 'mode']) assert(Number.isSafeInteger(grant.outputIdentity[key]));
  assert.equal(grant.outputIdentity.mode, 0o700);
  sameDirectory(outputRoot, grant.outputIdentity);
  const descriptor = readDescriptor(grant.descriptorPath, grant.descriptorSha256);
  const identity = grant.executorIdentity;
  assert(identity && typeof identity === 'object' && !Array.isArray(identity));
  exact(identity, ['ownerId', 'workspaceId', 'qualificationNonce', 'containerId',
    'imageId', 'packageSha256', 'profile', 'origin']);
  assert.equal(identity.ownerId, grant.ownerId);
  require('../postgres/secureshopCustomerPricingActual.integration.test').validatePricingDescriptor(descriptor, identity);
  const deadline = origin + grant.remainingMs;
  assert(performance.now() < deadline);
  const publicAdmission = Object.freeze({ descriptorPath: grant.descriptorPath,
    descriptorSha256: grant.descriptorSha256, expected: Object.freeze({ ...identity }),
    startedAt: origin, deadline });
  admittedV25 = Object.freeze({ outputRoot, outputIdentity: Object.freeze({ ...grant.outputIdentity }),
    descriptorPath: grant.descriptorPath, descriptorSha256: grant.descriptorSha256,
    publicAdmission });
  return publicAdmission;
}

function v25Admission() {
  assert(admittedV25, 'V25 inherited owner admission required');
  sameDirectory(admittedV25.outputRoot, admittedV25.outputIdentity);
  require('../postgres/secureshopCustomerPricingActual.integration.test').validatePricingDescriptor(
    readDescriptor(admittedV25.descriptorPath, admittedV25.descriptorSha256), admittedV25.publicAdmission.expected);
  return admittedV25.publicAdmission;
}

function isV25Admission(value) { return admittedV25 !== null && value === admittedV25.publicAdmission; }

function pricingOwnedOutputRoot() {
  const configured = process.env.OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT;
  if (process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE === '1') {
    assert(admittedV25, 'V25 inherited owner admission required');
    assert.equal(configured, admittedV25.outputRoot);
    sameDirectory(configured, admittedV25.outputIdentity);
    require('../postgres/secureshopCustomerPricingActual.integration.test').validatePricingDescriptor(
      readDescriptor(admittedV25.descriptorPath, admittedV25.descriptorSha256), admittedV25.publicAdmission.expected);
    return configured;
  }
  if (!configured) return process.cwd(); // Retained isolated-copy cohorts.
  if (!path.isAbsolute(configured) || fs.realpathSync(configured) !== configured) {
    throw Error('Pricing output root must be an exact absolute directory');
  }
  const stat = fs.lstatSync(configured);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
    throw Error('Pricing output root ownership or permissions mismatch');
  }
  const source = fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE || process.cwd());
  if (configured === source || configured.startsWith(source + path.sep)) {
    throw Error('Pricing output root must be outside source');
  }
  return configured;
}

module.exports = { pricingOwnedOutputRoot, admitV25FromInheritedOwner, v25Admission, isV25Admission };
