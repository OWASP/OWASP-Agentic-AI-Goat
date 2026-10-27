'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const producer = require('./postgres/ownedPricingOriginalBuild');
const { capturePricingPackage } = require('../server/services/secureshopPricingPackage');
const root = path.resolve(__dirname, '..');
const bytes = Buffer.from('controlled Debian artifact bytes, not an installable package');
const digest = crypto.createHash('sha256').update(bytes).digest('hex');
function stages() {
  return producer.STAGES.map(stage => ({ ...stage, packages: [...stage.packages],
    selection: `'http://deb.debian.org/debian/pool/main/f/fixture/fixture_1_arm64.deb' fixture.deb ${bytes.length} SHA256:${digest}\n`,
    selected: [{ name: 'fixture', version: '1', architecture: 'arm64', bytes: bytes.length,
      sha256: digest, filename: 'pool/main/f/fixture/fixture_1_arm64.deb' }] }));
}
test('producer captures exact original fourteen files and unchanged two-stage Dockerfile', () => {
  const target = producer.capturePricingTarget(root), original = capturePricingPackage(root);
  assert.equal(target.target, 'original-pricing'); assert.equal(target.files.length, 14);
  assert.equal(target.packageDigest, original.sha256); assert.deepEqual(target.fileSha256, original.files);
  assert.equal(target.npm, null); assert.equal(target.user, '10001:10001');
  assert.equal(producer.verifyPricingTarget(root, target), true);
  const dockerfile = target.files.find(row => row.name === target.dockerfile).bytes.toString();
  assert.equal(dockerfile.split(`FROM node:26.10.0-slim@${producer.BASE}`).length - 1, 2);
  assert.match(dockerfile, /install -y --no-install-recommends gcc libc6-dev libseccomp-dev/);
  assert.match(dockerfile, /install -y --no-install-recommends bubblewrap libseccomp2/);
  assert.doesNotMatch(dockerfile, /npm (?:ci|install)/);
});
test('descriptor cannot substitute source, target, base, npm, stages, entrypoint or omit files', () => {
  const original = producer.capturePricingTarget(root);
  for (const change of [value => { value.target = 'original-v23-registry'; },
    value => { value.baseImageDigest = 'sha256:' + 'a'.repeat(64); }, value => { value.npm = {}; },
    value => { value.aptStages = []; }, value => { value.entrypoint = ['sh']; },
    value => { value.files = value.files.slice(1); }, value => { value.extra = true; },
    value => { value.files = value.files.map(row => ({ ...row, bytes: Buffer.from(row.bytes) })); value.files[0].bytes[0] ^= 1; }]) {
    const value = { ...original }; change(value);
    assert.throws(() => producer.verifyPricingTarget(root, value), { code: 'PRICING_BUILD_DESCRIPTOR' });
  }
});
test('pricing reuses exact shared APT joins without npm or metadata authentication claims', () => {
  const plan = producer.pricingArtifactPlan({ stages: stages() });
  assert.equal(plan.artifacts.length, 1); assert.equal(plan.artifacts[0].kind, 'deb');
  assert.deepEqual(plan.artifacts[0].stages, ['build', 'runtime']);
  assert.equal(plan.npm, null); assert.equal(plan.metadataAuthenticated, false);
  assert.equal(plan.buildApproved, false); assert.equal(plan.qualificationComplete, false);
  for (const change of [value => { value[0].packages.push('curl'); },
    value => { value.reverse(); }, value => { value[0].selected[0].sha256 = 'bad'; },
    value => { value[0].selected[0].bytes++; }, value => { value[0].selected[0].architecture = 'amd64'; },
    value => { value[0].selection = value[0].selection.replace('deb.debian.org', 'untrusted.example'); }]) {
    const value = stages(); change(value);
    assert.throws(() => producer.pricingArtifactPlan({ stages: value }));
  }
});
test('invalid or promoted plans reject before acquisition effects', async () => {
  let calls = 0;
  for (const change of [value => { value.target = 'original-v23-registry'; },
    value => { value.metadataAuthenticated = true; }, value => { value.npm = {}; },
    value => { value.artifacts[0].kind = 'npm'; }]) {
    const plan = producer.pricingArtifactPlan({ stages: stages() }); change(plan);
    await assert.rejects(producer.acquirePricingArtifacts({ plan, directory: '/not-an-admitted-output',
      request: () => { calls++; throw Error('must not request'); } }), { code: 'PRICING_BUILD_ARTIFACT_PLAN' });
  }
  assert.equal(calls, 0);
});
test('shared bounded acquisition and exact artifact reader work for Debian-only pricing closure', async t => {
  assert.ok(path.resolve(os.tmpdir()).startsWith(path.join(root, 'tasks') + path.sep));
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'pricing-closure-'));
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const directory = path.join(parent, 'artifacts'); let calls = 0;
  const plan = producer.pricingArtifactPlan({ stages: stages() });
  const receipt = await producer.acquirePricingArtifacts({ plan, directory,
    request: async url => { calls++; assert.equal(url, plan.artifacts[0].urls[0]);
      return { status: 200, headers: {}, body: Readable.from([bytes]), closed: Promise.resolve(), destroy() {} }; } });
  assert.equal(calls, 1); assert.equal(receipt.bytes.npm, 0); assert.equal(receipt.bytes.deb, bytes.length);
  assert.equal(receipt.metadataAuthenticated, false); assert.equal(receipt.buildApproved, false);
  const read = producer.pricingArtifactReader(directory, receipt);
  const result = await read(plan.artifacts[0].urls[0]); const chunks = [];
  for await (const chunk of result.stream) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), bytes);
  await assert.rejects(read('https://registry.npmjs.org/substitute/-/substitute-1.tgz'), { code: 'CLOSURE_UNLISTED_URL' });
  const foreign = structuredClone(receipt); foreign.artifacts[0].kind = 'npm';
  assert.throws(() => producer.pricingArtifactReader(directory, foreign), { code: 'PRICING_BUILD_ARTIFACT_RECEIPT' });
});
