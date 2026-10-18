'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { NODE_IMAGE, NODE_DIGEST, TRACKED, effectMarkdown, validateV2Pair, verifyPackageSource }
  = require('../scripts/qualify-secureshop-policy-renderer-package-native');
const { ISOLATION, COMPILER_SHA256, WORKER_SHA256, requestDigest, renderExecutionDigest,
  createLiteralRenderResult } = require('../server/services/secureshopPromptPolicyContract');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function pair() {
  const request = { operationId: '31ec985d-b3ba-4742-83c8-664200654356', name: 'packaged',
    markdown: effectMarkdown, targets: ['admin'] };
  const vulnerable = { status: 200, body: {
    version: 2, kind: 'isolated_template', operationId: request.operationId,
    requestSha256: requestDigest(request),
    executionSha256: renderExecutionDigest({ version: 2, mode: 'vuln', request }),
    rendered: 'packaged-v2-canary', renderedSha256: sha('packaged-v2-canary'),
    isolation: ISOLATION, exitCode: 0, timedOut: false, truncated: false, drained: true,
    effectWitness: { version: 1, workerAttested: true, commandEffectObserved: true,
      effectSha256: sha('owned synthetic canary'), compilerSha256: COMPILER_SHA256,
      workerSha256: WORKER_SHA256 },
  } };
  return { request, vulnerable, fixed: { status: 200, body: createLiteralRenderResult(request) } };
}

test('package v2 receipt pins genuine isolated effect witness and fixed literal result', () => {
  const value = pair();
  const checked = validateV2Pair(value);
  assert.equal(checked.isolated.effectWitness.commandEffectObserved, true);
  assert.equal(checked.literal.rendered, effectMarkdown);
  assert.notEqual(checked.isolated.executionSha256, checked.literal.executionSha256);
  assert.equal(checked.isolated.requestSha256, checked.literal.requestSha256);
  assert.match(effectMarkdown, /\/owned-source\/effect-canary/);
  assert.match(effectMarkdown, /\/owned-effect\/command-effect/);
});

test('package v2 cannot accept a string-only claim or invented fixed sandbox witness', () => {
  const absent = pair(); absent.vulnerable.body.effectWitness.commandEffectObserved = false;
  absent.vulnerable.body.effectWitness.effectSha256 = null;
  assert.throws(() => validateV2Pair(absent), /effect or fixed literal proof/);
  const altered = pair(); altered.fixed.body = { ...altered.fixed.body, effectWitness: altered.vulnerable.body.effectWitness };
  assert.throws(() => validateV2Pair(altered), /unexpected fields/);
  const substitute = pair(); substitute.request.markdown = 'different';
  assert.throws(() => validateV2Pair(substitute), /canary source mismatch/);
});

test('nonallocating plan covers copied Docker inputs and exact pinned local base', () => {
  verifyPackageSource();
  assert.equal(NODE_IMAGE, `docker.io/library/node:26.10.0-slim@${NODE_DIGEST}`);
  for (const name of ['sidecars/sandbox-runner/owned-http/worker.js',
    'sidecars/sandbox-runner/owned-http/network-manifest.json',
    'sidecars/sandbox-runner/protected-operations/operationStore.js',
    'sidecars/sandbox-runner/labfs/etc/hosts.lab',
    'sidecars/sandbox-runner/policy-render/assets/nunjucks-3.2.4.js']) {
    assert.ok(TRACKED.includes(name), name);
  }
  const root = path.resolve(__dirname, '..');
  const plan = JSON.parse(execFileSync(process.execPath,
    ['scripts/qualify-secureshop-policy-renderer-package-native.js', '--plan'],
    { cwd: root, encoding: 'utf8', timeout: 10000 }));
  assert.equal(plan.nodeImage, NODE_IMAGE);
  assert.deepEqual(Object.keys(plan.tracked).sort(), [...TRACKED]);
});
