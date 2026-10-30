'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadSecureShopReviewCardRenderer }
  = require('../server/services/secureshopReviewCardRenderer');

function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function fixture(t, artifact) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-review-renderer-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'renderer.cjs'), artifact);
  fs.writeFileSync(path.join(root, 'manifest.json'), `${JSON.stringify({
    version: 1, component: 'SecureShop.ReviewCard',
    source: 'client/src/pages/secureshop/components/ReviewCard.jsx',
    sourceSha256: 'a'.repeat(64), artifact: 'renderer.cjs',
    artifactSha256: digest(artifact),
  })}\n`);
  return root;
}

test('renderer verifies the artifact and terminates its isolated worker', async t => {
  const artifact = Buffer.from(`const {parentPort,workerData}=require('node:worker_threads');
    parentPort.postMessage({ok:Object.keys(workerData).join(',')==='review',markup:'<article>'+workerData.review.body+'</article>'});`);
  const root = fixture(t, artifact);
  const renderer = loadSecureShopReviewCardRenderer({ root });
  fs.writeFileSync(path.join(root, 'renderer.cjs'),
    `throw new Error('changed artifact must not execute');`);
  assert.equal(await renderer.renderReviewCard({ body: 'owned' }), '<article>owned</article>');
  assert.equal(renderer.sourceSha256, 'a'.repeat(64));
  assert.equal(renderer.artifactSha256, digest(artifact));
});

test('renderer rejects changed artifacts and aborts an admitted worker', async t => {
  const artifact = Buffer.from(`const {parentPort}=require('node:worker_threads'); setInterval(()=>{},1000);
    parentPort.on('message',()=>{});`);
  const root = fixture(t, artifact);
  const renderer = loadSecureShopReviewCardRenderer({ root, timeoutMs: 5000 });
  const controller = new AbortController();
  const pending = renderer.renderReviewCard({ body: 'owned' }, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, error => error?.name === 'AbortError');

  fs.appendFileSync(path.join(root, 'renderer.cjs'), '\n// changed');
  assert.throws(() => loadSecureShopReviewCardRenderer({ root }), {
    code: 'SECURESHOP_REVIEW_RENDERER_UNAVAILABLE',
  });
});

test('default renderer composition honors an explicit absolute staged root and rejects relative roots', async t => {
  const artifact = Buffer.from(`const {parentPort,workerData}=require('node:worker_threads');
    parentPort.postMessage({ok:true,markup:'<article>'+workerData.review.body+'</article>'});`);
  const root = fixture(t, artifact);
  const prior = process.env.SECURESHOP_REVIEW_RENDERER_ROOT;
  t.after(() => {
    if (prior === undefined) delete process.env.SECURESHOP_REVIEW_RENDERER_ROOT;
    else process.env.SECURESHOP_REVIEW_RENDERER_ROOT = prior;
  });
  process.env.SECURESHOP_REVIEW_RENDERER_ROOT = root;
  assert.equal((await loadSecureShopReviewCardRenderer().renderReviewCard({ body: 'staged' })), '<article>staged</article>');
  process.env.SECURESHOP_REVIEW_RENDERER_ROOT = 'relative/staged-root';
  assert.throws(() => loadSecureShopReviewCardRenderer(), { code: 'SECURESHOP_REVIEW_RENDERER_UNAVAILABLE' });
});
