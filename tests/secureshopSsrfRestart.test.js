'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID: uuid } = require('node:crypto');
const { createSecureShopSsrfOwnedTarget } = require('../server/services/secureshopSsrfOwnedTarget');
const { createSecureShopSsrfTargetPool } = require('../server/services/secureshopSsrfTargetPool');

test('disconnect preserves exact fixtures; restart accepts a new request and reset removes them', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-restart-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const targetId = uuid(), first = await createSecureShopSsrfOwnedTarget({ root, targetId });
  t.after(() => first.disconnect());
  const issued = first.issue({ requestId: uuid(), resourceKind: 'private-policy' });
  const bytes = await (await fetch(issued.url)).text();
  await Promise.all([first.disconnect(), first.disconnect()]);
  assert.throws(() => first.issue({ requestId: uuid(), resourceKind: 'public-policy' }));
  assert.equal(await fs.readFile(path.join(root, targetId, 'private-policy.json'), 'utf8'), bytes);
  await assert.rejects(fetch(issued.url));
  const recovered = await createSecureShopSsrfOwnedTarget({ root, targetId });
  t.after(() => recovered.disconnect());
  assert.throws(() => recovered.readReceipt({ nonce: issued.nonce, requestId: issued.requestId }),
    'an old in-flight receipt is never invented after restart');
  const next = recovered.issue({ requestId: uuid(), resourceKind: 'private-policy' });
  assert.equal(await (await fetch(next.url)).text(), bytes);
  assert.equal(recovered.consume(next).status, 200);
  await recovered.cleanup();
  await assert.rejects(fs.stat(path.join(root, targetId)), { code: 'ENOENT' });
});

test('recovery rejects changed or linked files without overwriting or deleting them', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-recovery-negative-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const targetId = uuid(), target = await createSecureShopSsrfOwnedTarget({ root, targetId });
  await target.disconnect();
  const file = path.join(root, targetId, 'private-policy.json');
  await fs.writeFile(file, 'changed training record');
  await assert.rejects(createSecureShopSsrfOwnedTarget({ root, targetId }), { code: 'BOUND_SSRF_UNAVAILABLE' });
  assert.equal(await fs.readFile(file, 'utf8'), 'changed training record');
  await fs.unlink(file);
  await fs.symlink(path.join(root, targetId, 'public-policy.json'), file);
  await assert.rejects(createSecureShopSsrfOwnedTarget({ root, targetId }), { code: 'BOUND_SSRF_UNAVAILABLE' });
  assert.equal((await fs.lstat(file)).isSymbolicLink(), true);
});

test('pool shutdown waits for admitted creation, prohibits its issuance and disconnects without cleanup', async () => {
  let release, entered, disconnected = 0, issued = 0, cleaned = 0;
  const started = new Promise(resolve => { entered = resolve; });
  const held = new Promise(resolve => { release = resolve; });
  const pool = createSecureShopSsrfTargetPool({ root: '/owned-fixture', async createTarget() {
    entered(); await held; return {
      issue() { issued++; }, async disconnect() { disconnected++; }, async cleanup() { cleaned++; },
    };
  } });
  const scope = { targetId: uuid(), launchId: uuid(), scenarioId: 'ssrf', generation: 1,
    platformOwnerId: 1, platformSessionId: uuid() };
  const pending = assert.rejects(pool.issue(scope, {}), /pool closed/);
  await started;
  const closing = pool.close();
  assert.equal(pool.close(), closing);
  release();
  await Promise.all([closing, pending]);
  assert.deepEqual({ disconnected, issued, cleaned }, { disconnected: 1, issued: 0, cleaned: 0 });
  await assert.rejects(pool.issue(scope, {}), /pool closed/);
});
