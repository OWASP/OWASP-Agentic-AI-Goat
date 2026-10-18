'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const ROUTE = '/api/secureshop/admin/system/restart';
const RECOVERY = '/api/secureshop/admin/system/restart-operations/';

// The owning full-index fixture supplies an authenticated opaque-frame admin,
// navigation after parent reload, and a read-only canonical repository probe.
// This helper never seeds effects, mocks a provider, or repeats the mutation.
async function qualifySystemRestartBrowser({ page, frame, origin, evidenceDirectory, reopenSystem, readOperation }) {
  assert.equal(typeof reopenSystem, 'function');
  assert.equal(typeof readOperation, 'function');
  const posts = [], gets = [];
  const observe = request => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    if (url.pathname === ROUTE && request.method() === 'POST') posts.push(JSON.parse(request.postData()));
    if (url.pathname.startsWith(RECOVERY) && request.method() === 'GET') gets.push(url.pathname);
  };
  page.on('request', observe);
  const cdp = await page.createCDPSession();
  let committed, fault, intercepted = false;
  let resolveLost;
  const lost = new Promise(resolve => { resolveLost = resolve; });
  const paused = async event => {
    let ownsResponse = false;
    try {
      const url = new URL(event.request.url);
      if (intercepted || url.origin !== origin || url.pathname !== ROUTE || event.request.method !== 'POST') {
        await cdp.send('Fetch.continueRequest', { requestId: event.requestId }); return;
      }
      intercepted = true;
      ownsResponse = true;
      assert.equal(event.responseStatusCode, 200);
      const wire = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
      committed = JSON.parse(wire.base64Encoded ? Buffer.from(wire.body, 'base64').toString('utf8') : wire.body);
      assert.equal(committed.ok, true); assert.equal(committed.state, 'completed');
      assert.equal(Object.hasOwn(committed, 'workerToken'), false);
      assert.equal(committed.receipt.afterGeneration, committed.receipt.beforeGeneration + 1);
      assert.notEqual(committed.receipt.beforeInstanceId, committed.receipt.afterInstanceId);
      const durable = await readOperation(committed.operationId);
      assert.equal(durable.state, 'completed');
      assert.deepEqual(durable.receipt, committed.receipt);
      // Drop only the response after observing committed canonical state.
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'ConnectionReset' });
    } catch (error) {
      fault = error;
      await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    } finally { if (ownsResponse) resolveLost(); }
  };
  cdp.on('Fetch.requestPaused', paused);
  let deadline;
  try {
    await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `${origin}${ROUTE}`, requestStage: 'Response' }] });
    await frame.waitForFunction(() => {
      const panel = document.querySelector('[data-testid="system-restart-panel"]');
      return panel && !panel.querySelector('button[type="submit"]').disabled;
    });
    await frame.click('[data-testid="system-restart-panel"] button[type="submit"]');
    await Promise.race([lost, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Restart response was not observed')), 45000); })]);
    clearTimeout(deadline);
    if (fault) throw fault;
    assert.equal(posts.length, 1);
    assert.equal(posts[0].operationId, committed.operationId);
    await frame.waitForFunction(id => document.querySelector('[data-testid="system-restart-panel"]')?.textContent.includes(id), {}, committed.operationId);
    const findReference = id => {
      for (const key of Object.keys(localStorage)) {
        if (!key.startsWith('dvaia:secureshop:')) continue;
        const snapshot = JSON.parse(localStorage.getItem(key));
        const raw = snapshot.ss_system_restart_recovery;
        if (!raw) continue;
        const reference = JSON.parse(raw).references.find(row => row.operationId === id);
        if (reference) return { key, reference };
      }
      return null;
    };
    const saved = await page.evaluate(findReference, committed.operationId);
    assert.ok(saved);
    assert.deepEqual(Object.keys(saved.reference).sort(), ['operationId', 'scopeKey', 'state']);
    await cdp.send('Fetch.disable');
    await page.reload({ waitUntil: 'domcontentloaded' });
    frame = await reopenSystem();
    await frame.waitForFunction(() => [...document.querySelectorAll('[data-testid="system-restart-panel"] button')]
      .some(button => button.textContent === 'check restart outcome' && !button.disabled));
    await frame.evaluate(() => [...document.querySelectorAll('[data-testid="system-restart-panel"] button')]
      .find(button => button.textContent === 'check restart outcome' && !button.disabled).click());
    await frame.waitForFunction(() => document.querySelector('[data-testid="system-restart-panel"]')?.textContent.includes('Receipt verified.'));
    assert.equal(posts.length, 1);
    assert.ok(gets.some(url => url === RECOVERY + committed.operationId));
    assert.equal(await page.evaluate(findReference, committed.operationId), null);
    assert.deepEqual((await readOperation(committed.operationId)).receipt, committed.receipt);
    await frame.evaluate(() => document.querySelector('[data-testid="system-restart-panel"]').scrollIntoView({ block: 'center' }));
    await frame.waitForFunction(() => document.getAnimations({ subtree: true }).every(animation => ['finished', 'idle'].includes(animation.playState)));
    // Page screenshot avoids known opaque-iframe element clipping errors.
    await page.screenshot({ path: path.join(evidenceDirectory, 'system-restart-recovered.png') });
    const result = { operationId: committed.operationId, targetId: committed.targetId, receipt: committed.receipt,
      responseLossAfterDurableCommit: true, parentReloadRecoveredByGet: true, postCount: posts.length,
      opaqueReferenceRemoved: true, internalWorkerTokenAbsent: true };
    await fs.writeFile(path.join(evidenceDirectory, 'system-restart-browser-result.json'), JSON.stringify(result, null, 2), { mode: 0o600 });
    return result;
  } finally {
    clearTimeout(deadline);
    page.off('request', observe);
    cdp.off('Fetch.requestPaused', paused);
    await cdp.send('Fetch.disable').catch(() => {});
    await cdp.detach().catch(() => {});
  }
}

module.exports = { qualifySystemRestartBrowser };
