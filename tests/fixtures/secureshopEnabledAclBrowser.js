'use strict';
const assert = require('node:assert/strict');
async function qualifyEnabledAclBrowser({ page, frame, origin }) {
  const response = (suffix, method) => page.waitForResponse(r =>
    r.url() === origin + '/api/secureshop/admin/access-control' + suffix
    && r.request().method() === method, { timeout: 15000 });
  const loaded = response('', 'GET');
  await frame.click('a[href="/secureshop/admin/access-control"]');
  const initial = await loaded;
  assert.equal(initial.status(), 200);
  const policy = await initial.json();
  assert.equal(policy.administration.versionedPolicy, true);
  const toggle = async (selector, suffix) => {
    await frame.waitForSelector(selector);
    const changed = response(suffix, 'POST');
    const observed = response('', 'GET');
    await frame.click(selector);
    const result = await changed; assert.equal(result.status(), 200);
    const body = await result.json();
    // Successful writes refresh policy directly. Exercise durable readback
    // explicitly; the UI fetches this endpoint only for an unknown outcome.
    assert.equal(typeof body.receipt?.operationId, 'string');
    const durable = await frame.evaluate(async operationId => {
      const read = await globalThis.fetch('/api/secureshop/admin/access-control/operations/'
        + encodeURIComponent(operationId));
      return { status: read.status, body: await read.json() };
    }, body.receipt.operationId);
    assert.equal(durable.status, 200);
    assert.equal(durable.body.ok, true);
    assert.deepEqual(durable.body.receipt, body.receipt);
    const refreshed = await observed; assert.equal(refreshed.status(), 200);
    const current = await refreshed.json();
    assert.equal(current.version, body.receipt.version);
    assert.equal(current.registrySha256, body.receipt.registrySha256);
    if (suffix === '/permission') assert.equal(current.tools.find(row => row.tool_name === body.tool_name)[body.role], body.allowed);
    else assert.equal(current.enforcement_enabled, body.enforcement_enabled);
    await frame.waitForFunction(s => {
      const node = document.querySelector(s);
      return node && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
    }, {}, selector);
    return body;
  };
  const cell = '[data-testid="acl-cell-audit.search_by_user-admin"]';
  const denied = await toggle(cell, '/permission'); assert.equal(denied.allowed, false);
  const enforcement = '[data-testid="acl-enforcement-toggle"]';
  assert.equal((await toggle(enforcement, '/enforcement')).enforcement_enabled, true);
  assert.equal((await toggle(enforcement, '/enforcement')).enforcement_enabled, false);
  assert.equal((await toggle(cell, '/permission')).allowed, true);
  const unsupported = policy.tools.find(row => row.readOnly);
  assert.ok(unsupported);
  assert.equal(await frame.$eval(`[data-testid="acl-cell-${unsupported.tool_name}-admin"]`, node => node.disabled), true);
  return { policyMutations: 4, exactReceiptReadbacks: 4, acknowledgedReceiptsAndPolicyRefreshes: 4, unsupportedDisabled: true, defaultsRestored: true };
}
module.exports = { qualifyEnabledAclBrowser };
