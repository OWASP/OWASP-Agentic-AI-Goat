'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { qualifyEnabledAclBrowser } = require('./fixtures/secureshopEnabledAclBrowser');
function controlledBrowser({ corruptReceipt = false } = {}) {
  const origin = 'http://owned.invalid';
  const waits = [];
  let version = 1, allowed = true, enforcement = false, receipt;
  const operations = new Map();
  const policy = () => ({ administration: { versionedPolicy: true },
    version: String(version), registrySha256: 'a'.repeat(64), enforcement_enabled: enforcement,
    tools: [{ tool_name: 'audit.search_by_user', admin: allowed },
      { tool_name: 'unsupported', admin: false, readOnly: true }] });
  const emit = (suffix, method, body) => {
    const response = { url: () => origin + '/api/secureshop/admin/access-control' + suffix,
      request: () => ({ method: () => method }), status: () => 200, json: async () => body };
    const index = waits.findIndex(row => row.predicate(response));
    assert.notEqual(index, -1, 'fixture observes the intended policy/mutation response');
    waits.splice(index, 1)[0].resolve(response);
  };
  const page = { waitForResponse: predicate => new Promise(resolve => waits.push({ predicate, resolve })) };
  const frame = {
    waitForSelector: async () => {}, waitForFunction: async () => {}, $eval: async () => true,
    click: async selector => {
      if (selector.startsWith('a[')) { emit('', 'GET', policy()); return; }
      const permission = selector.includes('acl-cell-');
      if (permission) allowed = !allowed; else enforcement = !enforcement;
      version += 1;
      receipt = { operationId: `owned-operation-${version}`, version: String(version),
        registrySha256: 'a'.repeat(64) };
      operations.set(receipt.operationId, receipt);
      emit(permission ? '/permission' : '/enforcement', 'POST', {
        receipt, tool_name: 'audit.search_by_user', role: 'admin', allowed,
        enforcement_enabled: enforcement });
      emit('', 'GET', policy());
    },
    evaluate: async (read, operationId) => {
      // Execute the fixture's actual read callback with a controlled transport.
      const previous = globalThis.fetch;
      globalThis.fetch = async url => {
        assert.equal(url, '/api/secureshop/admin/access-control/operations/' + encodeURIComponent(operationId));
        const stored = operations.get(operationId);
        assert.ok(stored);
        return { status: 200, json: async () => ({ ok: true,
          receipt: corruptReceipt ? { ...stored, operationId: 'another-operation' } : stored }) };
      };
      try { return await read(operationId); } finally { globalThis.fetch = previous; }
    },
  };
  return { page, frame, origin };
}
test('ACL fixture checks durable receipts while retaining refreshed policy checks', async () => {
  const result = await qualifyEnabledAclBrowser(controlledBrowser());
  assert.equal(result.exactReceiptReadbacks, 4);
  assert.equal(result.acknowledgedReceiptsAndPolicyRefreshes, 4);
  assert.equal(result.defaultsRestored, true);
});
test('ACL fixture rejects another operation receipt despite matching refreshed policy', async () => {
  await assert.rejects(qualifyEnabledAclBrowser(controlledBrowser({ corruptReceipt: true })),
    { code: 'ERR_ASSERTION' });
});
