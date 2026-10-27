import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import BoundRoleAssistant from './BoundRoleAssistant.jsx';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

// Evaluate the actual guard without importing its native node:test registration.
const source = readFileSync(path.resolve(__dirname,
  '../../../../../tests/postgres/secureshopOwnedMcpRegistryRendered.native.js'), 'utf8');
const fixed = source.slice(source.indexOf('const V39_ATOMIC_BROWSER_FIXED ='), source.indexOf('const v39AdmissionWitnesses'));
const start = source.indexOf('function v39AtomicBrowserRequestAllowed(');
const end = source.indexOf('\nfunction ', start + 1);
const allowed = vm.runInNewContext(fixed + source.slice(start, end) + '\nv39AtomicBrowserRequestAllowed', { URL });
const expected = ['/api/secureshop/admin/access-control', '/api/secureshop/admin/mcp/servers',
  '/api/secureshop/admin/policies', '/api/secureshop/admin/system/diagnostic', '/api/secureshop/admin/system/restart'].sort();

test('genuine mounted admin confirmations with no proposal issue only five availability GETs', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear(); sessionStorage.clear();
  const original = globalThis.fetch, node = document.createElement('div'); document.body.append(node);
  const root = createRoot(node), calls = [];
  const transport = jest.fn(async (address, options = {}) => {
    calls.push({ address, options });
    expect(allowed({ origin: 'http://127.0.0.1:41111', url: 'http://127.0.0.1:41111' + address,
      method: options.method || 'GET' })).toBe(true);
    // Unavailable capability cannot cause a confirmation mutation or model call.
    return { ok: false, status: 503, headers: { get: () => 'application/json' }, json: async () => ({}) };
  });
  globalThis.fetch = transport;
  let unmounted = false;
  try {
    for (const authorityKey of ['control-session', 'fresh-treatment-session']) {
      const offset = calls.length;
      await act(async () => { root.render(<BoundRoleAssistant role="admin" shopUserId={7}
        authorityKey={authorityKey} transport={transport} />); });
      await act(async () => { await Promise.resolve(); });
      expect(calls.slice(offset).map(row => row.address).sort()).toEqual(expected);
      expect(calls.slice(offset).every(row => !row.options.method && !row.options.body && row.options.signal)).toBe(true);
      if (offset) expect(calls.slice(0, offset).every(row => row.options.signal.aborted)).toBe(true);
    }
    await act(async () => root.unmount()); unmounted = true;
    expect(calls.every(row => row.options.signal.aborted)).toBe(true);
    expect(calls).toHaveLength(10);
  } finally {
    if (!unmounted) await act(async () => root.unmount());
    globalThis.fetch = original; node.remove(); localStorage.clear(); sessionStorage.clear();
  }
});
