'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { auditMetadata } = require('../server/middleware/auditMetadata');

test('platform audit metadata excludes body, headers, query secrets and dynamic route values', () => {
  const req = {
    method: 'POST', baseUrl: '/api/auth', route: { path: '/reset/:token' },
    url: '/reset/secret-token?api_key=secret-key',
    body: { password: 'secret-password', nested: { token: 'secret-body' } },
    headers: { authorization: 'Bearer secret-auth' },
  };
  const data = auditMetadata(req);
  assert.equal(data.url, '/api/auth/reset/:token');
  assert.equal(data.method, 'POST');
  assert.equal(JSON.stringify(data).includes('secret'), false);
  assert.deepEqual(Object.keys(data).sort(), ['method', 'timestamp', 'url']);
});

test('unmatched request audit strips the query without collecting submitted data', () => {
  assert.equal(auditMetadata({ method: 'GET', url: '/login?password=hidden' }).url, '/login');
});
