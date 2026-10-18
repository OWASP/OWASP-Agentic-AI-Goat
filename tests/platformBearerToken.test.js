'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
const { createLegacyPlatformAuthorityResolver } = require('../server/services/legacyPlatformMutationLifecycle');

const invalidHeaders = [undefined, null, '', 'Basic signed-token', 'signed-token',
  'Bearer', 'Bearer  signed-token', 'Bearer signed-token extra',
  'Bearer signed-token,Bearer second-token', 'Bearer signed-token\t', 'Bearer signed-token\n', 'Bearer signed-token\r\n',
  ['Bearer signed-token'], { toString: () => 'Bearer signed-token' }];

function fixture() {
  const checked = [];
  const adapter = { repository: {}, async validateSession(token) {
    checked.push(token);
    return { user: { id: 7, role: 'student', username: 'fixture' }, session: { id: 12 } };
  } };
  return { checked, adapter };
}

async function invoke(middleware, authorization) {
  const req = { headers: { authorization } };
  let status = 200;
  let next = false;
  await middleware(req, { status(value) { status = value; return this; }, json() {} },
    () => { next = true; });
  return { status, next, req };
}

test('platform middleware rejects malformed or non-Bearer headers before session validation', async () => {
  const { checked, adapter } = fixture();
  const middleware = createPostgresAdminAuth(adapter).authenticateToken;
  for (const header of invalidHeaders) {
    const result = await invoke(middleware, header);
    assert.equal(result.status, 401);
    assert.equal(result.next, false);
    assert.equal(result.req.user, undefined);
  }
  assert.deepEqual(checked, []);
  for (const header of ['Bearer signed-token', 'bearer signed-token', 'BEARER signed-token']) {
    const result = await invoke(middleware, header);
    assert.equal(result.status, 200);
    assert.equal(result.next, true);
    assert.equal(result.req.user.id, 7);
  }
  assert.deepEqual(checked, ['signed-token', 'signed-token', 'signed-token']);
});

test('optional legacy authority permits only absent authorization to be anonymous', async () => {
  const { checked, adapter } = fixture();
  const resolve = createLegacyPlatformAuthorityResolver(adapter);
  assert.equal(await resolve({ headers: {} }), null);
  for (const header of invalidHeaders.filter(value => value !== undefined)) {
    await assert.rejects(resolve({ headers: { authorization: header } }), { statusCode: 401 });
  }
  assert.deepEqual(checked, []);
  assert.deepEqual(await resolve({ headers: { authorization: 'bearer signed-token' },
    body: { ownerId: 999 }, session: { platformOwnerId: 999 } }), { ownerId: 7, sessionId: 12 });
  assert.deepEqual(checked, ['signed-token']);
});

test('physical duplicate Authorization fields reject on actual IncomingMessage before validation', async t => {
  const http = require('node:http');
  const { checked, adapter } = fixture();
  const middleware = createPostgresAdminAuth(adapter).authenticateToken;
  const optional = createLegacyPlatformAuthorityResolver(adapter);
  const server = http.createServer(async (req, res) => {
    const reply = { status(value) { res.statusCode = value; return this; },
      json(value) { res.end(JSON.stringify(value)); } };
    if (req.url === '/optional') {
      try { await optional(req); res.end('accepted'); }
      catch (error) { res.statusCode = error.statusCode || 500; res.end('rejected'); }
    } else {
      await middleware(req, reply, () => res.end('accepted'));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  async function request(path, headers) {
    return new Promise((resolve, reject) => {
      const outgoing = http.request({ host: '127.0.0.1', port: server.address().port,
        path, headers: ['Host', '127.0.0.1', ...headers], method: 'GET' }, response => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      outgoing.on('error', reject);
      outgoing.end();
    });
  }
  for (const path of ['/', '/optional']) {
    assert.equal(await request(path, ['Authorization', 'Bearer first-token',
      'aUtHoRiZaTiOn', 'Bearer second-token']), 401);
  }
  assert.deepEqual(checked, []);
  assert.equal(await request('/', ['Authorization', 'Bearer signed-token']), 200);
  assert.deepEqual(checked, ['signed-token']);
});
