'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTeachingSessionAuthority } = require('../server/services/teachingSessionAuthority');
const cookie = () => ({ headers: {}, sessionID: 'owned-cookie', session: { userId: 7, platformOwnerId: 7, platformSessionId: 11 } });
const found = () => ({ user: { id: 7 }, session: { id: 11, user_id: 7 } });
const status = expected => error => error.statusCode === expected;

test('cookie authority is explicit, complete and bound to the canonical owner', async () => {
  const checks = [];
  const resolve = createTeachingSessionAuthority({ assertCookieBinding: async () => {}, validateSession: async () => found(), assertBinding: async value => checks.push(value) });
  await assert.rejects(resolve(cookie()), status(401));
  for (const change of [{ platformOwnerId: 8 }, { userId: null }, { platformSessionId: true }, { platformOwnerId: '7e0' }]) {
    const req = cookie(); Object.assign(req.session, change);
    await assert.rejects(resolve(req, { allowCookie: true }), status(401));
  }
  const req = cookie(); const authority = await resolve(req, { allowCookie: true });
  req.session.platformOwnerId = 99;
  await authority.check();
  assert.equal(authority.ownerId, 7);
  assert.equal(authority.source, 'teaching-cookie');
  assert.deepEqual(checks, [{ ownerId: 7, sessionId: 11 }, { ownerId: 7, sessionId: 11 }]);
  assert.ok(Object.isFrozen(checks[0]));
});

test('invalid or duplicate presented bearer never falls back to a valid cookie', async () => {
  let checked = 0;
  const resolve = createTeachingSessionAuthority({ assertCookieBinding: async () => {}, validateSession: async () => null, assertBinding: async () => checked++ });
  for (const headers of [{ authorization: 'Basic abc' }, { authorization: 'Bearer invalid' }]) {
    await assert.rejects(resolve({ ...cookie(), headers }, { allowCookie: true }), status(401));
  }
  await assert.rejects(resolve({ ...cookie(), headers: { authorization: 'Bearer first' },
    rawHeaders: ['Authorization', 'Bearer first', 'Authorization', 'Bearer second'] }, { allowCookie: true }), status(401));
  assert.equal(checked, 0);
});

test('captured bearer authority cannot switch identity and is revalidated after admission', async () => {
  let current = found(); const tokens = [];
  const resolve = createTeachingSessionAuthority({ assertCookieBinding: async () => {}, validateSession: async token => { tokens.push(token); return current; }, assertBinding: async () => {} });
  const req = { headers: { authorization: 'Bearer original' } };
  const authority = await resolve(req);
  req.headers.authorization = 'Bearer changed';
  await authority.check();
  assert.ok(tokens.every(value => value === 'original'));
  current = { user: { id: 8 }, session: { id: 12, user_id: 8 } };
  await assert.rejects(authority.check(), status(401));
  current = null;
  await assert.rejects(authority.check(), status(401));
});

test('revocation, deletion, account lock and unavailable store fail closed without private errors', async () => {
  let error;
  const resolve = createTeachingSessionAuthority({ assertCookieBinding: async () => {}, validateSession: async () => found(), assertBinding: async () => { if (error) throw error; } });
  const authority = await resolve(cookie(), { allowCookie: true });
  for (const [properties, expected] of [[{ code: '55000' }, 401], [{ name: 'AccountLocked' }, 423], [{ code: 'ECONNRESET' }, 503]]) {
    error = Object.assign(new Error('private database detail'), properties);
    await assert.rejects(authority.check(), e => status(expected)(e) && !e.message.includes('private'));
  }
});

test('cookie checks capture the issued ID and reject revocation after initial admission', async () => {
  let revoked = false; const seen = [];
  const resolve = createTeachingSessionAuthority({ validateSession: async () => found(), assertBinding: async () => {},
    assertCookieBinding: async (sid, binding) => { seen.push({ sid, ...binding }); if (revoked) throw Object.assign(new Error('retired'), { code: '55000' }); } });
  const req = cookie(); const authority = await resolve(req, { allowCookie: true });
  req.sessionID = 'replacement-cookie';
  revoked = true;
  await assert.rejects(authority.check(), status(401));
  assert.deepEqual(seen, [{ sid: 'owned-cookie', ownerId: 7, sessionId: 11 }, { sid: 'owned-cookie', ownerId: 7, sessionId: 11 }]);
  const incomplete = createTeachingSessionAuthority({ validateSession: async () => found(), assertBinding: async () => {} });
  await assert.rejects(incomplete(cookie(), { allowCookie: true }), status(401));
});
