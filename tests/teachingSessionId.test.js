'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTeachingSessionIds, MAX_AGE_MS } = require('../server/services/teachingSessionId');
test('issued teaching IDs survive a second instance but expire before tombstone removal', () => {
  let time = 1800000000000;
  const options = { secret: 'private-test-key-that-is-at-least-32-bytes', now: () => time };
  const one = createTeachingSessionIds(options), two = createTeachingSessionIds(options);
  const sid = one.generate();
  assert.deepEqual(one.decode(sid), two.decode(sid));
  assert.equal(two.decode(sid).expiresAt.getTime(), time + MAX_AGE_MS);
  time += MAX_AGE_MS - 1;
  assert.ok(two.decode(sid));
  time++;
  assert.equal(two.decode(sid), null);
});
test('tampered, foreign-key, future and malformed session IDs cannot be persisted', () => {
  const options = { secret: 'private-test-key-that-is-at-least-32-bytes', now: () => 1800000000000 };
  const ids = createTeachingSessionIds(options), sid = ids.generate();
  assert.equal(ids.decode(sid.replace('1800000000000', '1800000000001')), null);
  const future = createTeachingSessionIds({ ...options, now: () => 1800000030001 }).generate();
  assert.equal(ids.decode(future), null);
  assert.equal(createTeachingSessionIds({ ...options, secret: 'different-private-test-key-at-least-32-bytes' }).decode(sid), null);
  for (const value of [null, {}, 'x'.repeat(10000), sid + '=', sid + '\n']) assert.equal(ids.decode(value), null);
  assert.throws(() => createTeachingSessionIds({ secret: 'weak' }), /private/);
});

test('trusted issuance tolerates bounded cross-instance clock skew', () => {
  const secret = 'private-test-key-that-is-at-least-32-bytes';
  const issuer = createTeachingSessionIds({ secret, now: () => 1800000005000 });
  const replica = createTeachingSessionIds({ secret, now: () => 1800000000000 });
  assert.ok(replica.decode(issuer.generate()));
  const tooFar = createTeachingSessionIds({ secret, now: () => 1800000030001 });
  assert.equal(replica.decode(tooFar.generate()), null);
});
