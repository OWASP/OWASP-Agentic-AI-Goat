'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssWorkshopDb } = require('../server/database/postgres/xssWorkshopDb');
const { createXssProfileOriginRepository, anonymousOwner } = require('../server/database/postgres/xssProfileOriginRepository');

function fakePool() {
  const profiles = new Map();
  const origins = new Map();
  const connect = async () => {
    const client = {
      async query(sql, params = []) {
        if (/^(BEGIN|COMMIT|ROLLBACK)/.test(sql)) return { rows: [], rowCount: 0 };
        if (/INSERT INTO xss\.profiles\(user_key,([^,]+),([^\)]+)\)/.test(sql)) {
          const [, field] = sql.match(/INSERT INTO xss\.profiles\(user_key,([^,]+),/) || [];
          const owner = params[0];
          const profile = profiles.get(owner) || { name: 'Security Student', bio: 'Learning about web security.', website: 'https://example.com', name_revision: 0, bio_revision: 0, website_revision: 0 };
          profile[field] = params[1]; profile[`${field}_revision`] += 1; profiles.set(owner, profile);
          return { rows: [{ revision: profile[`${field}_revision`] }], rowCount: 1 };
        }
        if (/INSERT INTO xss\.profiles\s*\n?\s*\(user_key,name,bio/.test(sql)) {
          const owner = params[0];
          const prior = profiles.get(owner) || { name_revision: 0, bio_revision: 0, website_revision: 0 };
          const profile = { name: params[1], bio: params[2], website: params[3],
            name_revision: prior.name_revision + 1, bio_revision: prior.bio_revision + 1,
            website_revision: prior.website_revision + 1 };
          profiles.set(owner, profile);
          return { rows: [{ name_revision: profile.name_revision, bio_revision: profile.bio_revision, website_revision: profile.website_revision }], rowCount: 1 };
        }
        if (/DELETE FROM xss\.profile_model_origins/.test(sql)) { origins.delete(params[0]); return { rows: [], rowCount: 1 }; }
        throw new Error(`Unexpected fake query: ${sql}`);
      },
      release() {},
    };
    return client;
  };
  return {
    profiles, origins, connect,
    async query(sql, params = []) {
      if (/SELECT name,bio,website FROM xss\.profiles/.test(sql)) {
        const profile = profiles.get(params[0]);
        return { rows: profile ? [{ name: profile.name, bio: profile.bio, website: profile.website }] : [], rowCount: profile ? 1 : 0 };
      }
      throw new Error(`Unexpected fake pool query: ${sql}`);
    },
  };
}

test('anonymous PostgreSQL profile practice is isolated, raw, resettable and noncanonical', async () => {
  const pool = fakePool();
  const store = createXssWorkshopDb(pool);
  const alice = 'anon_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  const bob = 'anon_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
  const payload = '<img src=x onerror="alert(1)">';

  await store.updateProfileField(alice, 'bio', payload);
  await store.updateProfileField(bob, 'bio', '<script>alert(2)</script>');
  assert.equal((await store.getProfile(alice)).bio, payload);
  assert.equal((await store.getProfile(bob)).bio, '<script>alert(2)</script>');
  assert.equal(pool.origins.size, 0);
  await store.resetProfile(alice);
  assert.equal((await store.getProfile(alice)).bio, 'Learning about web security.');
  assert.equal((await store.getProfile(bob)).bio, '<script>alert(2)</script>');
});

test('anonymous owner validator rejects numeric impersonation, placeholders and arbitrary keys', () => {
  assert.equal(anonymousOwner('anon_0123456789abcdefghijklmnopqrstuv'), 'anon_0123456789abcdefghijklmnopqrstuv');
  for (const value of ['7', 'anon_undefined', 'anon_null', 'anon_', 'anon_short', 'owner-7', 'anon/other']) {
    assert.throws(() => anonymousOwner(value), /anonymous profile owner|required|owner/i);
  }
});

test('authenticated/model-origin repository paths remain strict for anonymous keys', async () => {
  const pool = fakePool();
  const repository = createXssProfileOriginRepository(pool);
  await assert.rejects(repository.readCurrent({ userKey: 'anon_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', field: 'bio', platformUserId: 7 }), /owner|required/i);
  await assert.rejects(repository.writeModelField({ userKey: 'anon_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', field: 'bio', value: 'x' }), /platform|required/i);
});
