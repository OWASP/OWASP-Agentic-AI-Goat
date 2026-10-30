'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { createPool, closePostgresPools } = require('../../server/database/postgres');
const { createIdentityRepository, initializeIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { createPostgresIdentityAdapter } = require('../../server/services/postgresIdentityAdapter');
const { createSessionDisclosureDb, initializeSessionDisclosureDb } = require(
  '../../server/database/postgres/sessionDisclosureDb');
const { closeSessionDisclosureLab } = require('../../server/services/sessionDisclosureLab');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' &&
  process.env.SESSION_DISCLOSURE_ISOLATED === '1';

function required(name) {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  assert.match(new URL(value).pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value;
}

function cookieFrom(response) {
  const raw = response.headers.get('set-cookie') || '';
  return raw.split(';', 1)[0];
}

test('mounted session disclosure route persists isolated owner credentials and rotates them atomically',
  { skip: !enabled, timeout: 120000 }, async () => {
    for (const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL',
      'SESSION_DISCLOSURE_DATABASE_URL','SESSION_DISCLOSURE_MIGRATION_DATABASE_URL']) required(key);
    const migrationDirectory = process.env.SESSION_DISCLOSURE_TEST_MIGRATION_DIR;
    assert.ok(migrationDirectory && path.isAbsolute(migrationDirectory));

    const identity = createPool(process.env, 'IDENTITY_DATABASE_URL');
    const identityMigration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
    const labPool = createPool(process.env, 'SESSION_DISCLOSURE_DATABASE_URL');
    const labMigration = createPool(process.env, 'SESSION_DISCLOSURE_MIGRATION_DATABASE_URL');
    let server;
    try {
      await initializeIdentityRepository(identity, identityMigration);
      await initializeSessionDisclosureDb(labPool, labMigration, migrationDirectory);
      // Exercise the no-argument startup contract used by initialize-application after promotion.
      await initializeSessionDisclosureDb(undefined, undefined, migrationDirectory);
      const identityRepo = createIdentityRepository(identity);
      const identityAdapter = createPostgresIdentityAdapter({ repository: identityRepo,
        progress: null, jwtSecret: process.env.JWT_SECRET });
      async function user(label) {
        const row = await identityRepo.createUser({ username: `session-${label}-${crypto.randomUUID()}`,
          email: `${crypto.randomUUID()}@owasp-ai-goat.invalid`, passwordHash: bcrypt.hashSync('owned-fixture', 4) });
        const credential = await identityRepo.findCredentialById(row.id);
        const issued = await identityAdapter.createSession(credential, { get: () => null, ip: '127.0.0.1' });
        return { id: row.id, token: issued.token };
      }
      const [alice, bob] = await Promise.all([user('alice'), user('bob')]);

      const app = express();
      app.use(cookieParser());
      app.use(express.json());
      app.use('/api/vulnerabilities', require('../../server/routes/vulnerabilities'));
      server = await new Promise(resolve => {
        const current = app.listen(0, '127.0.0.1', () => resolve(current));
      });
      const base = `http://127.0.0.1:${server.address().port}/api/vulnerabilities/session`;
      const request = (owner, suffix, options = {}) => fetch(`${base}${suffix}`, {
        method: options.method || 'GET',
        headers: { Authorization: `Bearer ${owner.token}`, ...(options.cookie ? { Cookie: options.cookie } : {}) },
      });

      const platformSecret = `connect.sid=platform-${crypto.randomBytes(20).toString('hex')}`;
      const concurrent = await Promise.all(Array.from({ length: 12 }, () =>
        request(alice, '/info', { cookie: platformSecret })));
      assert.ok(concurrent.every(response => response.status === 200));
      assert.ok(concurrent.every(response => response.headers.get('cache-control') === 'no-store'));
      const bodies = await Promise.all(concurrent.map(response => response.json()));
      assert.equal(new Set(bodies.map(body => body.session.sessionId)).size, 1);
      assert.equal(new Set(bodies.map(body => body.cookies.owasp_ai_goat_lab_session)).size, 1);
      assert.equal(bodies[0].session.generation, 1);
      assert.equal(Object.hasOwn(bodies[0].session, 'platformOwnerId'), false);
      assert.doesNotMatch(JSON.stringify(bodies), /connect\.sid|platform-/);
      const aliceCookie = `owasp_ai_goat_lab_session=${bodies[0].cookies.owasp_ai_goat_lab_session}`;

      const exact = await request(alice, '/info', { cookie: aliceCookie });
      assert.equal(exact.status, 200);
      assert.equal((await exact.json()).session.sessionId, bodies[0].session.sessionId);
      const bobWrong = await request(bob, '/info', { cookie: aliceCookie });
      assert.equal(bobWrong.status, 401);
      assert.match(bobWrong.headers.get('set-cookie') || '', /owasp_ai_goat_lab_session=;/);
      assert.doesNotMatch(JSON.stringify(await bobWrong.json()), new RegExp(bodies[0].session.sessionId));

      const bobFirst = await request(bob, '/info');
      assert.equal(bobFirst.status, 200);
      const bobBody = await bobFirst.json();
      assert.notEqual(bobBody.session.sessionId, bodies[0].session.sessionId);

      const resets = await Promise.all(Array.from({ length: 4 }, () =>
        request(alice, '/reset', { method: 'POST', cookie: aliceCookie })));
      assert.ok(resets.every(response => response.status === 200));
      const resetBodies = await Promise.all(resets.map(response => response.json()));
      assert.deepEqual(resetBodies.map(body => body.generation).sort((a,b) => a-b), [2,3,4,5]);
      const replay = await request(alice, '/info', { cookie: aliceCookie });
      assert.equal(replay.status, 401);
      const rotated = await request(alice, '/info');
      assert.equal(rotated.status, 200);
      const rotatedBody = await rotated.json();
      assert.equal(rotatedBody.session.generation, 5);
      assert.notEqual(rotatedBody.session.sessionId, bodies[0].session.sessionId);
      assert.notEqual(rotatedBody.session.csrfToken, bodies[0].session.csrfToken);

      const reopened = createSessionDisclosureDb(labPool);
      const persisted = await reopened.resolve(alice.id, rotatedBody.cookies.owasp_ai_goat_lab_session);
      assert.equal(persisted.sessionId, rotatedBody.session.sessionId);
      const bobPersisted = await reopened.resolve(bob.id, bobBody.cookies.owasp_ai_goat_lab_session);
      assert.equal(bobPersisted.sessionId, bobBody.session.sessionId);
      assert.equal(await reopened.resolve(bob.id, rotatedBody.cookies.owasp_ai_goat_lab_session), null);
      assert.equal(await reopened.destroyOwner(bob.id), 1);
      assert.equal(await reopened.resolve(bob.id, bobBody.cookies.owasp_ai_goat_lab_session), null);
      assert.ok(await reopened.resolve(alice.id, rotatedBody.cookies.owasp_ai_goat_lab_session));
    } finally {
      if (server) await new Promise(resolve => server.close(resolve));
      await closeSessionDisclosureLab();
      await closeSessionDisclosureLab();
      await Promise.allSettled([identity.end(), identityMigration.end(), labPool.end(), labMigration.end()]);
      await closePostgresPools();
    }
  });
