'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { PostgresTeachingSessionStore } = require('../../server/services/postgresTeachingSessionStore');
const { MAX_AGE_MS } = require('../../server/services/teachingSessionId');
const express = require('express'), session = require('express-session');

const identityMigrations = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const teachingMigration = '0095_teaching_sessions.sql';
function prefixMigrationLoader() {
  const fsp = require('node:fs/promises');
  const { Module, createRequire } = require('node:module');
  const filename = require.resolve('../../db/postgres/migrate');
  const localRequire = createRequire(filename);
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? {
    async readdir(directory, ...args) {
      assert.equal(path.resolve(directory), identityMigrations);
      return (await fsp.readdir(directory, ...args)).filter(name => name < teachingMigration);
    },
    readFile: (...args) => fsp.readFile(...args),
  } : localRequire(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}
test('teaching migration prefix preserves canonical bytes and checksums without disk staging', async () => {
  const fsp = require('node:fs/promises');
  const original = fsp.readdir;
  const full = await readMigrations(identityMigrations);
  assert.ok(full.some(row => row.name === teachingMigration));
  const prefix = await prefixMigrationLoader().readMigrations(identityMigrations);
  assert.deepEqual(prefix, full.filter(row => row.name < teachingMigration));
  assert.equal(fsp.readdir, original);
  assert.deepEqual(await readMigrations(identityMigrations), full);
});

test('native teaching sessions persist across instances and cannot resurrect after revocation', {
  skip: process.env.TEACHING_SESSION_NATIVE !== '1', timeout: 180000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
  const pools = [], servers = [], runtimes = [], authRouters = [];
  const connect = (role, max = 5) => {
    const url = new URL(process.env['WORKSHOP_RAG_' + role.toUpperCase() + '_URL']);
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/dvaia_test_workshop_rag_[a-f0-9]+$/);
    assert.equal(url.username, 'dvaia_identity_' + role);
    const pool = new Pool({ connectionString: url.href, max, statement_timeout: 10000 });
    pools.push(pool); return pool;
  };
  const migration = connect('migration'), runtime = connect('runtime', 2), effectPool = connect('runtime', 2);
  try {
    const canonical = await readMigrations(identityMigrations);
    const prefix = canonical.filter(row => row.name < teachingMigration);
    assert.ok(canonical.some(row => row.name === teachingMigration));
    assert.deepEqual(await prefixMigrationLoader().migrate(migration, identityMigrations), prefix.map(row => row.name));
    const ledger = async () => (await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await ledger(), prefix.map(({ name, checksum }) => ({ name, checksum })));
    const representative = (await migration.query("INSERT INTO identity.users(username,email,password) VALUES($1,$2,$3) RETURNING id,username,email,password,created_at",
      ['pre-upgrade-' + randomUUID(), randomUUID() + '@example.invalid', await require('bcryptjs').hash(randomUUID(), 4)])).rows[0];
    assert.deepEqual(await migrate(migration, identityMigrations), canonical.filter(row => row.name >= teachingMigration).map(row => row.name));
    assert.deepEqual(await ledger(), canonical.map(({ name, checksum }) => ({ name, checksum })));
    assert.deepEqual(await migrate(migration, identityMigrations), []);
    assert.deepEqual((await migration.query('SELECT id,username,email,password,created_at FROM identity.users WHERE id=$1', [representative.id])).rows[0], representative);
    const { assertTeachingSessionReadiness } = require('../../server/services/teachingSessionReadiness');
    assert.equal((await assertTeachingSessionReadiness(runtime)).ready, true);
    await assert.rejects(assertTeachingSessionReadiness(migration), { code: 'TEACHING_SESSION_NOT_READY' });
    await migration.query('REVOKE DELETE ON identity.teaching_sessions FROM dvaia_identity_runtime');
    try { await assert.rejects(assertTeachingSessionReadiness(runtime), { code: 'TEACHING_SESSION_NOT_READY' }); }
    finally { await migration.query('GRANT DELETE ON identity.teaching_sessions TO dvaia_identity_runtime'); }
    await migration.query('ALTER TABLE identity.users DISABLE TRIGGER retire_deleted_owner_teaching_sessions');
    try { await assert.rejects(assertTeachingSessionReadiness(runtime), { code: 'TEACHING_SESSION_NOT_READY' }); }
    finally { await migration.query('ALTER TABLE identity.users ENABLE TRIGGER retire_deleted_owner_teaching_sessions'); }
    assert.equal((await assertTeachingSessionReadiness(runtime)).ready, true);
    const repository = require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
    const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({ repository, jwtSecret: 'synthetic-qualification-signing-key-over32bytes' });
    const plainPassword = randomUUID();
    const password = await require('bcryptjs').hash(plainPassword, 4);
    const user = await repository.createUser({ username: 'session-' + randomUUID(), email: randomUUID() + '@example.invalid', passwordHash: password });
    const platform = await adapter.createSession({ ...user, password }, {});
    let clock = Date.now();
    const options = { pool: runtime, effectPool, secret: 'private-teaching-test-issuance-key-over32bytes', now: () => clock };
    const one = new PostgresTeachingSessionStore(options), two = new PostgresTeachingSessionStore(options);
    const call = (store, method, ...args) => new Promise((resolve, reject) => store[method](...args, (error, value) => error ? reject(error) : resolve(value)));
    const data = { userId: user.id, platformOwnerId: user.id, platformSessionId: platform.internalSessionId,
      username: user.username, cookie: { maxAge: MAX_AGE_MS } };
    const start = async (store, selectedMiddleware, bindBearer) => {
      const app = express();
      app.use(selectedMiddleware || session({ store, genid: store.genid, secret: 'intentionally-weak-teaching-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: false, maxAge: MAX_AGE_MS, sameSite: 'lax' } }));
      app.use(express.json());
      const pass = (_req, _res, next) => next();
      const authRouter = require('../../server/routes/postgresAuth').createPostgresAuthRouter({ adapter,
        limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass } });
      authRouters.push(authRouter); app.use('/auth', authRouter);
      app.get('/read', (req, res) => res.json({ owner: req.session?.userId || null }));
      if (bindBearer) app.get('/bind', async (req, res) => {
        try { const authority = await bindBearer(req); await authority.check(); res.json({ owner: authority.ownerId, rotated: authority.rotated }); }
        catch (error) { res.status(error.statusCode || 503).json({ error: 'Binding unavailable' }); }
      });
      if (bindBearer) app.post('/effect', async (req, res) => {
        try {
          const authority = await bindBearer(req);
          const value = await store.withAuthority(req.sessionID, authority, async () => {
            await authority.check();
            return (await runtime.query('SELECT 1 AS value')).rows[0].value;
          });
          // Session writes and HTTP completion must occur after the effect
          // lease commits: both need an UPDATE lock on the teaching row.
          req.session.lastEffect = value;
          await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
          res.json({ value });
        } catch (error) { res.status(error.statusCode || 503).json({ error: 'Effect unavailable' }); }
      });
      const server = app.listen(0, '127.0.0.1'); servers.push(server);
      await new Promise(resolve => server.once('listening', resolve));
      return 'http://127.0.0.1:' + server.address().port;
    };
    const originOne = await start(one), originTwo = await start(two);
    const login = await fetch(originOne + '/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: user.username, password: plainPassword }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const encoded = decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1));
    const issued = encoded.slice(2, encoded.lastIndexOf('.'));
    assert.ok(one.ids.decode(issued), 'own issued cookie must decode');
    assert.ok(two.ids.decode(issued), 'second instance must decode cookie');
    const storedLogin = (await runtime.query('SELECT owner_id,payload,revoked,expires_at>clock_timestamp() AS live FROM identity.teaching_sessions WHERE session_hash=$1', [one.ids.decode(issued).hash])).rows;
    assert.equal(storedLogin.length, 1, 'login session must be saved before its response ends');
    assert.equal(storedLogin[0].owner_id, user.id);
    assert.equal(storedLogin[0].payload.userId, user.id);
    assert.equal(storedLogin[0].live, true);
    assert.equal((await call(two, 'get', issued))?.userId, user.id, 'store can restore exact issued cookie');

    assert.equal((await (await fetch(originTwo + '/read', { headers: { cookie } })).json()).owner, user.id);
    const restored = new PostgresTeachingSessionStore(options), originRestored = await start(restored);
    assert.equal((await (await fetch(originRestored + '/read', { headers: { cookie } })).json()).owner, user.id);
    const { createTeachingSessionRuntime } = require('../../server/services/teachingSessionRuntime');
    const managed = createTeachingSessionRuntime({ adapter: { ...adapter, pool: runtime }, effectPool }); runtimes.push(managed);
    const managedOrigin = await start(managed.store, managed.middleware, managed.bindBearer);
    assert.equal((await fetch(managedOrigin + '/read')).status, 503);
    await Promise.all([managed.initialize(), managed.initialize()]);
    const managedLogin = await fetch(managedOrigin + '/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: user.username, password: plainPassword }) });
    assert.equal(managedLogin.status, 200);
    const managedCookie = managedLogin.headers.get('set-cookie').split(';')[0];
    const managedToken = (await managedLogin.json()).token;
    const nextManaged = createTeachingSessionRuntime({ adapter: { ...adapter, pool: runtime }, effectPool }); runtimes.push(nextManaged);
    await nextManaged.initialize();
    const nextOrigin = await start(nextManaged.store, nextManaged.middleware, nextManaged.bindBearer);
    assert.equal((await (await fetch(nextOrigin + '/read', { headers: { cookie: managedCookie } })).json()).owner, user.id);
    const bindRequest = (cookieValue, token) => fetch(nextOrigin + '/bind', { headers: { cookie: cookieValue, authorization: 'Bearer ' + token } });
    const sameBinding = await bindRequest(managedCookie, managedToken);
    assert.equal(sameBinding.status, 200); assert.equal((await sameBinding.json()).rotated, false);
    const effectResponse = await fetch(nextOrigin + '/effect', { method: 'POST',
      headers: { cookie: managedCookie, authorization: 'Bearer ' + managedToken }, signal: AbortSignal.timeout(5000) });
    assert.equal(effectResponse.status, 200); assert.deepEqual(await effectResponse.json(), { value: 1 });
    const rawManaged = decodeURIComponent(managedCookie.slice(managedCookie.indexOf('=') + 1));
    const managedSid = rawManaged.slice(2, rawManaged.lastIndexOf('.'));
    await call(managed.store, 'destroy', managedSid);
    const repairedBinding = await bindRequest(managedCookie, managedToken);
    assert.equal(repairedBinding.status, 200); assert.equal((await repairedBinding.json()).rotated, true);
    const repairedCookie = repairedBinding.headers.get('set-cookie').split(';')[0];
    assert.notEqual(repairedCookie, managedCookie);
    assert.equal(await call(managed.store, 'get', managedSid), null);
    assert.equal((await bindRequest(repairedCookie, 'invalid-token')).status, 401);
    const sibling = await repository.createUser({ username: 'sibling-' + randomUUID(), email: randomUUID() + '@example.invalid', passwordHash: password });
    const siblingPlatform = await adapter.createSession({ ...sibling, password }, {});
    const switched = await bindRequest(repairedCookie, siblingPlatform.token);
    assert.equal(switched.status, 200); assert.deepEqual(await switched.json(), { owner: sibling.id, rotated: true });
    const siblingCookie = switched.headers.get('set-cookie').split(';')[0];
    assert.notEqual(siblingCookie, repairedCookie);
    assert.equal((await (await fetch(nextOrigin + '/read', { headers: { cookie: siblingCookie } })).json()).owner, sibling.id);
    await managed.close();
    assert.equal((await fetch(managedOrigin + '/read', { headers: { cookie: managedCookie } })).status, 503);
    await nextManaged.close();
    const sid = one.genid(); await call(one, 'set', sid, data);
    assert.equal((await call(two, 'get', sid)).userId, user.id);
    await call(two, 'destroy', sid);
    await assert.rejects(call(one, 'set', sid, data), { code: 'TEACHING_SESSION_STORAGE_UNAVAILABLE' });
    assert.equal(await call(restored, 'get', sid), null);
    const sid2 = one.genid(); await call(one, 'set', sid2, data);
    await assert.rejects(call(two, 'set', sid2, { ...data, userId: user.id + 1, platformOwnerId: user.id + 1 }), { code: 'TEACHING_SESSION_STORAGE_UNAVAILABLE' });
    await two.assertSession(sid2, { ownerId: user.id, sessionId: platform.internalSessionId });
    await assert.rejects(two.assertSession(sid, { ownerId: user.id, sessionId: platform.internalSessionId }), { code: '55000' });
    await assert.rejects(two.assertSession(sid2, { ownerId: user.id + 1, sessionId: platform.internalSessionId }), { code: '55000' });
    await assert.rejects(call(one, 'set', one.genid(), { ...data, oversized: 'x'.repeat(61000) }));
    // More concurrent leases than the ordinary pool maximum must still make
    // progress when each callback needs another identity query.
    const concurrentIds = [one.genid(), one.genid(), one.genid(), one.genid()];
    for (const current of concurrentIds) await call(one, 'set', current, data);
    const concurrent = concurrentIds.map(current => one.withAuthority(current,
      { ownerId: user.id, sessionId: platform.internalSessionId }, async () => {
        await one.assertSession(current, { ownerId: user.id, sessionId: platform.internalSessionId });
        return (await runtime.query('SELECT 1 AS ok')).rows[0].ok;
      }));
    assert.deepEqual(await Promise.all(concurrent), [1, 1, 1, 1]);
    const fencedSid = one.genid(); await call(one, 'set', fencedSid, data);
    let entered, release;
    const ready = new Promise(resolve => { entered = resolve; });
    const barrier = new Promise(resolve => { release = resolve; });
    const effect = one.withAuthority(fencedSid, { ownerId: user.id, sessionId: platform.internalSessionId }, async () => { entered(); await barrier; });
    await ready;
    const retirement = call(two, 'destroy', fencedSid); retirement.catch(() => {});
    try {
      let waiting = false;
      for (let i = 0; i < 60 && !waiting; i++) {
        const rows = (await runtime.query("SELECT pid FROM pg_stat_activity WHERE usename=current_user AND wait_event_type='Lock' AND query LIKE '%INSERT INTO identity.teaching_sessions%' AND pid<>pg_backend_pid()")).rows;
        waiting = rows.length > 0;
        if (!waiting) await new Promise(resolve => setTimeout(resolve, 50));
      }
      assert.equal(waiting, true, 'retirement must wait for the admitted teaching effect');
    } finally { release(); await effect; await retirement; }
    await assert.rejects(one.assertSession(fencedSid, { ownerId: user.id, sessionId: platform.internalSessionId }), { code: '55000' });
    const expirySid = one.genid(); await call(one, 'set', expirySid, data);
    const initialClock = clock;
    try {
      await assert.rejects(one.withAuthority(expirySid, { ownerId: user.id, sessionId: platform.internalSessionId }, async () => { clock += MAX_AGE_MS; }), { code: '55000' });
    } finally { clock = initialClock; }
    await repository.revokeAllUserSessions(user.id);
    assert.equal(await call(two, 'get', sid2), null);
    const beforeRevokedTouch = (await runtime.query('SELECT * FROM identity.teaching_sessions WHERE session_hash=$1', [one.ids.decode(sid2).hash])).rows;
    await call(one, 'touch', sid2, data);
    assert.deepEqual((await runtime.query('SELECT * FROM identity.teaching_sessions WHERE session_hash=$1', [one.ids.decode(sid2).hash])).rows, beforeRevokedTouch);
    await assert.rejects(one.assertSession(sid2, { ownerId: user.id, sessionId: platform.internalSessionId }), { code: '55000' });
    // Supported deletion preserves an inactive identity tombstone.
    // This checks that database transition, not the full authorized journey.
    const ownerHashes = (await runtime.query('SELECT session_hash FROM identity.teaching_sessions WHERE owner_id=$1', [user.id])).rows.map(row => row.session_hash);
    await migration.query('UPDATE identity.users SET is_active=0 WHERE id=$1', [user.id]);
    const retained = (await runtime.query('SELECT owner_id,platform_session_id,payload,revoked FROM identity.teaching_sessions WHERE session_hash=ANY($1::text[])', [ownerHashes])).rows;
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM identity.teaching_sessions WHERE owner_id=$1 AND NOT revoked', [sibling.id])).rows[0].n, 1);
    assert.ok(retained.length >= 3);
    assert.ok(retained.every(row => row.revoked && row.payload === null && row.owner_id === null && row.platform_session_id === null));
    // Keep the separate physical-delete hook covered without replacing the
    // supported inactive-owner transition above or deleting its evidence.
    const deletedOwner = await repository.createUser({ username: 'deleted-' + randomUUID(),
      email: randomUUID() + '@example.invalid', passwordHash: password });
    const deletedPlatform = await adapter.createSession({ ...deletedOwner, password }, {});
    const deletedSid = one.genid();
    await call(one, 'set', deletedSid, { ...data, userId: deletedOwner.id,
      platformOwnerId: deletedOwner.id, platformSessionId: deletedPlatform.internalSessionId });
    const deletedHash = one.ids.decode(deletedSid).hash;
    const siblingBeforeDelete = (await runtime.query('SELECT * FROM identity.teaching_sessions WHERE owner_id=$1', [sibling.id])).rows;
    assert.equal((await call(one, 'get', deletedSid)).userId, deletedOwner.id);
    await migration.query('DELETE FROM identity.users WHERE id=$1', [deletedOwner.id]);
    const deletedReceipt = (await runtime.query('SELECT owner_id,platform_session_id,payload,revoked FROM identity.teaching_sessions WHERE session_hash=$1', [deletedHash])).rows;
    assert.deepEqual(deletedReceipt, [{ owner_id: null, platform_session_id: null, payload: null, revoked: true }]);
    assert.equal(await call(one, 'get', deletedSid), null);
    assert.deepEqual((await runtime.query('SELECT * FROM identity.teaching_sessions WHERE owner_id=$1', [sibling.id])).rows, siblingBeforeDelete);
    await migration.query("UPDATE identity.teaching_sessions SET expires_at=clock_timestamp()-interval '1 minute'");
    const beforePrune = (await runtime.query('SELECT count(*)::int AS n FROM identity.teaching_sessions')).rows[0].n;
    assert.equal(await one.pruneExpired(1), 1);
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM identity.teaching_sessions')).rows[0].n, beforePrune - 1);
    clock += MAX_AGE_MS;
    await runtime.query('DELETE FROM identity.teaching_sessions');
    await assert.rejects(call(one, 'set', sid, data), { code: 'TEACHING_SESSION_STORAGE_UNAVAILABLE' });
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM identity.teaching_sessions')).rows[0].n, 0);
    fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH, JSON.stringify({ status: 'passed', scope: 'candidate store/runtime with actual PostgreSQL runtime role, canonical mounted auth and two HTTP instances; not full server startup',
      crossInstance: true, reinitializedStore: true, destroyedIdCannotResurrect: true, revokedCanonicalSessionDenied: true,
      mountedSessionSaveAfterEffectLease: true,
      expiredIdCannotRecreateAfterCleanup: true, freshMigrationAndNoop: true, privateKeyDerivedRuntimeCrossInstance: true, readinessDriftDenial: true, startupShutdownGated: true, canonicalBearerRepairAndOwnerSwitch: true, siblingCookiePreserved: true, populatedAccountPreserved: true, expiryBeforeEffectPublicationDenied: true, nativeOwnerInactivationRedactsPayload: true, boundedCleanup: true, effectRetirementSerialized: true, separateLeasePoolNestedConcurrency: true, installedActivation: false }, null, 2));
  } finally {
    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    for (const router of authRouters) router.close();
    await Promise.all(runtimes.map(value => value.close()));
    await Promise.all(pools.map(pool => pool.end()));
  }
});
