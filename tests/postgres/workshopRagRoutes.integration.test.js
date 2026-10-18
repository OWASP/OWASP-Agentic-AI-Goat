'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

test('mounted durable IPI authentication, exact deletion and replacement retain sibling sources', {
  skip: process.env.WORKSHOP_RAG_ROUTES_NATIVE !== '1', timeout: 120000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  const url = role => {
    const u = new URL(process.env['WORKSHOP_RAG_' + role.toUpperCase() + '_URL']);
    assert.equal(u.hostname, '127.0.0.1'); assert.match(u.pathname, /^\/dvaia_test_workshop_rag_[a-f0-9]+$/);
    assert.equal(u.username, 'dvaia_identity_' + role); return u.href;
  };
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.IDENTITY_DATABASE_URL = url('runtime');
  process.env.IDENTITY_MIGRATION_DATABASE_URL = url('migration');
  process.env.JWT_SECRET = 'owned-native-route-qualification-secret-32bytes';
  const migration = new Pool({ connectionString: url('migration'), max: 2 });
  let directory, server;
  const evidence = { status: 'incomplete', scope: 'Mounted production IPI read/delete routes and canonical auth; controlled embeddings; no model or Judge call' };
  const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH;
  assert.ok(path.isAbsolute(evidencePath) && !path.resolve(evidencePath).startsWith(process.cwd() + path.sep));
  const save = () => fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  save();
  try {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rag-route-migrations-'));
    const base = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    for (const name of fs.readdirSync(base)) if (name.endsWith('.sql')) fs.copyFileSync(path.join(base, name), path.join(directory, name));
    fs.copyFileSync(path.resolve(__dirname, '../../docs/modernization/drafts/workshop-rag/0082_workshop_rag_sources.candidate.sql'), path.join(directory, '0082_workshop_rag_sources.sql'));
    await migrate(migration, directory); assert.deepEqual(await migrate(migration, directory), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const identity = require('../../server/database/postgres/identityRepository').createIdentityRepository(adapter.pool);
    const password = await require('bcryptjs').hash(randomUUID(), 4);
    const composition = require('../../server/services/workshopRagComposition').createWorkshopRagComposition({
      pool: adapter.pool, identityAdapter: adapter,
      assertReady: pool => require('../../server/services/workshopRagReadiness').assertWorkshopRagReadiness({ pool, expectedDatabase: new URL(url('runtime')).pathname.slice(1) }),
      embedder: { getRuntimeFingerprint: () => ({ fingerprint: 'a'.repeat(64) }),
        embed: async () => ({ embeddingDimension: 384, embedding: Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0) }) },
    });
    await composition.initialize();
    let failResetContinuation = false;
    const router = require('../../server/routes/ragInjection');
    router.configureDurableRag({ ...composition, async resolveRequest(req) {
      const scope = await composition.resolveRequest(req);
      return { ...scope, async reset(...args) {
        try {
          const [execution, options] = args;
          return await scope.reset(execution, { ...options, afterErase: async () => {
            if (failResetContinuation) { failResetContinuation = false; throw new Error('Controlled progress continuation interruption'); }
            return options.afterErase?.();
          } });
        }
        catch (error) { evidence.resetError = { code: error.code, message: error.message }; save(); throw error; }
      } };
    } });
    const express = require('express'); const app = express(); app.use(express.json()); app.use('/rag', router);
    server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const origin = `http://127.0.0.1:${server.address().port}`;
    async function owner() {
      const user = await identity.createUser({ username: 'route-' + randomUUID(), email: randomUUID() + '@example.invalid', passwordHash: password });
      const session = await adapter.createSession({ ...user, password }, {});
      const req = { user: { id: user.id }, identitySession: { id: session.internalSessionId }, headers: { authorization: `Bearer ${session.token}` } };
      return { user, session, scope: await composition.resolveRequest(req) };
    }
    const a = await owner(), b = await owner();
    const coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family: 'RAG' });
    async function ingest(o, filename) {
      const documentId = randomUUID();
      await coordinator.run(String(o.user.id), {}, async execution => {
        const store = await o.scope.bind(execution);
        await store.ingestAndSelect({ documentId, operationId: randomUUID(), filename,
          ingestionKind: 'upload', sourceBuffer: Buffer.from('Exact learner source for ' + filename) });
      }); return documentId;
    }
    const first = await ingest(a, 'first.txt'), sibling = await ingest(b, 'sibling.txt');
    const request = async (o, pathname, options = {}) => {
      const response = await fetch(origin + pathname, { ...options, headers: {
        ...(o ? { authorization: `Bearer ${o.session.token}` } : {}), ...options.headers,
      } }); return { status: response.status, body: await response.json() };
    };
    assert.equal((await request(null, '/rag/current-session')).status, 401);
    assert.equal((await request(null, '/rag/current-session', { headers: { authorization: 'Bearer invalid' } })).status, 401);
    assert.equal((await request(a, '/rag/current-session')).body.session_id, first);
    assert.equal((await request(b, '/rag/current-session')).body.session_id, sibling);
    const newer = await ingest(a, 'newer.txt');
    const operationId = randomUUID();
    const removed = await request(a, '/rag/session/' + first, { method: 'DELETE', headers: { 'x-reset-operation-id': operationId } });
    assert.equal(removed.status, 200, JSON.stringify(removed.body)); assert.equal(removed.body.deleted, true);
    assert.equal((await request(a, '/rag/current-session')).body.session_id, newer);
    assert.equal((await request(b, '/rag/current-session')).body.session_id, sibling);
    const replay = await request(a, '/rag/session/' + first, { method: 'DELETE', headers: { 'x-reset-operation-id': operationId } });
    assert.equal(replay.status, 200, JSON.stringify(replay.body));
    assert.equal((await request(a, '/rag/current-session')).body.session_id, newer);
    const foreign = await request(a, '/rag/session/' + sibling, { method: 'DELETE' });
    assert.equal(foreign.status, 404, JSON.stringify(foreign.body));
    assert.equal((await request(b, '/rag/current-session')).body.session_id, sibling);
    const invalidReset = await request(a, '/rag/progress/reset', { method: 'POST', headers: { 'x-reset-operation-id': 'not-an-operation-id' } });
    assert.equal(invalidReset.status, 400);
    assert.equal(invalidReset.body.code, 'RAG_REQUEST_INVALID');
    assert.equal((await request(a, '/rag/current-session')).body.session_id, newer);
    const resetId = randomUUID();
    const reset = await request(a, '/rag/progress/reset', { method: 'POST', headers: { 'x-reset-operation-id': resetId } });
    assert.equal(reset.status, 200, JSON.stringify(reset.body));
    assert.equal((await request(a, '/rag/current-session')).body.session_id, null);
    assert.equal((await request(b, '/rag/current-session')).body.session_id, sibling);
    const afterReset = await ingest(a, 'after-reset.txt');
    const resetReplay = await request(a, '/rag/progress/reset', { method: 'POST', headers: { 'x-reset-operation-id': resetId } });
    assert.equal(resetReplay.status, 200, JSON.stringify(resetReplay.body));
    assert.equal((await request(a, '/rag/current-session')).body.session_id, afterReset);
    failResetContinuation = true;
    const interruptedId = randomUUID();
    const interrupted = await request(a, '/rag/progress/reset', { method: 'POST', headers: { 'x-reset-operation-id': interruptedId } });
    assert.equal(interrupted.status, 503);
    await assert.rejects(ingest(a, 'denied-during-reset.txt'));
    assert.equal((await request(b, '/rag/current-session')).body.session_id, sibling);
    const resumed = await request(a, '/rag/progress/reset', { method: 'POST', headers: { 'x-reset-operation-id': interruptedId } });
    assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
    assert.equal((await request(a, '/rag/current-session')).body.session_id, null);
    const recovered = await ingest(a, 'recovered.txt');
    assert.equal((await request(a, '/rag/current-session')).body.session_id, recovered);
    await adapter.logout(a.session.token);
    assert.equal((await request(a, '/rag/current-session')).status, 401);
    evidence.status = 'passed'; evidence.authentication = 'missing/invalid/revoked denied';
    evidence.lifecycle = 'exact old-document deletion and replay preserve newer selection and sibling'; save();
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await require('../../server/database/postgres').closePostgresPools();
    await migration.end(); if (directory) fs.rmSync(directory, { recursive: true, force: true });
  }
});
