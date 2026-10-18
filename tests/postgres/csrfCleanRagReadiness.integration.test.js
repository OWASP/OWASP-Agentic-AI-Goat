'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');

test('current CSRF clean RAG answers through the mounted route and restores from durable state', {
  skip: process.env.CSRF_CLEAN_RAG_NATIVE !== '1', timeout: 240000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
  assert.equal(process.env.HF_HUB_OFFLINE, '1');
  assert.equal(process.env.TRANSFORMERS_OFFLINE, '1');
  const databaseUrl = (prefix, role, databasePattern, username) => {
    const value = new URL(process.env[`${prefix}_${role.toUpperCase()}_URL`]);
    assert.equal(value.hostname, '127.0.0.1');
    assert.match(value.pathname, databasePattern); assert.equal(value.username, username);
    return value.href;
  };
  const identityMigrationUrl = databaseUrl('WORKSHOP_RAG', 'migration', /^\/dvaia_test_workshop_rag_[a-f0-9]+$/, 'dvaia_identity_migration');
  const identityRuntimeUrl = databaseUrl('WORKSHOP_RAG', 'runtime', /^\/dvaia_test_workshop_rag_[a-f0-9]+$/, 'dvaia_identity_runtime');
  const csrfMigrationUrl = databaseUrl('CSRF_CLEAN_RAG', 'migration', /^\/dvaia_test_csrf_clean_rag_[a-f0-9]+$/, 'dvaia_csrf_migration');
  const csrfRuntimeUrl = databaseUrl('CSRF_CLEAN_RAG', 'runtime', /^\/dvaia_test_csrf_clean_rag_[a-f0-9]+$/, 'dvaia_csrf_runtime');
  Object.assign(process.env, { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    IDENTITY_DATABASE_URL: identityRuntimeUrl, IDENTITY_MIGRATION_DATABASE_URL: identityMigrationUrl,
    CSRF_WORKSHOP_DATABASE_URL: csrfRuntimeUrl, CSRF_WORKSHOP_MIGRATION_DATABASE_URL: csrfMigrationUrl,
    AI_PROVIDER: 'mock', JUDGE_PROVIDER: 'mock' });
  const migration = new Pool({ connectionString: identityMigrationUrl, max: 2 });
  const csrfMigration = new Pool({ connectionString: csrfMigrationUrl, max: 2 });
  const pools = [migration, csrfMigration]; const servers = []; const runtimes = []; const routes = []; const authRouters = [];
  const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH;
  assert.ok(path.isAbsolute(evidencePath) && !path.resolve(evidencePath).startsWith(process.cwd() + path.sep));
  const evidence = { status: 'incomplete', scope: 'Current mounted CSRF clean-query route with canonical identity and teaching authority, durable PostgreSQL sources, real cached CPU embeddings, and a controlled plain-text summarizer; no actual summarizer model, HTML/effect, attack, Judge, or credit claim.' };
  const save = () => fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 }); save();
  let originalLoad; let Module;
  try {
    const { migrate } = require('../../db/postgres/migrate');
    await migrate(migration, path.resolve('db/postgres/identity-migrations'));
    assert.deepEqual(await migrate(migration, path.resolve('db/postgres/identity-migrations')), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const csrfPool = require('../../server/database/postgres').createPool(process.env, 'CSRF_WORKSHOP_DATABASE_URL', { purpose: 'workshop' });
    const csrfStore = require('../../server/database/postgres/csrfWorkshopDb').createCsrfWorkshopDb(csrfPool);
    await csrfStore.initialize(csrfMigration);
    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const password = randomUUID();
    const passwordHash = await require('bcryptjs').hash(password, 4);
    const user = await adapter.repository.createUser({ username: `csrf-clean-${randomUUID()}`, email: `${randomUUID()}@example.invalid`, passwordHash });
    await migration.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,'csrf_workshop','vulnerable')", [user.id]);
    const beforeCredit = await migration.query("SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='csrf_workshop'", [user.id]);
    const ai = require('../../server/services/multiProviderAIService');
    let summaryCalls = 0;
    ai.chatWithMessages = async (messages, options) => {
      assert.equal(options.allowFallback, false); assert.equal(typeof messages[1].content, 'string');
      assert.match(messages[1].content, /reset your password/i);
      assert.match(messages[1].content, /expires in 30 minutes/i);
      assert.doesNotMatch(messages[1].content, /<[^>]+>/); summaryCalls++;
      return { response: 'CONTROLLED_CLEAN_SUMMARY: password-reset guidance comes from the canonical clean knowledge base.', provider: 'controlled-native', model: 'plain-text-marker-v1' };
    };
    Module = require('node:module'); originalLoad = Module._load;
    Module._load = function(name, ...args) { if (name === 'sqlite3' || name === 'better-sqlite3' || /(?:^|\/)authDb$/.test(name)) throw new Error('Legacy database forbidden'); return originalLoad.call(this, name, ...args); };
    const embedder = require('../../server/services/secureshopProductEmbedder').createSecureShopProductEmbedder();
    const createComposition = async () => {
      const composition = require('../../server/services/workshopRagComposition').createWorkshopRagComposition({
        pool: adapter.pool, identityAdapter: adapter,
        assertReady: pool => require('../../server/services/workshopRagReadiness').assertWorkshopRagReadiness({ pool, expectedDatabase: new URL(identityRuntimeUrl).pathname.slice(1) }),
        embedder,
      });
      await composition.initialize(); return composition;
    };
    const start = async composition => {
      const effectPool = require('../../server/database/postgres').createPool(process.env, 'IDENTITY_DATABASE_URL', { purpose: 'teaching' });
      const runtime = require('../../server/services/teachingSessionRuntime').createTeachingSessionRuntime({ adapter, effectPool });
      runtimes.push(runtime); await runtime.initialize();
      const routePath = require.resolve('../../server/routes/csrfWorkshop'); delete require.cache[routePath];
      const route = require(routePath); routes.push(route); route.configureDurableRag(composition);
      const express = require('express'); const app = express(); app.use(runtime.middleware); app.use(express.json());
      const pass = (_req, _res, next) => next();
      const auth = require('../../server/routes/postgresAuth').createPostgresAuthRouter({ adapter, limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass } });
      authRouters.push(auth); app.use('/auth', auth); app.use(route.configureTeachingSessions(runtime));
      app.use('/api/workshop', async (req, res, next) => { try { const match = /^Bearer (.+)$/.exec(req.headers.authorization || ''); const found = match && await adapter.validateSession(match[1]); if (!found) return res.sendStatus(401); req.user = found.user; req.identitySession = found.session; next(); } catch { res.sendStatus(401); } });
      app.use('/api/workshop/csrf', route);
      const server = app.listen(0, '127.0.0.1'); servers.push(server); await new Promise(resolve => server.once('listening', resolve));
      return { origin: `http://127.0.0.1:${server.address().port}`, route, server };
    };
    const login = async origin => { const response = await fetch(origin + '/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: user.username, password }) }); assert.equal(response.status, 200); return { cookie: response.headers.get('set-cookie').split(';')[0], ...(await response.json()) }; };
    const exercise = async mounted => {
      const auth = await login(mounted.origin); const headers = { authorization: `Bearer ${auth.token}`, cookie: auth.cookie, 'content-type': 'application/json' };
      const call = async (suffix, body) => { const response = await fetch(mounted.origin + '/api/workshop/csrf' + suffix, { method: body ? 'POST' : 'GET', headers, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(60000) }); return { status: response.status, body: await response.json() }; };
      const state = await call('/rag/state'); assert.equal(state.status, 200, JSON.stringify(state.body)); assert.equal(state.body.poisoned, false); assert.equal(state.body.retrievalReady, true);
      const toggle = await call('/agent-chat-toggle?tab=indirect', { enabled: true }); assert.equal(toggle.status, 200, JSON.stringify(toggle.body));
      const before = await call('/victim-state?tab=indirect'); assert.equal(before.status, 200);
      const answer = await call('/chat?tab=indirect', { message: 'What does the clean knowledge base say about password resets?' });
      assert.equal(answer.status, 200, JSON.stringify(answer.body)); assert.equal(answer.body.response, 'CONTROLLED_CLEAN_SUMMARY: password-reset guidance comes from the canonical clean knowledge base.');
      assert.doesNotMatch(answer.body.response, /<[^>]+>/); assert.equal('ragHtml' in answer.body, false); assert.equal('forged' in answer.body, false);
      assert.equal(answer.body.llmOk, true); assert.deepEqual(answer.body.newlyCompleted, []); assert.equal(answer.body.victimState.ragPoisoned, false);
      const after = await call('/victim-state?tab=indirect'); assert.equal(after.status, 200); assert.deepEqual(after.body, before.body);
      return { state: state.body, answer: { tab: answer.body.tab, llmOk: answer.body.llmOk, newlyCompleted: answer.body.newlyCompleted } };
    };
    const firstComposition = await createComposition(); const first = await start(firstComposition); const firstResult = await exercise(first);
    const firstSelection = (await migration.query("SELECT document_id::text, generation::text FROM workshop_rag.slots WHERE owner_id=$1 AND family='CSRF' AND slot='clean'", [user.id])).rows[0];
    assert.ok(firstSelection?.document_id);
    await new Promise(resolve => first.server.close(resolve)); servers.splice(servers.indexOf(first.server), 1); await first.route.closeBrowser(); routes.splice(routes.indexOf(first.route), 1);
    const secondComposition = await createComposition(); const second = await start(secondComposition); const secondResult = await exercise(second);
    const inspectionAuth = await login(second.origin);
    const inspectionSession = await adapter.validateSession(inspectionAuth.token);
    const scope = await secondComposition.resolveRequest({ user: { id: user.id }, identitySession: { id: inspectionSession.session.id }, headers: { authorization: `Bearer ${inspectionAuth.token}` } });
    const clean = await scope.read({ family: 'CSRF', slot: 'clean' }); assert.ok(clean.documentId); assert.equal(clean.resourceGeneration, '0');
    assert.deepEqual({ document_id: clean.documentId, generation: clean.resourceGeneration }, firstSelection);
    const poison = await scope.read({ family: 'CSRF', slot: 'poison' }); assert.equal(poison.document, null); assert.equal(poison.documentId, null);
    const sourceCount = await migration.query("SELECT count(*)::int AS n FROM workshop_rag.documents WHERE owner_id=$1 AND family='CSRF' AND ingestion_kind='canonical_clean'", [user.id]);
    assert.equal(sourceCount.rows[0].n, 1); assert.equal(summaryCalls, 2);
    const embeddings = await migration.query("SELECT r.runtime_fingerprint,array_length(v.embedding,1)::int AS dimensions FROM workshop_rag.embedding_heads h JOIN workshop_rag.embedding_revisions r USING(revision_id) JOIN workshop_rag.embedding_vectors v USING(revision_id) WHERE h.document_id=$1", [clean.documentId]);
    assert.ok(embeddings.rows.length > 0); assert.ok(embeddings.rows.every(row => row.dimensions === 384));
    assert.ok(embeddings.rows.every(row => /^[a-f0-9]{64}$/.test(row.runtime_fingerprint)));
    assert.equal(embeddings.rows[0].runtime_fingerprint, embedder.getRuntimeFingerprint().fingerprint);
    const afterCredit = await migration.query("SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='csrf_workshop'", [user.id]); assert.deepEqual(afterCredit.rows, beforeCredit.rows);
    evidence.status = 'passed'; evidence.checks = ['state reports retrievalReady with no poison slot','controlled summarizer received canonical password-reset content','real cached CPU embeddings persist as 384 dimensions with current runtime fingerprint','fresh route/composition restored the same clean document and generation','plain response has no HTML, forged effect, victim-state change, or new completion'];
    evidence.observed = { first: firstResult, restored: secondResult, cleanDocumentId: clean.documentId, cleanGeneration: clean.resourceGeneration, canonicalCleanDocumentCount: sourceCount.rows[0].n, poisonDocument: null, summaryCalls, embeddingDimensions: [...new Set(embeddings.rows.map(row => row.dimensions))], embeddingFingerprint: embedder.getRuntimeFingerprint() }; save();
  } catch (error) { evidence.failure = { name: error.name, code: error.code || null, message: error.message }; save(); throw error; }
  finally {
    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    await Promise.all(routes.map(route => route.closeBrowser()));
    await Promise.all(authRouters.map(router => router.close?.())); await Promise.all(runtimes.map(runtime => runtime.close()));
    await require('../../server/database/postgres').closePostgresPools(); await Promise.all(pools.map(pool => pool.end()));
    if (Module && originalLoad) Module._load = originalLoad;
  }
});
