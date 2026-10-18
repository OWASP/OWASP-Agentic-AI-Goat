'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createPool, closePostgresPools } = require('../../server/database/postgres');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createPostgresIdentityAdapter } = require('../../server/services/postgresIdentityAdapter');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
const { createWorkshopConfigRepository } = require('../../server/database/postgres/workshopConfigRepository');
const { createPostgresPromptInjectionProgressService } = require('../../server/services/promptInjectionProgressService');
const { createPostgresRagProgressStore } = require('../../server/services/ragProgressStore');
const { createObjectiveCompletionService } = require('../../server/services/objectiveCompletionService');
const { createObjectiveJudgmentRepository } = require('../../server/database/postgres/objectiveJudgmentRepository');
const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
const { randomUUID } = require('node:crypto');
const {
  createPostgresWorkshopResetAdapters,
  createPostgresWorkshopResetService,
} = require('../../server/services/postgresWorkshopResetService');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!process.env.PG_PROMPT_RAG_TEST_RUNTIME_URL;

test('native DPI and RAG progress preserve thresholds, canonical visibility and owner reset', { skip: !enabled }, async () => {
  process.env.JWT_SECRET = require('node:crypto').randomBytes(48).toString('hex');
  const runtime = createPool(process.env, 'PG_PROMPT_RAG_TEST_RUNTIME_URL');
  const migration = createPool(process.env, 'PG_PROMPT_RAG_TEST_MIGRATION_URL');
  let server;
  try {
    await initializeIdentityRepository(runtime, migration);
    await seedWorkshopPlatform(migration);
    const identity = createIdentityRepository(runtime);
    const user = await identity.createUser({
      username: `prompt-rag-${Date.now()}`,
      email: `prompt-rag-${Date.now()}@example.test`,
      passwordHash: await require('bcryptjs').hash('FixtureUser@123', 4),
    });
    const stores = {
      pool: runtime,
      progress: createWorkshopProgressRepository(runtime),
      config: createWorkshopConfigRepository(runtime),
    };
    const auth = createPostgresIdentityAdapter({
      repository: identity,
      progress: stores.progress,
      jwtSecret: process.env.JWT_SECRET,
    });
    const session = await auth.createSession(await identity.findCredentialById(user.id), {
      get: () => null,
      ip: '127.0.0.1',
    });
    const dpi = createPostgresPromptInjectionProgressService(stores);
    const identityArgs = { userId: user.id, userKey: String(user.id) };
    const completion = createObjectiveCompletionService({
      receipts: createObjectiveJudgmentRepository(runtime), progress: stores.progress,
      judge: async (packet) => {
        const prepared = prepareJudgeInput(packet);
        return { family: packet.rubric.family, scenario: packet.rubric.scenario,
          objectiveId: packet.rubric.objectiveId, rubricVersion: packet.rubric.version,
          evidenceDigest: prepared.evidenceDigest, runId: packet.execution.runId,
          mode: packet.rubric.mode, verdict: 'pass', explanation: 'Observed valid AWS interaction.',
          criteria: [{ id: 'observed_objective', satisfied: true, evidenceRefs: ['response'] }] };
      },
    });
    const gradePractice = async () => {
      const execution = { runId: randomUUID(), check: async () => {} };
      const attempt = await completion.beginAttempt({ userId: user.id,
        workshopKey: 'direct_prompt_injection', objectiveId: 'interact', execution });
      return completion.evaluate({ userId: user.id, workshopKey: 'direct_prompt_injection', execution, attempt,
        rubric: { family: 'DPI', scenario: 'aws_assistant', objectiveId: 'interact', version: 'dpi-structured-v1', mode: 'vuln',
          criteria: [{ id: 'observed_objective', description: 'Observed valid AWS interaction.', allowedSources: ['assistant_response'] }], requiredFacts: ['required_observation'] },
        evidence: [{ id: 'response', source: 'assistant_response', content: 'AWS S3 stores objects.' }],
        facts: { required_observation: true },
      });
    };
    let grade = await gradePractice();
    assert.equal(grade.completed, false);
    let result = await dpi.getProgress(identityArgs);
    assert.equal(result.objectives.interact.interactionCount, 1);
    assert.equal(result.objectives.interact.completed, false);
    grade = await gradePractice();
    assert.equal(grade.completed, true);
    result = await dpi.getProgress(identityArgs);
    assert.equal(result.objectives.interact.interactionCount, 2);
    assert.equal(result.objectives.interact.completed, true);

    const ragIds = ['rag_upload', 'rag_query', 'rag_clean_doc', 'rag_injected_doc', 'rag_query_injection'];
    const rag = createPostgresRagProgressStore(stores, ragIds);
    await rag.complete({ userKey: String(user.id), objectiveId: 'rag_upload', platformUserId: user.id });
    assert.equal((await rag.get({ platformUserId: user.id })).rag_upload.completed, true);

    Object.assign(process.env, {
      PLATFORM_DATABASE_ENGINE: 'postgres',
      IDENTITY_DATABASE_URL: process.env.PG_PROMPT_RAG_TEST_RUNTIME_URL,
    });
    const promptRouter = require('../../server/routes/promptInjectionWorkshop');
    const ragRouter = require('../../server/routes/ragInjection');
    assert.equal(Object.keys(require.cache).some((file) => /node_modules\/(sqlite3|better-sqlite3)\//.test(file)), false);
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.user = { id: user.id }; req.session = { userId: user.id }; next(); });
    app.use('/dpi', promptRouter);
    app.use('/rag', ragRouter);
    server = await new Promise((resolve) => {
      const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    const authenticated = { headers: { authorization: `Bearer ${session.token}` } };
    let response = await fetch(`${base}/dpi/progress`, authenticated);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).objectives.interact.completed, true);
    response = await fetch(`${base}/rag/progress`, authenticated);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).objectives.rag_upload.completed, true);

    response = await fetch(`${base}/dpi/progress/reset`, { ...authenticated, method: 'POST' });
    assert.equal(response.status, 200);
    assert.equal((await dpi.getProgress(identityArgs)).objectives.interact.interactionCount, 0);
    response = await fetch(`${base}/rag/progress/reset`, { ...authenticated, method: 'POST' });
    assert.equal(response.status, 200);
    assert.equal((await rag.get({ platformUserId: user.id })).rag_upload.completed, false);

    // The administrative service uses the same owner coordinator boundary as
    // the mounted routes, while canonical reset atomically advances generation
    // and removes DPI's receipt-backed interaction counter.
    await gradePractice();
    await rag.complete({ userKey: String(user.id), objectiveId: 'rag_upload', platformUserId: user.id });
    const beforeDpiGeneration = await stores.progress.getGeneration(user.id, 'direct_prompt_injection');
    const beforeRagGeneration = await stores.progress.getGeneration(user.id, 'indirect_prompt_injection');
    const clearedOwners = [];
    const resetAdapters = createPostgresWorkshopResetAdapters((request) => {
      if (request === '../routes/promptInjectionWorkshop') return { resetOwner: async (_owner, work) => work() };
      if (request === '../routes/ragInjection') return {
        resetOwner: async (_owner, work) => work(),
        clearOwnerState: async (owner) => clearedOwners.push(owner),
      };
      if (request === '../routes/emailAgent') return { resetOwner: async (_owner, work) => work() };
      if (request === './emailArtifactStore') return { assertReady: async () => {}, retireOwner: async () => {} };
      throw new Error(`Unexpected reset dependency: ${request}`);
    });
    const administrativeReset = createPostgresWorkshopResetService({
      progress: stores.progress,
      adapters: resetAdapters,
    });
    await administrativeReset.resetStudent({ userId: user.id, workshopKey: 'direct_prompt_injection' });
    await administrativeReset.resetStudent({ userId: user.id, workshopKey: 'indirect_prompt_injection' });
    assert.equal(await stores.progress.getGeneration(user.id, 'direct_prompt_injection'), beforeDpiGeneration + 1);
    assert.equal(await stores.progress.getGeneration(user.id, 'indirect_prompt_injection'), beforeRagGeneration + 1);
    assert.equal((await dpi.getProgress(identityArgs)).objectives.interact.interactionCount, 0);
    assert.equal((await rag.get({ platformUserId: user.id })).rag_upload.completed, false);
    assert.deepEqual(clearedOwners, [String(user.id)]);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    await Promise.all([runtime.end(), migration.end()]);
    await closePostgresPools();
  }
});
