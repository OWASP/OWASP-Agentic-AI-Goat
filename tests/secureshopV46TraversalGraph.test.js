'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
const { createSecureShopV46TraversalWriter } = require('../server/services/secureshopV46TraversalWriter');
const { createSecureShopV46TraversalApplication } = require('../server/services/secureshopV46TraversalApplication');
const { createSecureShopBoundUploadGraph } = require('../server/services/secureshopBoundUploadGraph');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { REGISTRY_SHA256 } = require('../server/services/secureshopBoundAclRegistry');
const { buildTraversalCandidate } = require('../server/services/secureshopV46TraversalEvidence');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');

test('V46 controlled graph uses the real bounded runner, unchanged sink, immutable effect and no asset capability', async t => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'ss-v46-graph-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 46, platformSessionId: 64 };
  const persona = { id: 146, role: 'customer' }, personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const target = createSceneBinding({ ...scope, targetId: randomUUID() }, {
    sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(), execution: scope, withLease: work => work()
  });
  const sessionId = randomUUID(), requestId = randomUUID(), runId = randomUUID();
  const messages = [], traces = [], turns = new Map(), effects = new Map(), admissions = new Map();
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  let savedTurn;
  const conversationRepository = {
    async getBoundSession() { return { id: sessionId, state: 'active', purpose: 'secureshop_avatar_upload',
      binding: { ...scope, shopUserId: persona.id, role: 'customer' } }; },
    async getMessages() { return messages; }, async appendMessage(_id, _binding, value) { messages.push(value); },
    async getTokens() { return 0; }, async addTokens() {},
    async appendTraces(_id, _binding, rows) { traces.push(...rows); }
  };
  const turnJournal = {
    async claim(input) { return turns.has(input.requestId) ? { status: 'completed', result: turns.get(input.requestId) }
      : { status: 'claimed', claimId: randomUUID() }; },
    async complete(input) { savedTurn = structuredClone(input); turns.set(input.requestId, input.result); }, async markUncertain() {}
  };
  const uploadJournal = {
    async claim(raw) { const value = normalizeAdmission(raw); admissions.set(value.operationId, value);
      return Object.freeze({ ...value, replayed: false }); },
    async recordEffect(admission, value) { const effect = normalizeEffect(value, admission); effects.set(admission.operationId, effect); return effect; }
  };
  let writes = 0, modelCalls = 0, mints = 0, modeName = 'vuln';
  const writer = createSecureShopV46TraversalWriter({ environment: { SECURESHOP_UPLOAD_ROOT: root } });
  const application = createSecureShopV46TraversalApplication({
    effects: { find: async admission => effects.get(admission.operationId) || null }, journal: uploadJournal,
    writer: { async writeAndReadBack(input) { writes++; return writer.writeAndReadBack(input); } }
  });
  const graph = createSecureShopBoundUploadGraph({
    launches: { async assertCurrent() {} }, conversationRepository, journal: turnJournal,
    coordinator: { async run(_id, options, work) { const admitted = await options.admit(); if (admitted.skip) return admitted.value;
      return work({ runId, ownerKey, generation: 1, durableGeneration: '1',
        async check() {}, async effect(_key, workEffect) { return workEffect(); },
        async effectWithReceipt(key, workEffect) { return { value: await workEffect(), receipt: { version: 1, runId,
          ownerKey, generation: '1', effectKey: `${options.idempotencyKey}:${key}`, status: 'completed' } }; }, async trace() {} }); } },
    provider: {
      async chat(input) { modelCalls++; assert.equal(input.closedToolCatalog, true); return { provider: 'controlled-provider', model: 'controlled-v46', mocked: false,
        stop_reason: 'tool_use', tool_uses: [{ id: 'v46-call', name: 'uploads.upload_avatar', args: {} }] }; },
      async finalResponse() { modelCalls++; return { provider: 'controlled-provider', model: 'controlled-v46', mocked: false,
        responseMode: 'structured_final', stop_reason: 'end_turn', text: 'Stored bounded traversal attachment.' }; }
    },
    uploadApplication: application, uploadJournal,
    personaAuthority: { async capture() { return { binding: { ...scope, personaId: persona.id, role: 'customer', ...personaSession },
      async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work(); } }; } },
    modeAuthority: { async capture() { return { snapshot: { version: 1, featureId: 'uploads',
      policyVersion: 'owner-bound-avatar-extension-policy-v1', mode: modeName, generation: 0, modeStamp: 'a'.repeat(64) }, async assertCurrent() {} }; }, assertToken: value => value },
    toolPolicyRepository: { async admitTool(input) { return { admissionId: randomUUID(), runId: input.runId,
      invocationId: input.invocationId, toolKey: 'uploads.upload_avatar', policyVersion: '1', registrySha256: REGISTRY_SHA256,
      enforcement: true, allowed: true, action: 'dispatch', policyViolation: null }; } },
    assetOrigin: 'http://127.0.0.2:9083', assetCapability: { mint() { mints++; throw Error('Traversal must not mint'); } },
    resolveTarget: async () => target, assertUploadCurrent: async () => {},
    verifyEffect: async admission => effects.get(admission.operationId) || null, traversal: true
  });
  const input = { scope, persona, personaSession, sessionId, requestId, message: 'Use the logical filename.',
    attachment: { bytes: Buffer.from('owned-v46'), filename: 'source.txt', logicalFilename: '....//escaped.txt', mime: 'text/plain', public: false } };
  const result = await graph.run(input), envelope = JSON.parse(result.taskMetadata.boundUpload.originalEnvelope);
  assert.equal(result.taskMetadata.boundUpload.version, 2);
  assert.equal(result.taskMetadata.boundUpload.variant, 'path_traversal_upload');
  assert.equal(result.taskMetadata.boundUpload.operationRelativePath, 'avatars/escaped.txt');
  assert.equal(result.taskMetadata.boundUpload.escapedAvatarSubdirectory, true);
  assert.equal(envelope.attachment.sourceFilename, 'source.txt');
  assert.equal(envelope.attachment.filename, '....//escaped.txt');
  assert.equal(result.hops[0].params && Object.keys(result.hops[0].params).length, 0);
  assert.equal(effects.values().next().value.file.isTraversal, true);
  assert.equal(writes, 1); assert.equal(modelCalls, 2); assert.equal(mints, 0);
  const original = result.taskMetadata.boundUpload;
  const effect = effects.get(original.operationId), admission = admissions.get(original.operationId);
  const storedBytes = await fs.readFile(path.join(root, effect.file.storedVirtualPath));
  const candidate = buildTraversalCandidate({
    binding: savedTurn.binding, personaSession,
    row: { session_id: savedTurn.sessionId, request_id: savedTurn.requestId, status: 'completed',
      request_version: 1, request_hash: createTurnRequest(savedTurn).hash, result_json: savedTurn.result },
    traces, retained: { admission, effect,
      readback: { byteCount: storedBytes.length, bodySha256: createHash('sha256').update(storedBytes).digest('hex') } },
    graphEffect: { run_id: original.graphEffect.runId, owner_key: original.graphEffect.ownerKey,
      generation: original.graphEffect.generation, effect_key: original.graphEffect.effectKey,
      status: 'completed', run_status: 'completed', live_generation: '1' },
    qualifyModel: identity => identity.provider === 'controlled-provider' && identity.model === 'controlled-v46'
  });
  assert.ok(candidate, 'current production upload graph and physical readback must build traversal evidence');
  assert.equal(candidate.objectiveId, 'ss_upload_path_traversal_write');
  assert.equal((await graph.run(input)).replayed, true);
  assert.equal(writes, 1); assert.equal(modelCalls, 2); assert.equal(mints, 0);
  modeName = 'fixed';
  const fixed = await graph.run({ ...input, requestId: randomUUID() });
  assert.equal(fixed.taskMetadata.boundUpload.outcome, 'denied');
  assert.equal(Object.hasOwn(fixed.taskMetadata.boundUpload, 'operationRelativePath'), false);
  assert.equal(writes, 1); assert.equal(mints, 0);
});
