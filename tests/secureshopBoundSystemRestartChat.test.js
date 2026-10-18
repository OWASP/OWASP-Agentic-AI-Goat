'use strict';
const controlledRestartModeAuthority={capture:async()=>({snapshot:{mode:'vuln'},assertCurrent:async()=>{}}),assertToken:t=>t};

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const C = require('../server/services/secureshopRoleSystemRestartProposal');
const { createBoundSystemRestartChat } = require('../server/services/secureshopBoundSystemRestartChat');
const { createBoundSystemRestartService } = require('../server/services/secureshopBoundSystemRestartService');
const { restartRequestDigest } = require('../server/services/secureshopSystemRestartContract');
const { createSecureShopSystemRestartClient, CAPABILITY } = require('../server/services/secureshopSystemRestartClient');

const sha = text => createHash('sha256').update(text).digest('hex');
const reorder = value => Array.isArray(value) ? value.map(reorder) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).reverse().map(key => [key, reorder(value[key])])) : value;
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const context = () => ({ scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: 17, platformSessionId: 19 }, persona: { id: 23, role: 'admin' },
personaSession: { sessionId: randomUUID(), authorityVersion: '1' } });
const source = () => ({ sessionId: randomUUID(), requestId: randomUUID() });
const origin = { step: 2, callId: 'restart-prepare-1' };

function receipt(targetId, operationId, name) {
  return { version: 'secureshop-owned-system-restart-http.v2', targetId, operationId,
    requestSha256: restartRequestDigest({ version: 1, operationId, name }),
    beforeInstanceId: randomUUID(), afterInstanceId: randomUUID(), beforeGeneration: 1,
    afterGeneration: 2, effectSha256: 'a'.repeat(64), outputText: '',
    outputSha256: sha(''), outputBytes: 0, ownedCommandEffectSha256: 'c'.repeat(64),
    ownedCommandEffectFiles: 2, ownedCommandEffectBytes: 6,
    command: `systemctl restart ${name}`, status: 'completed', isolation: 'owned-restart-namespace-v1' };
}
function storedReceipt(targetId, operationId, name) {
  const full = receipt(targetId, operationId, name);
  return Object.fromEntries(['beforeInstanceId', 'afterInstanceId', 'beforeGeneration',
    'afterGeneration', 'effectSha256', 'outputSha256', 'outputBytes', 'outputText']
    .map(key => [key, full[key]]));
}

test('restart preparation binds the original source and target without executing', async () => {
  const targetId = randomUUID(), ctx = context(), src = source(), calls = [];
  const service = { async administration() { calls.push('administration');
    return { restartCapability: CAPABILITY, targetId }; },
  async execute() { calls.push('execute'); assert.fail('preparation cannot restart'); },
  async operation() { assert.fail('preparation cannot read an operation'); } };
  const chat = createBoundSystemRestartChat({ getRestart: async () => ({ ready: true, service }) });
  const proposal = await chat.prepare({ context: ctx, source: src, origin,
    name: 'nginx; touch /owned-effect/witness', modeCapability });
  assert.deepEqual(calls, ['administration']);
  assert.equal(proposal.proposalId, C.validateRoleSystemRestartProposal(reorder(proposal), src).proposalId);
  assert.equal(proposal.scopeKey, sha(JSON.stringify({ restartTargetId: targetId })));
  assert.equal(proposal.requestSha256, restartRequestDigest({ version: 1,
    operationId: proposal.proposalId, name: proposal.name }));
  assert.deepEqual(Object.keys(C.projectRoleSystemRestartProposal(proposal, src)).sort(),
    ['version', 'proposalId', 'action', 'name', 'targetId', 'scopeKey',
      'sourceSnapshotSha256', 'modeCapability', 'requestSha256', 'proposalSha256'].sort());
  assert.throws(() => C.validateRoleSystemRestartProposal({ ...proposal, name: 'other' }, src));
  assert.throws(() => C.validateRoleSystemRestartProposal(proposal, { ...src, requestId: randomUUID() }));
  assert.throws(() => C.validateRoleSystemRestartProposal({ ...proposal,
    sourceSnapshotSha256: 'f'.repeat(64) }, src));
  assert.throws(() => C.createRoleSystemRestartProposal({ context: ctx,
    administration: { restartCapability: CAPABILITY, targetId }, source: src, origin,
    name: '', modeCapability }));
});

test('restart confirm rereads target, checks scene, then uses the existing exact operation', async () => {
  const targetId = randomUUID(), ctx = context(), src = source(), calls = [];
  let administrationTarget = targetId;
  const service = { async administration() { calls.push('administration');
    return { restartCapability: CAPABILITY, targetId: administrationTarget }; },
  async execute(input, options) {
    calls.push('execute');
    assert.equal(input.operationId, proposal.proposalId);
    assert.equal(input.name, proposal.name);
    assert.equal(typeof options.beforeEffect, 'function');
    await options.beforeEffect();
    const result = storedReceipt(targetId, proposal.proposalId, proposal.name);
    return { state: 'completed', operationId: proposal.proposalId,
      targetId, requestSha256: proposal.requestSha256, receipt: result };
  }, async operation(input) { calls.push('operation');
    assert.equal(input.operationId, proposal.proposalId);
    return { state: 'completed', operationId: proposal.proposalId,
      targetId, requestSha256: proposal.requestSha256,
      receipt: storedReceipt(targetId, proposal.proposalId, proposal.name) }; } };
  const chat = createBoundSystemRestartChat({ getRestart: async () => ({ ready: true, service }) });
  const proposal = await chat.prepare({ context: ctx, source: src, origin,
    name: 'owned-service', modeCapability });
  calls.length = 0;
  const result = await chat.confirm({ context: ctx, source: src, proposal,
    beforeEffect: async () => calls.push('scene') });
  assert.deepEqual(calls, ['administration', 'scene', 'execute', 'scene']);
  assert.equal(result.ok, true);
  assert.equal(result.operationId, proposal.proposalId);
  assert.equal(result.requestSha256, proposal.requestSha256);
  assert.equal((await chat.operation({ context: ctx, source: src, proposal })).ok, true);
  administrationTarget = randomUUID();
  await assert.rejects(chat.confirm({ context: ctx, source: src, proposal,
    beforeEffect: async () => assert.fail('stale target may not reach scene callback') }),
  { code: 'SYSTEM_RESTART_CHAT_SCOPE_MISMATCH' });
  assert.deepEqual(calls.slice(-1), ['administration']);
});

test('scene loss before POST records no effect; scene loss after POST records uncertainty for exact GET', async () => {
  for (const changedAt of [2, 3]) {
    const targetId = randomUUID(), operationId = randomUUID(), before = randomUUID();
    const input = { operationId, name: 'owned-service' };
    const events = [], saved = { state: 'running', operationId,
      requestSha256: restartRequestDigest({ version: 1, ...input }), targetId };
    const repository = { async ensureTarget() { events.push('ensure'); },
      async begin() { events.push('begin'); return { ...saved, workerToken: randomUUID() }; },
      async assertCurrent() { events.push('repository-current'); },
      async complete() { assert.fail('a stale scene cannot publish a completed chat operation'); },
      async fail(_raw, value) { saved.state = 'failed'; saved.failureCode = value.code;
        events.push(`failed:${value.code}`); },
      async operation() { return { ...saved }; } };
    const fetchImpl = async url => {
      const path = new URL(url).pathname;
      if (path.endsWith('/restart-health')) return Response.json({
        version: 'secureshop-owned-system-restart-http.v2', ready: true,
        isolation: 'owned-restart-namespace-v1', restartCapability: CAPABILITY,
        limits: { maxPersistedTargets: 200, maxResidentTargets: 32,
          maxConcurrentExecutions: 4, maxQueuedExecutions: 16 } });
      if (path.endsWith('/restart-target')) return Response.json({
        version: 'secureshop-owned-system-restart-http.v2', isolation: 'owned-restart-namespace-v1',
        targetId, instanceId: before, generation: 1, resident: true });
      if (path.endsWith('/restart')) {
        events.push('sidecar-POST');
        return Response.json(receipt(targetId, operationId, input.name));
      }
      assert.fail('unexpected private transport');
    };
    const client = createSecureShopSystemRestartClient({ baseURL: 'http://127.0.0.1:19091/',
      token: 'x'.repeat(43), fetchImpl });
    const service = createBoundSystemRestartService({modeAuthority:controlledRestartModeAuthority, repository, client,
      resolveTarget: async () => ({ targetId }) });
    let checks = 0;
    const work = service.execute(input, { beforeEffect: async () => {
      checks++;
      if (checks === changedAt) throw Object.assign(Error('scene changed'), { code: 'SHOP_SCENE_STALE' });
    } });
    if (changedAt === 2) {
      await assert.rejects(work, { code: 'SHOP_SCENE_STALE' });
      assert.equal(events.includes('sidecar-POST'), false);
      assert.equal(saved.failureCode, 'EXECUTION_FAILED');
    } else {
      await assert.rejects(work, { code: 'SYSTEM_RESTART_OUTCOME_UNCERTAIN', automaticRetry: false });
      assert.equal(events.filter(e => e === 'sidecar-POST').length, 1);
      assert.equal(saved.failureCode, 'OUTCOME_UNCERTAIN');
    }
    assert.equal((await service.operation({ operationId })).failureCode, saved.failureCode);
  }
});

test('lost publication after a validated sidecar receipt remains uncertain, never safely failed', async () => {
  const targetId = randomUUID(), operationId = randomUUID(), name = 'owned-service';
  const saved = { state: 'running', operationId, targetId,
    requestSha256: restartRequestDigest({ version: 1, operationId, name }) };
  const repository = { async ensureTarget() {},
    async begin() { return { ...saved, workerToken: randomUUID() }; },
    async assertCurrent() {},
    async complete() { throw Error('completion reply or transaction failed'); },
    async fail(_raw, value) { saved.state = 'failed'; saved.failureCode = value.code; },
    async operation() { return { ...saved }; } };
  const client = { async health() {}, async inspect() { return { instanceId: randomUUID(), generation: 1 }; },
    async execute(_wire, { assertCurrent }) { await assertCurrent();
      return receipt(targetId, operationId, name); } };
  const service = createBoundSystemRestartService({modeAuthority:controlledRestartModeAuthority, repository, client,
    resolveTarget: async () => ({ targetId }) });
  await assert.rejects(service.execute({ operationId, name }, { beforeEffect: async () => {} }),
    { code: 'SYSTEM_RESTART_OUTCOME_UNCERTAIN', automaticRetry: false });
  assert.equal((await service.operation({ operationId })).failureCode, 'OUTCOME_UNCERTAIN');
});
