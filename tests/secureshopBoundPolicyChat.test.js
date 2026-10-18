'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const C = require('../server/services/secureshopRolePolicyProposal');
const R = require('../server/services/secureshopPromptPolicyContract');
const T = require('../server/services/secureshopPromptPolicyTaskMutation');
const { createBoundPolicyChat } = require('../server/services/secureshopBoundPolicyChat');
const { createBoundPromptPolicyService } = require('../server/services/secureshopBoundPromptPolicyService');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const hash = v => createHash('sha256').update(v).digest('hex');
const jsonb = v => Array.isArray(v) ? v.map(jsonb) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().reverse().map(k => [k, jsonb(v[k])])) : v;
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
function fixture(taskTargets = []) {
  const context = { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 }, persona: { id: 3, role: 'admin' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  let head = '1', policies = [], renders = 0, revoked = false;
  const operations = new Map(), calls = [];
  const check = () => { if (revoked) throw Object.assign(Error('revoked'), { code: 'STALE_AUTHORITY' }); };
  const repository = {
    async list() { check(); return { version: head, policies: structuredClone(policies) }; },
    async beginRender(x) {
      check(); calls.push(['begin', structuredClone(x)]);
      const req = x.request.contractVersion === 2 ? T.renderRequest(x.request) : x.request;
      const digests = { requestSha256: R.requestDigest(req), ...(x.request.contractVersion === 2
        ? { policyRequestSha256: T.taskMutationDigest(x.request) } : {}) };
      const prior = operations.get(req.operationId);
      if (prior) {
        assert.deepEqual(prior.input, x, 'same UUID must retain exact request');
        return { state: prior.receipt ? 'completed' : 'pending', operationId: req.operationId,
          ...digests, ...(prior.receipt ? { receipt: jsonb({ ...prior.receipt, replayed: true }) } : {}) };
      }
      if (head !== x.expectedVersion) throw Object.assign(Error('stale'), { code: 'REVISION_CONFLICT' });
      operations.set(req.operationId, { input: structuredClone(x) });
      return { state: 'admitted', operationId: req.operationId, ...digests };
    },
    async publish(x) {
      check(); calls.push(['publish', structuredClone(x)]);
      if (head !== x.expectedVersion) throw Object.assign(Error('stale'), { code: 'REVISION_CONFLICT' });
      if (x.action === 'upsert') {
        head = String(BigInt(head) + 1n);
        policies = [...policies.filter(p => p.name !== x.request.name), { name: x.request.name,
          version: head, markdown: x.request.markdown, targets: x.request.targets }];
      }
      const receipt = { version: head, operationId: x.request.operationId,
        requestSha256: x.renderResult.requestSha256, renderResult: x.renderResult,
        ...(x.request.contractVersion === 2 ? { policyRequestSha256: T.taskMutationDigest(x.request) } : {}) };
      operations.get(x.request.operationId).receipt = structuredClone(receipt);
      return jsonb(receipt);
    },
    async remove(x) {
      check(); calls.push(['remove', structuredClone(x)]);
      const prior = operations.get(x.operationId);
      if (prior) { assert.deepEqual(prior.input, x); return jsonb({ ...prior.receipt, replayed: true }); }
      if (head !== x.expectedVersion) throw Object.assign(Error('stale'), { code: 'REVISION_CONFLICT' });
      head = String(BigInt(head) + 1n); policies = policies.filter(p => p.name !== x.name);
      const receipt = { version: head, operationId: x.operationId,
        requestSha256: canonicalDigest(['prompt-policy-delete-v1', x.scope, x.persona,
          x.personaSession, x.operationId, x.name, x.expectedVersion]), deleted: true };
      operations.set(x.operationId, { input: structuredClone(x), receipt }); return receipt;
    },
    async operation({ operationId }) { check(); const p = operations.get(operationId);
      return p ? p.receipt ? jsonb({ ...p.receipt, replayed: true }) : { state: 'pending', operationId } : null; },
  };
  const renderer = { async render(req) { renders++; const rendered = req.markdown;
    return { version: 1, operationId: req.operationId, requestSha256: R.requestDigest(req),
      isolation: R.ISOLATION, rendered, renderedSha256: hash(rendered), exitCode: 0,
      timedOut: false, truncated: false, drained: true }; } };
  const service = createBoundPromptPolicyService({ repository, renderer });
  const api = createBoundPolicyChat({ service, supportedTaskTargets: taskTargets });
  return { context, api, service, repository, renderer, operations, calls,
    renders: () => renders, revoke: () => { revoked = true; }, advance: () => { head = String(BigInt(head) + 1n); },
    seed: p => { policies = [{ name: 'named', version: head, markdown: 'original', targets: ['admin'], ...p }]; } };
}
async function prepare(f, action = 'create', candidate = { name: 'named', markdown: 'candidate', targets: ['admin'] }) {
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const state = await f.api.snapshot(f.context);
  const selected = action === 'create' ? null : { choiceId: randomUUID(), name: 'named',
    snapshotSha256: state.policies.find(p => p.name === 'named').snapshotSha256 };
  const args = { context: f.context, source, origin: { step: 1, callId: 'call-1' },
    action, selected, candidate, modeCapability };
  return { args, source, proposal: await f.api.prepare(args) };
}
test('preparation preserves full 16KiB raw candidate and JSONB canonical digest without any render or operation', async () => {
  const f = fixture(); const markdown = '{{ teaching_template }}' + 'x'.repeat(16384 - 23);
  assert.equal(Buffer.byteLength(markdown), 16384);
  const { proposal, source } = await prepare(f, 'create', { name: 'named', markdown, targets: ['merchant', 'admin'] });
  assert.equal(proposal.after.markdown, markdown); assert.deepEqual(proposal.after.targets, ['admin', 'merchant']);
  assert.deepEqual(C.validateRolePolicyProposal(jsonb(proposal), source), proposal);
  assert.equal(Object.hasOwn(C.projectRolePolicyProposal(proposal, source), 'origin'), false);
  assert.equal(f.operations.size, 0); assert.equal(f.renders(), 0); assert.deepEqual(f.calls, []);
  await assert.rejects(prepare(f, 'create', { name: 'named', markdown: markdown + 'x', targets: ['admin'] }));
});
test('create, edit, preview and delete use existing service receipts and exact UUID replay after changed state', async () => {
  const f = fixture();
  for (const action of ['create', 'preview', 'edit', 'delete']) {
    const { proposal, source } = await prepare(f, action, action === 'delete' ? null
      : { name: 'named', markdown: action === 'edit' ? 'edited' : 'candidate', targets: ['admin'] });
    const before = await f.api.snapshot(f.context);
    const result = await f.api.confirm({ context: f.context, proposal: jsonb(proposal), source });
    assert.equal(result.ok, true); assert.equal(result.receipt.operationId, proposal.proposalId);
    const after = await f.api.snapshot(f.context);
    assert.equal(after.headVersion, action === 'preview' ? before.headVersion : String(BigInt(before.headVersion) + 1n));
    const rendered = f.renders();
    const replay = { ok: true, receipt: { ...result.receipt, replayed: true } };
    assert.deepEqual(await f.api.confirm({ context: f.context, proposal, source }), replay);
    assert.deepEqual(await f.api.operation({ context: f.context, operationId: proposal.proposalId }), replay);
    assert.equal(f.renders(), rendered);
  }
  assert.equal(f.operations.size, 4); assert.equal(f.renders(), 3);
});
test('create existing name, unchanged edit, renamed candidate and stale selected head fail before admission', async () => {
  const f = fixture(); f.seed();
  await assert.rejects(prepare(f), { code: 'POLICY_NAME_EXISTS' });
  await assert.rejects(prepare(f, 'edit', { name: 'named', markdown: 'original', targets: ['admin'] }), { code: 'POLICY_NO_CHANGE' });
  await assert.rejects(prepare(f, 'edit', { name: 'renamed', markdown: 'new', targets: ['admin'] }), { code: 'POLICY_CHOICE_STALE' });
  const { args } = await prepare(f, 'edit'); f.advance();
  await assert.rejects(f.api.prepare(args), { code: 'POLICY_CHOICE_STALE' });
  assert.deepEqual(f.calls, []); assert.equal(f.renders(), 0);
});
test('configured task targets only; receipt retains separate task and renderer digests', async () => {
  assert.throws(() => fixture(['analytics']));
  const none = fixture();
  await assert.rejects(prepare(none, 'create', { name: 'named', markdown: 'source', targets: ['summarizer'] }));
  const f = fixture(['summarizer']);
  const { proposal, source } = await prepare(f, 'create', { name: 'named', markdown: 'source', targets: ['summarizer'] });
  const result = await f.api.confirm({ context: f.context, proposal, source });
  assert.match(result.receipt.policyRequestSha256, /^[a-f0-9]{64}$/);
  assert.notEqual(result.receipt.policyRequestSha256, result.receipt.requestSha256);
  assert.deepEqual(f.calls.find(c => c[0] === 'begin')[1].request.targets, ['summarizer']);
});
test('scope/session substitution rejects before renderer and does not alter original operation reference', async () => {
  const f = fixture(); const { proposal, source } = await prepare(f);
  const context = { ...f.context, personaSession: { ...f.context.personaSession, sessionId: randomUUID() } };
  await assert.rejects(f.api.confirm({ context, proposal, source }), { code: 'POLICY_SCOPE_MISMATCH' });
  assert.deepEqual(f.calls, []); assert.equal(f.operations.size, 0);
  f.revoke(); await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), { code: 'STALE_AUTHORITY' });
});
test('stale head is existing CAS denial, while a race after render retains a pending receipt and never rerenders', async () => {
  for (const afterRender of [false, true]) {
    const f = fixture(); const { proposal, source } = await prepare(f);
    if (afterRender) { const original = f.renderer.render; f.renderer.render = async request => {
      const result = await original(request); f.advance(); return result;
    }; } else f.advance();
    await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), { code: 'REVISION_CONFLICT' });
    const read = await f.api.operation({ context: f.context, operationId: proposal.proposalId });
    assert.deepEqual(read, afterRender ? { ok: false, state: 'pending', operationId: proposal.proposalId } : null);
    if (afterRender) assert.deepEqual(await f.api.confirm({ context: f.context, proposal, source }), read);
    assert.equal(f.renders(), afterRender ? 1 : 0);
  }
});
test('renderer and authority exceptions propagate without completed or no-effect conversion', async () => {
  const f = fixture(); const { proposal, source } = await prepare(f);
  const error = Object.assign(Error('uncertain'), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' });
  f.renderer.render = async () => { throw error; };
  await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), e => e === error);
  assert.deepEqual(await f.api.operation({ context: f.context, operationId: proposal.proposalId }),
    { ok: false, state: 'pending', operationId: proposal.proposalId });
});
test('closed proposal rejects extra fields, changed source/action/mode, malformed source and invalid bytes', async () => {
  const f = fixture(); const { proposal, source } = await prepare(f);
  for (const p of [{ ...proposal, extra: true }, { ...proposal, action: 'preview' },
    { ...proposal, after: { ...proposal.after, markdown: 'substituted' } },
    { ...proposal, modeCapability: { ...modeCapability, effectiveMode: 'other' } }]) {
    assert.throws(() => C.validateRolePolicyProposal(p, source));
  }
  assert.throws(() => C.validateRolePolicyProposal(proposal, { ...source, requestId: randomUUID() }));
  for (const markdown of ['\0', '\ud800']) await assert.rejects(prepare(f, 'create', { name: 'named', markdown, targets: ['admin'] }));
  assert.equal(f.operations.size, 0);
});
test('retained disabled targets stay inspectable/deletable but cannot be newly assigned or rendered', async () => {
  const f = fixture(); f.seed({ targets: ['analytics'] });
  const state = await f.api.snapshot(f.context);
  assert.deepEqual(state.policies[0].targets, ['analytics']);
  assert.equal(state.supportedTargets.includes('analytics'), false);
  await assert.rejects(prepare(f, 'preview', { name: 'named', markdown: 'original', targets: ['analytics'] }));
  const { proposal, source } = await prepare(f, 'delete', null);
  assert.deepEqual(proposal.before.targets, ['analytics']);
  assert.equal((await f.api.confirm({ context: f.context, proposal, source })).receipt.deleted, true);
});
test('authority version limit matches repository and delete verifies the exact existing receipt digest', async () => {
  const f = fixture(); f.seed();
  const { proposal, source } = await prepare(f, 'delete', null);
  for (const v of ['9007199254740991', '9223372036854775807']) {
    assert.throws(() => C.createRolePolicyProposal({ source, origin: proposal.origin,
      action: 'delete', selected: { choiceId: proposal.choiceId, snapshotSha256: proposal.sourceSnapshotSha256 },
      before: proposal.before, after: null, name: proposal.name, expectedVersion: v,
      scopeKey: proposal.scopeKey, modeCapability }, C.policySupportedTargets([])));
  }
  const remove = f.service.remove;
  // A well-shaped but substituted digest must never be projected as success.
  const api = createBoundPolicyChat({ service: { ...f.service,
    remove: async input => ({ ...await remove(input), requestSha256: 'a'.repeat(64) }) } });
  await assert.rejects(api.confirm({ context: f.context, proposal, source }), { code: 'POLICY_CHAT_STATE_INVALID' });
});
test('terminal valid head remains readable even though existing repository disallows another admission at that version', async () => {
  const f = fixture();
  f.repository.list = async () => ({ version: '9007199254740991', policies: [{ name: 'named',
    version: '9007199254740991', markdown: 'retained', targets: ['admin'] }] });
  const state = await f.api.snapshot(f.context);
  assert.equal(state.headVersion, '9007199254740991');
  assert.match(state.policies[0].snapshotSha256, /^[a-f0-9]{64}$/);
  await assert.rejects(prepare(f, 'preview', { name: 'named', markdown: 'retained', targets: ['admin'] }),
    { code: 'ROLE_POLICY_PROPOSAL_INVALID' });
  assert.equal(f.operations.size, 0);
});
test('original graph authority is rechecked after asynchronous scope read and before any admission', async () => {
  for (const action of ['create', 'delete']) {
    const f = fixture(); if (action === 'delete') f.seed();
    const { proposal, source } = await prepare(f, action, action === 'delete' ? null
      : { name: 'named', markdown: 'candidate', targets: ['admin'] });
    let changed = false;
    const originalList = f.repository.list;
    f.repository.list = async () => { const value = await originalList(); changed = true; return value; };
    await assert.rejects(f.api.confirm({ context: f.context, proposal, source,
      beforeEffect: async () => { assert.equal(changed, true);
        throw Object.assign(Error('mode changed'), { code: 'STALE_MODE' }); } }), { code: 'STALE_MODE' });
    assert.equal(f.operations.size, 0); assert.deepEqual(f.calls, []);
  }
});
test('abort during scope read prevents admission; abort after admission remains pending with no render', async () => {
  for (const afterAdmission of [false, true]) {
    const f = fixture(); const { proposal, source } = await prepare(f);
    const abort = new AbortController();
    if (afterAdmission) {
      const begin = f.repository.beginRender;
      f.repository.beginRender = async input => { const value = await begin(input); abort.abort(); return value; };
    } else {
      const list = f.repository.list;
      f.repository.list = async () => { const value = await list(); abort.abort(); return value; };
    }
    await assert.rejects(f.api.confirm({ context: f.context, proposal, source, signal: abort.signal }), { name: 'AbortError' });
    assert.equal(f.operations.size, afterAdmission ? 1 : 0); assert.equal(f.renders(), 0);
  }
});
