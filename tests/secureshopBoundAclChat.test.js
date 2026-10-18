'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const C = require('../server/services/secureshopRoleAclProposal');
const { createBoundAclChat } = require('../server/services/secureshopBoundAclChat');

const REGISTRY = 'a'.repeat(64);
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const jsonb = value => Array.isArray(value) ? value.map(jsonb)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().reverse().map(key => [key, jsonb(value[key])]))
    : value;

function fixture() {
  const context = { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 3, platformSessionId: 4 }, persona: { id: 5, role: 'admin' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  const scopeKey = JSON.stringify([context.scope.launchId, context.scope.scenarioId,
    context.scope.generation, context.scope.platformOwnerId, context.scope.platformSessionId,
    context.persona.id]);
  let head = '1', allowed = false, enforcement = false, revoked = false;
  let currentGeneration = context.scope.generation;
  const operations = new Map(), mutations = [];
  const sameContext = x => x.scope.launchId === context.scope.launchId
    && ['scenarioId', 'platformOwnerId', 'platformSessionId'].every(key => x.scope[key] === context.scope[key])
    && x.scope.generation === currentGeneration
    && x.persona.id === context.persona.id && x.persona.role === context.persona.role
    && x.personaSession.authorityVersion === context.personaSession.authorityVersion
    && x.personaSession.sessionId === context.personaSession.sessionId && !revoked;
  const accessControl = {
    async read(x) {
      if (!sameContext(x)) throw Object.assign(Error('denied'), { code: 'SHOP_AUTH_INVALID' });
      return { version: head, enforcement_enabled: enforcement, registrySha256: REGISTRY,
        administration: { versionedPolicy: true, scopeKey }, tools: [
          { tool_name: 'audit.search_by_user', supported: true, readOnly: false,
            applicable_roles: { customer: false, merchant: false, admin: true },
            customer: false, merchant: false, admin: allowed },
          { tool_name: 'retired.tool', supported: false, readOnly: true,
            applicable_roles: { customer: false, merchant: false, admin: false },
            customer: false, merchant: false, admin: false,
            unavailable_reason: 'No supported bound execution workflow' },
        ] };
    },
    async mutate(x) {
      if (!sameContext(x)) throw Object.assign(Error('denied'), { code: 'SHOP_AUTH_INVALID' });
      mutations.push(structuredClone(x));
      const prior = operations.get(x.operationId);
      if (prior) {
        if (prior.expectedVersion !== x.expectedVersion
            || JSON.stringify(prior.change) !== JSON.stringify(x.change)) {
          throw Object.assign(Error('conflict'), { code: 'ACL_OPERATION_CONFLICT' });
        }
        return { receipt: jsonb(prior) };
      }
      if (x.expectedVersion !== head) throw Object.assign(Error('stale'), { code: 'ACL_VERSION_CONFLICT' });
      head = String(BigInt(head) + 1n);
      if (x.change.kind === 'permission') allowed = x.change.allowed;
      else enforcement = x.change.enabled;
      const receipt = { operationId: x.operationId, expectedVersion: x.expectedVersion,
        version: head, registrySha256: REGISTRY, enforcement, change: x.change };
      operations.set(x.operationId, receipt);
      return { receipt: jsonb(receipt) };
    },
    async operation(x) {
      if (!sameContext(x)) throw Object.assign(Error('denied'), { code: 'SHOP_AUTH_INVALID' });
      return operations.has(x.operationId) ? jsonb(operations.get(x.operationId)) : null;
    },
  };
  return { api: createBoundAclChat({ accessControl }), context, scopeKey, operations, mutations,
    revoke: () => { revoked = true; }, retireGeneration: () => { currentGeneration++; }, advance: () => { head = String(BigInt(head) + 1n); },
    state: () => ({ head, allowed, enforcement }) };
}

async function prepared(f, action, enabled) {
  const state = await f.api.snapshot({ context: f.context });
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const selected = action === 'permission' ? { choiceId: randomUUID(),
    toolKey: state.choices[0].toolKey, role: state.choices[0].role,
    snapshotSha256: state.choices[0].snapshotSha256 } : null;
  const input = { context: f.context, source, origin: { step: 2, callId: 'call-2' },
    action, selected, candidate: action === 'permission' ? { allowed: enabled } : { enabled },
    modeCapability };
  return { input, source, proposal: await f.api.prepare(input) };
}

test('real matrix issues only applicable supported opaque choices and preparation has no policy effect', async () => {
  const f = fixture();
  const state = await f.api.snapshot({ context: f.context });
  assert.equal(state.choices.length, 1);
  assert.deepEqual(state.choices[0].toolKey, 'audit.search_by_user');
  assert.equal(state.choices[0].role, 'admin');
  assert.equal(Object.hasOwn(state.choices[0], 'choiceId'), false);
  assert.equal(state.choices[0].snapshotSha256, C.aclChoiceSnapshot({
    scopeKey: f.scopeKey, expectedVersion: '1', registrySha256: REGISTRY,
    toolKey: 'audit.search_by_user', role: 'admin', allowed: false, enforcement: false }));
  const { input, proposal, source } = await prepared(f, 'permission', true);
  // The shared SHOP_ACL_KEY reference parser accepts this exact UUIDv4 shape.
  assert.match(proposal.proposalId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepEqual(proposal.before, { allowed: false, enforcement: false });
  assert.deepEqual(proposal.after, { allowed: true, enforcement: false });
  assert.equal(proposal.choiceId, input.selected.choiceId);
  assert.deepEqual(C.validateRoleAclProposal(jsonb(proposal), source), proposal);
  assert.equal(Object.hasOwn(C.projectRoleAclProposal(proposal, source), 'origin'), false);
  assert.deepEqual(f.state(), { head: '1', allowed: false, enforcement: false });
  assert.equal(f.mutations.length, 0); assert.equal(f.operations.size, 0);
});

test('physical confirmation delegates one exact versioned mutation; replay and GET keep immutable receipt', async () => {
  const f = fixture();
  const { proposal, source } = await prepared(f, 'permission', true);
  let checked = false;
  const first = await f.api.confirm({ context: f.context, proposal: jsonb(proposal), source,
    beforeEffect: async () => { checked = true; assert.equal(f.mutations.length, 0); } });
  assert.equal(checked, true);
  assert.deepEqual(f.mutations[0].change, { kind: 'permission', toolKey: 'audit.search_by_user', role: 'admin', allowed: true });
  assert.equal(f.mutations[0].operationId, proposal.proposalId);
  assert.deepEqual(first, { ok: true, receipt: f.operations.get(proposal.proposalId) });
  assert.deepEqual(f.state(), { head: '2', allowed: true, enforcement: false });
  assert.deepEqual(await f.api.confirm({ context: f.context, proposal, source }), first);
  assert.deepEqual(await f.api.operation({ context: f.context, operationId: proposal.proposalId }), first);
  assert.equal(f.operations.size, 1);
  const second = await prepared(f, 'enforcement', true);
  const enabled = await f.api.confirm({ context: f.context, proposal: second.proposal, source: second.source });
  assert.deepEqual(enabled.receipt.change, { kind: 'enforcement', enabled: true });
  assert.equal(f.state().enforcement, true); assert.equal(f.operations.size, 2);
});

test('substituted choice, changed head, no-op and forged public fields fail before mutation', async () => {
  const f = fixture();
  const { input, proposal, source } = await prepared(f, 'permission', true);
  await assert.rejects(f.api.prepare({ ...input, selected: { ...input.selected, choiceId: 'not-a-uuid' } }),
    { code: 'ACL_CHOICE_STALE' });
  await assert.rejects(f.api.prepare({ ...input, selected: { ...input.selected, snapshotSha256: 'b'.repeat(64) } }),
    { code: 'ACL_CHOICE_STALE' });
  await assert.rejects(f.api.prepare({ ...input, candidate: { allowed: false } }), { code: 'ACL_NO_CHANGE' });
  const forged = { ...proposal, after: { ...proposal.after, allowed: false } };
  assert.throws(() => C.validateRoleAclProposal(forged, source), { code: 'ROLE_ACL_PROPOSAL_INVALID' });
  f.advance();
  await assert.rejects(f.api.prepare(input), { code: 'ACL_CHOICE_STALE' });
  await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), { code: 'ACL_VERSION_CONFLICT' });
  assert.equal(f.operations.size, 0);
});

test('fresh saved-card UUIDs for one unchanged ACL row remain distinct while sharing a canonical snapshot', async () => {
  const f = fixture();
  const state = await f.api.snapshot({ context: f.context });
  const row = state.choices[0];
  const first = randomUUID(), second = randomUUID();
  assert.notEqual(first, second);
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const input = { context: f.context, source, origin: { step: 2, callId: 'prepare' },
    action: 'permission', candidate: { allowed: true }, modeCapability };
  const one = await f.api.prepare({ ...input,
    selected: { choiceId: first, toolKey: row.toolKey, role: row.role, snapshotSha256: row.snapshotSha256 } });
  const two = await f.api.prepare({ ...input,
    selected: { choiceId: second, toolKey: row.toolKey, role: row.role, snapshotSha256: row.snapshotSha256 } });
  assert.equal(one.choiceId, first);
  assert.equal(two.choiceId, second);
  assert.equal(one.sourceSnapshotSha256, two.sourceSnapshotSha256);
  assert.notEqual(one.requestSha256, two.requestSha256);
  assert.deepEqual(f.state(), { head: '1', allowed: false, enforcement: false });
  assert.equal(f.mutations.length, 0);
});

test('foreign or retired original authority cannot prepare, confirm or read receipt', async () => {
  const f = fixture();
  const { proposal, source, input } = await prepared(f, 'permission', true);
  const foreign = { ...f.context, personaSession: { ...f.context.personaSession, sessionId: randomUUID() } };
  await assert.rejects(f.api.prepare({ ...input, context: foreign }), { code: 'SHOP_AUTH_INVALID' });
  await assert.rejects(f.api.confirm({ context: foreign, proposal, source }), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(await f.api.operation({ context: f.context, operationId: proposal.proposalId }), null);
  f.revoke();
  await assert.rejects(f.api.confirm({ context: f.context, proposal, source }), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(f.operations.size, 0); assert.equal(f.mutations.length, 0);
});

test('malformed service and receipt shape fail closed', async () => {
  assert.throws(() => createBoundAclChat({ accessControl: {} }), TypeError);
  const f = fixture();
  const { proposal, source } = await prepared(f, 'permission', true);
  const bad = createBoundAclChat({ accessControl: {
    read: async () => ({ version: '1', enforcement_enabled: false, registrySha256: REGISTRY,
      administration: { versionedPolicy: true, scopeKey: f.scopeKey }, tools: [] }),
    mutate: async () => ({ receipt: { operationId: proposal.proposalId } }),
    operation: async () => ({ operationId: proposal.proposalId }),
  } });
  await assert.rejects(bad.confirm({ context: f.context, proposal, source }), { code: 'ACL_CHAT_STATE_INVALID' });
  await assert.rejects(bad.operation({ context: f.context, operationId: proposal.proposalId }),
    { code: 'ACL_CHAT_STATE_INVALID' });
});

for (const change of ['foreign session', 'foreign owner', 'retired generation', 'revoked session'])
test(`pending enforcement rejects ${change} without a policy operation`, async () => {
  const f = fixture(), { proposal, source } = await prepared(f, 'enforcement', true);
  assert.equal(proposal.action, 'enforcement');
  const before = { state: f.state(), proposal: structuredClone(proposal), operations: [...f.operations] };
  const context = structuredClone(f.context);
  if (change === 'foreign session') context.personaSession.sessionId = randomUUID();
  if (change === 'foreign owner') context.scope.platformOwnerId++;
  if (change === 'retired generation') f.retireGeneration();
  if (change === 'revoked session') f.revoke();
  await assert.rejects(f.api.confirm({ context, proposal, source }), { code: 'SHOP_AUTH_INVALID' });
  assert.deepEqual(f.state(), before.state); assert.deepEqual([...f.operations], before.operations);
  assert.deepEqual(f.mutations, []); assert.deepEqual(proposal, before.proposal);
});
