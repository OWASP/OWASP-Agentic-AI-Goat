'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { _internals } = require('./helpers/secureshopAccessControlD22Qualification');

const registrySha256 = 'a'.repeat(64);
const id = '11111111-1111-4111-8111-111111111111';

test('D22 receipt contract requires a versioned audit-search policy mutation', () => {
  _internals.assertReceipt({ version: '2', registrySha256, operationId: id,
    enforcement: false, change: { kind: 'permission', toolKey: 'audit.search_by_user', role: 'admin', allowed: false } },
  { kind: 'permission', expectedVersion: '2', registrySha256, enabled: false });
  assert.throws(() => _internals.assertReceipt({ version: '2', registrySha256, operationId: id,
    enforcement: false, change: { kind: 'permission', toolKey: 'other', role: 'admin', allowed: false } },
  { kind: 'permission', expectedVersion: '2', registrySha256, enabled: false }));
  _internals.assertReceipt({ version: '3', registrySha256, operationId: id,
    enforcement: true, change: { kind: 'enforcement', enabled: true } },
  { kind: 'enforcement', expectedVersion: '3', registrySha256, enabled: true });
});

test('D22 actual outcome contract rejects a denied path that claims an effect', () => {
  const context = { launchId: id, scenarioId: '22222222-2222-4222-8222-222222222222', platformOwnerId: '9',
    platformSessionId: '13', personaId: '7', personaSessionId: '44444444-4444-4444-8444-444444444444',
    authorityVersion: '1', generation: '0', policyVersion: '3', registrySha256, runId: '55555555-5555-4555-8555-555555555555', invocationId: '1:call-1' };
  _internals.assertActualOutcome({ provider: 'ollama', model: 'llama3.1:8b', replayed: true,
    admission: { allowed: false, action: 'block', toolKey: 'audit.search_by_user' },
    noServiceDispatch: true, noQueryEffect: true, noJudgment: true, noCredit: true, actorFinalResponse: true, context }, { denied: true });
  assert.throws(() => _internals.assertActualOutcome({ provider: 'ollama', model: 'llama3.1:8b', replayed: true,
    admission: { allowed: false, action: 'block', toolKey: 'audit.search_by_user' },
    noServiceDispatch: true, noQueryEffect: false, noJudgment: true, noCredit: true, actorFinalResponse: true, context }, { denied: true }));
  assert.throws(() => _internals.assertAdmittedContext({ ...context,
    platformSessionId: '33333333-3333-4333-8333-333333333333' }),
  /platformSessionId|match/);
  assert.throws(() => _internals.assertAdmittedContext({ ...context,
    invocationId: '66666666-6666-4666-8666-666666666666' }), /invocationId|match/);
});

test('D22 production assembler rejects missing disposable dependencies before touching runtime configuration', async () => {
  const { createD22AuditApplication } = require('./helpers/secureshopD22ProductionAssembly');
  await assert.rejects(createD22AuditApplication(), /D22 identityPool is required/);
});
