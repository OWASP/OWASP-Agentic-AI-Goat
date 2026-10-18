'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const C = require('../server/services/secureshopRoleSystemDiagnosticProposal');
const { createBoundSystemDiagnosticChat } = require('../server/services/secureshopBoundSystemDiagnosticChat');
const { CAPABILITY } = require('../server/services/secureshopSystemDiagnosticClient');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { diagnosticRequestDigest, diagnosticCommand, VERSION } = require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const { bindDiagnosticResult } = require('../sidecars/sandbox-runner/owned-system/diagnostic-wire');

const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: 7, platformSessionId: 8 };
const context = { scope, persona: { id: 3, role: 'admin' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
const source = { sessionId: randomUUID(), requestId: randomUUID() };
const origin = { step: 2, callId: 'model-selected-diagnostic' };
function administration(mode = 'vuln', modeStamp = 'first') {
  return { diagnosticCapability: CAPABILITY,
    scopeKey: canonicalDigest({ version: 'secureshop-system-diagnostic-administration.v1',
      scope, persona: context.persona, personaSession: context.personaSession }),
    modeCapability: { version: 1, featureId: 'system_diagnostic',
      policyVersion: 'owned-system-diagnostic-shell-v1', effectiveMode: mode,
      scope: { kind: 'launch_feature', id: 'system_diagnostic' } },
    execution: { version: 1, featureId: 'system_diagnostic',
      policyVersion: 'owned-system-diagnostic-shell-v1', mode, generation: 2,
      modeStamp, scope } };
}
function fixture(mode = 'vuln') {
  let current = administration(mode), executions = 0, reads = 0, readResult = null;
  const application = {
    administration: async () => current,
    execute: async input => { executions++; return { operationId: input.operationId,
      requestSha256: require('../sidecars/sandbox-runner/owned-system/diagnostic-contract')
        .diagnosticRequestDigest({ operationId: input.operationId,
          cmd_template: input.cmd_template, args: input.args }), state: 'pending' }; },
    operation: async input => { reads++; return readResult || { operationId: input.operationId, state: 'not_found' }; },
  };
  const chat = createBoundSystemDiagnosticChat({ getDiagnostic: async () => ({ ready: true, service: application }) });
  return { chat, get executions() { return executions; }, get reads() { return reads; },
    set current(value) { current = value; }, set readResult(value) { readResult = value; } };
}
function completed(proposal) {
  const targetId = randomUUID(), request = { operationId: proposal.proposalId,
    cmd_template: proposal.cmd_template, args: proposal.args };
  const digest = diagnosticRequestDigest(request), empty = createHash('sha256').update('').digest('hex');
  const receipt = bindDiagnosticResult({ targetId, request }, { version: VERSION,
    isolation: 'bwrap-system-diagnostic-v1', operationId: request.operationId,
    requestSha256: digest, command: diagnosticCommand(request), executed: true,
    exitCode: 0, signal: null, drained: true, stdout: '', stderr: '', encoding: 'base64',
    stdoutBytes: 0, stderrBytes: 0, stdoutSha256: empty, stderrSha256: empty,
    timedOut: false, truncated: false });
  return { operationId: proposal.proposalId, requestSha256: digest, targetId,
    state: 'completed', receipt };
}
test('no-effect prepare preserves exact selected shell bytes and hides epoch from public proposal', async () => {
  const f = fixture();
  const proposal = await f.chat.prepare({ context, source, origin,
    cmd_template: 'printf', args: "' OR 1=1--" });
  assert.equal(f.executions, 0);
  assert.equal(f.reads, 0);
  assert.equal(proposal.cmd_template, 'printf');
  assert.equal(proposal.args, "' OR 1=1--");
  assert.equal(proposal.proposalId, (await f.chat.prepare({ context, source, origin,
    cmd_template: 'printf', args: "' OR 1=1--" })).proposalId);
  const publicValue = C.projectRoleSystemDiagnosticProposal(proposal, source);
  assert.equal(Object.hasOwn(publicValue, 'execution'), false);
  assert.equal(Object.hasOwn(publicValue, 'origin'), false);
  assert.equal(publicValue.modeCapability.featureId, 'system_diagnostic');
  assert.equal(publicValue.proposalId, proposal.proposalId);
  assert.equal((await f.chat.snapshot({ context })).sourceSnapshotSha256, proposal.sourceSnapshotSha256);
  assert.throws(() => C.createRoleSystemDiagnosticProposal({ context,
    administration: { ...administration(), scopeKey: 'a'.repeat(64) }, source, origin,
    cmd_template: 'printf', args: 'hello' }), { code: 'ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID' });
  assert.throws(() => C.validateRoleSystemDiagnosticProposal({ ...proposal,
    diagnosticCapability: 'forged' }, source), { code: 'ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID' });
  await assert.rejects(f.chat.prepare({ context, source, origin, cmd_template: 'x\0', args: '' }),
    { code: 'ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID' });
});
test('fixed and ABA mode changes deny execution while saved read stays owner-scoped', async () => {
  const f = fixture('fixed');
  const proposal = await f.chat.prepare({ context, source, origin, cmd_template: 'printf', args: 'hello' });
  let effects = 0;
  await assert.rejects(f.chat.confirm({ context, source, proposal,
    beforeEffect: async () => { effects++; } }), { code: 'SYSTEM_DIAGNOSTIC_FIXED_DENIED' });
  assert.equal(f.executions, 0); assert.equal(effects, 0);
  f.current = administration('vuln', 'second');
  assert.equal((await f.chat.operation({ context, source, proposal })).state, 'not_found');
  const g = fixture('vuln');
  const vulnProposal = await g.chat.prepare({ context, source, origin, cmd_template: 'printf', args: 'hello' });
  g.current = administration('vuln', 'changed');
  await assert.rejects(g.chat.confirm({ context, source, proposal: vulnProposal,
    beforeEffect: async () => { effects++; } }), { code: 'SYSTEM_DIAGNOSTIC_CHAT_SCOPE_MISMATCH' });
  assert.equal(g.executions, 0);
  const saved = await g.chat.operation({ context, source, proposal: vulnProposal });
  assert.equal(saved.state, 'not_found');
  g.readResult = completed(vulnProposal);
  g.current = administration('fixed', 'third');
  const historical = await g.chat.operation({ context, source, proposal: vulnProposal });
  assert.equal(historical.state, 'completed');
  assert.equal(historical.operationId, vulnProposal.proposalId);
  await assert.rejects(g.chat.confirm({ context, source, proposal: vulnProposal,
    beforeEffect: async () => { effects++; } }), { code: 'SYSTEM_DIAGNOSTIC_CHAT_SCOPE_MISMATCH' });
});
test('genuine confirm preserves original operation and requires trusted effect callback', async () => {
  const f = fixture();
  const proposal = await f.chat.prepare({ context, source, origin, cmd_template: 'echo', args: '  raw  ' });
  await assert.rejects(f.chat.confirm({ context, source, proposal }),
    { code: 'ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID' });
  let checks = 0;
  const result = await f.chat.confirm({ context, source, proposal,
    beforeEffect: async () => { checks++; } });
  assert.equal(result.state, 'pending');
  assert.equal(result.operationId, proposal.proposalId);
  assert.equal(f.executions, 1); assert.equal(checks, 1);
  const read = await f.chat.operation({ context, source, proposal });
  assert.equal(read.state, 'not_found'); assert.equal(f.reads, 1);
  await assert.rejects(f.chat.confirm({ context, source,
    proposal: { ...proposal, args: 'mutated' }, beforeEffect: async () => {} }),
  { code: 'ROLE_SYSTEM_DIAGNOSTIC_PROPOSAL_INVALID' });
});
