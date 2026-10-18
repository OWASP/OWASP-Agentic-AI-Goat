'use strict';

// Production graph, protected source reader, evidence and assessment are joined
// here with controlled stores/providers. These tests establish no native SQL,
// physical confirmation, executor, genuine model or objective-credit proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { diagnosticAssessmentSourceFixture } = require('./secureshopBoundRoleChat.test');
const { fixture: assessmentFixture } = require('./secureshopSystemDiagnosticAssessment.test');
const { buildSystemDiagnosticCandidate } = require('../server/services/secureshopSystemDiagnosticEvidence');
const { VERSION, diagnosticCommand, diagnosticRequestDigest } = require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const { bindDiagnosticResult, diagnosticHostname } = require('../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const hash = text => createHash('sha256').update(text).digest('hex');

async function fixture(options = {}) {
  const graph = await diagnosticAssessmentSourceFixture(options);
  const { f, d, reference } = graph;
  const turn = f.savedTurn(reference.requestId);
  const proposal = turn.taskMetadata.roleChat.systemDiagnosticProposal;
  const targetId = randomUUID();
  const request = { operationId: proposal.proposalId, cmd_template: proposal.cmd_template, args: proposal.args };
  const stdout = 'diagnostic-baseline\n' + diagnosticHostname(targetId) + '\n';
  const receipt = bindDiagnosticResult({ targetId, request }, {
    version: VERSION, isolation: 'bwrap-system-diagnostic-v1',
    operationId: request.operationId, requestSha256: diagnosticRequestDigest(request),
    command: diagnosticCommand(request), executed: true, drained: true,
    exitCode: 0, signal: null, stdout: Buffer.from(stdout).toString('base64'), stderr: '', encoding: 'base64',
    stdoutBytes: Buffer.byteLength(stdout), stderrBytes: 0, stdoutSha256: hash(stdout), stderrSha256: hash(''),
    timedOut: false, truncated: false,
  });
  // Explicit synthetic repository outcome; never invoke a diagnostic executor.
  d.setOperation(proposal.proposalId, { operationId: proposal.proposalId, requestSha256: proposal.requestSha256,
    targetId, state: 'completed', receipt: structuredClone(receipt) });
  const source = await f.runtime.readSystemDiagnosticAssessmentSource(reference);
  const original = { proposal, sourceBinding: source.sourceBinding, input: {
    ...source, sessionId: reference.sessionId, requestId: reference.requestId,
    binding: { ...reference.scope, shopUserId: reference.persona.id, role: reference.persona.role },
    personaSession: { sessionId: reference.personaSession.sessionId, authorityVersion: reference.personaSession.authorityVersion },
    systemExecution: proposal.execution,
    qualifyModel: identity => identity.provider === 'ollama' && identity.model === 'llama3.1:8b',
  } };
  const assessment = assessmentFixture({ original,
    readSource: input => f.runtime.readSystemDiagnosticAssessmentSource(input) });
  return { ...graph, source, original, assessment };
}

function noNewExecution(graph, baseline) {
  assert.equal(graph.f.modelCalls, baseline.models);
  assert.equal(graph.f.finalCalls, baseline.finals);
  assert.equal(graph.f.reservations, baseline.reservations);
  assert.equal(graph.d.executions, 0);
}
function counts(graph) {
  return { models: graph.f.modelCalls, finals: graph.f.finalCalls, reservations: graph.f.reservations };
}

test('V47 production reader feeds full real graph DTO into canonical assessment without replaying preparation', async () => {
  const f = await fixture(), a = f.assessment, baseline = counts(f);
  assert.deepEqual(f.source.traces.map(row => row.event_id),
    f.source.turn.taskMetadata.roleChat.systemDiagnosticOrigin.traceEventIds);
  assert.deepEqual(f.source.traces.slice(-2).map(row => row.kind), ['final', 'terminal']);
  assert.ok(buildSystemDiagnosticCandidate(f.original.input), 'actual graph source must be eligible, not silently ineligible');
  assert.deepEqual(await a.service.readOutcome(a.input), { completed: false, status: 'unconfirmed', modelEvaluated: false });
  const result = await a.service.runAttempt(a.input);
  assert.equal(result.completed, false); assert.equal(result.judgment.verdict, 'fail');
  assert.equal(a.calls.judge, 1); assert.equal(a.calls.verdict, 1);
  assert.deepEqual(await a.service.readOutcome(a.input), { ...result, replayed: true });
  assert.deepEqual(await a.service.runAttempt(a.input), { ...result, replayed: true });
  assert.equal(a.calls.judge, 1); assert.equal(a.calls.effects, 0);
  noNewExecution(f, baseline);
});

test('V47 populated saved source remains exact while controlled positive grading cannot earn credit', async () => {
  const f = await fixture(), a = f.assessment, baseline = counts(f);
  const first = await f.f.runtime.readSystemDiagnosticAssessmentSource(f.reference);
  assert.deepEqual(first, await f.f.runtime.readSystemDiagnosticAssessmentSource(f.reference));
  a.controlledPositiveJudge();
  const result = await a.service.runAttempt(a.input);
  assert.equal(a.calls.judge, 1); assert.equal(result.completed, false);
  assert.notEqual(a.canonicalRow.disposition, 'pass');
  assert.deepEqual(await a.service.readOutcome(a.input), { ...result, replayed: true });
  noNewExecution(f, baseline);
});

for (const action of ['grant', 'scene', 'mode', 'source']) {
  test(`V47 composed source/current authority rejects ${action} drift during canonical Judge without publishing`, async () => {
    const f = await fixture(), a = f.assessment, baseline = counts(f);
    a.onJudge(() => {
      if (action === 'grant') f.f.rotateGrant();
      if (action === 'scene') f.f.setRetainedScene(false);
      if (action === 'mode') {
        f.d.setMode('fixed');
        // Saved operation reads intentionally preserve their original mode.
        // The assessment's independent current mode authority must revoke it.
        a.original.input.systemExecution = { ...a.original.input.systemExecution, mode: 'fixed' };
      }
      if (action === 'source') f.f.alterSaved(f.reference.requestId, turn => { turn.text += ' altered'; });
    });
    await assert.rejects(a.service.runAttempt(a.input));
    assert.equal(a.calls.judge, 1); assert.equal(a.calls.verdict, 0);
    assert.equal(a.calls.complete, 0); assert.equal(a.calls.effects, 0);
    noNewExecution(f, baseline);
  });
}

test('V47 retained canonical packet rechecks the production source after uncertain journal publication', async () => {
  const f = await fixture(), a = f.assessment, baseline = counts(f);
  a.onCompleteError(Object.assign(Error('controlled journal publication failure'), { code: 'CONTROLLED_JOURNAL_UNCERTAIN' }));
  await assert.rejects(a.service.runAttempt(a.input));
  assert.equal(a.journalRow.status, 'uncertain'); assert.equal(a.calls.verdict, 1);
  const guard = await a.service.assertRetainedPacket({ ...a.input, packet: a.packet });
  await guard.assertCurrent();
  f.f.rotateGrant();
  await assert.rejects(guard.assertCurrent());
  assert.equal(a.calls.judge, 1); assert.equal(a.calls.claim, 1); assert.equal(a.calls.effects, 0);
  assert.equal(a.journalRow.status, 'uncertain'); noNewExecution(f, baseline);
});


test('V47 missing confirmation and foreign persona session cannot admit a canonical assessment', async () => {
  for (const change of ['missing-operation', 'foreign-session']) {
    const f = await fixture(), a = f.assessment, baseline = counts(f);
    if (change === 'missing-operation') {
      f.d.setOperation(f.reference.proposalId, { state: 'not_found', operationId: f.reference.proposalId });
      assert.deepEqual(await a.service.runAttempt(a.input), { completed: false, status: 'ineligible', modelEvaluated: false });
    } else {
      await assert.rejects(a.service.runAttempt({ ...a.input,
        personaSession: { ...a.input.personaSession, sessionId: randomUUID() } }));
    }
    assert.equal(a.calls.claim, 0); assert.equal(a.calls.judge, 0); assert.equal(a.calls.verdict, 0);
    noNewExecution(f, baseline);
  }
});
