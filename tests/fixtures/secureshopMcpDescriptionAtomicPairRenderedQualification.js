'use strict';
// A rendered pair can be admitted only from two independently persisted original
// turns and two retired physical provider relays. The source-only atomic pair
// contract is not an execution authority.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { armDefinition, VERSION, LIMITS } = require('./secureshopMcpDescriptionAtomicPair');
const original = require('./secureshopMcpDescriptionRenderedQualification');
const evidence = require('../../server/services/secureshopMcpDescriptionEvidence');
const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');

const SCOPE = 'mcp-description-v39-atomic-pair-current-main-v1';
const SHA = /^[a-f0-9]{64}$/;
const hash = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
const creditTables = ['assessment_judgments', 'assessment_contributions', 'assessment_completions'];

function assertPhysicalArm(arm, calls) {
  assert.ok(Array.isArray(calls) && calls.length >= 8 && calls.length <= LIMITS.physicalPerArm);
  const actors = calls.filter(call => call.kind === 'actor');
  const judges = calls.filter(call => call.kind === 'judge');
  assert.ok(actors.length >= 7 && actors.length <= LIMITS.actorPerArm);
  assert.ok(judges.length >= 1 && judges.length <= LIMITS.judgePerArm);
  for (let i = 0; i < calls.length; i++) {
    const call = calls[i];
    assert.ok(call.kind === 'actor' || call.kind === 'judge');
    assert.equal(call.arm, arm);
    assert.equal(call.index, i + 1);
    assert.equal(call.status, 200); assert.equal(call.responseComplete, true);
    assert.equal(call.responseCaptureTruncated, false);
    assert.equal(call.error, undefined);
    assert.equal(hash(call.request), call.requestSha256);
    assert.equal(hash(call.response), call.responseSha256);
  }
  return { actorCalls: actors.length, judgeCalls: judges.length, physicalCalls: calls.length };
}
function assertControlCreditReadbacks(captured) {
  for (const key of ['controlCreditBefore', 'controlCreditAfterFixed', 'controlCreditAfterReset']) {
    const rows = captured[key];
    assert.ok(exact(rows, creditTables));
    for (const table of creditTables) assert.deepEqual(rows[table], [], `${key}.${table}`);
  }
  assert.equal(captured.canonicalCredit, false);
  assert.equal(captured.diagnostic?.canonicalCredit, false);
}
function assertCapturedArm(arm, captured, calls, qualifyModelTrace) {
  const definition = armDefinition(arm);
  assert.equal(captured?.version, 2); assert.equal(captured.arm, arm);
  assert.equal(captured.scope, VERSION);
  assert.equal(captured.requests?.length, 4);
  assert.deepEqual(captured.requests.map(row => row.body.message).slice(2, 3), [original.SOURCE_TASK]);
  assert.equal(captured.phases?.length, 2);
  assert.deepEqual(captured.phases.map(row => row.name), definition.registrations.map(row => row.name));
  assert.ok(captured.fences?.fixed && captured.fences?.resetId && captured.fences?.peerLaunchId);
  const source = captured.original;
  const observed = evidence.validateSource(source, qualifyModelTrace);
  const reset = captured.fences.reset;
  assert.equal(reset?.status, 'committed');
  assert.equal(reset.resetId, captured.fences.resetId);
  assert.equal(reset.binding?.launchId, observed.atomicScope?.launch.launchId);
  assert.equal(reset.fromGeneration, observed.atomicScope?.launch.generation);
  assert.equal(reset.toGeneration, reset.fromGeneration + 1);
  assert.equal(reset.binding?.generation, reset.toGeneration);
  assert.equal(reset.binding?.platformOwnerId, observed.atomicScope?.launch.platformOwnerId);
  assert.equal(reset.binding?.platformSessionId, observed.atomicScope?.launch.platformSessionId);
  assert.equal(observed.atomicScope?.arm, arm);
  assert.equal(observed.atomicScope?.endpoint, definition.registrations[1].url);
  assert.deepEqual(captured.atomicScope, observed.atomicScope);
  assert.equal(observed.originalTask, original.SOURCE_TASK);
  assert.equal(typeof observed.selectedArgs?.query, 'string');
  assert.ok(observed.selectedArgs.query.length > 0 && observed.selectedArgs.query.length <= 256);
  const offered = observed.offered;
  assert.equal(offered.length, 2);
  assert.equal(offered[0].description, armDefinition('control').description);
  assert.equal(offered[1].description, definition.description);
  assert.ok(!JSON.stringify(observed.observation).includes(original.V39_FINAL_PREFIX));
  if (arm === 'control') {
    assertControlCreditReadbacks(captured);
    assert.ok(!observed.finalText.trimStart().startsWith(original.V39_FINAL_PREFIX));
    const diagnostic = captured.diagnostic;
    assert.ok(diagnostic && diagnostic.outcome?.verdict === 'fail');
    assert.equal(evidence.isMcpDescriptionDiagnosticInputValid(diagnostic.input, qualifyModelTrace), true);
    assert.equal(evidence.isMcpDescriptionJudgeInputValid(diagnostic.input, qualifyModelTrace), false);
    assert.deepEqual(diagnostic.input.rubric, evidence.RUBRIC);
    const prepared = prepareJudgeInput(diagnostic.input);
    assert.equal(typeof prepared.packet, 'string');
    assert.ok(captured.model?.transcripts.some(row => row.header?.packet === prepared.packet
      && isDeepStrictEqual(row.outcome?.value, diagnostic.outcome)));
  } else {
    original.assertOriginalAdoption({ finalText: observed.finalText,
      originalTask: observed.originalTask, originalToolResult: observed.observation,
      offeredTools: offered }, definition.description);
    assert.equal(captured.assessment?.completed, true);
    assert.equal(captured.assessment?.judgment?.verdict, 'pass');
    assert.equal(captured.judgment?.verdict, 'pass');
    assert.equal(captured.judgment?.disposition, 'awarded');
    assert.ok(evidence.buildMcpDescriptionCandidate({ source,
      assessmentExecution: { runId: captured.judgment.run_id,
        ownerKey: captured.judgment.owner_key,
        durableGeneration: String(captured.judgment.owner_generation) },
      qualifyModelTrace }));
  }
  const counts = assertPhysicalArm(arm, calls);
  assert.ok(captured.model?.providerCalls?.length >= 4);
  assert.ok(captured.model?.transcripts?.length === 1);
  return { ...counts, launchId: observed.atomicScope.launch.launchId,
    launchGeneration: String(observed.atomicScope.launch.generation),
    platformOwnerId: observed.atomicScope.launch.platformOwnerId,
    platformSessionId: observed.atomicScope.launch.platformSessionId,
    sessionId: observed.atomicScope.personaSession.sessionId,
    runId: observed.atomicScope.runId,
    sourceSha256: hash(JSON.stringify(source)),
    offeredSchemaSha256: hash(JSON.stringify(offered.map(row => row.inputSchema))),
    resultSha256: hash(JSON.stringify(observed.observation)),
    trustedTaskSha256: hash(observed.originalTask),
    selectedArgsSha256: hash(JSON.stringify(observed.selectedArgs)) };
}
function assertPairCaptured({ control, treatment, controlCalls, treatmentCalls, qualifyModelTrace }) {
  assert.equal(typeof qualifyModelTrace, 'function');
  const clean = assertCapturedArm('control', control, controlCalls, qualifyModelTrace);
  const treated = assertCapturedArm('treatment', treatment, treatmentCalls, qualifyModelTrace);
  assert.ok(clean.launchId !== treated.launchId || clean.launchGeneration !== treated.launchGeneration,
    'arms require distinct canonical launch epochs');
  if (clean.launchId === treated.launchId) {
    assert.equal(clean.platformOwnerId, treated.platformOwnerId);
    assert.equal(clean.platformSessionId, treated.platformSessionId);
    assert.ok(BigInt(treated.launchGeneration) > BigInt(clean.launchGeneration),
      'same-launch treatment must follow the control reset');
  }
  assert.notEqual(clean.sessionId, treated.sessionId);
  assert.notEqual(clean.runId, treated.runId);
  for (const key of ['offeredSchemaSha256', 'resultSha256', 'trustedTaskSha256', 'selectedArgsSha256'])
    assert.equal(clean[key], treated[key], `${key} must differ only by the registered description`);
  assert.ok(clean.physicalCalls + treated.physicalCalls <= LIMITS.physicalPair);
  const receipt = { version: 2, scope: SCOPE, pairVersion: VERSION,
    control: { ...clean, canonicalCredit: 0 }, treatment: { ...treated, canonicalCredit: 1 },
    physicalCalls: clean.physicalCalls + treated.physicalCalls,
    sameTaskCatalogSchemaResult: true, controlNoCredit: true,
    treatmentCanonicalCredit: true, fixedAndLifecycle: true, errors: [] };
  return receipt;
}
function finalizePairReceipt(evidenceReceipt, { cleanupComplete, relayRetired, browserApi }) {
  const receipt = { ...evidenceReceipt, cleanupComplete, relayRetired, browserApi };
  return assertPairReceipt(receipt);
}
function assertPairReceipt(value) {
  assert.ok(exact(value, ['version', 'scope', 'pairVersion', 'control', 'treatment',
    'physicalCalls', 'sameTaskCatalogSchemaResult', 'controlNoCredit',
    'treatmentCanonicalCredit', 'fixedAndLifecycle', 'cleanupComplete',
    'relayRetired', 'browserApi', 'errors']));
  assert.equal(value.version, 2); assert.equal(value.scope, SCOPE);
  assert.equal(value.pairVersion, VERSION);
  const armKeys = ['actorCalls', 'judgeCalls', 'physicalCalls', 'launchId',
    'launchGeneration', 'platformOwnerId', 'platformSessionId', 'sessionId',
    'runId', 'sourceSha256', 'offeredSchemaSha256', 'resultSha256',
    'trustedTaskSha256', 'selectedArgsSha256', 'canonicalCredit'];
  for (const [arm, credit] of [['control', 0], ['treatment', 1]]) {
    const row = value[arm]; assert.ok(exact(row, armKeys));
    assert.equal(row.canonicalCredit, credit);
    assert.ok(Number.isSafeInteger(row.actorCalls) && row.actorCalls >= 7 && row.actorCalls <= 13);
    assert.ok(Number.isSafeInteger(row.judgeCalls) && row.judgeCalls >= 1 && row.judgeCalls <= 4);
    assert.equal(row.physicalCalls, row.actorCalls + row.judgeCalls);
    assert.ok(row.physicalCalls <= 14);
    for (const key of ['sourceSha256', 'offeredSchemaSha256', 'resultSha256',
      'trustedTaskSha256', 'selectedArgsSha256']) assert.match(row[key], SHA);
    assert.ok(typeof row.launchId === 'string' && row.launchId);
    assert.match(row.launchGeneration, /^(0|[1-9][0-9]*)$/);
    assert.ok(Number.isSafeInteger(row.platformOwnerId) && row.platformOwnerId > 0);
    assert.ok(Number.isSafeInteger(row.platformSessionId) && row.platformSessionId > 0);
    assert.ok(typeof row.sessionId === 'string' && row.sessionId);
    assert.ok(typeof row.runId === 'string' && row.runId);
  }
  assert.ok(value.control.launchId !== value.treatment.launchId
    || value.control.launchGeneration !== value.treatment.launchGeneration);
  if (value.control.launchId === value.treatment.launchId) {
    assert.equal(value.control.platformOwnerId, value.treatment.platformOwnerId);
    assert.equal(value.control.platformSessionId, value.treatment.platformSessionId);
    assert.ok(BigInt(value.treatment.launchGeneration) > BigInt(value.control.launchGeneration));
  }
  assert.notEqual(value.control.sessionId, value.treatment.sessionId);
  assert.notEqual(value.control.runId, value.treatment.runId);
  for (const key of ['offeredSchemaSha256', 'resultSha256', 'trustedTaskSha256', 'selectedArgsSha256'])
    assert.equal(value.control[key], value.treatment[key]);
  assert.equal(value.physicalCalls, value.control.physicalCalls + value.treatment.physicalCalls);
  assert.ok(value.physicalCalls <= LIMITS.physicalPair);
  for (const key of ['sameTaskCatalogSchemaResult', 'controlNoCredit',
    'treatmentCanonicalCredit', 'fixedAndLifecycle']) assert.equal(value[key], true);
  assert.equal(value.cleanupComplete, true);
  assert.equal(value.relayRetired, true);
  assert.ok(exact(value.browserApi, ['total', 'apiRequests', 'denied', 'interceptionErrors']));
  assert.ok(Number.isSafeInteger(value.browserApi.total) && value.browserApi.total > 0
    && value.browserApi.total <= 1200);
  assert.ok(Number.isSafeInteger(value.browserApi.apiRequests) && value.browserApi.apiRequests > 0
    && value.browserApi.apiRequests <= value.browserApi.total);
  assert.deepEqual(value.browserApi.denied, []);
  assert.equal(value.browserApi.interceptionErrors, 0);
  assert.deepEqual(value.errors, []);
  return value;
}
module.exports = { SCOPE, assertPhysicalArm, assertCapturedArm, assertPairCaptured,
  finalizePairReceipt, assertPairReceipt };
