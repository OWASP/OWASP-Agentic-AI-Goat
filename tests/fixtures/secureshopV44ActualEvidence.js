'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createConversationBinding, createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../../server/services/secureshopTurnRequest');
const { canonicalDigest } = require('../../server/services/mcp/protocolContext');
const { createV44FilePathSummaryTurnReader } = require('../../server/database/postgres/secureshopV44FilePathSummaryTurnReader');
const { buildFilePathTraversalCandidate, FILE_PATH_OBJECTIVE, FILE_PATH_RUBRIC, FILE_PATH_PURPOSE } = require('../../server/services/secureshopV44FilePathTraversalEvidence');
const { isQualifiedSecureShopModelTrace } = require('../../server/services/secureshopRealModelTrace');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const COUNTERS = Object.freeze(['actorDecisions', 'toolCalls', 'fileReadEffects', 'judgeCalls', 'canonicalJudgments', 'completionRows']);
const hash = value => createHash('sha256').update(value).digest('hex');
const parsed = value => typeof value === 'string' ? JSON.parse(value) : value;

// This observer never dispatches a source or Judge call. Callers preserve original
// transport packets before invoking assertions, including incomplete runs.
function assertOriginalActorJoin({ actorSpans, wire, row, traces, qualifyModel, requestedPath }) {
  assert.equal(typeof qualifyModel, 'function');
  assert.ok(Array.isArray(wire));
  assert.equal(actorSpans.length, 2);
  assert.deepEqual(actorSpans.map(span => span.method), ['chat', 'finalResponse']);
  const turn = row.result_json, meta = turn.taskMetadata.boundFilePathSummary;
  assert.equal(turn.steps, 2); assert.equal(turn.stopReason, 'end_turn');
  assert.equal(turn.hops.length, 1);
  assert.equal(turn.hops[0].tool, 'summarizer.summarize_file');
  assert.deepEqual(turn.hops[0].params, { path: requestedPath });
  assert.equal(turn.hops[0].error, null); assert.equal(turn.hops[0].policyViolation, null);
  for (const kind of ['local_tool_call', 'local_tool_result', 'final', 'terminal'])
    assert.equal(traces.filter(trace => trace.kind === kind).length, 1);
  assert.equal(traces.filter(trace => ['error', 'tool_cancelled', 'tool_blocked'].includes(trace.kind)).length, 0);
  for (const span of actorSpans) {
    assert.equal(span.response.mocked, false);
    assert.notEqual(span.response.fallback, true);
    assert.ok(qualifyModel(span.response));
    if (span.method === 'chat') {
      assert.equal(require('./secureshopV19RenderedCohort').assertActorWire(span, wire[span.wireStart]), true);
    } else {
      const { FINAL_RESPONSE_SCHEMA, serializeMessage } = require('../../server/services/secureshop/providers/ollamaProvider');
      const physical = wire[span.wireStart], input = span.request;
      assert.equal(span.error, undefined); assert.equal(span.wireEnd, span.wireStart + 1);
      assert.equal(physical.kind, 'actor'); assert.equal(physical.status, 200);
      assert.equal(physical.responseComplete, true); assert.equal(physical.responseCaptureTruncated, false);
      assert.equal(hash(physical.request), physical.requestSha256); assert.equal(hash(physical.response), physical.responseSha256);
      assert.equal(Object.hasOwn(input, 'tools'), false); assert.equal(Object.hasOwn(input, 'closedToolCatalog'), false);
      const request = JSON.parse(physical.request);
      assert.equal(request.model, span.response.model); assert.deepEqual(request.format, FINAL_RESPONSE_SCHEMA);
      assert.equal(Object.hasOwn(request, 'tools'), false);
      assert.deepEqual(request.messages.slice(1), input.messages.map(serializeMessage));
      assert.equal(request.messages[0].role, 'system');
      assert.ok(request.messages[0].content.startsWith(input.system + '\n\n'));
      const content = physical.response.trim().split('\n').map(line => JSON.parse(line).message?.content || '').join('');
      assert.deepEqual(JSON.parse(content), { answer: span.response.text });
      assert.equal(span.response.responseMode, 'structured_final');
    }
  }
  const selected = actorSpans[0].response.tool_uses;
  assert.equal(selected.length, 1);
  const call = selected[0];
  assert.equal(call.name, 'summarizer.summarize_file');
  assert.deepEqual(call.args, { path: requestedPath });
  if (meta.outcome === 'read') assert.equal(call.id, meta.graphEffect.callId);
  assert.equal(actorSpans[1].response.stop_reason, 'end_turn');
  assert.equal(actorSpans[1].response.text, turn.text);
  assert.ok(!actorSpans[1].response.tool_uses?.length);
  const decisions = traces.filter(trace => trace.kind === 'model_decision');
  assert.equal(decisions.length, 2);
  assert.deepEqual(parsed(decisions[0].params_json), {
    decision: 'tool_use', toolCalls: [{ id: call.id, name: call.name, args: { path: requestedPath } }]
  });
  for (const [index, decision] of decisions.entries()) {
    assert.equal(isQualifiedSecureShopModelTrace(decision, qualifyModel), true);
    assert.equal(decision.provider, actorSpans[index].response.provider);
    assert.equal(parsed(decision.result_json).model, actorSpans[index].response.model);
  }
  assert.equal(parsed(decisions[1].result_json).text, turn.text);
  const terminal = traces.at(-1);
  assert.equal(terminal.kind, 'terminal');
  assert.equal(isQualifiedSecureShopModelTrace(terminal, qualifyModel), true);
  const firstMessages = actorSpans[0].request.messages;
  assert.equal(firstMessages.length, 1);
  assert.equal(firstMessages[0].role, 'user'); assert.equal(firstMessages[0].content, meta.originalEnvelope);
  assert.equal(firstMessages.filter(message => message.role === 'tool').length, 0,
    'Each qualification case uses a fresh conversation');
  const observed = actorSpans[1].request.messages.filter(message => message.role === 'tool');
  assert.equal(observed.length, 1);
  assert.equal(observed[0].tool_call_id, call.id);
  assert.equal(observed[0].content, turn.hops[0].result.content[0].text);
  return Object.freeze({ callId: call.id, responseSha256: hash(turn.text) });
}

async function readOriginalFilePathSummary(input) {
  const { agents, identity, conversations, sourceReader, scope, persona, personaSession,
    target, mode, sessionId, requestId, actorSpans, wire, qualifyModel, check, checkAtEffect,
    requestedPath, message } = input;
  assert.equal(typeof check, 'function'); assert.equal(typeof checkAtEffect, 'function');
  assert.match(sessionId, UUID); assert.match(requestId, UUID);
  assert.equal(require('node:path').posix.resolve('/uploads', requestedPath), '/etc/passwd');
  assert.ok(['vuln', 'fixed'].includes(mode.mode));
  await check();
  const binding = createConversationBinding(scope, persona);
  // The graph projects authenticated public-user/session records into this
  // closed authority tuple before hashing. Profile fields are not authority.
  const trustedPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
  const trustedPersonaSession = Object.freeze({ sessionId: personaSession.sessionId.toLowerCase(),
    authorityVersion: personaSession.authorityVersion });
  assert.match(trustedPersonaSession.sessionId, UUID);
  assert.match(trustedPersonaSession.authorityVersion, /^[1-9][0-9]{0,18}$/);
  const row = await createV44FilePathSummaryTurnReader({ pool: agents }).readFilePathSummaryRequest({
    binding, sessionId, requestId, purpose: FILE_PATH_PURPOSE
  });
  assert.equal(row?.status, 'completed');
  const turn = row.result_json, meta = turn?.taskMetadata?.boundFilePathSummary;
  assert.equal(meta?.outcome, mode.mode === 'fixed' ? 'no_tool' : 'read');
  const original = JSON.parse(meta.originalEnvelope);
  assert.equal(original.path, requestedPath); assert.equal(original.message, message);
  assert.equal(createTurnRequest({ sessionId, requestId, binding, message: meta.originalEnvelope }).hash, row.request_hash);
  const authority = { scope: createLaunchScope(binding), persona: trustedPersona,
    personaSession: trustedPersonaSession, sessionId, requestId,
    scene: structuredClone(target.scene), sceneTargetId: target.targetId, mode };
  assert.equal(original.authoritySha256, canonicalDigest(authority));
  assert.equal(original.operationId, meta.operationId);
  const traces = await conversations.getTraceEvents(sessionId, binding, meta.traceEventIds, FILE_PATH_PURPOSE);
  assert.deepEqual(traces.map(trace => trace.event_id), meta.traceEventIds);
  const actor = assertOriginalActorJoin({ actorSpans, wire, row, traces, qualifyModel, requestedPath });
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  const effectKey = `${requestId}:${JSON.stringify([1, actor.callId, 'summarizer.summarize_file'])}`;
  const effects = (await identity.query(`SELECT e.run_id::text,e.owner_key,e.generation::text,e.effect_key,e.status,
    r.status run_status,o.generation::text live_generation FROM graph_runtime.effects e
    JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
    JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
    WHERE e.owner_key=$1 AND e.effect_key=$2`, [ownerKey, effectKey])).rows;
  assert.equal(effects.length, 1);
  const graphEffect = effects[0];
  assert.equal(graphEffect.status, 'completed'); assert.equal(graphEffect.run_status, 'completed');
  assert.equal(String(graphEffect.live_generation), String(graphEffect.generation));
  let retained = null, candidate = null;
  if (mode.mode === 'vuln') {
    const graph = meta.graphEffect;
    assert.equal(graph.runId, graphEffect.run_id); assert.equal(graph.ownerKey, ownerKey);
    assert.equal(graph.effectKey, effectKey); assert.equal(graph.generation, String(graphEffect.generation));
    retained = await sourceReader.read({ scope: binding, persona: trustedPersona,
      personaSession: trustedPersonaSession, sessionId, requestId,
      receipt: meta.readReceipt, target, mode, check, checkAtEffect });
    assert.deepEqual(retained.receipt.authority, authority);
    assert.equal(retained.receipt.requestedPath, requestedPath);
    assert.equal(retained.receipt.resolvedPath, '/etc/passwd');
    assert.equal(hash(retained.data), retained.receipt.bodySha256);
    assert.equal(retained.data.length, retained.receipt.byteCount);
    candidate = buildFilePathTraversalCandidate({ binding, personaSession: trustedPersonaSession,
      row, traces, graphEffect, retained, qualifyModel });
    assert.ok(candidate); assert.equal(candidate.objectiveId, FILE_PATH_OBJECTIVE);
  } else {
    for (const key of ['readReceipt', 'graphEffect', 'toolResultSha256']) assert.equal(meta[key], undefined);
    assert.deepEqual(JSON.parse(turn.hops[0].result.content[0].text), {
      path: requestedPath, error: 'path outside owned uploads directory'
    });
  }
  await check();
  return Object.freeze({ row, traces, graphEffect, retained, candidate, actor });
}

function assertCounterSnapshot(value) {
  assert.deepEqual(Object.keys(value).sort(), [...COUNTERS].sort());
  for (const count of Object.values(value)) assert.ok(Number.isSafeInteger(count) && count >= 0);
  return Object.freeze({ ...value });
}
function assertGetOnlyRecovery(before, after) {
  assert.deepEqual(assertCounterSnapshot(after), assertCounterSnapshot(before));
}

async function assertCanonicalFilePathSummaryAssessment({ identity, assessment, scope, persona, personaSession,
  packet, evidenceDigest, evaluationId, expectedVerdict, judgeResult }) {
  assert.match(evaluationId, UUID);
  assert.ok(['pass', 'fail'].includes(expectedVerdict));
  const guard = await assessment.assertRetainedPacket({ packet, scope, persona, personaSession });
  await guard.assertCurrent();
  const rows = (await identity.query(`SELECT objective_id,family,scenario,rubric_version,shop_user_id,packet,
    evidence_digest,result_json,result_serialized,result_digest,execution_json,judge_observations,judge_result_json
    FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1 AND shop_user_id=$2`,
  [evaluationId, persona.id])).rows;
  assert.equal(rows.length, 1);
  const saved = rows[0];
  assert.equal(saved.objective_id, FILE_PATH_OBJECTIVE); assert.equal(saved.family, FILE_PATH_RUBRIC.family);
  assert.equal(saved.scenario, FILE_PATH_RUBRIC.scenario); assert.equal(saved.rubric_version, FILE_PATH_RUBRIC.version);
  assert.equal(saved.packet, packet); assert.equal(saved.evidence_digest, evidenceDigest);
  assert.equal(hash(saved.result_serialized), saved.result_digest);
  assert.deepEqual(JSON.parse(saved.result_serialized), saved.result_json);
  assert.equal(saved.result_json.verdict, expectedVerdict);
  const proof = require('../../server/agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(judgeResult);
  assert.ok(proof); assert.deepEqual(proof, saved.judge_observations);
  assert.equal(JSON.stringify(judgeResult), saved.judge_result_json);
  assert.equal(proof.evidenceDigest, evidenceDigest);
  assert.deepEqual(saved.execution_json.scope, createLaunchScope(scope));
  assert.equal(saved.execution_json.personaSessionId, personaSession.sessionId);
  assert.equal(saved.execution_json.role, 'customer');
  // Evaluation-scoped joins avoid mistaking a prior positive case for negative credit.
  for (const table of ['active_assessment_contributions', 'assessment_completions']) {
    const credit = (await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.${table} c
      JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=c.tenant_id AND j.principal_id=c.principal_id
       AND j.evaluation_id=c.evaluation_id AND j.objective_id=c.objective_id AND j.generation=c.generation
      WHERE c.evaluation_id=$1 AND c.objective_id=$2 AND j.shop_user_id=$3
       AND j.execution_json->'scope'->>'launchId'=$4 AND j.execution_json->'scope'->>'platformOwnerId'=$5`,
    [evaluationId, FILE_PATH_OBJECTIVE, persona.id, scope.launchId, String(scope.platformOwnerId)])).rows;
    assert.deepEqual(credit, expectedVerdict === 'pass' ? [{ evaluation_id: evaluationId }] : []);
  }
  await guard.assertCurrent();
  return Object.freeze({ judgment: saved });
}
async function captureImmutableHistory({ agents, identity, scope, sessionId }) {
  assert.match(sessionId, UUID);
  scope = createLaunchScope(scope);
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  const snapshot = {
    turns: (await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 ORDER BY request_id', [sessionId])).rows,
    traces: (await agents.query('SELECT * FROM secureshop_agents.agent_trace WHERE session_id=$1 ORDER BY event_id', [sessionId])).rows,
    effects: (await identity.query('SELECT * FROM graph_runtime.effects WHERE owner_key=$1 ORDER BY effect_key', [ownerKey])).rows,
    judgments: (await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
      WHERE objective_id=$1 AND execution_json->'scope'->>'launchId'=$2
      AND execution_json->'scope'->>'platformOwnerId'=$3 ORDER BY evaluation_id`,
    [FILE_PATH_OBJECTIVE, scope.launchId, String(scope.platformOwnerId)])).rows,
  };
  // SQL Date values are projected consistently before before/after comparison.
  return Object.freeze(JSON.parse(JSON.stringify(snapshot)));
}
function assertFixedAssessmentControl({ result, before, after, contributionRows, completionRows }) {
  assert.deepEqual(result, { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.deepEqual(assertCounterSnapshot(before), { actorDecisions: 2, toolCalls: 1,
    fileReadEffects: 0, judgeCalls: 0, canonicalJudgments: 0, completionRows: 0 });
  assertGetOnlyRecovery(before, after);
  assert.deepEqual(contributionRows, []); assert.deepEqual(completionRows, []);
}
function assertPublicProgress(value, completed) {
  assert.ok(Array.isArray(value.objectives));
  assert.equal(value.totalObjectives, value.objectives.length);
  assert.equal(value.completedObjectives, value.objectives.filter(row => row.completed).length);
  const objective = value.objectives.filter(row => row.objectiveId === FILE_PATH_OBJECTIVE);
  assert.equal(objective.length, 1); assert.equal(objective[0].completed, completed);
  return value;
}
module.exports = { COUNTERS, captureImmutableHistory, assertFixedAssessmentControl, assertPublicProgress,
  assertActorWire: require('./secureshopV19RenderedCohort').assertActorWire,
  assertJudgeWire: require('./secureshopV19RenderedCohort').assertJudgeWire,
  assertConfiguredJudgeRecord: require('./secureshopV19RenderedCohort').assertConfiguredJudgeRecord, assertOriginalActorJoin, readOriginalFilePathSummary,
  assertCounterSnapshot, assertGetOnlyRecovery, assertCanonicalFilePathSummaryAssessment };
