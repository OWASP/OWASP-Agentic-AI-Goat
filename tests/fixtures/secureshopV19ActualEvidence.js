'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createConversationBinding, createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../../server/services/secureshopTurnRequest');
const { canonicalDigest } = require('../../server/services/mcp/protocolContext');
const { createV19FileSummaryTurnReader } = require('../../server/database/postgres/secureshopV19FileSummaryTurnReader');
const { buildFileSummaryCandidate, SUMMARY_OBJECTIVE, SUMMARY_RUBRIC, SUMMARY_PURPOSE } = require('../../server/services/secureshopV19FileSummaryEvidence');
const { isQualifiedSecureShopModelTrace } = require('../../server/services/secureshopRealModelTrace');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const COUNTERS = Object.freeze(['actorDecisions', 'toolCalls', 'fileWrites', 'judgeCalls', 'canonicalJudgments', 'completionRows']);
const hash = value => createHash('sha256').update(value).digest('hex');
const parsed = value => typeof value === 'string' ? JSON.parse(value) : value;

// This observer never dispatches a source or Judge call. Callers preserve original
// transport packets before invoking assertions, including incomplete runs.
function assertOriginalActorJoin({ actorSpans, row, traces, qualifyModel }) {
  assert.equal(typeof qualifyModel, 'function');
  assert.equal(actorSpans.length, 2);
  assert.deepEqual(actorSpans.map(span => span.method), ['chat', 'chat']);
  const turn = row.result_json, meta = turn.taskMetadata.boundFileSummary;
  assert.equal(turn.steps, 2); assert.equal(turn.stopReason, 'end_turn');
  assert.equal(turn.hops.length, 1);
  assert.equal(turn.hops[0].tool, 'summarizer.summarize_file');
  assert.deepEqual(turn.hops[0].params, {});
  assert.equal(turn.hops[0].error, null); assert.equal(turn.hops[0].policyViolation, null);
  for (const kind of ['local_tool_call', 'local_tool_result', 'final', 'terminal'])
    assert.equal(traces.filter(trace => trace.kind === kind).length, 1);
  assert.equal(traces.filter(trace => ['error', 'tool_cancelled', 'tool_blocked'].includes(trace.kind)).length, 0);
  for (const span of actorSpans) {
    assert.equal(span.response.mocked, false);
    assert.notEqual(span.response.fallback, true);
    assert.ok(qualifyModel(span.response));
  }
  const selected = actorSpans[0].response.tool_uses;
  assert.equal(selected.length, 1);
  const call = selected[0];
  assert.equal(call.name, 'summarizer.summarize_file');
  assert.deepEqual(call.args, {});
  assert.equal(call.id, meta.graphEffect.callId);
  assert.equal(actorSpans[1].response.stop_reason, 'end_turn');
  assert.equal(actorSpans[1].response.text, turn.text);
  assert.ok(!actorSpans[1].response.tool_uses?.length);
  const decisions = traces.filter(trace => trace.kind === 'model_decision');
  assert.equal(decisions.length, 2);
  assert.deepEqual(parsed(decisions[0].params_json), {
    decision: 'tool_use', toolCalls: [{ id: call.id, name: call.name, args: {} }]
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

async function readOriginalFileSummary(input) {
  const { agents, identity, conversations, sourceReader, scope, persona, personaSession,
    target, mode, sessionId, requestId, actorSpans, qualifyModel, check, checkAtEffect } = input;
  assert.equal(typeof check, 'function'); assert.equal(typeof checkAtEffect, 'function');
  assert.match(sessionId, UUID); assert.match(requestId, UUID);
  await check();
  const binding = createConversationBinding(scope, persona);
  const row = await createV19FileSummaryTurnReader({ pool: agents }).readFileSummaryRequest({
    binding, sessionId, requestId, purpose: SUMMARY_PURPOSE
  });
  assert.equal(row?.status, 'completed');
  const turn = row.result_json, meta = turn?.taskMetadata?.boundFileSummary;
  assert.equal(meta?.outcome, 'read');
  const original = JSON.parse(meta.originalEnvelope);
  assert.equal(createTurnRequest({ sessionId, requestId, binding, message: meta.originalEnvelope }).hash, row.request_hash);
  assert.equal(original.authoritySha256, canonicalDigest(meta.attachmentReceipt.authority));
  assert.equal(original.operationId, meta.operationId);
  const traces = await conversations.getTraceEvents(sessionId, binding, meta.traceEventIds, SUMMARY_PURPOSE);
  assert.deepEqual(traces.map(trace => trace.event_id), meta.traceEventIds);
  const graph = meta.graphEffect;
  assert.equal(graph.ownerKey, JSON.stringify(['SecureShopBoundConversation', sessionId]));
  assert.equal(graph.effectKey, `${requestId}:${JSON.stringify([1, graph.callId, 'summarizer.summarize_file'])}`);
  const effects = (await identity.query(`SELECT e.run_id::text,e.owner_key,e.generation::text,e.effect_key,e.status,
    r.status run_status,o.generation::text live_generation FROM graph_runtime.effects e
    JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
    JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
    WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4`,
  [graph.runId, graph.ownerKey, graph.generation, graph.effectKey])).rows;
  assert.equal(effects.length, 1);
  const graphEffect = effects[0];
  assert.equal(graphEffect.status, 'completed'); assert.equal(graphEffect.run_status, 'completed');
  assert.equal(String(graphEffect.live_generation), graph.generation);
  const retained = await sourceReader.read({ scope: binding, persona, personaSession, sessionId, requestId,
    receipt: meta.attachmentReceipt, target, mode, check, checkAtEffect });
  assert.deepEqual(retained.receipt.attachment, original.attachment);
  assert.equal(hash(retained.data), original.attachment.bodySha256);
  assert.equal(retained.data.length, original.attachment.byteCount);
  const actor = assertOriginalActorJoin({ actorSpans, row, traces, qualifyModel });
  const candidate = buildFileSummaryCandidate({ binding, personaSession, row, traces, graphEffect, retained, qualifyModel });
  if (mode.mode === 'vuln') {
    assert.ok(candidate); assert.equal(candidate.objectiveId, SUMMARY_OBJECTIVE);

  } else { assert.equal(mode.mode, 'fixed'); assert.equal(candidate, null); }
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

async function assertCanonicalFileSummaryAssessment({ identity, assessment, scope, persona, personaSession,
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
  assert.equal(saved.objective_id, SUMMARY_OBJECTIVE); assert.equal(saved.family, SUMMARY_RUBRIC.family);
  assert.equal(saved.scenario, SUMMARY_RUBRIC.scenario); assert.equal(saved.rubric_version, SUMMARY_RUBRIC.version);
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
    [evaluationId, SUMMARY_OBJECTIVE, persona.id, scope.launchId, String(scope.platformOwnerId)])).rows;
    assert.deepEqual(credit, expectedVerdict === 'pass' ? [{ evaluation_id: evaluationId }] : []);
  }
  await guard.assertCurrent();
  return Object.freeze({ judgment: saved });
}
module.exports = { COUNTERS, assertOriginalActorJoin, readOriginalFileSummary,
  assertCounterSnapshot, assertGetOnlyRecovery, assertCanonicalFileSummaryAssessment };
