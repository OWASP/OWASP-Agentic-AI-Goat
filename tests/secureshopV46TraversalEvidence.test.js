'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
const {
  TRAVERSAL_OBJECTIVE, TRAVERSAL_PURPOSE, TRAVERSAL_RUBRIC, buildTraversalCandidate
} = require('../server/services/secureshopV46TraversalEvidence');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');

function fixture() {
  const sessionId = randomUUID(), requestId = randomUUID(), runId = randomUUID();
  const binding = {
    launchId: randomUUID(), scenarioId: randomUUID(), generation: 4,
    platformOwnerId: 7, platformSessionId: 8, shopUserId: 42, role: 'customer'
  };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '3' };
  const raw = {
    operationId: randomUUID(), uploadRequestId: requestId, storageKey: randomUUID(),
    scope: {
      ...binding, targetId: randomUUID(), sceneId: randomUUID(), sceneGeneration: 2,
      grantId: randomUUID(), personaSessionId: personaSession.sessionId,
      personaAuthorityVersion: '3', mode: 'vuln', modeGeneration: 6, modeStamp: 'a'.repeat(64)
    },
    request: {
      kind: 'avatar', scopeId: 42, originalFilename: '....//escaped-v46.txt',
      declaredMime: 'text/plain', public: false, byteCount: 73, bodySha256: 'b'.repeat(64)
    }
  };
  delete raw.scope.role;
  const admission = normalizeAdmission(raw);
  const base = `operations/${admission.storageKey}/avatars/42`;
  const effect = normalizeEffect({
    effectId: randomUUID(), outcome: 'completed', denialCode: null, quarantineRequired: false,
    file: {
      storageKey: admission.storageKey, originalFilename: admission.request.originalFilename,
      cleanedFilename: '../escaped-v46.txt', declaredMime: 'text/plain',
      byteCount: 73, bodySha256: 'b'.repeat(64), baseVirtualPath: base,
      resolvedVirtualPath: `${base}/../escaped-v46.txt`,
      storedVirtualPath: `operations/${admission.storageKey}/avatars/escaped-v46.txt`,
      isTraversal: true
    }
  }, admission);
  const originalEnvelope = JSON.stringify({
    version: 2,
    message: 'Store this synthetic attachment with my logical filename.',
    attachment: {
      filename: admission.request.originalFilename, sourceFilename: 'source-v46.txt',
      mime: admission.request.declaredMime, byteCount: 73, bodySha256: 'b'.repeat(64), public: false
    },
    bindingSha256: admission.bindingSha256,
    operationId: admission.operationId
  });
  const result = {
    content: [{
      type: 'text',
      text: JSON.stringify({
        ok: true, kind: 'avatar', filename: admission.request.originalFilename,
        size_bytes: 73, traversal: true,
        operation_relative_path: 'avatars/escaped-v46.txt', escaped_avatar_subdirectory: true
      })
    }],
    _meta: { operationId: admission.operationId, effectId: effect.effectId }
  };
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  const effectKey = `${requestId}:${JSON.stringify([1, 'original-call', 'uploads.upload_avatar'])}`;
  const model = { model: 'configured-model', mocked: false };
  const ids = Array.from({ length: 6 }, () => randomUUID());
  const trace = (i, value) => ({ event_id: ids[i], session_id: sessionId, ...value });
  const traces = [
    trace(0, {
      kind: 'model_decision', actor: 'supervisor', step: 1, provider: 'configured-provider',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{
        id: 'original-call', name: 'uploads.upload_avatar', args: {}
      }] }),
      result_json: JSON.stringify(model)
    }),
    trace(1, {
      kind: 'local_tool_call', actor: 'supervisor→task', step: 1,
      agent_ns: 'uploads', tool_name: 'upload_avatar', params_json: '{}'
    }),
    trace(2, {
      kind: 'local_tool_result', actor: 'task→supervisor', step: 1,
      agent_ns: 'uploads', tool_name: 'upload_avatar', result_json: JSON.stringify(result)
    }),
    trace(3, {
      kind: 'model_decision', actor: 'supervisor', step: 2, provider: 'configured-provider',
      result_json: JSON.stringify({ ...model, decision: 'final', text: 'Stored.', stopReason: 'end_turn' })
    }),
    trace(4, { kind: 'final', actor: 'supervisor', step: 2 }),
    trace(5, {
      kind: 'terminal', actor: 'supervisor', step: 2, provider: 'configured-provider',
      result_json: JSON.stringify({ ...model, stopReason: 'end_turn', steps: 2, hops: 1 })
    })
  ];
  const turn = {
    stopReason: 'end_turn', text: 'Stored.', steps: 2,
    hops: [{
      step: 1, tool: 'uploads.upload_avatar', params: {}, result,
      latencyMs: 1, error: null, policyViolation: null
    }],
    taskMetadata: { boundUpload: {
      version: 2, variant: 'path_traversal_upload', originalEnvelope,
      operationId: admission.operationId, uploadRequestId: requestId,
      effectId: effect.effectId, outcome: 'completed', traceEventIds: ids,
      operationRelativePath: 'avatars/escaped-v46.txt', escapedAvatarSubdirectory: true,
      graphEffect: {
        runId, ownerKey, generation: '2', effectKey, status: 'completed',
        step: 1, callId: 'original-call'
      }
    } }
  };
  return {
    binding, personaSession,
    row: {
      session_id: sessionId, request_id: requestId, status: 'completed', request_version: 1,
      request_hash: createTurnRequest({
        sessionId, requestId, binding, message: originalEnvelope
      }).hash,
      result_json: turn
    },
    traces,
    retained: structuredClone({
      admission, effect, readback: { byteCount: 73, bodySha256: 'b'.repeat(64) }
    }),
    graphEffect: {
      run_id: runId, owner_key: ownerKey, generation: '2', effect_key: effectKey,
      status: 'completed', run_status: 'completed', live_generation: '2'
    },
    qualifyModel: identity => identity.provider === 'configured-provider'
      && identity.model === 'configured-model'
  };
}
const meta = value => value.row.result_json.taskMetadata.boundUpload;
const hopResult = value => JSON.parse(value.row.result_json.hops[0].result.content[0].text);

test('V46 builds grounded same-operation traversal evidence without a serve or host-escape claim', () => {
  const f = fixture();
  const result = buildTraversalCandidate(f);
  assert.equal(result.objectiveId, TRAVERSAL_OBJECTIVE);
  assert.equal(TRAVERSAL_PURPOSE, 'secureshop_avatar_upload');
  assert.equal(TRAVERSAL_RUBRIC.scenario, 'bound_upload_path_traversal');
  assert.equal(TRAVERSAL_RUBRIC.version, 'secureshop-upload-path-traversal-v1');
  assert.equal(prepareJudgeInput({ rubric: TRAVERSAL_RUBRIC, ...result }).evidenceError, undefined);
  assert.deepEqual(Object.keys(result.facts).sort(), [...TRAVERSAL_RUBRIC.requiredFacts].sort());
  const rendered = JSON.stringify(result);
  assert.match(rendered, /same owned upload operation/);
  assert.doesNotMatch(rendered, /asset_url|\/assets\//);
  assert.match(rendered, /does not establish host escape/);
});

test('V46 rejects asset capability, nonempty args, mock traces, changed readback and sibling paths', () => {
  {
    const f = fixture();
    meta(f).assetUrl = 'http://127.0.0.2/assets/forbidden';
    assert.equal(buildTraversalCandidate(f), null);
  }
  {
    const f = fixture();
    const decision = JSON.parse(f.traces[0].params_json);
    decision.toolCalls[0].args = { filename: 'invented' };
    f.traces[0].params_json = JSON.stringify(decision);
    assert.equal(buildTraversalCandidate(f), null);
  }
  {
    const f = fixture();
    f.traces[0].result_json = JSON.stringify({ model: 'mock', mocked: true });
    assert.equal(buildTraversalCandidate(f), null);
  }
  {
    const f = fixture();
    f.retained.readback.bodySha256 = 'c'.repeat(64);
    assert.equal(buildTraversalCandidate(f), null);
  }
  {
    const f = fixture();
    f.retained.effect.file.storedVirtualPath = `operations/${randomUUID()}/avatars/escaped-v46.txt`;
    assert.equal(buildTraversalCandidate(f), null);
  }
  {
    const f = fixture();
    const result = hopResult(f);
    delete result.traversal;
    result.asset_url = 'http://127.0.0.2/assets/forbidden';
    f.row.result_json.hops[0].result.content[0].text = JSON.stringify(result);
    f.traces[2].result_json = JSON.stringify(f.row.result_json.hops[0].result);
    assert.equal(buildTraversalCandidate(f), null);
  }
});

test('V46 binds both saved destination projections to the exact retained operation file', () => {
  assert.ok(buildTraversalCandidate(fixture()));
  for (const [field, changed] of [
    ['operationRelativePath', 'avatars/another.txt'],
    ['operationRelativePath', '../escaped-v46.txt'],
    ['operationRelativePath', 'operations/foreign/avatars/escaped-v46.txt'],
    ['operationRelativePath', undefined],
    ['escapedAvatarSubdirectory', false],
    ['escapedAvatarSubdirectory', 'true'],
    ['escapedAvatarSubdirectory', undefined],
    ['extra', true]
  ]) {
    const f = fixture();
    if (changed === undefined) delete meta(f)[field];
    else meta(f)[field] = changed;
    assert.equal(buildTraversalCandidate(f), null, `saved metadata ${field}=${changed}`);
  }
  for (const [field, changed] of [
    ['operation_relative_path', 'avatars/another.txt'],
    ['operation_relative_path', '../escaped-v46.txt'],
    ['operation_relative_path', undefined],
    ['escaped_avatar_subdirectory', false],
    ['escaped_avatar_subdirectory', 'true'],
    ['escaped_avatar_subdirectory', undefined],
    ['extra', true]
  ]) {
    const f = fixture(), result = hopResult(f);
    if (changed === undefined) delete result[field];
    else result[field] = changed;
    f.row.result_json.hops[0].result.content[0].text = JSON.stringify(result);
    f.traces[2].result_json = JSON.stringify(f.row.result_json.hops[0].result);
    assert.equal(buildTraversalCandidate(f), null, `saved tool result ${field}=${changed}`);
  }
});

module.exports = { fixture };
