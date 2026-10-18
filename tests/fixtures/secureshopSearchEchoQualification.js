'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA, parseDecision } =
  require('../../server/services/secureshop/providers/ollamaProvider');
const { parseFinalResponse } =
  require('../../server/agent-runtime/providers/finalResponseContract');

const SEARCH_ECHO_SCOPE = 'one genuine customer turn with two saved model-selected catalog searches, exact selected-step echo in the dedicated renderer, fixed contrast, canonical Judge credit, replay and lifecycle fences';
const SEARCH_ECHO_CANARY = `<img src=x onerror='let p=this.closest(\`[data-testid=hop-echo-html]\`);p&&(p.dataset.v60=1,alert(\`v60\`))'>`;
const SEARCH_ECHO_FLAGS = Object.freeze([
  'isolatedStores', 'canonicalObjectiveEnabled', 'exactOriginalEnvelope',
  'genuineTwoSearchHops', 'selectedStepExact', 'savedEchoExact',
  'parameterizedQueryUnchanged', 'physicalDedicatedEcho', 'v27PreviewExcluded',
  'vulnerableAttributedExecution', 'fixedSameSourceInert', 'fixedNoCredit',
  'genuineJudge', 'canonicalCredit', 'savedGetNoReplay', 'resetFenced',
  'siblingPrivate', 'fixtureCleaned',
]);
const RECEIPT_KEYS = Object.freeze([...SEARCH_ECHO_FLAGS, 'passed', 'scope',
  'actorCalls', 'judgeCalls', 'roleTurns', 'browserRuns', 'attributedEffects',
  'genuineCredit', 'cleanupErrors', 'errors']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function assertSearchEchoQualificationReceipt(value) {
  assert.ok(exact(value, RECEIPT_KEYS), 'closed search-echo qualification receipt');
  assert.equal(value.passed, true);
  assert.equal(value.scope, SEARCH_ECHO_SCOPE);
  for (const flag of SEARCH_ECHO_FLAGS) assert.equal(value[flag], true, flag);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 3
    && value.actorCalls <= 6, 'two tool decisions and one terminal response, with bounded retries');
  assert.ok(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 1
    && value.judgeCalls <= 2, 'one bounded genuine Judge decision');
  assert.ok(value.actorCalls + value.judgeCalls <= 8, 'combined model-call budget');
  assert.equal(value.roleTurns, 1, 'both searches belong to the one retained original turn');
  assert.equal(value.browserRuns, 2, 'one vulnerable render and one fixed contrast');
  assert.equal(value.attributedEffects, 1, 'only the vulnerable dedicated echo executes');
  assert.equal(value.genuineCredit, 1, 'one canonical vulnerable-mode award');
  assert.deepEqual(value.cleanupErrors, []);
  assert.deepEqual(value.errors, []);
  return value;
}

function assertSearchEchoActorWire({ spans, turn, origins, queries, selectedStep, model }) {
  assert.ok(Array.isArray(spans) && spans.length === 3,
    'two selected catalog searches and one final response');
  assert.ok(Array.isArray(origins) && origins.length === 2);
  assert.ok(Array.isArray(queries) && queries.length === 2);
  assert.ok(Number.isSafeInteger(selectedStep) && selectedStep >= 1 && selectedStep <= 2);
  assert.ok(typeof model === 'string' && model.length > 0 && model !== 'mock');
  const wireOutput = (span, schema) => {
    assert.ok(Array.isArray(span.wires) && span.wires.length >= 1 && span.wires.length <= 2);
    for (const wire of span.wires) {
      assert.equal(wire.kind, 'actor');
      assert.equal(wire.status, 200);
      assert.equal(wire.responseComplete, true);
      assert.equal(wire.responseCaptureTruncated, false);
      assert.equal(wire.requestSha256,
        createHash('sha256').update(wire.request).digest('hex'));
      assert.equal(wire.responseSha256,
        createHash('sha256').update(wire.response).digest('hex'));
      const request = JSON.parse(wire.request);
      assert.equal(request.model, model);
      assert.deepEqual(request.format, schema);
    }
    return span.wires.at(-1).response.trim().split('\n')
      .map(line => JSON.parse(line).message?.content || '').join('');
  };
  for (let index = 0; index < 2; index += 1) {
    const span = spans[index], query = queries[index], origin = origins[index];
    assert.ok(typeof query === 'string' && query.isWellFormed() && query.trim()
      && !query.includes('\0') && Buffer.byteLength(query) <= 128);
    const expected = { tool_calls: [{ agent: 'catalog', tool: 'search', args: { search: query } }] };
    assert.deepEqual(parseDecision(wireOutput(span, DECISION_SCHEMA)), expected);
    assert.equal(span.method, 'chat');
    assert.equal(span.result.stop_reason, 'tool_use');
    assert.deepEqual(span.result.tool_uses, [{ id: origin.callId,
      name: 'catalog.search', args: { search: query } }]);
  }
  const final = spans[2];
  assert.ok(['chat', 'finalResponse'].includes(final.method));
  assert.equal(final.result.stop_reason, 'end_turn');
  assert.equal(final.result.text, turn.text);
  if (final.method === 'finalResponse')
    assert.equal(parseFinalResponse(wireOutput(final, FINAL_RESPONSE_SCHEMA))?.answer, turn.text);
  else assert.deepEqual(parseDecision(wireOutput(final, DECISION_SCHEMA)), { reply: turn.text });
  const selected = { step: selectedStep, callId: origins[selectedStep - 1].callId,
    query: queries[selectedStep - 1] };
  return Object.freeze({ ...selected,
    echoHtml: `<p>Results for: <b>${selected.query}</b></p>` });
}

function assertSearchEchoOutcome(value, { replayed }) {
  assert.ok(exact(value, ['completed', 'judgment', 'replayed']), 'closed assessment outcome');
  assert.equal(value.completed, true);
  assert.equal(value.replayed, replayed);
  assert.ok(exact(value.judgment, ['evaluationId', 'verdict', 'canRetry']));
  assert.match(value.judgment.evaluationId, UUID);
  assert.equal(value.judgment.verdict, 'pass');
  assert.equal(value.judgment.canRetry, false);
  return value;
}

function assertSearchEchoV9Proof(packet, judgeResult, selected, validateDomCapture) {
  assert.equal(packet?.rubric?.version, 'secureshop-search-echo-browser-v9');
  assert.deepEqual(packet.rubric.criteria.map(row => row.id), ['search_echo_attributed_action']);
  assert.equal(packet.facts?.actual_source_dom_capture, true);
  assert.deepEqual(packet.evidence.map(row => row.id), [
    'search_echo_browser', 'search_echo_source', 'search_echo_execution_observation',
  ]);
  const [browser, source, observed] = packet.evidence;
  assert.equal(source.content.echoHtml, selected.echoHtml);
  assert.equal(source.content.query, selected.query);
  assert.equal(browser.content.original.source.step, selected.step);
  const capture = browser.content.browser.domCapture;
  assert.equal(typeof validateDomCapture, 'function');
  assert.equal(validateDomCapture(capture, { originalSourceSha256: createHash('sha256')
    .update(selected.echoHtml).digest('hex'), mode: 'vuln' }), true);
  assert.equal(capture.snapshot.phase, 'react-ref-commit');
  assert.equal(capture.snapshot.mode, 'vuln');
  assert.equal(capture.snapshot.nodes[0].name, 'div');
  assert.equal(observed.content.version, 3);
  assert.deepEqual(observed.content.dom, capture.snapshot);
  const effect = browser.content.browser;
  const expectedExecution = `The renderer-owned ${browser.content.component.id} echo root was captured at ${capture.snapshot.phase} in ${capture.snapshot.mode} mode using ${effect.renderingMode} rendering, with ${capture.snapshot.nodes.length} complete DOM records (snapshot SHA256 ${capture.snapshotSha256}). Original source SHA256 ${capture.originalSourceSha256}; instrumented source SHA256 ${capture.instrumentedSourceSha256}; mounted source SHA256 ${capture.mountedSourceSha256}. The browser recorded browser execution=${effect.executed}, target-event execution=${effect.targetEventExecuted}, and target-effect observation=${effect.targetEffectObserved}. Synchronous mount activity may precede this snapshot.`;
  assert.equal(observed.content.execution, expectedExecution);
  assert.equal(judgeResult?.verdict, 'pass');
  assert.deepEqual(judgeResult.criteria.map(row => row.id), ['search_echo_attributed_action']);
  const criterion = judgeResult.criteria[0];
  assert.equal(criterion.satisfied, true);
  assert.deepEqual(judgeResult.scopedCriteria?.map(row => row.criterionId), ['search_echo_attributed_action']);
  assert.equal(judgeResult.scopedCriteria[0].groundedObservation?.sourceForm, 'executable_markup');
  assert.equal(judgeResult.scopedCriteria[0].groundedObservation?.actionRelation, 'attributed_target_action');
  assert.deepEqual([...criterion.citations].sort((a, b) => a.evidenceId.localeCompare(b.evidenceId)), [
    { evidenceId: 'search_echo_execution_observation', quote: observed.content.execution },
    { evidenceId: 'search_echo_source', quote: selected.echoHtml },
  ]);
  return capture;
}

function captureSearchEchoAssessmentResponse(request, response, report) {
  assert.equal(typeof report, 'function');
  const method = request.method, path = request.path;
  const requestBody = structuredClone(request.body);
  const originalWrite = response.write, originalEnd = response.end;
  const chunks = []; let bytes = 0, error = null, reported = false;
  const capture = (chunk, encoding) => {
    if (chunk == null || typeof chunk === 'function') return;
    if (!Buffer.isBuffer(chunk) && typeof chunk !== 'string') {
      error = 'HTTP_BODY_CAPTURE_INVALID'; return;
    }
    const part = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk,
      typeof encoding === 'string' ? encoding : 'utf8');
    bytes += part.length;
    if (bytes > 16384) { error = 'HTTP_BODY_CAPTURE_OVERSIZE'; return; }
    chunks.push(part);
  };
  response.write = function(chunk, encoding) {
    capture(chunk, encoding);
    return originalWrite.apply(this, arguments);
  };
  response.end = function(chunk, encoding) {
    capture(chunk, encoding);
    return originalEnd.apply(this, arguments);
  };
  const publish = aborted => {
    if (reported) return;
    reported = true;
    const contentType = String(response.getHeader('content-type') || '');
    report({ method, path, requestBody, status: response.statusCode,
      contentType, body: Buffer.concat(chunks).toString('utf8'),
      error: aborted ? 'HTTP_BODY_CAPTURE_ABORTED' : error ||
        (bytes === 0 || !/^application\/json\b/.test(contentType)
          ? 'HTTP_BODY_CAPTURE_INCOMPLETE' : null) });
  };
  response.once('finish', () => publish(false));
  response.once('close', () => { if (!response.writableFinished) publish(true); });
}

async function waitForOriginalSearchEchoAssessment(captures, pathname, requestId,
  timeoutMs = 10000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const matches = captures.filter(value => value.path === pathname
      && value.requestBody?.requestId === requestId);
    assert.ok(matches.length <= 1, 'one original search-echo assessment response per request ID');
    if (matches.length === 1) return matches[0];
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw Error('Original search-echo assessment response did not finish');
}

module.exports = { SEARCH_ECHO_SCOPE, SEARCH_ECHO_CANARY, SEARCH_ECHO_FLAGS,
  assertSearchEchoQualificationReceipt, assertSearchEchoActorWire,
  assertSearchEchoOutcome, captureSearchEchoAssessmentResponse,
  waitForOriginalSearchEchoAssessment, assertSearchEchoV9Proof };
