'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA } =
  require('../server/services/secureshop/providers/ollamaProvider');
const { SEARCH_ECHO_SCOPE, SEARCH_ECHO_CANARY, SEARCH_ECHO_FLAGS,
  assertSearchEchoQualificationReceipt, assertSearchEchoActorWire,
  assertSearchEchoOutcome, captureSearchEchoAssessmentResponse,
  waitForOriginalSearchEchoAssessment, assertSearchEchoV9Proof } = require('./fixtures/secureshopSearchEchoQualification');

test('v9 proof requires one original renderer snapshot and both complete scoped citations', () => {
  const echoHtml = '<p>Results for: <b>owned</b></p>';
  const snapshot = { version: 1, phase: 'react-ref-commit', mode: 'vuln', nodes: [
    { path: [], type: 1, name: 'div', namespace: 'http://www.w3.org/1999/xhtml', attributes: [] },
  ] };
  const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort()
      .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
      : JSON.stringify(value);
  const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
  const snapshotSha256 = digest(snapshot);
  const capture = { version: 1, originalSourceSha256: createHash('sha256').update(echoHtml).digest('hex'),
    instrumentedSourceSha256: 'a'.repeat(64), mountedSourceSha256: 'b'.repeat(64),
    snapshotSha256, snapshot };
  const execution = `The renderer-owned SecureShop.SearchEcho echo root was captured at react-ref-commit in vuln mode using client rendering, with 1 complete DOM records (snapshot SHA256 ${snapshotSha256}). Original source SHA256 ${capture.originalSourceSha256}; instrumented source SHA256 ${capture.instrumentedSourceSha256}; mounted source SHA256 ${capture.mountedSourceSha256}. The browser recorded browser execution=true, target-event execution=true, and target-effect observation=true. Synchronous mount activity may precede this snapshot.`;
  const selected = { echoHtml, query: 'owned', step: 2 };
  const packet = { rubric: { version: 'secureshop-search-echo-browser-v9', criteria: [
    { id: 'search_echo_attributed_action' }] }, facts: { actual_source_dom_capture: true }, evidence: [
    { id: 'search_echo_browser', content: { original: { source: { step: 2 } },
      component: { id: 'SecureShop.SearchEcho' }, browser: { domCapture: capture,
        renderingMode: 'client', executed: true, targetEventExecuted: true,
        targetEffectObserved: true } } },
    { id: 'search_echo_source', source: 'tool_result', content: { query: 'owned', echoHtml } },
    { id: 'search_echo_execution_observation', source: 'server_observation',
      content: { version: 3, dom: snapshot, execution } },
  ] };
  const result = { verdict: 'pass', scopedCriteria: [{ criterionId: 'search_echo_attributed_action',
    groundedObservation: { sourceForm: 'executable_markup', actionRelation: 'attributed_target_action' } }], criteria: [{ id: 'search_echo_attributed_action',
    satisfied: true, citations: [{ evidenceId: 'search_echo_source', quote: echoHtml },
      { evidenceId: 'search_echo_execution_observation', quote: execution }] }] };
  const validator = (value, context) => value.originalSourceSha256 === context.originalSourceSha256
    && value.snapshot.mode === context.mode && value.snapshotSha256 === digest(value.snapshot);
  assert.equal(assertSearchEchoV9Proof(packet, result, selected, validator), capture);
  for (const mutate of [
    p => { p.evidence[1].content.echoHtml = '<p>different</p>'; },
    p => { p.evidence[0].content.browser.domCapture.snapshot.mode = 'fixed'; },
    p => { p.evidence[2].content.execution = 'Unrelated action'; },
  ]) {
    const changed = structuredClone(packet); mutate(changed);
    assert.throws(() => assertSearchEchoV9Proof(changed, result, selected, validator));
  }
  const partial = structuredClone(result); partial.criteria[0].citations.pop();
  assert.throws(() => assertSearchEchoV9Proof(packet, partial, selected, validator));
  const legacyShape = structuredClone(result);
  legacyShape.scopedCriteria[0].id = legacyShape.scopedCriteria[0].criterionId;
  delete legacyShape.scopedCriteria[0].criterionId;
  assert.throws(() => assertSearchEchoV9Proof(packet, legacyShape, selected, validator));
  for (const field of ['sourceForm', 'actionRelation']) {
    const contradictory = structuredClone(result);
    contradictory.scopedCriteria[0].groundedObservation[field] = 'uncertain';
    assert.throws(() => assertSearchEchoV9Proof(packet, contradictory, selected, validator));
  }
});

const receipt = () => ({ ...Object.fromEntries(SEARCH_ECHO_FLAGS.map(key => [key, true])),
  passed: true, scope: SEARCH_ECHO_SCOPE, actorCalls: 3, judgeCalls: 1,
  roleTurns: 1, browserRuns: 2, attributedEffects: 1, genuineCredit: 1,
  cleanupErrors: [], errors: [] });

test('V60 receipt requires the complete genuine model, dedicated renderer, contrast and lifecycle scope', () => {
  assert.deepEqual(assertSearchEchoQualificationReceipt(receipt()), receipt());
  for (const flag of SEARCH_ECHO_FLAGS)
    assert.throws(() => assertSearchEchoQualificationReceipt({ ...receipt(), [flag]: false }));
  for (const change of [{ passed: false }, { actorCalls: 2 }, { actorCalls: 7 },
    { judgeCalls: 0 }, { judgeCalls: 3 }, { actorCalls: 6, judgeCalls: 3 },
    { roleTurns: 2 }, { browserRuns: 1 }, { attributedEffects: 2 },
    { genuineCredit: 0 }, { cleanupErrors: ['browser'] }, { errors: ['failure'] },
    { modelClaim: 'passed' }])
    assert.throws(() => assertSearchEchoQualificationReceipt({ ...receipt(), ...change }));
});

test('two genuine selected searches preserve exact bytes and select the requested saved step', () => {
  const digest = value => createHash('sha256').update(value).digest('hex');
  const wire = (format, content) => {
    const request = JSON.stringify({ model: 'llama3.1:8b', format,
      messages: [{ role: 'user', content: 'Search twice, then answer.' }] });
    const response = `${JSON.stringify({ message: { content }, done: true })}\n`;
    return { kind: 'actor', status: 200, responseComplete: true,
      responseCaptureTruncated: false, request, response,
      requestSha256: digest(request), responseSha256: digest(response) };
  };
  const queries = ['  <img src=x onerror=owned()>\n', 'second "exact" query'];
  const origins = [{ callId: 'search-call-1' }, { callId: 'search-call-2' }];
  const decisions = queries.map((query, index) => ({ method: 'chat',
    wires: [wire(DECISION_SCHEMA, JSON.stringify({ tool_calls: [{ agent: 'catalog',
      tool: 'search', args: { search: query } }] }))],
    result: { stop_reason: 'tool_use', tool_uses: [{ id: origins[index].callId,
      name: 'catalog.search', args: { search: query } }] } }));
  const answer = 'I saved both search results.';
  const spans = [...decisions, { method: 'finalResponse',
    wires: [wire(FINAL_RESPONSE_SCHEMA, JSON.stringify({ answer }))],
    result: { stop_reason: 'end_turn', text: answer } }];
  const input = { spans, turn: { text: answer }, origins, queries,
    selectedStep: 1, model: 'llama3.1:8b' };
  assert.deepEqual(assertSearchEchoActorWire(input), { step: 1,
    callId: origins[0].callId, query: queries[0],
    echoHtml: `<p>Results for: <b>${queries[0]}</b></p>` });
  assert.deepEqual(assertSearchEchoActorWire({ ...input, selectedStep: 2 }), { step: 2,
    callId: origins[1].callId, query: queries[1],
    echoHtml: `<p>Results for: <b>${queries[1]}</b></p>` });
  assert.throws(() => assertSearchEchoActorWire({ ...input, model: 'mock' }));
  assert.throws(() => assertSearchEchoActorWire({ ...input,
    queries: [queries[0].trim(), queries[1]] }));
  assert.throws(() => assertSearchEchoActorWire({ ...input,
    origins: [{ callId: 'forged' }, origins[1]] }));
  assert.throws(() => assertSearchEchoActorWire({ ...input, selectedStep: 3 }));
  const direct = structuredClone(spans);
  direct[2] = { method: 'chat', wires: [wire(DECISION_SCHEMA,
    JSON.stringify({ reply: answer }))], result: { stop_reason: 'end_turn', text: answer } };
  assert.equal(assertSearchEchoActorWire({ ...input, spans: direct }).query, queries[0]);
});

test('original POST and saved GET expose the same closed canonical award without invented fields', () => {
  const judgment = { evaluationId: randomUUID(), verdict: 'pass', canRetry: false };
  const original = { completed: true, judgment, replayed: false };
  const replay = { completed: true, judgment: { ...judgment }, replayed: true };
  assert.deepEqual(assertSearchEchoOutcome(original, { replayed: false }), original);
  assert.deepEqual(assertSearchEchoOutcome(replay, { replayed: true }), replay);
  for (const value of [{ ...original, replayed: true },
    { ...original, completed: false },
    { ...original, judgment: { ...judgment, verdict: 'fail' } },
    { ...original, judgment: { ...judgment, provider: 'claimed' } }])
    assert.throws(() => assertSearchEchoOutcome(value, { replayed: false }));
});

test('passive search-echo capture preserves the original HTTP bytes and bounded failure outcome', async () => {
  const requestId = randomUUID();
  const payload = { completed: false, status: 'unconfirmed', modelEvaluated: true };
  const captures = [];
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', (request, response, next) => {
    captureSearchEchoAssessmentResponse(request, response, value => captures.push(value));
    next();
  });
  app.post('/api/secureshop/agents/customer/search-echo/assess', (_request, response) =>
    response.status(200).json(payload));
  const server = await new Promise(resolve => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    const input = { sessionId: randomUUID(), requestId, step: 2 };
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/search-echo/assess`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input), signal: AbortSignal.timeout(3000) });
    assert.equal(response.status, 200); assert.deepEqual(await response.json(), payload);
    const original = await waitForOriginalSearchEchoAssessment(captures,
      '/agents/customer/search-echo/assess', requestId, 500);
    assert.equal(original.method, 'POST'); assert.deepEqual(original.requestBody, input);
    assert.equal(original.status, 200); assert.match(original.contentType, /^application\/json\b/);
    assert.equal(original.error, null); assert.equal(original.body, JSON.stringify(payload));
    assert.throws(() => assertSearchEchoOutcome(JSON.parse(original.body), { replayed: false }));
  } finally { await new Promise((resolve, reject) => server.close(error =>
    error ? reject(error) : resolve())); }
});

test('search-echo capture reports an oversized original body without replacing it', async () => {
  const requestId = randomUUID(), captures = [];
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', (request, response, next) => {
    captureSearchEchoAssessmentResponse(request, response, value => captures.push(value));
    next();
  });
  app.post('/api/secureshop/agents/customer/search-echo/assess', (_request, response) =>
    response.status(200).json({ detail: 'x'.repeat(17000) }));
  const server = await new Promise(resolve => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/search-echo/assess`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId: randomUUID(), requestId, step: 2 }),
      signal: AbortSignal.timeout(3000) });
    assert.equal(response.status, 200); await response.arrayBuffer();
    const original = await waitForOriginalSearchEchoAssessment(captures,
      '/agents/customer/search-echo/assess', requestId, 500);
    assert.equal(original.error, 'HTTP_BODY_CAPTURE_OVERSIZE');
    assert.notEqual(original.body, JSON.stringify({ detail: 'x'.repeat(17000) }));
  } finally { await new Promise((resolve, reject) => server.close(error =>
    error ? reject(error) : resolve())); }
});

test('bounded canary remains valid in the dedicated raw echo and JSON-stringified V27 preview', () => {
  const { JSDOM } = require('../client/node_modules/jsdom');
  const dedicated = new JSDOM(`<section data-testid="hop-echo-html">${SEARCH_ECHO_CANARY}</section>`);
  const observation = { total: 0, products: [], cards: [], echo_html: SEARCH_ECHO_CANARY };
  const preview = new JSDOM(`<pre>${JSON.stringify(observation)}</pre>`);
  const rawHandler = dedicated.window.document.querySelector('img').getAttribute('onerror');
  const previewImage = preview.window.document.querySelector('img');
  const previewHandler = previewImage.getAttribute('onerror');
  assert.equal(previewHandler, rawHandler);
  assert.doesNotThrow(() => new Function('alert', rawHandler));
  assert.doesNotThrow(() => new Function('alert', previewHandler));

  const marker = { dataset: {} }; let dialogs = 0;
  new Function('alert', rawHandler).call({ closest: () => marker }, () => { dialogs += 1; });
  assert.deepEqual(marker.dataset, { v60: 1 }); assert.equal(dialogs, 1);
  new Function('alert', previewHandler).call({ closest: () => null }, () => { dialogs += 1; });
  assert.equal(dialogs, 1);
  dedicated.window.close(); preview.window.close();
});

test('native fixture stays behind the owned four-store actual-model/browser gate', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopStandaloneSearchEchoRendered.integration.test.js'), 'utf8');
  assert.ok(source.includes("const GATE = 'SECURESHOP_SEARCH_ECHO_BROWSER_NATIVE'"));
  assert.ok(source.includes("const PREFIX = 'PG_SECURESHOP_SEARCH_ECHO_'"));
  assert.ok(source.includes("createMailActualTransport({ maxHttpCalls: 8, allowMetadata: true })"));
  assert.ok(source.includes('.createSecureShopBoundReviewComposition({'));
  assert.ok(source.includes('searchEchoEvidenceVersion: 9'));
  assert.ok(source.includes('assertSearchEchoV9Proof(packet, rawJudge, selected'));
  assert.ok(source.includes("require('../../server/services/secureshopPersonaInboxActivationPolicy')"));
  assert.ok(source.includes('.activationPolicy(process.env).requested'));
  assert.ok(source.includes("require('../../server/services/secureshopMcpTrustActivationPolicy')"));
  assert.ok(source.includes("require('../../server/services/secureshopSsrfProduction')"));
  assert.ok(source.includes('assert.equal(requestedPanels.personaInboxFeature, true)'));
  assert.ok(source.includes('assert.equal(requestedPanels.mcpTrustFeature, false)'));
  assert.ok(source.includes('assert.equal(requestedPanels.ssrfFeature, false)'));
  assert.ok(source.includes('couponDependencies, ...requestedPanels'));
  assert.ok(source.includes('.createSecureShopBoundApplication({'));
  assert.ok(source.includes('.createSecureShopAssessmentProgress({ repository:'));
  assert.ok(source.includes('standalone.assessmentProgress.readSelf(customerBase)'));
  assert.ok(source.includes('bound.standaloneReadiness.checks.requestedPanels'));
  assert.ok(source.includes("setHeaders: response => response.set('Access-Control-Allow-Origin', '*')"));
  assert.ok(source.includes("'search-echo-browser-failure.png'"));
  assert.ok(source.includes("stage: 'search-echo-rendered-failure'"));
  assert.ok(source.includes('const actorSpans = [], requests = [], pageErrors = [], judgePackets = [], httpStatuses = []'));
  assert.ok(source.includes('customerTaskSelectors: document.querySelectorAll('));
  assert.ok(source.includes("page.on('requestfailed'"));
  assert.ok(source.includes("page.on('console'"));
  assert.ok(source.includes(".replace(/Bearer\\s+\\S+/gi, 'Bearer [redacted]')"));
  assert.ok(source.includes('browserScreenshot: failure ? failureScreenshot : screenshotPath'));
  assert.ok(source.includes('composition.searchEcho.assessment'));
  assert.ok(source.includes('captureSearchEchoAssessmentResponse(request, response'));
  assert.ok(source.includes('waitForOriginalSearchEchoAssessment(assessmentHttpCaptures'));
  assert.ok(source.includes('assert.equal(assessed.request().failure(), null)'));
  assert.ok(source.includes('JSON.parse(originalAssessment.body)'));
  assert.ok(!source.includes('await assessed.json()'));
  assert.ok(source.includes("'/api/secureshop/agents/customer/search-echo/assess'"));
  assert.ok(source.includes('assertSearchEchoActorWire({ spans: actorSpans'));
  assert.ok(source.includes("selectedStep: searchHops[1].step"));
  const terminalWait = source.indexOf('CUSTOMER-SUPERVISOR\\s+done');
  const renderedHopAssertion = source.indexOf("'[aria-label^=\"Step \"][aria-label*=\"catalog.search completed\"]'");
  const savedTurnRead = source.indexOf('SELECT status,result_json FROM secureshop_agents.turn_requests');
  assert.ok(terminalWait > 0 && terminalWait < renderedHopAssertion
    && renderedHopAssertion < savedTurnRead);
  assert.ok(source.includes("createSecureShopSearchEchoBrowserQualification()"));
  assert.ok(source.includes("effectiveMode: 'fixed'"));
  assert.ok(source.includes('status.savedGetNoReplay = true'));
  assert.ok(source.includes('{ skip: !ENABLED, timeout: 300000 }, async t =>'));
  assert.ok(source.includes('outsideDedicatedMarkers: 0'));
  assert.ok(source.includes("assert.equal(sandboxTokens.includes('allow-modals'), false)"));
  assert.ok(source.includes('assert.deepEqual(dialogs, [])'));
  assert.ok(source.includes("assert.equal(retainedProof?.component?.id, 'SecureShop.SearchEcho')"));
  assert.ok(source.includes('assert.equal(retainedProof?.browser?.targetEventExecuted, true)'));
  assert.ok(source.includes('assert.equal(retainedProof?.browser?.targetEffectObserved, true)'));
  assert.ok(source.includes('assert.ok(retainedProof.browser.markers.length > 0)'));
  assert.ok(source.includes('status.resetFenced = status.siblingPrivate = true'));
  assert.ok(!source.includes("provider: 'mock'"));
  assert.ok(!source.includes('controlledProvider'));
});
