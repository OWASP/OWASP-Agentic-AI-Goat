'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { Readable } = require('node:stream');
const Busboy = require('busboy');
const Helper = require('./secureshopFileSummaryRenderedQualification');
const Evidence = require('./secureshopV19ActualEvidence');
const { SUMMARY_OBJECTIVE, SUMMARY_RUBRIC } = require('../../server/services/secureshopV19FileSummaryEvidence');
const SCOPE = 'V19 genuine owned file-summary instruction adoption with original model and Judge wire evidence, physical upload, negative controls, fixed contrast and saved recovery';
const FLAGS = Object.freeze(['isolatedStores', 'fixtureLocalCandidateAdmission', 'physicalUploads', 'originalGraphAndWire',
  'canonicalPositive', 'negativeVerdictsObserved', 'fixedContrast', 'savedGetNoReplay', 'siblingPrivate', 'resetFenced',
  'immutableHistoryRetained', 'fixtureCleaned', 'passed']);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const clone = value => JSON.parse(JSON.stringify(value));
const INPUT_SHA = '9892b4faef49b3cfc4ee123cc249136c120a8807e040dd54e1e727262e0178ad';
function wireText(wire) {
  assert.equal(wire.status, 200); assert.equal(wire.responseComplete, true);
  assert.equal(wire.responseCaptureTruncated, false);
  assert.equal(hash(wire.request), wire.requestSha256); assert.equal(hash(wire.response), wire.responseSha256);
  return wire.response.trim().split('\n').map(line => JSON.parse(line).message?.content || '').join('');
}
function assertJudgeWire(transcript, wires) {
  assert.equal(transcript.complete, true); assert.equal(transcript.header.maximumCalls, 4);
  assert.equal(transcript.calls.length, wires.length); assert.ok(wires.length >= 2 && wires.length <= 4);
  for (const [index, call] of transcript.calls.entries()) {
    const wire = wires[index], request = JSON.parse(wire.request);
    assert.equal(wire.kind, 'judge'); assert.equal(call.transport, 'returned');
    assert.equal(call.request.method, 'chat');
    assert.deepEqual(request.messages, call.request.input); assert.deepEqual(request.format, call.request.schema);
    assert.equal(wireText(wire), call.response); assert.equal(hash(call.response), call.responseSha256);
    assert.equal(call.metadata.provider, 'ollama'); assert.equal(call.metadata.mocked, false);
  }
}
function assertConfiguredJudgeRecord(transcript, wires, saved, result) {
  assertJudgeWire(transcript, wires);
  assert.deepEqual(transcript.outcome.value, result);
  assert.equal(transcript.outcome.bytes, JSON.stringify(result));
  assert.equal(transcript.outcome.sha256, hash(transcript.outcome.bytes));
  assert.equal(saved.judge_result_json, transcript.outcome.bytes);
  const proof = saved.judge_observations;
  assert.equal(proof.version, 1); assert.equal(proof.judgeVersion, transcript.header.judgeVersion);
  assert.equal(proof.runId, transcript.header.runId); assert.equal(proof.evidenceDigest, transcript.header.evidenceDigest);
  assert.equal(proof.resultSha256, transcript.outcome.sha256);
  assert.deepEqual(proof.calls, transcript.calls.map((call, index) => {
    const wire = wires[index], request = JSON.parse(wire.request);
    assert.equal(call.metadata.model, 'llama3.1:8b'); assert.equal(call.metadata.fallback, false);
    return { stage: call.stage, attempt: call.attempt, provider: call.metadata.provider, model: call.metadata.model,
      requestSha256: hash(JSON.stringify({ method: 'chat', input: request.messages, schema: request.format ?? null })),
      responseSha256: hash(wireText(wire)) };
  }));
}
function assertActorWire(span, wire) {
  const { serializeMessage, serializeTools, DECISION_SCHEMA } = require('../../server/services/secureshop/providers/ollamaProvider');
  assert.equal(span.error, undefined);
  assert.equal(span.wireEnd, span.wireStart + 1, 'One original physical call per actor decision');
  assert.equal(wire.kind, 'actor');
  const request = JSON.parse(wire.request), input = span.request;
  assert.equal(request.model, span.response.model);
  assert.equal(span.response.provider, 'ollama'); assert.equal(span.response.mocked, false);
  assert.equal(input.closedToolCatalog, true); assert.ok(input.maxToolCalls === undefined || input.maxToolCalls === 1);
  assert.deepEqual(request.messages.slice(1), input.messages.map(serializeMessage));
  assert.equal(request.messages[0].role, 'system');
  assert.ok(request.messages[0].content.startsWith(input.system + '\n\n'));
  assert.ok(request.messages[0].content.includes(serializeTools(input.tools)));
  const schema = clone(DECISION_SCHEMA);
  schema.oneOf[1].properties.tool_calls.items = { oneOf: input.tools.map(tool => ({ type: 'object', properties: {
    agent: { type: 'string', enum: [tool.agent] }, tool: { type: 'string', enum: [tool.tool] }, args: clone(tool.inputSchema)
  }, required: ['agent', 'tool', 'args'], additionalProperties: false })) };
  if (input.maxToolCalls !== undefined) schema.oneOf[1].properties.tool_calls.maxItems = input.maxToolCalls;
  if (input.requireToolCall) schema.oneOf.shift();
  assert.deepEqual(request.format, schema);
  const raw = JSON.parse(wireText(wire));
  if (span.response.stop_reason === 'tool_use') {
    assert.deepEqual(Object.keys(raw), ['tool_calls']);
    assert.deepEqual(raw.tool_calls.map(call => ({ name: call.agent + '.' + call.tool, args: call.args })),
      span.response.tool_uses.map(call => ({ name: call.name, args: call.args })));
  } else {
    assert.equal(span.response.stop_reason, 'end_turn'); assert.deepEqual(raw, { reply: span.response.text });
  }
  return true;
}
function qualificationPins() {
  const pairs = [['sourceManifestSha256', 'SECURESHOP_V19_SOURCE_MANIFEST'],
    ['frontendInventorySha256', 'SECURESHOP_V19_FRONTEND_INVENTORY'], ['modelManifestSha256', 'SECURESHOP_V19_MODEL_MANIFEST']];
  const pins = {};
  for (const [key, prefix] of pairs) {
    const filename = process.env[prefix + '_PATH'], expected = process.env[prefix + '_SHA256'];
    assert.ok(path.isAbsolute(filename)); assert.match(expected, /^[a-f0-9]{64}$/);
    const stat = fs.lstatSync(filename); assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false);
    assert.equal(hash(fs.readFileSync(filename)), expected); pins[key] = expected;
  }
  for (const [key, variable] of [['browserSha256', 'SECURESHOP_V19_BROWSER_SHA256'], ['nodeSha256', 'SECURESHOP_V19_NODE_SHA256']]) {
    assert.match(process.env[variable], /^[a-f0-9]{64}$/); pins[key] = process.env[variable];
  }
  assert.equal(hash(fs.readFileSync(process.execPath)), pins.nodeSha256);
  return Object.freeze(pins);
}
function validateV19OriginalEvidence(document) {
  const cases = require('./secureshopV19ActualCases.json').cases;
  assert.equal(document.version, 1); assert.equal(document.scope, SCOPE); assert.equal(document.inputsSha256, INPUT_SHA);
  assert.equal(document.passed, true); assert.deepEqual(document.failures, []);
  assert.equal(document.qualificationComplete, false);
  assert.equal(document.qualificationStatus, 'provisional-original-answer-review-required');
  assert.equal(document.semanticReviewRequired, true);
  assert.equal(document.cases.length, cases.length); assert.equal(document.actorSpans.length, 10);
  assert.equal(document.multipart.length, 5); assert.equal(document.judgeTranscripts.length, 4);
  assert.ok(document.wire.length >= 18 && document.wire.length <= 26);
  const used = new Set();
  for (const span of document.actorSpans) {
    assert.ok(Number.isSafeInteger(span.wireStart) && span.wireStart >= 0);
    assertActorWire(span, document.wire[span.wireStart]); assert.equal(used.has(span.wireStart), false); used.add(span.wireStart);
  }
  for (const [index, expected] of cases.entries()) {
    const actual = document.cases[index];
    for (const [key, value] of Object.entries(expected)) assert.deepEqual(actual[key], value);
    assert.equal(actual.passed, true); assert.equal(actual.actorCalls, 2); assert.equal(actual.runPosts, 1);
    const spans = document.actorSpans.filter(span => span.caseId === actual.id), original = actual.original;
    Evidence.assertOriginalActorJoin({ actorSpans: spans, row: original.row, traces: original.traces,
      qualifyModel: value => value.provider === 'ollama' && value.model === 'llama3.1:8b' && value.mocked === false });
    const bytes = Buffer.from(original.retained.bodyBase64, 'base64');
    assert.equal(bytes.toString('utf8'), expected.attachmentText); assert.equal(hash(bytes), expected.attachmentSha256);
    assert.equal(original.retained.receipt.attachment.bodySha256, hash(bytes));
    assert.deepEqual(JSON.parse(original.row.result_json.taskMetadata.boundFileSummary.originalEnvelope).attachment, original.retained.receipt.attachment);
    assert.equal(original.graphEffect.status, 'completed'); assert.equal(original.graphEffect.run_status, 'completed');
    const multipart = document.multipart.filter(row => row.fields.requestId === actual.reference.requestId);
    assert.equal(multipart.length, 1); assert.equal(multipart[0].file.bodyBase64, original.retained.bodyBase64);
    assert.equal(multipart[0].fields.message, expected.message); assert.equal(multipart[0].fields.sessionId, actual.reference.sessionId);
    assert.equal(actual.response.text, original.row.result_json.text);
    assert.equal(actual.reset.status, 'committed'); assert.equal(actual.resetFileAbsent, true);
    assert.equal(actual.historyPreserved, true); assert.equal(actual.siblingPreserved, true);
    assert.equal(actual.cleanupReceipt.kind, 'files');
    assert.equal(actual.cleanupReceipt.targetId, original.retained.receipt.file.targetId);
    assert.equal(actual.cleanupReceipt.operationId, actual.reset.resetId);
    assert.deepEqual(actual.recoveryCounters.before, actual.recoveryCounters.after);
    if (actual.id === 'vulnerable-adoption') {
      assert.equal(actual.responseAckLost, true); assert.equal(actual.committedRun.replayed, false); assert.equal(actual.response.replayed, true);
      assert.deepEqual(actual.response, { ...actual.committedRun, replayed: true });
      assert.deepEqual(actual.ackLossCounters.before, actual.ackLossCounters.after);
    }
    assert.equal(actual.publicProgress.objectives.find(row => row.objectiveId === SUMMARY_OBJECTIVE).completed, expected.expectedAssessment === 'pass');
    assert.equal(actual.publicProgressAfterReset.objectives.find(row => row.objectiveId === SUMMARY_OBJECTIVE).completed, false);
    if (expected.mode === 'fixed') {
      assert.equal(actual.assessmentCalls, 0); assert.equal(original.candidate, null);
      assert.deepEqual(actual.assessment, { completed: false, status: 'ineligible', modelEvaluated: false });
    } else {
      assert.equal(actual.assessmentCalls, 1); assert.equal(actual.assessment.judgment.verdict, expected.expectedAssessment);
      assert.equal(actual.assessment.completed, expected.expectedAssessment === 'pass');
      const transcript = document.judgeTranscripts.find(row => row.header.evidenceDigest === actual.canonical.judgment.evidence_digest);
      assert.ok(transcript); assertJudgeWire(transcript, document.wire.slice(actual.judgeWireStart, actual.judgeWireEnd));
      for (let cursor = actual.judgeWireStart; cursor < actual.judgeWireEnd; cursor++) { assert.equal(used.has(cursor), false); used.add(cursor); }
      const saved = actual.canonical.judgment;
      assert.equal(hash(saved.result_serialized), saved.result_digest); assert.deepEqual(JSON.parse(saved.result_serialized), saved.result_json);
      assert.equal(saved.result_json.verdict, expected.expectedAssessment); assert.equal(saved.packet, transcript.header.packet);
      assert.equal(saved.evidence_digest, transcript.header.evidenceDigest);
      assert.equal(saved.judge_result_json, JSON.stringify(actual.judgeResult));
      assert.equal(saved.judge_observations.resultSha256, hash(saved.judge_result_json));
      assertConfiguredJudgeRecord(transcript, document.wire.slice(actual.judgeWireStart, actual.judgeWireEnd), saved, actual.judgeResult);
    }
  }
  assert.equal(used.size, document.wire.length, 'No unjoined model traffic');
  const expectedDelta = { actorDecisions: 10, toolCalls: 5, fileWrites: 5, judgeCalls: 4, canonicalJudgments: 4, completionRows: 1 };
  for (const [key, delta] of Object.entries(expectedDelta)) assert.equal(document.finalCounters[key] - document.baselineCounters[key], delta);
  assert.ok(document.siblingSetup.fixtureOwned && document.siblingSetup.receipt);
  assert.equal(document.siblingSetup.claimsModelEvidence, false);
  return true;
}
function observeMultipartRequest(request, { maxBytes = 24576, timeoutMs = 10000 } = {}) {
  assert.ok(request && typeof request.emit === 'function');
  assert.ok(Number.isSafeInteger(maxBytes) && maxBytes > 0 && maxBytes <= 24576);
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 10000);
  const originalEmit = request.emit, chunks = [];
  let size = 0, terminal = false, captureFailure = null, timer, resolveResult, rejectResult;
  const result = new Promise((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
  result.catch(() => {});
  const typed = (code, message, cause) => Object.assign(Error(message, cause ? { cause } : undefined), { code });
  const settle = (error, parse = false) => {
    if (terminal) return;
    terminal = true; request.emit = originalEmit; clearTimeout(timer);
    if (error) rejectResult(error);
    else if (!parse) rejectResult(typed('MULTIPART_OBSERVER_CLOSED', 'Multipart observer closed before request end'));
    else Promise.resolve().then(() => {
      if (captureFailure) throw captureFailure;
      return parseMultipart(Buffer.concat(chunks), request.headers);
    }).then(resolveResult, rejectResult);
  };
  request.emit = function(type, ...args) {
    if (type === 'data' && !captureFailure) {
      const chunk = args[0];
      if (!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) {
        captureFailure = typed('MULTIPART_CHUNK_INVALID', 'Unexpected multipart stream chunk');
      } else {
        size += chunk.length;
        if (size > maxBytes) captureFailure = typed('MULTIPART_CAPTURE_OVERFLOW', 'Multipart capture exceeded bounded bytes');
        else chunks.push(Buffer.from(chunk));
      }
    }
    let returned;
    try { returned = Reflect.apply(originalEmit, this, [type, ...args]); }
    catch (error) { settle(typed('MULTIPART_EMIT_FAILED', 'Multipart request emitter failed', error)); throw error; }
    if (type === 'data' && captureFailure) settle(captureFailure);
    else if (type === 'end') settle(null, true);
    else if (type === 'aborted') settle(typed('MULTIPART_REQUEST_ABORTED', 'Multipart request aborted'));
    else if (type === 'error') settle(typed('MULTIPART_REQUEST_FAILED', 'Multipart request failed', args[0] instanceof Error ? args[0] : undefined));
    else if (type === 'close') settle(typed('MULTIPART_REQUEST_CLOSED', 'Multipart request closed before end'));
    return returned;
  };
  timer = setTimeout(() => settle(typed('MULTIPART_OBSERVER_TIMEOUT', 'Multipart observer timed out before request end')), timeoutMs);
  timer.unref?.();
  return Object.freeze({ result, close() { settle(typed('MULTIPART_OBSERVER_CLOSED', 'Multipart observer closed before request end')); } });
}
function trackOwnedOperation(operation, pending, owner, owners, failures) {
  assert.ok(operation && typeof operation.then === 'function');
  assert.ok(pending instanceof Set && owners instanceof Set && Array.isArray(failures));
  pending.add(operation); owners.add(owner);
  const release = () => { pending.delete(operation); owners.delete(owner); };
  operation.then(release, error => { failures.push(error); release(); });
  return operation;
}
function takeOwnedOperationFailures(failures) {
  assert.ok(Array.isArray(failures));
  return failures.splice(0);
}
async function parseMultipart(bytes, headers) {
  const fields = Object.create(null), parts = [], parser = Busboy({ headers, limits: { files: 1, fields: 3, parts: 5, fileSize: 8192, fieldSize: 8193 } });
  let bad = false;
  for (const event of ['filesLimit', 'fieldsLimit', 'partsLimit']) parser.on(event, () => { bad = true; });
  parser.on('field', (key, value, info) => { if (Object.hasOwn(fields, key) || info.valueTruncated) bad = true; fields[key] = value; });
  parser.on('file', (key, stream, info) => {
    const chunks = []; stream.on('limit', () => { bad = true; });
    stream.on('data', chunk => chunks.push(Buffer.from(chunk)));
    stream.on('end', () => { const body = Buffer.concat(chunks); parts.push({ key, filename: info.filename, mime: info.mimeType,
      byteCount: body.length, bodySha256: hash(body), bodyBase64: body.toString('base64'), partCount: 1 }); });
  });
  await new Promise((resolve, reject) => { parser.once('error', reject); parser.once('close', resolve); Readable.from(bytes).pipe(parser); });
  assert.equal(bad, false); assert.equal(parts.length, 1); assert.equal(parts[0].key, 'file');
  const { key, ...file } = parts[0];
  assert.deepEqual(Object.keys(fields).sort(), ['message', 'requestId', 'sessionId']);
  return { fields: { ...fields }, file };
}
function captureFinishedJson(record, response, save) {
  const json = response.json;
  response.json = function(value) { record.body = clone(value); return json.call(this, value); };
  response.once('finish', () => { record.status = response.statusCode; record.finished = true; save(); });
}
function findCommittedRunResponse(records, { sessionId, requestId }) {
  const rows = records.filter(row => row.method === 'POST' && row.path === '/agents/customer/file-summary/run'
    && row.finished === true && row.status === 200 && row.body?.sessionId === sessionId && row.body?.requestId === requestId);
  assert.ok(rows.length <= 1);
  return rows[0] ? clone(rows[0].body) : null;
}
function createV19RenderedCohort({ root, receiptPath, status, diagnosticOnly = false }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(typeof diagnosticOnly, 'boolean');
  const ownedRoot = path.resolve(process.env.SECURESHOP_V19_OWNED_FILES_ROOT || '/');
  assert.ok(ownedRoot !== '/' && !ownedRoot.startsWith(root + path.sep));
  assert.ok(path.isAbsolute(receiptPath) && !receiptPath.startsWith(root + path.sep));
  const inputsBytes = fs.readFileSync(path.join(root, 'tests/fixtures/secureshopV19ActualCases.json'));
  assert.equal(hash(inputsBytes), INPUT_SHA);
  const inputs = JSON.parse(inputsBytes);
  const evidencePath = path.join(path.dirname(receiptPath), 'v19-original-evidence.json');
  assert.equal(fs.existsSync(evidencePath), false);
  const document = { version: 1, scope: SCOPE, inputsSha256: INPUT_SHA, diagnosticOnly, cases: [], wire: [], actorSpans: [],
    http: [], multipart: [], judgeTranscripts: [], graphFailures: [], failures: [], passed: false, qualificationComplete: false,
    qualificationStatus: diagnosticOnly ? 'diagnostic-nonqualification' : 'provisional-original-answer-review-required',
    semanticReviewRequired: true };
  let active = null, transport, originalJudgeURL, judgeURLChanged = false, writes = 0, closed = false, graphDiagnostic = null;
  let pinnedInputs;
  const ownedViews = new Set(), chooserDirectories = new Set();
  const pending = new Set(), multipartObservers = new Set(), operationFailures = [];
  function save() {
    const text = JSON.stringify(document);
    assert.ok(Buffer.byteLength(text) <= 16 * 1024 * 1024, 'Bounded original evidence');
    fs.writeFileSync(evidencePath, text, { mode: 0o600 });
  }
  function syncGraphDiagnostic() {
    const failure = graphDiagnostic?.state().captureFailure;
    if (failure && !document.graphDiagnosticCaptureFailure) document.graphDiagnosticCaptureFailure = failure;
  }
  const rawFiles = require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({ root: ownedRoot });
  const files = Object.freeze({ ...rawFiles, async writeFile(...args) { writes++; return rawFiles.writeFile(...args); } });
  const cohort = {
    files, document, ownedRoot,
    installGraphDiagnostic(graphModule) {
      assert.equal(diagnosticOnly, true);
      graphDiagnostic = require('./secureshopV19GraphFailureDiagnostic').createV19GraphFailureDiagnostic({
        graphModule, workspace: root, record(value) {
          assert.ok(document.graphFailures.length < 1, 'One original graph failure maximum');
          document.graphFailures.push(value); save();
        }
      });
      return graphDiagnostic;
    },
    async start() {
      pinnedInputs = qualificationPins(); document.qualificationPins = pinnedInputs; save();
      transport = await require('../postgres/secureshopMailActualTransport').createMailActualTransport({
        protocol: 'v19-file-summary-v1', maxHttpCalls: diagnosticOnly ? 2 : 26, allowMetadata: true,
        record(value) { document.wire = value.calls; save(); }
      });
      originalJudgeURL = process.env.OLLAMA_BASE_URL;
      process.env.OLLAMA_BASE_URL = transport.judgeUrl; judgeURLChanged = true;
    },
    recordFailure(stage, error) { syncGraphDiagnostic(); document.failures.push({ stage, name: error.name, code: error.code, message: error.message }); save(); },
    actorURL() { assert.ok(transport); return transport.actorUrl; },
    wrapProvider(provider) {
      const invoke = provider.chat.bind(provider);
      provider.chat = async input => {
        assert.ok(active); assert.ok(++status.actualModelCalls <= (diagnosticOnly ? 2 : 10)); assert.ok(++active.actorCalls <= 2);
        const span = { caseId: active.id, method: 'chat', request: clone({ ...input, signal: undefined }), wireStart: transport.calls.length };
        document.actorSpans.push(span); save();
        try { const response = await invoke(input); span.response = clone(response); return response; }
        catch (error) { span.error = { name: error.name, code: error.code }; throw error; }
        finally { span.wireEnd = transport.calls.length; save(); }
      };
      return provider;
    },
    createJudge() {
      if (diagnosticOnly) return async () => { throw Object.assign(new Error('V19 diagnostic forbids Judge execution'), { code: 'V19_DIAGNOSTIC_JUDGE_FORBIDDEN' }); };
      const configured = require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
        observeExecutionTranscript(value) { document.judgeTranscripts.push(value); save(); }
      });
      return async input => {
        assert.ok(active && active.mode === 'vuln'); assert.ok(++status.judgeCalls <= 4);
        assert.equal(++active.assessmentCalls, 1);
        active.judgeWireStart = transport.calls.length; save();
        try { const result = await configured(input); active.judgeResult = result; return result; } finally { active.judgeWireEnd = transport.calls.length; save(); }
      };
    },
    observeHttp(req, res, next) {
      if (!req.path.startsWith('/agents/customer/file-summary')) return next();
      const record = { caseId: active?.id || null, method: req.method, path: req.path };
      document.http.push(record);
      captureFinishedJson(record, res, save);
      if (req.method === 'POST' && req.path.endsWith('/run')) {
        assert.ok(active); assert.equal(++active.runPosts, 1);
        const observer = observeMultipartRequest(req); multipartObservers.add(observer);
        const promise = observer.result.then(captured => { document.multipart.push(captured); save(); }, error => {
          document.failures.push({ stage: 'multipart', name: error.name, code: error.code, message: error.message }); save();
        });
        trackOwnedOperation(promise, pending, observer, multipartObservers, operationFailures);
      }
      next();
    },
    async admitCandidate(options) {
      const result = await require('./secureshopV19CandidateCatalog').admitV19DisposableCandidate(options);
      status.fixtureLocalCandidateAdmission = result.fixtureLocalCandidateAdmission; return result;
    },
    async run(context) {
      const { auth, bootstrap, composition, identity, agents, modeAuthority, mode, reset, browser,
        origin, frameFor, waitFor, siblingActor, siblingReady } = context;
      const qualifier = require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(context.provider);
      const views = ownedViews;
      const scalar = async sql => Number((await identity.query(sql, [SUMMARY_OBJECTIVE])).rows[0].n);
      const counts = async () => ({ actorDecisions: status.actualModelCalls,
        toolCalls: Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.agent_trace WHERE kind='local_tool_call' AND agent_ns='summarizer' AND tool_name='summarize_file'")).rows[0].n),
        fileWrites: writes, judgeCalls: status.judgeCalls,
        canonicalJudgments: await scalar('SELECT count(*)::int n FROM secureshop_auth.assessment_judgments WHERE objective_id=$1'),
        completionRows: await scalar('SELECT count(*)::int n FROM secureshop_auth.assessment_completions WHERE objective_id=$1') });
      const siblingSnapshot = async () => ({ scope: clone(siblingActor.scope),
        judgments: (await identity.query("SELECT evaluation_id::text,result_digest FROM secureshop_auth.assessment_judgments WHERE execution_json->'scope'->>'platformOwnerId'=$1 ORDER BY evaluation_id", [String(siblingActor.scope.platformOwnerId)])).rows });
      const siblingInput = { scope: siblingActor.scope, persona: siblingActor.persona, personaSession: siblingActor.personaSession,
        sessionId: randomUUID(), requestId: randomUUID() };
      await composition.catalog.prepareTarget(siblingActor);
      const siblingBytes = Buffer.from('Fixture-owned sibling file: retain exact bytes across unrelated resets.\n');
      const siblingFile = await composition.fileSummary.attachment.writeAndReadBack({ ...siblingInput,
        filename: 'sibling-control.txt', mime: 'text/plain', bytes: siblingBytes },
      { check: () => composition.launches.assertCurrent(siblingActor.scope),
        checkAtEffect: () => composition.launches.assertCurrent(siblingActor.scope) });
      document.siblingSetup = { fixtureOwned: true, claimsModelEvidence: false, receipt: siblingFile.receipt,
        bodyBase64: siblingBytes.toString('base64') };
      const siblingBefore = await siblingSnapshot();
      document.baselineCounters = await counts();
      const caseErrors = [];
      for (const item of (diagnosticOnly ? inputs.cases.slice(0, 1) : inputs.cases)) {
        try {
        active = { ...item, actorCalls: 0, assessmentCalls: 0, runPosts: 0 };
        document.cases.push(active); save();
        const username = `v19_${item.id.replaceAll('-', '_')}_${randomUUID().slice(0, 8)}`, password = 'owned-file-summary-customer';
        const registered = await auth.register({ username, password, email: `${username}@example.invalid`, role: 'customer' });
        if (item.mode === 'fixed') { const before = await mode.get(registered.context); await mode.set(registered.context, { mode: 'fixed', expectedRevision: before.revision }); }
        const browserContext = await browser.createBrowserContext(); views.add(browserContext);
        const page = await browserContext.newPage(); await page.setViewport({ width: 1280, height: 900 });
        await page.setRequestInterception(true);
        page.on('request', request => { const url = new URL(request.url()); void (url.origin === origin ? request.continue() : request.abort()).catch(() => {}); });
        await page.goto(origin + '/secureshop/login'); await page.waitForSelector('#ss-login-user');
        await page.type('#ss-login-user', username); await page.type('#ss-login-pw', password);
        const boot = page.waitForResponse(response => new URL(response.url()).pathname === '/api/secureshop/auth/bootstrap' && response.request().method() === 'POST', { timeout: 30000 });
        await page.click('button[type="submit"]');
        const bootResponse = await boot; assert.equal(bootResponse.status(), 200);
        const ready = await Helper.readBoundedJson(bootResponse, { maxBytes: 32768 });
        const scope = await composition.launches.resolveCapability(ready.bearer);
        const actor = await composition.personaAuth.authenticateBoundToken({ scope, token: ready.persona.token });
        const actorInput = { scope, persona: actor.user, personaSession: { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion } };
        const target = await composition.catalog.prepareTarget(actorInput);
        const modeFence = await modeAuthority.capture(scope, 'file_summary');
        const check = async () => { await composition.launches.assertCurrent(scope); await modeFence.assertCurrent(); };
        const checkAtEffect = async () => {
          await composition.launches.assertCurrent(scope); await modeFence.assertCurrentAtEffect();
        };
        let frame = await frameFor(page); await Helper.selectFileSummaryLesson(page, frame);
        const bytes = Buffer.from(item.attachmentText, 'utf8'); assert.equal(hash(bytes), item.attachmentSha256);
        const chooserDirectory = path.join(path.dirname(receiptPath), item.id); await fsp.mkdir(chooserDirectory, { mode: 0o700 }); chooserDirectories.add(chooserDirectory);
        const chooserPath = path.join(chooserDirectory, item.filename); await fsp.writeFile(chooserPath, bytes, { flag: 'wx', mode: 0o600 });
        const readReference = referenceKey => page.evaluate(({ base, sceneId, referenceKey }) => {
          const marker = localStorage.getItem(base + ':scene-storage-v1'); if (marker !== null && marker !== '1') throw Error('Storage marker unavailable');
          const value = JSON.parse(localStorage.getItem(marker === null ? base : base + ':scene:' + sceneId));
          if (!value) throw Error('Parent acknowledged state missing'); return value[referenceKey] === undefined ? null : JSON.parse(value[referenceKey]);
        }, { base: `dvaia:secureshop:${scope.launchId.toLowerCase()}:${scope.generation}`, sceneId: target.scene.sceneId.toLowerCase(), referenceKey });
        const spanStart = document.actorSpans.length;
        let original;
        const run = await Helper.runRenderedFileSummary({ page, frame, filePath: chooserPath, filename: item.filename,
          byteCount: bytes.length, message: item.message, expectedStatus: 'completed', readAcknowledgedReference: readReference,
          ...(item.id === 'vulnerable-adoption' ? { responseAckLoss: { beforeCounters: counts, afterCounters: counts,
            readCommittedRunResponse: reference => waitFor(() => findCommittedRunResponse(document.http, reference),
              'Original V19 server-finished run') } } : {}),
          readOriginalMultipart: requestId => waitFor(() => document.multipart.find(row => row.fields.requestId === requestId), 'V19 original multipart'),
          assertOriginalGraphEvidence: async ({ reference, canonicalMime }) => {
            original = await Evidence.readOriginalFileSummary({ agents, identity, conversations: composition.repositories.conversations,
              sourceReader: composition.fileSummary.sourceReader, ...actorInput, target, mode: modeFence.snapshot,
              sessionId: reference.sessionId, requestId: reference.requestId, actorSpans: document.actorSpans.slice(spanStart),
              qualifyModel: qualifier, check, checkAtEffect });
            assert.equal(original.retained.receipt.attachment.mime, canonicalMime); assert.deepEqual(original.retained.data, bytes);
            for (const span of document.actorSpans.slice(spanStart)) assertActorWire(span, transport.calls[span.wireStart]);
            active.original = clone({ ...original, retained: { receipt: original.retained.receipt, bodyBase64: bytes.toString('base64') } }); save();
            return true;
          }
        });
        active.reference = run.reference; active.response = run.run;
        if (diagnosticOnly) {
          assert.ok(active.actorCalls >= 1 && active.actorCalls <= 2); assert.equal(status.judgeCalls, 0);
          document.diagnosticOutcome = { status: 'graph_succeeded', actorCalls: active.actorCalls, judgeCalls: status.judgeCalls };
          save(); throw Object.assign(new Error('V19 graph diagnostic unexpectedly succeeded'),
            { code: 'V19_DIAGNOSTIC_GRAPH_SUCCEEDED' });
        }
        if (run.responseAckLost) { active.responseAckLost = true; active.committedRun = run.committedRun; active.ackLossCounters = run.responseAckLossCounters; }
        save();
        active.recoveryCounters = { before: await counts() };
        const recovered = await Helper.recoverFileSummaryAfterReload({ page, getFrame: () => frameFor(page), reference: run.reference,
          beforeCounters: counts, afterCounters: counts }); frame = recovered.frame;
        active.recoveryCounters.after = await counts();
        const progress = async () => (await identity.query(`SELECT count(*)::int n FROM secureshop_auth.active_assessment_contributions c
          JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
          WHERE c.objective_id=$1 AND j.shop_user_id=$2 AND j.execution_json->'scope'->>'launchId'=$3`,
        [SUMMARY_OBJECTIVE, actor.user.id, scope.launchId])).rows[0].n === 1;
        const delta = { actorDecisions: 0, toolCalls: 0, fileWrites: 0, judgeCalls: item.mode === 'fixed' ? 0 : 1,
          canonicalJudgments: item.mode === 'fixed' ? 0 : 1, completionRows: item.expectedAssessment === 'pass' ? 1 : 0 };
        const assessed = await Helper.runFileSummaryAssessment({ page, frame, sessionId: run.reference.sessionId, requestId: run.reference.requestId,
          completed: item.expectedAssessment === 'pass', status: item.mode === 'fixed' ? 'ineligible' : undefined,
          readCanonicalProgress: progress, readAcknowledgedReference: readReference, beforeCounters: counts, afterCounters: counts, expectedDelta: delta });
        active.assessment = assessed;
        const readPublicProgress = async () => page.evaluate(async () => {
          const reply = await fetch('/api/secureshop/auth/progress', { credentials: 'include', signal: AbortSignal.timeout(10000) });
          if (reply.status !== 200) throw Error('Public progress unavailable');
          const text = await reply.text(); if (new TextEncoder().encode(text).length > 32768) throw Error('Public progress too large');
          return JSON.parse(text);
        });
        const assertProgressParity = value => {
          assert.equal(value.totalObjectives, value.objectives.length);
          assert.equal(value.completedObjectives, value.objectives.filter(row => row.completed).length);
          const objective = value.objectives.filter(row => row.objectiveId === SUMMARY_OBJECTIVE);
          assert.equal(objective.length, 1); return objective[0].completed;
        };
        active.publicProgress = await readPublicProgress();
        assert.equal(assertProgressParity(active.publicProgress), item.expectedAssessment === 'pass'); save();
        if (item.mode === 'fixed') assert.deepEqual(assessed, { completed: false, status: 'ineligible', modelEvaluated: false });
        else {
          assert.equal(assessed.judgment.verdict, item.expectedAssessment);
          const transcript = document.judgeTranscripts.at(-1); assert.equal(transcript.header.rubric.objectiveId, SUMMARY_OBJECTIVE);
          assert.equal(require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput({ ...original.candidate, rubric: SUMMARY_RUBRIC }).packet, transcript.header.packet);
          assertJudgeWire(transcript, transport.calls.slice(active.judgeWireStart, active.judgeWireEnd));
          active.canonical = await Evidence.assertCanonicalFileSummaryAssessment({ identity, assessment: composition.fileSummary.assessment, ...actorInput,
            packet: transcript.header.packet, evidenceDigest: transcript.header.evidenceDigest, evaluationId: assessed.judgment.evaluationId,
            expectedVerdict: item.expectedAssessment, judgeResult: active.judgeResult });
          assertConfiguredJudgeRecord(transcript, transport.calls.slice(active.judgeWireStart, active.judgeWireEnd), active.canonical.judgment, active.judgeResult);
          await Helper.recoverFileSummaryAssessment({ page, frame, sessionId: run.reference.sessionId, requestId: run.reference.requestId,
            evaluationId: assessed.judgment.evaluationId, completed: item.expectedAssessment === 'pass', beforeCounters: counts, afterCounters: counts });
        }
        const suffixes = [`requests/${run.reference.sessionId}/${run.reference.requestId}`, `assess/${run.reference.sessionId}/${run.reference.requestId}`];
        const privateGet = async (value, suffix) => { const reply = await fetch(origin + Helper.BASE + '/' + suffix, {
          headers: { authorization: `Bearer ${value.persona.token}`, 'x-dvaia-secureshop-launch': value.bearer }, signal: AbortSignal.timeout(10000) });
          const body = await reply.json(); assert.ok(reply.status !== 200 || ['ineligible', 'unconfirmed'].includes(body.status)); return { status: reply.status, body }; };
        active.siblingReads = [];
        for (const suffix of suffixes) active.siblingReads.push(await privateGet(siblingReady, suffix));
        const immutableBefore = clone(original.row);
        const historySnapshot = async () => ({
          traces: (await agents.query('SELECT * FROM secureshop_agents.agent_trace WHERE session_id=$1 ORDER BY event_id', [run.reference.sessionId])).rows,
          effects: (await identity.query('SELECT * FROM graph_runtime.effects WHERE owner_key=$1 ORDER BY effect_key', [original.graphEffect.owner_key])).rows,
          judgments: (await identity.query("SELECT * FROM secureshop_auth.assessment_judgments WHERE execution_json->'scope'->>'launchId'=$1 ORDER BY evaluation_id", [scope.launchId])).rows
        });
        const historyBefore = clone(await historySnapshot());
        const retired = await reset.launchResetCoordinator.reset({ ...scope, expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
        assert.equal(retired.status, 'committed'); active.reset = retired;
        active.cleanupReceipt = await require('../../server/services/secureshopFileCleanupReceiptReader')
          .createSecureShopFileCleanupReceiptReader({ files, cleanupAuthority: reset.cleanupAuthority })({
            ...scope, targetKind: 'files', targetId: original.retained.receipt.file.targetId,
            fromGeneration: scope.generation, operationId: retired.resetId });
        save();
        for (const suffix of suffixes) await privateGet(ready, suffix);
        await assert.rejects(composition.fileSummary.sourceReader.read({ ...actorInput, sessionId: run.reference.sessionId,
          requestId: run.reference.requestId, receipt: original.retained.receipt, target, mode: modeFence.snapshot,
          check, checkAtEffect }), { code: 'STALE_LAUNCH' });
        await assert.rejects(fsp.lstat(path.join(ownedRoot, 'target-' + original.retained.receipt.file.targetId)), { code: 'ENOENT' });
        active.resetFileAbsent = true; assert.equal(await progress(), false);
        active.publicProgressAfterReset = await readPublicProgress();
        assert.equal(assertProgressParity(active.publicProgressAfterReset), false);
        assert.deepEqual(clone(await historySnapshot()), historyBefore); active.historyPreserved = true;
        const retained = (await agents.query('SELECT result_json,request_hash,status FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2', [run.reference.sessionId, run.reference.requestId])).rows;
        assert.equal(retained.length, 1); assert.deepEqual(retained[0].result_json, immutableBefore.result_json);
        assert.equal(retained[0].request_hash, immutableBefore.request_hash); assert.equal(retained[0].status, 'completed');
        await composition.launches.assertCurrent(siblingActor.scope); assert.deepEqual(await siblingSnapshot(), siblingBefore);
        assert.notEqual(original.retained.receipt.file.targetId, siblingFile.receipt.file.targetId);
        const siblingAfter = await composition.fileSummary.attachment.readRetained(siblingInput, siblingFile.receipt,
          { check: () => composition.launches.assertCurrent(siblingActor.scope),
            checkAtEffect: () => composition.launches.assertCurrent(siblingActor.scope) });
        assert.deepEqual(siblingAfter.data, siblingBytes); assert.deepEqual(siblingAfter.receipt, siblingFile.receipt);
        active.siblingPreserved = true;
        await fsp.unlink(chooserPath); await fsp.rmdir(chooserDirectory); chooserDirectories.delete(chooserDirectory); await browserContext.close(); views.delete(browserContext);
        active.passed = true; save();
        } catch (error) {
          caseErrors.push(error); cohort.recordFailure(active?.id || item.id, error);
          if (diagnosticOnly) {
            assert.ok(active.actorCalls >= 1 && active.actorCalls <= 2); assert.equal(status.judgeCalls, 0);
            document.diagnosticOutcome ||= { status: document.graphFailures.length === 1 ? 'graph_failed' : 'harness_failed',
              actorCalls: active.actorCalls, judgeCalls: status.judgeCalls };
            save(); throw error;
          }
        }
      }
      if (caseErrors.length) throw new AggregateError(caseErrors, 'V19 declared cohort did not qualify');
      document.finalCounters = await counts();
      const delta = { actorDecisions: 10, toolCalls: 5, fileWrites: 5, judgeCalls: 4, canonicalJudgments: 4, completionRows: 1 };
      for (const [key, value] of Object.entries(delta)) assert.equal(document.finalCounters[key] - document.baselineCounters[key], value, key);
      assert.equal(document.actorSpans.length, 10); assert.equal(status.judgeCalls, 4);
      assert.equal(document.cases.every(row => row.passed), true);
      for (const flag of FLAGS.filter(flag => !['fixtureCleaned', 'passed'].includes(flag))) status[flag] = true;
      document.passed = true; status.passed = true; save();
    },
    async close() {
      if (closed) return; closed = true; syncGraphDiagnostic();
      const errors = takeOwnedOperationFailures(operationFailures);
      for (const observer of multipartObservers) observer.close();
      for (const operation of [...pending, ...[...ownedViews].map(view => view.close()),
        ...[...chooserDirectories].map(directory => fsp.rm(directory, { recursive: true, force: true })),
        transport?.close()]) { try { await operation; } catch (error) { errors.push(error); } }
      if (judgeURLChanged) { if (originalJudgeURL === undefined) delete process.env.OLLAMA_BASE_URL; else process.env.OLLAMA_BASE_URL = originalJudgeURL; }
      if (errors.length) document.failures.push({ stage: 'owned cleanup', count: errors.length });
      try { save(); } catch (error) { errors.push(error); }
      if (errors.length) throw new AggregateError(errors, 'V19 cleanup failed');
    },
    finalize() {
      syncGraphDiagnostic();
      document.passed = status.passed && status.fixtureCleaned; save();
      if (document.passed) validateV19OriginalEvidence(document);
      fs.writeFileSync(receiptPath, JSON.stringify({ version: 1, scope: SCOPE, ...status,
        qualificationPins: pinnedInputs, inputsSha256: INPUT_SHA, originalEvidenceSha256: hash(fs.readFileSync(evidencePath)),
        physicalModelCalls: transport?.calls.length || 0, semanticReviewRequired: true, qualificationComplete: false,
        qualificationStatus: diagnosticOnly ? 'diagnostic-nonqualification' : 'provisional-original-answer-review-required' }), { mode: 0o600 });
    }
  };
  return Object.freeze(cohort);
}
module.exports = { SCOPE, FLAGS, INPUT_SHA, createV19RenderedCohort, parseMultipart, observeMultipartRequest, trackOwnedOperation, takeOwnedOperationFailures, assertJudgeWire, assertActorWire, assertConfiguredJudgeRecord, validateV19OriginalEvidence, captureFinishedJson, findCommittedRunResponse };
