'use strict';
// Supplied-response semantic calibration only. No actor, application, database, or credit path.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { performance } = require('node:perf_hooks');

const ROOT = path.resolve(__dirname, '../..');
const MODEL = 'llama3.1:8b';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const VERSION = 'dpi-virtualization-context-calibration-v1';
const MAXIMUM_INFERENCE_CALLS = 16;
const RETRIES = 0;
const CASES = Object.freeze([
  ['DPG009', 'pass'], ['DPG011', 'fail'], ['WTC001', 'pass'], ['WTC002', 'fail'],
  ['BOUND001', 'fail'], ['BOUND002', 'fail'], ['BOUND003', 'pass'], ['BOUND004', 'fail'],
].map(Object.freeze));
const INPUTS = Object.freeze([
  Object.freeze({ path: 'tests/release-inputs/dpi-whole-task-intent-qualification8-inputs-v1.json', sha256: 'd9dddf09ed7fc58c39a11aa953f518cc3b85f3ab1022d094d83d5a7f14d5853c', count: 8 }),
  Object.freeze({ path: 'tests/release-inputs/dpi-bound-evidence-heldout4-input-v1.json', sha256: '21aa2054d4a8a19399bafb39358bf97f4ea2cae2586d20eeaa42b66408a7cbbc', count: 4 }),
]);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const ensure = (condition, message) => { if (!condition) throw Error(message); };
function appendResponseChunk(capture, chunks, chunk, limit = 1024 * 1024) {
  const remaining = Math.max(0, limit - capture.receivedResponseBytes);
  const kept = Buffer.from(chunk).subarray(0, remaining);
  if (kept.length) chunks.push(kept);
  const bytes = Buffer.concat(chunks);
  capture.receivedResponseBytes = bytes.length;
  capture.responseRaw = bytes.toString('utf8');
  capture.responseSha256 = sha(bytes);
  capture.responseCaptureTruncated = kept.length !== chunk.byteLength;
  return !capture.responseCaptureTruncated;
}

function loadCases(root = ROOT) {
  const available = new Map();
  const inputPins = {};
  for (const input of INPUTS) {
    const bytes = fs.readFileSync(path.join(root, input.path));
    ensure(sha(bytes) === input.sha256, 'Frozen virtualization input hash mismatch');
    const parsed = JSON.parse(bytes);
    ensure(parsed.actorProof === false && parsed.creditProof === false && parsed.cases.length === input.count, 'Diagnostic input shape changed');
    for (const row of parsed.cases) available.set(row.id, row);
    inputPins[input.path] = input.sha256;
  }
  const cases = CASES.map(([id, expected]) => {
    const row = available.get(id);
    ensure(row?.objective === 'virtualization', 'Exact virtualization case missing');
    ensure(Array.isArray(row.evidence) && row.evidence.length === 2, 'Complete source/response evidence required');
    ensure(row.evidence[0]?.id === 'request' && row.evidence[0]?.source === 'student_input' && typeof row.evidence[0]?.content === 'string', 'Complete source bytes required');
    ensure(row.evidence[1]?.id === 'response' && row.evidence[1]?.source === 'assistant_response' && typeof row.evidence[1]?.content === 'string', 'Complete response bytes required');
    return Object.freeze({ id, expected, input: row });
  });
  ensure(new Set(cases.map(row => row.id)).size === CASES.length, 'Duplicate virtualization case');
  return Object.freeze({ cases: Object.freeze(cases), inputPins: Object.freeze(inputPins) });
}

function createPlan(root = ROOT) {
  const loaded = loadCases(root);
  const { createDpiVirtualizationContextCandidate } = require('../../server/agent-runtime/dpiVirtualizationContextCandidate');
  const cases = loaded.cases.map(row => {
    const candidate = createDpiVirtualizationContextCandidate({ objective: row.input.objective, evidence: row.input.evidence });
    ensure(candidate.policy.maximumCalls === 2 && candidate.policy.maxOutput === 900 && candidate.policy.contextTokens === 32768, 'Candidate budget changed');
    ensure(candidate.stages.length === 2 && candidate.stages.every(stage => stage.maximumCalls === 1), 'Two independent one-call assessments required');
    const stages = candidate.stages.map(stage => Object.freeze({ id: stage.id, maximumCalls: stage.maximumCalls }));
    return Object.freeze({ id: row.id, expected: row.expected, input: row.input, candidate, stages: Object.freeze(stages) });
  });
  ensure(cases.reduce((count, row) => count + row.stages.length, 0) === MAXIMUM_INFERENCE_CALLS, 'Exact sixteen-call plan required');
  return Object.freeze({ version: VERSION, model: MODEL, digest: DIGEST, maximumInferenceCalls: MAXIMUM_INFERENCE_CALLS,
    retries: RETRIES, actorProof: false, creditProof: false, inputPins: loaded.inputPins, cases: Object.freeze(cases) });
}

async function main() {
  const resultPath = process.env.DPI_VIRTUALIZATION_RESULT;
  ensure(path.isAbsolute(resultPath || ''), 'Owned result path required');
  const plan = createPlan();
  const sourcePins = Object.fromEntries(Object.keys(require.cache).filter(file => file.startsWith(ROOT + path.sep)).sort()
    .map(file => [path.relative(ROOT, file), sha(fs.readFileSync(file))]));
  const result = { version: 1, candidateVersion: VERSION, model: MODEL, digest: DIGEST, inputPins: plan.inputPins,
    runtimePath: process.execPath, runtimeSha256: sha(fs.readFileSync(process.execPath)), sourcePins,
    maximumInferenceCalls: MAXIMUM_INFERENCE_CALLS, retries: RETRIES, actorProof: false, exerciseQualification: false,
    creditAuthorized: false, physicalPending: 0, httpCallCount: 0, complete: false, gatePassed: false, metadataCalls: [], calls: [], cases: [] };
  const save = () => fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  if (process.env.DPI_VIRTUALIZATION_PREFLIGHT_ONLY === '1') {
    result.status = 'prepared';
    result.plannedCases = plan.cases.map(row => ({ id: row.id, expected: row.expected,
      stages: row.stages.map(stage => ({ id: stage.id, maximumCalls: stage.maximumCalls })) }));
    result.sourceUnchanged = Object.entries(sourcePins).every(([file, digest]) => sha(fs.readFileSync(path.join(ROOT, file))) === digest);
    save(); return;
  }
  const abort = new AbortController();
  const wallTimer = setTimeout(() => abort.abort(Error('Virtualization diagnostic wall deadline')), 900000);
  const signalHandler = () => abort.abort(Error('Virtualization diagnostic interrupted'));
  process.on('SIGTERM', signalHandler); process.on('SIGINT', signalHandler);
  async function request(endpoint, body, capture, timeoutMs = 60000) {
    ensure(['/api/tags', '/api/chat'].includes(endpoint), 'Endpoint outside virtualization diagnostic');
    ensure(capture && typeof capture === 'object', 'Owned HTTP capture required');
    ensure(result.httpCallCount < MAXIMUM_INFERENCE_CALLS + 2, 'No extra virtualization HTTP calls');
    const requestRaw = body === undefined ? '' : JSON.stringify(body);
    Object.assign(capture, { endpoint, requestRaw, requestSha256: sha(requestRaw), status: null,
      receivedResponseBytes: 0, responseRaw: '', responseSha256: sha(''), responseCaptureTruncated: false });
    result.httpCallCount += 1;
    result.physicalPending += 1; save();
    try {
      const response = await fetch('http://127.0.0.1:11434' + endpoint, { signal: AbortSignal.any([abort.signal, AbortSignal.timeout(timeoutMs)]),
        ...(body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: requestRaw }) });
      capture.status = response.status; save();
      const reader = response.body.getReader(); const chunks = [];
      try {
        for (;;) {
          const next = await reader.read(); if (next.done) break;
          const complete = appendResponseChunk(capture, chunks, next.value); save();
          ensure(complete, 'Ollama response limit');
        }
      } finally { await reader.cancel(); }
      ensure(response.ok, 'Ollama HTTP status mismatch');
      capture.terminal = 'returned'; save();
      return { requestRaw, responseRaw: capture.responseRaw, value: JSON.parse(capture.responseRaw) };
    } catch (error) {
      capture.terminal = 'failed'; capture.failure = { name: error.name, message: error.message }; save(); throw error;
    } finally { result.physicalPending -= 1; save(); }
  }
  try {
    const beforeCapture = { phase: 'before' }; result.metadataCalls.push(beforeCapture);
    const before = await request('/api/tags', undefined, beforeCapture);
    ensure(before.value.models?.some(row => (row.name === MODEL || row.model === MODEL) && row.digest === DIGEST), 'Installed model identity changed');
    result.modelIdentityBefore = { model: MODEL, digest: DIGEST };
    for (const row of plan.cases) {
      abort.signal.throwIfAborted();
      const started = performance.now(); const entry = { id: row.id, expected: row.expected, evidence: row.input.evidence, stages: [] };
      result.cases.push(entry); const values = [];
      for (const [index, stage] of row.stages.entries()) {
        ensure(result.calls.length < MAXIMUM_INFERENCE_CALLS, 'Global virtualization call budget exceeded');
        const wire = row.candidate.stages[index].messages();
        const requestBody = { model: MODEL, messages: wire.messages, format: wire.format, stream: false,
          options: { temperature: 0, num_predict: 900, num_ctx: 32768 } };
        ensure(Buffer.byteLength(JSON.stringify(wire.messages)) + Buffer.byteLength(JSON.stringify(wire.format)) + 900 + 1024 <= 32768, 'Diagnostic context guard');
        const call = { index: result.calls.length, caseId: row.id, stage: stage.id, request: requestBody,
          requestSha256: sha(JSON.stringify(requestBody)), terminal: 'pending' };
        result.calls.push(call); save();
        try {
          const responseWire = await request('/api/chat', requestBody, call, Math.max(1, Math.min(60000, 300000 - Math.round(performance.now() - started))));
          ensure(sha(responseWire.requestRaw) === call.requestSha256, 'Request wire changed');
          call.requestRaw = responseWire.requestRaw; call.responseRaw = responseWire.responseRaw; call.responseSha256 = sha(responseWire.responseRaw);
          ensure(responseWire.value.model === MODEL && responseWire.value.done === true && responseWire.value.done_reason === 'stop', 'Incomplete/model-mismatched generation');
          ensure(typeof responseWire.value.message?.content === 'string', 'Missing model output');
          call.output = responseWire.value.message.content; call.terminal = 'returned';
          try { values[index] = row.candidate.stages[index].validate(call.output); entry.stages.push({ id: stage.id, value: values[index] }); }
          catch (error) { call.validationError = { name: error.name, message: error.message }; entry.stages.push({ id: stage.id, validationError: call.validationError }); break; }
        } catch (error) { call.terminal = 'failed'; call.failure ||= { name: error.name, message: error.message }; save(); throw error; }
        save();
      }
      if (values.length === 2 && values.every(Boolean)) entry.decision = row.candidate.combine(...values);
      entry.matchesExpected = entry.decision?.verdict === row.expected;
      entry.independentPassSupport = row.expected !== 'pass' || values.length === 2 && values.every(value => value.verdict === 'pass');
      entry.elapsedMs = Math.round(performance.now() - started); save();
    }
    ensure(result.calls.length <= MAXIMUM_INFERENCE_CALLS, 'Virtualization inference ceiling exceeded');
    const afterCapture = { phase: 'after' }; result.metadataCalls.push(afterCapture);
    const after = await request('/api/tags', undefined, afterCapture);
    ensure(after.value.models?.some(row => (row.name === MODEL || row.model === MODEL) && row.digest === DIGEST), 'Installed model identity changed after run');
    result.modelIdentityAfter = { model: MODEL, digest: DIGEST };
    result.complete = true;
    result.gatePassed = result.calls.length === MAXIMUM_INFERENCE_CALLS && result.cases.length === CASES.length && result.cases.every(row => row.matchesExpected && row.independentPassSupport);
    result.status = result.gatePassed ? 'diagnostic_pass' : 'diagnostic_mismatch';
    ensure(result.metadataCalls.length === 2 && result.httpCallCount === result.calls.length + 2, 'Exact identity/inference call accounting required');
    if (!result.gatePassed) process.exitCode = 1;
  } catch (error) { result.status = 'failed'; result.error = { name: error.name, message: error.message }; process.exitCode = 1; }
  finally {
    clearTimeout(wallTimer); process.off('SIGTERM', signalHandler); process.off('SIGINT', signalHandler);
    result.sourceUnchanged = Object.entries(sourcePins).every(([file, digest]) => sha(fs.readFileSync(path.join(ROOT, file))) === digest);
    if (!result.sourceUnchanged || result.physicalPending !== 0) process.exitCode = 1;
    save();
    console.log(JSON.stringify({ resultPath, status: result.status, calls: result.calls.length,
      cases: result.cases.map(row => ({ id: row.id, expected: row.expected, verdict: row.decision?.verdict, matchesExpected: row.matchesExpected })) }));
  }
}

module.exports = { MODEL, DIGEST, VERSION, MAXIMUM_INFERENCE_CALLS, RETRIES, CASES, INPUTS, appendResponseChunk, loadCases, createPlan };
if (require.main === module) main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
