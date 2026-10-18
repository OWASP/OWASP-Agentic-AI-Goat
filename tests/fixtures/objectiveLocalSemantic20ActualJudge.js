'use strict';

// One-sample-per-input, Judge-only calibration. No actor, database, persistence,
// completion, eligibility, or credit path is invoked by this runner.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { declarations, sha, MODEL, DIGEST, MANAGED_NODE_VERSION, MANAGED_NODE_SHA256,
  MAXIMUM_INFERENCE_CALLS } = require('./objectiveLocalSemantic20Declarations');
const { transport, reconstruct, assertMetadataIdentity } = require('./pricingDirectiveGroupsActualJudge');

const ROOT = path.resolve(__dirname, '../..');
const MAXIMUM_HTTP_CALLS = 21;
const PRIVATE_ROOT = path.join(ROOT, 'backups/private-recovery') + path.sep;
const SOURCE_FILES = Object.freeze([
  'server/agent-runtime/objectiveLocalSemanticRubricsCandidate.js',
  'server/agent-runtime/objectiveJudge.js',
  'server/agent-runtime/judgeExecutionTranscript.js',
  'server/agent-runtime/judgeProviderConfiguration.js',
  'server/agent-runtime/providers/langchainProvider.js',
  'server/agent-runtime/providers/modelScheduler.js',
  'tests/fixtures/objectiveLocalSemantic20Declarations.js',
  'tests/fixtures/objectiveLocalSemantic20ActualJudge.js',
  'tests/fixtures/pricingDirectiveGroupsActualJudge.js',
]);

function sourcePins(root = ROOT) {
  return Object.freeze(Object.fromEntries(SOURCE_FILES.map(file => [file, sha(fs.readFileSync(path.join(root, file)))])));
}
function atomicSave(output, value) {
  const temporary = `${output}.tmp`;
  const fd = fs.openSync(temporary, 'w', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temporary, output);
  const directory = fs.openSync(path.dirname(output), 'r');
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}
function hardHttpBound(upstream, accounting) {
  return async function boundedFetch(url, options = {}) {
    const target = new URL(typeof url === 'string' ? url : url.url || String(url));
    assert.equal(target.origin, 'http://127.0.0.1:11434'); assert.equal(target.search, ''); assert.equal(target.hash, '');
    const kind = target.pathname === '/api/tags' ? 'metadata' : target.pathname === '/api/chat' ? 'inference' : null;
    assert(kind, 'Endpoint outside bounded semantic calibration');
    assert(accounting.total < MAXIMUM_HTTP_CALLS, 'Semantic calibration HTTP budget exhausted before network');
    if (kind === 'metadata') assert.equal(accounting.metadata, 0, 'Only one metadata call is allowed');
    if (kind === 'inference') assert(accounting.inference < MAXIMUM_INFERENCE_CALLS, 'Inference budget exhausted before network');
    accounting.total += 1; accounting[kind] += 1;
    try { return await upstream(url, options); }
    catch (error) { error.transportKind = kind; throw error; }
  };
}
function oneSampleModel(base, row) {
  let calls = 0;
  return Object.freeze({
    provider: base.provider, model: base.model,
    async chat(messages, tools, options) {
      calls += 1; row.adapterAttempts = calls;
      if (calls > 1) {
        row.repairDeniedBeforeProvider = true;
        const error = new Error('One-sample calibration denied ObjectiveJudge repair before provider invocation');
        error.code = 'LOCAL_REPAIR_DENIED'; throw error;
      }
      return base.chat(messages, tools, options);
    },
  });
}
function runtimeAdmission() {
  assert.equal(process.cwd(), ROOT, 'Calibration must run from the main checkout cwd');
  assert.equal(process.version, MANAGED_NODE_VERSION, 'Managed Node version changed');
  assert.equal(sha(fs.readFileSync(process.execPath)), MANAGED_NODE_SHA256, 'Managed Node bytes changed');
  return Object.freeze({ cwd: process.cwd(), executable: process.execPath, version: process.version,
    sha256: MANAGED_NODE_SHA256 });
}

async function main(options = {}) {
  assert.deepEqual(Object.keys(options), [], 'Actual semantic calibration accepts no runtime options');
  assert.equal(process.env.OBJECTIVE_LOCAL_SEMANTIC20_ACTUAL, '1');
  const output = path.resolve(process.env.OBJECTIVE_LOCAL_SEMANTIC20_RESULT || '');
  assert(output.startsWith(PRIVATE_ROOT), 'Result must stay in main-checkout private recovery evidence');
  assert(fs.existsSync(path.dirname(output)), 'Private result directory must already exist');
  const runtime = runtimeAdmission();
  const declared = declarations(ROOT); assert.equal(declared.cases.length, 20);
  const initialPins = sourcePins();
  const state = { version: 1, status: 'preparing', scope: 'Unmounted canonical ObjectiveJudge calibration on exactly 20 frozen supplied-response inputs; no actor, database, persistence, eligibility, completion, or credit proof.',
    model: { name: MODEL, digest: DIGEST }, runtime, inputPins: declared.inputPins, sourcePins: initialPins,
    bounds: { cases: 20, metadataCalls: 1, inferenceCalls: 20, physicalInferencePerCase: 1,
      repairSamples: 0, maximumHttpCalls: MAXIMUM_HTTP_CALLS, perHttpSeconds: 60,
      overallSeconds: 1260, contextTokens: 32768, outputTokens: 900 },
    actorCalls: 0, databaseConnections: 0, creditAuthorized: false, productionMounted: false,
    technicalComplete: false, semanticAccepted: false, physicalPending: 0, accounting: { total: 0, metadata: 0, inference: 0 },
    metadata: null, calls: [], invalidAttempts: [], cases: [], postflight: null };
  const save = () => atomicSave(output, state); save();
  const lifetime = new AbortController();
  const timer = setTimeout(() => lifetime.abort(Error('Objective-local semantic calibration deadline')), 1260000);
  const interrupt = () => lifetime.abort(Error('Objective-local semantic calibration interrupted'));
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  const originalFetch = global.fetch;
  const boundedFetch = hardHttpBound(originalFetch, state.accounting);
  let wire;
  try {
    wire = transport({ fetch: boundedFetch, signal: lifetime.signal, profile: 'historical84', record: () => {
      state.calls = wire.calls; state.physicalPending = wire.calls.filter(call => call.status === 'pending').length; save();
    } });
    global.fetch = wire.fetch; state.status = 'running'; save();
    const metadataResponse = await fetch('http://127.0.0.1:11434/api/tags');
    assert.equal(metadataResponse.status, 200); const metadata = await metadataResponse.json(); assertMetadataIdentity(metadata);
    state.metadata = { model: MODEL, digest: DIGEST, admitted: true }; save();
    const base = require('../../server/agent-runtime/providers/langchainProvider')
      .createLangChainProvider({ provider: 'ollama', baseURL: 'http://127.0.0.1:11434', model: MODEL });
    const { createObjectiveJudge } = require('../../server/agent-runtime/objectiveJudge');
    for (const item of declared.cases) {
      lifetime.signal.throwIfAborted(); wire.beginCase(item.id);
      const row = { id: item.id, cohort: item.cohort, expectedVerdict: item.expectedVerdict,
        provenance: item.provenance, inputSha256: item.inputSha256, packet: item.packet, packetSha256: sha(JSON.stringify(item.packet)),
        adapterAttempts: 0, repairDeniedBeforeProvider: false, invalidAttempts: [], transcript: null,
        result: null, physicalInferenceCalls: 0, technicalComplete: false, semanticMatch: false };
      state.cases.push(row); save(); const started = performance.now();
      const model = oneSampleModel(base, row);
      const judge = createObjectiveJudge({ model, contextTokens: 32768, timeoutMs: 60000,
        captureInvalidAttempt: async value => { row.invalidAttempts.push(value); state.invalidAttempts.push({ caseId: item.id, ...value }); save(); },
        observeExecutionTranscript: value => { row.transcript = value; save(); } });
      row.result = await judge({ ...item.packet, execution: { signal: lifetime.signal } });
      const sent = wire.calls.filter(call => call.caseId === item.id); row.physicalInferenceCalls = sent.length;
      assert.equal(sent.length, 1, 'Exactly one physical Judge inference is required per input');
      assert.equal(sent[0].kind, 'inference');
      if (sent[0].status !== 'returned' || sent[0].httpStatus !== 200) {
        const error = new Error('Judge transport did not return a complete successful response'); error.code = 'TRANSPORT_INCOMPLETE'; throw error;
      }
      const rawOutput = reconstruct(sent[0].response);
      assert.equal(sent[0].responseSha256, sha(sent[0].response));
      assert.equal(row.transcript?.complete, true); assert.equal(row.transcript.header.maximumCalls, 2);
      assert.equal(row.transcript.calls[0].response, rawOutput); assert.equal(row.transcript.calls[0].responseSha256, sha(rawOutput));
      if (row.adapterAttempts === 2) assert.equal(row.repairDeniedBeforeProvider, true);
      else assert.equal(row.adapterAttempts, 1);
      assert(row.result && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(row.result.verdict));
      row.semanticMatch = row.result.verdict === item.expectedVerdict; row.technicalComplete = true;
      row.elapsedMs = Math.round(performance.now() - started); wire.endCase(); save();
    }
    assert.equal(state.cases.length, 20); assert(state.cases.every(row => row.technicalComplete));
    assert.equal(state.accounting.metadata, 1); assert.equal(state.accounting.inference, 20); assert.equal(state.accounting.total, 21);
    assert.equal(wire.calls.filter(call => call.kind === 'inference').length, 20);
    state.technicalComplete = true; state.semanticAccepted = state.cases.every(row => row.semanticMatch);
    state.status = state.semanticAccepted ? 'semantic-accepted-controlled-inputs' : 'semantic-mismatch';
    if (!state.semanticAccepted) process.exitCode = 1;
  } catch (error) {
    state.status = 'incomplete'; state.error = { name: error.name, code: error.code || null, message: error.message };
    process.exitCode = 1;
  } finally {
    clearTimeout(timer); lifetime.abort(); wire?.close(); global.fetch = originalFetch;
    process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
    const finalPins = sourcePins();
    state.physicalPending = state.calls.filter(call => call.status === 'pending').length;
    state.postflight = { cwdUnchanged: process.cwd() === ROOT, runtimeUnchanged: process.version === MANAGED_NODE_VERSION
      && sha(fs.readFileSync(process.execPath)) === MANAGED_NODE_SHA256,
    sourceUnchanged: JSON.stringify(finalPins) === JSON.stringify(initialPins), sourcePins: finalPins,
    metadataCalls: state.accounting.metadata, inferenceCalls: state.accounting.inference,
    physicalPending: state.physicalPending, completedAt: new Date().toISOString() };
    if (!state.postflight.cwdUnchanged || !state.postflight.runtimeUnchanged || !state.postflight.sourceUnchanged
      || state.physicalPending !== 0 || state.accounting.metadata > 1 || state.accounting.inference > 20) process.exitCode = 1;
    save();
  }
}

module.exports = Object.freeze({ ROOT, MAXIMUM_HTTP_CALLS, SOURCE_FILES, sourcePins, atomicSave,
  hardHttpBound, oneSampleModel, runtimeAdmission, main });
if (require.main === module) main().catch(error => { console.error(JSON.stringify({ name: error.name, code: error.code || null })); process.exitCode = 1; });
