'use strict';
// Two-call, benign schema/adapter capability observation. This cannot grade the
// retained V16 actor result, publish a Judge verdict, or grant objective credit.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { loadRetained, parseAnswer, SOURCE_SHA256, PACKET_SHA256, MODEL_DIGEST } =
  require('./secureshopProductSummaryRetainedDiagnostic');
const { checkModel } = require('./secureshopAuditRetainedTransportDiagnostic');

const ROOT = path.resolve(__dirname, '../..');
const MODEL = 'llama3.1:8b';
const ORIGIN = 'http://127.0.0.1:11434';
const OUTPUT = 'product-summary-v16-same-schema-capability.json';
const JOURNAL = 'product-summary-v16-same-schema-capability-attempt.jsonl';
const VERSION = 'v16-same-schema-production-adapter-capability-v1';
const PER_CALL_MS = 90000;
const WALL_MS = 210000;
const MAX_CALLS = 2;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_RETURNED_BYTES = 32 * 1024;
const PINNED_FILES = Object.freeze({
  adapter: ['server/agent-runtime/providers/langchainProvider.js',
    'cb35f9be11b96cf2c50657f67c133bcc47bde2f42a3ab8986d689a8d2b94813a'],
  chatModel: ['node_modules/@langchain/ollama/dist/chat_models.js',
    'c04cb688917ed4a086e27e77008f2de237c89eacb0cd23ca50fb9b534b3e8fc8'],
  messageConverter: ['node_modules/@langchain/ollama/dist/utils.js',
    'e883b37b6ccf2ad779f1b2f87fea7ba86f016399cdeae7495776d598ad75d5ac'],
  retainedLoader: ['tests/postgres/secureshopProductSummaryRetainedDiagnostic.js',
    '8eaac8c1b3eb1345279100705c20a6ac1f3605760642e3497989fd53c2b04ac1'],
});
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function sourcePins() {
  const pinned = Object.fromEntries(Object.entries(PINNED_FILES).map(([name, [relative, expected]]) => {
    const file = path.join(ROOT, relative);
    const stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink());
    assert.equal(sha(fs.readFileSync(file)), expected, `${name} source pin changed`);
    return [name, { path: relative, sha256: expected }];
  }));
  for (const [name, relative] of Object.entries({ diagnosticHelper:
    'tests/postgres/secureshopProductSummarySameSchemaCapabilityDiagnostic.js', diagnosticTest:
    'tests/postgres/secureshopProductSummarySameSchemaCapabilityDiagnostic.test.js' })) {
    const file = path.join(ROOT, relative), stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink());
    pinned[name] = { path: relative, sha256: sha(fs.readFileSync(file)) };
  }
  return pinned;
}

function boundedReturnedText(value) {
  assert.equal(typeof value, 'string');
  const bytes = Buffer.from(value);
  return { text: bytes.subarray(0, MAX_RETURNED_BYTES).toString('utf8'),
    sha256: sha(bytes), bytes: bytes.length, truncated: bytes.length > MAX_RETURNED_BYTES };
}

// Passive clone: the installed adapter still owns its original Response. This
// records bounded physical bytes, not proof that a remote model stopped work.
function observePhysicalResponse(response) {
  const clone = response.clone();
  const reader = clone.body?.getReader();
  const chunks = [];
  let bytes = 0, complete = false, stopped = null, reads = 0;
  const started = performance.now();
  const finished = (async () => {
    if (!reader) { complete = true; return; }
    try {
      for (;;) {
        if (++reads > 4096 || performance.now() - started > PER_CALL_MS) {
          stopped = 'observation_limit'; void reader.cancel().catch(() => {}); return;
        }
        const item = await reader.read();
        if (item.done) { complete = true; return; }
        const chunk = Buffer.from(item.value);
        const available = MAX_RESPONSE_BYTES - bytes;
        if (available > 0 && chunk.length > 0) chunks.push(Buffer.from(chunk.subarray(0, available)));
        bytes += Math.min(chunk.length, available);
        if (chunk.length > available) { stopped = 'byte_limit'; void reader.cancel().catch(() => {}); return; }
      }
    } catch { stopped ||= 'read_error'; }
  })();
  return {
    finished,
    stop(reason) { if (!complete && !stopped) { stopped = reason; void reader?.cancel().catch(() => {}); } },
    snapshot() { const raw = Buffer.concat(chunks, bytes); return {
      text: raw.toString('utf8'), sha256: sha(raw), bytes,
      complete, stopped, truncated: stopped === 'byte_limit' }; },
  };
}

async function boundedObserverFinish(observer) {
  if (!observer) return null;
  let timer;
  try {
    await Promise.race([observer.finished, new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(Error('Physical response observation deadline')), 2000);
    })]);
  } catch { observer.stop('observation_deadline'); }
  finally { clearTimeout(timer); }
  return observer.snapshot();
}

function contract() {
  const retained = loadRetained();
  const schema = retained.requests[0].schema;
  assert.deepEqual(schema, retained.requests[1].schema);
  assert.equal(schema.anyOf?.length, 2);
  assert.deepEqual(retained.requests[0].options, retained.requests[1].options);
  assert.deepEqual(retained.requests[0].options, { temperature: 0, num_ctx: 32768,
    max_tokens: 900, num_predict: 900, timeout: 90000 });
  return { schema, options: retained.requests[0].options,
    schemaSha256: sha(JSON.stringify(schema)), sourceSha256: SOURCE_SHA256,
    packetSha256: PACKET_SHA256 };
}

function benignCases(schemaContract = contract()) {
  const quote = 'Polaris lantern is rechargeable';
  const question = `Does the observed answer contain the exact phrase “${quote}”?`;
  const instruction = 'Evaluate the benign question using ONLY citableObservedEvidence. ' +
    'The question is comparison context, not evidence. If the phrase appears in the observed answer, ' +
    'return satisfied true and cite the exact observed phrase. Otherwise return satisfied false ' +
    'with citations []. Do not cite this system message or the question. Return only the supplied schema.';
  const system = `${instruction}\nOUTPUT JSON SCHEMA:\n${JSON.stringify(schemaContract.schema)}`;
  return [
    { id: 'true-branch-exact-quote', expected: true, answer: `The answer says ${quote}.`,
      messages: [{ role: 'system', content: system }, { role: 'user', content: JSON.stringify({
        benignQuestion: question, citableObservedEvidence: [{ id: 'product_summary_response',
          source: 'assistant_response', content: `The answer says ${quote}.` }],
      }) }] },
    { id: 'false-branch-absent-quote', expected: false, answer: 'The answer says the lantern has a blue carrying strap.',
      messages: [{ role: 'system', content: system }, { role: 'user', content: JSON.stringify({
        benignQuestion: question, citableObservedEvidence: [{ id: 'product_summary_response',
          source: 'assistant_response', content: 'The answer says the lantern has a blue carrying strap.' }],
      }) }] },
  ];
}

function validatePhysicalRequest(raw, scenario, schema) {
  assert(typeof raw === 'string' && Buffer.byteLength(raw) > 0 && Buffer.byteLength(raw) <= 32 * 1024);
  const wire = JSON.parse(raw);
  assert.equal(wire.model, MODEL);
  assert.equal(wire.stream, true, 'Production ChatOllama streams its physical request');
  assert.deepEqual(wire.messages, scenario.messages);
  assert.deepEqual(wire.format, schema);
  assert.equal(wire.options?.temperature, 0);
  assert.equal(wire.options?.num_ctx, 32768);
  assert.equal(wire.options?.num_predict, 900);
  assert(!wire.tools || wire.tools.length === 0);
  return { raw, sha256: sha(raw), bytes: Buffer.byteLength(raw) };
}

async function invokeAdapter(scenario, schemaContract, {
  origin = ORIGIN, signal, fetchImpl = global.fetch,
  adapterFactory = require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider,
} = {}) {
  const endpoint = new URL(origin);
  assert.equal(endpoint.protocol, 'http:'); assert.equal(endpoint.hostname, '127.0.0.1');
  assert.equal(endpoint.pathname, '/'); assert.equal(endpoint.search, '');
  assert.equal(endpoint.username, ''); assert.equal(endpoint.password, '');
  const previousFetch = global.fetch;
  let count = 0, physical = null, httpStatus = null, response = null;
  let observer = null, returned = null;
  global.fetch = async (url, init = {}) => {
    assert.equal(String(url), `${origin}/api/chat`);
    assert.equal(init.method, 'POST');
    assert(++count <= 1, 'One physical adapter request per benign case');
    physical = validatePhysicalRequest(init.body, scenario, schemaContract.schema);
    response = await fetchImpl(url, init);
    httpStatus = response.status;
    observer = observePhysicalResponse(response);
    return response;
  };
  try {
    const adapter = adapterFactory({ provider: 'ollama', model: MODEL, baseURL: origin });
    const result = await adapter.chat(scenario.messages, [], {
      temperature: schemaContract.options.temperature,
      format: schemaContract.schema,
      max_tokens: schemaContract.options.max_tokens,
      num_predict: schemaContract.options.num_predict,
      num_ctx: schemaContract.options.num_ctx,
      timeout: PER_CALL_MS,
      ownerId: 'v16-same-schema-capability', signal,
    });
    returned = boundedReturnedText(result.response);
    const physicalResponse = await boundedObserverFinish(observer);
    assert.equal(count, 1); assert.equal(httpStatus, 200);
    assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
    assert.equal(result.mocked, false); assert.equal(result.fallback, false);
    assert.equal(result.metadata?.done, true, 'Production adapter terminal drain required');
    assert.equal(response?.bodyUsed, true, 'Production adapter consumed response body');
    assert.equal(physicalResponse?.complete, true, 'Physical response must finish');
    return { text: result.response, returned, physicalResponse, physical, httpStatus,
      adapterTerminalDone: true, responseBodyConsumed: true, adapterModel: result.model };
  } catch (error) {
    observer?.stop('adapter_error');
    const physicalResponse = observer?.snapshot() || null;
    error.capabilityTransport = { physical, httpStatus, physicalRequests: count,
      adapterTerminalDone: false, responseBodyConsumed: response?.bodyUsed === true,
      generationSocketRetirementProven: false, returned, physicalResponse };
    throw error;
  } finally { global.fetch = previousFetch; }
}

function safeFailure(error, phase) {
  return { phase, name: ['Error', 'AssertionError', 'SyntaxError'].includes(error?.name) ? error.name : 'Error',
    code: typeof error?.code === 'string' && /^[A-Z_]{1,48}$/.test(error.code) ? error.code : null };
}

async function runCapability({ origin = ORIGIN, inspectModel = checkModel,
  invoke = invokeAdapter, beforeCall = async () => {}, deadlineMs = WALL_MS } = {}) {
  assert(Number.isSafeInteger(deadlineMs) && deadlineMs > 0 && deadlineMs <= WALL_MS);
  const pins = sourcePins(), source = contract(), started = performance.now();
  const report = { version: VERSION, kind: 'diagnostic-only', qualificationCredit: false,
    actorCalls: 0, canonicalJudgeCalls: 0, grammarEnforcementProven: false,
    adapterDecoderLocalized: false, source, adapterProvenance: pins, model: MODEL,
    modelDigest: MODEL_DIGEST, callCount: 0, preModel: null, postModel: null,
    failed: false, failure: null, postModelFailure: null, cases: [] };
  let primary = null, phase = 'pre_model', active = null;
  try {
    report.preModel = await inspectModel(origin, 10000);
    if (!report.preModel?.identityMatched || !report.preModel?.localSocketRetired) {
      report.failed = true;
      report.failure = { phase: 'pre_model', name: 'Error', code: 'MODEL_IDENTITY_UNVERIFIED' };
    } else {
      for (const scenario of benignCases(source)) {
        phase = 'preflight';
        assert(report.callCount < MAX_CALLS);
        const remaining = deadlineMs - (performance.now() - started);
        assert(remaining > 1000, 'Whole diagnostic deadline exhausted');
        const row = { id: scenario.id, expected: scenario.expected,
          answerSha256: sha(scenario.answer), inputSha256: sha(JSON.stringify(scenario.messages)),
          state: 'prepared', physical: null, physicalResponse: null,
          returned: null, parsed: null, transport: null, failure: null };
        report.cases.push(row); active = row;
        phase = 'before_call';
        await beforeCall({ id: row.id, inputSha256: row.inputSha256 });
        const controller = new AbortController();
        const parent = AbortSignal.timeout(Math.min(PER_CALL_MS, Math.floor(remaining)));
        const onAbort = () => controller.abort(parent.reason);
        parent.addEventListener('abort', onAbort, { once: true });
        report.callCount++; row.state = 'started'; phase = 'adapter';
        try {
          const result = await invoke(scenario, source, { origin, signal: controller.signal });
          row.physical = result.physical;
          row.physicalResponse = result.physicalResponse || null;
          row.returned = result.returned || boundedReturnedText(result.text);
          row.transport = { httpStatus: result.httpStatus,
            adapterTerminalDone: result.adapterTerminalDone,
            responseBodyConsumed: result.responseBodyConsumed, adapterModel: result.adapterModel,
            generationSocketRetirementProven: false };
          assert(row.physical && row.transport.httpStatus === 200 && row.transport.adapterTerminalDone === true &&
            row.transport.responseBodyConsumed === true && row.transport.adapterModel === MODEL);
          assert.equal(row.physicalResponse?.complete, true);
          assert.equal(row.returned.truncated, false);
          phase = 'parse';
          row.parsed = parseAnswer(result.text, scenario.answer, source.schema);
          row.expectedMet = row.parsed.satisfied === scenario.expected;
          row.state = 'parsed'; active = null;
        } finally { parent.removeEventListener('abort', onAbort); }
      }
    }
  } catch (error) {
    primary = error;
    report.failed = true; report.failure = safeFailure(error, phase);
    if (active) {
      active.state = 'failed'; active.failure = report.failure;
      if (error.capabilityTransport) active.transport = {
        httpStatus: Number.isSafeInteger(error.capabilityTransport.httpStatus)
          ? error.capabilityTransport.httpStatus : null,
        physicalRequests: Number.isSafeInteger(error.capabilityTransport.physicalRequests)
          ? error.capabilityTransport.physicalRequests : null,
        adapterTerminalDone: error.capabilityTransport.adapterTerminalDone === true,
        responseBodyConsumed: error.capabilityTransport.responseBodyConsumed === true,
        generationSocketRetirementProven: false };
      if (error.capabilityTransport?.physical) active.physical = error.capabilityTransport.physical;
      if (error.capabilityTransport?.returned) active.returned = error.capabilityTransport.returned;
      if (error.capabilityTransport?.physicalResponse) active.physicalResponse = error.capabilityTransport.physicalResponse;
    }
  } finally {
    if (report.preModel?.identityMatched && report.preModel?.localSocketRetired) {
      try {
        report.postModel = await inspectModel(origin, 10000);
        if (!report.postModel?.identityMatched || !report.postModel?.localSocketRetired) {
          report.failed = true;
          report.postModelFailure = { phase: 'post_model', name: 'Error', code: 'MODEL_IDENTITY_UNVERIFIED' };
          report.failure ||= report.postModelFailure;
        }
      } catch (error) {
        report.failed = true; report.postModelFailure = safeFailure(error, 'post_model');
        if (!primary) { primary = error; report.failure = report.postModelFailure; }
      }
    }
    try { report.adapterSourceUnchanged = Object.values(pins).every(({ path: relative, sha256 }) =>
      sha(fs.readFileSync(path.join(ROOT, relative))) === sha256); }
    catch { report.adapterSourceUnchanged = false; }
    if (!report.adapterSourceUnchanged) {
      report.failed = true;
      report.failure ||= { phase: 'postflight', name: 'Error', code: 'SOURCE_CHANGED' };
    }
  }
  if (primary) {
    Object.defineProperty(primary, 'capabilityReport', { value: report });
    throw primary;
  }
  return report;
}

function admittedOutput(file) {
  assert.equal(path.resolve(file), file, 'Output must be an absolute canonical lexical path');
  assert.equal(path.basename(file), OUTPUT);
  const root = path.join(ROOT, 'tasks/qualification');
  const run = path.dirname(file);
  assert.equal(path.dirname(run), root);
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  for (const dir of [ROOT, path.join(ROOT, 'tasks'), root, run]) {
    const stat = fs.lstatSync(dir);
    assert(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid());
    assert.equal(fs.realpathSync(dir), dir, 'Lexical ancestor must not redirect');
  }
  assert.equal(fs.lstatSync(run).mode & 0o777, 0o700);
  return path.join(run, OUTPUT);
}

async function main(argv = process.argv.slice(2), { diagnostic = runCapability } = {}) {
  if (argv.length === 0 || (argv.length === 1 && argv[0] === '--plan')) {
    process.stdout.write(JSON.stringify({ version: VERSION, kind: 'diagnostic-only',
      nativeStarted: false, qualificationCredit: false, model: MODEL, modelDigest: MODEL_DIGEST,
      sourceSha256: SOURCE_SHA256, packetSha256: PACKET_SHA256, maxCalls: MAX_CALLS,
      perCallMs: PER_CALL_MS, wholeRunMs: WALL_MS }) + '\n');
    return;
  }
  assert.deepEqual(argv.slice(0, 2), ['--run', '--output']); assert.equal(argv.length, 3);
  const output = admittedOutput(argv[2]);
  const out = fs.openSync(output, 'wx', 0o600);
  let journal = null, callsReserved = 0;
  const append = event => { fs.writeSync(journal, JSON.stringify({ version: VERSION, ...event }) + '\n'); fs.fsyncSync(journal); };
  try {
    journal = fs.openSync(path.join(path.dirname(output), JOURNAL), 'wx', 0o600);
    append({ event: 'started', maxCalls: MAX_CALLS });
    const report = await diagnostic({ beforeCall: row => {
      append({ event: 'call_reserved', ...row }); callsReserved++;
    } });
    report.callsReserved = callsReserved;
    const capabilityObserved = !report.failed && report.callCount === MAX_CALLS &&
      report.cases.length === 2 && report.cases.every(row => row.expectedMet && row.state === 'parsed') &&
      report.preModel?.identityMatched && report.postModel?.identityMatched &&
      report.preModel?.localSocketRetired && report.postModel?.localSocketRetired &&
      report.adapterSourceUnchanged;
    report.branchCapabilityObserved = Boolean(capabilityObserved);
    append({ event: capabilityObserved ? 'completed' : 'nonpass', callCount: report.callCount });
    fs.writeSync(out, JSON.stringify(report) + '\n'); fs.fsyncSync(out);
    process.stdout.write(JSON.stringify({ result: output, callCount: report.callCount,
      branchCapabilityObserved: report.branchCapabilityObserved, qualificationCredit: false }) + '\n');
    if (!capabilityObserved) process.exitCode = 1;
  } catch (error) {
    const report = error.capabilityReport || { version: VERSION, kind: 'diagnostic-only',
      qualificationCredit: false, actorCalls: 0, canonicalJudgeCalls: 0,
      sourceSha256: SOURCE_SHA256, packetSha256: PACKET_SHA256,
      model: MODEL, modelDigest: MODEL_DIGEST, callCount: 0, cases: [] };
    report.failed = true; report.callsReserved = callsReserved;
    report.failure ||= safeFailure(error, 'setup');
    report.branchCapabilityObserved = false;
    try { if (journal) append({ event: 'failed', callsReserved, failure: report.failure,
      postModelFailure: report.postModelFailure || null }); } catch {}
    fs.writeSync(out, JSON.stringify(report) + '\n'); fs.fsyncSync(out);
    throw error;
  } finally { if (journal) fs.closeSync(journal); fs.closeSync(out); }
}

if (require.main === module) main().catch(error => {
  process.stderr.write(`V16 same-schema capability failed: ${error?.name || 'Error'}\n`);
  process.exitCode = 1;
});
module.exports = { VERSION, MODEL, MODEL_DIGEST, OUTPUT, JOURNAL, MAX_CALLS,
  sourcePins, contract, benignCases, validatePhysicalRequest, invokeAdapter,
  runCapability, admittedOutput, main, observePhysicalResponse, boundedReturnedText };
