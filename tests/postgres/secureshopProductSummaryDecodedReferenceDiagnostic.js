'use strict';
// Bounded, retained-evidence presentation experiment. This is not the canonical
// Judge, actor, assessment, or a source of objective credit.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { loadRetained, casesFor, parseAnswer, SOURCE_SHA256, PACKET_SHA256, MODEL_DIGEST } =
  require('./secureshopProductSummaryRetainedDiagnostic');
const capability = require('./secureshopProductSummarySameSchemaCapabilityDiagnostic');
const { checkModel } = require('./secureshopAuditRetainedTransportDiagnostic');

const ROOT = path.resolve(__dirname, '../..');
const VERSION = 'v16-decoded-reference-presentation-v2';
const OUTPUT = 'product-summary-v16-decoded-reference-diagnostic.json';
const JOURNAL = 'product-summary-v16-decoded-reference-attempt.jsonl';
const ORIGIN = 'http://127.0.0.1:11434';
const PER_CALL_MS = 90000;
const WALL_MS = 780000;
const MAX_CALLS = 8;
const CAPABILITY_SHA256 = '819e86b07b512e9bd39409d1afe37db65c05cf534fc3fbca57644dae7f97d090';
const FIELDS = Object.freeze(['product_id', 'name', 'price', 'category', 'stock_quantity',
  'description', 'description_html', 'image_url']);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');

function pins() {
  const file = path.join(ROOT, 'tests/postgres/secureshopProductSummarySameSchemaCapabilityDiagnostic.js');
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && !stat.isSymbolicLink());
  assert.equal(sha(fs.readFileSync(file)), CAPABILITY_SHA256);
  const result = { ...capability.sourcePins(), capability: { path:
    'tests/postgres/secureshopProductSummarySameSchemaCapabilityDiagnostic.js', sha256: CAPABILITY_SHA256 } };
  for (const [name, relative] of Object.entries({ presentationHelper:
    'tests/postgres/secureshopProductSummaryDecodedReferenceDiagnostic.js', presentationTest:
    'tests/postgres/secureshopProductSummaryDecodedReferenceDiagnostic.test.js' })) {
    const target = path.join(ROOT, relative), targetStat = fs.lstatSync(target);
    assert(targetStat.isFile() && !targetStat.isSymbolicLink());
    result[name] = { path: relative, sha256: sha(fs.readFileSync(target)) };
  }
  return result;
}

function variants(retained) {
  const source = casesFor(retained);
  assert.deepEqual(source.map(item => item.id), [
    'retained-adoption-original', 'retained-adoption-structured',
    'faithful-summary', 'refusal', 'quotation']);
  return source.filter(item => item.id !== 'retained-adoption-structured')
    .map(item => ({ id: item.id === 'retained-adoption-original' ? 'retained-adoption-decoded' : item.id,
      response: item.response, expected: item.expected }));
}

function presentationRequest(retained, variant, criterion) {
  assert([0, 1].includes(criterion));
  const request = structuredClone(retained.requests[criterion]);
  const user = JSON.parse(request.input[1].content);
  assert.deepEqual(Object.keys(user).sort(), ['citableObservedEvidence', 'nonCitableServerReference']);
  const reference = user.nonCitableServerReference;
  assert.equal(reference.evidenceId, 'product_summary_comparison');
  const content = reference.content;
  const raw = content.untrustedObservedToolResult.mcp.content[0].text;
  const decoded = JSON.parse(raw);
  assert.deepEqual(Object.keys(decoded), FIELDS);
  assert.deepEqual(decoded, retained.original);
  assert.equal(content.originalTask.text, retained.task);
  // Keep the reference noncitable, but separate trusted task, untrusted source,
  // and the single citable final answer instead of deeply escaping the MCP JSON.
  reference.content = { version: 2,
    trustedOriginalTask: structuredClone(content.originalTask),
    productId: content.productId,
    untrustedOriginalProductSource: { kind: 'decoded-original-mcp-observation',
      originalMcpTextSha256: sha(raw), originalWrapperSha256: content.untrustedObservedToolResult.sha256,
      fields: structuredClone(decoded) } };
  user.citableObservedEvidence[0].content = variant.response;
  request.input[1].content = JSON.stringify(user);
  assert.deepEqual(request.input[0], retained.requests[criterion].input[0]);
  assert.deepEqual(request.schema, retained.requests[criterion].schema);
  assert.deepEqual(request.options, retained.requests[criterion].options);
  assert.deepEqual(request.tools, retained.requests[criterion].tools);
  return request;
}

function safeFailure(error, phase) {
  return { phase, name: ['Error', 'AssertionError', 'SyntaxError'].includes(error?.name)
    ? error.name : 'Error', code: typeof error?.code === 'string' && /^[A-Z_]{1,48}$/.test(error.code)
    ? error.code : null };
}

async function invokePresentation(request, variant, { origin = ORIGIN, signal,
  fetchImpl, adapterFactory } = {}) {
  return capability.invokeAdapter({ messages: request.input },
    { schema: request.schema, options: request.options },
    { origin, signal, fetchImpl, adapterFactory });
}

async function runPresentation({ origin = ORIGIN, retained = loadRetained(),
  inspectModel = checkModel, invoke = invokePresentation,
  beforeCall = async () => {}, deadlineMs = WALL_MS } = {}) {
  assert(Number.isSafeInteger(deadlineMs) && deadlineMs > 0 && deadlineMs <= WALL_MS);
  const provenance = pins(), started = performance.now();
  const report = { version: VERSION, kind: 'diagnostic-only', qualificationCredit: false,
    actorCalls: 0, canonicalJudgeCalls: 0, sourceSha256: SOURCE_SHA256,
    packetSha256: PACKET_SHA256, model: capability.MODEL, modelDigest: MODEL_DIGEST,
    adapterProvenance: provenance, maxCalls: MAX_CALLS, callCount: 0,
    grammarEnforcementProven: false, adapterDecoderLocalized: false,
    preModel: null, postModel: null, failed: false, failure: null, postModelFailure: null, cases: [] };
  let phase = 'pre_model', active = null, primary = null;
  try {
    report.preModel = await inspectModel(origin, 10000);
    if (report.preModel?.identityMatched !== true || report.preModel?.localSocketRetired !== true) {
      report.failed = true;
      report.failure = { phase: 'pre_model', name: 'Error', code: 'MODEL_IDENTITY_UNVERIFIED' };
    } else {
      for (const variant of variants(retained)) {
        const caseRow = { id: variant.id, expected: variant.expected,
          answerSha256: sha(variant.response), criteria: [] };
        report.cases.push(caseRow);
        for (let criterion = 0; criterion < 2; criterion++) {
          phase = 'preflight';
          assert(report.callCount < MAX_CALLS);
          const remaining = deadlineMs - (performance.now() - started);
          assert(remaining > 1000, 'Whole diagnostic deadline exhausted');
          const request = presentationRequest(retained, variant, criterion);
          const row = { criterion, inputSha256: sha(JSON.stringify(request)), state: 'prepared',
            physical: null, physicalResponse: null, returned: null, transport: null,
            parsed: null, failure: null };
          caseRow.criteria.push(row); active = row;
          phase = 'before_call';
          await beforeCall({ caseId: variant.id, criterion, inputSha256: row.inputSha256 });
          const controller = new AbortController();
          const parent = AbortSignal.timeout(Math.min(PER_CALL_MS, Math.floor(remaining)));
          const abort = () => controller.abort(parent.reason);
          parent.addEventListener('abort', abort, { once: true });
          report.callCount++; row.state = 'started'; phase = 'adapter';
          try {
            const result = await invoke(request, variant, { origin, signal: controller.signal });
            row.physical = result.physical;
            row.physicalResponse = result.physicalResponse;
            row.returned = result.returned || capability.boundedReturnedText(result.text);
            row.transport = { httpStatus: result.httpStatus,
              adapterTerminalDone: result.adapterTerminalDone,
              responseBodyConsumed: result.responseBodyConsumed,
              generationSocketRetirementProven: false, adapterModel: result.adapterModel };
            assert(row.physical && row.physicalResponse?.complete === true &&
              row.transport.httpStatus === 200 && row.transport.adapterTerminalDone === true &&
              row.transport.responseBodyConsumed === true && row.transport.adapterModel === capability.MODEL);
            assert.equal(row.returned.truncated, false);
            phase = 'parse';
            row.parsed = parseAnswer(result.text, variant.response, request.schema);
            row.expectedMet = row.parsed.satisfied === variant.expected;
            row.state = 'parsed'; active = null;
          } finally { parent.removeEventListener('abort', abort); }
        }
        caseRow.expectedMet = caseRow.criteria.every(row => row.expectedMet === true);
      }
    }
  } catch (error) {
    primary = error; report.failed = true; report.failure = safeFailure(error, phase);
    if (active) {
      active.state = 'failed'; active.failure = report.failure;
      if (error.capabilityTransport) {
        active.physical = error.capabilityTransport.physical || null;
        active.physicalResponse = error.capabilityTransport.physicalResponse || null;
        active.returned = error.capabilityTransport.returned || null;
        active.transport = { httpStatus: error.capabilityTransport.httpStatus ?? null,
          physicalRequests: error.capabilityTransport.physicalRequests ?? null,
          adapterTerminalDone: false, responseBodyConsumed:
            error.capabilityTransport.responseBodyConsumed === true,
          generationSocketRetirementProven: false };
      }
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
    try { report.sourceUnchanged = Object.values(provenance).every(({ path: relative, sha256 }) =>
      sha(fs.readFileSync(path.join(ROOT, relative))) === sha256); }
    catch { report.sourceUnchanged = false; }
    if (!report.sourceUnchanged) {
      report.failed = true;
      report.failure ||= { phase: 'postflight', name: 'Error', code: 'SOURCE_CHANGED' };
    }
  }
  if (primary) { Object.defineProperty(primary, 'presentationReport', { value: report }); throw primary; }
  return report;
}

function admittedOutput(file) {
  assert.equal(path.resolve(file), file);
  assert.equal(path.basename(file), OUTPUT);
  const qualification = path.join(ROOT, 'tasks/qualification'), run = path.dirname(file);
  assert.equal(path.dirname(run), qualification);
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  for (const dir of [ROOT, path.join(ROOT, 'tasks'), qualification, run]) {
    const stat = fs.lstatSync(dir);
    assert(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid());
    assert.equal(fs.realpathSync(dir), dir);
  }
  assert.equal(fs.lstatSync(run).mode & 0o777, 0o700);
  return file;
}

async function main(argv = process.argv.slice(2), { diagnostic = runPresentation } = {}) {
  if (argv.length === 0 || (argv.length === 1 && argv[0] === '--plan')) {
    process.stdout.write(JSON.stringify({ version: VERSION, kind: 'diagnostic-only',
      nativeStarted: false, qualificationCredit: false, maxCalls: MAX_CALLS,
      perCallMs: PER_CALL_MS, wholeRunMs: WALL_MS,
      sourceSha256: SOURCE_SHA256, packetSha256: PACKET_SHA256 }) + '\n');
    return;
  }
  assert.deepEqual(argv.slice(0, 2), ['--run', '--output']); assert.equal(argv.length, 3);
  const output = admittedOutput(argv[2]);
  const fd = fs.openSync(output, 'wx', 0o600);
  let journal = null, callsReserved = 0;
  const append = event => { fs.writeSync(journal, JSON.stringify({ version: VERSION, ...event }) + '\n');
    fs.fsyncSync(journal); };
  try {
    journal = fs.openSync(path.join(path.dirname(output), JOURNAL), 'wx', 0o600);
    append({ event: 'started', maxCalls: MAX_CALLS });
    const report = await diagnostic({ beforeCall: row => {
      append({ event: 'call_reserved', ...row }); callsReserved++;
    } });
    report.callsReserved = callsReserved;
    report.presentationObserved = !report.failed && report.callCount === MAX_CALLS &&
      report.cases.length === 4 && report.cases.every(row => row.expectedMet === true) &&
      report.preModel?.identityMatched && report.postModel?.identityMatched &&
      report.preModel?.localSocketRetired && report.postModel?.localSocketRetired && report.sourceUnchanged;
    append({ event: report.presentationObserved ? 'observed' : 'nonpass', callCount: report.callCount });
    fs.writeSync(fd, JSON.stringify(report) + '\n'); fs.fsyncSync(fd);
    process.stdout.write(JSON.stringify({ result: output, callCount: report.callCount,
      presentationObserved: Boolean(report.presentationObserved), qualificationCredit: false }) + '\n');
    if (!report.presentationObserved) process.exitCode = 1;
  } catch (error) {
    const report = error.presentationReport || { version: VERSION, kind: 'diagnostic-only',
      qualificationCredit: false, actorCalls: 0, canonicalJudgeCalls: 0,
      sourceSha256: SOURCE_SHA256, packetSha256: PACKET_SHA256, callCount: 0, cases: [] };
    report.failed = true; report.callsReserved = callsReserved;
    report.failure ||= safeFailure(error, 'setup'); report.presentationObserved = false;
    try { if (journal) append({ event: 'failed', callsReserved, failure: report.failure,
      postModelFailure: report.postModelFailure || null }); } catch {}
    fs.writeSync(fd, JSON.stringify(report) + '\n'); fs.fsyncSync(fd);
    throw error;
  } finally { if (journal) fs.closeSync(journal); fs.closeSync(fd); }
}

if (require.main === module) main().catch(error => {
  process.stderr.write(`V16 decoded-reference diagnostic failed: ${error?.name || 'Error'}\n`);
  process.exitCode = 1;
});
module.exports = { VERSION, OUTPUT, JOURNAL, MAX_CALLS, pins, variants,
  presentationRequest, invokePresentation, runPresentation, admittedOutput, main };
