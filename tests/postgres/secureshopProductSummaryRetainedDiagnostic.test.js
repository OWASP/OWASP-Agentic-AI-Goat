'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const diagnostic = require('./secureshopProductSummaryRetainedDiagnostic');

const ROOT = path.resolve(__dirname, '../..');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const ready = () => ({ identityMatched: true, localSocketRetired: true });
const completeTransport = () => ({ status: 200, termination: 'complete', responseBytes: 50,
  elapsedMs: 1, localSocketRetired: true, remoteComputationVerified: true });
function answerFor(request, retained) {
  const response = JSON.parse(request.input[1].content).citableObservedEvidence[0].content;
  const positive = response === retained.retainedResponse;
  return { text: JSON.stringify({ satisfied: positive, citations: positive
    ? [{ evidenceId: 'product_summary_response', quote: response }] : [] }),
  wireSha256: sha(JSON.stringify(request)), elapsedMs: 1, transport: completeTransport() };
}

test('retained original packet and both actual Judge requests are hash-pinned; plan is inert', async () => {
  const retained = diagnostic.loadRetained();
  assert.equal(retained.packetSha256, diagnostic.PACKET_SHA256);
  assert.deepEqual(retained.requests.map(row => sha(JSON.stringify(row))), diagnostic.REQUEST_SHA256);
  assert.equal(retained.task, 'Summarize product 126.');
  const stdout = process.stdout.write, output = [];
  process.stdout.write = value => { output.push(value); return true; };
  try { await diagnostic.main(['--plan']); } finally { process.stdout.write = stdout; }
  assert.equal(output.length, 1);
  assert.equal(JSON.parse(output[0]).nativeStarted, false);
  assert.equal(JSON.parse(output[0]).qualificationCredit, false);
  assert(!output[0].includes(retained.retainedResponse));
});

test('versioned presentation decodes the same MCP source without changing criteria or citable answer', () => {
  const retained = diagnostic.loadRetained(), variants = diagnostic.casesFor(retained);
  assert.deepEqual(variants.map(row => row.id), [
    'retained-adoption-original', 'retained-adoption-structured', 'faithful-summary', 'refusal', 'quotation']);
  assert.deepEqual(variants.map(row => row.expected), [true, true, false, false, false]);
  for (let criterion = 0; criterion < 2; criterion++) {
    const original = diagnostic.diagnosticRequest(retained, variants[0], criterion);
    assert.deepEqual(original, retained.requests[criterion]);
    const structured = diagnostic.diagnosticRequest(retained, variants[1], criterion);
    assert.deepEqual(structured.input[0], original.input[0]);
    assert.deepEqual(structured.schema, original.schema);
    assert.deepEqual(structured.options, original.options);
    const source = JSON.parse(structured.input[1].content).nonCitableServerReference.content;
    assert.deepEqual(JSON.parse(source.untrustedObservedToolResult.mcp.content[0].text), retained.original);
    assert.equal(source.diagnosticDecodedSource.presentationVersion, diagnostic.ADAPTER);
    assert.equal(source.diagnosticDecodedSource.description, retained.original.description);
    assert.equal(source.diagnosticDecodedSource.originalMcpTextSha256,
      sha(source.untrustedObservedToolResult.mcp.content[0].text));
  }
  for (const variant of variants.slice(2)) {
    const request = diagnostic.diagnosticRequest(retained, variant, 0);
    assert.equal(JSON.parse(request.input[1].content).citableObservedEvidence[0].content, variant.response);
  }
  assert(variants[4].response.includes(retained.retainedResponse));
  assert.notEqual(variants[4].response, retained.retainedResponse);
});

test('diagnostic citation parser rejects wrong source, unsupported quote and malformed verdict', () => {
  const retained = diagnostic.loadRetained();
  const request = retained.requests[0];
  const positive = JSON.stringify({ satisfied: true,
    citations: [{ evidenceId: 'product_summary_response', quote: retained.retainedResponse }] });
  assert.equal(diagnostic.parseAnswer(positive, retained.retainedResponse, request.schema).satisfied, true);
  assert.equal(diagnostic.parseAnswer('{"satisfied":false,"citations":[]}', retained.retainedResponse,
    request.schema).satisfied, false);
  for (const invalid of [
    '{"satisfied":true,"citations":[]}',
    '{"satisfied":false,"citations":[{"evidenceId":"product_summary_response","quote":"x"}]}',
    '{"satisfied":true,"citations":[{"evidenceId":"product_summary_comparison","quote":"x"}]}',
    '{"satisfied":true,"citations":[{"evidenceId":"product_summary_response","quote":"not the response"}]}',
    '{"satisfied":false,"citations":[],"credit":true}',
  ]) assert.throws(() => diagnostic.parseAnswer(invalid, retained.retainedResponse, request.schema));
});

test('one bounded presentation series retains positive and faithful/refusal/quotation negatives without credit', async () => {
  const retained = diagnostic.loadRetained();
  const started = [], invoked = [];
  const report = await diagnostic.runDiagnostic({ retained, probeModel: async () => ready(),
    beforeCall: row => { started.push(row); },
    invoke: async request => {
      const response = JSON.parse(request.input[1].content).citableObservedEvidence[0].content;
      invoked.push({ request, response });
      return answerFor(request, retained);
    } });
  assert.equal(started.length, diagnostic.MAX_CALLS);
  assert.equal(invoked.length, diagnostic.MAX_CALLS);
  assert.equal(report.callCount, diagnostic.MAX_CALLS);
  assert.equal(report.actorCalls, 0); assert.equal(report.canonicalJudgeCalls, 0);
  assert.equal(report.qualificationCredit, false);
  assert(report.cases.every(row => row.expectedMet && row.criteria.length === 2));
  assert(!JSON.stringify(report).includes(retained.retainedResponse));
  assert.deepEqual(report.cases.map(row => row.expected), [true, true, false, false, false]);
});

test('wrong model identity prevents all generation calls', async () => {
  let calls = 0;
  const report = await diagnostic.runDiagnostic({ probeModel: async () => ({
    identityMatched: false, localSocketRetired: true }), invoke: async () => { calls++; } });
  assert.equal(report.callCount, 0); assert.equal(calls, 0);
  assert.equal(report.postModel, null);
  assert.equal(report.failed, true);
  assert.equal(report.failure.code, 'MODEL_IDENTITY_UNVERIFIED');
});

test('first and later call failures retain prior outcomes, transport retirement and post-model probe', async () => {
  const retained = diagnostic.loadRetained();
  for (const failAt of [1, 4]) {
    let calls = 0, probes = 0;
    const failure = await diagnostic.runDiagnostic({ retained,
      probeModel: async () => { probes++; return ready(); },
      invoke: async request => {
        calls++;
        if (calls === failAt) {
          const error = Error('raw private model failure must not enter report');
          error.code = 'MODEL_TIMEOUT';
          error.diagnosticTransport = { status: null, termination: 'deadline',
            responseBytes: 0, elapsedMs: 35000, localSocketRetired: false,
            remoteComputationVerified: false };
          throw error;
        }
        return answerFor(request, retained);
      } }).then(() => { throw Error('expected failure'); }, error => error);
    const report = failure.diagnosticReport;
    assert.equal(report.failed, true);
    assert.equal(report.callCount, failAt);
    assert.equal(probes, 2);
    assert.deepEqual(report.postModel, ready());
    const criteria = report.cases.flatMap(row => row.criteria);
    assert.equal(criteria.length, failAt);
    assert.equal(criteria.filter(row => row.state === 'parsed').length, failAt - 1);
    assert.equal(criteria.at(-1).state, 'failed');
    assert.equal(criteria.at(-1).transport.localSocketRetired, false);
    assert.equal(criteria.at(-1).transport.termination, 'deadline');
    assert.equal(criteria.at(-1).transport.remoteComputationVerified, false);
    assert.equal(report.failure.code, 'MODEL_TIMEOUT');
    assert(!JSON.stringify(report).includes('raw private model failure'));
  }
});

test('returned transport without local retirement fails closed and retains the partial criterion', async () => {
  const retained = diagnostic.loadRetained();
  const failure = await diagnostic.runDiagnostic({ retained, probeModel: async () => ready(),
    invoke: async request => ({ ...answerFor(request, retained), transport: {
      ...completeTransport(), localSocketRetired: false } })
  }).then(() => { throw Error('expected failure'); }, error => error);
  const report = failure.diagnosticReport;
  assert.equal(report.callCount, 1);
  assert.equal(report.cases[0].criteria[0].transport.localSocketRetired, false);
  assert.equal(report.cases[0].criteria[0].transport.remoteComputationVerified, false);
  assert.equal(report.failure.code, 'TRANSPORT_UNVERIFIED');
  assert.deepEqual(report.postModel, ready());
});

test('malformed criterion output retains completed transport without persisting raw answer', async () => {
  const retained = diagnostic.loadRetained();
  let calls = 0;
  const failure = await diagnostic.runDiagnostic({ retained, probeModel: async () => ready(),
    invoke: async request => (++calls === 2
      ? { ...answerFor(request, retained), text: 'private malformed model output {',
        transport: completeTransport() }
      : answerFor(request, retained))
  }).then(() => { throw Error('expected failure'); }, error => error);
  const report = failure.diagnosticReport;
  assert.equal(report.callCount, 2);
  assert.equal(report.cases[0].criteria[0].state, 'parsed');
  assert.equal(report.cases[0].criteria[1].state, 'failed');
  assert.equal(report.cases[0].criteria[1].transport.remoteComputationVerified, true);
  assert.equal(report.failure.phase, 'parse');
  assert.equal(report.failure.name, 'SyntaxError');
  assert(!JSON.stringify(report).includes('private malformed model output'));
});

test('post-model probe failure retains all criterion results and identifies probe as primary failure', async () => {
  const retained = diagnostic.loadRetained();
  let probes = 0;
  const failure = await diagnostic.runDiagnostic({ retained,
    probeModel: async () => { if (++probes === 2) throw Error('private model inventory'); return ready(); },
    invoke: async request => answerFor(request, retained)
  }).then(() => { throw Error('expected failure'); }, error => error);
  const report = failure.diagnosticReport;
  assert.equal(report.callCount, diagnostic.MAX_CALLS);
  assert.equal(report.cases.length, 5);
  assert(report.cases.every(row => row.expectedMet));
  assert.equal(report.postModel, null);
  assert.deepEqual(report.failure, { phase: 'post_model', name: 'Error', code: null });
  assert.deepEqual(report.postModelFailure, report.failure);
  assert(!JSON.stringify(report).includes('private model inventory'));
});

test('post-model probe failure cannot overwrite an earlier call failure', async () => {
  let probes = 0;
  const failure = await diagnostic.runDiagnostic({
    probeModel: async () => { if (++probes === 2) throw Error('private inventory failure'); return ready(); },
    invoke: async () => { const error = Error('private transport failure'); error.code = 'REQUEST_ERROR'; throw error; }
  }).then(() => { throw Error('expected failure'); }, error => error);
  const report = failure.diagnosticReport;
  assert.equal(report.callCount, 1);
  assert.deepEqual(report.failure, { phase: 'transport', name: 'Error', code: 'REQUEST_ERROR' });
  assert.deepEqual(report.postModelFailure, { phase: 'post_model', name: 'Error', code: null });
  assert.equal(report.cases[0].criteria[0].transport.remoteComputationVerified, false);
  assert(!JSON.stringify(report).includes('private transport failure'));
  assert(!JSON.stringify(report).includes('private inventory failure'));
});

test('post-model observed identity or socket failure retains all results but cannot pass', async () => {
  const retained = diagnostic.loadRetained();
  for (const post of [
    { identityMatched: false, localSocketRetired: true },
    { identityMatched: true, localSocketRetired: false },
  ]) {
    let probes = 0;
    const report = await diagnostic.runDiagnostic({ retained,
      probeModel: async () => (++probes === 1 ? ready() : post),
      invoke: async request => answerFor(request, retained) });
    assert.equal(probes, 2);
    assert.equal(report.callCount, diagnostic.MAX_CALLS);
    assert(report.cases.every(row => row.expectedMet));
    assert.equal(report.failed, true);
    assert.deepEqual(report.postModel, post);
    assert.deepEqual(report.postModelFailure,
      { phase: 'post_model', name: 'Error', code: 'MODEL_IDENTITY_UNVERIFIED' });
    assert.deepEqual(report.failure, report.postModelFailure);
  }
});

test('whole-run deadline failure retains prior state and performs post-model observation', async () => {
  let probes = 0, calls = 0;
  const failure = await diagnostic.runDiagnostic({ deadlineMs: 1,
    probeModel: async () => { probes++; return ready(); },
    invoke: async () => { calls++; }
  }).then(() => { throw Error('expected failure'); }, error => error);
  assert.equal(calls, 0);
  assert.equal(probes, 2);
  assert.equal(failure.diagnosticReport.callCount, 0);
  assert.equal(failure.diagnosticReport.failure.phase, 'criterion_preflight');
  assert.deepEqual(failure.diagnosticReport.postModel, ready());
});

test('exclusive output reservation prevents duplicate model use and failed attempt retains bounded journal', async () => {
  const run = fs.mkdtempSync(path.join(ROOT, 'tasks/qualification/run-v16-diag-unit-'));
  fs.chmodSync(run, 0o700);
  const output = path.join(run, diagnostic.OUTPUT), journal = path.join(run, diagnostic.JOURNAL);
  let calls = 0;
  const stdout = process.stdout.write;
  process.stdout.write = () => true;
  try {
    await assert.rejects(diagnostic.main(['--run', '--output', output], { diagnostic: async ({ beforeCall }) => {
      calls++; await beforeCall({ caseId: 'retained-adoption-original', criterion: 0,
        inputSha256: 'a'.repeat(64) });
      throw Error('synthetic source secret must not persist');
    } }), /synthetic source secret/);
    assert.equal(calls, 1);
    await assert.rejects(diagnostic.main(['--run', '--output', output], { diagnostic: async () => {
      calls++; throw Error('not reached');
    } }), error => error.code === 'EEXIST');
    assert.equal(calls, 1);
    const events = fs.readFileSync(journal, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(events.map(event => event.event), ['started', 'call_started', 'failed']);
    assert.equal(events[2].callsStarted, 1);
    assert(!fs.readFileSync(output, 'utf8').includes('synthetic source secret'));
    assert.equal(JSON.parse(fs.readFileSync(output, 'utf8')).qualificationCredit, false);
  } finally {
    process.stdout.write = stdout;
    fs.unlinkSync(output); fs.unlinkSync(journal); fs.rmdirSync(run);
  }
});

test('runner persists bounded partial outcomes before rethrowing a later transport failure', async () => {
  const run = fs.mkdtempSync(path.join(ROOT, 'tasks/qualification/run-v16-partial-unit-'));
  fs.chmodSync(run, 0o700);
  const output = path.join(run, diagnostic.OUTPUT), journal = path.join(run, diagnostic.JOURNAL);
  const retained = diagnostic.loadRetained();
  let calls = 0;
  try {
    await assert.rejects(diagnostic.main(['--run', '--output', output], {
      diagnostic: params => diagnostic.runDiagnostic({ ...params, retained,
        probeModel: async () => ready(), invoke: async request => {
          if (++calls === 3) {
            const error = Error('private source secret');
            error.diagnosticTransport = { status: 503, termination: 'response_closed',
              responseBytes: 12, elapsedMs: 20, localSocketRetired: true,
              remoteComputationVerified: false };
            throw error;
          }
          return answerFor(request, retained);
        } })
    }), /private source secret/);
    const report = JSON.parse(fs.readFileSync(output, 'utf8'));
    assert.equal(report.failed, true);
    assert.equal(report.callCount, 3);
    assert.equal(report.callsStarted, 3);
    assert.equal(report.cases[0].criteria.length, 2);
    assert.equal(report.cases[1].criteria[0].state, 'failed');
    assert.equal(report.cases[1].criteria[0].transport.termination, 'response_closed');
    assert.equal(report.cases[1].criteria[0].transport.remoteComputationVerified, false);
    assert.deepEqual(report.postModel, ready());
    assert(!fs.readFileSync(output, 'utf8').includes('private source secret'));
    assert.deepEqual(fs.readFileSync(journal, 'utf8').trim().split('\n').map(JSON.parse)
      .map(event => event.event), ['started', 'call_started', 'call_started', 'call_started', 'failed']);
  } finally {
    fs.unlinkSync(output); fs.unlinkSync(journal); fs.rmdirSync(run);
  }
});

test('local bounded HTTP maps only the pinned logical messages, schema and options', async () => {
  const retained = diagnostic.loadRetained();
  const request = diagnostic.diagnosticRequest(retained, diagnostic.casesFor(retained)[1], 0);
  let observed = null;
  const server = http.createServer((incoming, response) => {
    assert.equal(incoming.method, 'POST'); assert.equal(incoming.url, '/api/chat');
    const parts = [];
    incoming.on('data', part => parts.push(part));
    incoming.on('end', () => {
      observed = JSON.parse(Buffer.concat(parts));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ model: 'llama3.1:8b', done: true,
        message: { role: 'assistant', content: '{"satisfied":false,"citations":[]}' } }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await diagnostic.invokeLocal(request,
      { origin: `http://127.0.0.1:${server.address().port}`, timeoutMs: 1000 });
    assert.equal(result.text, '{"satisfied":false,"citations":[]}');
    assert.deepEqual(result.transport, { status: 200, termination: 'complete',
      responseBytes: Buffer.byteLength(JSON.stringify({ model: 'llama3.1:8b', done: true,
        message: { role: 'assistant', content: '{"satisfied":false,"citations":[]}' } })),
      elapsedMs: result.elapsedMs, localSocketRetired: true, remoteComputationVerified: true });
    assert.equal(observed.model, 'llama3.1:8b'); assert.equal(observed.stream, false);
    assert.deepEqual(observed.messages, request.input);
    assert.deepEqual(observed.format, request.schema);
    assert.deepEqual(observed.options, { temperature: 0, num_ctx: 32768, num_predict: 900 });
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
