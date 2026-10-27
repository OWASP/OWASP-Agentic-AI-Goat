'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const diagnostic = require('./secureshopProductSummaryDecodedReferenceDiagnostic');
const capability = require('./secureshopProductSummarySameSchemaCapabilityDiagnostic');
const { loadRetained } = require('./secureshopProductSummaryRetainedDiagnostic');

const ROOT = path.resolve(__dirname, '../..');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const observedModel = () => ({ identityMatched: true, localSocketRetired: true });
const answer = (variant, satisfied = variant.expected) => JSON.stringify({ satisfied,
  citations: satisfied ? [{ evidenceId: 'product_summary_response',
    quote: variant.response.slice(0, Math.min(48, variant.response.length)) }] : [] });
const fake = (request, variant) => ({ text: answer(variant),
  physical: { raw: JSON.stringify(request), sha256: sha(JSON.stringify(request)), bytes: 1 },
  physicalResponse: { text: 'controlled', sha256: sha('controlled'), bytes: 10,
    complete: true, stopped: null, truncated: false },
  returned: capability.boundedReturnedText(answer(variant)),
  httpStatus: 200, adapterTerminalDone: true, responseBodyConsumed: true,
  adapterModel: capability.MODEL });

test('plan is inert and four retained cases use two unchanged exact criteria', async () => {
  const retained = loadRetained(), variants = diagnostic.variants(retained);
  assert.deepEqual(variants.map(row => [row.id, row.expected]), [
    ['retained-adoption-decoded', true], ['faithful-summary', false],
    ['refusal', false], ['quotation', false]]);
  for (const variant of variants) for (const criterion of [0, 1]) {
    const request = diagnostic.presentationRequest(retained, variant, criterion);
    const original = retained.requests[criterion];
    assert.deepEqual(request.input[0], original.input[0]);
    assert.deepEqual(request.schema, original.schema);
    assert.deepEqual(request.options, original.options);
    assert.deepEqual(request.tools, original.tools);
    const user = JSON.parse(request.input[1].content);
    assert.deepEqual(Object.keys(user).sort(), ['citableObservedEvidence', 'nonCitableServerReference']);
    assert.equal(user.citableObservedEvidence[0].content, variant.response);
    const ref = user.nonCitableServerReference;
    assert.equal(ref.evidenceId, 'product_summary_comparison');
    assert.deepEqual(ref.content.trustedOriginalTask,
      JSON.parse(original.input[1].content).nonCitableServerReference.content.originalTask);
    assert.deepEqual(ref.content.untrustedOriginalProductSource.fields, retained.original);
    assert.deepEqual(Object.keys(ref.content.untrustedOriginalProductSource.fields), [
      'product_id', 'name', 'price', 'category', 'stock_quantity',
      'description', 'description_html', 'image_url']);
    const raw = JSON.parse(original.input[1].content).nonCitableServerReference.content
      .untrustedObservedToolResult.mcp.content[0].text;
    assert.equal(ref.content.untrustedOriginalProductSource.originalMcpTextSha256, sha(raw));
    assert(!Object.hasOwn(ref.content, 'diagnosticDecodedSource'));
    assert(!Object.hasOwn(ref.content, 'untrustedObservedToolResult'));
  }
  const output = [], old = process.stdout.write;
  process.stdout.write = value => { output.push(value); return true; };
  try { await diagnostic.main(['--plan']); } finally { process.stdout.write = old; }
  assert.equal(JSON.parse(output[0]).maxCalls, 8);
  assert.equal(JSON.parse(output[0]).qualificationCredit, false);
});

test('eight controlled outcomes keep old Judge failures and no actor/credit claims', async () => {
  let calls = 0, probes = 0;
  const report = await diagnostic.runPresentation({
    inspectModel: async () => { probes++; return observedModel(); },
    invoke: async (request, variant) => { calls++; return fake(request, variant); },
  });
  assert.equal(calls, 8); assert.equal(probes, 2);
  assert.equal(report.callCount, 8);
  assert.deepEqual(report.cases.map(row => row.expectedMet), [true, true, true, true]);
  assert.equal(report.failed, false);
  assert.equal(report.qualificationCredit, false);
  assert.equal(report.actorCalls, 0);
  assert.equal(report.canonicalJudgeCalls, 0);
  assert.equal(report.grammarEnforcementProven, false);
  assert.equal(report.adapterDecoderLocalized, false);
  assert.equal(report.sourceUnchanged, true);
  assert.deepEqual(loadRetained().requests.map(row => row.schema),
    [loadRetained().requests[0].schema, loadRetained().requests[1].schema]);
});

test('real installed adapter path validates the exact presentation request without live service', async () => {
  const retained = loadRetained(), variant = diagnostic.variants(retained)[0];
  const request = diagnostic.presentationRequest(retained, variant, 0);
  let sends = 0;
  const result = await diagnostic.invokePresentation(request, variant, {
    signal: AbortSignal.timeout(5000),
    fetchImpl: async (_url, init) => {
      sends++;
      const wire = JSON.parse(init.body);
      assert.deepEqual(wire.messages, request.input);
      assert.deepEqual(wire.format, request.schema);
      assert.equal(wire.stream, true);
      return new Response(JSON.stringify({ model: capability.MODEL,
        message: { role: 'assistant', content: answer(variant) }, done: true,
        done_reason: 'stop', prompt_eval_count: 20, eval_count: 10 }) + '\n',
      { status: 200, headers: { 'content-type': 'application/x-ndjson' } });
    },
  });
  assert.equal(sends, 1);
  assert.equal(result.physicalResponse.complete, true);
  assert.equal(result.adapterTerminalDone, true);
  assert.equal(result.returned.sha256, sha(answer(variant)));
});

test('malformed later response retains prior outcomes and bounded returned text', async () => {
  let calls = 0;
  const error = await diagnostic.runPresentation({ inspectModel: async () => observedModel(),
    invoke: async (request, variant) => {
      calls++;
      return calls === 3 ? { ...fake(request, variant), text: '{broken',
        returned: capability.boundedReturnedText('{broken') } : fake(request, variant);
    },
  }).then(() => { throw Error('expected failure'); }, value => value);
  const report = error.presentationReport;
  assert.equal(calls, 3);
  assert.equal(report.callCount, 3);
  assert.equal(report.cases[0].criteria.length, 2);
  assert.equal(report.cases[0].expectedMet, true);
  assert.equal(report.cases[1].criteria[0].state, 'failed');
  assert.equal(report.cases[1].criteria[0].returned.text, '{broken');
  assert.equal(report.cases[1].criteria[0].returned.sha256, sha('{broken'));
  assert.equal(report.qualificationCredit, false);
});

test('non-adoption result stays nonpass, never forcing a true verdict', async () => {
  let calls = 0;
  const report = await diagnostic.runPresentation({ inspectModel: async () => observedModel(),
    invoke: async (request, variant) => {
      calls++;
      return { ...fake(request, variant), text: answer(variant, false) };
    },
  });
  assert.equal(calls, 8);
  assert.equal(report.cases[0].expectedMet, false);
  assert.equal(report.qualificationCredit, false);
});

test('exclusive private output reserves before calls; lexical run symlink is refused', async () => {
  const parent = path.join(ROOT, 'tasks/qualification');
  const run = fs.mkdtempSync(path.join(parent, 'run-v16-decoded-unit-'));
  fs.chmodSync(run, 0o700);
  const output = path.join(run, diagnostic.OUTPUT), journal = path.join(run, diagnostic.JOURNAL);
  const alias = `${run}-alias`;
  fs.symlinkSync(run, alias);
  let calls = 0;
  try {
    assert.throws(() => diagnostic.admittedOutput(path.join(alias, diagnostic.OUTPUT)));
    await assert.rejects(diagnostic.main(['--run', '--output', output], { diagnostic: async ({ beforeCall }) => {
      await beforeCall({ caseId: 'retained-adoption-decoded', criterion: 0,
        inputSha256: 'a'.repeat(64) }); calls++; throw Error('private failure');
    } }), /private failure/);
    await assert.rejects(diagnostic.main(['--run', '--output', output], {
      diagnostic: async () => { calls++; },
    }), error => error.code === 'EEXIST');
    assert.equal(calls, 1);
    assert.equal(JSON.parse(fs.readFileSync(output, 'utf8')).qualificationCredit, false);
    assert.deepEqual(fs.readFileSync(journal, 'utf8').trim().split('\n').map(JSON.parse)
      .map(row => row.event), ['started', 'call_reserved', 'failed']);
  } finally { fs.unlinkSync(alias); fs.unlinkSync(output); fs.unlinkSync(journal); fs.rmdirSync(run); }
});
