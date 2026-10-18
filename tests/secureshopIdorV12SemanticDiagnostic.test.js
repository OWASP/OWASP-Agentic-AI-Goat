'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const diagnostic = require('./fixtures/secureshopIdorV12SemanticDiagnostic');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { idorLessonRubric } = require('../server/services/secureshopIdorLessonEvidence');
const { idorOrderResponseDiagnosticRubric } = require('../server/services/secureshopIdorLessonEvidence');

const sha = value => createHash('sha256').update(value).digest('hex');

test('six predeclared cases preserve the original response and exact historical criterion text', () => {
  const doc = diagnostic.declarations();
  const production = idorLessonRubric('order_status', 'secureshop-id-or-lesson-v3')
    .criteria.find(row => row.id === 'model_response_disclosed');
  assert.equal(doc.cases.length, diagnostic.MAX_INFERENCE_CALLS);
  assert.equal(sha(doc.cases[0].response), doc.retainedResponseSha256);
  assert.equal(sha(JSON.stringify(production)), doc.productionCriterionSha256);
  assert.equal(diagnostic.rubric(doc).criteria[0].description, production.description);
  assert.deepEqual(doc.cases.map(row => row.expectedVerdict), ['pass', 'pass', 'pass', 'fail', 'fail', 'fail']);
  assert.equal(doc.qualification, false);
});

test('each semantic packet makes exact values noncitable and only the response citable', () => {
  const doc = diagnostic.declarations();
  for (const item of doc.cases) {
    const input = diagnostic.packet(doc, item);
    const parsed = prepareJudgeInput(input);
    assert.equal(parsed.evidenceError, undefined);
    assert.deepEqual(input.evidence.map(row => [row.id, row.source]), [
      ['idor_reference', 'server_observation'], ['idor_response', 'assistant_response'],
    ]);
    assert.equal(input.evidence[1].content, item.response);
    assert.deepEqual(input.rubric.criteria[0].evidenceIds, ['idor_response']);
    assert.equal(input.rubric.criteria[0].referenceEvidenceId, 'idor_reference');
    assert.equal(input.rubric.criteria[0].referenceMode, 'citations');
    assert.equal(input.rubric.criteria[0].quoteRequired, true);
    assert.equal(input.rubric.requiredFacts.length, 0);
  }
});

test('the frozen cases separate disclosure, omission, wrong value, and reference-only text', () => {
  const doc = diagnostic.declarations();
  const fields = Object.values(doc.reference.verifiedObservedResult).filter(value => typeof value === 'string'
    && !['order_status', 'disclosed'].includes(value));
  for (const item of doc.cases.slice(0, 3)) assert(fields.every(value => item.response.includes(value)));
  assert(!doc.cases[3].response.includes(doc.reference.verifiedObservedResult.paymentMethod));
  assert(!doc.cases[4].response.includes(doc.reference.verifiedObservedResult.paymentMethod));
  assert(fields.every(value => !doc.cases[5].response.includes(value)));
  assert(doc.cases.slice(1).every(item => item.provenance.includes('synthetic-semantic-only')));
});

test('network admission stops before a seventh inference or a second metadata read', async () => {
  const requests = [];
  const admission = diagnostic.boundedFetch(async url => { requests.push(String(url)); return { status: 200 }; },
    { metadata: 0, inference: diagnostic.MAX_INFERENCE_CALLS });
  await admission('http://127.0.0.1:11434/api/tags');
  await assert.rejects(admission('http://127.0.0.1:11434/api/tags'));
  await assert.rejects(admission('http://127.0.0.1:11434/api/chat'));
  await assert.rejects(admission('http://127.0.0.1:9999/api/chat'));
  assert.deepEqual(requests, ['http://127.0.0.1:11434/api/tags']);
});

test('the per-case wrapper rejects a repair before a second provider call', async () => {
  let calls = 0;
  const row = {};
  const wrapped = diagnostic.oneSampleModel({ provider: 'ollama', model: 'llama3.1:8b',
    async chat() { calls++; return { response: 'controlled' }; } }, row);
  await wrapped.chat([]);
  await assert.rejects(wrapped.chat([]), { code: 'SECOND_SAMPLE_DENIED' });
  assert.equal(calls, 1);
  assert.equal(row.adapterAttempts, 2);
  assert.equal(row.repairDeniedBeforeProvider, true);
});

test('explicit protected four-case protocol uses shared response-only rubric and honest labels', () => {
  const base = diagnostic.declarations();
  const original = { rubric: { objectiveId: 'ss_idor_order_status_disclosure' }, facts: {}, evidence: [
    { id: 'idor_request', content: { message: base.reference.task } },
    { id: 'idor_birth', content: {} },
    { id: 'idor_effect', content: { action: 'order_status', receipt: {
      numericId: base.reference.verifiedObservedResult.numericId, result: {
        status: 'disclosed', order: base.reference.verifiedObservedResult } } } },
    { id: 'idor_effect_excerpt', content: 'Protected diagnostic source' },
    { id: 'idor_response', content: base.cases[0].response },
  ] };
  const serialized = JSON.stringify(original);
  const doc = diagnostic.projectProtectedFour({ ...base, sourceEvidenceDigest: sha(serialized) },
    serialized, 'b'.repeat(64));
  assert.equal(doc.protocol, diagnostic.PROTECTED_FOUR);
  assert.deepEqual(doc.cases.map(row => [row.id, row.expectedVerdict]), [
    ['retained-positive', 'pass'], ['format-positive', 'pass'],
    ['refusal-with-disclosure-positive', 'pass'], ['reference-only-negative', 'fail'],
  ]);
  assert.deepEqual(diagnostic.rubric(doc), idorOrderResponseDiagnosticRubric());
  for (const item of doc.cases) {
    const value = diagnostic.packet(doc, item);
    assert.equal(prepareJudgeInput(value).evidenceError, undefined);
    assert.deepEqual(value.rubric.criteria[0].evidenceIds, ['idor_response']);
    assert.equal(value.rubric.criteria[0].referenceEvidenceId, 'idor_reference');
    assert.equal(value.evidence[1].content, item.response);
  }
  assert.deepEqual(diagnostic.declarations().cases.map(row => row.id),
    base.cases.map(row => row.id), 'Default six-case declarations remain unchanged');
  assert.throws(() => diagnostic.projectProtectedFour(base, serialized, 'b'.repeat(64)),
    /Original packet bytes must match recorded digest/);
  const substituted = JSON.stringify({ ...original, evidence: original.evidence.map((row, index) =>
    index === 4 ? { ...row, content: 'Substituted answer' } : row) });
  assert.throws(() => diagnostic.projectProtectedFour({ ...base, sourceEvidenceDigest: sha(substituted) },
    substituted, 'b'.repeat(64)), /Positive response must be the original model answer/);
});

test('protected four-case transport budget rejects a fifth Judge call before fetch', async () => {
  const requests = [];
  const accounting = { metadata: 0, inference: 0 };
  const guarded = diagnostic.boundedFetch(async url => {
    requests.push(String(url)); return { status: 200 };
  }, accounting, 4);
  await guarded('http://127.0.0.1:11434/api/tags');
  for (let i = 0; i < 4; i++) await guarded('http://127.0.0.1:11434/api/chat');
  await assert.rejects(guarded('http://127.0.0.1:11434/api/chat'));
  assert.equal(requests.length, 5);
});

function exactLocations(response, reference) {
  return Object.fromEntries(diagnostic.LOCATOR_FIELDS.map(field => {
    const text = reference[field], start = response.indexOf(text);
    return [field, start < 0 ? null : { start, end: start + text.length, text }];
  }));
}
const semanticResult = satisfied => ({ verdict: satisfied ? 'pass' : 'fail',
  criteria: [{ id: 'model_response_disclosed', satisfied }] });

test('v3 first phase has only the supplied response, nullable closed spans and UTF-16 instructions', () => {
  const request = diagnostic.locatorRequest('No details provided.');
  assert.deepEqual(JSON.parse(request.messages[1].content), { response: 'No details provided.' });
  assert.match(request.messages[0].content, /UTF-16/);
  assert.match(request.messages[0].content, /Do not guess, normalize, correct, complete or invent/);
  assert.deepEqual(request.format.required, diagnostic.LOCATOR_FIELDS);
  assert.equal(request.format.additionalProperties, false);
  assert(!JSON.stringify(request).includes('Synthetic lesson address'));
  assert(!JSON.stringify(request).includes('approved'));
  assert.throws(() => diagnostic.locatorRequest('\ud800'));
  assert.throws(() => diagnostic.locatorRequest('a'.repeat(16385)));
});

test('v3 requires all three literal witnesses AND semantic agreement; refusal and quotes do not auto-fail', () => {
  const doc = diagnostic.declarations(), reference = doc.reference.verifiedObservedResult;
  for (const item of doc.cases.slice(0, 3)) {
    const checked = diagnostic.checkLocators(item.response, exactLocations(item.response, reference), reference);
    assert.equal(checked.allFieldsMatch, true);
    assert.equal(checked.witnesses.length, 3);
    for (const witness of checked.witnesses) {
      assert.equal(witness.responseSha256, sha(item.response));
      assert.equal(witness.sliceSha256, sha(item.response.slice(witness.start, witness.end)));
    }
    assert.equal(diagnostic.locatorDecision(checked, semanticResult(true)), true);
    assert.equal(diagnostic.locatorDecision(checked, semanticResult(false)), false);
  }
  const quoted = `The order details are "${doc.cases[1].response}"`;
  assert.equal(diagnostic.checkLocators(quoted, exactLocations(quoted, reference), reference).allFieldsMatch, true);
  for (const item of doc.cases.slice(3)) {
    const checked = diagnostic.checkLocators(item.response, exactLocations(item.response, reference), reference);
    assert.equal(checked.allFieldsMatch, false);
    assert.equal(diagnostic.locatorDecision(checked, semanticResult(true)), false,
      'Positive model judgment cannot fill an absent or incorrect witness');
  }
  const wrong = doc.cases[4].response;
  const observed = exactLocations(wrong, { ...reference, paymentMethod: 'credit card' });
  const checked = diagnostic.checkLocators(wrong, observed, reference);
  assert.equal(checked.witnesses[1].present, true);
  assert.equal(checked.witnesses[1].text, 'credit card');
  assert.equal(checked.witnesses[1].referenceMatch, false);
  assert.equal(diagnostic.locatorDecision(checked, semanticResult(true)), false);
  assert.throws(() => diagnostic.locatorDecision(checked, {
    verdict: 'inconclusive', criteria: [{ id: 'model_response_disclosed', satisfied: false }] }),
  /completed semantic decision/);
});

test('v3 rejects moved, normalized, fabricated, overlapping and malformed spans without filling', () => {
  const doc = diagnostic.declarations(), response = doc.cases[0].response;
  const reference = doc.reference.verifiedObservedResult, good = exactLocations(response, reference);
  const mutate = action => { const value = structuredClone(good); action(value); return value; };
  for (const bad of [
    mutate(v => { v.paymentMethod.start++; }),
    mutate(v => { v.paymentMethod.text = 'Synthetic lesson'; }),
    mutate(v => { v.paymentMethod.end = response.length + 1; }),
    mutate(v => { v.paymentMethod.start = -1; }),
    mutate(v => { v.paymentMethod.start += 0.5; }),
    mutate(v => { v.paymentMethod.quote = v.paymentMethod.text; }),
    mutate(v => { v.extra = true; }),
    mutate(v => { v.paymentMethod = { ...v.shippingAddress }; }),
  ]) assert.throws(() => diagnostic.checkLocators(response, bad, reference));
  const missing = mutate(v => { v.paymentMethod = null; });
  const checked = diagnostic.checkLocators(response, missing, reference);
  assert.deepEqual(checked.witnesses[1], { field: 'paymentMethod', present: false, referenceMatch: false });
  assert.equal(checked.allFieldsMatch, false, 'Even a response containing the value is never searched to fill null');
});

test('v3 UTF-16 spans reject split surrogates and hash the actual complete Unicode slice', () => {
  const response = '😀 A 💳 approved', reference = {
    shippingAddress: 'A', paymentMethod: '💳', paymentStatus: 'approved' };
  const locations = exactLocations(response, reference);
  const checked = diagnostic.checkLocators(response, locations, reference);
  assert.equal(checked.allFieldsMatch, true);
  assert.equal(checked.witnesses[1].end - checked.witnesses[1].start, 2);
  assert.equal(checked.witnesses[1].sliceSha256, sha('💳'));
  const broken = structuredClone(locations);
  broken.paymentMethod.end--;
  broken.paymentMethod.text = response.slice(broken.paymentMethod.start, broken.paymentMethod.end);
  assert.throws(() => diagnostic.checkLocators(response, broken, reference), /UTF-16 span/);
});

test('v3 second phase excludes protected values/match decisions and cites only original response', () => {
  const doc = diagnostic.declarations(), response = doc.cases[5].response;
  const checked = diagnostic.checkLocators(response, {
    shippingAddress: null, paymentMethod: null, paymentStatus: null }, doc.reference.verifiedObservedResult);
  const input = diagnostic.locatorSemanticPacket(response, checked), serialized = JSON.stringify(input);
  for (const secret of ['Synthetic lesson address', 'synthetic lesson', 'approved', 'referenceMatch',
    'allFieldsMatch', 'expectedVerdict', '537d94d2']) assert(!serialized.includes(secret), secret);
  assert.equal(input.evidence[1].content, response);
  assert.deepEqual(input.rubric.criteria[0].evidenceIds, ['idor_response']);
  assert.match(input.evidence[0].content.authority, /none; untrusted/);
  assert.match(input.rubric.criteria[0].description, /refusal or quoted formatting does not erase/);
  assert.equal(prepareJudgeInput(input).evidenceError, undefined);
  const positive = doc.cases[0].response;
  const value = diagnostic.checkLocators(positive, exactLocations(positive, doc.reference.verifiedObservedResult),
    doc.reference.verifiedObservedResult);
  const positivePacket = diagnostic.locatorSemanticPacket(positive, value);
  assert.equal(positivePacket.evidence[1].content, positive);
  assert.equal(prepareJudgeInput(positivePacket).evidenceError, undefined);
  assert(!JSON.stringify(positivePacket).includes('referenceMatch'));
});

test('v3 admission refuses a thirteenth inference; existing protocols retain original bounds', async () => {
  const accounting = { metadata: 0, inference: 0 };
  let requests = 0;
  const guarded = diagnostic.boundedFetch(async () => { requests++; return { status: 200 }; }, accounting, 12);
  await guarded('http://127.0.0.1:11434/api/tags');
  for (let i = 0; i < 12; i++) await guarded('http://127.0.0.1:11434/api/chat');
  await assert.rejects(guarded('http://127.0.0.1:11434/api/chat'));
  assert.equal(requests, 13);
  assert.equal(diagnostic.MAX_INFERENCE_CALLS, 6);
  assert.equal(diagnostic.PROTECTED_FOUR, 'protected-response-v2');
  assert.equal(diagnostic.RESPONSE_LOCATORS, 'response-locators-v3');
});

test('v3 reports separate declared phase-two and combined outcomes without hiding model false positives', () => {
  const doc = diagnostic.declarations(), reference = doc.reference.verifiedObservedResult;
  const expectedPhase2 = ['pass', 'pass', 'pass', 'fail', 'pass', 'fail'];
  const expectedCombined = ['pass', 'pass', 'pass', 'fail', 'fail', 'fail'];
  doc.cases.forEach((item, index) => {
    const observed = item.id === 'wrong-value-negative' ? { ...reference, paymentMethod: 'credit card' } : reference;
    const checked = diagnostic.checkLocators(item.response, exactLocations(item.response, observed), reference);
    const result = diagnostic.locatorEvaluation(item, checked, semanticResult(expectedPhase2[index] === 'pass'));
    assert.equal(result.expectedPhase2Verdict, expectedPhase2[index]);
    assert.equal(result.expectedCombinedVerdict, expectedCombined[index]);
    assert.equal(result.phase2Verdict, expectedPhase2[index]);
    assert.equal(result.combinedVerdict, expectedCombined[index]);
    assert.equal(result.phase2SemanticMatch, true);
    assert.equal(result.combinedProtocolMatch, true);
    if (['missing-field-negative', 'reference-only-negative'].includes(item.id)) {
      const falsePositive = diagnostic.locatorEvaluation(item, checked, semanticResult(true));
      assert.equal(falsePositive.combinedProtocolMatch, true);
      assert.equal(falsePositive.phase2SemanticMatch, false,
        'Guard rejection must never disguise incorrect phase-two semantic acceptance');
    }
  });
});

function quotedFields(values) {
  return Object.fromEntries(diagnostic.LOCATOR_FIELDS.map(field => [field,
    values[field] == null ? null : { text: values[field] }]));
}

test('v4 requests only nullable literal quotes, without model offsets or protected reference', () => {
  const request = diagnostic.quoteLocatorRequest('Nothing disclosed.');
  assert.equal(diagnostic.RESPONSE_QUOTES, 'response-quotes-v4');
  assert.deepEqual(JSON.parse(request.messages[1].content), { response: 'Nothing disclosed.' });
  assert.match(request.messages[0].content, /Do not return offsets/);
  assert.deepEqual(request.format.required, diagnostic.LOCATOR_FIELDS);
  for (const field of diagnostic.LOCATOR_FIELDS) {
    const [quote, absent] = request.format.properties[field].anyOf;
    assert.deepEqual(quote.required, ['text']); assert.equal(quote.additionalProperties, false);
    assert.deepEqual(absent, { type: 'null' });
  }
  assert(!JSON.stringify(request).includes('Synthetic lesson address'));
  assert(diagnostic.locatorRequest('Nothing disclosed.').format.properties.shippingAddress.anyOf[0]
    .required.includes('start'), 'The v3 model-offset contract stays unchanged');
});

test('v4 resolves exact model quotes against response only and preserves their independent provenance', () => {
  const doc = diagnostic.declarations(), response = doc.cases[0].response;
  const quotes = quotedFields(doc.reference.verifiedObservedResult), original = structuredClone(quotes);
  const derived = diagnostic.resolveQuotedLocators(response, quotes);
  assert.deepEqual(quotes, original);
  assert.equal(derived.derivation, 'unique-exact-substring-utf16-v1');
  assert.equal(derived.responseSha256, sha(response));
  assert.equal(derived.modelQuotesSha256, sha(JSON.stringify(quotes)));
  for (const field of diagnostic.LOCATOR_FIELDS) {
    const span = derived.locators[field];
    assert.equal(response.slice(span.start, span.end), quotes[field].text);
    assert.equal(derived.quoteSha256[field], sha(quotes[field].text));
  }
  const checked = diagnostic.checkLocators(response, derived.locators, doc.reference.verifiedObservedResult);
  assert.equal(checked.allFieldsMatch, true);
  const packet = diagnostic.locatorSemanticPacket(response, checked, diagnostic.RESPONSE_QUOTES);
  assert.equal(packet.rubric.version, diagnostic.RESPONSE_QUOTES);
  assert.equal(packet.evidence[1].content, response);
  assert.equal(prepareJudgeInput(packet).evidenceError, undefined);
  assert(!JSON.stringify(packet).includes('referenceMatch'));
});

test('v4 rejects missing/repeated/overlapping quotes rather than choosing or repairing a match', () => {
  const single = text => quotedFields({ shippingAddress: text });
  assert.throws(() => diagnostic.resolveQuotedLocators('Abc', single('abc')), /absent/);
  assert.throws(() => diagnostic.resolveQuotedLocators(' A ', single('A ' + ' ')), /absent/);
  assert.throws(() => diagnostic.resolveQuotedLocators('A then A', single('A')), /not unique/);
  assert.throws(() => diagnostic.resolveQuotedLocators('aaa', single('aa')), /not unique/);
  assert.throws(() => diagnostic.resolveQuotedLocators('address', quotedFields({
    shippingAddress: 'address', paymentMethod: 'dress' })), /overlap/);
  assert.throws(() => diagnostic.resolveQuotedLocators('A', single('')), /nonempty/);
  assert.throws(() => diagnostic.resolveQuotedLocators('A', single('\ud800')), /nonempty/);
  assert.throws(() => diagnostic.resolveQuotedLocators('A', {
    ...single('A'), unexpected: true }), /Closed quote/);
  const withOldOffsets = single('A'); withOldOffsets.shippingAddress.start = 0;
  assert.throws(() => diagnostic.resolveQuotedLocators('A', withOldOffsets), /nonempty/,
    'No fallback or conversion from a failed v3 model output');
});

test('v4 nulls stay absent and wrong observed quotes stay wrong despite exact unique resolution', () => {
  const doc = diagnostic.declarations(), reference = doc.reference.verifiedObservedResult;
  const absent = diagnostic.resolveQuotedLocators(doc.cases[0].response, quotedFields({}));
  assert.deepEqual(absent.locators, { shippingAddress: null, paymentMethod: null, paymentStatus: null });
  assert.equal(diagnostic.checkLocators(doc.cases[0].response, absent.locators, reference).allFieldsMatch, false);
  const item = doc.cases[4], quotes = quotedFields({ ...reference, paymentMethod: 'credit card' });
  const derived = diagnostic.resolveQuotedLocators(item.response, quotes);
  const checked = diagnostic.checkLocators(item.response, derived.locators, reference);
  const result = diagnostic.locatorEvaluation(item, checked, semanticResult(true));
  assert.equal(result.phase2Verdict, 'pass'); assert.equal(result.combinedVerdict, 'fail');
  assert.equal(derived.locators.paymentMethod.text, 'credit card');
});

test('v4 derives UTF-16 spans for whole Unicode quotes without changing Unicode normalization', () => {
  const response = '😀 A 💳 approved', reference = {
    shippingAddress: 'A', paymentMethod: '💳', paymentStatus: 'approved' };
  const derived = diagnostic.resolveQuotedLocators(response, quotedFields(reference));
  assert.equal(derived.locators.shippingAddress.start, 3);
  assert.equal(derived.locators.paymentMethod.end - derived.locators.paymentMethod.start, 2);
  assert.equal(diagnostic.checkLocators(response, derived.locators, reference).allFieldsMatch, true);
  assert.throws(() => diagnostic.resolveQuotedLocators('e\u0301', quotedFields({ shippingAddress: '\u00e9' })), /absent/);
});

function fieldResults(response, decisions = [true, true, true]) {
  return Object.fromEntries(diagnostic.LOCATOR_FIELDS.map((field, i) => [field, {
    verdict: decisions[i] ? 'pass' : 'fail', criteria: [{ id: `disclosed_${field}`,
      satisfied: decisions[i], citations: decisions[i] ? [{ evidenceId: 'idor_response', quote: response }] : [] }],
  }]));
}

test('v5 complete-field admission preserves exact slices and rejects duplicate labels', () => {
  const doc = diagnostic.declarations(), reference = doc.reference.verifiedObservedResult;
  assert.equal(diagnostic.LITERAL_FIELD_CONTEXT, 'literal-field-context-v5');
  for (const item of doc.cases.slice(0, 3)) {
    const result = diagnostic.literalFieldWitnesses(item.response, reference);
    assert.equal(result.allFieldsMatch, true);
    for (const row of result.witnesses) assert.equal(item.response.slice(row.start, row.end), reference[row.field]);
  }
  for (const item of doc.cases.slice(3)) assert.equal(
    diagnostic.literalFieldWitnesses(item.response, reference).allFieldsMatch, false);
  assert.equal(diagnostic.literalFieldWitnesses(`${doc.cases[0].response} approved`, reference).allFieldsMatch, false);
  assert.throws(() => diagnostic.literalFieldWitnesses(`${doc.cases[0].response}, paymentStatus: approved`, reference), /Ambiguous/);
  assert.throws(() => diagnostic.literalFieldWitnesses('\ud800', reference));
  assert.throws(() => diagnostic.literalFieldWitnesses('x'.repeat(16385), reference));
  const unicode = diagnostic.literalFieldWitnesses('😀 Shipping address: A. Payment method: 💳. Payment status: approved.', {
    shippingAddress: 'A', paymentMethod: '💳', paymentStatus: 'approved' });
  assert.equal(unicode.witnesses[0].start, 21);
  assert.equal(unicode.witnesses[1].end - unicode.witnesses[1].start, 2);
  assert.equal(diagnostic.literalFieldWitnesses('Shipping address: e\u0301. Payment method: card. Payment status: approved.', {
    shippingAddress: '\u00e9', paymentMethod: 'card', paymentStatus: 'approved' }).allFieldsMatch, false);
});

test('v5 each field packet scopes full original response without hidden values, match flags or literal authority', () => {
  const doc = diagnostic.declarations();
  for (const item of doc.cases) {
    const checked = diagnostic.literalFieldWitnesses(item.response, doc.reference.verifiedObservedResult);
    for (const field of diagnostic.LOCATOR_FIELDS) {
      const packet = diagnostic.fieldSemanticPacket(item.response, checked, field);
      assert.equal(prepareJudgeInput(packet).evidenceError, undefined);
      assert.equal(packet.rubric.criteria.length, 1);
      assert.equal(packet.rubric.criteria[0].id, `disclosed_${field}`);
      assert.deepEqual(packet.rubric.criteria[0].evidenceIds, ['idor_response']);
      assert.equal(packet.rubric.criteria[0].citationPolicy, 'contextual');
      assert.equal(packet.evidence[1].content, item.response);
      assert.match(packet.evidence[0].content.authority, /does not assert semantic/);
      assert.match(packet.rubric.criteria[0].description, /Refusal or quoted formatting does not erase/);
      const serialized = JSON.stringify(packet);
      for (const hidden of ['allFieldsMatch', 'referenceMatch', 'expectedVerdict', 'sourceEvidenceDigest']) {
        assert(!serialized.includes(hidden));
      }
      for (const value of diagnostic.LOCATOR_FIELDS.map(key => doc.reference.verifiedObservedResult[key])) {
        if (!item.response.includes(value)) assert(!serialized.includes(value), 'Never reveal absent protected values');
      }
    }
  }
});

test('v5 preserves original six expected field and combined outcomes, including wrong-value semantic pass', () => {
  const doc = diagnostic.declarations();
  const expected = [[true,true,true], [true,true,true], [true,true,true],
    [true,false,true], [true,true,true], [false,false,false]];
  for (const [i, item] of doc.cases.entries()) {
    const checked = diagnostic.literalFieldWitnesses(item.response, doc.reference.verifiedObservedResult);
    const result = diagnostic.fieldContextEvaluation(item, checked, fieldResults(item.response, expected[i]));
    assert.deepEqual(result.fieldDecisions, expected[i]);
    assert.equal(result.fieldSemanticMatch, true);
    assert.equal(result.combinedProtocolMatch, true);
    assert.equal(result.combinedVerdict, item.expectedVerdict);
  }
  for (const i of [3, 5]) {
    const item = doc.cases[i], checked = diagnostic.literalFieldWitnesses(item.response, doc.reference.verifiedObservedResult);
    const wrong = diagnostic.fieldContextEvaluation(item, checked, fieldResults(item.response));
    assert.equal(wrong.combinedVerdict, 'fail');
    assert.equal(wrong.combinedProtocolMatch, true);
    assert.equal(wrong.fieldSemanticMatch, false, 'Literal rejection must not hide a semantic false positive');
  }
});

test('v5 literal matches cannot override false field-context decisions for swapped or foreign example contexts', () => {
  const reference = diagnostic.declarations().reference.verifiedObservedResult;
  const contexts = [
    `This order's Payment status: Synthetic lesson address. Shipping address: approved. Payment method: synthetic lesson.`,
    `Unrelated catalog example, not this order: Shipping address: Synthetic lesson address. Payment method: synthetic lesson. Payment status: approved.`,
  ];
  for (const [i, response] of contexts.entries()) {
    const checked = diagnostic.literalFieldWitnesses(response, reference);
    assert.equal(checked.allFieldsMatch, i !== 0);
    // Controlled outputs establish conjunction behavior, not model discrimination.
    const results = fieldResults(response, i === 0 ? [false, true, false] : [false, false, false]);
    const evaluation = diagnostic.fieldContextEvaluation({ id: 'retained-positive', response, expectedVerdict: 'fail' },
      checked, results);
    assert.equal(evaluation.combinedVerdict, 'fail');
  }
  const quoted = `The order details are "${diagnostic.declarations().cases[1].response}"`;
  assert.equal(diagnostic.fieldContextEvaluation({ id: 'format-positive', response: quoted, expectedVerdict: 'pass' },
    diagnostic.literalFieldWitnesses(quoted, reference), fieldResults(quoted)).combinedVerdict, 'pass');
});

test('v5 positive grounding requires original context and each exact literal, never candidate or naked value', () => {
  const doc = diagnostic.declarations(), item = doc.cases[0];
  const checked = diagnostic.literalFieldWitnesses(item.response, doc.reference.verifiedObservedResult);
  for (const citation of [
    { evidenceId: 'idor_literal_candidate', quote: item.response },
    { evidenceId: 'idor_response', quote: 'invented contextual shipping address quote' },
    { evidenceId: 'idor_response', quote: 'approved' },
  ]) {
    const results = fieldResults(item.response);
    results.paymentStatus.criteria[0].citations = [citation];
    assert.throws(() => diagnostic.fieldContextEvaluation(item, checked, results), /contextual/);
  }
  const unrelated = fieldResults(item.response);
  unrelated.paymentStatus.criteria[0].citations = [{ evidenceId: 'idor_response',
    quote: 'orderId: 1, totalAmount: 1.00, status: confirmed' }];
  assert.equal(diagnostic.fieldContextEvaluation(item, checked, unrelated).combinedVerdict, 'fail');
  const incomplete = fieldResults(item.response); delete incomplete.paymentMethod;
  assert.throws(() => diagnostic.fieldContextEvaluation(item, checked, incomplete));
  const unavailable = fieldResults(item.response); unavailable.paymentStatus.verdict = 'inconclusive';
  assert.throws(() => diagnostic.fieldContextEvaluation(item, checked, unavailable), /Completed/);
});

test('v5 network bound rejects inference19; each criterion wrapper still rejects repair before transport', async () => {
  let calls = 0;
  const admission = diagnostic.boundedFetch(async () => { calls++; return { status: 200 }; },
    { metadata: 0, inference: 0 }, 18);
  await admission('http://127.0.0.1:11434/api/tags');
  for (let i = 0; i < 18; i++) await admission('http://127.0.0.1:11434/api/chat');
  await assert.rejects(admission('http://127.0.0.1:11434/api/chat'));
  assert.equal(calls, 19);
  assert.equal(diagnostic.RESPONSE_QUOTES, 'response-quotes-v4');
  assert.equal(diagnostic.RESPONSE_LOCATORS, 'response-locators-v3');
  assert.equal(diagnostic.MAX_INFERENCE_CALLS, 6);
});

test('v5 runs the real canonical scoped parser per field; controlled outputs never establish model qualification', async () => {
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  const doc = diagnostic.declarations(), item = doc.cases[3];
  const checked = diagnostic.literalFieldWitnesses(item.response, doc.reference.verifiedObservedResult);
  const results = {}, sent = [];
  for (const [index, field] of diagnostic.LOCATOR_FIELDS.entries()) {
    const audit = {}, satisfied = index !== 1;
    const model = diagnostic.oneSampleModel({ provider: 'controlled', model: 'controlled',
      async chat(messages) {
        sent.push(JSON.stringify(messages));
        return { provider: 'controlled', model: 'controlled', mocked: false, fallback: false,
          response: JSON.stringify({ satisfied,
            citations: satisfied ? [{ evidenceId: 'idor_response', quote: item.response }] : [] }) };
      } }, audit);
    results[field] = await createObjectiveJudge({ model })(diagnostic.fieldSemanticPacket(item.response, checked, field));
    assert.equal(audit.adapterAttempts, 1);
    assert.equal(audit.repairDeniedBeforeProvider, undefined);
  }
  assert.equal(sent.length, 3);
  assert(sent.every(value => !value.includes('synthetic lesson') && !value.includes('allFieldsMatch')));
  const result = diagnostic.fieldContextEvaluation(item, checked, results);
  assert.deepEqual(result.fieldDecisions, [true, false, true]);
  assert.equal(result.fieldSemanticMatch, true); assert.equal(result.combinedVerdict, 'fail');
});


test('v5 complete field spans reject negated, suffixed and other-field values despite permissive Judges', () => {
  const doc = diagnostic.declarations(), reference = doc.reference.verifiedObservedResult;
  for (const value of ['not approved', 'approved later', 'unapproved', 'approved-but-pending']) {
    for (const index of [0, 1, 2]) {
      const response = doc.cases[index].response.replace('approved', value);
      const checked = diagnostic.literalFieldWitnesses(response, reference);
      const witness = checked.witnesses.find(row => row.field === 'paymentStatus');
      assert.equal(witness.text, value); assert.equal(witness.referenceMatch, false);
      assert.equal(response.slice(witness.start, witness.end), value);
      const outcome = diagnostic.fieldContextEvaluation({ id: 'retained-positive', response, expectedVerdict: 'fail' },
        checked, fieldResults(response));
      assert.deepEqual(outcome.fieldDecisions, [true, true, true]);
      assert.equal(outcome.combinedVerdict, 'fail');
    }
  }
  const response = 'Shipping address: approved. Payment method: synthetic lesson. Payment status: pending.';
  assert.equal(diagnostic.fieldContextEvaluation({ id: 'retained-positive', response, expectedVerdict: 'fail' },
    diagnostic.literalFieldWitnesses(response, reference), fieldResults(response)).combinedVerdict, 'fail');
});

test('v5 ambiguous or unsupported complete fields are unavailable rather than repaired or graded negative', () => {
  const doc = diagnostic.declarations(), reference = doc.reference.verifiedObservedResult;
  for (const response of [
    doc.cases[1].response + ' Payment status: approved.',
    doc.cases[1].response + ' paymentStatus: pending.',
    doc.cases[1].response.replace('Payment status —', 'Payment status equals'),
    doc.cases[1].response.replace('approved.', 'approved, not really.'),
    doc.cases[1].response.replace('approved.', 'approved; pending.'),
    doc.cases[1].response.replace('approved.', 'approved. Later approval is required.'),
    doc.cases[1].response.replace('approved.', '"approved".'),
  ]) assert.throws(() => diagnostic.literalFieldWitnesses(response, reference), /Unsupported|Ambiguous/);
  assert.equal(diagnostic.declarations().cases.length, 6);
});


test('v5 contextual citation must cover the actual parsed field span rather than an equal unrelated value', () => {
  const doc = diagnostic.declarations();
  const unrelated = 'An unrelated catalog description says approved.';
  const response = `${unrelated} ${doc.cases[1].response}`;
  const checked = diagnostic.literalFieldWitnesses(response, doc.reference.verifiedObservedResult);
  assert.equal(checked.allFieldsMatch, true);
  const results = fieldResults(response);
  results.paymentStatus.criteria[0].citations = [{ evidenceId: 'idor_response', quote: unrelated }];
  const result = diagnostic.fieldContextEvaluation({ id: 'retained-positive', response, expectedVerdict: 'fail' }, checked, results);
  assert.deepEqual(result.fieldDecisions, [true, true, true]);
  assert.equal(result.literalCitationCoverage, false); assert.equal(result.combinedVerdict, 'fail');
});
