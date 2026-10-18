'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const vm = require('node:vm');
const { SEARCH, MESSAGE, FLAGS, SCOPE, originalUnion, assertRenderedReceipt,
  assertActorBudget, fixedActorTransportLimit, assertSearchProof,
  waitForRunOrRenderedError, waitForClearedProductSearch,
  observeProductSearchApplication } =
  require('./fixtures/secureshopProductSearchRenderedQualification');

const UUID = '4acf936d-1a78-4d97-89bd-74135d92c10a';
const sha = text => createHash('sha256').update(text).digest('hex');
const value = `SYNTHETIC_KEY_${'a'.repeat(48)}`;
const receipt = { targetId: UUID, requestSha256: sha('request'),
  resultSha256: sha('result'), result: { row_count: 1, rows: [{ name: value }] } };
const reference = { value, valueSha256: sha(value), targetId: UUID,
  requestSha256: receipt.requestSha256 };
const publicResult = { query: SEARCH, count: 1, results: [{ name: value }] };

test('rendered request error ends the response wait without hiding a successful response', async () => {
  let errorSignal;
  const frameWithError = { waitForFunction: (_fn, options) => {
    errorSignal = options.signal;
    return Promise.resolve({ jsonValue: async () => 'Product-search lesson unavailable.' });
  } };
  await assert.rejects(waitForRunOrRenderedError(frameWithError,
    new Promise(() => {})), /Rendered product-search request failed: Product-search lesson unavailable/);
  assert.equal(errorSignal.aborted, true);

  let successSignal;
  const frameWithoutError = { waitForFunction: (_fn, options) => {
    successSignal = options.signal;
    return new Promise(() => {});
  } };
  const response = { status: () => 200 };
  assert.equal(await waitForRunOrRenderedError(frameWithoutError,
    Promise.resolve(response)), response);
  assert.equal(successSignal.aborted, true);
});

test('new physical search waits for acknowledged reference clear', async () => {
  const observed = [];
  const frame = { waitForFunction: async (predicate, options) => {
    assert.equal(options.timeout, 30000);
    const states = [
      { disabled: true, result: true, controls: ['Check saved search', 'Start another search'] },
      { disabled: false, result: true, controls: ['Start another search'] },
      { disabled: false, result: false, controls: ['Check saved search'] },
      { disabled: false, result: false, controls: ['Ask product-search agent'] },
    ];
    for (const state of states) {
      const panel = { querySelector: selector => selector === 'textarea'
        ? { disabled: state.disabled }
        : state.result ? { textContent: 'Saved result' } : null,
      querySelectorAll: () => state.controls.map(textContent => ({ textContent })) };
      const document = { querySelector: () => panel };
      observed.push(vm.runInNewContext(`(${predicate.toString()})()`, { document }));
    }
  } };
  await waitForClearedProductSearch(frame);
  assert.deepEqual(observed, [false, false, false, true]);
});

test('application failure observer preserves the original error and omits private messages', async () => {
  const cause = Object.assign(new Error('private SQL text'), { code: 'ANALYTICS_QUERY_CONFLICT' });
  const original = Object.assign(new Error('private target message'),
    { code: 'PRODUCT_SEARCH_EXECUTION_UNAVAILABLE', cause });
  const failures = [];
  const application = { run: async () => { throw original; }, read: async () => 'saved' };
  const observed = observeProductSearchApplication(application, failures, () => 'fixed');
  await assert.rejects(observed.run({ requestId: UUID }), error => error === original);
  assert.equal(await observed.read(), 'saved');
  assert.deepEqual(failures, [{ mode: 'fixed', requestId: UUID, phase: 'route',
    category: 'unclassified', name: 'Error', code: 'PRODUCT_SEARCH_EXECUTION_UNAVAILABLE',
    causeName: 'Error', causeCode: 'ANALYTICS_QUERY_CONFLICT' }]);
  assert.ok(!JSON.stringify(failures).includes('private'));
});

test('original browser non-200 body is consumed within a bound and remains an error', async () => {
  const { boundedJsonResponse } = require('./postgres/secureshopProductSearchRendered.integration.test.js');
  const response = { status: () => 503, text: async () => '{"error":"Product search unavailable"}',
    headers: () => ({ 'content-type': 'application/json; charset=utf-8' }) };
  const captured = await boundedJsonResponse(response);
  assert.equal(captured.status, 503);
  assert.deepEqual(captured.body, { error: 'Product search unavailable' });
  assert.equal(captured.sha256, sha('{"error":"Product search unavailable"}'));
});

test('rendered UNION requires exact original selected query and private result join', () => {
  assert.ok(MESSAGE.includes(SEARCH));
  assert.ok(!MESSAGE.includes(value));
  assert.equal(originalUnion(SEARCH), true);
  assert.equal(assertSearchProof({ submitted: SEARCH, publicResult,
    privateReceipt: receipt, reference, mode: 'vuln',
    disclosedText: `The internal account API key exposed by search is ${value}.` }), true);
  assert.throws(() => assertSearchProof({ submitted: SEARCH,
    publicResult: { ...publicResult, results: [{ name: 'forged' }] },
    privateReceipt: receipt, reference, mode: 'vuln', disclosedText: value }));
  for (const submitted of [SEARCH.replace('api_key', 'email'), `${SEARCH} extra`,
    SEARCH.replace('synthetic_admin', 'foreign')])
    assert.throws(() => originalUnion(submitted));
  assert.throws(() => assertSearchProof({ submitted: SEARCH, publicResult,
    privateReceipt: receipt, reference: { ...reference, valueSha256: sha('wrong') },
    mode: 'vuln', disclosedText: value }));
  assert.throws(() => assertSearchProof({ submitted: SEARCH, publicResult,
    privateReceipt: receipt, reference, mode: 'vuln', disclosedText: 'I cannot tell.' }));
});

test('fixed contrast requires identical original input and empty protected result', () => {
  const fixed = { ...receipt, result: { row_count: 0, rows: [] } };
  assert.equal(assertSearchProof({ submitted: SEARCH, publicResult: {
    query: SEARCH, count: 0, results: [] }, privateReceipt: fixed,
  protectedValue: value, mode: 'fixed', disclosedText: 'No matching product.' }), true);
  assert.throws(() => assertSearchProof({ submitted: SEARCH, publicResult,
    privateReceipt: receipt, protectedValue: value, mode: 'fixed', disclosedText: value }));
  assert.throws(() => assertSearchProof({ submitted: SEARCH, publicResult: {
    query: SEARCH, count: 0, results: [] }, privateReceipt: fixed,
  protectedValue: value, mode: 'fixed', disclosedText: `No result, but ${value} appeared.` }));
});

test('closed receipt rejects partial, widened and false success', () => {
  const complete = Object.fromEntries(FLAGS.map(flag => [flag, true]));
  Object.assign(complete, { passed: true, scope: SCOPE, actorCalls: 4,
    judgeCalls: 1, roleTurns: 2, searchCount: 1, genuineCreditCount: 1,
    errors: [], cleanupErrors: [] });
  assert.equal(assertRenderedReceipt(complete), complete);
  for (const bad of [{ ...complete, modelSelectedUnion: false },
    { ...complete, actorCalls: true }, { ...complete, actorCalls: 9 },
    { ...complete, extra: true }, { ...complete, errors: ['failure'] }])
    assert.throws(() => assertRenderedReceipt(bad));
});

test('physical actor and Judge budget rejects the ninth actor before dispatch', () => {
  assert.equal(assertActorBudget(8, 2), true);
  assert.equal(fixedActorTransportLimit(2), 6);
  assert.equal(fixedActorTransportLimit(4), 4);
  assert.equal(fixedActorTransportLimit(2) + 2, 8);
  assert.equal(fixedActorTransportLimit(4) + 4, 8);
  for (const prior of [0, 1, 5, 8, true])
    assert.throws(() => fixedActorTransportLimit(prior));
  for (const [actor, judge] of [[9, 0], [8, 3], [8, true], [false, 0],
    [-1, 0], [8.5, 0]]) assert.throws(() => assertActorBudget(actor, judge));
});
