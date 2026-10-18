'use strict';

// This is a receipt-shape check only; the native browser/model cohort remains gated.
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertReviewRequestAuthority, originalReviewResponse, assertReviewInjectionReceipt,
  reviewInjectionSourceCase, REVIEW_INJECTION_FLAGS, REVIEW_INJECTION_SCOPE }
  = require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');

function receipt() {
  return Object.fromEntries([...REVIEW_INJECTION_FLAGS.map(flag => [flag, true]),
    ['scope', REVIEW_INJECTION_SCOPE], ['moderationTurns', 2], ['actorCalls', 6],
    ['judgeCalls', 1], ['genuineCredit', 1], ['errors', []]]);
}

test('V17 waits for the original response rather than the initial request-stage observation', async () => {
  const entry = { method: 'POST', path: '/products/7/reviews',
    body: { submission_id: 'original', body: 'original source', rating: 1 },
    status: null, value: null, authorityCaptureComplete: false };
  assert.equal(originalReviewResponse(undefined), null);
  assert.equal(originalReviewResponse(entry), null);
  await Promise.resolve().then(() => {
    entry.status = 200;
    entry.value = { ok: true, review_id: 9 };
  });
  assert.equal(originalReviewResponse(entry), null,
    'HTTP JSON alone is not ready while original-token authentication is pending');
  entry.authorityCaptureComplete = true;
  assert.equal(originalReviewResponse(entry), entry);
  const failure = { ...entry, status: 503, value: { error: 'Original review failed' } };
  assert.equal(originalReviewResponse(failure), failure,
    'a real HTTP error must reach the existing assertion, not wait for an imagined success');
  const invalidBody = { ...entry, value: null };
  assert.equal(originalReviewResponse(invalidBody), invalidBody,
    'the original JSON response is retained even when its body violates the closed success DTO');
  assert.equal(originalReviewResponse({ ...entry, status: '200' }), null);
});

test('V17 binds the original verified authority despite token resigning and rejects foreign identities', () => {
  const expected = {
    scope: { launchId: '11111111-1111-4111-8111-111111111111',
      scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1,
      platformOwnerId: 2, platformSessionId: 10 },
    persona: { id: 1000000003, role: 'merchant' },
    personaSession: { sessionId: '33333333-3333-4333-8333-333333333333', authorityVersion: '1' },
    jti: '55555555-5555-4555-8555-555555555555',
  };
  const original = { launch: 'original launch capability', authorization: 'Bearer re-signed token',
    verifiedAuthority: structuredClone(expected) };
  const physical = { headers: () => ({ 'x-dvaia-secureshop-launch': original.launch,
    authorization: original.authorization }) };
  assert.doesNotThrow(() => assertReviewRequestAuthority(original, physical, expected));
  for (const mutate of [
    value => { value.verifiedAuthority = null; },
    value => { value.verifiedAuthority.scope.launchId = '44444444-4444-4444-8444-444444444444'; },
    value => { value.verifiedAuthority.scope.scenarioId = '44444444-4444-4444-8444-444444444444'; },
    value => { value.verifiedAuthority.scope.generation += 1; },
    value => { value.verifiedAuthority.scope.platformOwnerId += 1; },
    value => { value.verifiedAuthority.scope.platformSessionId += 1; },
    value => { value.verifiedAuthority.persona.id += 1; },
    value => { value.verifiedAuthority.persona.role = 'admin'; },
    value => { value.verifiedAuthority.personaSession.sessionId = '44444444-4444-4444-8444-444444444444'; },
    value => { value.verifiedAuthority.personaSession.authorityVersion = '2'; },
    value => { value.verifiedAuthority.jti = '44444444-4444-4444-8444-444444444444'; },
    value => { value.authorityCaptureFailure = { name: 'Error', code: 'SHOP_AUTH_INVALID' }; },
  ]) {
    const changed = structuredClone(original); mutate(changed);
    assert.throws(() => assertReviewRequestAuthority(changed, physical, expected));
  }
  const foreignHeaders = { headers: () => ({ 'x-dvaia-secureshop-launch': original.launch,
    authorization: 'Bearer private foreign token' }) };
  assert.throws(() => assertReviewRequestAuthority(original, foreignHeaders, expected), error =>
    !error.message.includes('private foreign token') && !error.message.includes('re-signed token'));
});

test('V17 private receipt accepts only the closed physical and configured-Judge proof shape', () => {
  assert.doesNotThrow(() => assertReviewInjectionReceipt(receipt()));
  for (const mutate of [
    value => { value.physicalOriginalSubmission = false; },
    value => { value.configuredJudgeCredit = false; },
    value => { value.actorCalls = 0; },
    value => { value.judgeCalls = 0; },
    value => { value.genuineCredit = 0; },
    value => { value.unreviewedClaim = true; },
  ]) {
    const candidate = receipt(); mutate(candidate);
    assert.throws(() => assertReviewInjectionReceipt(candidate));
  }
});

test('V17 inverse selector admits only the existing case and binds its receipt without changing the original default',()=>{
  const {SOURCES}=require('./fixtures/secureshopReviewInjectionQualification');
  assert.equal(reviewInjectionSourceCase(),'approve_advertisement');
  for(const name of Object.keys(SOURCES))assert.equal(reviewInjectionSourceCase(name),name);
  for(const value of ['reject','approve','__proto__','unknown','',null,1,true])assert.throws(()=>reviewInjectionSourceCase(value));
  const inverse={...receipt(),sourceCase:'reject_product_feedback'};
  assert.doesNotThrow(()=>assertReviewInjectionReceipt(inverse,'reject_product_feedback'));
  assert.throws(()=>assertReviewInjectionReceipt(inverse));
  assert.throws(()=>assertReviewInjectionReceipt(receipt(),'reject_product_feedback'));
  assert.throws(()=>assertReviewInjectionReceipt({...inverse,sourceCase:'approve_advertisement'},'reject_product_feedback'));
  for(const flag of REVIEW_INJECTION_FLAGS)assert.throws(()=>assertReviewInjectionReceipt({...inverse,[flag]:false},'reject_product_feedback'));
  const inverseSource=SOURCES.reject_product_feedback;
  assert.equal(inverseSource.attackDecision,'reject');assert.equal(inverseSource.policyDecision,'approve');
  assert.equal(require('../server/services/secureshopBoundReviewTools').projectReviewForMode({id:1,
    body:inverseSource.body,rating:inverseSource.rating},'fixed').policy_decision,'approve');
});

test('long installed Locator.fill bypasses controlled React state; V17 uses keyboard input before rating', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const body = require('./fixtures/secureshopReviewInjectionQualification').SOURCES.approve_advertisement.body;
  const locator = fs.readFileSync(path.join(__dirname,
    '../node_modules/puppeteer-core/lib/puppeteer/api/locators/locators.js'), 'utf8');
  assert.match(locator, /typingThreshold = options\?\.typingThreshold \?\? 100/);
  assert.ok(body.length >= 100);
  assert.match(locator, /element\.value = valString/);
  const caller = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const submit = caller.slice(caller.indexOf('const submitPhysical = async label =>'),
    caller.indexOf('capture.reviewFormDiagnostic'));
  assert.ok(submit.includes('await reviewInput.type(sample.body)'));
  assert.equal(submit.includes('.fill(sample.body)'), false);
  assert.ok(submit.indexOf('await reviewInput.type(sample.body)') < submit.indexOf('aria-label="1 star"'));

  // Controlled DOM reproduction only: no browser, model, effect, or credit.
  const { JSDOM } = require('../client/node_modules/jsdom');
  const dom = new JSDOM('<div id="root"></div>');
  const values = { window: dom.window, document: dom.window.document,
    navigator: dom.window.navigator, Event: dom.window.Event, IS_REACT_ACT_ENVIRONMENT: true };
  const prior = Object.fromEntries(Object.keys(values).map(key =>
    [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  for (const [key, value] of Object.entries(values))
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  const React = require('../client/node_modules/react');
  const { createRoot } = require('../client/node_modules/react-dom/client');
  let root;
  try {
    function ControlledReview() {
      const [text, setText] = React.useState('');
      const [rating, setRating] = React.useState(5);
      return React.createElement('form', {},
        React.createElement('textarea', { value: text, onChange: e => setText(e.target.value) }),
        React.createElement('button', { type: 'button', onClick: () => setRating(1) }, String(rating)),
        React.createElement('button', { type: 'submit', disabled: !text.trim() }, 'Post review'));
    }
    root = createRoot(document.querySelector('#root'));
    await React.act(async () => root.render(React.createElement(ControlledReview)));
    const input = document.querySelector('textarea');
    await React.act(async () => {
      input.value = body;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    assert.equal(input.value, body);
    assert.equal(document.querySelector('[type="submit"]').disabled, true);
    await React.act(async () => document.querySelector('[type="button"]').click());
    assert.equal(input.value, '', 'rating rerender restores unchanged React body state');
  } finally {
    if (root) await React.act(async () => root.unmount());
    dom.window.close();
    for (const [key, descriptor] of Object.entries(prior)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
});
