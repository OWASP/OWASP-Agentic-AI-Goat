'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const ids = ['catalog.product.reviews.create', 'catalog.product.reviews.browserAttempt'];

function source(file) {
  const absolute = path.resolve(root, file);
  assert(absolute.startsWith(root + path.sep));
  assert.equal(fs.realpathSync(absolute), absolute);
  return fs.readFileSync(absolute, 'utf8');
}
function parse(code) { return parser.parse(code, { sourceType: 'unambiguous', plugins: ['jsx'] }); }
function nodes(node, predicate) {
  const found = [];
  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (predicate(value)) found.push(value);
    for (const [key, child] of Object.entries(value)) {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'innerComments', 'extra'].includes(key)) continue;
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object') visit(child);
    }
  }
  visit(node);
  return found;
}
function name(node) {
  if (!node) return null;
  if (node.type === 'Identifier' || node.type === 'JSXIdentifier') return node.name;
  if (['MemberExpression', 'OptionalMemberExpression'].includes(node.type) && !node.computed) {
    return `${name(node.object)}.${name(node.property)}`;
  }
  return null;
}
const calls = (node, called) => nodes(node, value => value.type === 'CallExpression' && name(value.callee) === called);
function local(node, identifier) {
  const found = nodes(node, value => value.type === 'VariableDeclarator' && name(value.id) === identifier);
  assert.equal(found.length, 1, `exact local ${identifier}`);
  return found[0].init;
}
function property(object, key) {
  assert.equal(object?.type, 'ObjectExpression');
  const found = object.properties.filter(value => value.type === 'ObjectProperty' && name(value.key) === key);
  assert.equal(found.length, 1, `exact property ${key}`);
  return found[0].value;
}
function routeCall(ast, verb, route) {
  const found = calls(ast, `router.${verb}`).filter(value => value.arguments[0]?.value === route);
  assert.equal(found.length, 1, `${verb.toUpperCase()} ${route}`);
  return found[0];
}
function verify(overrides = {}) {
  const bindings = manifest.productReviewCreateBindings;
  assert.deepEqual(bindings.map(row => row.actionId), ids);
  for (const binding of bindings) {
    const action = manifest.actions.find(row => row.id === binding.actionId);
    assert.equal(action?.review, binding.actionId);
    assert.equal(binding.runtimeEvidence, null);
    assert.equal(binding.confirmation.physicalUiVerified, false);
    assert.equal(binding.confirmation.denialNoEffectVerified, false);
    assert.equal(binding.recovery.nativeVerified, false);
    assert.deepEqual(binding.linkedObjectiveIds, []);
    assert.deepEqual(binding.evidenceAdapters, []);
  }
  assert.equal(manifest.qualification.Q05, 'deferred_unverified');
  assert.equal(manifest.qualification.Q08, 'deferred_unverified');
  assert.equal(manifest.scope.supportedActionDenominatorComplete, false);
  assert.equal(manifest.scope.globalDenominatorComplete, false);

  const submit = bindings[0];
  const browser = bindings[1];
  const read = (binding, key) => overrides[key] ?? source(binding.sourceBinding[key]);
  const uiText = read(submit, 'uiFile');
  const ui = parse(uiText);
  const product = nodes(ui, value => value.type === 'FunctionDeclaration' && name(value.id) === 'Product');
  assert.equal(product.length, 1);
  const submitReview = local(product[0], 'submitReview');
  assert.match(uiText, /if \(!reviewBody\.trim\(\) \|\| reviewAction\.current\.inFlight \|\| browserAction\.current\.inFlight\) return;/,
    'submission remains gated before request preparation');
  assert.equal(calls(submitReview, 'reviewRequests.current.prepare').filter(call => call.arguments[0]?.value === 'submission').length, 1);
  const reviewFetch = calls(submitReview, 'reviewRequests.current.fetch').filter(call =>
    call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products//reviews'
    && nodes(call.arguments[1], value => value.type === 'ObjectProperty' && name(value.key) === 'method'
      && value.value?.value === 'POST').length === 1);
  assert.equal(reviewFetch.length, 1, 'exact customer review POST');
  const payload = local(submitReview, 'payload');
  assert.deepEqual(payload.properties.map(value => name(value.key)), ['author_id', 'body', 'rating']);
  assert.equal(calls(submitReview, 'reviewRequests.current.complete').filter(call => call.arguments[0]?.value === 'submission').length, 1);
  assert.equal(calls(submitReview, 'loadReviews').length, 2,
    'pending browser retry and accepted submission each reload the exact review list');
  const reviewForm = nodes(product[0], value => value.type === 'JSXElement'
    && name(value.openingElement?.name) === 'form'
    && nodes(value.openingElement, child => child.type === 'JSXAttribute' && name(child.name) === 'onSubmit'
      && name(child.value?.expression) === 'submitReview').length === 1);
  assert.equal(reviewForm.length, 1);
  assert.equal(nodes(reviewForm[0], value => value.type === 'JSXText' && value.value.trim() === 'Post review').length, 1,
    'the existing explicit action is the source-level disclosure');

  const helperText = read(submit, 'requestHelperFile');
  const helper = parse(helperText);
  assert.equal(nodes(helper, value => value.type === 'ObjectProperty' && name(value.key) === 'submission'
    && value.value?.value === 'submission_id').length, 1);
  assert.equal(nodes(helper, value => value.type === 'ObjectProperty' && name(value.key) === 'browser'
    && value.value?.value === 'request_id').length, 1);
  assert.equal(calls(helper, 'getBridgeFetchMetadata').length, 1, 'bound request IDs require acknowledged bridge metadata');
  assert.equal(nodes(helper, value => value.type === 'CallExpression' && name(value.callee) === 'pending.clear').length, 1,
    'scope invalidation retires retained request identities');

  const pending = local(product[0], 'pendingReviewIsRendered');
  assert.equal(calls(pending, 'reviews.some').length, 1);
  assert.equal(calls(submitReview, 'reviewRequests.current.prepare').filter(call => call.arguments[0]?.value === 'browser').length, 1,
    'browser continuation receives an identity only after accepted submission');
  const browserEffect = calls(product[0], 'useEffect').find(effect => calls(effect, 'reviewRequests.current.fetch').some(call =>
    call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products//reviews//browser-attempt'));
  assert.ok(browserEffect, 'one mounted effect dispatches the retained browser attempt');
  assert.equal(calls(browserEffect, 'reviewRequests.current.fetch').filter(call =>
    call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products//reviews//browser-attempt'
    && nodes(call.arguments[1], value => value.type === 'ObjectProperty' && name(value.key) === 'method'
      && value.value?.value === 'POST').length === 1).length, 1);
  assert.equal(calls(browserEffect, 'reviewRequests.current.complete').filter(call => call.arguments[0]?.value === 'browser').length, 1);
  assert.equal(calls(browserEffect, 'controller.signal.throwIfAborted').length, 0,
    'the source record describes existing generation/abort fencing without inventing another contract');
  assert.match(uiText, /controller\.signal\.aborted \|\| browserAction\.current\.generation !== generation/,
    'late browser outcomes remain fenced');

  const registered = parse(read(submit, 'bridgeFile'));
  for (const id of ids) assert.equal(nodes(registered, value => value.type === 'ObjectProperty' && value.key?.value === id).length, 1);
  const reviews = parse(read(submit, 'reviewRouteFile'));
  const submitRoute = routeCall(reviews, 'post', '/products/:id/reviews');
  assert.equal(calls(submitRoute, 'service.submitReview').length, 1);
  assert.equal(nodes(submitRoute, value => value.type === 'CallExpression' && name(value.callee) === 'exactObject'
    && value.arguments[1]?.type === 'ArrayExpression'
    && value.arguments[1].elements.map(item => item.value).join(',') === 'submission_id,author_id,body,rating').length, 1);
  const browserRoute = routeCall(parse(read(browser, 'browserRouteFile')), 'post',
    '/products/:productId/reviews/:reviewId/browser-attempt');
  assert.equal(calls(browserRoute, 'assessment.runAttempt').length, 1);
  assert.equal(nodes(browserRoute, value => value.type === 'CallExpression' && name(value.callee) === 'plainExact'
    && value.arguments[1]?.type === 'ArrayExpression' && value.arguments[1].elements[0]?.value === 'request_id').length, 1);
  const composition = parse(read(submit, 'compositionFile'));
  assert.equal(calls(composition, 'createBoundBrowserRouter').length, 1);
  const application = parse(read(submit, 'applicationFile'));
  assert.equal(nodes(application, value => value.type === 'ObjectProperty' && name(value.key) === 'reviewsRouter'
    && name(value.value) === 'composition.router').length, 1);
  assert.equal(nodes(application, value => value.type === 'ObjectProperty' && name(value.key) === 'browserRouter'
    && name(value.value) === 'composition.browserRouter').length, 1);
  const gateway = parse(read(submit, 'gatewayFile'));
  assert.equal(calls(gateway, 'router.use').filter(call => name(call.arguments[0]) === 'reviewsRouter').length, 1);
  assert.equal(calls(gateway, 'router.use').filter(call => name(call.arguments[0]) === 'browserRouter').length, 1);
}

test('Product review submit and its rendered browser-attempt continuation are source-linked without qualification claims', async () => {
  verify();
  const { describeOperations, matchOperationRequest } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const registered = describeOperations().operations.filter(row => ids.includes(row.name));
  assert.deepEqual(registered.map(row => [row.name, row.method, row.pathTemplate, row.body]), [
    ['catalog.product.reviews.create', 'POST', '/api/secureshop/products/:id/reviews', ['submission_id', 'author_id', 'body', 'rating']],
    ['catalog.product.reviews.browserAttempt', 'POST', '/api/secureshop/products/:productId/reviews/:reviewId/browser-attempt', ['request_id']],
  ]);
  assert.deepEqual([
    matchOperationRequest({ pathname: '/api/secureshop/products/7/reviews', method: 'POST', body: { submission_id: '11111111-1111-4111-8111-111111111111', author_id: 41, body: 'review', rating: 5 } }),
    matchOperationRequest({ pathname: '/api/secureshop/products/7/reviews/9/browser-attempt', method: 'POST', body: { request_id: '22222222-2222-4222-8222-222222222222' } }),
  ].map(row => row.name), ids);
});

test('changed submit intent, request identity, endpoint, route effect, or browser assessment cannot inherit source review', () => {
  const submit = manifest.productReviewCreateBindings[0].sourceBinding;
  const browser = manifest.productReviewCreateBindings[1].sourceBinding;
  const ui = source(submit.uiFile);
  const helper = source(submit.requestHelperFile);
  const reviews = source(submit.reviewRouteFile);
  const browserRoute = source(browser.browserRouteFile);
  const wrongUi = ui.replace('Post review', 'Save review');
  const wrongPrepare = ui.replace("prepare('submission'", "prepare('browser'");
  const wrongHelper = helper.replace("submission: 'submission_id'", "submission: 'request_id'");
  const wrongRoute = reviews.replace('service.submitReview({', 'service.listProductReviews({');
  const wrongBrowser = browserRoute.replace('assessment.runAttempt({', 'assessment.readAttempt({');
  for (const [key, value] of Object.entries({ uiFile: wrongUi })) {
    assert.notEqual(value, source(submit[key]));
    assert.throws(() => verify({ [key]: value }), key);
  }
  for (const [key, value] of Object.entries({ requestHelperFile: wrongHelper, reviewRouteFile: wrongRoute, browserRouteFile: wrongBrowser })) {
    const binding = key === 'browserRouteFile' ? browser : submit;
    assert.notEqual(value, source(binding[key]));
    assert.throws(() => verify({ [key]: value }), key);
  }
  assert.notEqual(wrongPrepare, ui);
  assert.throws(() => verify({ uiFile: wrongPrepare }), 'submission cannot become browser preparation');
});
