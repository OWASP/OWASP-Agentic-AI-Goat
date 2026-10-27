'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const ids = ['cart.get', 'cart.applyCoupon', 'orders.summary', 'orders.list', 'orders.get'];

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
  if (['MemberExpression', 'OptionalMemberExpression'].includes(node.type) && !node.computed) return `${name(node.object)}.${name(node.property)}`;
  return null;
}
const calls = (node, called) => nodes(node, value => value.type === 'CallExpression' && name(value.callee) === called);
function local(node, identifier) {
  const found = nodes(node, value => value.type === 'VariableDeclarator' && name(value.id) === identifier);
  assert.equal(found.length, 1, `exact local ${identifier}`);
  return found[0].init;
}
function routeCall(ast, verb, route) {
  const found = calls(ast, `router.${verb}`).filter(value => value.arguments[0]?.value === route);
  assert.equal(found.length, 1, `${verb.toUpperCase()} ${route}`);
  return found[0];
}

function verify(overrides = {}) {
  const bindings = manifest.customerPurchaseReadBindings;
  assert.deepEqual(bindings.map(row => row.actionId), ids);
  const read = (binding, key) => overrides[key] ?? source(binding.sourceBinding[key]);
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
  assert.match(bindings[1].consequence, /may persist or change/);
  assert.match(bindings[2].consequence, /does not classify the POST as side-effect-free/);
  assert.equal(manifest.qualification.Q05, 'deferred_unverified');
  assert.equal(manifest.qualification.Q08, 'deferred_unverified');
  assert.equal(manifest.scope.supportedActionDenominatorComplete, false);
  assert.equal(manifest.scope.globalDenominatorComplete, false);

  const cartGet = bindings[0], coupon = bindings[1], summary = bindings[2], orderList = bindings[3], orderGet = bindings[4];
  const context = parse(read(cartGet, 'cartContextFile'));
  const reload = local(context, 'reload');
  assert.equal(calls(reload, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/cart').length, 1);
  assert.equal(calls(reload, 'isCurrent').length >= 2, true, 'cart reload keeps its identity fence');
  const applyCoupon = local(context, 'applyCoupon');
  assert.equal(calls(applyCoupon, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/cart/apply-coupon'
    && nodes(call.arguments[1], value => value.type === 'ObjectProperty' && name(value.key) === 'method'
      && value.value?.value === 'POST').length === 1).length, 1);
  assert.equal(calls(applyCoupon, 'persist').length >= 2, true, 'bound coupon identity is retained before dispatch and cleared only after success');
  assert.match(read(coupon, 'cartContextFile'), /without automatic replay/);
  const cart = parse(read(coupon, 'cartUiFile'));
  const submitCoupon = local(nodes(cart, value => value.type === 'FunctionDeclaration' && name(value.id) === 'Cart')[0], 'submitCoupon');
  assert.equal(calls(submitCoupon, 'applyCoupon').filter(call => call.arguments[0]?.name === 'couponCode').length, 1);
  assert.equal(nodes(cart, value => value.type === 'JSXText' && value.value.trim() === 'Apply').length, 1,
    'existing Apply action is recorded without inventing a modal');

  const checkout = parse(read(summary, 'checkoutUiFile'));
  assert.equal(calls(checkout, 'requestFetch').filter(call => call.arguments[0]?.value === '/api/secureshop/orders/summary'
    && nodes(call.arguments[1], value => value.type === 'ObjectProperty' && name(value.key) === 'method'
      && value.value?.value === 'POST').length === 1).length, 1);
  assert.match(read(summary, 'checkoutUiFile'), /controller\.abort\(\);/);
  const orders = parse(read(orderList, 'ordersUiFile'));
  assert.equal(calls(orders, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/orders').length, 1);
  const openDetail = local(nodes(orders, value => value.type === 'FunctionDeclaration' && name(value.id) === 'Orders')[0], 'openDetail');
  assert.equal(calls(openDetail, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/orders/').length, 1);
  assert.equal(calls(openDetail, 'isCurrent').length >= 2, true, 'detail response remains owner-fenced');

  const bridge = parse(read(cartGet, 'bridgeFile'));
  for (const id of ids) assert.equal(nodes(bridge, value => value.type === 'ObjectProperty' && value.key?.value === id).length, 1);
  const gateway = parse(read(cartGet, 'gatewayFile'));
  for (const [verb, route, effect] of [
    ['get', '/cart', 'commerce.cart'], ['post', '/cart/apply-coupon', 'commerce.applyCoupon'],
    ['post', '/orders/summary', 'commerce.summary'], ['get', '/orders', 'commerce.orders'], ['get', '/orders/:id', 'commerce.order'],
  ]) assert.equal(calls(routeCall(gateway, verb, route), effect).length, 1, `${route} exact customer commerce dispatch`);
}

test('customer cart, coupon, checkout-summary and order reads are source-linked without treating their POSTs as consequence-free', async () => {
  verify();
  const { describeOperations } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  assert.deepEqual(describeOperations().operations.filter(row => ids.includes(row.name)).map(row => [row.name, row.method, row.pathTemplate]), [
    ['cart.get', 'GET', '/api/secureshop/cart'],
    ['cart.applyCoupon', 'POST', '/api/secureshop/cart/apply-coupon'],
    ['orders.summary', 'POST', '/api/secureshop/orders/summary'],
    ['orders.list', 'GET', '/api/secureshop/orders'],
    ['orders.get', 'GET', '/api/secureshop/orders/:id'],
  ]);
});

test('a changed Apply dispatch, coupon operation endpoint, summary method, order detail path, or commerce effect cannot inherit source review', () => {
  const coupon = manifest.customerPurchaseReadBindings[1].sourceBinding;
  const summary = manifest.customerPurchaseReadBindings[2].sourceBinding;
  const order = manifest.customerPurchaseReadBindings[3].sourceBinding;
  const cart = source(coupon.cartUiFile);
  const context = source(coupon.cartContextFile);
  const checkout = source(summary.checkoutUiFile);
  const orders = source(order.ordersUiFile);
  const gateway = source(coupon.gatewayFile);
  const changes = {
    cartUiFile: cart.replace('await applyCoupon(couponCode)', 'await applyCoupon("other")'),
    cartContextFile: context.replace('/cart/apply-coupon', '/cart/apply-other'),
    checkoutUiFile: checkout.replace("method: 'POST'", "method: 'GET'"),
    ordersUiFile: orders.replace('/api/secureshop/orders/${order.id}', '/api/secureshop/orders/other'),
    gatewayFile: gateway.replace('commerce.applyCoupon({...commerceContext(req)', 'commerce.cart({...commerceContext(req)'),
  };
  for (const [key, value] of Object.entries(changes)) {
    const binding = key === 'checkoutUiFile' ? summary : key === 'ordersUiFile' ? order : coupon;
    assert.notEqual(value, source(binding[key]));
    assert.throws(() => verify({ [key]: value }), key);
  }
});
