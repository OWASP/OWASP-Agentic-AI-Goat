'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const paths = {
  checkout: 'client/src/pages/secureshop/pages/Checkout.jsx',
  lane: 'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  cartCard: 'client/src/pages/secureshop/components/CustomerCartConfirmation.jsx',
  checkoutCard: 'client/src/pages/secureshop/components/CustomerCheckoutCard.jsx',
  gateway: 'server/routes/secureshop/boundGateway.js',
  repository: 'server/database/postgres/secureshopConversationalCommerceRepository.js',
};
const source = Object.fromEntries(Object.entries(paths).map(([key, value]) =>
  [key, fs.readFileSync(path.join(root, value), 'utf8')]));
const parse = value => parser.parse(value, { sourceType: 'unambiguous', plugins: ['jsx'] });

function find(node, predicate) {
  const result = [];
  function walk(value) {
    if (!value || typeof value !== 'object') return;
    if (predicate(value)) result.push(value);
    for (const [key, child] of Object.entries(value)) {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'extra'].includes(key)) continue;
      if (Array.isArray(child)) child.forEach(walk);
      else if (child && typeof child === 'object') walk(child);
    }
  }
  walk(node);
  return result;
}
const one = (matches, name) => { assert.equal(matches.length, 1, name); return matches[0]; };
const member = value => value?.type === 'Identifier' ? value.name
  : ['MemberExpression', 'OptionalMemberExpression'].includes(value?.type) && !value.computed
    ? `${member(value.object)}.${value.property.name}` : null;
const string = (value, expected) => value?.type === 'StringLiteral' && value.value === expected;
const property = (value, key) => value?.type === 'ObjectExpression'
  ? value.properties.find(item => item.type === 'ObjectProperty' && item.key?.name === key)?.value : null;
const keys = value => value?.type === 'ObjectExpression'
  ? value.properties.map(item => item.key?.name).sort() : null;
const calls = (node, name) => find(node, item => item.type === 'CallExpression'
  && member(item.callee) === name);
const functionNamed = (node, name) => one(find(node, item => item.type === 'FunctionDeclaration'
  && item.id?.name === name), name);
const variable = (node, name) => one(find(node, item => item.type === 'VariableDeclarator'
  && item.id?.name === name), name).init;
const opening = (node, name) => one(find(node, item => item.type === 'JSXOpeningElement'
  && item.name?.name === name), `mount ${name}`);
const attribute = (node, name) => node.attributes.find(item => item.type === 'JSXAttribute'
  && item.name.name === name)?.value?.expression;
const button = (node, label) => one(find(node, item => item.type === 'JSXElement'
  && ['button', 'Button'].includes(item.openingElement?.name?.name)
  && item.children.some(child => child.type === 'JSXText' && child.value.trim() === label)), label);
const contains = (outer, inner) => outer.start <= inner.start && inner.end <= outer.end;
const awaited = (outer, inner) => find(outer, item => item.type === 'AwaitExpression'
  && item.argument === inner).length === 1;
const request = (node, caller, url, method) => one(calls(node, caller).filter(item =>
  string(item.arguments[0], url) && string(property(item.arguments[1], 'method'), method)),
`request ${url}`);

function checkChatCard(ast, componentName, confirmLabel, recoveryLabel, endpoint,
  referenceSave, referenceRead) {
  const component = functionNamed(ast, componentName);
  const run = variable(component, 'run');
  const confirm = button(component, confirmLabel);
  const recovery = button(component, recoveryLabel);
  const confirmHandler = attribute(confirm.openingElement, 'onClick');
  const recoveryHandler = attribute(recovery.openingElement, 'onClick');
  assert.equal(member(confirmHandler.body.argument?.callee), 'run');
  assert.equal(confirmHandler.body.argument.arguments[0]?.value, true);
  assert.equal(member(recoveryHandler.body.argument?.callee), 'run');
  assert.equal(recoveryHandler.body.argument.arguments[0]?.value, false);
  const recoveryBranch = one(find(run, item => item.type === 'IfStatement'
    && item.test?.name === 'saved' && calls(item.consequent, 'readExact').length),
  `${componentName} saved recovery branch`);
  assert(find(recoveryBranch.consequent, item => item.type === 'ReturnStatement').length);
  assert.equal(calls(recoveryBranch.consequent, 'transport').length, 0,
    'saved reference never repeats a POST');
  const preflight = one(calls(run, 'transport').filter(item => item.arguments[0]?.type === 'TemplateLiteral'
    && item.arguments[0].quasis[0].value.cooked === '/api/secureshop/customer/commerce/operations/'
    && member(item.arguments[0].expressions[0]) === 'proposal.proposalId'
    && string(property(item.arguments[1], 'method'), 'GET')), 'proposal preflight');
  assert(find(run, item => item.type === 'IfStatement'
    && find(item.test, child => member(child) === 'proposal.quoteSha256').length
    && find(item.consequent, child => child.type === 'ThrowStatement').length
    && preflight.start < item.start).length, 'quote digest mismatch rejects confirmation');
  const save = one(calls(run, referenceSave), 'saved reference');
  assert(awaited(run, save), 'parent reference write is awaited');
  const reread = variable(run, 'acknowledged');
  assert.equal(member(reread.callee), referenceRead);
  const post = request(run, 'transport', endpoint, 'POST');
  assert.equal(member(property(post.arguments[1], 'body')?.callee), 'JSON.stringify');
  assert.deepEqual(keys(property(post.arguments[1], 'body').arguments[0]), ['proposalId']);
  assert.equal(member(property(post.arguments[1], 'body').arguments[0].properties[0].value),
    componentName === 'CustomerCartConfirmation' ? 'saved.operationId' : 'proposal.proposalId');
  assert(preflight.start < save.start && save.start < reread.start && reread.start < post.start,
    'preflight, save, acknowledge, then one POST');
  assert(awaited(run, post), 'confirmation POST is awaited');
  const readExact = variable(component, 'readExact');
  assert.equal(calls(readExact, 'transport').filter(item => item.arguments[0]?.type === 'TemplateLiteral'
    && item.arguments[0].quasis[0].value.cooked === '/api/secureshop/customer/commerce/operations/'
    && member(item.arguments[0].expressions[0]) === 'saved.operationId'
    && string(property(item.arguments[1], 'method'), 'GET')).length, 1);
  assert(calls(run, 'readExact').some(item => item.start > post.end && awaited(run, item)),
    'POST outcome uses awaited exact readback');
  assert(find(run, item => item.type === 'IfStatement'
    && find(item.test, child => child.type === 'UnaryExpression'
      && child.argument?.name === 'confirm').length && find(item.consequent,
      child => child.type === 'ReturnStatement').length).length,
  'non-confirm invocation exits before any new proposal dispatch');
}

function validate(parts = source) {
  const checkout = parse(parts.checkout), lane = parse(parts.lane);
  const cartCard = parse(parts.cartCard), checkoutCard = parse(parts.checkoutCard);
  const gateway = parse(parts.gateway), repository = parse(parts.repository);
  const checkoutComponent = functionNamed(checkout, 'Checkout');
  const stepReview = functionNamed(checkout, 'StepReview');
  const manualMount = one(find(checkoutComponent, item => item.type === 'JSXOpeningElement'
    && item.name?.name === 'StepReview'), 'mounted StepReview');
  assert.equal(member(attribute(manualMount, 'onPlace')), 'placeOrder');
  const manualButton = one(find(stepReview, item => item.type === 'JSXElement'
    && item.openingElement?.name?.name === 'Button'
    && member(attribute(item.openingElement, 'onClick')) === 'onPlace'), 'manual action Button');
  assert.equal(member(attribute(manualButton.openingElement, 'onClick')), 'onPlace');
  assert(find(manualButton, item => item.type === 'ConditionalExpression'
    && item.test?.name === 'proposal'
    && string(item.consequent, 'Confirm exact quote')).length,
  'same rendered action changes label after a quote');
  assert(find(attribute(manualButton.openingElement, 'disabled'), item =>
    item.type === 'UnaryExpression' && item.argument?.name === 'confirmEligible').length,
  'quote confirmation requires eligibility');
  const placeOrder = variable(checkoutComponent, 'placeOrder');
  const placeBound = variable(checkoutComponent, 'placeBoundOrder');
  assert(find(placeOrder, item => item.type === 'IfStatement' && item.test?.name === 'bound'
    && calls(item.consequent, 'placeBoundOrder').some(call => awaited(item.consequent, call))).length,
  'bound click dispatches to bound checkout handler');
  const prepare = request(placeBound, 'requestFetch', '/api/secureshop/customer/commerce/checkout/prepare', 'POST');
  assert.deepEqual(keys(property(prepare.arguments[1], 'body')?.arguments[0]),
    ['addressChoiceId', 'operationId', 'paymentChoiceId']);
  const saveManual = one(calls(placeBound, 'saveCheckoutReference'), 'manual saved quote');
  assert(awaited(placeBound, saveManual));
  assert(prepare.start < saveManual.start && saveManual.start < one(calls(placeBound,
    'setConfirmEligible').filter(item => item.arguments[0]?.value === true),
  'eligible prepared quote').start);
  const manualPost = request(placeBound, 'requestFetch',
    '/api/secureshop/customer/commerce/checkout/confirm', 'POST');
  assert.deepEqual(keys(property(manualPost.arguments[1], 'body')?.arguments[0]), ['proposalId']);
  assert.equal(member(property(manualPost.arguments[1], 'body').arguments[0].properties[0].value),
    'reference.operationId');
  assert(find(placeBound, item => item.type === 'IfStatement' && item.test?.type === 'UnaryExpression'
    && item.test.argument?.name === 'confirmEligible'
    && find(item.consequent, child => child.type === 'ThrowStatement').length
    && item.start < manualPost.start).length, 'second click eligibility gate');
  assert(calls(placeBound, 'readBoundOperation').some(item => item.start < manualPost.start
    && awaited(placeBound, item)), 'saved operation read before manual confirm');
  assert(calls(placeBound, 'readCheckoutReference').some(item => item.start < manualPost.start),
  'saved reference acknowledged before manual confirm');
  assert(calls(placeBound, 'placeBoundOrder').some(item => item.start > manualPost.end
    && item.arguments[0]?.type === 'ObjectExpression'
    && property(item.arguments[0], 'confirmedHere')?.value === true),
  'manual confirmation re-enters the saved-operation read path after response');

  const laneComponent = functionNamed(lane, 'GeneralHelpTask');
  const operations = variable(laneComponent, 'currentOperations');
  assert(find(operations, item => item.type === 'BinaryExpression' && item.operator === '==='
    && member(item.left) === 'latestTurn.status' && string(item.right, 'done')).length);
  assert(find(operations, item => item.type === 'BinaryExpression' && item.operator === '==='
    && member(item.left) === 'latestTurn.stopReason' && string(item.right, 'end_turn')).length);
  assert(calls(operations, 'trustedTurnMode').length === 1);
  for (const [name, prop] of [['CustomerCartConfirmation', 'cartProposal'],
    ['CustomerCheckoutCard', 'checkoutProposal']]) {
    const mount = opening(laneComponent, name);
    assert.equal(member(attribute(mount, 'proposal')), prop);
    assert(calls(variable(laneComponent, prop), 'currentOperations.find').length === 1,
      `${prop} is derived from guarded saved operations`);
  }
  checkChatCard(cartCard, 'CustomerCartConfirmation', 'Confirm cart change',
    'Check saved cart change', '/api/secureshop/customer/commerce/cart/confirm',
    'saveChatCartReference', 'readChatCartReference');
  checkChatCard(checkoutCard, 'CustomerCheckoutCard', 'Confirm this practice order',
    'Check saved checkout', '/api/secureshop/customer/commerce/checkout/confirm',
    'saveCheckoutReference', 'readCheckoutReference');

  const gatewayLoop = one(find(gateway, item => item.type === 'ForOfStatement'
    && item.right?.type === 'ArrayExpression'
    && item.right.elements.some(tuple => tuple.type === 'ArrayExpression'
      && string(tuple.elements[0], 'prepareCheckout'))), 'closed commerce route loop');
  for (const [method, url, verb, bodyKeys, effects] of [
    ['prepareCheckout', '/customer/commerce/checkout/prepare', 'post',
      ['operationId', 'addressChoiceId', 'paymentChoiceId'], ['quote', 'insert']],
    ['confirmCheckout', '/customer/commerce/checkout/confirm', 'post', ['proposalId'],
      ['quote', 'checkoutWithClient', 'complete']],
    ['confirmCart', '/customer/commerce/cart/confirm', 'post', ['proposalId'],
      ['cartIntentSnapshot', 'addCartWithClient', 'updateCartWithClient', 'removeCartWithClient', 'complete']],
    ['readOperation', '/customer/commerce/operations/:operationId', 'get', [], ['transaction']],
  ]) {
    const tuple = one(gatewayLoop.right.elements.filter(item => item.type === 'ArrayExpression'
      && item.elements.length === 4 && string(item.elements[0], method)
      && string(item.elements[1], url) && string(item.elements[2], verb)), `gateway ${method}`);
    assert.deepEqual(tuple.elements[3].elements.map(item => item.value), bodyKeys);
    const repoMethod = one(find(repository, item => item.type === 'ObjectMethod'
      && item.key?.name === method), `repository ${method}`);
    for (const effect of effects)
      assert(calls(repoMethod, effect).length >= 1, `${method} consequence ${effect}`);
    assert(calls(repoMethod, 'transaction').length === 1, `${method} effect is in transaction`);
    if (method !== 'readOperation') assert(calls(repoMethod, 'prior').length === 1);
    if (method === 'confirmCheckout')
      assert(find(repoMethod, item => item.type === 'IfStatement'
        && find(item.test, child => member(child) === 'original.payment.snapshot.scenario').length
        && calls(item.consequent, 'checkoutWithClient').length === 1).length,
      'order effect is conditional on approved synthetic payment');
  }
}

test('checkout/cart source review accounts for three new bindings without qualification', () => {
  const evidence = manifest.commerceUiEvidence;
  const reviewed = [...evidence.reviewedProfileBindings, ...evidence.reviewedCheckoutCartBindings,
    ...evidence.reviewedAddressPaymentBindings]
    .map(item => item.actionId);
  assert.deepEqual(evidence.reviewedCheckoutCartBindings.map(item => item.actionId), [
    'customer.commerce.checkout.prepare', 'customer.commerce.checkout.confirm',
    'customer.commerce.cart.confirm']);
  assert.equal(manifest.commerceBindings.length, 12);
  assert.deepEqual([...evidence.remainingUnresolvedActionIds].sort(), manifest.commerceBindings
    .map(item => item.actionId).filter(id => !reviewed.includes(id)).sort());
  assert(evidence.remainingUnresolvedActionIds.includes('customer.commerce.operation'));
  assert.equal(evidence.sourceEvidence, 'endpoint_reference_only');
  assert.equal(evidence.eventToRequestRelation, 'unresolved');
  assert.equal(evidence.physicalUiVerified, false);
  assert.equal(evidence.runtimeEffectVerified, false);
  assert.equal(evidence.q08Qualification, 'deferred_unverified');
  for (const id of evidence.reviewedCheckoutCartBindings.map(item => item.actionId)) {
    const row = manifest.commerceBindings.find(item => item.actionId === id);
    assert(row && !row.confirmation.physicalUiVerified && !row.recovery.nativeVerified);
    assert.equal(row.runtimeEvidence, null);
    assert.match(row.q08Applicability, /scoring_unresolved/);
  }
  validate();
});

test('selected AST paths reject mismatched buttons, gates, requests, recovery and effects', () => {
  const cases = [
    ['manual click disconnected', 'checkout', 'onPlace={placeOrder}', 'onPlace={prevStep}'],
    ['manual eligibility bypass', 'checkout', 'if (!confirmEligible) {', 'if (confirmEligible) {'],
    ['manual prepare endpoint changed', 'checkout',
      "requestFetch('/api/secureshop/customer/commerce/checkout/prepare'",
      "requestFetch('/api/secureshop/customer/commerce/checkout/other'"],
    ['manual confirm ID changed', 'checkout', 'JSON.stringify({ proposalId: reference.operationId })',
      'JSON.stringify({ proposalId: operationId })'],
    ['manual reference no longer awaited', 'checkout',
      'await saveCheckoutReference(reference);', 'void saveCheckoutReference(reference);'],
    ['trusted turn check removed', 'lane', 'trustedTurnMode(latestTurn.modeCapability) ? (latestTurn.operations || [])',
      '(latestTurn.operations || [])'],
    ['chat cart mount disconnected', 'lane', '<CustomerCartConfirmation proposal={cartProposal}',
      '<CustomerCartConfirmation proposal={checkoutProposal}'],
    ['chat checkout recovery becomes confirmation', 'checkoutCard',
      'onClick={() => void run(false)}>Check saved checkout',
      'onClick={() => void run(true)}>Check saved checkout'],
    ['chat cart reference not awaited', 'cartCard', 'await saveChatCartReference(saved);',
      'void saveChatCartReference(saved);'],
    ['chat cart readback removed', 'cartCard',
      'const outcome = await readExact(saved, controller.signal);',
      'const outcome = { status: "completed" };'],
    ['chat cart post path swapped', 'cartCard',
      "transport('/api/secureshop/customer/commerce/cart/confirm'",
      "transport('/api/secureshop/customer/commerce/checkout/confirm'"],
    ['gateway confirm method changed', 'gateway',
      "['confirmCheckout','/customer/commerce/checkout/confirm','post'",
      "['confirmCheckout','/customer/commerce/checkout/confirm','get'"],
    ['repository cart effect disconnected', 'repository',
      'removeCartWithClient(client,value,a.owner,databaseId(selected.cart_item_id))',
      'removeOtherCartWithClient(client,value,a.owner,databaseId(selected.cart_item_id))'],
  ];
  for (const [name, part, before, after] of cases) {
    assert(source[part].includes(before), `${name}: source mutation anchor`);
    const changed = { ...source, [part]: source[part].replace(before, after) };
    assert.throws(() => validate(changed), undefined, name);
  }
});
