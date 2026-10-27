'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const paths = {
  account: 'client/src/pages/secureshop/pages/Account.jsx',
  checkout: 'client/src/pages/secureshop/pages/Checkout.jsx',
  lane: 'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  address: 'client/src/pages/secureshop/components/PracticeAddressSetup.jsx',
  payment: 'client/src/pages/secureshop/components/PracticePaymentSetup.jsx',
  gateway: 'server/routes/secureshop/boundGateway.js',
  repository: 'server/database/postgres/secureshopConversationalCommerceRepository.js',
};
const source = Object.fromEntries(Object.entries(paths).map(([key, value]) =>
  [key, fs.readFileSync(path.join(root, value), 'utf8')]));
const parse = text => parser.parse(text, { sourceType: 'unambiguous', plugins: ['jsx'] });
function find(node, predicate) {
  const found = [];
  function walk(value) {
    if (!value || typeof value !== 'object') return;
    if (predicate(value)) found.push(value);
    for (const [key, child] of Object.entries(value)) {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'extra'].includes(key)) continue;
      if (Array.isArray(child)) child.forEach(walk);
      else if (child && typeof child === 'object') walk(child);
    }
  }
  walk(node);
  return found;
}
const one = (values, label) => { assert.equal(values.length, 1, label); return values[0]; };
const member = node => node?.type === 'Identifier' ? node.name
  : ['MemberExpression', 'OptionalMemberExpression'].includes(node?.type) && !node.computed
    ? `${member(node.object)}.${node.property.name}` : null;
const string = (node, value) => node?.type === 'StringLiteral' && node.value === value;
const calls = (node, name) => find(node, value => value.type === 'CallExpression'
  && member(value.callee) === name);
const fn = (node, name) => one(find(node, value => value.type === 'FunctionDeclaration'
  && value.id?.name === name), name);
const variable = (node, name) => one(find(node, value => value.type === 'VariableDeclarator'
  && value.id?.name === name), name).init;
const property = (node, name) => node?.type === 'ObjectExpression'
  ? node.properties.find(value => value.type === 'ObjectProperty' && value.key?.name === name)?.value : null;
const keys = node => node?.type === 'ObjectExpression'
  ? node.properties.map(value => value.key?.name).sort() : null;
const awaited = (node, call) => find(node, value => value.type === 'AwaitExpression'
  && value.argument === call).length === 1;
const request = (node, caller, url, method) => one(calls(node, caller).filter(value =>
  string(value.arguments[0], url) && string(property(value.arguments[1], 'method'), method)),
`request ${url} ${method}`);
const opening = (node, name, entry) => one(find(node, value => value.type === 'JSXOpeningElement'
  && value.name?.name === name && (!entry || value.attributes.some(attribute =>
    attribute.type === 'JSXAttribute' && attribute.name.name === 'entryPoint'
    && attribute.value?.value === entry))), `${name} ${entry || ''}`);
const button = (node, label) => one(find(node, value => value.type === 'JSXElement'
  && value.openingElement?.name?.name === 'button'
  && value.children.some(child => child.type === 'JSXText' && child.value.trim() === label)), label);
const onClick = element => element.openingElement.attributes.find(value =>
  value.type === 'JSXAttribute' && value.name.name === 'onClick')?.value?.expression;

function validate(parts = source) {
  const account = parse(parts.account), checkout = parse(parts.checkout), lane = parse(parts.lane);
  const address = parse(parts.address), payment = parse(parts.payment);
  const gateway = parse(parts.gateway), repository = parse(parts.repository);
  const accountPage = fn(account, 'Account');
  assert(find(accountPage, value => value.type === 'ConditionalExpression'
    && find(value.test, item => item.type === 'BinaryExpression'
      && member(item.left) === 'user.role' && string(item.right, 'customer')).length
    && calls(value.test, 'getBridgeFetchMetadata').length
    && find(value.consequent, item => item.type === 'JSXOpeningElement'
      && item.name?.name === 'BoundAddressesTab').length
    && find(value.alternate, item => item.type === 'JSXOpeningElement'
      && item.name?.name === 'AddressesTab').length).length,
  'bound account branch differs from the unbound address editor');
  const bound = fn(account, 'BoundAddressesTab');
  const refresh = variable(bound, 'refresh');
  const addressGet = request(refresh, 'transport',
    '/api/secureshop/customer/commerce/addresses', 'GET');
  assert(awaited(refresh, addressGet));
  assert(calls(refresh, 'decodeAddressCards').length === 1);
  const accountMount = opening(bound, 'PracticeAddressSetup', 'account');
  assert(accountMount.attributes.some(value => value.name?.name === 'action'
    && member(value.value?.expression) === 'editing.action'));
  assert(accountMount.attributes.some(value => value.name?.name === 'choiceId'
    && member(value.value?.expression) === 'editing.choiceId'));
  const checkoutPage = fn(checkout, 'Checkout');
  const choices = one(calls(checkoutPage, 'Promise.all').filter(value =>
    find(value, item => item.type === 'CallExpression' && member(item.callee) === 'requestFetch'
      && string(item.arguments[0], '/api/secureshop/customer/commerce/addresses')).length
    && find(value, item => item.type === 'CallExpression' && member(item.callee) === 'requestFetch'
      && string(item.arguments[0], '/api/secureshop/customer/commerce/payment-methods')).length),
  'bound checkout address/payment choices');
  assert(find(checkoutPage, value => value.type === 'CallExpression'
    && member(value.callee) === 'useEffect'
    && find(value, item => item === choices).length
    && find(value.arguments[0], item => item.type === 'IfStatement'
      && find(item.test, gate => gate.type === 'UnaryExpression'
        && gate.argument?.name === 'bound').length
      && find(item.test, gate => gate.type === 'BinaryExpression'
        && gate.operator === '!==' && gate.left?.name === 'step'
        && gate.right?.value === 1).length
      && find(item.consequent, gate => gate.type === 'ReturnStatement').length).length).length,
  'choice loading is in bound payment step effect');
  const checkoutAddress = opening(checkoutPage, 'PracticeAddressSetup');
  assert(checkoutAddress.attributes.some(value => value.name?.name === 'entryPoint'
    && value.value?.expression?.type === 'ConditionalExpression'));
  const checkoutPayment = opening(fn(checkout, 'StepPayment'), 'PracticePaymentSetup', 'checkout');
  assert(checkoutPayment.attributes.some(value => value.name?.name === 'onConfirmed'));
  const chat = fn(lane, 'GeneralHelpTask');
  assert(request(variable(chat, 'refreshAddressChoices'), 'transport',
    '/api/secureshop/customer/commerce/addresses', 'GET'));
  assert(request(variable(chat, 'refreshPaymentChoices'), 'transport',
    '/api/secureshop/customer/commerce/payment-methods', 'GET'));
  opening(chat, 'PracticeAddressSetup', 'chat');
  opening(chat, 'PracticePaymentSetup', 'chat');

  const addressComponent = fn(address, 'PracticeAddressSetup');
  const addressEffect = one(find(addressComponent, value => value.type === 'CallExpression'
    && member(value.callee) === 'useEffect'
    && find(value.arguments[0], item => item.type === 'CallExpression'
      && member(item.callee) === 'transport'
      && item.arguments[0]?.type === 'TemplateLiteral'
      && item.arguments[0].quasis[0].value.cooked === '/api/secureshop/customer/commerce/address-form').length),
  'address form loading effect');
  assert(find(addressEffect, value => value.type === 'ConditionalExpression'
    && string(value.alternate, '?action=create')
    && value.consequent?.type === 'TemplateLiteral'
    && value.consequent.quasis[0].value.cooked === '?action=update&choiceId=').length,
  'create/update exact query branches');
  const addressRun = variable(addressComponent, 'run');
  const addressSavedBranch = one(find(addressRun, value => value.type === 'IfStatement'
    && value.test?.type === 'LogicalExpression'
    && value.test.left?.name === 'saved' && value.test.right?.name === 'recover'),
  'address saved-operation branch');
  assert(calls(addressSavedBranch.consequent, 'readExact').length === 1);
  assert(find(addressSavedBranch.consequent, value => value.type === 'ReturnStatement').length);
  assert.equal(calls(addressSavedBranch.consequent, 'transport').length, 0);
  const review = button(addressComponent, 'Review address');
  assert(calls(onClick(review), 'setReview').some(value => value.arguments[0]?.value === true));
  assert(find(addressRun, value => value.type === 'IfStatement'
    && find(value.test, item => item.type === 'UnaryExpression'
      && item.argument?.name === 'review').length
    && find(value.consequent, item => item.type === 'ReturnStatement').length).length,
  'review must precede save');
  const confirm = one(find(addressComponent, value => value.type === 'JSXElement'
    && value.openingElement?.name?.name === 'button'
    && calls(onClick(value), 'run').some(call => call.arguments.length === 0)),
  'address Confirm control');
  assert(confirm.start > review.start);
  const savedAddress = one(calls(addressRun, 'saveAddressReference'), 'saved address reference');
  assert(awaited(addressRun, savedAddress));
  const priorAddress = calls(addressRun, 'readExact').find(value =>
    value.start > savedAddress.end && value.start < request(addressRun, 'transport',
      '/api/secureshop/customer/commerce/addresses', 'POST').start);
  assert(priorAddress && awaited(addressRun, priorAddress));
  const addressPost = request(addressRun, 'transport',
    '/api/secureshop/customer/commerce/addresses', 'POST');
  assert.deepEqual(keys(property(addressPost.arguments[1], 'body')?.arguments[0]),
    ['action', 'choiceId', 'defaultSetSha256', 'expectedSnapshotSha256', 'fields', 'operationId']);
  const addressBody = property(addressPost.arguments[1], 'body').arguments[0];
  for (const key of ['action', 'choiceId', 'defaultSetSha256',
    'expectedSnapshotSha256', 'operationId'])
    assert.equal(member(property(addressBody, key)), `saved.${key}`, `address ${key} binding`);
  assert.equal(member(property(addressBody, 'fields')), 'normalized');
  assert(awaited(addressRun, addressPost));
  assert(calls(addressRun, 'readExact').some(value => value.start > addressPost.end
    && awaited(addressRun, value)), 'address POST followed by exact GET');
  const addressRecovery = button(addressComponent, 'Check saved address');
  assert(calls(onClick(addressRecovery), 'run').some(value => value.arguments[0]?.value === true));

  const paymentComponent = fn(payment, 'PracticePaymentSetup');
  const paymentRun = variable(paymentComponent, 'run');
  const paymentSavedBranch = one(find(paymentRun, value => value.type === 'IfStatement'
    && value.test?.name === 'saved'
    && calls(value.consequent, 'readExact').length === 1), 'payment saved-operation branch');
  assert(calls(paymentSavedBranch.consequent, 'readExact').length === 1);
  assert(find(paymentSavedBranch.consequent, value => value.type === 'ReturnStatement').length);
  assert.equal(calls(paymentSavedBranch.consequent, 'transport').length, 0);
  const paymentSelect = one(calls(paymentComponent, 'setScenario').filter(value =>
    value.arguments[0]?.name === 'value'), 'scenario-selection control');
  assert(paymentSelect.start < button(paymentComponent, 'Create selected practice payment').start);
  const create = button(paymentComponent, 'Create selected practice payment');
  assert(calls(onClick(create), 'run').some(value => value.arguments[0]?.name === 'scenario'));
  const paymentGet = request(paymentRun, 'transport',
    '/api/secureshop/customer/commerce/payment-methods', 'GET');
  assert(awaited(paymentRun, paymentGet));
  assert(find(paymentRun, value => value.type === 'IfStatement'
    && find(value.test, item => item.type === 'CallExpression'
      && item.callee?.property?.name === 'includes'
      && item.callee.object?.type === 'ArrayExpression'
      && item.callee.object.elements.map(choice => choice.value).join(',') === 'approved,declined'
      && item.arguments[0]?.name === 'selectedScenario').length
    && find(value.consequent, item => item.type === 'ReturnStatement').length).length,
  'payment scenario has only approved/declined choices');
  const savedPayment = one(calls(paymentRun, 'savePracticePaymentReference'), 'saved payment reference');
  assert(awaited(paymentRun, savedPayment));
  const paymentPost = request(paymentRun, 'transport',
    '/api/secureshop/customer/commerce/payment-methods', 'POST');
  assert(paymentGet.start < savedPayment.start && savedPayment.start < paymentPost.start);
  assert.deepEqual(keys(property(paymentPost.arguments[1], 'body')?.arguments[0]),
    ['operationId', 'scenario']);
  const paymentBody = property(paymentPost.arguments[1], 'body').arguments[0];
  assert.equal(member(property(paymentBody, 'operationId')), 'saved.operationId');
  assert.equal(member(property(paymentBody, 'scenario')), 'saved.scenario');
  assert(awaited(paymentRun, paymentPost));
  assert(calls(paymentRun, 'readExact').some(value => value.start > paymentPost.end
    && awaited(paymentRun, value)), 'payment POST followed by exact GET');
  const paymentRecovery = button(paymentComponent, 'Check saved practice payment');
  assert(calls(onClick(paymentRecovery), 'run').some(value => value.arguments[0]?.type === 'NullLiteral'));

  const loop = one(find(gateway, value => value.type === 'ForOfStatement'
    && value.right?.type === 'ArrayExpression'
    && value.right.elements.some(item => item.type === 'ArrayExpression'
      && string(item.elements[0], 'addressChoices'))), 'mounted commerce dispatch loop');
  for (const [method, url, verb, fields, effect] of [
    ['addressChoices', '/customer/commerce/addresses', 'get', [], 'issue'],
    ['saveAddress', '/customer/commerce/addresses', 'post',
      ['operationId', 'action', 'choiceId', 'expectedSnapshotSha256', 'defaultSetSha256', 'fields'],
      'saveAddressWithClient'],
    ['paymentMethods', '/customer/commerce/payment-methods', 'get', [], 'listKind'],
    ['createPaymentMethod', '/customer/commerce/payment-methods', 'post',
      ['operationId', 'scenario'], 'insert'],
  ]) {
    const tuple = one(loop.right.elements.filter(item => item.type === 'ArrayExpression'
      && string(item.elements[0], method) && string(item.elements[1], url)
      && string(item.elements[2], verb)), `gateway ${method}`);
    assert.deepEqual(tuple.elements[3].elements.map(item => item.value), fields);
    const methodNode = one(find(repository, value => value.type === 'ObjectMethod'
      && value.key?.name === method), `repository ${method}`);
    assert(calls(methodNode, 'transaction').length === 1);
    assert(calls(methodNode, effect).length >= 1, `${method} selected effect`);
  }
  const formRoute = one(calls(gateway, 'router.get').filter(value =>
    string(value.arguments[0], '/customer/commerce/address-form')), 'address form route');
  assert(calls(formRoute, 'conversationDomain.addressForm').length === 1);
  const formMethod = one(find(repository, value => value.type === 'ObjectMethod'
    && value.key?.name === 'addressForm'), 'address form repository');
  assert(calls(formMethod, 'addressState').length === 1);
}

test('five selected address/payment bindings preserve partial shared recovery and unresolved scoring', () => {
  const evidence = manifest.commerceUiEvidence;
  assert.deepEqual(evidence.reviewedAddressPaymentBindings.map(value => value.actionId), [
    'customer.commerce.addresses', 'customer.commerce.addressForm',
    'customer.commerce.addresses.save', 'customer.commerce.paymentMethods.list',
    'customer.commerce.paymentMethods.create']);
  const reviewed = [...evidence.reviewedProfileBindings, ...evidence.reviewedCheckoutCartBindings,
    ...evidence.reviewedAddressPaymentBindings].map(value => value.actionId);
  assert.equal(manifest.commerceBindings.length, 12);
  assert.deepEqual(evidence.remainingUnresolvedActionIds, ['customer.commerce.operation']);
  assert.deepEqual([...reviewed, ...evidence.remainingUnresolvedActionIds].sort(),
    manifest.commerceBindings.map(value => value.actionId).sort());
  assert.equal(evidence.sourceEvidence, 'endpoint_reference_only');
  assert.equal(evidence.eventToRequestRelation, 'unresolved');
  assert.equal(evidence.physicalUiVerified, false);
  assert.equal(evidence.runtimeEffectVerified, false);
  assert.equal(evidence.q08Qualification, 'deferred_unverified');
  for (const id of evidence.reviewedAddressPaymentBindings.map(value => value.actionId)) {
    const row = manifest.commerceBindings.find(value => value.actionId === id);
    assert(row && !row.confirmation.physicalUiVerified && !row.recovery.nativeVerified);
    assert.equal(row.runtimeEvidence, null);
    assert.match(row.q08Applicability, /scoring_unresolved/);
  }
  validate();
});

test('selected address/payment AST relations reject swapped authority, handlers, requests and effects', () => {
  const cases = [
    ['bound account branch removed', 'account', '<BoundAddressesTab /> : <AddressesTab />',
      '<AddressesTab /> : <BoundAddressesTab />'],
    ['account choice GET changed', 'account',
      "transport('/api/secureshop/customer/commerce/addresses'",
      "transport('/api/secureshop/customer/commerce/other'"],
    ['account setup mode swapped', 'account', 'entryPoint="account" action={editing.action}',
      'entryPoint="chat" action={editing.action}'],
    ['address form query swapped', 'address', "'?action=create'", "'?action=update'"],
    ['address review gate removed', 'address', '|| !review || handoffError) return;',
      '|| review || handoffError) return;'],
    ['address reference not awaited', 'address', 'await saveAddressReference(saved);',
      'void saveAddressReference(saved);'],
    ['address recovery becomes new dispatch', 'address',
      'onClick={() => void run(true)}>Check saved address',
      'onClick={() => void run()}>Check saved address'],
    ['address payload omits default set', 'address',
      'defaultSetSha256: saved.defaultSetSha256, fields: normalized',
      'defaultSetSha256: null, fields: normalized'],
    ['payment selection button disconnected', 'payment', 'void run(scenario)}>Create selected practice payment',
      'void run(null)}>Create selected practice payment'],
    ['payment choice GET changed', 'payment',
      "transport('/api/secureshop/customer/commerce/payment-methods', { method: 'GET'",
      "transport('/api/secureshop/customer/commerce/payment-methods', { method: 'POST'"],
    ['payment reference not awaited', 'payment', 'await savePracticePaymentReference(saved);',
      'void savePracticePaymentReference(saved);'],
    ['payment recovery loses saved return', 'payment',
      'await showOutcome(saved, await readExact(saved, controller.signal), current); return;',
      'await showOutcome(saved, await readExact(saved, controller.signal), current); void saved;'],
    ['gateway address kind changed', 'gateway',
      "['addressChoices','/customer/commerce/addresses','get'",
      "['addresses','/customer/commerce/addresses','get'"],
    ['repository choice issuance removed', 'repository',
      "await issue(client,value,a,'address',current)",
      "await noIssue(client,value,a,'address',current)"],
  ];
  for (const [label, part, before, after] of cases) {
    assert(source[part].includes(before), `${label}: mutation anchor`);
    assert.throws(() => validate({ ...source, [part]: source[part].replace(before, after) }),
      undefined, label);
  }
});
