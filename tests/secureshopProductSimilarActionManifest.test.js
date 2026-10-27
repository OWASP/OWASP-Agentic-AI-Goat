'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');
const root = path.resolve(__dirname, '..');
const ids = ['catalog.product.similarSession', 'catalog.product.similarRun',
  'catalog.product.similarSaved'];

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
      if (['loc','start','end','comments','leadingComments','trailingComments','innerComments','extra'].includes(key)) continue;
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object') visit(child);
    }
  }
  visit(node); return found;
}
function name(node) {
  if (!node) return null;
  if (node.type === 'Identifier' || node.type === 'JSXIdentifier') return node.name;
  if (['MemberExpression', 'OptionalMemberExpression'].includes(node.type) && !node.computed)
    return `${name(node.object)}.${name(node.property)}`;
  return null;
}
const calls = (node, called) => nodes(node, value => value.type === 'CallExpression'
  && name(value.callee) === called);
function local(node, variable) {
  const found = nodes(node, value => value.type === 'VariableDeclarator'
    && name(value.id) === variable);
  assert.equal(found.length, 1, `exact local ${variable}`);
  return found[0].init;
}
function routeCall(ast, verb, route) {
  const found = calls(ast, `router.${verb}`).filter(value => value.arguments[0]?.value === route);
  assert.equal(found.length, 1, `${verb.toUpperCase()} ${route}`);
  return found[0];
}
function requestCall(node, method) {
  return calls(node, 'transport').filter(value => nodes(value.arguments[1], field =>
    field.type === 'ObjectProperty' && name(field.key) === 'method'
      && field.value?.value === method).length === 1);
}
function property(object, key) {
  assert.equal(object?.type, 'ObjectExpression');
  const found = object.properties.filter(value => value.type === 'ObjectProperty'
    && name(value.key) === key);
  assert.equal(found.length, 1, `Exact property ${key}`);
  return found[0].value;
}
function requiredFactoryCall(ast, modulePath, exportName) {
  return nodes(ast, value => value.type === 'CallExpression'
    && value.callee?.type === 'MemberExpression'
    && name(value.callee.property) === exportName
    && value.callee.object?.type === 'CallExpression'
    && name(value.callee.object.callee) === 'require'
    && value.callee.object.arguments[0]?.value === modulePath);
}
function verifySourceJoin(overrides = {}) {
  const bindings = manifest.productSimilarBindings;
  assert.deepEqual(bindings.map(row => row.actionId), ids);
  const files = bindings[0].sourceBinding;
  assert.equal(files.runtimeFile, 'client/src/pages/secureshop/bridge/runtime.mjs');
  assert.equal(files.fetchAdapterFile, 'client/src/pages/secureshop/bridge/fetchAdapter.mjs');
  const fileKeys = Object.keys(files).filter(key => key.endsWith('File'));
  assert.deepEqual(bindings.map(row => [row.sourceBinding.uiCall, row.sourceBinding.hookCall,
    row.sourceBinding.gatewayCall, row.sourceBinding.effectCall]), [
    ['similar.start', 'transport POST productPath(selected)/session',
      'productAssist.createSimilarSession', 'conversations.create'],
    ['similar.start', 'transport POST productPath(selected)',
      'productAssist.runSimilar', 'runner.run'],
    ['similar.check', 'transport GET savedPath(ref)',
      'productAssist.readSimilar', 'journal.readBoundRequest'],
  ]);
  for (const binding of bindings) {
    assert.deepEqual(Object.fromEntries(fileKeys.map(key => [key, binding.sourceBinding[key]])),
      Object.fromEntries(fileKeys.map(key => [key, files[key]])));
    assert.equal(binding.runtimeEvidence, null);
    assert.equal(binding.confirmation.physicalUiVerified, false);
    assert.equal(binding.confirmation.denialNoEffectVerified, false);
    assert.equal(binding.recovery.nativeVerified, false);
    assert.deepEqual(binding.linkedObjectiveIds, []);
    assert.deepEqual(binding.evidenceAdapters, []);
    assert.equal(manifest.actions.find(row => row.id === binding.actionId)?.review, binding.actionId);
  }
  assert.equal(manifest.actions.find(row => row.id === 'catalog.product.similar')?.review, null,
    'Legacy GET is not the bound button mutation');
  const read = key => overrides[key] ?? source(files[key]);
  const ui = parse(read('uiFile'));
  const product = nodes(ui, value => value.type === 'FunctionDeclaration'
    && name(value.id) === 'Product');
  assert.equal(product.length, 1);
  assert.equal(calls(product[0], 'useProductSimilar').length, 1);
  const pageHook = local(product[0], 'similar');
  assert.equal(name(pageHook.callee), 'useProductSimilar');
  assert.equal(name(local(product[0], 'summaryTransport')), 'globalThis.fetch');
  assert.equal(name(property(pageHook.arguments[0], 'transport')), 'summaryTransport');
  const customer = property(pageHook.arguments[0], 'shopUserId');
  assert.equal(customer.type, 'ConditionalExpression');
  assert.equal(customer.test.type, 'LogicalExpression');
  assert.equal(name(customer.test.left), 'isAuthed');
  assert.equal(customer.test.right.operator, '===');
  assert.equal(name(customer.test.right.left), 'user.role');
  assert.equal(customer.test.right.right.value, 'customer');
  assert.equal(name(customer.consequent), 'user.id');
  assert.equal(customer.alternate.type, 'NullLiteral');
  const button = nodes(product[0], value => value.type === 'JSXElement'
    && name(value.openingElement?.name) === 'button'
    && nodes(value, child => child.type === 'JSXText'
      && child.value.trim() === 'Find similar products').length === 1
    && nodes(value.openingElement, child => child.type === 'JSXAttribute'
      && name(child.name) === 'onClick'
      && calls(child.value?.expression, 'similar.start').length === 1).length === 1);
  assert.equal(button.length, 1, 'Exact visible button must dispatch similar.start');
  const retryButton = nodes(product[0], value => value.type === 'JSXElement'
    && name(value.openingElement?.name) === 'button'
    && nodes(value, child => child.type === 'JSXText'
      && child.value.trim() === 'Try again').length === 1
    && nodes(value.openingElement, child => child.type === 'JSXAttribute'
      && name(child.name) === 'onClick'
      && calls(child.value?.expression, 'similar.retryNotFound').length === 1).length === 1);
  assert.equal(retryButton.length, 1, 'Try again must retain the same-ID retry handler');
  assert.equal(nodes(product[0], value => value.type === 'LogicalExpression'
    && name(value.left) === 'ownSimilar'
    && nodes(value.right, child => child === button[0]).length === 1).length, 1,
  'Button must remain under authenticated customer gate');
  assert.equal(nodes(parse(read('uiRouteFile')), value => value.type === 'JSXOpeningElement'
    && name(value.name) === 'Route'
    && value.attributes.some(attr => name(attr.name) === 'path' && attr.value?.value === 'product/:id')
    && nodes(value, child => name(child.name) === 'SSv2Product').length).length, 2);

  const hook = parse(read('hookFile'));
  const hookFunction = nodes(hook, value => value.type === 'FunctionDeclaration'
    && name(value.id) === 'useProductSimilar');
  assert.equal(hookFunction.length, 1);
  const start = local(hookFunction[0], 'start');
  const readSaved = local(hookFunction[0], 'readSaved');
  const check = local(hookFunction[0], 'check');
  const retry = local(hookFunction[0], 'retryNotFound');
  assert.equal(calls(start, 'referenceStore.save').length, 1);
  assert.equal(calls(start, 'crypto.randomUUID').length, 1);
  const post = requestCall(start, 'POST');
  assert.equal(post.length, 2, 'Session then original POST, no additional effect call');
  assert.equal(post[0].arguments[0].type, 'TemplateLiteral');
  assert.equal(post[0].arguments[0].quasis.map(q => q.value.cooked).join(''), '/session');
  assert.equal(calls(post[0].arguments[0], 'productPath').length, 1);
  assert.equal(calls(post[1].arguments[0], 'productPath').length, 1);
  assert.equal(calls(post[1].arguments[1], 'JSON.stringify').length, 1);
  assert(start.start < calls(start, 'referenceStore.save')[0].start
    && calls(start, 'referenceStore.save')[0].start < post[1].start);
  assert.equal(calls(start, 'discardIgnoredMutationResponse').length, 1);
  assert.equal(calls(start, 'readSaved').length, 1);
  assert.equal(requestCall(readSaved, 'GET').length, 1);
  assert.equal(calls(requestCall(readSaved, 'GET')[0].arguments[0], 'savedPath').length, 1);
  assert.equal(calls(check, 'readSaved').length, 1);
  assert.equal(calls(retry, 'readSaved').length, 2);
  assert.equal(calls(retry, 'crypto.randomUUID').length, 0,
    'Not-found retry must retain original request identity');
  assert.equal(requestCall(retry, 'POST').length, 1);

  const runtime = parse(read('runtimeFile'));
  assert.equal(nodes(runtime, value => value.type === 'ImportDeclaration'
    && value.source.value === './fetchAdapter.mjs'
    && value.specifiers.some(spec => name(spec.imported) === 'createBridgeFetch')).length, 1);
  const frame = nodes(runtime, value => value.type === 'FunctionDeclaration'
    && name(value.id) === 'startShopFrame');
  assert.equal(frame.length, 1);
  const install = calls(frame[0], 'createBridgeFetch');
  assert.equal(install.length, 1);
  assert.equal(name(property(install[0].arguments[0], 'bridge')), 'bridge');
  const patch = nodes(frame[0], value => value.type === 'AssignmentExpression'
    && name(value.left) === 'frameWindow.fetch' && name(value.right) === 'patchedFetch');
  assert.equal(patch.length, 1);
  assert(install[0].start < patch[0].start && patch[0].start < calls(frame[0], 'render')[0].start,
    'Acknowledged bridge fetch must be installed before Product renders');
  const adapter = parse(read('fetchAdapterFile'));
  assert.equal(nodes(adapter, value => value.type === 'ImportDeclaration'
    && value.source.value === './operations.mjs'
    && value.specifiers.some(spec => name(spec.imported) === 'matchOperationRequest')).length, 1);
  const makeFetch = nodes(adapter, value => value.type === 'FunctionDeclaration'
    && name(value.id) === 'createBridgeFetch');
  assert.equal(makeFetch.length, 1);
  const match = calls(makeFetch[0], 'matchOperationRequest');
  assert.equal(match.length, 1);
  assert.deepEqual(['pathname', 'method', 'query', 'body'].map(key => name(property(match[0].arguments[0], key))),
    ['url.pathname', 'request.method', 'query', 'body']);
  const dispatch = calls(makeFetch[0], 'bridge.request').filter(value => name(value.arguments[0]) === 'name');
  assert.equal(dispatch.length, 1);
  assert.equal(name(dispatch[0].arguments[1]), 'operationInput');
  assert(match[0].start < dispatch[0].start, 'Matched operation identity precedes parent bridge dispatch');

  const registered = parse(read('bridgeFile'));
  for (const id of ids) assert.equal(nodes(registered, value => value.type === 'ObjectProperty'
    && value.key?.value === id).length, 1, `Bridge identity ${id}`);
  const gateway = parse(read('gatewayFile'));
  for (const [verb, route, method] of [
    ['post', '/products/:id/similar/session', 'createSimilarSession'],
    ['post', '/products/:id/similar', 'runSimilar'],
    ['get', '/products/:id/similar/sessions/:sessionId/requests/:requestId', 'readSimilar'],
  ]) {
    const row = routeCall(gateway, verb, route);
    assert.equal(calls(row, `productAssist.${method}`).length, 1,
      `${method} must be called by its exact route body`);
    assert.equal(calls(row, 'persona').filter(value => value.arguments[0]?.value === 'customer').length, 1);
    assert.equal(nodes(gateway, value => value.type === 'IfStatement'
      && value.test?.operator === '===' && value.test.left?.operator === 'typeof'
      && name(value.test.left.argument) === `productAssist.${method}`
      && value.test.right?.value === 'function'
      && calls(value.consequent, `productAssist.${method}`).includes(calls(row, `productAssist.${method}`)[0])
      && calls(value.alternate, 'registerUnavailable').length === 1).length, 1,
    `${method} must have conditional availability and unavailable fallback`);
  }
  const service = parse(read('serviceFile'));
  const factory = nodes(service, value => value.type === 'FunctionDeclaration'
    && name(value.id) === 'createSecureShopBoundProductAssist');
  assert.equal(factory.length, 1);
  const serviceFunction = method => {
    const found = nodes(factory[0], value => value.type === 'FunctionDeclaration'
      && name(value.id) === method);
    assert.equal(found.length, 1, `Exact service method ${method}`);
    return found[0];
  };
  const create = serviceFunction('createSimilarSession');
  const saved = serviceFunction('readSimilar');
  assert.equal(calls(create, 'conversations.create').length, 1);
  assert.equal(calls(saved, 'conversations.assertOwned').length, 1);
  assert.equal(calls(saved, 'journal.readBoundRequest').length, 1);
  assert.equal(calls(factory[0], 'runner.run').length, 1);
  const bridge = nodes(factory[0], value => value.type === 'ObjectProperty'
    && name(value.key) === 'runSimilar');
  assert.equal(bridge.length, 1);
  assert.equal(calls(bridge[0].value, 'execute').filter(value => value.arguments[0]?.value === 'similar').length, 1);
  assert.equal(calls(parse(read('compositionFile')), 'createSecureShopBoundProductAssist').length, 1);
  assert.equal(requiredFactoryCall(parse(read('applicationFile')),
    '../routes/secureshop/boundGateway', 'createSecureShopBoundGateway').length, 1);
  assert.equal(requiredFactoryCall(parse(read('serverMountFile')),
    './services/secureshopBoundApplication', 'createSecureShopBoundApplication').length, 1);
  assert.equal(manifest.scope.supportedActionDenominatorComplete, false);
  assert.equal(manifest.scope.globalDenominatorComplete, false);
  assert.equal(manifest.qualification.Q08, 'deferred_unverified');
}

test('Product customer transport, installed fetch mapping, saved reference, routes and effect form one source chain', async () => {
  verifySourceJoin();
  const { describeOperations, matchOperationRequest } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const registered = describeOperations().operations.filter(row => ids.includes(row.name));
  assert.deepEqual(registered.map(row => [row.name, row.method, row.pathTemplate]),
    manifest.actions.filter(row => ids.includes(row.id)).map(row => [row.id, row.method, row.path]));
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const requestId = '22222222-2222-4222-8222-222222222222';
  assert.deepEqual([
    matchOperationRequest({ pathname: '/api/secureshop/products/17/similar/session', method: 'POST', body: {} }),
    matchOperationRequest({ pathname: '/api/secureshop/products/17/similar', method: 'POST', body: { sessionId, requestId } }),
    matchOperationRequest({ pathname: `/api/secureshop/products/17/similar/sessions/${sessionId}/requests/${requestId}`, method: 'GET' }),
  ].map(row => row.name), ids);
});

test('unrelated button, changed session path or substituted gateway effect cannot inherit source review', () => {
  const binding = manifest.productSimilarBindings[0].sourceBinding;
  const ui = source(binding.uiFile), hook = source(binding.hookFile), gateway = source(binding.gatewayFile);
  const runtime = source(binding.runtimeFile), adapter = source(binding.fetchAdapterFile);
  const wrongButton = ui.replace('void similar.start()', 'void similar.check()');
  const wrongCustomer = ui.replace("user?.role === 'customer' ? user?.id : null",
    "user?.role === 'merchant' ? user?.id : null");
  const wrongRetry = ui.replace('void similar.retryNotFound()', 'void similar.start()');
  const wrongSession = hook.replace('`${productPath(selected)}/session`', '`${productPath(selected)}/wrong`');
  const wrongEffect = gateway.replace('productAssist.runSimilar({', 'productAssist.similar({');
  const wrongInstall = runtime.replace('frameWindow.fetch=patchedFetch;', 'frameWindow.fetch=originalFetch;');
  const wrongMatch = adapter.replace('matchOperationRequest({ pathname: url.pathname, method: request.method, query, body })',
    'matchOperationRequest({ pathname: url.pathname, method: "GET", query, body })');
  assert.notEqual(wrongButton, ui);
  assert.notEqual(wrongCustomer, ui);
  assert.notEqual(wrongRetry, ui);
  assert.notEqual(wrongSession, hook);
  assert.notEqual(wrongEffect, gateway);
  assert.notEqual(wrongInstall, runtime);
  assert.notEqual(wrongMatch, adapter);
  assert.throws(() => verifySourceJoin({ uiFile: wrongButton }));
  assert.throws(() => verifySourceJoin({ uiFile: wrongCustomer }));
  assert.throws(() => verifySourceJoin({ uiFile: wrongRetry }));
  assert.throws(() => verifySourceJoin({ hookFile: wrongSession }));
  assert.throws(() => verifySourceJoin({ gatewayFile: wrongEffect }));
  assert.throws(() => verifySourceJoin({ runtimeFile: wrongInstall }));
  assert.throws(() => verifySourceJoin({ fetchAdapterFile: wrongMatch }));
});
