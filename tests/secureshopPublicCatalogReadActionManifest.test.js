'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const ids = ['catalog.list', 'catalog.categories', 'catalog.product.get',
  'catalog.product.reviews.list', 'catalog.product.similar'];

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
function routeCall(ast, route) {
  const found = calls(ast, 'router.get').filter(value => value.arguments[0]?.value === route);
  assert.equal(found.length, 1, `GET ${route}`);
  return found[0];
}

function verify(overrides = {}) {
  const bindings = manifest.publicCatalogReadBindings;
  assert.deepEqual(bindings.map(row => row.actionId), ids);
  const read = (binding, key) => overrides[key] ?? source(binding.sourceBinding[key]);
  for (const binding of bindings) {
    const action = manifest.actions.find(row => row.id === binding.actionId);
    assert.equal(action?.review, binding.actionId);
    assert.equal(action?.method, 'GET');
    assert.equal(binding.runtimeEvidence, null);
    assert.equal(binding.confirmation.physicalUiVerified, false);
    assert.equal(binding.confirmation.denialNoEffectVerified, false);
    assert.equal(binding.recovery.nativeVerified, false);
    assert.deepEqual(binding.linkedObjectiveIds, []);
    assert.deepEqual(binding.evidenceAdapters, []);
    assert.match(binding.confirmation.kind, /consequence_unresolved/);
  }
  assert.equal(manifest.qualification.Q05, 'deferred_unverified');
  assert.equal(manifest.qualification.Q08, 'deferred_unverified');
  assert.equal(manifest.scope.supportedActionDenominatorComplete, false);
  assert.equal(manifest.scope.globalDenominatorComplete, false);

  const base = bindings[0];
  const guestEntry = parse(read(base, 'guestEntryFile'));
  const mount = calls(guestEntry, 'mountShopFrame');
  assert.equal(mount.length, 1);
  assert.equal(nodes(mount[0].arguments[0], value => value.type === 'ObjectProperty' && name(value.key) === 'compileOperation'
    && name(value.value) === 'compileGuestRead').length, 1);
  assert.equal(nodes(mount[0].arguments[0], value => value.type === 'ObjectProperty' && name(value.key) === 'transportOptions'
    && nodes(value.value, child => child.type === 'ObjectProperty' && name(child.key) === 'publicOnly'
      && child.value?.value === true).length === 1).length, 1);

  const compilerText = read(base, 'guestCompilerFile');
  const compiler = parse(compilerText);
  for (const id of ids) assert.equal(nodes(compiler, value => value.type === 'ObjectProperty' && value.key?.value === id).length, 1,
    `guest compiler permits ${id}`);
  assert.match(compilerText, /replace\(\/\\\/similar\(\?=\\\?\|\$\)\/, '\/related'\)/,
    'legacy similar registration is rewritten only for the public related route');

  const transportText = read(base, 'transportFile');
  const transport = parse(transportText);
  assert.equal(calls(transport, 'compileGuestRead').length, 1);
  assert.equal(calls(transport, 'isGuestReadOperation').length, 1);
  assert.match(transportText, /request\.method !== 'GET'/);
  assert.ok(transportText.includes('|| message.shopBearer !== undefined || request.body !== undefined)) throw protocolError();'),
    'the public-only admission rejects bearer and body together');

  const catalogText = read(base, 'catalogUiFile');
  const catalog = parse(catalogText);
  assert.equal(calls(catalog, 'fetch').filter(call => call.arguments[0]?.value === '/api/secureshop/categories').length, 1);
  assert.equal(calls(catalog, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products?').length, 1);
  const productText = read(bindings[2], 'productUiFile');
  const product = parse(productText);
  assert.equal(calls(product, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products/').length, 1);
  assert.equal(calls(product, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products//reviews?limit=&offset=').length, 1);
  assert.equal(calls(product, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
    && call.arguments[0].quasis.map(part => part.value.cooked).join('') === '/api/secureshop/products//similar').length, 1);
  assert.match(productText, /if \(isAuthed\) return \(\) => \{ controller\.abort\(\); \};/,
    'ordinary related read stays guest-only');

  const routesText = read(base, 'publicRouteFile');
  const routes = parse(routesText);
  const expected = [
    ['/products', 'repository.browse'],
    ['/categories', 'repository.categories'],
    ['/products/:id', 'repository.product'],
    ['/products/:id/reviews', 'repository.reviews'],
    ['/products/:id/related', 'repository.related'],
  ];
  for (const [route, repository] of expected) assert.equal(calls(routeCall(routes, route), repository).length, 1,
    `${route} reaches its exact public repository read`);
}

test('anonymous catalog reads join the guest compiler, bearerless public transport, mounted UI and exact public routes without qualification claims', async () => {
  verify();
  const { describeOperations } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  assert.deepEqual(describeOperations().operations.filter(row => ids.includes(row.name)).map(row =>
    [row.name, row.method, row.pathTemplate]), [
    ['catalog.list', 'GET', '/api/secureshop/products'],
    ['catalog.categories', 'GET', '/api/secureshop/categories'],
    ['catalog.product.get', 'GET', '/api/secureshop/products/:id'],
    ['catalog.product.reviews.list', 'GET', '/api/secureshop/products/:id/reviews'],
    ['catalog.product.similar', 'GET', '/api/secureshop/products/:id/similar'],
  ]);
  const { compileGuestRead } = await import('../client/src/pages/secureshop/bridge/guestRead.mjs');
  assert.deepEqual([
    compileGuestRead('catalog.list', { query: { limit: '8' } }).path,
    compileGuestRead('catalog.categories', {}).path,
    compileGuestRead('catalog.product.get', { params: { id: '7' } }).path,
    compileGuestRead('catalog.product.reviews.list', { params: { id: '7' }, query: { limit: '10', offset: '0' } }).path,
    compileGuestRead('catalog.product.similar', { params: { id: '7' } }).path,
  ], [
    '/api/secureshop/public/products?limit=8',
    '/api/secureshop/public/categories',
    '/api/secureshop/public/products/7',
    '/api/secureshop/public/products/7/reviews?limit=10&offset=0',
    '/api/secureshop/public/products/7/related',
  ]);
});

test('a broadened guest permit, non-public transport, changed UI path, or substituted public repository cannot inherit source review', () => {
  const binding = manifest.publicCatalogReadBindings[0].sourceBinding;
  const compiler = source(binding.guestCompilerFile);
  const transport = source(binding.transportFile);
  const catalog = source(binding.catalogUiFile);
  const routes = source(binding.publicRouteFile);
  const wrongCompiler = compiler.replace("'catalog.product.similar'", "'catalog.product.unrelated'");
  const wrongTransport = transport.replace('message.shopBearer !== undefined', 'false');
  const wrongCatalog = catalog.replace('/api/secureshop/categories', '/api/secureshop/recommended');
  const wrongRoute = routes.replace('repository.related(', 'repository.product(');
  for (const [key, value] of Object.entries({ guestCompilerFile: wrongCompiler, transportFile: wrongTransport,
    catalogUiFile: wrongCatalog, publicRouteFile: wrongRoute })) {
    assert.notEqual(value, source(binding[key]));
    assert.throws(() => verify({ [key]: value }), key);
  }
});
