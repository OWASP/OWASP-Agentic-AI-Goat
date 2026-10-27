'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const {windowsProtectedModules, setupPuppeteerLoaders} = require('./fixtures/secureShopAgentHostSourceClosure');

const source = fs.readFileSync(path.join(__dirname, '../scripts/start-application.js'), 'utf8');
const parse = text => parser.parse(text, {sourceType: 'unambiguous',
  plugins: ['classProperties', 'dynamicImport', 'jsx', 'nullishCoalescingOperator',
    'optionalChaining', 'topLevelAwait']});

test('Windows protected service map closes exactly two services and six modules', () => {
  const value = windowsProtectedModules(parse(source), parser);
  assert.equal(value.calls.size, 3);
  assert.deepEqual(value.modules, [
    '../server/services/mcp/ownedHttpManagedConfiguration',
    '../server/services/mcp/ownedShadowManagedConfiguration',
    './install/mcp-owned-http', './install/mcp-owned-shadow',
    '../server/services/mcp/ownedHttpServiceClient',
    '../server/services/mcp/ownedShadowServiceClient',
  ]);
});

test('setup browser runtime closes the exact npm Puppeteer resolver without claiming local source', () => {
  const setup = fs.readFileSync(path.join(__dirname, '../scripts/setup-application.js'), 'utf8');
  const calls = setupPuppeteerLoaders(parse(setup), parser);
  assert.equal(calls.size, 2);
  for (const call of calls) assert.equal(call.callee.name, 'require');
  for (const [original, changed] of [
    ["require.resolve('puppeteer'", "require.resolve('unreviewed'"],
    ['{ paths: [target] }', '{ paths: [process.cwd()] }'],
    ["target => require(require.resolve('puppeteer'", "target => requireOther(require.resolve('puppeteer'"],
  ]) {
    assert.ok(setup.includes(original));
    assert.throws(() => setupPuppeteerLoaders(parse(setup.replace(original, changed)), parser),
      /unreviewed Puppeteer package loader/);
    const last = setup.lastIndexOf(original);
    assert.throws(() => setupPuppeteerLoaders(parse(
      setup.slice(0, last) + changed + setup.slice(last + original.length)), parser),
      /unreviewed Puppeteer package loader/);
  }
});

test('Windows protected service expansion rejects changed registry and require arguments', () => {
  const cases = [
    ["['http', 'shadow'].map(kind", "['http', 'unreviewed'].map(kind"],
    ['`./install/mcp-owned-${kind}`', '`./install/mcp-owned-${kind}-other`'],
    ['config.managedPath(options)', 'config.managedPath({})'],
    ["kind === 'http' ? 'Http' : 'Shadow'", "kind === 'http' ? 'Http' : 'Unreviewed'"],
  ];
  for (const [original, changed] of cases) {
    assert.ok(source.includes(original), `reviewed source must contain ${original}`);
    assert.throws(() => windowsProtectedModules(parse(source.replace(original, changed)), parser),
      /unreviewed Windows protected service registry or arguments/);
  }
});
