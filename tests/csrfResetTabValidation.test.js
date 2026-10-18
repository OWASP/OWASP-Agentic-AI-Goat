'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const routePath = path.resolve(__dirname, '../server/routes/csrfWorkshop.js');
const source = fs.readFileSync(routePath, 'utf8');

function loadRouteHelpers() {
  const tabOf = source.match(/function tabOf\(req\) \{[\s\S]*?\n\}/)?.[0];
  const validate = source.match(/function requireValidResetTab\(req, res, next\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(tabOf, 'tabOf helper must remain available');
  assert.ok(validate, 'reset-tab validation helper must remain available');
  const context = { module: { exports: {} } };
  vm.runInNewContext(
    `'use strict'; const TAB_IDS = ['get', 'post', 'xss', 'indirect'];\n${tabOf}\n${validate}\nmodule.exports = { tabOf, requireValidResetTab };`,
    context,
    { filename: routePath },
  );
  return context.module.exports;
}

function invoke(middleware, { query = {}, body = {} } = {}) {
  const calls = [];
  const response = {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
  middleware({ query, body }, response, () => calls.push('admission'));
  return { calls, response };
}

test('reset-tab rejects an explicit invalid tab before owner admission or cleanup', () => {
  const { requireValidResetTab } = loadRouteHelpers();
  assert.match(source, /router\.post\('\/progress\/reset-tab', requireWorkshopUser, requireValidResetTab, ownerWorkflowRoute\(/);

  for (const request of [
    { body: { tab: 'indirec' } },
    { query: { tab: 'unknown' } },
    { body: { tab: '' } },
    { body: { tab: ['get'] } },
  ]) {
    const result = invoke(requireValidResetTab, request);
    assert.equal(result.response.statusCode, 400);
    assert.deepEqual(result.calls, []);
    assert.equal(result.response.body.error, 'A valid workshop tab is required');
  }
});

test('reset-tab preserves valid tabs and the documented absent-tab GET default', () => {
  const { tabOf, requireValidResetTab } = loadRouteHelpers();
  for (const body of [{ tab: 'get' }, { tab: 'POST' }, { tab: 'xss' }, { tab: 'indirect' }]) {
    const result = invoke(requireValidResetTab, { body });
    assert.deepEqual(result.calls, ['admission']);
    assert.equal(tabOf({ query: {}, body }), body.tab.toLowerCase());
  }

  const absent = invoke(requireValidResetTab);
  assert.deepEqual(absent.calls, ['admission']);
  assert.equal(tabOf({ query: {}, body: {} }), 'get');

  const bodyFallback = invoke(requireValidResetTab, { query: { tab: '' }, body: { tab: 'post' } });
  assert.deepEqual(bodyFallback.calls, ['admission']);
  assert.equal(tabOf({ query: { tab: '' }, body: { tab: 'post' } }), 'post');
});
