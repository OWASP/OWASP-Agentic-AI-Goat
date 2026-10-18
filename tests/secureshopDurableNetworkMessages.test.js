'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { configureDurableNetworkMessages, DURABLE_NETWORK_LIMITS } = require('./fixtures/configureDurableNetworkMessages');
const { configurePage } = require('./fixtures/fullBackendRenderedSecureShop');

function pageHarness(send = async () => {}) {
  const order = [], page = new EventEmitter();
  page._client = () => ({ send: async (method, params) => {
    order.push({ operation: 'cdp', method, params });return send(method, params);
  } });
  page.setDefaultTimeout = value => order.push({ operation: 'timeout', value });
  page.setRequestInterception = async value => order.push({ operation: 'interception', value });
  page.evaluateOnNewDocument = async () => order.push({ operation: 'preload' });
  page.goto = async () => order.push({ operation: 'navigation' });
  return { page, order };
}

test('durable response buffering uses the pinned page CDP session and finite bounds', async () => {
  const { page, order } = pageHarness();
  await configureDurableNetworkMessages(page);
  assert.deepEqual(order, [{ operation: 'cdp', method: 'Network.configureDurableMessages',
    params: { maxTotalBufferSize: 64 * 1024 * 1024, maxResourceBufferSize: 8 * 1024 * 1024 } }]);
  assert.equal(Object.getPrototypeOf(order[0].params), Object.prototype);
  assert.ok(Object.isFrozen(order[0].params));
  assert.deepEqual(DURABLE_NETWORK_LIMITS,
    { maxTotalBufferSize: 64 * 1024 * 1024, maxResourceBufferSize: 8 * 1024 * 1024 });
  assert.ok(Object.isFrozen(DURABLE_NETWORK_LIMITS));
});

test('fixture configures durable bodies before requests on new and reused pages', async () => {
  const { page, order } = pageHarness();
  await configurePage(page, 'http://127.0.0.1:35001', [], []);
  await page.goto();
  assert.equal(order[0].operation, 'cdp');
  assert.ok(order.findIndex(row => row.operation === 'cdp') < order.findIndex(row => row.operation === 'interception'));
  assert.ok(order.findIndex(row => row.operation === 'cdp') < order.findIndex(row => row.operation === 'navigation'));
  await page.goto();
  assert.equal(order.filter(row => row.operation === 'cdp').length, 1,
    'a configured page must retain the same session before later reused-page requests');
});

test('configuration failure propagates before later page setup', async () => {
  const failure = new Error('durable configuration unavailable');
  const { page, order } = pageHarness(async () => { throw failure; });
  await assert.rejects(configurePage(page, 'http://127.0.0.1:35001', [], []), error => error === failure);
  assert.deepEqual(order.map(row => row.operation), ['cdp']);
});

test('invalid bounds and missing pinned Puppeteer client fail closed', async () => {
  const { page } = pageHarness();
  for (const limits of [
    { maxTotalBufferSize: Infinity, maxResourceBufferSize: 1 },
    { maxTotalBufferSize: 1024, maxResourceBufferSize: 2048 },
    { maxTotalBufferSize: 0, maxResourceBufferSize: 0 },
    { maxTotalBufferSize: 64 * 1024 * 1024 + 1, maxResourceBufferSize: 1 },
    { maxTotalBufferSize: 64 * 1024 * 1024, maxResourceBufferSize: 8 * 1024 * 1024 + 1 },
  ]) await assert.rejects(configureDurableNetworkMessages(page, limits), /finite durable network buffer limits/i);
  await assert.rejects(configureDurableNetworkMessages({}), /pinned Puppeteer CDP page client/i);
});

test('buffer limits are read once and the exact validated snapshot is sent', async () => {
  const { page, order } = pageHarness();
  let reads = 0;
  await configureDurableNetworkMessages(page, {
    get maxTotalBufferSize() { reads += 1;return reads === 1 ? 1024 : Infinity; },
    maxResourceBufferSize: 512,
  });
  assert.equal(reads, 1);
  assert.deepEqual(order[0].params, { maxTotalBufferSize: 1024, maxResourceBufferSize: 512 });
});
