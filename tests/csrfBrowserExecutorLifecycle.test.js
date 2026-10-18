'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createCsrfBrowserExecutor } = require('../server/services/csrfBrowserExecutor');

const ATTACKER = 'http://attacker.lifecycle.invalid';
const VICTIM = 'http://victim.lifecycle.invalid';
const cookie = { name: 'owned_victim', value: 'owned-fixture-cookie' };
const payload = '<p>owned lifecycle fixture</p>';
const callback = async () => ({ status: 200 });

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test('invalid signal is rejected before consuming a concurrency slot', async t => {
  let launches = 0;
  const executor = createCsrfBrowserExecutor({
    attackerOrigin: ATTACKER,
    victimOrigin: VICTIM,
    maxConcurrent: 1,
    puppeteer: { launch: async () => { launches += 1; throw new Error('must not launch'); } },
  });
  t.after(() => executor.close());

  await assert.rejects(executor.execute({ html: payload, victimCookie: cookie, signal: {}, onRequest: callback }), TypeError);
  const controller = new AbortController();
  controller.abort(Object.assign(new Error('owned cancellation'), { name: 'AbortError' }));
  await assert.rejects(executor.execute({ html: payload, victimCookie: cookie, signal: controller.signal, onRequest: callback }), {
    name: 'AbortError',
  });
  assert.equal(launches, 0);
});

test('abort settles while deferred context creation later closes its result', async t => {
  const contextCreation = deferred();
  let contextCloses = 0;
  const browser = { createBrowserContext: () => contextCreation.promise, close: async () => {} };
  const executor = createCsrfBrowserExecutor({
    attackerOrigin: ATTACKER,
    victimOrigin: VICTIM,
    puppeteer: { launch: async () => browser },
  });
  t.after(() => executor.close());
  const controller = new AbortController();
  const pending = executor.execute({ html: payload, victimCookie: cookie, signal: controller.signal, onRequest: callback });
  await new Promise(resolve => setImmediate(resolve));
  controller.abort(Object.assign(new Error('owned cancellation'), { name: 'AbortError' }));
  await assert.rejects(pending, { name: 'AbortError' });
  contextCreation.resolve({ close: async () => { contextCloses += 1; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(contextCloses, 1, 'a context created after cancellation is still disposed');
});

test('abort settles while deferred page creation later closes both page and context', async t => {
  const pageCreation = deferred();
  let pageCloses = 0;
  let contextCloses = 0;
  const context = { newPage: () => pageCreation.promise, close: async () => { contextCloses += 1; } };
  const browser = { createBrowserContext: async () => context, close: async () => {} };
  const executor = createCsrfBrowserExecutor({
    attackerOrigin: ATTACKER,
    victimOrigin: VICTIM,
    puppeteer: { launch: async () => browser },
  });
  t.after(() => executor.close());
  const controller = new AbortController();
  const pending = executor.execute({ html: payload, victimCookie: cookie, signal: controller.signal, onRequest: callback });
  await new Promise(resolve => setImmediate(resolve));
  controller.abort(Object.assign(new Error('owned cancellation'), { name: 'AbortError' }));
  await assert.rejects(pending, { name: 'AbortError' });
  pageCreation.resolve({ close: async () => { pageCloses += 1; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(contextCloses, 1, 'the assigned context closes immediately on cancellation');
  assert.equal(pageCloses, 1, 'a page created after cancellation is still disposed');
});

test('close is terminal, aborts active work and waits for an admitted callback to drain', async () => {
  let requestHandler;
  let pageCloses = 0;
  let contextCloses = 0;
  let browserCloses = 0;
  let callbackEntered;
  let releaseCallback;
  const entered = new Promise(resolve => { callbackEntered = resolve; });
  const callbackGate = new Promise(resolve => { releaseCallback = resolve; });
  const mainFrame = { url: () => `${ATTACKER}/__dvaia_csrf_browser_attempt__` };
  const page = {
    setBypassServiceWorker: async () => {},
    setRequestInterception: async () => {},
    setCookie: async () => {},
    mainFrame: () => mainFrame,
    on(name, handler) { if (name === 'request') requestHandler = handler; },
    off() {},
    async goto() {
      const victimRequest = {
        url: () => `${VICTIM}/api/workshop/csrf/agent-action?tab=post`,
        method: () => 'POST',
        postData: () => 'tab=post&message=held',
        resourceType: () => 'document',
        frame: () => mainFrame,
        headers: () => ({ cookie: `${cookie.name}=${cookie.value}`, 'content-type': 'application/x-www-form-urlencoded' }),
        isNavigationRequest: () => true,
        respond: async () => {},
        abort: async () => {},
      };
      requestHandler(victimRequest);
    },
    close: async () => { pageCloses += 1; },
  };
  const context = { newPage: async () => page, close: async () => { contextCloses += 1; } };
  const browser = { createBrowserContext: async () => context, close: async () => { browserCloses += 1; } };
  const executor = createCsrfBrowserExecutor({
    attackerOrigin: ATTACKER,
    victimOrigin: VICTIM,
    puppeteer: { launch: async () => browser },
  });
  let executeSettled = false;
  const running = executor.execute({
    html: payload,
    victimCookie: cookie,
    onRequest: async () => {
      callbackEntered();
      await callbackGate;
      return { status: 200 };
    },
  });
  running.then(() => { executeSettled = true; }, () => { executeSettled = true; });
  await entered;

  let closeSettled = false;
  const firstClose = executor.close();
  firstClose.then(() => { closeSettled = true; });
  assert.equal(executor.close(), firstClose, 'concurrent close calls share one shutdown');
  await assert.rejects(executor.execute({ html: payload, victimCookie: cookie, onRequest: callback }), {
    code: 'CSRF_BROWSER_CLOSED',
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(closeSettled, false, 'shutdown retains resources while an admitted callback may still hold an effect');
  assert.equal(executeSettled, false);

  releaseCallback();
  await assert.rejects(running, { name: 'AbortError', code: 'CSRF_BROWSER_CLOSED' });
  await firstClose;
  assert.equal(closeSettled, true);
  assert.equal(pageCloses, 1);
  assert.equal(contextCloses, 1);
  assert.equal(browserCloses, 1);
  await executor.close();
  assert.equal(browserCloses, 1, 'completed shutdown remains idempotent');
  await assert.rejects(executor.execute(), { code: 'CSRF_BROWSER_CLOSED' });
});
