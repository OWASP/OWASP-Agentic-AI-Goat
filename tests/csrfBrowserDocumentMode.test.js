'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createCsrfBrowserExecutor, BOUNDARY, VICTIM_DOCUMENT_BOUNDARY } = require('../server/services/csrfBrowserExecutor');
const attacker = 'http://attacker.csrf.invalid';
const victim = 'http://victim.csrf.invalid';
const path = '/api/workshop/csrf/agent-action';
const cookie = { name: 'synthetic', value: 'owned-fixture' };

// Controlled transport adapter: these checks establish mode and observation
// contracts, not proof that Chrome executed a learner's document.
function fixture({ mode, frameOrigin, includeCookie = true, hover = false,
  targetBoxes = [{width: 30,height: 20}], actionOnHover = 0, abortOnHover = null,
  actionDuringBoundingAt = null } = {}) {
  let emitAction, hoverCalls = 0, disposed = 0, boundingCalls = 0;
  let navigation, initialHtml, pageClosed = 0, contextClosed = 0;
  const page = new EventEmitter();
  const frame = { url: () => `${frameOrigin || new URL(navigation).origin}/__owasp_ai_goat_csrf_browser_attempt__` };
  Object.assign(page, {
    setBypassServiceWorker: async () => {}, setRequestInterception: async () => {},
    setCookie: async () => {}, mainFrame: () => frame,
    $$: async selector => { assert.equal(selector, '[onmouseover]'); return targetBoxes.map((box, index) => ({
      boundingBox: async () => {
        boundingCalls++;
        if (index === actionDuringBoundingAt) emitAction();
        return box;
      },
      hover: async () => {
        hoverCalls++;
        abortOnHover?.(index);
        if (index === actionOnHover) emitAction();
      },
      dispose: async () => { disposed++; },
    })); },
    close: async () => { pageClosed++; },
    goto: async url => {
      navigation = url;
      const initial = {
        url: () => url, isNavigationRequest: () => true, frame: () => frame,
        respond: async value => { initialHtml = value.body; }, abort: async () => {},
      };
      page.emit('request', initial);
      const action = {
        url: () => `${victim}${path}?tab=xss`, method: () => 'POST',
        postData: () => '{"message":"owned"}', resourceType: () => 'fetch',
        frame: () => frame, isNavigationRequest: () => false,
        headers: () => ({ 'content-type': 'application/json', ...(includeCookie ? { cookie: `${cookie.name}=${cookie.value}` } : {}) }),
        respond: async response => { page.emit('response', { request: () => action, status: () => response.status }); },
        abort: async () => {},
      };
      emitAction = () => page.emit('request', action);
      if (!hover) emitAction();
    },
  });
  const context = { newPage: async () => page, close: async () => { contextClosed++; } };
  const executor = createCsrfBrowserExecutor({ attackerOrigin: attacker, victimOrigin: victim,
    ...(mode === undefined ? {} : { documentOrigin: mode }),
    ...(hover ? { documentInteraction: 'reader-hover' } : {}),
    puppeteer: { launch: async () => ({ createBrowserContext: async () => context, close: async () => {} }) } });
  return { executor, state: () => ({ navigation, initialHtml, pageClosed, contextClosed,
    hoverCalls, boundingCalls, disposed }) };
}

for (const mode of ['attacker', 'victim']) {
  test(`constructor ${mode} mode selects exact document origin and retains response/cookie observation`, async t => {
    const f = fixture({ mode }); t.after(() => f.executor.close());
    let calls = 0;
    const html = '<p>exact selected document</p>';
    const result = await f.executor.execute({ html, victimCookie: cookie,
      documentOrigin: mode === 'victim' ? 'attacker' : 'victim', // ignored public-shaped override
      onRequest: async () => { calls++; return { status: 200, body: 'ok' }; } });
    const expected = mode === 'victim' ? victim : attacker;
    assert.equal(f.state().navigation, `${expected}/__owasp_ai_goat_csrf_browser_attempt__`);
    assert.equal(f.state().initialHtml, html);
    assert.equal(result.observation.frameOrigin, expected);
    assert.equal(result.observation.cookiePresent, true);
    assert.equal(result.responseObserved, true);
    assert.equal(result.boundary, mode === 'victim' ? VICTIM_DOCUMENT_BOUNDARY : BOUNDARY);
    assert.equal(calls, 1);
    assert.equal(f.state().pageClosed, 1); assert.equal(f.state().contextClosed, 1);
    assert(!JSON.stringify(result).includes(cookie.value));
  });
}

test('victim document cannot admit an attacker-frame observation or a missing cookie', async t => {
  for (const scenario of [{ frameOrigin: attacker, code: 'CSRF_BROWSER_WRONG_FRAME' },
    { includeCookie: false, code: 'CSRF_BROWSER_COOKIE_MISSING' }]) {
    const f = fixture({ mode: 'victim', ...scenario }); t.after(() => f.executor.close());
    let calls = 0;
    await assert.rejects(f.executor.execute({ html: '<p>fixture</p>', victimCookie: cookie,
      onRequest: async () => { calls++; return { status: 200 }; } }), { code: scenario.code });
    assert.equal(calls, 0);
    assert.equal(f.state().pageClosed, 1); assert.equal(f.state().contextClosed, 1);
  }
});

test('document origin mode is a closed constructor enum', () => {
  for (const documentOrigin of [null, '', victim, 'VICTIM', {}, true]) {
    assert.throws(() => createCsrfBrowserExecutor({ attackerOrigin: attacker, victimOrigin: victim, documentOrigin }), /document origin mode/);
  }
});


test('victim reader hover uses pointer API and reports observed interaction', async t => {
  const f = fixture({mode: 'victim', hover: true}); t.after(() => f.executor.close());
  let calls = 0;
  const result = await f.executor.execute({html: '<a onmouseover="fixture()">hover</a>', victimCookie: cookie,
    onRequest: async () => { calls++; return {status: 200}; }});
  assert.equal(calls, 1); assert.equal(f.state().hoverCalls, 1); assert.equal(f.state().disposed, 1);
  assert.equal(result.interaction, 'reader-hover'); assert.equal(result.responseObserved, true);
});

test('reader hover skips hidden targets and disposes every acquired handle', async t => {
  const f = fixture({ mode: 'victim', hover: true,
    targetBoxes: [null, { width: 0, height: 20 }, { width: 20, height: 10 }], actionOnHover: 2 });
  t.after(() => f.executor.close());
  const result = await f.executor.execute({ html: '<span hidden onmouseover="x()"></span><a onmouseover="y()">read</a>',
    victimCookie: cookie, onRequest: async () => ({ status: 200 }) });
  assert.equal(result.interaction, 'reader-hover');
  assert.equal(f.state().boundingCalls, 3);
  assert.equal(f.state().hoverCalls, 1);
  assert.equal(f.state().disposed, 3);
});

test('reader hover examines at most eight targets and disposes targets beyond the interaction bound', async t => {
  const f = fixture({ mode: 'victim', hover: true,
    targetBoxes: Array.from({ length: 10 }, () => ({ width: 20, height: 10 })), actionOnHover: 7 });
  t.after(() => f.executor.close());
  const result = await f.executor.execute({ html: '<a onmouseover="x()">read</a>', victimCookie: cookie,
    onRequest: async () => ({ status: 200 }) });
  assert.equal(result.responseObserved, true);
  assert.equal(f.state().boundingCalls, 8);
  assert.equal(f.state().hoverCalls, 8);
  assert.equal(f.state().disposed, 10);
});

test('load action reserved during bounding-box await suppresses pointer hover', async t => {
  const f = fixture({ mode: 'victim', hover: true,
    targetBoxes: [{ width: 20, height: 10 }, { width: 20, height: 10 }],
    actionOnHover: -1, actionDuringBoundingAt: 0 });
  t.after(() => f.executor.close());
  let calls = 0;
  const result = await f.executor.execute({ html: '<a onmouseover="x()">read</a>', victimCookie: cookie,
    onRequest: async () => { calls++; return { status: 200 }; } });
  assert.equal(calls, 1);
  assert.equal(result.interaction, 'load');
  assert.equal(f.state().boundingCalls, 1);
  assert.equal(f.state().hoverCalls, 0);
  assert.equal(f.state().disposed, 2);
});

test('abort during reader hover rejects and still disposes handles, page and context', async t => {
  const controller = new AbortController();
  const reason = Object.assign(new Error('controlled hover abort'), { name: 'AbortError' });
  const f = fixture({ mode: 'victim', hover: true,
    targetBoxes: [{ width: 20, height: 10 }, { width: 20, height: 10 }], actionOnHover: -1,
    abortOnHover: index => { if (index === 0) controller.abort(reason); } });
  t.after(() => f.executor.close());
  await assert.rejects(f.executor.execute({ html: '<a onmouseover="x()">read</a>', victimCookie: cookie,
    signal: controller.signal, onRequest: async () => ({ status: 200 }) }), error => error === reason);
  assert.equal(f.state().hoverCalls, 1);
  assert.equal(f.state().disposed, 2);
  assert.equal(f.state().pageClosed, 1);
  assert.equal(f.state().contextClosed, 1);
});

test('reader interaction is constructor-only and cannot widen attacker mode', () => {
  for (const documentInteraction of ['click', null, {}, 'reader-hover']) {
    assert.throws(() => createCsrfBrowserExecutor({attackerOrigin: attacker, victimOrigin: victim,
      documentInteraction}), /document interaction/);
  }
});
