'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const { createXssBrowserQualification, MAX_HTML_BYTES } = require('../server/services/xssBrowserQualification');

test('fresh sandboxed browser context reproduces innerHTML event handlers and blocks external requests', async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());
  for (const html of [
    '<img src="https://attacker.invalid/pixel" onerror=alert(document.domain)>',
    '<input onfocus=alert(1)>',
    '<input oninput=alert(5)>',
    '<details ontoggle=alert(2)>test</details>',
    '<svg onmouseover=alert(3)>hover</svg>',
    '<button onclick=alert(6)>click</button>',
    '<a href="javascript:alert(7)">link</a>',
  ]) {
    const result = await runner.qualify(html);
    assert.equal(result.executed, true, `${html}: ${JSON.stringify(result)}`);
    assert.equal(result.syntheticCookieOnly, true);
  }
  const network = await runner.qualify('<img src="https://attacker.invalid/collect" onerror=alert(4)>');
  assert(network.blockedRequests.some(item => item.url === 'https://attacker.invalid/collect'));
  assert.equal(network.elementCount, 1);
});

test('Chrome launches with its sandbox defaults intact', async () => {
  let options;
  const fakeBrowser = { createBrowserContext: async () => { throw new Error('fixture stop'); },
    close: async () => {}, process: () => null };
  const runner = createXssBrowserQualification({ timeoutMs: 500, puppeteer: {
    launch: async value => { options = value; return fakeBrowser; },
  } });
  assert.equal((await runner.qualify('<b>test</b>')).reason, 'qualification_error');
  await runner.close();
  assert.deepEqual(options, { headless: true, timeout: 30000 });
  assert.equal(options.args, undefined);
});

test('cold browser launch has a separate bounded budget and page timeout still starts after launch', async () => {
  let releaseLaunch;
  let releasePage;
  let contextCloses = 0;
  let pagesCreated = 0;
  const page = {
    on() {}, close: async () => {}, setRequestInterception: async () => {}, setCookie: async () => {},
    goto: async () => {}, $eval: async () => {}, $$: async () => [],
    evaluate: async () => ({ cookie: 'qualification_session=synthetic-fixture-only', elementCount: 1, eventAttributes: [] }),
  };
  const browser = {
    createBrowserContext: async () => ({
      newPage: async () => ++pagesCreated === 1 ? page : new Promise(resolve => { releasePage = resolve; }),
      close: async () => { contextCloses++; releasePage?.({}); },
    }),
    close: async () => {},
    process: () => null,
  };
  const runner = createXssBrowserQualification({ timeoutMs: 500, startupTimeoutMs: 1000,
    retirementTimeoutMs: 500, puppeteer: { launch: () => new Promise(resolve => { releaseLaunch = resolve; }) } });
  try {
    let settled = false;
    const pending = runner.qualify('<b>safe</b>').finally(() => { settled = true; });
    await new Promise(resolve => setTimeout(resolve, 600));
    assert.equal(settled, false, 'page budget must not expire while Chrome is launching');
    releaseLaunch(browser);
    const launched = await pending;
    assert.equal(launched.reason, 'no_instrumented_execution');
    const timedOut = await runner.qualify('<b>another</b>');
    assert.equal(timedOut.reason, 'qualification_timeout');
    assert.equal(contextCloses, 2, 'both the successful and timed-out contexts must retire');
  } finally { await runner.close(); }
});

test('externally owned browser connector is exclusive and disconnects without closing or killing', async () => {
  let connected = 0;
  let disconnected = 0;
  let closed = 0;
  let killed = 0;
  const browser = {
    createBrowserContext: async () => { throw new Error('controlled stop'); },
    disconnect: () => { disconnected++; },
    close: async () => { closed++; },
    process: () => ({ kill: () => { killed++; } }),
  };
  assert.throws(() => createXssBrowserQualification({ puppeteer: {}, connectBrowser: async () => browser }),
    /mutually exclusive/);
  assert.throws(() => createXssBrowserQualification({ connectBrowser: true }), /connector/);
  const runner = createXssBrowserQualification({ timeoutMs: 500,
    connectBrowser: async () => { connected++;return browser; } });
  assert.equal((await runner.qualify('<b>test</b>')).reason, 'qualification_error');
  await runner.close();
  assert.equal(connected, 1);
  assert.equal(disconnected, 1);
  assert.equal(closed, 0);
  assert.equal(killed, 0);
});

test('popup effects are observed outside the page and leave no qualification context open', { timeout: 15000 }, async () => {
  const puppeteer = require('puppeteer');
  let launched;
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: {
    launch: async options => { launched = await puppeteer.launch({ ...options, timeout: 15000, protocolTimeout: 15000 }); return launched; },
  } });
  try {
    const result = await runner.qualify('<button onclick="window.open(\'about:blank\')">open</button>');
    assert.ok(result.markers.some(effect => effect.kind === 'window_open'), JSON.stringify(result));
    assert.equal(launched.browserContexts().length, 1, 'fresh context and popup must both be closed after qualification');
  } finally { await runner.close(); }
});

test('module loading is lazy and a missing browser runtime fails qualification closed', async () => {
  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'puppeteer') throw new Error('browser runtime absent');
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    const runner = createXssBrowserQualification({ timeoutMs: 500 });
    const result = await runner.qualify('<img src=x onerror=alert(1)>');
    assert.equal(result.executed, false);
    assert.equal(result.reason, 'qualification_error');
    await runner.close();
  } finally {
    Module._load = originalLoad;
  }
});

test('script tags inserted with innerHTML do not execute and plain markup remains non-executable', async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());
  assert.equal((await runner.qualify('<script>alert(1)</script>')).executed, false);
  assert.equal((await runner.qualify('<b>rendered markup</b>')).executed, false);
});

test('learner element comparison allows presentation attributes but preserves source DOM semantics', { timeout: 15000 }, async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());

  const styled = await runner.qualify('<div class="assistant"><b style="font-family: Arial">hello</b></div>', {
    learnerHtml: '<b>hello</b>',
  });
  assert.equal(styled.learnerElementPreserved, true, JSON.stringify(styled));
  assert.equal(styled.learnerElementTag, 'b');

  const cases = [
    {
      learnerHtml: '<a href="/original">open</a>',
      output: '<a href="/changed">open</a>',
      label: 'changed learner attribute',
    },
    { learnerHtml: '<b>hello</b>', output: '<b style="color:red">goodbye</b>', label: 'changed learner content' },
    { learnerHtml: '<b>hello</b>', output: '&lt;b&gt;hello&lt;/b&gt;', label: 'escaped learner markup' },
    { learnerHtml: '<b>hello</b>', output: '<div><b>unrelated</b><span>hello</span></div>', label: 'unrelated wrapper markup' },
  ];
  for (const fixture of cases) {
    const result = await runner.qualify(fixture.output, { learnerHtml: fixture.learnerHtml });
    assert.equal(result.learnerElementPreserved, false, `${fixture.label}: ${JSON.stringify(result)}`);
  }

  const noInput = await runner.qualify('<b style="font-family:Arial">hello</b>');
  assert.equal(noInput.learnerElementPreserved, false);
  assert.equal(noInput.learnerElementTag, null);
});

test('document renderer proves inline script parsing without attributing sibling handlers', { timeout: 15000 }, async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());
  const script = await runner.qualifyDocument('<script>alert(1)</script>');
  assert.equal(script.executed, true);
  assert.equal(script.scriptExecuted, true);
  assert.equal(script.renderingMode, 'document');

  const sibling = await runner.qualifyDocument(`<script type="application/json">{}</script>
    <img src=x onerror="window.__owasp-ai-goatXssMarkers=[];window.__owasp-ai-goatXssMarkers.push({kind:'script',value:'parser_execution'})">`);
  assert.equal(sibling.executed, false);
  assert.equal(sibling.scriptExecuted, false);
  assert.deepEqual(sibling.markers, [], 'page-owned marker writes are not browser evidence');

  const source = '<script>alert(3)</script>';
  for (const persisted of [
    `<!--${source}--><script>alert(9)</script>`,
    `<template>${source}</template><script>alert(9)</script>`,
    `<textarea>${source}</textarea><script>alert(9)</script>`,
  ]) {
    const contextual = await runner.qualifyDocument(persisted, { scriptSource: source });
    assert.equal(contextual.executed, true, persisted);
    assert.equal(contextual.scriptExecuted, false, persisted);
  }
});

test('innerHTML target attribution rejects inert fields despite an executing sibling handler', { timeout: 15000 }, async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());
  const source = '<img src=x onerror=alert(2)>';
  for (const persisted of [
    `<!--${source}--><img src=x onerror=alert(9)>`,
    `<template>${source}</template><img src=x onerror=alert(9)>`,
    `<textarea>${source}</textarea><img src=x onerror=alert(9)>`,
  ]) {
    const result = await runner.qualify(persisted, { eventSource: source });
    assert.equal(result.executed, false, persisted);
    assert.equal(result.targetEventExecuted, false, persisted);
  }
  const active = await runner.qualify(`<section>${source}</section><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(active.targetEventExecuted, true);

  const copied = `<textarea id="stolen">${source}</textarea>
    <img src=x onerror="const proof=document.querySelector('#stolen').value.match(/globalThis\\.([A-Za-z0-9_]+)\\(String\\(0x([a-f0-9]+)n\\)\\)/);if(proof){this.setAttribute('onerror','globalThis.'+proof[1]+'(String(0x'+proof[2]+'n));alert(99)');this.dispatchEvent(new Event('error'))}">`;
  const spoof = await runner.qualify(copied, { eventSource: source });
  assert.equal(spoof.targetEventExecuted, false, JSON.stringify(spoof));
  assert.equal(spoof.executed, false, 'non-target executable attributes are disabled before live DOM attachment');

  const quoted = await runner.qualify(`<div title='${source}'>safe</div><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(quoted.targetEventExecuted, false, JSON.stringify(quoted));
  assert.equal(quoted.executed, false, 'instrumentation must not change an inert quoted-attribute parse');
});

test('innerHTML target attribution supports javascript URLs in their persisted context', { timeout: 15000 }, async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());
  const source = '<a href="javascript:alert(7)">open</a>';
  const active = await runner.qualify(`<section>${source}</section><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(active.executed, true, JSON.stringify(active));
  assert.equal(active.targetEventExecuted, true, JSON.stringify(active));

  const inert = await runner.qualify(`<textarea>${source}</textarea><img src=x onerror=alert(9)>`, { eventSource: source });
  assert.equal(inert.targetEventExecuted, false, JSON.stringify(inert));
  assert.equal(inert.executed, false, JSON.stringify(inert));

  const bareUrl = 'javascript:alert(8)';
  const substitutedUrl = await runner.qualify(`<a href="${bareUrl}">open</a>`, { eventSource: bareUrl });
  assert.equal(substitutedUrl.targetEventExecuted, true, JSON.stringify(substitutedUrl));

  const breakout = '" onmouseover=alert(3) data-x="';
  const substitutedAttribute = await runner.qualify(`<div title="${breakout}">hover</div>`, { eventSource: breakout });
  assert.equal(substitutedAttribute.targetEventExecuted, true, JSON.stringify(substitutedAttribute));

  const mixedOrigin = '<img src=x onclick="void 0" onerror="alert(4)">';
  const modelOnly = await runner.qualify(mixedOrigin, { eventSources: ['onclick="void 0"'] });
  assert.equal(modelOnly.targetEventExecuted, true, JSON.stringify(modelOnly));
  assert.equal(modelOnly.targetEffectObserved, false, 'profile-owned onerror must be removed from the target projection');

  const fakeEffect = '<img src=x onerror="window.__owasp-ai-goatXssMarkers=[];window.__owasp-ai-goatXssMarkers.push({kind:\'alert\',value:\'1\'})">';
  const forged = await runner.qualify(fakeEffect, { eventSource: fakeEffect });
  assert.equal(forged.targetEventExecuted, true, JSON.stringify(forged));
  assert.equal(forged.targetEffectObserved, false, 'page-owned marker writes cannot impersonate a browser dialog');
});

test('oversized payloads and saturated queues fail closed', async () => {
  const runner = createXssBrowserQualification({
    timeoutMs: 500,
    startupTimeoutMs: 500,
    retirementTimeoutMs: 100,
    maxQueue: 1,
    puppeteer: { launch: () => new Promise(() => {}) },
  });
  const pending = runner.qualify('<img src=x onerror=alert(1)>');
  assert.equal((await runner.qualify('<img src=x onerror=alert(2)>')).reason, 'qualification_queue_full');
  await assert.rejects(pending, { code: 'BROWSER_RETIREMENT_INCOMPLETE' });
  await assert.rejects(runner.qualify('x'), { code: 'BROWSER_RETIREMENT_INCOMPLETE' });
  await assert.rejects(runner.close(), { code: 'BROWSER_RETIREMENT_INCOMPLETE' });
  const fresh = createXssBrowserQualification({ puppeteer: { launch: () => { throw Error('Must not launch'); } } });
  assert.equal((await fresh.qualify('x'.repeat(MAX_HTML_BYTES + 1))).reason, 'invalid_or_oversized_html');
  await fresh.close();
});

test('timeout during CDP setup retires its context before accepting another qualification', async () => {
  let releaseSetup;
  let setupStarted;
  const started = new Promise(resolve => { setupStarted = resolve; });
  let contextsClosed = 0;
  let contextsCreated = 0;
  const page = {
    on() {},
    createCDPSession: async () => ({
      on() {},
      send: async name => {
        if (name === 'Debugger.enable') {
          setupStarted();
          await new Promise(resolve => { releaseSetup = resolve; });
        }
        return { result: [] };
      },
      detach: async () => {},
    }),
    close: async () => {},
    setRequestInterception: async () => {},
    setCookie: async () => {},
    goto: async () => {},
    $eval: async () => {},
    $$: async () => [],
    evaluate: async () => ({ cookie: 'qualification_session=synthetic-fixture-only', elementCount: 1, eventAttributes: [] }),
  };
  const browser = {
    createBrowserContext: async () => {
      contextsCreated++;
      return { newPage: async () => page, close: async () => { contextsClosed++; releaseSetup?.(); } };
    },
    close: async () => {},
    process: () => null,
  };
  const runner = createXssBrowserQualification({ timeoutMs: 500, retirementTimeoutMs: 1000,
    puppeteer: { launch: async () => browser } });
  try {
    const pending = runner.qualifyDocument('<script>alert(1)</script>');
    await started;
    const result = await pending;
    assert.equal(result.reason, 'qualification_timeout');
    assert.equal(contextsClosed, 1);
    const next = await runner.qualify('<b>safe</b>');
    assert.equal(next.reason, 'no_instrumented_execution');
    assert.equal(contextsCreated, 2);
    assert.equal(contextsClosed, 2);
  } finally { await runner.close(); }
});

test('oversized learner comparison source is rejected without changing candidate qualification', { timeout: 15000 }, async t => {
  const runner = createXssBrowserQualification({ timeoutMs: 8000, idleCloseMs: 5000, puppeteer: boundedPuppeteer });
  t.after(() => runner.close());
  const result = await runner.qualify('<b>hello</b>', { learnerHtml: `<b>${'x'.repeat(MAX_HTML_BYTES)}</b>` });
  assert.equal(result.reason, 'no_instrumented_execution');
  assert.equal(result.elementCount, 1);
  assert.equal(result.learnerElementPreserved, false);
  assert.equal(result.learnerElementTag, null);
});

const boundedPuppeteer = { launch: options => require('puppeteer').launch({ ...options, timeout: 15000, protocolTimeout: 15000 }) };
