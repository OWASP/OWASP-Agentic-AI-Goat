'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const express = require('express');
const session = require('express-session');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');
const { JSDOM } = require('../../client/node_modules/jsdom');
const { admitQ05, buildInventory, validateLaunchGrant,
  q05PageTargets, q05AuxiliaryRequestAllowed,
  renderedRowAction, focusQ05MainPage, physicalQ05DeactivationRowAction,
  physicalQ05NamedButton, physicalQ05AccountButton,
  physicalQ05DeactivationButton, deactivationDiscardFact,
  createQ05DeactivationAckCapture, installQ05DeactivationAckObserver,
  q05DeactivationResponseIdentity, installQ05DeactivationBrowserLoss,
  installQ05StudentPasswordBrowserLoss, q05StudentPasswordResponseWitness,
  physicalQ05StudentPasswordButton,
  q05PrimaryErrorFact, closeQ05OwnedServer,
  q05ExactResponseWitness, q05DeactivationFailureFact, q05RecordDeactivationFailure,
  clickNamed, clickInPanel, formForHeading, waitForModalHeadingAbsence,
  remountQ05StudentPasswordAction,
  studentReadbackFlags, formValidityFlags,
  replaceInput } = require('./adminQ05RenderedScenario');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const ROOT = path.resolve(__dirname, '../..');

test('password restage remount waits for one exact enabled rendered student row', async () => {
  const dom = new JSDOM(`<h2>Student Management</h2><table><tbody></tbody></table>`,
    { url: 'http://127.0.0.1:43915/admin/students' });
  Object.defineProperty(dom.window.document.body, 'innerText',
    { get: () => dom.window.document.body.textContent });
  const previousDocument = global.document, previousLocation = global.location;
  global.document = dom.window.document;
  global.location = dom.window.location;
  let readiness;
  const calls = [];
  const page = {
    goto: async (url, options) => calls.push({ url, options }),
    waitForFunction: async (predicate, options, arg) => {
      calls.push({ options, arg });
      if (arg === 'Student Management') {
        assert(predicate(arg));
      } else {
        readiness = () => predicate(arg);
        assert.equal(readiness(), false, 'missing target must not be ready');
        dom.window.document.querySelector('tbody').innerHTML =
          '<tr><td>other</td><td><button>Password</button></td></tr>';
        assert.equal(readiness(), false, 'wrong target must not be ready');
        dom.window.document.querySelector('tbody').innerHTML =
          '<tr><td>synthetic</td><td><button disabled>Password</button></td></tr>';
        assert.equal(readiness(), false, 'disabled action must not be ready');
        dom.window.document.querySelector('tbody').innerHTML =
          '<tr><td>synthetic</td><td><button>Password</button></td></tr>';
        assert.equal(readiness(), true);
      }
      return { dispose: async () => calls.push({ disposed: true }) };
    },
  };
  try {
    await remountQ05StudentPasswordAction(page, 'http://127.0.0.1:43915', 'synthetic');
    assert.equal(calls[0].url, 'http://127.0.0.1:43915/admin/students');
    assert.deepEqual(calls[0].options, { waitUntil: 'domcontentloaded' });
    assert.equal(calls[2].options.timeout, 15000);
    assert(calls.some(call => call.disposed === true));
    dom.window.document.querySelector('tbody').insertAdjacentHTML('beforeend',
      '<tr><td>synthetic</td><td><button>Password</button></td></tr>');
    assert.equal(readiness(), false, 'ambiguous duplicate target must not be ready');
    dom.reconfigure({ url: 'http://127.0.0.1:43915/admin/dashboard' });
    assert.equal(readiness(), false, 'wrong route must not be ready');
  } finally { global.document = previousDocument; global.location = previousLocation; }
});

test('student password pointer is confined to one enabled exact rendered form', async () => {
  const dom = new JSDOM(`<section><h2>Change Student Password</h2><form>
    <button type="submit">Change Password</button></form></section>
    <button>Change Password</button>`);
  const clicked = [];
  const page = { evaluateHandle: async (callback, value) => {
    const prior = global.document;
    global.document = dom.window.document;
    let node;
    try { node = callback(value); } finally { global.document = prior; }
    return { asElement: () => node && ({ click: async options =>
      clicked.push({ text: node.textContent, count: options.clickCount }) }),
    dispose: async () => {} };
  } };
  await physicalQ05StudentPasswordButton(page, 'Change Password', { clickCount: 2 });
  assert.deepEqual(clicked, [{ text: 'Change Password', count: 2 }]);
  dom.window.document.querySelector('form button').disabled = true;
  await assert.rejects(physicalQ05StudentPasswordButton(page, 'Change Password'), /One enabled/);
  dom.window.document.querySelector('form button').disabled = false;
  dom.window.document.querySelector('form').insertAdjacentHTML('beforeend', '<button>Change Password</button>');
  await assert.rejects(physicalQ05StudentPasswordButton(page, 'Change Password'), /One enabled/);
  dom.window.document.querySelector('form button:last-child').remove();
  dom.window.document.querySelector('section').insertAdjacentHTML('beforeend', '<h2>Change Student Password</h2>');
  await assert.rejects(physicalQ05StudentPasswordButton(page, 'Change Password'), /One enabled/);
});

test('student password loss is one exact HTTP 200 response-stage failure with physical request witness', async () => {
  const base = 'http://127.0.0.1:43915';
  const endpoint = '/api/admin/students/19/change-password';
  const client = new EventEmitter(), page = new EventEmitter(), calls = [];
  client.send = async (method, args) => { calls.push({ method, args }); };
  client.detach = async () => {};
  page.createCDPSession = async () => client;
  const observed = q05StudentPasswordResponseWitness(page, base, endpoint);
  const loss = await installQ05StudentPasswordBrowserLoss(page, base, endpoint);
  const event = (id, method, url, status = 200) => ({ requestId: id,
    request: { method, url }, responseStatusCode: status });
  const request = (method, url) => ({ method: () => method, url: () => url });
  const exact = request('POST', `${base}${endpoint}`);
  for (const ignored of [request('GET', `${base}${endpoint}`),
    request('POST', `${base}/api/admin/students/20/change-password`)]) {
    page.emit('request', ignored); page.emit('requestfailed', ignored);
  }
  page.emit('request', exact); page.emit('requestfailed', exact);
  client.emit('Fetch.requestPaused', event('wrong-method', 'GET', `${base}${endpoint}`));
  client.emit('Fetch.requestPaused', event('wrong-target', 'POST', `${base}/api/admin/students/20/change-password`));
  client.emit('Fetch.requestPaused', event('exact', 'POST', `${base}${endpoint}`));
  client.emit('Fetch.requestPaused', event('duplicate', 'POST', `${base}${endpoint}`));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(observed.snapshot(), { browserRequests: 1, browserFailed: 1, browserFinished: 0 });
  assert.deepEqual(loss.snapshot(), { selected: true, failed: 1, failure: false });
  assert.deepEqual(calls.filter(call => call.method === 'Fetch.failRequest').map(call => call.args.requestId), ['exact']);
  await loss.close(); observed.stop();
  assert.equal(client.listenerCount('Fetch.requestPaused'), 0);
  const rejectedClient = new EventEmitter(), rejected = [];
  rejectedClient.send = async (method, args) => { rejected.push({ method, args }); };
  rejectedClient.detach = async () => {};
  const rejectedLoss = await installQ05StudentPasswordBrowserLoss(
    { createCDPSession: async () => rejectedClient }, base, endpoint);
  rejectedClient.emit('Fetch.requestPaused', event('denied', 'POST', `${base}${endpoint}`, 503));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(rejectedLoss.snapshot(), { selected: true, failed: 0, failure: true });
  assert.equal(rejected.some(call => call.method === 'Fetch.failRequest'), false);
  await assert.rejects(rejectedLoss.close());
});

test('Q05 deactivation failure diagnostic counts only exact request outcomes and serializes no secrets', () => {
  const page = new EventEmitter();
  const base = 'http://127.0.0.1:43129';
  const endpoint = '/api/admin/administrators/7';
  const observed = q05ExactResponseWitness(page, base, 'DELETE', endpoint);
  const request = (method, url) => ({ method: () => method, url: () => url });
  const target = request('DELETE', `${base}${endpoint}`);
  const wrongMethod = request('GET', `${base}${endpoint}`);
  const wrongTarget = request('DELETE', `${base}/api/admin/administrators/8`);
  const wrongOrigin = request('DELETE', `http://127.0.0.1:43130${endpoint}`);
  for (const ignored of [wrongMethod, wrongTarget, wrongOrigin]) {
    page.emit('response', { request: () => ignored, status: () => 200 });
    page.emit('requestfinished', ignored);
    page.emit('requestfailed', ignored);
  }
  page.emit('response', { request: () => target, status: () => 200 });
  page.emit('requestfailed', target);
  page.emit('response', { request: () => target, status: () => 503 });
  page.emit('requestfinished', target);
  assert.deepEqual(observed.snapshot(), { response200: 1, responseOther: 1, finished: 1, failed: 1 });
  observed.stop();
  page.emit('requestfailed', target);
  assert.equal(observed.snapshot().failed, 1);

  const secret = 'bearer-never-record-this';
  const fact = q05DeactivationFailureFact({
    browser: { requests: 2, ...observed.snapshot(), targetReadbacks: 0, rosterReads: 1,
      url: secret },
    server: { received: 2, armed: false, validDrops: 1, invalidDrops: 0,
      validStatus200: true, body: secret },
    ui: { dialogPresent: false, unknownNotice: false, rejectedNotice: false,
      successNotice: true, administratorsPanelPresent: true, twoStorageEvents: true,
      text: secret },
  });
  assert.deepEqual(fact.browser, { requests: 2, response200: 1, responseOther: 1,
    finished: 1, failed: 1, targetReadbacks: 0, rosterReads: 1 });
  assert.deepEqual(fact.server, { received: 2, armed: false, validDrops: 1,
    invalidDrops: 0, validStatus200: true });
  assert.equal(JSON.stringify(fact).includes(secret), false);
});

test('Q05 deactivation diagnostic checkpoints primary counts before a stalled browser read', async () => {
  const recorded = [];
  const original = new Error('synthetic primary');
  const began = Date.now();
  await q05RecordDeactivationFailure({ error: original,
    browser: { requests: 1, response200: 1, responseOther: 0, finished: 0,
      failed: 1, targetReadbacks: 0, rosterReads: 0 },
    server: { received: 1, armed: false, validDrops: 1, invalidDrops: 0,
      validStatus200: true },
    observeUi: () => new Promise(() => {}),
    record: async (error, diagnostic) => recorded.push({ error, diagnostic }),
    uiTimeoutMs: 20,
  });
  assert(Date.now() - began < 500, 'Diagnostic browser read must have its own short bound');
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].error, original);
  assert.equal(recorded[0].diagnostic.browser.requests, 1);
  assert.equal(recorded[0].diagnostic.server.validDrops, 1);
  assert.equal(recorded[0].diagnostic.ui, null);
});

test('Q05 primary error receipt records only closed categories and owned numeric location', () => {
  const secret = 'bearer-should-never-be-recorded';
  const error = new Error(`Execution context was destroyed ${secret}`);
  error.name = 'UntrustedError';
  error.code = `UNTRUSTED_${secret}`;
  error.stack = `Error: ${secret}\n    at handler (${require.resolve('./adminQ05RenderedScenario')}:521:17)`;
  const fact = q05PrimaryErrorFact(error);
  assert.deepEqual(fact, { name: 'OtherError', code: null, reason: 'context-destroyed',
    source: { file: 'adminQ05RenderedScenario.js', line: 521, column: 17 } });
  assert(!JSON.stringify(fact).includes(secret));
  for (const [message, reason] of [
    ['Node is detached from document', 'node-detached'],
    ['Frame was detached', 'frame-detached'],
    ['Navigation failed: net::ERR_ABORTED', 'navigation-failed'],
    ['Runtime.callFunctionOn timed out', 'timeout'],
  ]) assert.equal(q05PrimaryErrorFact(new Error(message)).reason, reason);
});

test('Q05 closes only its owned server with an active unfinished HTTP response', async t => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.write('unfinished');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { if (server.listening) server.closeAllConnections(); });
  const responseStarted = new Promise((resolve, reject) => {
    const request = http.get(`http://127.0.0.1:${server.address().port}/`, response => {
      response.on('error', () => {});
      resolve();
    });
    request.on('error', reject);
  });
  await responseStarted;
  await closeQ05OwnedServer(server);
  assert.equal(server.listening, false);
});

test('Q05 owned server close finishes once, rejects a missing callback within five seconds', async () => {
  const events = [];
  const completed = { listening: true,
    close(callback) { events.push('close'); callback(); },
    closeAllConnections() { events.push('connections'); } };
  await closeQ05OwnedServer(completed, { timeoutMs: 50 });
  assert.deepEqual(events, ['close', 'connections']);
  await assert.rejects(closeQ05OwnedServer({ listening: true,
    close(callback) { callback(); },
    closeAllConnections() { throw new Error('owned connection retirement failed'); },
  }, { timeoutMs: 50 }), /owned connection retirement failed/);
  let lateCallback;
  const stalled = { listening: true,
    close(callback) { lateCallback = callback; }, closeAllConnections() { events.push('stalled-connections'); } };
  await assert.rejects(closeQ05OwnedServer(stalled, { timeoutMs: 20 }), /timed out/);
  lateCallback();
  assert.deepEqual(events.slice(-1), ['stalled-connections']);
  await assert.rejects(closeQ05OwnedServer(stalled, { timeoutMs: 5001 }), /assert/);
});

test('Q05 admits one armed auxiliary page and denies unarmed or cross-origin pages', () => {
  const unexpected = [];
  const targets = q05PageTargets(target => unexpected.push(target));
  const main = { type: () => 'page' };
  const unarmed = { type: () => 'page' };
  const auxiliary = { type: () => 'page' };
  assert.equal(targets.observe(main), true);
  assert(targets.mainIs(main));
  assert.equal(targets.observe(unarmed), false);
  targets.armAuxiliary();
  assert.equal(targets.observe(auxiliary), true);
  assert(targets.auxiliaryIs(auxiliary));
  assert.equal(targets.observe({ type: () => 'page' }), false);
  targets.closeAuxiliary(auxiliary);
  assert.equal(targets.observe({ type: () => 'page' }), false);
  assert.equal(targets.auxiliaryUsed(), true);
  assert.deepEqual(unexpected.length, 3);
  assert.throws(() => targets.armAuxiliary(), /Only one/);
  const base = 'http://127.0.0.1:34567';
  assert(q05AuxiliaryRequestAllowed(`${base}/api/auth/status`, base));
  assert(q05AuxiliaryRequestAllowed('about:blank', base));
  assert(!q05AuxiliaryRequestAllowed('http://127.0.0.1:34568/api/auth/status', base));
  assert(!q05AuxiliaryRequestAllowed('https://example.invalid/', base));
  assert(!q05AuxiliaryRequestAllowed('garbage', base));
});

test('new account actions use scoped pointer handles and reject ambiguous or disabled controls', async () => {
  const dom = new JSDOM(`<button>Manage Users</button>
    <section id="user-management-students-panel"><table><tr><td>synthetic-target</td><td><button>Lock</button></td></tr></table></section>
    <table><tr><td>synthetic-target</td><td><button>Lock</button></td></tr></table>
    <section aria-label="Confirm account access change"><button>Cancel</button><button>Confirm Lock</button></section>
    <button>Confirm Lock</button>`);
  const clicks = [], disposed = [];
  const page = { evaluateHandle: async (callback, arg) => {
    const prior = global.document;
    global.document = dom.window.document;
    let node;
    try { node = callback(arg); } finally { global.document = prior; }
    return { asElement: () => node && ({ click: async options => {
      clicks.push({ text: node.textContent, clickCount: options?.clickCount || 1 });
    } }), dispose: async () => disposed.push(true) };
  } };
  await physicalQ05NamedButton(page, 'Manage Users');
  await assert.rejects(renderedRowAction(page, 'synthetic-target', 'Lock'), /One enabled/);
  await renderedRowAction(page, 'synthetic-target', 'Lock',
    { within: '#user-management-students-panel' });
  await physicalQ05AccountButton(page, 'Confirm Lock', { clickCount: 2 });
  assert.deepEqual(clicks, [{ text: 'Manage Users', clickCount: 1 },
    { text: 'Lock', clickCount: 1 },
    { text: 'Confirm Lock', clickCount: 2 }]);
  assert.equal(disposed.length, 4);
  dom.window.document.querySelector('[aria-label="Confirm account access change"] button:last-child').disabled = true;
  await assert.rejects(physicalQ05AccountButton(page, 'Confirm Lock'), /One enabled/);
  dom.window.document.querySelector('#user-management-students-panel tr').insertAdjacentHTML('afterend',
    '<tr><td>synthetic-target</td><td><button>Lock</button></td></tr>');
  await assert.rejects(renderedRowAction(page, 'synthetic-target', 'Lock',
    { within: '#user-management-students-panel' }), /One enabled/);
  await assert.rejects(renderedRowAction(page, 'synthetic-target', 'Lock',
    { within: '#wrong-panel' }), /One enabled/);
});

test('administrator deactivation uses only the unique owned dialog and exact server acknowledgement', async () => {
  const dom = new JSDOM(`<section role="dialog" aria-label="Deactivate administrator">
    <button>Cancel</button><button>Confirm deactivation</button></section>
    <section role="dialog" aria-label="Unrelated"><button>Confirm deactivation</button></section>`);
  const clicks = [];
  const page = { bringToFront: async () => clicks.push({ focus: true }),
    waitForFunction: async () => { clicks.push({ visible: true }); return { dispose: async () => {} }; },
    evaluateHandle: async (callback, arg) => {
    const prior = global.document;
    global.document = dom.window.document;
    let node;
    try { node = callback(arg); } finally { global.document = prior; }
    return { asElement: () => node && ({ click: async options => {
      clicks.push({ text: node.textContent, count: options?.clickCount || 1 });
    } }), dispose: async () => {} };
  } };
  await physicalQ05DeactivationButton(page, 'Cancel');
  await physicalQ05DeactivationButton(page, 'Confirm deactivation', { clickCount: 2 });
  assert.deepEqual(clicks, [{ focus: true }, { visible: true }, { text: 'Cancel', count: 1 },
    { focus: true }, { visible: true }, { text: 'Confirm deactivation', count: 2 }]);
  dom.window.document.querySelector('[aria-label="Deactivate administrator"] button:last-child').disabled = true;
  await assert.rejects(physicalQ05DeactivationButton(page, 'Confirm deactivation'), /One enabled/);
  dom.window.document.body.insertAdjacentHTML('beforeend',
    '<section role="dialog" aria-label="Deactivate administrator"><button>Cancel</button></section>');
  await assert.rejects(physicalQ05DeactivationButton(page, 'Cancel'), /One enabled/);

  const endpoint = '/api/admin/administrators/29';
  const valid = JSON.stringify({ success: true, user: { id: 29, is_active: 0 }, permissions: [] });
  assert.deepEqual(deactivationDiscardFact(200, valid, endpoint),
    { status: 200, serverAcknowledgedInactive: true });
  for (const [status, body, path] of [
    [201, valid, endpoint], [200, valid, '/api/admin/students/29'],
    [200, JSON.stringify({ success: false, user: { id: 29, is_active: 0 } }), endpoint],
    [200, JSON.stringify({ success: true, user: { id: 28, is_active: 0 } }), endpoint],
    [200, JSON.stringify({ success: true, user: { id: 29, is_active: 1 } }), endpoint],
    [200, 'x'.repeat(8193), endpoint],
  ]) assert.throws(() => deactivationDiscardFact(status, body, path));
});

test('Q05 deactivation response capture joins split bytes and rejects malformed, oversized or wrong-target ACKs', () => {
  const endpoint = '/api/admin/administrators/29';
  const valid = JSON.stringify({ success: true, user: { id: 29, is_active: 0 } });
  const split = createQ05DeactivationAckCapture(endpoint);
  split.write(Buffer.from(valid.slice(0, -1)));
  assert.deepEqual(split.end(200, Buffer.from(valid.slice(-1))), {
    valid: true, fact: { status: 200, serverAcknowledgedInactive: true }, writes: 1 });
  assert.deepEqual(split.end(200, ''), { valid: false, reason: 'duplicate-end' });
  for (const [body, reason] of [
    ['{broken', 'invalid-ack'],
    [JSON.stringify({ success: true, user: { id: 30, is_active: 0 } }), 'invalid-ack'],
    ['x'.repeat(8193), 'oversize'],
  ]) {
    const capture = createQ05DeactivationAckCapture(endpoint);
    assert.deepEqual(capture.end(200, body), { valid: false, reason, writes: 0 });
  }
  const unsupported = createQ05DeactivationAckCapture(endpoint);
  unsupported.write('{', 'latin1');
  assert.deepEqual(unsupported.end(200, '}'),
    { valid: false, reason: 'unsupported-chunk', writes: 1 });
});

test('Q05 observes actual express-session split ACK while preserving complete HTTP response', async t => {
  const endpoint = '/api/admin/administrators/29';
  const observations = [];
  const app = express();
  app.use((request, response, next) => {
    if (request.method === 'DELETE' && request.path === endpoint)
      installQ05DeactivationAckObserver(request, response, endpoint,
        result => observations.push(result));
    next();
  });
  app.use(session({ secret: 'owned-q05-split-response-control-secret',
    resave: false, saveUninitialized: false }));
  app.get('/seed', (request, response) => {
    request.session.marker = 'owned';
    response.json({ seeded: true });
  });
  app.delete(endpoint, (_request, response) => {
    response.status(200).json({ success: true, user: { id: 29, is_active: 0 }, permissions: [] });
  });
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => closeQ05OwnedServer(server));
  const base = `http://127.0.0.1:${server.address().port}`;
  const seed = await fetch(`${base}/seed`);
  assert.equal(seed.status, 200);
  const cookie = seed.headers.get('set-cookie')?.split(';')[0];
  assert(cookie?.startsWith('connect.sid='));
  const browserOutcome = await fetch(`${base}${endpoint}`, { method: 'DELETE', headers: { cookie } });
  assert.equal(browserOutcome.status, 200);
  assert.deepEqual(await browserOutcome.json(),
    { success: true, user: { id: 29, is_active: 0 }, permissions: [] });
  assert.equal(observations.length, 1);
  assert.deepEqual(observations[0], {
    valid: true, fact: { status: 200, serverAcknowledgedInactive: true }, writes: 1 });
});

test('Q05 pass-through observer contains invalid ACK failures without changing write/end callbacks', async () => {
  const endpoint = '/api/admin/administrators/29';
  for (const body of ['{broken', 'x'.repeat(8193),
    JSON.stringify({ success: true, user: { id: 30, is_active: 0 } })]) {
    const observed = [], sent = [], callbacks = [];
    const request = {};
    const response = { statusCode: 200, getHeader: () => undefined,
      write: (chunk, callback) => { sent.push(chunk); callback(); return false; },
      end: chunk => { sent.push(chunk); return 'original-end'; } };
    installQ05DeactivationAckObserver(request, response, endpoint,
      result => observed.push(result));
    assert.equal(response.write(body, () => callbacks.push('called')), false);
    assert.equal(response.end(), 'original-end');
    assert.deepEqual(callbacks, ['called']);
    assert.equal(observed.length, 1);
    assert.equal(observed[0].valid, false);
    assert.deepEqual(sent, [body, undefined]);
  }
});

test('Q05 browser loss selects only exact response-stage DELETE and fails it once', async () => {
  const base = 'http://127.0.0.1:43915';
  const endpoint = '/api/admin/administrators/29';
  const client = new EventEmitter();
  const calls = [];
  client.send = async (method, args) => { calls.push({ method, args }); };
  client.detach = async () => { calls.push({ method: 'detach' }); };
  const page = { createCDPSession: async () => client };
  const serverSnapshot = () => ({ received: 1, validDrops: 1, invalidDrops: 0 });
  const loss = await installQ05DeactivationBrowserLoss(page, base, endpoint, serverSnapshot);
  const event = (id, method, url, status = 200) => ({ requestId: id,
    request: { method, url }, responseStatusCode: status });
  client.emit('Fetch.requestPaused', event('other-method', 'GET', `${base}${endpoint}`));
  client.emit('Fetch.requestPaused', event('other-target', 'DELETE', `${base}/api/admin/administrators/30`));
  client.emit('Fetch.requestPaused', event('other-origin', 'DELETE', `http://127.0.0.1:43916${endpoint}`));
  client.emit('Fetch.requestPaused', event('selected', 'DELETE', `${base}${endpoint}`));
  client.emit('Fetch.requestPaused', event('second', 'DELETE', `${base}${endpoint}`));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(loss.snapshot(), { selected: true, failed: 1, failure: false });
  assert.deepEqual(calls.filter(call => call.method === 'Fetch.failRequest')
    .map(call => call.args.requestId), ['selected']);
  assert.deepEqual(calls.filter(call => call.method === 'Fetch.continueRequest')
    .map(call => call.args.requestId).sort(),
  ['other-method', 'other-origin', 'other-target', 'second']);
  await loss.close();
  assert.equal(client.listenerCount('Fetch.requestPaused'), 0);
  assert.equal(q05DeactivationResponseIdentity(event('exact', 'DELETE', `${base}${endpoint}`), base, endpoint), true);
  assert.equal(q05DeactivationResponseIdentity(event('wrong', 'GET', `${base}${endpoint}`), base, endpoint), false);
  assert.throws(() => q05DeactivationResponseIdentity(event('bad-status', 'DELETE', `${base}${endpoint}`, 403), base, endpoint));
});

test('Q05 browser loss refuses a non-200 or unvalidated target acknowledgement', async () => {
  const base = 'http://127.0.0.1:43915';
  const endpoint = '/api/admin/administrators/29';
  const event = (id, status) => ({ requestId: id,
    request: { method: 'DELETE', url: `${base}${endpoint}` }, responseStatusCode: status });
  for (const [status, server] of [
    [403, { received: 1, validDrops: 0, invalidDrops: 1 }],
    [200, { received: 1, validDrops: 0, invalidDrops: 1 }],
  ]) {
    const client = new EventEmitter();
    const calls = [];
    client.send = async (method, args) => { calls.push({ method, args }); };
    client.detach = async () => {};
    const loss = await installQ05DeactivationBrowserLoss(
      { createCDPSession: async () => client }, base, endpoint, () => server);
    client.emit('Fetch.requestPaused', event(`denied-${status}`, status));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(loss.snapshot(), { selected: true, failed: 0, failure: true });
    assert.equal(calls.some(call => call.method === 'Fetch.failRequest'), false);
    assert(calls.some(call => call.method === 'Fetch.continueRequest'
      && call.args.requestId === `denied-${status}`));
    await assert.rejects(loss.close());
  }
});

test('Q05 physical deactivation row focuses the admitted main page before pointer input', async () => {
  const dom = new JSDOM(`<section id="user-management-administrators-panel"><table><tr>
    <td>synthetic-admin</td><td><button>Deactivate</button></td></tr></table></section>`);
  const order = [];
  const page = {
    bringToFront: async () => order.push('focus'),
    waitForFunction: async () => {
      order.push('visible');
      return { dispose: async () => order.push('visible-handle-disposed') };
    },
    evaluateHandle: async (callback, arg) => {
      const prior = global.document;
      global.document = dom.window.document;
      let node;
      try { node = callback(arg); } finally { global.document = prior; }
      return { asElement: () => node && ({ click: async () => order.push('physical-click') }),
        dispose: async () => order.push('button-handle-disposed') };
    },
  };
  await physicalQ05DeactivationRowAction(page, 'synthetic-admin');
  assert.deepEqual(order, ['focus', 'visible', 'visible-handle-disposed',
    'physical-click', 'button-handle-disposed']);
  await assert.rejects(physicalQ05DeactivationRowAction({
    ...page, waitForFunction: async () => { throw new Error('not visible'); },
  }, 'synthetic-admin'), /not visible/);
  assert.equal(order.filter(item => item === 'physical-click').length, 1,
    'A non-visible main page must not receive pointer input');
  assert.equal(typeof focusQ05MainPage, 'function');
});

async function temporary(t) {
  assert(path.resolve(os.tmpdir()).startsWith(path.join(ROOT, 'tasks/tmp')),
    'Controlled Q05 tests require the repository wrapper');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'q05-js-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

async function admitted(t) {
  const repo = await temporary(t);
  const buildDirectory = path.join(repo, 'client/build');
  await fs.mkdir(buildDirectory, { recursive: true });
  await fs.writeFile(path.join(buildDirectory, 'index.html'), '<html></html>');
  const run = path.join(repo, 'tasks/qualification/run-abcdef123456');
  const runtime = path.join(run, 'runtime');
  const tempRoot = path.join(runtime, 'tmp/admin-browser-runtime');
  const journalPath = path.join(runtime, 'tmp/admin-browser-resources.json');
  const actual = path.join(repo, 'pinned-chromium');
  const env = {
    ADMIN_Q05_CURRENT_HOST: '1', RUN_ADMIN_PRODUCTION_BROWSER: '1',
    ADMIN_Q05_BUILD_DIRECTORY: buildDirectory,
    ADMIN_Q05_BUILD_SHA256: (await buildInventory(buildDirectory)).sha256,
    ADMIN_Q05_SNAPSHOT_SHA256: 'a'.repeat(64),
    ADMIN_Q05_BROWSER_ACK: path.join(runtime, 'browser-ack.json'),
    ADMIN_Q05_ADMISSION_FD: '3',
    PUPPETEER_EXECUTABLE_PATH: actual,
    DVAIA_CHROMIUM_ACTUAL_EXECUTABLE: actual,
  };
  return { repo, buildDirectory, runtime, tempRoot, journalPath, env,
    q05: admitQ05({ env, repo, journalPath, tempRoot }) };
}

test('Q05 build inventory uses ordinal sorted path→hash JSON and detects drift', async t => {
  const { buildDirectory, q05, env } = await admitted(t);
  await fs.writeFile(path.join(buildDirectory, 'Z.js'), 'upper');
  await fs.writeFile(path.join(buildDirectory, 'a.js'), 'lower');
  await fs.writeFile(path.join(buildDirectory, '_x.js'), 'underscore');
  const expected = Object.fromEntries(['Z.js', '_x.js', 'a.js', 'index.html']
    .map(name => [name, sha(name === 'Z.js' ? 'upper' : name === '_x.js' ? 'underscore'
      : name === 'a.js' ? 'lower' : '<html></html>')]));
  const inventory = await buildInventory(buildDirectory);
  assert.deepEqual(inventory.files, expected);
  assert.equal(inventory.sha256, sha(JSON.stringify(expected)));
  await assert.rejects(q05.verifyBuild(), /pin mismatch/);
  env.ADMIN_Q05_BUILD_SHA256 = inventory.sha256;
  await q05.verifyBuild();
  await fs.writeFile(path.join(buildDirectory, 'a.js'), 'mutated');
  await assert.rejects(q05.verifyBuild(), /pin mismatch/);
  await fs.symlink('index.html', path.join(buildDirectory, 'linked.html'));
  await assert.rejects(buildInventory(buildDirectory), /symlinks/);
});

test('Q05 admission rejects wrong build, profile, ACK and inherited descriptor', async t => {
  const { repo, journalPath, tempRoot, env } = await admitted(t);
  const parse = () => admitQ05({ env, repo, journalPath, tempRoot });
  env.ADMIN_Q05_BUILD_DIRECTORY = path.join(repo, 'client/other');
  assert.throws(parse, /existing build/);
  env.ADMIN_Q05_BUILD_DIRECTORY = path.join(repo, 'client/build');
  env.ADMIN_Q05_BROWSER_ACK = path.join(repo, 'foreign.json');
  assert.throws(parse, /ACK path/);
  env.ADMIN_Q05_BROWSER_ACK = path.join(path.dirname(tempRoot), '..', 'browser-ack.json');
  env.ADMIN_Q05_ADMISSION_FD = '1';
  assert.throws(parse, /admission pipe/);
  env.ADMIN_Q05_ADMISSION_FD = '10';
  assert.doesNotThrow(parse);
  env.ADMIN_Q05_ADMISSION_FD = '20';
  assert.doesNotThrow(parse);
  env.ADMIN_Q05_ADMISSION_FD = '3';
  assert.throws(() => admitQ05({ env, repo, journalPath,
    tempRoot: path.join(repo, 'unrelated/admin-browser-runtime') }), /tmp|private under the run root/);
});

test('Q05 rejects a socket substituted for the Python FIFO admission pipe', async t => {
  const { repo, journalPath, tempRoot, env } = await admitted(t);
  const helper = path.join(ROOT, 'tests/postgres/adminQ05RenderedScenario.js');
  const script = `const {admitQ05}=require(${JSON.stringify(helper)});\n`
    + `(async()=>{const q=admitQ05({env:process.env,repo:process.env.TEST_REPO,`
    + `journalPath:process.env.TEST_JOURNAL,tempRoot:process.env.TEST_TEMP});`
    + `console.log(JSON.stringify({pid:process.pid,parent:process.ppid}));`
    + `const value=await q.consumeLaunchGrant(process.env.TEST_PROFILE);`
    + `console.log(JSON.stringify(value));})().catch(error=>{console.error(error.message);process.exitCode=1});`;
  const profile = path.join(tempRoot, 'chromium-profile');
  const child = spawn(process.execPath, ['-e', script], {
    cwd: ROOT, env: { ...process.env, ...env, TEST_REPO: repo,
      TEST_JOURNAL: journalPath, TEST_TEMP: tempRoot, TEST_PROFILE: profile },
    stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
  });
  const exited = new Promise(resolve => child.once('exit', resolve));
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  await new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = () => stdout.includes('\n') ? resolve()
      : Date.now() - started > 3000 ? reject(new Error('Controlled child did not start'))
      : setTimeout(poll, 10);
    poll();
  });
  const declared = JSON.parse(stdout.split('\n')[0]);
  assert.equal(declared.pid, child.pid);
  assert.equal(declared.parent, process.pid);
  const grant = { version: 1, cohort: 'admin-q05-current-host', launcherPid: process.pid,
    workerPid: child.pid, nonce: 'b'.repeat(64), workspace: repo,
    buildSha256: env.ADMIN_Q05_BUILD_SHA256,
    snapshotSha256: env.ADMIN_Q05_SNAPSHOT_SHA256,
    outerSandbox: 'repository-only', chromium: env.DVAIA_CHROMIUM_ACTUAL_EXECUTABLE,
    profile };
  child.stdio[3].end(JSON.stringify(grant));
  const exit = await exited;
  assert.equal(exit, 1);
  assert.match(stderr, /Q05 admission must be an inherited pipe/);
});

test('Q05 repeatedly consumes and closes real FIFO grants, preserving rejected-grant errors', async t => {
  const { repo, journalPath, tempRoot, env } = await admitted(t);
  const helper = path.join(ROOT, 'tests/postgres/adminQ05RenderedScenario.js');
  const profile = path.join(tempRoot, 'chromium-profile');
  const nodeScript = `const fs=require('node:fs');const {admitQ05}=require(${JSON.stringify(helper)});`
    + `const fd=Number(process.env.ADMIN_Q05_ADMISSION_FD);`
    + `const fdClosed=()=>{try{fs.fstatSync(fd);return false}catch(error){return error.code==='EBADF'}};`
    + `(async()=>{const q=admitQ05({env:process.env,repo:process.env.TEST_REPO,`
    + `journalPath:process.env.TEST_JOURNAL,tempRoot:process.env.TEST_TEMP});`
    + `const admitted=await q.consumeLaunchGrant(process.env.TEST_PROFILE);`
    + `process.stdout.write(JSON.stringify({admitted,fdClosed:fdClosed(),`
    + `fdCleared:!process.env.ADMIN_Q05_ADMISSION_FD}));`
    + `})().catch(error=>{process.stdout.write(JSON.stringify({errorName:error.name,`
    + `errorMessage:error.message,fdClosed:fdClosed(),`
    + `fdCleared:!process.env.ADMIN_Q05_ADMISSION_FD}));process.exitCode=1});`;
  const python = `import json, os, subprocess, sys\n`
    + `results = []\n`
    + `for attempt in range(8):\n`
    + `    read_fd, write_fd = os.pipe()\n`
    + `    child_env = os.environ.copy()\n`
    + `    child_env['ADMIN_Q05_ADMISSION_FD'] = str(read_fd)\n`
    + `    child = subprocess.Popen([os.environ['TEST_NODE_BIN'], '-e', os.environ['TEST_NODE_SCRIPT']], env=child_env, pass_fds=(read_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n`
    + `    os.close(read_fd)\n`
    + `    grant = {'version': 1, 'cohort': 'admin-q05-current-host', 'launcherPid': os.getpid(), 'workerPid': child.pid, 'nonce': 'b'*64, 'workspace': os.environ['TEST_REPO'], 'buildSha256': os.environ['ADMIN_Q05_BUILD_SHA256'], 'snapshotSha256': os.environ['ADMIN_Q05_SNAPSHOT_SHA256'], 'outerSandbox': 'repository-only', 'chromium': os.environ['DVAIA_CHROMIUM_ACTUAL_EXECUTABLE'], 'profile': os.environ['TEST_PROFILE']}\n`
    + `    if attempt == 7: grant['workerPid'] += 1\n`
    + `    os.write(write_fd, json.dumps(grant).encode())\n`
    + `    os.close(write_fd)\n`
    + `    out, err = child.communicate(timeout=5)\n`
    + `    results.append({'code': child.returncode, 'out': out, 'err': err})\n`
    + `print(json.dumps(results))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 20000,
    env: { ...process.env, ...env, TEST_REPO: repo, TEST_JOURNAL: journalPath,
      TEST_TEMP: tempRoot, TEST_PROFILE: profile, TEST_NODE_SCRIPT: nodeScript,
      TEST_NODE_BIN: process.execPath },
  });
  assert.equal(result.status, 0, result.stderr);
  const completed = JSON.parse(result.stdout.trim());
  assert.equal(completed.length, 8);
  for (const accepted of completed.slice(0, 7)) {
    assert.equal(accepted.code, 0, accepted.err);
    assert.deepEqual(JSON.parse(accepted.out), {
      admitted: { admitted: true, nonceSha256: sha('b'.repeat(64)) },
      fdClosed: true, fdCleared: true });
  }
  assert.equal(completed[7].code, 1);
  const denied = JSON.parse(completed[7].out);
  assert.equal(denied.errorName, 'AssertionError');
  assert(!denied.errorMessage.includes('EBADF'));
  assert.equal(denied.fdClosed, true);
  assert.equal(denied.fdCleared, true);
});

test('Q05 launch grant validator binds every exact identity and rejects decoys', async t => {
  const { repo, tempRoot, env } = await admitted(t);
  const context = { repo, buildSha256: env.ADMIN_Q05_BUILD_SHA256,
    snapshotSha256: env.ADMIN_Q05_SNAPSHOT_SHA256,
    chromium: env.DVAIA_CHROMIUM_ACTUAL_EXECUTABLE,
    profile: path.join(tempRoot, 'chromium-profile'), launcherPid: 77, workerPid: 88 };
  const grant = { version: 1, cohort: 'admin-q05-current-host',
    launcherPid: 77, workerPid: 88, nonce: 'b'.repeat(64),
    workspace: repo, buildSha256: context.buildSha256,
    snapshotSha256: context.snapshotSha256, outerSandbox: 'repository-only',
    chromium: context.chromium, profile: context.profile };
  assert.deepEqual(validateLaunchGrant(grant, context), {
    admitted: true, nonceSha256: sha(grant.nonce) });
  for (const [key, replacement] of [
    ['workerPid', 89], ['launcherPid', 78], ['workspace', '/tmp/other'],
    ['buildSha256', 'c'.repeat(64)], ['snapshotSha256', 'd'.repeat(64)],
    ['outerSandbox', 'unsandboxed'], ['profile', '/tmp/foreign'],
    ['chromium', '/tmp/foreign-browser'], ['nonce', 'short'],
  ]) assert.throws(() => validateLaunchGrant({ ...grant, [key]: replacement }, context));
  assert.throws(() => validateLaunchGrant({ ...grant, injected: true }, context));
});

test('manual and student-reset current-host grants are mutually exclusive', async t => {
  const { repo, journalPath, tempRoot, env } = await admitted(t);
  const reset = 'admin-student-reset-current-host';
  const manual = 'admin-q05-current-host';
  const context = { repo, buildSha256: env.ADMIN_Q05_BUILD_SHA256,
    snapshotSha256: env.ADMIN_Q05_SNAPSHOT_SHA256,
    chromium: env.DVAIA_CHROMIUM_ACTUAL_EXECUTABLE,
    profile: path.join(tempRoot, 'chromium-profile'), launcherPid: 77, workerPid: 88 };
  const grant = { version: 1, cohort: manual, launcherPid: 77, workerPid: 88,
    nonce: 'b'.repeat(64), workspace: repo, buildSha256: context.buildSha256,
    snapshotSha256: context.snapshotSha256, outerSandbox: 'repository-only',
    chromium: context.chromium, profile: context.profile };
  assert.throws(() => validateLaunchGrant({ ...grant, cohort: reset }, context));
  assert.deepEqual(validateLaunchGrant({ ...grant, cohort: reset }, { ...context, expectedCohort: reset }),
    { admitted: true, nonceSha256: sha(grant.nonce) });
  assert.throws(() => validateLaunchGrant(grant, { ...context, expectedCohort: reset }));
  assert.throws(() => validateLaunchGrant(grant, { ...context, expectedCohort: 'arbitrary' }));
  env.ADMIN_Q05_COHORT = reset;
  env.ADMIN_STUDENT_RESET_ONLY = '1';
  assert.doesNotThrow(() => admitQ05({ env, repo, journalPath, tempRoot, expectedCohort: reset }));
  assert.throws(() => admitQ05({ env, repo, journalPath, tempRoot }));
  delete env.ADMIN_STUDENT_RESET_ONLY;
  assert.throws(() => admitQ05({ env, repo, journalPath, tempRoot, expectedCohort: reset }));
  delete env.ADMIN_Q05_COHORT;
  assert.doesNotThrow(() => admitQ05({ env, repo, journalPath, tempRoot }));
  assert.throws(() => admitQ05({ env, repo, journalPath, tempRoot, expectedCohort: reset }));
});

test('Q05 rendered click helpers require a unique scoped button', async () => {
  const dom = new JSDOM(`<button>Disable All</button><button>Disable All</button>
    <section aria-label="Confirm all exercise visibility change"><h2>Disable all exercises?</h2>
    <button>Cancel</button><button>Confirm Disable All</button></section>`);
  const page = { evaluate: async (callback, arg) => {
    const prior = global.document;
    global.document = dom.window.document;
    try { return callback(arg); } finally { global.document = prior; }
  } };
  const clicks = [];
  dom.window.document.querySelectorAll('button').forEach(button => button.addEventListener('click',
    () => clicks.push(button.textContent)));
  await assert.rejects(clickNamed(page, 'Disable All'), /One enabled/);
  await clickNamed(page, 'Confirm Disable All', {
    within: '[aria-label="Confirm all exercise visibility change"]' });
  await clickInPanel(page, 'Disable all exercises?', 'Cancel');
  assert.deepEqual(clicks, ['Confirm Disable All', 'Cancel']);
});

test('Q05 self-password modal h2 stays distinct from background h4 with the same label', async () => {
  const dom = new JSDOM(`<section><h4>Change Password</h4><button>Change Password</button></section>
    <section id="modal"><header><h2>Change Password</h2></header><form>
    <input type="password"><button type="button">Cancel</button>
    <button type="submit">Change Password</button></form></section>`);
  const inDocument = callback => {
    const prior = global.document;
    global.document = dom.window.document;
    try { return callback(); } finally { global.document = prior; }
  };
  const page = {
    evaluate: async (callback, arg) => inDocument(() => callback(arg)),
    evaluateHandle: async (callback, arg) => ({ asElement: () => inDocument(() => callback(arg)) }),
    waitForFunction: async (callback, options, arg) => {
      assert.equal(options.timeout, 15000);
      assert.equal(inDocument(() => callback(arg)), false,
        'exiting modal heading must block the background click');
      dom.window.document.querySelector('#modal').remove();
      assert.equal(inDocument(() => callback(arg)), true);
    },
  };
  dom.window.document.querySelector('#modal form').addEventListener('submit', event => event.preventDefault());
  const clicked = [];
  dom.window.document.querySelectorAll('button').forEach(button => button.addEventListener('click',
    () => clicked.push(button.textContent)));
  await assert.rejects(clickInPanel(page, 'Change Password', 'Cancel'), /One enabled/);
  await assert.rejects(formForHeading(page, 'Change Password'), /form required/);
  const form = await formForHeading(page, 'Change Password', { modalHeadingOnly: true });
  assert.equal(form, dom.window.document.querySelector('#modal form'));
  await clickInPanel(page, 'Change Password', 'Cancel', { modalHeadingOnly: true });
  await clickInPanel(page, 'Change Password', 'Change Password', { modalHeadingOnly: true });
  await assert.rejects(clickNamed(page, 'Change Password'), /One enabled/);
  await waitForModalHeadingAbsence(page, 'Change Password');
  await clickNamed(page, 'Change Password');
  assert.deepEqual(clicked, ['Cancel', 'Change Password', 'Change Password']);
});

test('Q05 failed-readback facts distinguish a rendered row from a toast without retaining field values', async () => {
  const dom = new JSDOM(`<h2>Create New Student</h2><p>Created q05-synthetic-1</p>
    <form><input name="email" type="email" value="invalid-email"></form>
    <table><tbody><tr><td>different-student</td></tr></tbody></table>`,
  { url: 'http://127.0.0.1/admin/students' });
  Object.defineProperty(dom.window.document.body, 'innerText', {
    get() { return this.textContent; },
  });
  const page = { evaluate: async (callback, arg) => {
    const priorDocument = global.document;
    const priorLocation = global.location;
    global.document = dom.window.document;
    global.location = dom.window.location;
    try { return callback(arg); }
    finally { global.document = priorDocument; global.location = priorLocation; }
  } };
  assert.deepEqual(await studentReadbackFlags(page, 'q05-synthetic-1'), {
    exactRenderedRow: false, renderedRowCount: 1, bodyContainsSyntheticUsername: true,
    pathname: '/admin/students', createModalStillOpen: true,
    createOutcomeUnknown: false, createOutcomeRejected: false,
  });
  assert.deepEqual(await formValidityFlags(page), {
    pathname: '/admin/students', invalidFieldCount: 1, invalidFieldNames: ['email'],
  });
  dom.window.document.querySelector('tbody td').textContent = 'q05-synthetic-1';
  assert.equal((await studentReadbackFlags(page, 'q05-synthetic-1')).exactRenderedRow, true);
});

test('Q05 input replacement uses physical select-all and fails closed on a stale or invalid field', async () => {
  const { CdpKeyboard } = await import('../../node_modules/puppeteer-core/lib/puppeteer/cdp/Input.js');
  const events = [];
  const element = { value: 'old@example.invalid', validity: { valid: true } };
  let selected = false;
  const keyboard = new CdpKeyboard({ send: async (method, details) => {
    events.push({ method, ...details });
    if (details.commands?.includes('selectAll')) selected = true;
    if (details.code === 'Backspace' && details.type === 'rawKeyDown' && selected) {
      element.value = '';
      selected = false;
    }
  } });
  const calls = [];
  const handle = {
    frame: { page: () => ({ keyboard }) },
    click: async () => { calls.push('click'); },
    type: async value => { calls.push('type'); element.value += value; },
    evaluate: async callback => callback(element),
  };
  await replaceInput(handle, 'new@example.invalid');
  assert.deepEqual(calls, ['click', 'type']);
  const modifier = process.platform === 'darwin' ? 'Meta' : 'Control';
  const modifierBit = process.platform === 'darwin' ? 4 : 2;
  assert(events.some(event => event.code === 'KeyA' && event.type === 'rawKeyDown'
    && event.modifiers === modifierBit && event.commands?.includes('selectAll')),
  'installed CDP keyboard must forward selectAll with a held modifier');
  assert(events.some(event => event.code === 'Backspace' && event.type === 'rawKeyDown'
    && event.modifiers === 0), 'Backspace must edit after modifier release');
  assert(events.some(event => event.key === modifier && event.type === 'keyUp'));
  assert.equal(keyboard._modifiers, 0, 'modifier must be released before typing');
  assert.equal(element.value, 'new@example.invalid');
  const stale = { ...handle, type: async () => { element.value = 'old@example.invalid'; } };
  await assert.rejects(replaceInput(stale, 'next@example.invalid'), /did not match/);
  const invalid = { ...handle, type: async value => {
    element.value = value;
    element.validity.valid = false;
  } };
  await assert.rejects(replaceInput(invalid, 'next@example.invalid'), /invalid field/);
  const notCleared = { ...handle, frame: { page: () => ({ keyboard: {
    down: async () => {}, press: async () => {}, up: async () => {},
  } }) } };
  element.value = 'old@example.invalid';
  await assert.rejects(replaceInput(notCleared, 'next@example.invalid'), /not cleared/);
  const released = [];
  const failedHandle = { ...handle, frame: { page: () => ({ keyboard: {
    down: async key => released.push(`down:${key}`),
    press: async () => { throw new Error('key event failed'); },
    up: async key => released.push(`up:${key}`),
  } }) } };
  await assert.rejects(replaceInput(failedHandle, 'next@example.invalid'), /key event failed/);
  assert.deepEqual(released, [`down:${modifier}`, `up:${modifier}`]);
});
