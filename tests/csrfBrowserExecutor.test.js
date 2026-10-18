'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { randomBytes } = require('node:crypto');
const puppeteer = require('puppeteer');
const { createCsrfBrowserExecutor, BOUNDARY, DEFAULT_MAX_HTML_BYTES, MAX_BLOCKED_REQUESTS } = require('../server/services/csrfBrowserExecutor');

const ATTACKER = 'http://attacker.csrf.invalid';
const VICTIM = 'http://victim.csrf.invalid';
const PATH = '/api/workshop/csrf/agent-action';

async function ownedListener() {
  let hits = 0;
  const server = http.createServer((_req, res) => { hits++; res.end('must not be reached'); });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { url: `http://127.0.0.1:${server.address().port}/escape`, hits: () => hits,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

function cookie() {
  return { name: 'dvaia_csrf_victim', value: randomBytes(24).toString('base64url') };
}

test('real Chrome executes exact form payload once and reports the outgoing ambient cookie without exposing it to the page', { timeout: 30000 }, async t => {
  let browser;
  let launchOptions;
  const executor = createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: VICTIM, victimPath: PATH,
    puppeteer: { launch: async options => { launchOptions = options; browser = await puppeteer.launch(options); return browser; } } });
  t.after(() => executor.close());
  const secretCookie = cookie();
  const nonce = randomBytes(19).toString('hex');
  const html = `<form id="attack" action="${VICTIM}${PATH}?tab=post" method="POST"><input name="message" value="${nonce}"><input id="leak" name="leak"></form><script>document.querySelector('#leak').value=document.cookie;document.querySelector('#attack').submit()</script>`;
  const calls = [];
  const result = await executor.execute({ html, victimCookie: secretCookie, onRequest: async observation => {
    calls.push(observation);
    return { status: 200, contentType: 'text/html; charset=utf-8', body: 'owned action response' };
  } });

  assert.equal(calls.length, 1);
  assert.equal(result.observation, calls[0]);
  assert.equal(result.observation.url, `${VICTIM}${PATH}?tab=post`);
  assert.equal(result.observation.method, 'POST');
  assert.equal(result.observation.resourceType, 'document');
  assert.equal(result.observation.frameOrigin, ATTACKER);
  assert.equal(result.observation.cookiePresent, true, 'proof comes from Puppeteer request.headers().cookie');
  assert.match(result.observation.contentType, /^application\/x-www-form-urlencoded/);
  assert.match(result.observation.postData, new RegExp(`message=${nonce}`));
  assert.match(result.observation.postData, /(?:^|&)leak=(?:&|$)/, 'HttpOnly victim cookie is unavailable to learner JavaScript');
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secretCookie.value));
  assert.equal(result.responseStatus, 200);
  assert.equal(result.responseObserved, true);
  assert.equal(result.boundary, BOUNDARY);
  assert.equal(browser.browserContexts().length, 1, 'fresh attempt context is closed');
  assert.equal(launchOptions.args.some(arg => /no-sandbox|disable-setuid-sandbox/.test(arg)), false);
  assert(launchOptions.args.some(arg => arg.startsWith('--proxy-server=http://127.0.0.1:')));
  assert(launchOptions.args.includes('--proxy-bypass-list=<-loopback>'));
});

test('real Chrome handles JSON preflight without consuming the one allowed action', { timeout: 30000 }, async t => {
  const executor = createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: VICTIM, victimPath: PATH });
  t.after(() => executor.close());
  const marker = randomBytes(17).toString('hex');
  const html = `<script>fetch('${VICTIM}${PATH}?tab=post',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:'${marker}'})})</script>`;
  let calls = 0;
  const result = await executor.execute({ html, victimCookie: cookie(), onRequest: async observation => {
    calls++;
    assert.equal(observation.method, 'POST');
    assert.equal(observation.contentType, 'application/json');
    assert.deepEqual(JSON.parse(observation.postData), { message: marker });
    return { status: 403, contentType: 'application/json', body: '{"blocked":true}' };
  } });
  assert.equal(calls, 1, 'OPTIONS does not consume or invoke the action callback');
  assert.equal(result.responseStatus, 403);
  assert.equal(result.observation.cookiePresent, true);
});

test('network, popup, frame, worker and duplicate action attempts cannot escape the intercepted fixture boundary', { timeout: 30000 }, async t => {
  const external = await ownedListener();
  const executor = createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: VICTIM, victimPath: PATH });
  t.after(async () => { await executor.close(); await external.close(); });
  const target = `${VICTIM}${PATH}?tab=get&message=owned`;
  const noise = Array.from({ length: MAX_BLOCKED_REQUESTS + 20 }, (_, index) => `<img src="${external.url}?noise=${index}">`).join('');
  const html = `<iframe src="${external.url}"></iframe><img src="${external.url}?image">${noise}<script>
    window.open('${external.url}?popup');
    try { const worker=new Worker(URL.createObjectURL(new Blob(["fetch('${external.url}?worker')"],{type:'text/javascript'}))); } catch (_) {}
    setTimeout(()=>{fetch('${target}',{credentials:'include'});fetch('${target}&duplicate=1',{credentials:'include'});},150);
  </script>`;
  let calls = 0;
  const result = await executor.execute({ html, victimCookie: cookie(), onRequest: async () => {
    calls++;
    await new Promise(resolve => setTimeout(resolve, 100));
    return { status: 200, body: 'ok' };
  } });
  assert.equal(calls, 1);
  assert.equal(external.hits(), 0, 'owned external listener receives no browser traffic');
  assert(result.blockedRequests.some(request => request.url.startsWith(external.url)));
  assert.equal(result.blockedRequests.length, MAX_BLOCKED_REQUESTS);
  assert.equal(result.blockedRequestsTruncated, true);
});

test('abort closes the browser context immediately but retains execute until an admitted callback drains', { timeout: 30000 }, async t => {
  let browser;
  const executor = createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: VICTIM, victimPath: PATH,
    puppeteer: { launch: async options => { browser = await puppeteer.launch(options); return browser; } } });
  t.after(() => executor.close());
  const controller = new AbortController();
  let entered;
  let release;
  let settled = false;
  const callbackEntered = new Promise(resolve => { entered = resolve; });
  const callbackGate = new Promise(resolve => { release = resolve; });
  const pending = executor.execute({
    html: `<form action="${VICTIM}${PATH}?tab=post" method="POST"><input name="message" value="held"></form><script>document.forms[0].submit()</script>`,
    victimCookie: cookie(),
    signal: controller.signal,
    onRequest: async () => { entered(); await callbackGate; return { status: 200, body: 'late result' }; },
  });
  pending.then(() => { settled = true; }, () => { settled = true; });
  await callbackEntered;
  controller.abort(Object.assign(new Error('owned reset'), { name: 'AbortError' }));
  for (let index = 0; index < 50 && browser.browserContexts().length !== 1; index++) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(browser.browserContexts().length, 1, 'attempt context closes while callback is still held');
  assert.equal(settled, false, 'outer execution remains pending until admitted callback drains');
  release();
  await assert.rejects(pending, { name: 'AbortError' });
  assert.equal(settled, true);
});

test('abort, deadline and invalid callback output fail closed and clean fresh contexts', { timeout: 30000 }, async t => {
  let browser;
  const executor = createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: VICTIM, victimPath: PATH,
    timeoutMs: 500, puppeteer: { launch: async options => { browser = await puppeteer.launch(options); return browser; } } });
  t.after(() => executor.close());

  const controller = new AbortController();
  const cancelled = executor.execute({ html: '<p>wait forever</p>', victimCookie: cookie(), signal: controller.signal, onRequest: async () => ({ status: 200 }) });
  controller.abort(Object.assign(new Error('owned reset'), { name: 'AbortError' }));
  await assert.rejects(cancelled, { name: 'AbortError' });

  await assert.rejects(executor.execute({ html: '<p>no request</p>', victimCookie: cookie(), onRequest: async () => ({ status: 200 }) }),
    error => error.name === 'AbortError' && error.code === 'CSRF_BROWSER_TIMEOUT');

  await assert.rejects(executor.execute({ html: `<img src="${VICTIM}${PATH}?tab=get&message=x">`, victimCookie: cookie(),
    onRequest: async () => ({ status: 302, body: 'redirect forbidden' }) }), { code: 'CSRF_BROWSER_INVALID_RESPONSE' });
  assert.equal(browser.browserContexts().length, 1);
});

test('constructor and input bounds require an intercepted same-site cross-origin fixture', async () => {
  assert.throws(() => createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: ATTACKER }), /same-site and cross-origin/);
  assert.throws(() => createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: 'http://victim.other.invalid' }), /same-site and cross-origin/);
  assert.throws(() => createCsrfBrowserExecutor({ attackerOrigin: 'http://localhost:3000', victimOrigin: VICTIM }), /origin/);
  const executor = createCsrfBrowserExecutor({ attackerOrigin: ATTACKER, victimOrigin: VICTIM });
  await assert.rejects(executor.execute({ html: 'x'.repeat(DEFAULT_MAX_HTML_BYTES + 1), victimCookie: cookie(), onRequest: async () => ({ status: 200 }) }),
    { code: 'CSRF_BROWSER_INVALID_HTML' });
  await executor.close();
});
