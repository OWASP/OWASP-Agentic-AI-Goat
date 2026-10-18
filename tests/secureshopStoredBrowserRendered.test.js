'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('built opaque frame posts, renders, and assesses the exact learner review once', {
  skip: process.env.DVAIA_VERIFY_BUILT_SHOP_FRAME !== '1', timeout: 45000,
}, async t => {
  let server, browser, profile;
  t.after(async () => {
    try { await browser?.close(); }
    finally {
      if (server) await new Promise(resolve => server.close(resolve));
      if (profile) await fs.rm(profile, { recursive: true, force: true });
    }
  });
  const scenarioId = '10000000-0000-4000-8000-000000000041';
  const launch = 'l'.repeat(43); const token = 'owned-shop-token';
  const payload = '<img src="/owned-frame-missing.png" onerror="document.body.dataset.ownedStoredReview=\'1\'">';
  let stored = null; let nativeFormEffects = 0; const requests = []; const attempts = [];
  const app = express(); app.use(express.json());
  app.get('/bridge/:name.mjs', async (req, res) => {
    if (!/^[a-zA-Z]+$/.test(req.params.name)) return res.sendStatus(404);
    try { return res.type('js').send(await fs.readFile(path.join(__dirname,
      '../client/src/pages/secureshop/bridge', `${req.params.name}.mjs`), 'utf8')); }
    catch { return res.sendStatus(404); }
  });
  app.get('/utils/shopStorage.mjs', async (_req, res) => res.type('js').send(
    await fs.readFile(path.join(__dirname,
      '../client/src/pages/secureshop/utils/shopStorage.mjs'), 'utf8')));
  app.get('/', (_req, res) => res.type('html').send(`<!doctype html><body><script type="module">
    import {mountShopFrame} from '/bridge/handshake.mjs';
    import {compileBridgeOperation} from '/bridge/compiler.mjs';
    import {createScopedShopStateStore} from '/bridge/stateStore.mjs';
    const scenario=${JSON.stringify(scenarioId)};
    localStorage.setItem('dvaia:secureshop:'+scenario+':1',JSON.stringify({secureshop_v2_token:${JSON.stringify(token)},ss_guest_cart:null}));
    const frame=document.createElement('iframe');frame.id='shop';
    const stateStore=createScopedShopStateStore({storage:localStorage,scenarioId:scenario,generation:1,isCurrent:()=>true});
    window.host=mountShopFrame({frame,url:'/secureshop-frame.html',origin:location.origin,
      compileOperation:compileBridgeOperation,getLaunchBearer:()=>${JSON.stringify(launch)},stateStore});
    window.host.ready.then(()=>window.connected=true).catch(error=>{window.failed=true;window.failure=String(error)});document.body.append(frame);
  </script></body>`));
  app.use('/api/secureshop', (req, res, next) => {
    requests.push({ method: req.method, path: req.path,
      launch: req.get('x-dvaia-secureshop-launch'), cookie: req.get('cookie') });
    if (req.get('x-dvaia-secureshop-launch') !== launch) return res.sendStatus(401);
    return next();
  });
  app.get('/api/secureshop/v2/auth/whoami', (req, res) => req.get('authorization') === `Bearer ${token}`
    ? res.json({ user: { id: 41, username: 'owned_customer', role: 'customer' },
      expiresAt: new Date(Date.now() + 1800000).toISOString() }) : res.sendStatus(401));
  app.get('/api/secureshop/products', (_req, res) => res.json({ products: [{ id: 7,
    name: 'Owned frame product', description: 'Factual product fixture.', price: 10,
    category: 'Home', stock_quantity: 3, images: [] }], total: 1 }));
  app.get('/api/secureshop/products/7', (_req, res) => res.json({ product: { id: 7,
    name: 'Owned frame product', description: 'Factual product fixture.', price: 10,
    category: 'Home', stock_quantity: 3, images: [] } }));
  app.post('/api/secureshop/products/7/summary', (_req, res) => res.json({ summary: 'Fixture summary.' }));
  app.get('/api/secureshop/products/7/similar', (_req, res) => res.json({ results: [] }));
  app.get('/api/secureshop/products/7/reviews', (_req, res) => res.json({ reviews: stored ? [stored] : [] }));
  app.post('/api/secureshop/products/7/reviews', (req, res) => {
    stored = { id: 51, body: req.body.body, rating: req.body.rating, status: 'pending',
      created_at: '2026-09-13T00:00:00Z' };
    res.json({ ok: true, review_id: 51 });
  });
  app.post('/api/secureshop/products/7/reviews/51/browser-attempt', (req, res) => {
    attempts.push(req.body); res.json({ completed: true });
  });
  app.all('/owned-native-form-sink', (_req, res) => {
    nativeFormEffects += 1; res.sendStatus(204);
  });
  app.use(express.static(path.join(__dirname, '../client/build'), {
    index: false, setHeaders: res => res.set('Access-Control-Allow-Origin', '*'),
  }));
  server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-stored-browser-frame-'));
  browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
    ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) });
  const page = await browser.newPage(); await page.setRequestInterception(true);
  page.on('request', request => request.url().startsWith(origin + '/')
    ? request.continue() : request.abort());
  await page.goto(origin); await page.waitForFunction(() => window.connected === true || window.failed === true);
  assert.equal(await page.evaluate(() => window.failure || null), null);
  const frame = await (await page.$('#shop')).contentFrame();
  await frame.waitForFunction(() => document.body.textContent.includes('Owned frame product'));
  await frame.evaluate(() => [...document.querySelectorAll('a')]
    .find(link => link.textContent.includes('Owned frame product')).click());
  await frame.waitForSelector('textarea[aria-label="Review body"]');
  await frame.$eval('textarea[aria-label="Review body"]', (textarea, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
    setter.call(textarea, value); textarea.dispatchEvent(new Event('input', { bubbles: true }));
  }, payload);
  await frame.waitForFunction(value => {
    const textarea = document.querySelector('textarea[aria-label="Review body"]');
    return textarea?.value === value && textarea.closest('form')?.querySelector('button[type="submit"]')?.disabled === false;
  }, {}, payload);
  await frame.$eval('textarea[aria-label="Review body"]', textarea =>
    textarea.closest('form').querySelector('button[type="submit"]').click());
  const deadline = Date.now() + 8000;
  while (attempts.length === 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 25));
  assert.equal(attempts.length, 1);
  const renderedSink = await frame.evaluate(() => {
    const image = document.querySelector('img[src="/owned-frame-missing.png"]');
    return image ? { html: image.outerHTML, handler: typeof image.onerror,
      executed: document.body.dataset.ownedStoredReview === '1' } : null;
  });
  assert.deepEqual(renderedSink, { html: payload, handler: 'function', executed: true });
  await frame.waitForFunction(() => document.body.textContent.includes('Browser objective completed'));
  assert.equal(stored.body, payload);
  assert.match(attempts[0].request_id, /^[a-f0-9-]{36}$/);
  assert.ok(requests.every(request => request.launch === launch && request.cookie === undefined));
  const frameUrl = frame.url();
  await frame.evaluate(() => {
    const form = document.createElement('form');
    form.method = 'POST'; form.action = '/owned-native-form-sink';
    document.body.append(form); form.submit();
  });
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal(nativeFormEffects, 0, 'frame CSP must block native form transport');
  assert.equal(frame.url(), frameUrl, 'blocked native form must not navigate the frame');
  await page.evaluate(() => window.host.close());
  t.diagnostic('Built opaque-frame React form works through the bridge; CSP blocks native form transport. Fixture endpoint only, no native/Judge claim.');
});
