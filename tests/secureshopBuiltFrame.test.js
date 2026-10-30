'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

test('built SecureShop application renders through an opaque acknowledged bridge', {
  skip: process.env.OWASP_AI_GOAT_VERIFY_BUILT_SHOP_FRAME !== '1', timeout: 45000,
}, async t => {
  let server, browser, profile;
  t.after(async () => {
    try { await browser?.close(); }
    finally {
      if (server) await new Promise(resolve => server.close(resolve));
      if (profile) await fs.rm(profile, { recursive: true, force: true });
    }
  });
  const app = express();
  app.get('/bridge/:name.mjs', async (req, res) => {
    if (!/^[a-zA-Z]+$/.test(req.params.name)) return res.sendStatus(404);
    const file = path.join(__dirname, '../client/src/pages/secureshop/bridge', `${req.params.name}.mjs`);
    try { res.type('js').send(await fs.readFile(file, 'utf8')); }
    catch { res.sendStatus(404); }
  });
  app.get('/utils/shopStorage.mjs', async (_req, res) => res.type('js').send(
    await fs.readFile(path.join(__dirname, '../client/src/pages/secureshop/utils/shopStorage.mjs'), 'utf8')));
  app.get('/', (_req, res) => res.type('html').send(`<!doctype html><body><script type="module">
    import {mountShopFrame} from '/bridge/handshake.mjs';
    import {compileBridgeOperation} from '/bridge/compiler.mjs';
    import {createScopedShopStateStore} from '/bridge/stateStore.mjs';
    localStorage.setItem('platform-test-secret','parent-only');
    const frame=document.createElement('iframe'); frame.id='shop';
    const stateStore=createScopedShopStateStore({storage:localStorage,
      scenarioId:'11111111-1111-4111-8111-111111111111',generation:1,isCurrent:()=>true});
    window.host=mountShopFrame({frame,url:'/secureshop-frame.html',origin:location.origin,
      compileOperation:compileBridgeOperation,getLaunchBearer:()=> 'a'.repeat(43),stateStore});
    window.host.ready.then(()=>window.connected=true).catch(()=>window.failed=true);
    document.body.append(frame);
  </script></body>`));
  const requests = [];
  app.use('/api', (req, res) => {
    requests.push({ path: req.path, launch: req.get('x-owasp-ai-goat-secureshop-launch'), cookie: req.get('cookie') });
    if (req.get('x-owasp-ai-goat-secureshop-launch') !== 'a'.repeat(43)) return res.sendStatus(401);
    // UI transport fixture only: this test does not prove database effects.
    if (req.path === '/secureshop/products') return res.json({ products: [{ id: 1,
      name: 'Frame transport product', price: 10, description: 'UI qualification fixture',
      category: 'Electronics', stock: 1 }], total: 1 });
    return res.status(503).json({ error: 'Outside UI transport fixture' });
  });
  app.use(express.static(path.join(__dirname, '../client/build'), {
    index: false, setHeaders: res => res.set('Access-Control-Allow-Origin', '*'),
  }));
  server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-built-shop-frame-'));
  browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
    ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) });
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on('request', request => request.url().startsWith(origin + '/') ? request.continue() : request.abort());
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.waitForFunction(() => window.connected === true);
  const frame = await (await page.$('#shop')).contentFrame();
  await frame.waitForFunction(() => document.body.textContent.includes('Frame transport product'));
  assert.equal(await frame.evaluate(() => {
    try { return parent.localStorage.getItem('platform-test-secret'); }
    catch (error) { return error.name; }
  }), 'SecurityError');
  assert.equal(await frame.evaluate(() => window.origin), 'null');
  assert.ok(requests.length > 0);
  assert.ok(requests.every(request => request.launch === 'a'.repeat(43) && request.cookie === undefined));
  assert.deepEqual(errors, []);
  await page.evaluate(() => window.host.close());
});
