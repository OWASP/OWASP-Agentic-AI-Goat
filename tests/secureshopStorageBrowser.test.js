'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

test('actual opaque Chromium frames keep shop state separate while Web Storage is denied', { timeout: 30000 }, async t => {
  const source = await fs.readFile(path.join(__dirname, '../client/src/pages/secureshop/utils/shopStorage.mjs'), 'utf8');
  const secret = crypto.randomBytes(16).toString('hex');
  let browser; let server; let profile;
  t.after(()=>retireFixture(browser,server,profile));

  server = http.createServer((req, res) => {
    if (req.url === '/shopStorage.mjs') {
      // Only this owned test origin serves the pure production module to its
      // opaque fixture. This is not a change to application CORS policy.
      res.writeHead(200, { 'content-type': 'text/javascript', 'access-control-allow-origin': '*' });
      res.end(source); return;
    }
    res.setHeader('content-type', 'text/html');
    if (req.url?.startsWith('/frame')) {
      res.end(`<!doctype html><script type="module">
        import {shopStorage,SHOP_TOKEN_KEY,SHOP_CART_KEY} from '/shopStorage.mjs';
        window.testStorage = shopStorage;
        let denied=false; try { localStorage.getItem('token'); } catch(e) { denied=e.name==='SecurityError'; }
        document.body.dataset.storageDenied=String(denied);
        document.body.dataset.ready='true';
      </script><body>Shop storage fixture</body>`);return;
    }
    if (req.url === '/') {
      res.end(`<!doctype html><script>localStorage.setItem('token',${JSON.stringify(secret)})</script><iframe id="a" sandbox="allow-scripts" src="/frame?a"></iframe><iframe id="b" sandbox="allow-scripts" src="/frame?b"></iframe>`);return;
    }
    res.writeHead(404);res.end();
  });
  await bounded(new Promise((resolve, reject) => { server.once('error', reject);server.listen(0, '127.0.0.1', resolve); }),10000);
  const origin = `http://127.0.0.1:${server.address().port}`;
  profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-shop-storage-browser-'));
  const puppeteer = require('puppeteer');
  browser = await puppeteer.launch({ headless: true, timeout: 15000, protocolTimeout: 15000, userDataDir: profile, ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) });
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
  await page.setRequestInterception(true);
  page.on('request', request => { if (request.url().startsWith(origin + '/')) request.continue(); else request.abort(); });
  await page.goto(origin, { waitUntil: 'networkidle0' });
  const frames = page.frames().filter(frame => frame.url().includes('/frame?'));
  assert.equal(frames.length, 2);
  for (const frame of frames) await frame.waitForFunction(() => document.body.dataset.ready === 'true');
  const first = frames.find(frame => frame.url().endsWith('?a'));
  const second = frames.find(frame => frame.url().endsWith('?b'));
  const result = await first.evaluate(() => {
    testStorage.setItem('secureshop_v2_token', 'shop-only-token');
    testStorage.setItem('ss_guest_cart', '[{"product_id":3,"quantity":2}]');
    let parentDenied = false; let keyDenied = false;
    try { parent.localStorage.getItem('token'); } catch(e) { parentDenied = e.name === 'SecurityError'; }
    try { testStorage.getItem('token'); } catch(e) { keyDenied = e instanceof TypeError; }
    return { localDenied: document.body.dataset.storageDenied, parentDenied, keyDenied,
      token: testStorage.getItem('secureshop_v2_token'), cart: JSON.parse(testStorage.getItem('ss_guest_cart')) };
  });
  assert.deepEqual(result, { localDenied: 'true', parentDenied: true, keyDenied: true, token: 'shop-only-token', cart: [{ product_id: 3, quantity: 2 }] });
  assert.equal(await second.evaluate(() => testStorage.getItem('secureshop_v2_token')), null);
  assert.equal(await page.evaluate(() => localStorage.getItem('token')), secret);
  await first.evaluate(() => testStorage.removeItem('secureshop_v2_token'));
  assert.equal(await first.evaluate(() => testStorage.getItem('secureshop_v2_token')), null);
  assert.ok(await first.evaluate(() => testStorage.getItem('ss_guest_cart')));
});

async function bounded(work, ms=5000) {
  let timer;
  try { return await Promise.race([work, new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned fixture deadline; retain data for outer retirement')),ms);})]); }
  finally { clearTimeout(timer); }
}
async function retireFixture(browser, server, root) {
  const results=await Promise.allSettled([
    bounded(Promise.resolve().then(()=>browser?.close())),
    bounded(Promise.resolve().then(()=>{server?.closeAllConnections();return server?.listening?new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())):undefined;})),
  ]);
  const failures=results.filter(r=>r.status==='rejected').map(r=>r.reason);
  if(failures.length)throw new AggregateError(failures,'Owned cleanup uncertain; fixture retained');
  if(root)await fs.rm(root,{recursive:true,force:true});
}
