const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
const buildUploadsRouter = require('../server/routes/secureshop/uploads');
const { createApplicationCors } = require('../server/middleware/applicationCors');
const { createUploadTools } = require('../agent-host/agents/uploads/tools');
const { createSecureShopUploadAssetService } = require('../server/services/secureshopUploadAssetService');
const { createSecureShopUploadAssetCapability } = require('../server/services/secureshopUploadAssetCapability');

async function cleanupFixture({root,server,browser}) { return retireFixture(browser,server,root); }

test('actual upload/download route preserves PHP source; acceptance is not server-side execution', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ss-upload-authenticity-'));
  let server;
  let browser;
  t.after(() => cleanupFixture({ root, server, browser }));
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop', buildUploadsRouter({ uploadRoot: root }));
  server = http.createServer(app);
  await bounded(new Promise(resolve => server.listen(0, '127.0.0.1', resolve)),10000);
  const base = `http://127.0.0.1:${server.address().port}`;
  {
    const marker = crypto.randomBytes(16).toString('hex');
    // Harmless source, never invoking a shell or reading any host file.
    const source = `<?php echo "${marker}"; ?>`;
    const form = new FormData();
    form.append('kind', 'avatar');
    form.append('scope_id', '1');
    form.append('file', new Blob([source], { type: 'text/plain' }), 'example.php');
    const response = await fetch(`${base}/api/secureshop/uploads`, { method: 'POST', body: form });
    assert.equal(response.status, 200);
    const uploaded = await response.json();
    assert.equal(uploaded.ok, true);
    assert.equal(uploaded.filename, 'example.php');
    const relative = path.relative(root, uploaded.written_path);
    assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
    assert.equal(await fs.readFile(uploaded.written_path, 'utf8'), source);
    const downloaded = await fetch(`${base}/api/secureshop/uploads/download?id=${encodeURIComponent(relative)}`);
    assert.equal(downloaded.status, 200);
    assert.match(downloaded.headers.get('content-type'), /^application\/x-httpd-php/);
    assert.equal(await downloaded.text(), source, 'the server sends source bytes, not PHP output');
  }
});

test('two routers use their configured roots for concurrent writes, downloads and static reads', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ss-upload-roots-'));
  const previous = process.env.SECURESHOP_UPLOAD_ROOT;
  let server;
  t.after(async () => {
    if (previous === undefined) delete process.env.SECURESHOP_UPLOAD_ROOT;
    else process.env.SECURESHOP_UPLOAD_ROOT = previous;
    await cleanupFixture({ root, server });
  });
  const roots = { alpha: path.join(root, 'alpha'), beta: path.join(root, 'beta') };
  const app = express();
  app.use(express.json());
  for (const [name, uploadRoot] of Object.entries(roots)) {
    app.use(`/${name}`, buildUploadsRouter({ uploadRoot }));
    await fs.mkdir(path.join(uploadRoot, 'avatars', '1'), { recursive: true });
    await fs.writeFile(path.join(uploadRoot, 'avatars', '1', 'probe.txt'), name);
  }
  // Fail closed if any code accidentally falls back to ambient configuration.
  process.env.SECURESHOP_UPLOAD_ROOT = 'invalid-relative-fallback';
  server = http.createServer(app);
  await bounded(new Promise(resolve => server.listen(0, '127.0.0.1', resolve)),10000);
  const origin = `http://127.0.0.1:${server.address().port}`;
  await Promise.all(Object.keys(roots).map(async name => {
    const content = `${name}-${crypto.randomUUID()}`;
    const response = await fetch(`${origin}/${name}/uploads`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ kind: 'avatar', scope_id: 1, filename: 'new.txt',
        file_bytes_base64: Buffer.from(content).toString('base64'), uploadRoot: roots[name === 'alpha' ? 'beta' : 'alpha'] }),
    });
    assert.equal(response.status, 200);
    const uploaded = await response.json();
    assert.equal(uploaded.ok, true);
    const relative = path.relative(roots[name], uploaded.written_path);
    assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
    assert.equal(await fs.readFile(uploaded.written_path, 'utf8'), content);
    for (const endpoint of ['uploads/download?id=avatars%2F1%2Fprobe.txt', 'uploads/static/avatars/1/probe.txt']) {
      const result = await fetch(`${origin}/${name}/${endpoint}`);
      assert.equal(result.status, 200);
      assert.equal(await result.text(), name);
    }
  }));
});

test('scoped tool construction validates its root but preserves the teaching traversal sink', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ss-upload-traversal-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createUploadTools({ uploadRoot: 'relative' }), /absolute path/);
  const tools = createUploadTools({ uploadRoot: path.join(root, 'uploads') });
  const target = path.join(root, 'synthetic-outside-upload.txt');
  const result = tools.upload_avatar({ user_id: 1, filename: target,
    file_bytes_base64: Buffer.from('owned traversal proof').toString('base64') });
  assert.equal(result.ok, true);
  assert.equal(result.is_traversal, true);
  assert.equal(result.written_path, target);
  assert.equal(await fs.readFile(target, 'utf8'), 'owned traversal proof');
  assert.equal(tools.download({ id: target }).body_utf8, 'owned traversal proof');
});

test('real IPv6 asset listener receives no localhost platform cookie in an opaque iframe', { timeout: 30000 }, async t => {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'ss-upload-ipv6-cookie-'));
  let platform,browser,asset;
  t.after(async()=>{
    const outcomes=await Promise.allSettled([
      bounded(Promise.resolve().then(()=>browser?.close()),10000),
      bounded(Promise.resolve().then(()=>asset?.stop()),10000),
      bounded(Promise.resolve().then(()=>platform?.listening?new Promise((resolve,reject)=>platform.close(error=>error?reject(error):resolve())):undefined),10000)
    ]);
    const failures=outcomes.filter(value=>value.status==='rejected').map(value=>value.reason);
    if(failures.length)throw new AggregateError(failures,'IPv6 asset fixture cleanup failed');
    await fs.rm(root,{recursive:true,force:true});
  });
  const reserve=http.createServer();
  await bounded(new Promise((resolve,reject)=>reserve.once('error',reject).listen(0,'::1',resolve)),10000);
  const assetPort=reserve.address().port;
  await bounded(new Promise((resolve,reject)=>reserve.close(error=>error?reject(error):resolve())),10000);
  const ids={effectId:'00000001-0000-4000-8000-000000000001',operationId:'00000002-0000-4000-8000-000000000002',targetId:'00000003-0000-4000-8000-000000000003',generation:2,sceneId:'00000004-0000-4000-8000-000000000004',sceneGeneration:3,mode:'vuln',modeGeneration:4,modeStamp:'a'.repeat(64)};
  const capability=createSecureShopUploadAssetCapability({secret:'x'.repeat(32),ttlMs:60000});
  const claim=capability.mint(ids),bytes=Buffer.from('<!doctype html><script>parent.postMessage({origin:self.origin},"*")</script>');
  let serves=0;
  asset=createSecureShopUploadAssetService({
    assetHost:'::1',platformHosts:['localhost','127.0.0.1'],port:assetPort,origin:`http://[::1]:${assetPort}`,capability,
    lookup:async()=>({admission:{scope:{}},effect:{effectId:ids.effectId},contentType:'text/html',contentDisposition:'inline; filename="lesson.html"',responseByteCount:bytes.length,responseSha256:crypto.createHash('sha256').update(bytes).digest('hex')}),
    read:async()=>bytes,assertCurrent:async()=>{},recordServe:async()=>{serves++;},createServer:http.createServer
  });
  await bounded(asset.start(),10000);
  platform=http.createServer((_req,res)=>{
    res.setHeader('Set-Cookie','platform_session=synthetic; Path=/; HttpOnly; SameSite=Lax');
    res.setHeader('Content-Type','text/html');
    res.end(`<!doctype html><body><script>window.receipt=null;addEventListener('message',event=>{if(event.origin==='null')window.receipt=event.data});const frame=document.createElement('iframe');frame.id='asset';frame.sandbox='allow-scripts';frame.src=${JSON.stringify(`http://[::1]:${assetPort}${claim.path}`)};document.body.append(frame)</script></body>`);
  });
  await bounded(new Promise((resolve,reject)=>platform.once('error',reject).listen(0,'127.0.0.1',resolve)),10000);
  const platformOrigin=`http://localhost:${platform.address().port}`;
  browser=await require('puppeteer').launch({headless:true,timeout:15000,protocolTimeout:15000,userDataDir:path.join(root,'browser-profile'),args:['--disable-background-networking','--no-proxy-server']});
  assert.equal(browser.process().spawnargs.includes('--no-sandbox'),false);
  const page=await browser.newPage();
  page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
  await page.setRequestInterception(true);
  page.on('request',request=>{
    const url=new URL(request.url());
    if(url.origin===platformOrigin||url.origin===`http://[::1]:${assetPort}`||url.protocol==='about:')request.continue();
    else request.abort('blockedbyclient');
  });
  await page.goto(platformOrigin,{waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>window.receipt!==null);
  assert.deepEqual(await page.evaluate(()=>window.receipt),{origin:'null'});
  assert.equal(serves,1);
  assert.match((await page.cookies(platformOrigin)).map(value=>value.name).join(','),/platform_session/);
  assert.deepEqual(await page.cookies(`http://[::1]:${assetPort}`),[]);
  assert.equal(await page.$eval('#asset',node=>node.getAttribute('sandbox')),'allow-scripts');
});

test('uploaded HTML executes in an opaque frame while identical text stays inert', { timeout: 20000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'ss-upload-browser-'));
  let server;
  let browser;
  t.after(() => cleanupFixture({ root, server, browser }));
  const uploadRoot = path.join(root, 'uploads');
  const app = express();
  let cors;
  let effects = 0;
  const blockedRequests = [];
  const assets = {};
  app.use((req, res, next) => {
    if (req.path === '/api/auth/upload-probe') {
      res.once('finish', () => blockedRequests.push({ origin: req.headers.origin, status: res.statusCode }));
    }
    cors(req, res, next);
  });
  app.use(express.json());
  app.use('/api/secureshop', buildUploadsRouter({ uploadRoot }));
  app.post('/api/auth/upload-probe', (_req, res) => { effects++; res.json({ ok: true }); });
  app.get('/parent/:kind', (req, res) => {
    const asset = assets[req.params.kind];
    if (!asset) return res.sendStatus(404);
    res.type('html').send(`<!doctype html><body><div id="parent-marker">unchanged</div><script>
      localStorage.setItem('synthetic-parent-token', 'parent-only');
      const frame = document.createElement('iframe'); frame.id = 'artifact';
      frame.sandbox = 'allow-scripts'; frame.src = ${JSON.stringify(asset)};
      window.receipt = null;
      addEventListener('message', event => {
        if (event.source === frame.contentWindow && event.origin === 'null') window.receipt = event.data;
      });
      document.body.append(frame);
    </script></body>`);
  });
  server = http.createServer(app);
  await bounded(new Promise(resolve => server.listen(0, '127.0.0.1', resolve)),10000);
  const origin = `http://127.0.0.1:${server.address().port}`;
  cors = createApplicationCors({ secureShopOrigins: [origin], platformOrigins: [origin] });
  {
    const marker = crypto.randomBytes(16).toString('hex');
    const source = `<!doctype html><body><div id="effect">before</div><script>
      (async () => {
        window.__uploadExecuted = ${JSON.stringify(marker)};
        document.getElementById('effect').textContent = window.__uploadExecuted;
        const proof = { marker: window.__uploadExecuted, origin: self.origin };
        try { parent.document.getElementById('parent-marker').textContent = 'changed'; }
        catch (error) { proof.parentDomBlocked = error.name === 'SecurityError'; }
        try { parent.localStorage.getItem('synthetic-parent-token'); }
        catch (error) { proof.parentStorageBlocked = error.name === 'SecurityError'; }
        try { await fetch('/api/auth/upload-probe', { method: 'POST', body: 'synthetic', credentials: 'include' }); }
        catch { proof.fetchBlocked = true; }
        parent.postMessage(proof, '*');
      })();
    </script></body>`;
    for (const kind of ['html', 'txt']) {
      const form = new FormData();
      form.append('kind', 'avatar'); form.append('scope_id', '1');
      form.append('file', new Blob([source], { type: 'text/plain' }), `artifact.${kind}`);
      const response = await fetch(`${origin}/api/secureshop/uploads`, { method: 'POST', body: form });
      assert.equal(response.status, 200);
      const uploaded = await response.json();
      assert.equal(uploaded.ok, true);
      const relative = path.relative(uploadRoot, uploaded.written_path);
      assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
      assert.equal(await fs.readFile(uploaded.written_path, 'utf8'), source);
      assets[kind] = `/api/secureshop/uploads/download?id=${encodeURIComponent(relative)}`;
      const served = await fetch(origin + assets[kind]);
      assert.equal(served.status, 200);
      assert.match(served.headers.get('content-type'), kind === 'html' ? /^text\/html/ : /^text\/plain/);
      assert.equal(await served.text(), source);
    }
    browser = await require('puppeteer').launch({
      headless: true, timeout: 15000, protocolTimeout: 15000, userDataDir: path.join(root, 'browser-profile'), args: ['--disable-background-networking'],
    });
    assert.equal(browser.process().spawnargs.includes('--no-sandbox'), false);
    const page = await browser.newPage();
  page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
    await page.setRequestInterception(true);
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.origin === origin || url.protocol === 'about:') request.continue();
      else request.abort('blockedbyclient');
    });
    await page.goto(`${origin}/parent/html`, { waitUntil: 'networkidle0' });
    await page.waitForFunction(() => window.receipt !== null, { timeout: 5000 });
    const state = await page.evaluate(() => ({
      receipt: window.receipt, marker: document.getElementById('parent-marker').textContent,
      token: localStorage.getItem('synthetic-parent-token'), sandbox: document.getElementById('artifact').getAttribute('sandbox'),
    }));
    assert.deepEqual(state.receipt, { marker, origin: 'null', parentDomBlocked: true, parentStorageBlocked: true, fetchBlocked: true });
    assert.equal(state.marker, 'unchanged'); assert.equal(state.token, 'parent-only');
    assert.equal(state.sandbox, 'allow-scripts');
    const htmlFrame = page.frames().find(frame => frame.url().includes('/uploads/download'));
    assert.equal(await htmlFrame.evaluate(() => document.getElementById('effect').textContent), marker);
    assert.equal(effects, 0);
    assert.deepEqual(blockedRequests, [{ origin: 'null', status: 403 }]);

    await page.goto(`${origin}/parent/txt`, { waitUntil: 'networkidle0' });
    const textFrame = page.frames().find(frame => frame.url().includes('/uploads/download'));
    assert.equal(await textFrame.evaluate(() => window.__uploadExecuted), undefined);
    assert.ok((await textFrame.evaluate(() => document.body.textContent)).includes(marker));
    assert.equal(await page.evaluate(() => window.receipt), null);
    assert.equal(blockedRequests.length, 1);
  }
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
