'use strict';

/**
 * Feasibility proof for a SecureShop opaque-origin iframe boundary.
 *
 * This uses real Chromium execution and the production CORS middleware, but it
 * is not the live SecureShop SPA, a platform session, or a complete postMessage
 * bridge. It proves only the browser primitives exercised below. Production
 * integration still needs authenticated launch state, capability issuance,
 * schema validation, replay/generation fencing, and end-to-end UI qualification.
 * In particular, it does not contain the live app's still-mounted legacy
 * `/api/vulnerabilities` routes, so passing cannot establish whole-app safety.
 */

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createApplicationCors } = require('../server/middleware/applicationCors');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function parentDocument(nonce) {
  const encodedNonce = JSON.stringify(nonce);
  return `<!doctype html>
<meta charset="utf-8">
<title>Opaque frame parent fixture</title>
<div id="parent-marker">SAFE_PARENT</div>
<script>
  localStorage.setItem('platformBearer', 'synthetic-parent-bearer');
  const expectedNonce = ${encodedNonce};
  const allowedOperation = Object.freeze({
    operation: 'asset.read',
    method: 'GET',
    path: '/api/secureshop/opaque/assets/1'
  });
  const state = window.__opaqueState = { accepted: [], rejected: [], evidence: null, evidenceEventOrigin: null };
  const target = document.createElement('iframe');
  const sibling = document.createElement('iframe');
  target.id = 'target-frame';
  target.sandbox = 'allow-scripts';
  target.src = '/malicious?nonce=' + encodeURIComponent(expectedNonce);
  sibling.id = 'sibling-frame';
  sibling.sandbox = 'allow-scripts';
  sibling.src = '/sibling?nonce=' + encodeURIComponent(expectedNonce);

  window.addEventListener('message', event => {
    const message = event.data || {};
    if (message.kind === 'evidence') {
      if (event.source === target.contentWindow && event.origin === 'null') {
        state.evidence = message.value;
        state.evidenceEventOrigin = event.origin;
      }
      return;
    }
    if (message.kind !== 'bridge') return;
    if (event.source !== target.contentWindow) {
      state.rejected.push({ reason: 'source', label: message.label, origin: event.origin });
      return;
    }
    if (event.origin !== 'null') {
      state.rejected.push({ reason: 'origin', label: message.label, origin: event.origin });
      return;
    }
    if (message.nonce !== expectedNonce) {
      state.rejected.push({ reason: 'nonce', label: message.label, origin: event.origin });
      return;
    }
    if (message.operation !== allowedOperation.operation) {
      state.rejected.push({ reason: 'operation', label: message.label, origin: event.origin });
      return;
    }
    if (message.method !== allowedOperation.method) {
      state.rejected.push({ reason: 'method', label: message.label, origin: event.origin });
      return;
    }
    if (message.path !== allowedOperation.path) {
      state.rejected.push({ reason: 'path', label: message.label, origin: event.origin });
      return;
    }
    state.accepted.push({
      label: message.label,
      operation: message.operation,
      method: message.method,
      path: message.path,
      origin: event.origin
    });
  });

  document.body.append(target, sibling);
</script>`;
}

function maliciousDocument() {
  return `<!doctype html>
<meta charset="utf-8">
<script>
  window.__innerExecuted = true;
  (async () => {
    const nonce = new URL(location.href).searchParams.get('nonce');
    const evidence = { origin: self.origin, parentDomBlocked: false, parentStorageBlocked: false, fetchRejected: false };
    try { void parent.document.querySelector('#parent-marker').textContent; }
    catch (error) { evidence.parentDomBlocked = error && error.name === 'SecurityError'; }
    try { void parent.localStorage.getItem('platformBearer'); }
    catch (error) { evidence.parentStorageBlocked = error && error.name === 'SecurityError'; }
    try {
      const response = await fetch('/api/auth/opaque-frame-probe', { method: 'POST', body: 'attempted effect' });
      evidence.fetchStatus = response.status;
    } catch (error) {
      evidence.fetchRejected = true;
      evidence.fetchError = error && error.name;
    }
    parent.postMessage({ kind: 'evidence', value: evidence }, '*');
    const allowed = { kind: 'bridge', operation: 'asset.read', method: 'GET', path: '/api/secureshop/opaque/assets/1' };
    parent.postMessage({ ...allowed, label: 'bad-nonce', nonce: 'attacker-nonce' }, '*');
    parent.postMessage({ ...allowed, label: 'platform-path', nonce, path: '/api/auth/status' }, '*');
    parent.postMessage({ ...allowed, label: 'traversal-path', nonce, path: '/api/secureshop/opaque/../../auth/status' }, '*');
    parent.postMessage({ ...allowed, label: 'encoded-traversal', nonce, path: '/api/secureshop/opaque/%2e%2e/%2e%2e/api/auth/status' }, '*');
    parent.postMessage({ ...allowed, label: 'unexpected-method', nonce, method: 'POST' }, '*');
    parent.postMessage({ ...allowed, label: 'allowed', nonce }, '*');
  })();
</script>`;
}

function siblingDocument() {
  return `<!doctype html>
<meta charset="utf-8">
<script>
  const nonce = new URL(location.href).searchParams.get('nonce');
  parent.postMessage({ kind: 'bridge', label: 'sibling', nonce, operation: 'asset.read', method: 'GET', path: '/api/secureshop/opaque/assets/1' }, '*');
</script>`;
}

test('opaque sandbox frame contains malicious script and CORS blocks its direct platform effect', { timeout: 30_000 }, async (t) => {
  const nonce = crypto.randomBytes(24).toString('base64url');
  const profileParent = await fs.mkdtemp(path.join(os.tmpdir(), 'secureshop-opaque-frame-'));
  const profile = path.join(profileParent, 'chromium-profile');
  const app = express();
  const requests = [];
  let protectedEffects = 0;
  let applicationCors;

  app.use((req, res, next) => {
    if (req.path === '/api/auth/opaque-frame-probe') {
      const record = { method: req.method, origin: req.get('Origin') || null, status: null };
      requests.push(record);
      res.once('finish', () => { record.status = res.statusCode; });
    }
    next();
  });
  app.use((req, res, next) => applicationCors(req, res, next));
  app.get('/parent', (_req, res) => res.type('html').send(parentDocument(nonce)));
  app.get('/malicious', (_req, res) => res.type('html').send(maliciousDocument()));
  app.get('/sibling', (_req, res) => res.type('html').send(siblingDocument()));
  app.post('/api/auth/opaque-frame-probe', express.text(), (_req, res) => {
    protectedEffects += 1;
    res.json({ ok: true });
  });

  const server = http.createServer(app);
  let browser;
  t.after(()=>retireFixture(browser,server,profileParent));
  await bounded(listen(server),10000);
  const origin = `http://127.0.0.1:${server.address().port}`;
  applicationCors = createApplicationCors({
    secureShopOrigins: [origin],
    platformOrigins: [origin],
  });

  const puppeteer = require('puppeteer');
  const launchOptions = {
    headless: true, timeout: 15000, protocolTimeout: 15000,
    userDataDir: profile,
    args: ['--disable-background-networking'],
  };
  assert.equal(launchOptions.args.includes('--no-sandbox'), false);
  browser = await puppeteer.launch(launchOptions);
  assert.equal(browser.process().spawnargs.includes('--no-sandbox'), false);
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
  await page.setRequestInterception(true);
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.protocol === 'about:' || (url.hostname === '127.0.0.1' && url.port === String(server.address().port))) {
      request.continue();
    } else {
      request.abort('blockedbyclient');
    }
  });

  await page.goto(`${origin}/parent`, { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => {
    const state = window.__opaqueState;
    return Boolean(state?.evidence && state.accepted.length === 1 && state.rejected.length === 6);
  }, { timeout: 8_000 });

  const browserProof = await page.evaluate(() => ({
    marker: document.querySelector('#parent-marker').textContent,
    bearer: localStorage.getItem('platformBearer'),
    sandbox: document.querySelector('#target-frame').getAttribute('sandbox'),
    state: window.__opaqueState,
  }));
  const targetFrame = page.frames().find((frame) => frame.url().includes('/malicious?'));
  assert.ok(targetFrame, 'target sandbox frame loaded');
  assert.equal(await targetFrame.evaluate(() => window.__innerExecuted), true);

  assert.equal(browserProof.marker, 'SAFE_PARENT');
  assert.equal(browserProof.bearer, 'synthetic-parent-bearer');
  assert.equal(browserProof.sandbox, 'allow-scripts');
  assert.equal(browserProof.state.evidence.origin, 'null');
  assert.equal(browserProof.state.evidenceEventOrigin, 'null');
  assert.equal(browserProof.state.evidence.parentDomBlocked, true);
  assert.equal(browserProof.state.evidence.parentStorageBlocked, true);
  assert.equal(browserProof.state.evidence.fetchRejected, true);
  assert.deepEqual(browserProof.state.accepted, [
    {
      label: 'allowed',
      operation: 'asset.read',
      method: 'GET',
      path: '/api/secureshop/opaque/assets/1',
      origin: 'null',
    },
  ]);
  assert.deepEqual(
    browserProof.state.rejected.sort((left, right) => left.label.localeCompare(right.label)),
    [
      { reason: 'nonce', label: 'bad-nonce', origin: 'null' },
      { reason: 'path', label: 'encoded-traversal', origin: 'null' },
      { reason: 'path', label: 'platform-path', origin: 'null' },
      { reason: 'source', label: 'sibling', origin: 'null' },
      { reason: 'path', label: 'traversal-path', origin: 'null' },
      { reason: 'method', label: 'unexpected-method', origin: 'null' },
    ].sort((left, right) => left.label.localeCompare(right.label)),
  );
  assert.equal(protectedEffects, 0);
  assert.deepEqual(requests, [{ method: 'POST', origin: 'null', status: 403 }]);
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
