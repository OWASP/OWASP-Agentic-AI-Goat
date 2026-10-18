'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { once } = require('node:events');
const { BROWSER_SHA, browserEndpoint } = require('./fullBackendRenderedBranch');
const { cleanBrowserEnvironment } = require('./fullBackendBrowserNetworkPolicy');
const { captureBrowserProcessIdentity } = require('./browserProcessOwnership');

const PROFILE_NAME = 'assessment-browser-profile';
const PROCESS_RECEIPT = 'assessment-browser-process.json';
const CLEANUP_RECEIPT = 'assessment-browser-cleanup.json';

async function createAssessmentDenyProxy() {
  const counters = { denied: 0, connectDenied: 0, upgradeDenied: 0 };
  const sockets = new Set();
  let closed = false;
  const server = http.createServer((_request, response) => {
    counters.denied++;
    response.writeHead(403, { connection: 'close', 'content-type': 'text/plain' });
    response.end('Denied');
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('connect', (_request, socket) => {
    counters.connectDenied++;
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
  });
  server.on('upgrade', (_request, socket) => {
    counters.upgradeDenied++;
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return Object.freeze({
    origin: `http://127.0.0.1:${server.address().port}`,
    counters: () => Object.freeze({ ...counters }),
    async close() {
      if (closed) return;
      closed = true;
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    },
  });
}

function assertProcessAbsent(pid) {
  try { process.kill(pid, 0); }
  catch (error) {
    if (error.code === 'ESRCH') return true;
    throw error;
  }
  return false;
}

async function launchOwnedAssessmentBrowserInternal({ root, admission, owned, signal,
  connect = endpoint => require('puppeteer').connect({ browserWSEndpoint: endpoint, protocolTimeout: 15000 }),
  captureIdentity = captureBrowserProcessIdentity, processAbsent = assertProcessAbsent } = {}, expectedSha256) {
  assert.ok(root && path.isAbsolute(root));
  assert.equal(fs.realpathSync(root), root);
  assert.equal(fs.statSync(root).uid, process.getuid());
  assert.ok(owned && typeof owned.launch === 'function' && typeof owned.stop === 'function');
  assert.equal(typeof connect, 'function');
  assert.equal(typeof captureIdentity, 'function');
  assert.equal(typeof processAbsent, 'function');
  const executable = admission?.executable;
  assert.ok(executable && path.isAbsolute(executable));
  assert.equal(fs.realpathSync(executable), executable);
  assert.match(expectedSha256, /^[0-9a-f]{64}$/);
  assert.equal(createHash('sha256').update(fs.readFileSync(executable)).digest('hex'), expectedSha256);
  signal?.throwIfAborted();

  const profile = path.join(root, PROFILE_NAME);
  const processReceipt = path.join(root, PROCESS_RECEIPT);
  const cleanupReceipt = path.join(root, CLEANUP_RECEIPT);
  for (const candidate of [profile, processReceipt, cleanupReceipt]) {
    assert.equal(fs.existsSync(candidate), false, `${path.basename(candidate)} must be fresh`);
  }
  fs.mkdirSync(profile, { mode: 0o700 });
  assert.equal(fs.statSync(profile).mode & 0o777, 0o700);

  let proxy;
  let deniedListener;
  let reservation;
  let child;
  let endpoint;
  let stderrHandle;
  let stderrListener;
  let closing;
  let canaryConnections = 0;
  const closeServer = server => server
    ? new Promise((resolve, reject) => {
      server.closeAllConnections?.();
      server.close(error => error ? reject(error) : resolve());
    }) : Promise.resolve();
  async function close() {
    if (closing) return closing;
    closing = (async () => {
      signal?.removeEventListener('abort', abort);
      const resources = await Promise.allSettled([
        proxy?.close(), closeServer(deniedListener), closeServer(reservation),
      ]);
      let stopError;
      if (child) {
        try { await owned.stop(child); } catch (error) { stopError = error; }
      }
      if (stderrHandle !== undefined) {
        if (stderrListener) child?.stderr?.removeListener('data', stderrListener);
        fs.closeSync(stderrHandle);
        stderrHandle = undefined;
      }
      let pidAbsent = child === undefined;
      if (child && !stopError) pidAbsent = processAbsent(child.pid) === true;
      const closed = !stopError && pidAbsent && resources.every(result => result.status === 'fulfilled');
      if (closed) fs.rmSync(profile, { recursive: true, force: true });
      fs.writeFileSync(cleanupReceipt, JSON.stringify({ browserPid: child?.pid || null,
        pidAbsent, profileAbsent: !fs.existsSync(profile), closed }), { flag: 'wx', mode: 0o600 });
      if (!closed) {
        const failures = resources.filter(result => result.status === 'rejected').map(result => result.reason);
        if (stopError) failures.push(stopError);
        throw new AggregateError(failures, 'Assessment browser cleanup failed');
      }
    })();
    return closing;
  }
  const abort = () => { void close().catch(() => {}); };

  try {
    proxy = await createAssessmentDenyProxy();
    deniedListener = net.createServer(socket => { canaryConnections++;socket.end(); });
    deniedListener.listen(0, '127.0.0.1');
    await once(deniedListener, 'listening');
    reservation = net.createServer();
    reservation.listen(0, '127.0.0.1');
    await once(reservation, 'listening');
    const devtoolsPort = reservation.address().port;
    await closeServer(reservation);
    reservation = undefined;
    const netLog = path.join(root, 'assessment-browser-netlog.json');
    fs.writeFileSync(netLog, '', { flag: 'wx', mode: 0o600 });
    stderrHandle = fs.openSync(path.join(root, 'assessment-browser-stderr.log'), 'wx', 0o600);
    child = owned.launch(executable, ['--headless', `--remote-debugging-port=${devtoolsPort}`,
      `--user-data-dir=${profile}`, `--proxy-server=${proxy.origin}`, '--proxy-bypass-list=<-loopback>',
      '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      `--log-net-log=${netLog}`, '--net-log-capture-mode=Default', '--disable-background-networking',
      '--disable-component-update', '--disable-default-apps', '--disable-sync', '--no-first-run',
      '--disable-domain-reliability', '--disable-extensions',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', 'about:blank'],
    { cwd: root, env: cleanBrowserEnvironment(root), stdio: ['ignore', 'ignore', 'pipe'] });
    assert.ok(Number.isSafeInteger(child.pid) && child.pid > 0);
    let stderrBytes = 0;
    stderrListener = chunk => {
      if (stderrHandle !== undefined && stderrBytes < 10 * 1024 * 1024) {
        fs.writeSync(stderrHandle, chunk.subarray(0, 10 * 1024 * 1024 - stderrBytes));
      }
      stderrBytes += chunk.length;
    };
    child.stderr.on('data', stderrListener);
    const identity = captureIdentity(child.pid);
    fs.writeFileSync(processReceipt, JSON.stringify({ ...identity, profile,
      executableSha256: expectedSha256 }), { flag: 'wx', mode: 0o600 });
    endpoint = await browserEndpoint(child, signal, 30000, devtoolsPort);
    const browser = await connect(endpoint);
    let page;
    try {
      page = await browser.newPage();
      const before = proxy.counters();
      for (const target of [`http://127.0.0.1:${deniedListener.address().port}/`, 'http://external.invalid/']) {
        const response = await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 10000 });
        assert.equal(response.status(), 403, 'assessment browser proxy must deny every destination');
      }
      assert.equal(canaryConnections, 0, 'assessment browser must not reach another owned loopback listener');
      const after = proxy.counters();
      assert.ok(after.denied >= before.denied + 2);
      fs.writeFileSync(path.join(root, 'assessment-browser-network.json'), JSON.stringify({
        scope: 'secureshop_backend_assessment_browser', canaryUntouched: true,
        deniedSmokeDestinations: 2, counters: after,
      }), { flag: 'wx', mode: 0o600 });
    } finally {
      try { await page?.close(); }
      finally { browser.disconnect(); }
    }
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) signal.throwIfAborted();
    return Object.freeze({ endpoint, close });
  } catch (error) {
    try { await close(); } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'Assessment browser launch and cleanup failed');
    }
    throw error;
  }
}

function launchOwnedAssessmentBrowser(options) {
  return launchOwnedAssessmentBrowserInternal(options, BROWSER_SHA);
}

function launchOwnedAssessmentBrowserForTest(options, expectedSha256) {
  return launchOwnedAssessmentBrowserInternal(options, expectedSha256);
}

module.exports = { launchOwnedAssessmentBrowser, createAssessmentDenyProxy,
  launchOwnedAssessmentBrowserForTest, PROFILE_NAME, PROCESS_RECEIPT, CLEANUP_RECEIPT };
