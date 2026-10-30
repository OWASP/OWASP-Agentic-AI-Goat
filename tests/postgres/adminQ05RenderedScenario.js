'use strict';

// A test-only, model-free rendered slice of Q05. The current-host launcher owns
// Chrome process signals, profile retirement, source pins and Docker cleanup.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { readInheritedFifoGrant } = require('../fixtures/inheritedFifoGrant');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const hex = value => /^[0-9a-f]{64}$/.test(value || '');

function q05PrimaryErrorFact(error) {
  const categories = new Set(['Error', 'AssertionError', 'TimeoutError', 'ProtocolError',
    'TypeError', 'TargetCloseError']);
  const codes = new Set(['ECONNRESET', 'ETIMEDOUT', 'ERR_ABORTED',
    'ERR_STREAM_PREMATURE_CLOSE', 'ERR_SERVER_NOT_RUNNING', 'ERR_SOCKET_CLOSED']);
  const name = categories.has(error?.name) ? error.name : 'OtherError';
  const code = codes.has(error?.code) ? error.code : null;
  const message = typeof error?.message === 'string' ? error.message : '';
  const reason = /execution context was destroyed/i.test(message) ? 'context-destroyed'
    : /node is detached|element is not attached/i.test(message) ? 'node-detached'
      : /frame (?:was )?detached|detached frame/i.test(message) ? 'frame-detached'
        : /navigation failed|net::ERR_ABORTED/i.test(message) ? 'navigation-failed'
          : /timed out|timeout/i.test(message) ? 'timeout' : 'other';
  const ownedLine = typeof error?.stack === 'string'
    ? error.stack.split('\n').find(line => line.includes(`${__filename}:`)) : null;
  const location = ownedLine?.match(/:(\d+):(\d+)\)?\s*$/);
  const source = location && Number.isSafeInteger(Number(location[1]))
    && Number.isSafeInteger(Number(location[2]))
    && Number(location[1]) > 0 && Number(location[2]) > 0
    ? { file: 'adminQ05RenderedScenario.js', line: Number(location[1]),
      column: Number(location[2]) } : null;
  return { name, code, reason, source };
}

async function closeQ05OwnedServer(server, { timeoutMs = 5000 } = {}) {
  assert(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 5000);
  if (!server?.listening) return;
  await new Promise((resolve, reject) => {
    let settled = false;
    let closeSetupComplete = false;
    let synchronousCloseError;
    let synchronousCloseCalled = false;
    const finish = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => finish(new Error('Owned Q05 HTTP server close timed out')), timeoutMs);
    try {
      server.close(error => {
        if (!closeSetupComplete) {
          synchronousCloseCalled = true;
          synchronousCloseError = error;
        } else finish(error);
      });
      // After close admission stops, retire only this fixture server's live
      // HTTP connections. The outer launcher still owns the browser process.
      server.closeAllConnections();
      closeSetupComplete = true;
      if (synchronousCloseCalled) finish(synchronousCloseError);
    } catch (error) { finish(error); }
  });
}

function deactivationDiscardFact(status, chunk, endpoint) {
  assert(/^\/api\/admin\/administrators\/[1-9]\d*$/.test(endpoint));
  assert.equal(status, 200, 'Real deactivation must return HTTP 200 before loss');
  assert(typeof chunk === 'string' || Buffer.isBuffer(chunk),
    'Real deactivation must return a bounded JSON acknowledgement');
  assert(Buffer.byteLength(chunk) <= 8192, 'Real deactivation acknowledgement exceeds bounded evidence');
  const body = JSON.parse(Buffer.isBuffer(chunk)
    ? new TextDecoder('utf-8', { fatal: true }).decode(chunk) : chunk);
  assert.equal(body?.success, true, 'Real deactivation must acknowledge success before loss');
  assert.equal(String(body?.user?.id), endpoint.split('/').at(-1));
  assert([0, false].includes(body.user.is_active),
    'Real deactivation must acknowledge inactivity');
  return { status: 200, serverAcknowledgedInactive: true };
}

function createQ05DeactivationAckCapture(endpoint) {
  assert(/^\/api\/admin\/administrators\/[1-9]\d*$/.test(endpoint));
  const chunks = [];
  let bytes = 0, writes = 0, failure = null, ended = false;
  const add = (chunk, encoding) => {
    if (failure || chunk == null) return;
    if (!(typeof chunk === 'string' || Buffer.isBuffer(chunk))
      || (typeof chunk === 'string' && encoding != null
        && (typeof encoding !== 'string'
          || !['utf8', 'utf-8'].includes(encoding.toLowerCase())))) {
      failure = 'unsupported-chunk';
      return;
    }
    const length = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk, 'utf8');
    if (bytes + length > 8192) {
      failure = 'oversize';
      chunks.length = 0;
      return;
    }
    if (length) chunks.push(Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk, 'utf8'));
    bytes += length;
  };
  return {
    write(chunk, encoding) { writes += 1; add(chunk, encoding); },
    end(status, chunk, encoding, contentEncoding) {
      if (ended) return { valid: false, reason: 'duplicate-end' };
      ended = true;
      add(chunk, encoding);
      if (contentEncoding != null && contentEncoding !== 'identity') failure ||= 'encoded-response';
      if (failure) return { valid: false, reason: failure, writes };
      try {
        return { valid: true, fact: deactivationDiscardFact(status, Buffer.concat(chunks, bytes), endpoint),
          writes };
      } catch { return { valid: false, reason: 'invalid-ack', writes }; }
    },
  };
}

function installQ05DeactivationAckObserver(req, res, endpoint, observe) {
  assert.equal(typeof observe, 'function');
  const capture = createQ05DeactivationAckCapture(endpoint);
  const originalWrite = res.write;
  const originalEnd = res.end;
  // Express-session may split JSON between write/end. Observe the complete
  // mounted handler response, preserving the real HTTP bytes and callbacks.
  res.write = function captureWrite(chunk, encoding, callback) {
    const actualEncoding = typeof encoding === 'function' ? undefined : encoding;
    capture.write(chunk, actualEncoding);
    return originalWrite.apply(this, arguments);
  };
  res.end = function observeCompleteAcknowledgement(chunk, encoding) {
    const actualEncoding = typeof encoding === 'function' ? undefined : encoding;
    const result = capture.end(res.statusCode, chunk, actualEncoding,
      res.getHeader('content-encoding'));
    observe(result);
    return originalEnd.apply(this, arguments);
  };
}

function q05DeactivationResponseIdentity(event, base, endpoint) {
  if (event?.request?.method !== 'DELETE' || event.request.url !== `${base}${endpoint}`) return false;
  assert.equal(event.responseStatusCode, 200,
    'Browser loss may only follow the real exact-target HTTP 200');
  return true;
}

async function installQ05DeactivationBrowserLoss(page, base, endpoint, serverSnapshot) {
  assert.equal(typeof serverSnapshot, 'function');
  const client = await page.createCDPSession();
  const tasks = new Set();
  let selected = false, failed = 0, error = null;
  const onPaused = event => {
    const selectedHere = !selected && event?.request?.method === 'DELETE'
      && event.request.url === `${base}${endpoint}`;
    if (selectedHere) selected = true;
    const work = (async () => {
      if (!selectedHere) return client.send('Fetch.continueRequest', { requestId: event.requestId });
      q05DeactivationResponseIdentity(event, base, endpoint);
      const deadline = Date.now() + 2000;
      let state = serverSnapshot();
      while (!state.validDrops && !state.invalidDrops && Date.now() < deadline) {
        await delay(10);
        state = serverSnapshot();
      }
      assert.equal(state.received, 1, 'Exactly one mounted DELETE must reach the server');
      assert.equal(state.validDrops, 1, 'The real exact-target inactive ACK must be validated');
      assert.equal(state.invalidDrops, 0);
      await client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      failed += 1;
    })().catch(async cause => {
      error ||= cause;
      await client.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => {});
    });
    tasks.add(work); void work.finally(() => tasks.delete(work));
  };
  client.on('Fetch.requestPaused', onPaused);
  try {
    await client.send('Fetch.enable', { patterns: [{ urlPattern: `${base}${endpoint}`, requestStage: 'Response' }] });
  } catch (error) { client.off('Fetch.requestPaused', onPaused); await client.detach(); throw error; }
  return { snapshot: () => ({ selected, failed, failure: Boolean(error) }),
    async close() {
      try { await client.send('Fetch.disable'); await Promise.all([...tasks]); }
      finally { client.off('Fetch.requestPaused', onPaused); await client.detach(); }
      if (error) throw error;
    } };
}

async function installQ05StudentPasswordBrowserLoss(page, base, endpoint) {
  assert(/^\/api\/admin\/students\/[1-9]\d*\/change-password$/.test(endpoint));
  const client = await page.createCDPSession();
  const tasks = new Set();
  let selected = false, failed = 0, error = null;
  const onPaused = event => {
    const exact = !selected && event?.request?.method === 'POST'
      && event.request.url === `${base}${endpoint}`;
    if (exact) selected = true;
    const work = (async () => {
      if (!exact) return client.send('Fetch.continueRequest', { requestId: event.requestId });
      assert.equal(event.responseStatusCode, 200,
        'Only the real password-rotation HTTP 200 may be withheld from the browser');
      await client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      failed += 1;
    })().catch(async cause => {
      error ||= cause;
      await client.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => {});
    });
    tasks.add(work); void work.finally(() => tasks.delete(work));
  };
  client.on('Fetch.requestPaused', onPaused);
  try {
    await client.send('Fetch.enable', { patterns: [{ urlPattern: `${base}${endpoint}`, requestStage: 'Response' }] });
  } catch (cause) { client.off('Fetch.requestPaused', onPaused); await client.detach(); throw cause; }
  return { snapshot: () => ({ selected, failed, failure: Boolean(error) }),
    async close() {
      try { await client.send('Fetch.disable'); await Promise.all([...tasks]); }
      finally { client.off('Fetch.requestPaused', onPaused); await client.detach(); }
      if (error) throw error;
    } };
}

function validateLaunchGrant(grant, { repo, buildSha256, snapshotSha256, chromium, profile,
  launcherPid, workerPid, expectedCohort = 'admin-q05-current-host' }) {
  assert(['admin-q05-current-host', 'admin-student-reset-current-host'].includes(expectedCohort),
    'Only the two closed current-host cohorts are admitted');
  assert(grant && typeof grant === 'object' && !Array.isArray(grant));
  assert.deepEqual(Object.keys(grant).sort(), ['version', 'cohort', 'launcherPid', 'workerPid',
    'nonce', 'workspace', 'buildSha256', 'snapshotSha256', 'outerSandbox', 'chromium', 'profile'].sort());
  assert.equal(grant.version, 1);
  assert.equal(grant.cohort, expectedCohort);
  assert.equal(grant.launcherPid, launcherPid);
  assert.equal(grant.workerPid, workerPid);
  assert(/^[0-9a-f]{64}$/.test(grant.nonce));
  assert.equal(grant.workspace, repo);
  assert.equal(grant.buildSha256, buildSha256);
  assert.equal(grant.snapshotSha256, snapshotSha256);
  assert.equal(grant.outerSandbox, 'repository-only');
  assert.equal(grant.chromium, chromium);
  assert.equal(grant.profile, profile);
  return { admitted: true, nonceSha256: sha(grant.nonce) };
}

async function buildInventory(buildDirectory) {
  const root = await fs.realpath(buildDirectory);
  assert.equal(root, buildDirectory, 'Q05 build path must be canonical');
  const entries = {};
  async function walk(directory) {
    for (const item of await fs.readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, item.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      assert(!item.isSymbolicLink(), 'Q05 build symlinks are forbidden');
      if (item.isDirectory()) await walk(absolute);
      else {
        assert(item.isFile(), 'Q05 build special files are forbidden');
        const before = await fs.stat(absolute);
        entries[relative] = sha(await fs.readFile(absolute));
        const after = await fs.stat(absolute);
        assert.equal(after.ino, before.ino, 'Q05 build file replaced during inventory');
        assert.equal(after.size, before.size, 'Q05 build file changed during inventory');
        assert.equal(after.mtimeMs, before.mtimeMs, 'Q05 build file changed during inventory');
      }
    }
  }
  await walk(root);
  assert(entries['index.html'], 'Q05 existing production build requires index.html');
  const ordered = Object.fromEntries(Object.entries(entries).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
  return { files: ordered, sha256: sha(Buffer.from(JSON.stringify(ordered), 'utf8')) };
}

function admitQ05({ env, repo, journalPath, tempRoot,
  expectedCohort = 'admin-q05-current-host' }) {
  assert(['admin-q05-current-host', 'admin-student-reset-current-host'].includes(expectedCohort),
    'Only the two closed current-host cohorts are admitted');
  if (expectedCohort === 'admin-student-reset-current-host') {
    assert.equal(env.ADMIN_Q05_COHORT, expectedCohort);
    assert.equal(env.ADMIN_STUDENT_RESET_ONLY, '1');
  } else {
    assert.ok(env.ADMIN_Q05_COHORT === undefined || env.ADMIN_Q05_COHORT === expectedCohort);
    assert.notEqual(env.ADMIN_STUDENT_RESET_ONLY, '1');
  }
  assert.equal(env.ADMIN_Q05_CURRENT_HOST, '1');
  assert.equal(env.RUN_ADMIN_PRODUCTION_BROWSER, '1');
  const buildDirectory = path.join(repo, 'client/build');
  assert.equal(env.ADMIN_Q05_BUILD_DIRECTORY, buildDirectory, 'Q05 must serve the admitted existing build');
  assert(hex(env.ADMIN_Q05_BUILD_SHA256), 'Q05 existing-build SHA-256 required');
  assert.equal(path.basename(tempRoot), 'admin-browser-runtime');
  assert.equal(path.basename(path.dirname(tempRoot)), 'tmp');
  assert.equal(path.dirname(tempRoot), path.dirname(journalPath),
    'Q05 browser runtime must be private under the run root');
  const ackPath = path.join(path.dirname(tempRoot), '..', 'browser-ack.json');
  assert.equal(env.ADMIN_Q05_BROWSER_ACK, path.normalize(ackPath), 'Q05 ACK path must be exact');
  assert.equal(env.PUPPETEER_EXECUTABLE_PATH, env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE,
    'Q05 must launch the pinned actual Chromium executable');
  assert.equal(typeof env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE, 'string');
  assert(path.isAbsolute(env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE));
  assert(hex(env.ADMIN_Q05_SNAPSHOT_SHA256), 'Q05 current-source snapshot pin required');
  assert(/^(0|[1-9]\d*)$/.test(env.ADMIN_Q05_ADMISSION_FD || '')
    && Number.isSafeInteger(Number(env.ADMIN_Q05_ADMISSION_FD))
    && Number(env.ADMIN_Q05_ADMISSION_FD) > 2, 'Q05 inherited admission pipe required');
  const initial = { files: null };
  async function verifyBuild() {
    const current = await buildInventory(buildDirectory);
    assert.equal(current.sha256, env.ADMIN_Q05_BUILD_SHA256, 'Q05 existing build pin mismatch');
    if (initial.files) assert.deepEqual(current.files, initial.files, 'Q05 existing build changed');
    else initial.files = current.files;
    return current;
  }
  async function awaitBrowserAck(pid, profile) {
    assert.equal(profile, path.join(tempRoot, 'chromium-profile'));
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      let info;
      try { info = await fs.lstat(ackPath); }
      catch (error) { if (error.code === 'ENOENT') { await delay(25); continue; } throw error; }
      assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o077) === 0
        && info.uid === process.getuid(), 'Q05 ACK must be a private owned regular file');
      const ack = JSON.parse(await fs.readFile(ackPath, 'utf8'));
      assert.equal(ack.version, 1);
      assert.equal(ack.pid, pid);
      assert(Number.isInteger(ack.pgid) && ack.pgid > 0);
      assert.equal(ack.uid, process.getuid());
      assert(Number.isInteger(ack.sessionId) && ack.sessionId > 0);
      assert(Number.isInteger(ack.startSec) && ack.startSec > 0);
      assert(Number.isInteger(ack.startUsec) && ack.startUsec >= 0);
      assert.equal(ack.profile, profile);
      assert.equal(ack.executable, env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE);
      return { acknowledged: true, pid, profile };
    }
    throw new Error('Q05 live Chromium birth ACK timed out');
  }
  async function consumeLaunchGrant(profile) {
    assert.equal(profile, path.join(tempRoot, 'chromium-profile'));
    const grant = await readInheritedFifoGrant(env, 'ADMIN_Q05_ADMISSION_FD', 'Q05');
    return validateLaunchGrant(grant, { repo, buildSha256: env.ADMIN_Q05_BUILD_SHA256,
      snapshotSha256: env.ADMIN_Q05_SNAPSHOT_SHA256,
      chromium: env.OWASP_AI_GOAT_CHROMIUM_ACTUAL_EXECUTABLE, profile,
      launcherPid: process.ppid, workerPid: process.pid, expectedCohort });
  }
  return { buildDirectory, buildSha256: env.ADMIN_Q05_BUILD_SHA256,
    verifyBuild, consumeLaunchGrant, awaitBrowserAck, run: context => runQ05(context) };
}

function requestWitness(page, base) {
  const rows = [];
  const onRequest = request => {
    const url = new URL(request.url());
    if (url.origin === base && url.pathname.startsWith('/api/'))
      rows.push({ method: request.method(), path: url.pathname });
  };
  page.on('request', onRequest);
  const count = (method, endpoint) => rows.filter(row => row.method === method && row.path === endpoint).length;
  return { count, stop: () => page.off('request', onRequest),
    totals: () => Object.fromEntries([...new Set(rows.map(row => `${row.method} ${row.path}`))]
      .sort().map(key => [key, rows.filter(row => `${row.method} ${row.path}` === key).length])) };
}

function q05ExactResponseWitness(page, base, method, endpoint) {
  assert(['DELETE'].includes(method));
  assert(/^\/api\/admin\/administrators\/[1-9]\d*$/.test(endpoint));
  const observed = { response200: 0, responseOther: 0, finished: 0, failed: 0 };
  const matches = request => {
    try {
      const url = new URL(request.url());
      return url.origin === base && url.pathname === endpoint && request.method() === method;
    } catch { return false; }
  };
  const onResponse = response => {
    if (!matches(response.request())) return;
    if (response.status() === 200) observed.response200 += 1;
    else observed.responseOther += 1;
  };
  const onFinished = request => { if (matches(request)) observed.finished += 1; };
  const onFailed = request => { if (matches(request)) observed.failed += 1; };
  page.on('response', onResponse);
  page.on('requestfinished', onFinished);
  page.on('requestfailed', onFailed);
  return { snapshot: () => ({ ...observed }), stop: () => {
    page.off('response', onResponse);
    page.off('requestfinished', onFinished);
    page.off('requestfailed', onFailed);
  } };
}

function q05StudentPasswordResponseWitness(page, base, endpoint) {
  assert(/^\/api\/admin\/students\/[1-9]\d*\/change-password$/.test(endpoint));
  const seen = { browserRequests: 0, browserFailed: 0, browserFinished: 0 };
  const matches = request => {
    try { const url = new URL(request.url());
      return url.origin === base && url.pathname === endpoint && request.method() === 'POST';
    } catch { return false; }
  };
  const onRequest = request => { if (matches(request)) seen.browserRequests += 1; };
  const onFailed = request => { if (matches(request)) seen.browserFailed += 1; };
  const onFinished = request => { if (matches(request)) seen.browserFinished += 1; };
  page.on('request', onRequest);
  page.on('requestfailed', onFailed);
  page.on('requestfinished', onFinished);
  return { snapshot: () => ({ ...seen }), stop: () => {
    page.off('request', onRequest);
    page.off('requestfailed', onFailed);
    page.off('requestfinished', onFinished);
  } };
}

function q05DeactivationFailureFact({ browser, server, browserLoss, ui }) {
  const nonnegative = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const flag = value => value === true;
  return {
    browser: {
      requests: nonnegative(browser?.requests), response200: nonnegative(browser?.response200),
      responseOther: nonnegative(browser?.responseOther), finished: nonnegative(browser?.finished),
      failed: nonnegative(browser?.failed), targetReadbacks: nonnegative(browser?.targetReadbacks),
      rosterReads: nonnegative(browser?.rosterReads),
    },
    server: {
      received: nonnegative(server?.received), armed: flag(server?.armed),
      validDrops: nonnegative(server?.validDrops), invalidDrops: nonnegative(server?.invalidDrops),
      validStatus200: flag(server?.validStatus200),
    },
    browserLoss: browserLoss ? {
      selected: flag(browserLoss.selected), failed: nonnegative(browserLoss.failed),
      failure: flag(browserLoss.failure),
    } : null,
    ui: ui ? {
      dialogPresent: flag(ui.dialogPresent), unknownNotice: flag(ui.unknownNotice),
      rejectedNotice: flag(ui.rejectedNotice), successNotice: flag(ui.successNotice),
      administratorsPanelPresent: flag(ui.administratorsPanelPresent),
      twoStorageEvents: flag(ui.twoStorageEvents),
    } : null,
  };
}

async function q05RecordDeactivationFailure({ error, browser, server, browserLoss, observeUi, record,
  uiTimeoutMs = 500 }) {
  assert(Number.isInteger(uiTimeoutMs) && uiTimeoutMs > 0 && uiTimeoutMs <= 500);
  const initial = q05DeactivationFailureFact({ browser, server, browserLoss, ui: null });
  // Save the primary error and exact request counts before any browser protocol
  // read: a stalled renderer must not erase the useful failure evidence.
  try { await record(error, initial); } catch { /* Retain the primary error. */ }
  let timer;
  const ui = await Promise.race([
    Promise.resolve().then(observeUi).catch(() => null),
    new Promise(resolve => { timer = setTimeout(() => resolve(null), uiTimeoutMs); }),
  ]);
  clearTimeout(timer);
  if (ui) {
    try { await record(error, q05DeactivationFailureFact({ browser, server, browserLoss, ui })); }
    catch { /* Initial durable counts remain available. */ }
  }
}

function q05PageTargets(onUnexpected) {
  assert.equal(typeof onUnexpected, 'function');
  let mainPending = true, main = null, auxiliaryArmed = false, auxiliary = null, auxiliaryUsed = false;
  return Object.freeze({
    observe(target) {
      if (mainPending && target.type() === 'page') {
        mainPending = false; main = target; return true;
      }
      if (auxiliaryArmed && !auxiliaryUsed && target.type() === 'page') {
        auxiliaryArmed = false; auxiliaryUsed = true; auxiliary = target; return true;
      }
      onUnexpected(target); return false;
    },
    mainIs(target) { return target === main; },
    armAuxiliary() {
      assert(main && !auxiliaryArmed && !auxiliaryUsed && !auxiliary,
        'Only one explicitly armed Q05 auxiliary page is permitted');
      auxiliaryArmed = true;
    },
    auxiliaryIs(target) { return target === auxiliary; },
    auxiliaryUsed() { return auxiliaryUsed; },
    closeAuxiliary(target) {
      assert(target === auxiliary, 'Only the admitted Q05 auxiliary page can retire');
      auxiliary = null;
    },
    disarmAuxiliary() { auxiliaryArmed = false; },
  });
}

function q05AuxiliaryRequestAllowed(url, base) {
  try {
    const target = new URL(url);
    return target.origin === base || target.protocol === 'about:' || target.protocol === 'data:';
  } catch { return false; }
}

async function renderedRowAction(page, username, label, { within } = {}) {
  const handle = await page.evaluateHandle(({ username, label, within }) => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const root = within ? document.querySelector(within) : document;
    const rows = [...(root?.querySelectorAll('tr') || [])].filter(row =>
      [...row.querySelectorAll('td')].some(cell => clean(cell.textContent) === username));
    if (rows.length !== 1) return null;
    const buttons = [...rows[0].querySelectorAll('button')]
      .filter(button => clean(button.textContent) === label && !button.disabled);
    return buttons.length === 1 ? buttons[0] : null;
  }, { username, label, within });
  try {
    const button = handle.asElement();
    assert(button, `One enabled ${label} action for the exact synthetic account required`);
    await button.click();
  } finally { await handle.dispose(); }
}

async function focusQ05MainPage(page) {
  await page.bringToFront();
  const visible = await page.waitForFunction(() =>
    document.visibilityState === 'visible' && !document.hidden, { timeout: 15000 });
  await visible.dispose();
}

async function physicalQ05DeactivationRowAction(page, username) {
  await focusQ05MainPage(page);
  await renderedRowAction(page, username, 'Deactivate',
    { within: '#user-management-administrators-panel' });
}

async function physicalQ05NamedButton(page, text) {
  const handle = await page.evaluateHandle(text => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const buttons = [...document.querySelectorAll('button')]
      .filter(button => clean(button.textContent) === text && !button.disabled);
    return buttons.length === 1 ? buttons[0] : null;
  }, text);
  try {
    const button = handle.asElement();
    assert(button, `One enabled rendered ${text} button required`);
    await button.click();
  } finally { await handle.dispose(); }
}

async function openQ05ManagementStudentControls(page, base, username) {
  // Account Lock is not on /admin/students. It is mounted only in the
  // User Management modal's Students tab under Settings.
  await waitForPath(page, `${base}/admin/settings`, 'Security Settings');
  await focusQ05MainPage(page);
  await physicalQ05NamedButton(page, 'Manage Users');
  await page.waitForSelector('#user-management-students-tab');
  await page.click('#user-management-students-tab');
  await page.waitForFunction(username => {
    const panel = document.querySelector('#user-management-students-panel');
    return [...(panel?.querySelectorAll('tr') || [])].some(row =>
      [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === username)
      && [...row.querySelectorAll('button')].some(button =>
        button.textContent.trim() === 'Lock' && !button.disabled));
  }, { timeout: 15000 }, username);
}

async function physicalQ05AccountButton(page, text, { clickCount = 1 } = {}) {
  assert([1, 2].includes(clickCount));
  const handle = await page.evaluateHandle(text => {
    const dialog = document.querySelectorAll('[aria-label="Confirm account access change"]');
    if (dialog.length !== 1) return null;
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const buttons = [...dialog[0].querySelectorAll('button')]
      .filter(button => clean(button.textContent) === text && !button.disabled);
    return buttons.length === 1 ? buttons[0] : null;
  }, text);
  try {
    const button = handle.asElement();
    assert(button, `One enabled ${text} button in the exact account dialog required`);
    await button.click({ clickCount });
  } finally { await handle.dispose(); }
}

async function physicalQ05StudentPasswordButton(page, text, { clickCount = 1 } = {}) {
  assert([1, 2].includes(clickCount));
  const handle = await page.evaluateHandle(text => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const headings = [...document.querySelectorAll('h2')]
      .filter(node => clean(node.textContent) === 'Change Student Password');
    if (headings.length !== 1) return null;
    const panel = headings[0].parentElement?.parentElement;
    const forms = [...(panel?.querySelectorAll('form') || [])];
    if (forms.length !== 1) return null;
    const buttons = [...forms[0].querySelectorAll('button')]
      .filter(button => clean(button.textContent) === text && !button.disabled);
    return buttons.length === 1 ? buttons[0] : null;
  }, text);
  try {
    const button = handle.asElement();
    assert(button, `One enabled ${text} in the exact student password form required`);
    await button.click({ clickCount });
  } finally { await handle.dispose(); }
}

async function physicalQ05DeactivationButton(page, text, { clickCount = 1 } = {}) {
  assert([1, 2].includes(clickCount));
  await focusQ05MainPage(page);
  const handle = await page.evaluateHandle(text => {
    const dialogs = document.querySelectorAll('[role="dialog"][aria-label="Deactivate administrator"]');
    if (dialogs.length !== 1) return null;
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const buttons = [...dialogs[0].querySelectorAll('button')]
      .filter(button => clean(button.textContent) === text && !button.disabled);
    return buttons.length === 1 ? buttons[0] : null;
  }, text);
  try {
    const button = handle.asElement();
    assert(button, `One enabled ${text} button in the exact deactivation dialog required`);
    await button.click({ clickCount });
  } finally { await handle.dispose(); }
}

async function accountAccessRow(runtime, id) {
  const rows = (await runtime.query(`SELECT account_locked_until,login_attempts
    FROM identity.users WHERE id=$1`, [id])).rows;
  assert.equal(rows.length, 1);
  return rows[0];
}

async function runAccountAccessQ05({ page, base, runtime, studentId, student, password,
  token, alternateToken, authorityTab, armAcknowledgementLoss, witness, phase }) {
  assert(authorityTab && typeof authorityTab.swap === 'function');
  assert(alternateToken && alternateToken !== token);
  const lockEndpoint = `/api/admin/users/${studentId}/lock`;
  const unlockEndpoint = `/api/admin/users/${studentId}/unlock`;
  const login = secret => fetch(`${base}/api/auth/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: student.username, password: secret }) });
  await phase('account-lock-session-and-failed-attempts');
  const priorLogin = await login(password);
  assert.equal(priorLogin.status, 200);
  const priorToken = (await priorLogin.json()).token;
  assert.equal(typeof priorToken, 'string');
  const priorSessionDigest = sha(priorToken);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
  [studentId, priorSessionDigest])).rows[0].n, 1);
  assert.equal((await login(`${password}-wrong`)).status, 401);
  const before = await accountAccessRow(runtime, studentId);
  assert.equal(before.account_locked_until, null);
  assert(Number(before.login_attempts) > 0 && Number(before.login_attempts) < 5);
  await openQ05ManagementStudentControls(page, base, student.username);
  const lockBefore = witness.count('POST', lockEndpoint);
  await phase('account-lock-cancel');
  await renderedRowAction(page, student.username, 'Lock', { within: '#user-management-students-panel' });
  await physicalQ05AccountButton(page, 'Cancel');
  assert.equal(witness.count('POST', lockEndpoint), lockBefore);
  assert.deepEqual(await accountAccessRow(runtime, studentId), before);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
  [studentId, priorSessionDigest])).rows[0].n, 1,
  'cancelling Lock must preserve the original active student session');

  await phase('account-lock-physical-cross-tab-aba');
  await renderedRowAction(page, student.username, 'Lock', { within: '#user-management-students-panel' });
  await page.evaluate(() => {
    window.__q05TokenStorageEvents = 0;
    window.addEventListener('storage', event => {
      if (event.key === 'token') window.__q05TokenStorageEvents += 1;
    });
  });
  let eventsObserved;
  {
    await authorityTab.swap(token, alternateToken);
    await focusQ05MainPage(page);
    // After restoring the main page's visibility, attempt the rendered action
    // without waiting for authority settlement: either the storage handler's
    // retirement or the confirm-time authority guard must win.
    const confirmHandle = await page.evaluateHandle(() => {
      const dialog = document.querySelector('[aria-label="Confirm account access change"]');
      return [...(dialog?.querySelectorAll('button') || [])]
        .find(item => item.textContent.trim() === 'Confirm Lock' && !item.disabled) || null;
    });
    const physicalConfirm = confirmHandle.asElement();
    if (physicalConfirm) {
      try { await physicalConfirm.click(); }
      catch (error) {
        const retired = await page.evaluate(() =>
          !document.querySelector('[aria-label="Confirm account access change"]'));
        if (!retired) throw error;
      }
    }
    await confirmHandle.dispose();
    await page.waitForFunction(() => window.__q05TokenStorageEvents >= 2, { timeout: 15000 });
    eventsObserved = await page.evaluate(() => window.__q05TokenStorageEvents);
    assert.equal(eventsObserved, 2, 'Exact B→A storage event sequence required');
    await page.waitForFunction(() => !document.querySelector('[aria-label="Confirm account access change"]'),
      { timeout: 15000 });
  }
  assert.equal(witness.count('POST', lockEndpoint), lockBefore);
  assert.deepEqual(await accountAccessRow(runtime, studentId), before);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
  [studentId, priorSessionDigest])).rows[0].n, 1,
  'cross-tab ABA must preserve the original active student session');

  await phase('account-lock-confirm');
  await openQ05ManagementStudentControls(page, base, student.username);
  await renderedRowAction(page, student.username, 'Lock', { within: '#user-management-students-panel' });
  await responseAfter(page, base, 'POST', lockEndpoint,
    () => physicalQ05AccountButton(page, 'Confirm Lock', { clickCount: 2 }));
  assert.equal(witness.count('POST', lockEndpoint), lockBefore + 1);
  const locked = await accountAccessRow(runtime, studentId);
  assert(locked.account_locked_until && new Date(locked.account_locked_until).getTime() > Date.now());
  assert.equal(Number(locked.login_attempts), Number(before.login_attempts));
  assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
  [studentId, priorSessionDigest])).rows[0].n, 0);
  assert.equal((await fetch(`${base}/api/auth/status`, {
    headers: { authorization: `Bearer ${priorToken}` },
  }).then(response => response.json())).authenticated, false);
  assert.equal((await login(password)).status, 401);

  await phase('account-unlock-cancel');
  await waitForPath(page, `${base}/admin/locked-users`, 'Locked Users Management');
  await page.waitForFunction(username => [...document.querySelectorAll('tr')].some(row =>
    [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === username)),
  { timeout: 15000 }, student.username);
  const unlockBefore = witness.count('POST', unlockEndpoint);
  await renderedRowAction(page, student.username, 'Unlock');
  await physicalQ05AccountButton(page, 'Cancel');
  assert.equal(witness.count('POST', unlockEndpoint), unlockBefore);
  assert.deepEqual(await accountAccessRow(runtime, studentId), locked);

  await phase('account-unlock-lost-ack');
  await renderedRowAction(page, student.username, 'Unlock');
  armAcknowledgementLoss('POST', unlockEndpoint);
  await physicalQ05AccountButton(page, 'Confirm Unlock', { clickCount: 2 });
  await page.waitForFunction(() => document.body.innerText.includes('The request outcome could not be confirmed.'),
    { timeout: 15000 });
  assert.equal(witness.count('POST', unlockEndpoint), unlockBefore + 1);
  const unlocked = await accountAccessRow(runtime, studentId);
  assert.equal(unlocked.account_locked_until, null);
  assert.equal(Number(unlocked.login_attempts), 0);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
    WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
  [studentId, priorSessionDigest])).rows[0].n, 0);
  await delay(250);
  assert.equal(witness.count('POST', unlockEndpoint), unlockBefore + 1,
    'unknown Unlock outcome must not automatically retry');
  await physicalQ05AccountButton(page, 'Close');
  assert.equal((await login(password)).status, 200);
  return { lock: { cancelNoRequest: true, crossTabAbaNoRequest: true,
    storageEventsObserved: eventsObserved, oneConfirmedRequest: true, sessionsRevoked: true,
    loginDenied: true, targetId: studentId },
  unlock: { cancelNoRequest: true, lostAckEffectPersisted: true,
    unknownUiNoRetry: true, failedAttemptsCleared: true,
    revokedSessionStayedRevoked: true, freshLogin: true, targetId: studentId } };
}

async function runAdministratorDeactivationQ05({ page, base, runtime, admin, adminId,
  administrator, adminPassword, token, authorityTab, armAcknowledgementLoss, witness, phase,
  firstStudent, secondStudent, onLostAckFailure }) {
  assert.notEqual(adminId, admin.id, 'The target must not be the acting administrator');
  assert.notEqual(adminId, firstStudent.id);
  assert.notEqual(adminId, secondStudent.id);
  const endpoint = `/api/admin/administrators/${adminId}`;
  const targetBefore = await snapshotUser(runtime, adminId);
  const actorBefore = await snapshotUser(runtime, admin.id);
  const siblingsBefore = await snapshotSiblings(runtime, firstStudent, secondStudent);
  assert.equal(targetBefore?.is_active, 1);
  assert.equal(targetBefore.role, 'admin');
  assert.equal(targetBefore.admin_level, 1);
  const login = async (username, password) => {
    const response = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }) });
    assert.equal(response.status, 200, 'A genuine owner-bound login is required');
    const body = await response.json();
    assert.equal(typeof body.token, 'string');
    return body.token;
  };
  const targetToken = await login(administrator.username, administrator.password);
  const alternateToken = await login('rendered-admin', adminPassword);
  assert.notEqual(alternateToken, token, 'The equally privileged B session must differ from A');
  const sessionCount = async (userId, bearer) => (await runtime.query(`SELECT count(*)::integer AS n
    FROM identity.user_sessions WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
  [userId, sha(bearer)])).rows[0].n;
  assert.equal(await sessionCount(adminId, targetToken), 1);
  assert.equal(await sessionCount(admin.id, token), 1);
  assert.equal(await sessionCount(admin.id, alternateToken), 1);
  const targetActiveSessions = (await runtime.query(`SELECT id FROM identity.user_sessions
    WHERE user_id=$1 AND is_active=1 ORDER BY id`, [adminId])).rows;
  assert(targetActiveSessions.length >= 1);
  await page.waitForFunction(username => [...document.querySelectorAll('#user-management-administrators-panel tr')]
    .some(row => [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === username)
      && [...row.querySelectorAll('button')].some(button => button.textContent.trim() === 'Deactivate'
        && !button.disabled)), { timeout: 15000 }, administrator.username);
  const before = witness.count('DELETE', endpoint);
  await phase('administrator-deactivation-cancel');
  await physicalQ05DeactivationRowAction(page, administrator.username);
  await page.waitForFunction(username => {
    const dialogs = document.querySelectorAll('[role="dialog"][aria-label="Deactivate administrator"]');
    return dialogs.length === 1 && dialogs[0].textContent.includes(`Deactivate ${username}?`)
      && dialogs[0].textContent.includes('removes sign-in access and revokes sessions')
      && dialogs[0].textContent.includes('audit and learner evidence are retained');
  }, { timeout: 15000 }, administrator.username);
  await physicalQ05DeactivationButton(page, 'Cancel');
  assert.equal(witness.count('DELETE', endpoint), before);
  assert.deepEqual(await snapshotUser(runtime, adminId), targetBefore);
  assert.equal(await sessionCount(adminId, targetToken), 1);

  await phase('administrator-deactivation-cross-tab-aba');
  await physicalQ05DeactivationRowAction(page, administrator.username);
  await page.evaluate(() => {
    window.__q05DeactivationStorageEvents = 0;
    window.addEventListener('storage', event => {
      if (event.key === 'token') window.__q05DeactivationStorageEvents += 1;
    });
  });
  await authorityTab.swap(token, alternateToken);
  await focusQ05MainPage(page);
  const confirmHandle = await page.evaluateHandle(() => {
    const dialog = document.querySelector('[role="dialog"][aria-label="Deactivate administrator"]');
    return [...(dialog?.querySelectorAll('button') || [])]
      .find(button => button.textContent.trim() === 'Confirm deactivation' && !button.disabled) || null;
  });
  const staleConfirm = confirmHandle.asElement();
  if (staleConfirm) {
    try { await staleConfirm.click(); }
    catch (error) {
      const retired = await page.evaluate(() =>
        !document.querySelector('[role="dialog"][aria-label="Deactivate administrator"]'));
      if (!retired) throw error;
    }
  }
  await confirmHandle.dispose();
  await page.waitForFunction(() => window.__q05DeactivationStorageEvents >= 2,
    { timeout: 15000 });
  const eventsObserved = await page.evaluate(() => window.__q05DeactivationStorageEvents);
  assert.equal(eventsObserved, 2);
  await page.waitForFunction(() =>
    !document.querySelector('[role="dialog"][aria-label="Deactivate administrator"]'),
  { timeout: 15000 });
  assert.equal(witness.count('DELETE', endpoint), before);
  assert.deepEqual(await snapshotUser(runtime, adminId), targetBefore);
  assert.equal(await sessionCount(adminId, targetToken), 1);

  await phase('administrator-deactivation-lost-ack');
  await waitForPath(page, `${base}/admin/settings`, 'Security Settings');
  await physicalQ05NamedButton(page, 'Manage Users');
  await page.waitForSelector('#user-management-administrators-panel');
  await page.waitForFunction(username => [...document.querySelectorAll('#user-management-administrators-panel tr')]
    .some(row => [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === username)
      && [...row.querySelectorAll('button')].some(button => button.textContent.trim() === 'Deactivate'
        && !button.disabled)), { timeout: 15000 }, administrator.username);
  await physicalQ05DeactivationRowAction(page, administrator.username);
  const targetReadsBefore = witness.count('GET', `/api/admin/users/${adminId}`);
  const rosterReadsBefore = witness.count('GET', '/api/admin/users');
  const responseWitness = q05ExactResponseWitness(page, base, 'DELETE', endpoint);
  const serverSnapshot = armAcknowledgementLoss('DELETE', endpoint);
  const browserLoss = await installQ05DeactivationBrowserLoss(page, base, endpoint, serverSnapshot);
  let originalFailure = null;
  try {
    await physicalQ05DeactivationButton(page, 'Confirm deactivation', { clickCount: 2 });
    await page.waitForFunction(() => document.body.innerText.includes('The request outcome could not be confirmed.'),
      { timeout: 15000 });
    const requestOutcome = responseWitness.snapshot();
    const lossOutcome = browserLoss.snapshot();
    assert.deepEqual({ requests: witness.count('DELETE', endpoint) - before,
      finished: requestOutcome.finished, failed: requestOutcome.failed,
      selected: lossOutcome.selected,
      failedResponseStages: lossOutcome.failed, listenerFailure: lossOutcome.failure },
    { requests: 1, finished: 0, failed: 1,
      selected: true, failedResponseStages: 1, listenerFailure: false },
    'Exactly one DELETE must fail in Chromium after the validated real HTTP 200');
  } catch (error) {
    originalFailure = error;
    await q05RecordDeactivationFailure({ error,
      browser: { requests: witness.count('DELETE', endpoint) - before,
        targetReadbacks: witness.count('GET', `/api/admin/users/${adminId}`) - targetReadsBefore,
        rosterReads: witness.count('GET', '/api/admin/users') - rosterReadsBefore,
        ...responseWitness.snapshot() },
      server: typeof serverSnapshot === 'function' ? serverSnapshot() : null,
      browserLoss: browserLoss.snapshot(),
      record: onLostAckFailure || (() => {}),
      observeUi: () => page.evaluate(() => {
        const body = document.body?.innerText || '';
        return { dialogPresent: Boolean(document.querySelector('[role="dialog"][aria-label="Deactivate administrator"]')),
          unknownNotice: body.includes('The request outcome could not be confirmed.'),
          rejectedNotice: body.includes('The server rejected deactivation:'),
          successNotice: body.includes('Administrator deactivated'),
          administratorsPanelPresent: Boolean(document.querySelector('#user-management-administrators-panel')),
          twoStorageEvents: window.__q05DeactivationStorageEvents === 2 };
      }),
    });
    throw error;
  } finally {
    responseWitness.stop();
    try { await browserLoss.close(); }
    catch (closeError) { if (!originalFailure) throw closeError; }
  }
  assert.equal(witness.count('DELETE', endpoint), before + 1);
  assert.deepEqual(serverSnapshot(), { received: 1, armed: false,
    validDrops: 1, invalidDrops: 0, validStatus200: true });
  const targetAfter = await snapshotUser(runtime, adminId);
  assert.equal(targetAfter.is_active, 0);
  assert.deepEqual({ ...targetAfter, is_active: 1 }, targetBefore,
    'Deactivation must retain the account and all non-status fields');
  assert.equal(await sessionCount(adminId, targetToken), 0);
  assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
    WHERE user_id=$1 AND is_active=1`, [adminId])).rows[0].n, 0);
  const revoked = (await runtime.query(`SELECT id,is_active,revoke_reason,revoked_at
    FROM identity.user_sessions WHERE id=ANY($1::integer[]) ORDER BY id`,
  [targetActiveSessions.map(row => row.id)])).rows;
  assert.equal(revoked.length, targetActiveSessions.length);
  for (const row of revoked) {
    assert.equal(row.is_active, 0);
    assert.equal(row.revoke_reason, 'account_deactivated');
    assert(row.revoked_at, 'The target session must record its revocation time');
  }
  assert.equal((await fetch(`${base}/api/auth/status`, {
    headers: { authorization: `Bearer ${targetToken}` },
  }).then(response => response.json())).authenticated, false);
  assert.equal(await sessionCount(admin.id, token), 1);
  assert.equal(await sessionCount(admin.id, alternateToken), 1);
  assert.deepEqual(await snapshotUser(runtime, admin.id), actorBefore);
  assert.deepEqual(await snapshotSiblings(runtime, firstStudent, secondStudent), siblingsBefore);
  await delay(250);
  assert.equal(witness.count('DELETE', endpoint), before + 1,
    'Unknown deactivation outcome must not automatically retry DELETE');
  assert.equal(serverSnapshot().received, 1,
    'Unknown deactivation outcome must not reach the server through another DELETE');
  await physicalQ05DeactivationButton(page, 'Close');
  const responseStage = { browserRequests: witness.count('DELETE', endpoint) - before,
    browserFailed: responseWitness.snapshot().failed,
    browserFinished: responseWitness.snapshot().finished,
    serverReceived: serverSnapshot().received };
  return { action: { cancelNoRequest: true, crossTabAbaNoRequest: true,
    storageEventsObserved: eventsObserved, oneConfirmedRequest: true,
    inactive: true, sessionsRevoked: true, actorPreserved: true,
    siblingsPreserved: true, lostAckEffectPersisted: true,
    unknownUiNoRetry: true, responseStageBrowserFailure: true,
    targetId: adminId }, responseStage, alternateToken };
}

async function clickNamed(page, text, { within } = {}) {
  const found = await page.evaluate(({ text, within }) => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const root = within ? document.querySelector(within) : document;
    const choices = [...(root?.querySelectorAll('button') || [])].filter(button => clean(button.textContent) === text);
    if (choices.length !== 1 || choices[0].disabled) return false;
    choices[0].click();
    return true;
  }, { text, within });
  assert(found, `One enabled rendered ${text} button required`);
}

async function clickInPanel(page, heading, text, { twice = false, modalHeadingOnly = false } = {}) {
  const found = await page.evaluate(({ heading, text, twice, modalHeadingOnly }) => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const headers = [...document.querySelectorAll(modalHeadingOnly ? 'h2' : 'h2,h4')]
      .filter(node => clean(node.textContent) === heading);
    if (headers.length !== 1) return false;
    let panel = headers[0].parentElement;
    while (panel) {
      const buttons = [...panel.querySelectorAll('button')].filter(button => clean(button.textContent) === text);
      if (buttons.length === 1 && !buttons[0].disabled) {
        buttons[0].click();
        if (twice) buttons[0].click();
        return true;
      }
      panel = panel.parentElement;
    }
    return false;
  }, { heading, text, twice, modalHeadingOnly });
  assert(found, `One enabled ${text} button inside ${heading} required`);
}

async function formForHeading(page, heading, { modalHeadingOnly = false } = {}) {
  const handle = await page.evaluateHandle(({ heading, modalHeadingOnly }) => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    const headers = [...document.querySelectorAll(modalHeadingOnly ? 'h2' : 'h2,h4')]
      .filter(node => clean(node.textContent) === heading);
    if (headers.length !== 1) return null;
    for (let node = headers[0].parentElement; node; node = node.parentElement) {
      const form = node.querySelector('form');
      if (form) return form;
    }
    return null;
  }, { heading, modalHeadingOnly });
  const form = handle.asElement();
  assert(form, `Rendered ${heading} form required`);
  return form;
}

async function waitForModalHeadingAbsence(page, heading) {
  await page.waitForFunction(heading => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim();
    return ![...document.querySelectorAll('h2')]
      .some(node => clean(node.textContent) === heading);
  }, { timeout: 15000 }, heading);
}

async function replaceInput(handle, value) {
  assert(handle, 'Rendered input required');
  assert.equal(typeof value, 'string');
  await handle.click();
  const keyboard = handle.frame.page().keyboard;
  const modifier = process.platform === 'darwin' ? 'Meta' : 'Control';
  await keyboard.down(modifier);
  try { await keyboard.press('KeyA', { commands: ['selectAll'] }); }
  finally { await keyboard.up(modifier); }
  await keyboard.press('Backspace');
  assert(await handle.evaluate(element => element.value === ''),
    'Rendered input was not cleared by physical select-all');
  await handle.type(value);
  const state = await handle.evaluate(element => ({ value: element.value,
    valid: element.validity.valid }));
  assert(state.value === value, 'Rendered input replacement did not match requested value');
  assert(state.valid, 'Rendered input replacement left an invalid field');
}

async function waitForPath(page, pathname, label) {
  await page.goto(pathname, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(label => document.body.innerText.includes(label), { timeout: 15000 }, label);
}

async function remountQ05StudentPasswordAction(page, base, username) {
  assert.equal(new URL(base).hostname, '127.0.0.1');
  assert(typeof username === 'string' && username.length > 0);
  await waitForPath(page, `${base}/admin/students`, 'Student Management');
  const ready = await page.waitForFunction(name => {
    if (location.pathname !== '/admin/students') return false;
    const rows = [...document.querySelectorAll('tr')].filter(row =>
      [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === name));
    if (rows.length !== 1) return false;
    const buttons = [...rows[0].querySelectorAll('button')]
      .filter(button => button.textContent.trim() === 'Password' && !button.disabled);
    return buttons.length === 1;
  }, { timeout: 15000 }, username);
  await ready.dispose();
}

async function snapshotUser(pool, id) {
  return (await pool.query(`SELECT id,username,email,full_name,role,admin_level,is_active,
    department,phone FROM identity.users WHERE id=$1`, [id])).rows[0] || null;
}

async function snapshotSiblings(pool, first, second) {
  const ids = [first.id, second.id];
  return {
    users: (await pool.query(`SELECT id,username,email,full_name,role,admin_level,is_active,
      department,phone FROM identity.users WHERE id=ANY($1::integer[]) ORDER BY id`, [ids])).rows,
    completions: (await pool.query(`SELECT user_id,workshop_key,objective_id FROM workshop_platform.completions
      WHERE user_id=ANY($1::integer[]) ORDER BY user_id,workshop_key,objective_id`, [ids])).rows,
    time: (await pool.query(`SELECT user_id,workshop_key,duration_seconds FROM workshop_platform.time_tracking
      WHERE user_id=ANY($1::integer[]) ORDER BY user_id,workshop_key,duration_seconds`, [ids])).rows,
  };
}

async function responseAfter(page, base, method, endpoint, act) {
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === base && url.pathname === endpoint && response.request().method() === method;
  }, { timeout: 15000 });
  await act();
  const response = await pending;
  assert([200, 201].includes(response.status()), `${method} ${endpoint} must acknowledge success`);
  return response;
}

async function studentReadbackFlags(page, username) {
  return page.evaluate(username => {
    const exactRow = [...document.querySelectorAll('tr')].some(row =>
      [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === username));
    const body = document.body?.innerText || '';
    return { exactRenderedRow: exactRow,
      renderedRowCount: document.querySelectorAll('tbody tr').length,
      bodyContainsSyntheticUsername: body.includes(username),
      pathname: location.pathname,
      createModalStillOpen: [...document.querySelectorAll('h2')]
        .some(heading => heading.textContent.trim() === 'Create New Student'),
      createOutcomeUnknown: body.includes('Student creation could not be confirmed.'),
      createOutcomeRejected: body.includes('Student creation was rejected.') };
  }, username);
}

async function formValidityFlags(page) {
  return page.evaluate(() => {
    const invalid = [...document.querySelectorAll('form input,form select,form textarea')]
      .filter(field => field.willValidate && !field.validity.valid);
    return { pathname: location.pathname, invalidFieldCount: invalid.length,
      invalidFieldNames: invalid.slice(0, 12).map(field =>
        String(field.getAttribute('name') || field.id || field.type || 'unlabeled').slice(0, 64)) };
  });
}

async function runQ05({ page, base, runtime, migration, admin, firstStudent, secondStudent, token,
  adminPassword, armAcknowledgementLoss, openAuthorityTab, record }) {
  assert.equal(new URL(base).hostname, '127.0.0.1');
  const witness = requestWitness(page, base), facts = { modelCalls: 0, judgeCalls: 0,
    excluded: ['student-reset', 'student-deletion', 'model-grading', 'full-Q05-denominator'],
    actions: {}, phase: 'student-create-preparation' };
  const siblingBefore = await snapshotSiblings(runtime, firstStudent, secondStudent);
  const checkpoint = async () => { if (record) await record(structuredClone(facts)); };
  const nonce = crypto.randomBytes(5).toString('hex');
  const student = { username: `q05-student-${nonce}`, email: `q05-student-${nonce}@example.invalid`,
    password: `Q05-Student-${nonce}!` };
  const administrator = { username: `q05-admin-${nonce}`, email: `q05-admin-${nonce}@example.invalid`,
    password: `Q05-Admin-${nonce}!` };
  const rosterReadbacks = [];
  let authorityTab = null;
  let primaryFailure = null;
  let deactivationLossDiagnostic = null;
  let createSubmitted = false;
  const onRoster = response => {
    const url = new URL(response.url());
    if (url.origin !== base || url.pathname !== '/api/admin/students'
      || response.request().method() !== 'GET') return;
    const entry = { status: response.status(), afterCreateSubmit: createSubmitted,
      containsSyntheticTarget: false };
    rosterReadbacks.push(entry);
    if (response.status() === 200) void response.json().then(body => {
      entry.containsSyntheticTarget = Array.isArray(body?.students)
        && body.students.some(row => row?.username === student.username);
    }).catch(() => { entry.bodyUnavailable = true; });
  };
  page.on('response', onRoster);
  const phase = async name => { facts.phase = name; await checkpoint(); };
  try {
    // These are genuine mounted forms and routes. No HTTP request body or secret
    // is stored in the returned evidence; only endpoint counts and SQL effects.
    await phase('student-create-open');
    await waitForPath(page, `${base}/admin/students`, 'Student Management');
    const createEndpoint = '/api/admin/students';
    const fillStudentCreate = async () => {
      const form = await formForHeading(page, 'Create New Student');
      await replaceInput(await form.$('input[placeholder="Enter username"]'), student.username);
      await replaceInput(await form.$('input[placeholder="Enter email"]'), student.email);
      await replaceInput(await form.$('input[placeholder="Enter password"]'), student.password);
      await replaceInput(await form.$('input[placeholder="Confirm password"]'), student.password);
      await form.dispose();
    };
    await clickNamed(page, 'Create New Student');
    await fillStudentCreate();
    const createBefore = witness.count('POST', createEndpoint);
    await clickInPanel(page, 'Create New Student', 'Cancel');
    assert.equal(witness.count('POST', createEndpoint), createBefore);
    assert.equal((await runtime.query('SELECT count(*)::integer AS n FROM identity.users WHERE username=$1',
      [student.username])).rows[0].n, 0);
    await clickNamed(page, 'Create New Student');
    await fillStudentCreate();
    await phase('student-create-response-await');
    createSubmitted = true;
    await responseAfter(page, base, 'POST', createEndpoint,
      () => clickInPanel(page, 'Create New Student', 'Create Student', { twice: true }));
    assert.equal(witness.count('POST', createEndpoint), createBefore + 1);
    const createdStudent = (await runtime.query(`SELECT id FROM identity.users
      WHERE username=$1 AND role='student' AND admin_level=0`, [student.username])).rows;
    assert.equal(createdStudent.length, 1);
    const studentId = createdStudent[0].id;
    assert.equal((await snapshotUser(runtime, studentId)).email, student.email);
    facts.actions.studentCreate = { cancelNoRequest: true, oneConfirmedRequest: true,
      persisted: true, targetId: studentId };
    facts.phase = 'student-create-sql-confirmed-await-rendered-row';
    await checkpoint();

    // Student edit: cancellation and a replaced authority must both leave the
    // original row and exact PUT endpoint untouched.
    await page.waitForFunction(name => [...document.querySelectorAll('tr')].some(row =>
      [...row.querySelectorAll('td')].some(cell => cell.textContent.trim() === name)),
    { timeout: 15000 }, student.username);
    const rowButton = async label => {
      const clicked = await page.evaluate(({ username, label }) => {
        const row = [...document.querySelectorAll('tr')].find(item =>
          [...item.querySelectorAll('td')].some(cell => cell.textContent.trim() === username));
        const button = [...(row?.querySelectorAll('button') || [])]
          .find(item => item.textContent.trim() === label);
        if (!button || button.disabled) return false;
        button.click(); return true;
      }, { username: student.username, label });
      assert(clicked, `Rendered ${label} action for new student required`);
    };
    const editEndpoint = `/api/admin/students/${studentId}`;
    await phase('student-edit-cancel-and-stale-authority');
    await rowButton('Edit');
    const editBefore = witness.count('PUT', editEndpoint);
    await clickInPanel(page, 'Edit Student Profile', 'Cancel');
    assert.equal(witness.count('PUT', editEndpoint), editBefore);
    assert.equal((await snapshotUser(runtime, studentId)).email, student.email);
    await rowButton('Edit');
    const editForm = await formForHeading(page, 'Edit Student Profile');
    await replaceInput(await editForm.$('input[type="email"]'), `q05-edited-${nonce}@example.invalid`);
    await editForm.dispose();
    await page.evaluate(() => localStorage.setItem('token', 'q05-stale-authority'));
    await clickInPanel(page, 'Edit Student Profile', 'Update Student');
    assert.equal(witness.count('PUT', editEndpoint), editBefore,
      'stale captured authority must not dispatch student edit');
    assert.equal((await snapshotUser(runtime, studentId)).email, student.email);
    await page.evaluate(value => localStorage.setItem('token', value), token);
    await clickInPanel(page, 'Edit Student Profile', 'Cancel');
    await rowButton('Edit');
    const editForm2 = await formForHeading(page, 'Edit Student Profile');
    const editedEmail = `q05-edited-${nonce}@example.invalid`;
    await replaceInput(await editForm2.$('input[type="email"]'), editedEmail);
    await editForm2.dispose();
    await phase('student-edit-response-await');
    await responseAfter(page, base, 'PUT', editEndpoint,
      () => clickInPanel(page, 'Edit Student Profile', 'Update Student', { twice: true }));
    assert.equal(witness.count('PUT', editEndpoint), editBefore + 1);
    assert.equal((await snapshotUser(runtime, studentId)).email, editedEmail);
    facts.actions.studentEdit = { cancelNoRequest: true, staleAuthorityNoRequest: true,
      oneConfirmedRequest: true, persisted: true, targetId: studentId };
    await checkpoint();

    // Student password rotates a real session; only boolean credential checks
    // leave this process and no password/hash appears in the evidence packet.
    await phase('student-password-rotate');
    const studentLogin = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: student.username, password: student.password }) });
    assert.equal(studentLogin.status, 200);
    const studentSession = await studentLogin.json();
    const priorCredential = (await runtime.query('SELECT password FROM identity.users WHERE id=$1',
      [studentId])).rows[0].password;
    const oldSession = await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
      WHERE user_id=$1 AND is_active=1`, [studentId]);
    assert(oldSession.rows[0].n >= 1);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
      WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
    [studentId, sha(studentSession.token)])).rows[0].n, 1);
    const passwordEndpoint = `/api/admin/students/${studentId}/change-password`;
    await rowButton('Password');
    const passwordBefore = witness.count('POST', passwordEndpoint);
    await clickInPanel(page, 'Change Student Password', 'Cancel');
    assert.equal(witness.count('POST', passwordEndpoint), passwordBefore);

    // Reuse the cohort's single explicitly admitted auxiliary page for all
    // authority-race facets. A second real session of the same actor supplies B.
    const alternateLogin = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'rendered-admin', password: adminPassword }) });
    assert.equal(alternateLogin.status, 200);
    const alternateToken = (await alternateLogin.json()).token;
    assert.equal(typeof alternateToken, 'string');
    assert.notEqual(alternateToken, token);
    authorityTab = await openAuthorityTab();
    await focusQ05MainPage(page);

    await phase('student-password-physical-cross-tab-aba');
    await rowButton('Password');
    const nextStudentPassword = `Q05-Student-Next-${nonce}!`;
    const staleForm = await formForHeading(page, 'Change Student Password');
    for (const input of await staleForm.$$('input[type="password"]'))
      await replaceInput(input, nextStudentPassword);
    await staleForm.dispose();
    await page.evaluate(() => {
      window.__q05StudentPasswordStorageEvents = 0;
      window.addEventListener('storage', event => {
        if (event.key === 'token') window.__q05StudentPasswordStorageEvents += 1;
      });
    });
    await authorityTab.swap(token, alternateToken);
    await focusQ05MainPage(page);
    // Do not wait for React's storage handler before attempting the pointer
    // action. Either it retires the dialog or the staged authority guard wins.
    const staleSubmit = await page.evaluateHandle(() => {
      const heading = [...document.querySelectorAll('h2')]
        .find(node => node.textContent.trim() === 'Change Student Password');
      const form = heading?.closest('form') || heading?.parentElement?.parentElement?.querySelector('form');
      return [...(form?.querySelectorAll('button') || [])]
        .find(button => button.textContent.trim() === 'Change Password' && !button.disabled) || null;
    });
    const staleButton = staleSubmit.asElement();
    if (staleButton) {
      try { await staleButton.click(); }
      catch (error) {
        const retired = await page.evaluate(() => ![...document.querySelectorAll('h2')]
          .some(node => node.textContent.trim() === 'Change Student Password'));
        if (!retired) throw error;
      }
    }
    await staleSubmit.dispose();
    await page.waitForFunction(() => window.__q05StudentPasswordStorageEvents >= 2, { timeout: 15000 });
    const passwordAbaEvents = await page.evaluate(() => window.__q05StudentPasswordStorageEvents);
    assert.equal(passwordAbaEvents, 2);
    await waitForModalHeadingAbsence(page, 'Change Student Password');
    assert.equal(witness.count('POST', passwordEndpoint), passwordBefore);
    assert.equal((await runtime.query('SELECT password FROM identity.users WHERE id=$1',
      [studentId])).rows[0].password, priorCredential);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
      WHERE user_id=$1 AND is_active=1`, [studentId])).rows[0].n, oldSession.rows[0].n);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
      WHERE user_id=$1 AND session_token_hash=$2 AND is_active=1`,
    [studentId, sha(studentSession.token)])).rows[0].n, 1);

    await phase('student-password-lost-ack');
    await remountQ05StudentPasswordAction(page, base, student.username);
    await rowButton('Password');
    const passForm = await formForHeading(page, 'Change Student Password');
    const blankDraft = await passForm.evaluate(form => [...form.querySelectorAll('input[type="password"]')]
      .every(input => input.value === ''));
    assert(blankDraft, 'ABA must retire the prior visible password draft');
    for (const input of await passForm.$$('input[type="password"]'))
      await replaceInput(input, nextStudentPassword);
    await passForm.dispose();
    const passwordResponse = q05StudentPasswordResponseWitness(page, base, passwordEndpoint);
    const passwordLoss = await installQ05StudentPasswordBrowserLoss(page, base, passwordEndpoint);
    let passwordResponseStage;
    try {
      await phase('student-password-lost-ack-response-await');
      await physicalQ05StudentPasswordButton(page, 'Change Password', { clickCount: 2 });
      await page.waitForFunction(() => document.body.innerText.includes('The password-change outcome could not be confirmed.'),
        { timeout: 15000 });
      assert.deepEqual(passwordLoss.snapshot(), { selected: true, failed: 1, failure: false });
      passwordResponseStage = passwordResponse.snapshot();
    } finally { try { await passwordLoss.close(); } finally { passwordResponse.stop(); } }
    assert.deepEqual(passwordResponseStage, { browserRequests: 1, browserFailed: 1, browserFinished: 0 });
    assert.equal(witness.count('POST', passwordEndpoint), passwordBefore + 1);
    const studentCredential = (await runtime.query('SELECT password FROM identity.users WHERE id=$1',
      [studentId])).rows[0].password;
    const bcrypt = require('bcryptjs');
    assert.equal(await bcrypt.compare(nextStudentPassword, studentCredential), true);
    assert.equal(await bcrypt.compare(student.password, studentCredential), false);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
      WHERE user_id=$1 AND is_active=1`, [studentId])).rows[0].n, 0);
    assert.equal((await fetch(`${base}/api/auth/status`, {
      headers: { authorization: `Bearer ${studentSession.token}` },
    }).then(response => response.json())).authenticated, false);
    await delay(250);
    assert.equal(witness.count('POST', passwordEndpoint), passwordBefore + 1,
      'unknown password outcome must not automatically retry');
    facts.actions.studentPassword = { cancelNoRequest: true, oneConfirmedRequest: true,
      credentialRotated: true, sessionsRevoked: true, targetId: studentId,
      crossTabAbaNoRequest: true, storageEventsObserved: passwordAbaEvents,
      secretsRetired: true, lostAckEffectPersisted: true, unknownUiNoRetry: true,
      responseStageBrowserFailure: true };
    facts.studentPasswordResponseStage = passwordResponseStage;
    await checkpoint();
    await clickInPanel(page, 'Change Student Password', 'Close');
    await waitForModalHeadingAbsence(page, 'Change Student Password');

    // A level-2 administrator creates and edits a second, strictly synthetic
    // administrator through the mounted User Management modal.
    await phase('administrator-create');
    await waitForPath(page, `${base}/admin/settings`, 'Security Settings');
    await clickNamed(page, 'Manage Users');
    await page.waitForSelector('#user-management-administrators-panel');
    const adminCreateEndpoint = '/api/admin/administrators';
    const fillAdminCreate = async () => {
      await replaceInput(await page.$('#new-admin-username'), administrator.username);
      await replaceInput(await page.$('#new-admin-email'), administrator.email);
      await replaceInput(await page.$('#new-admin-name'), 'Q05 synthetic administrator');
      await replaceInput(await page.$('#new-admin-password'), administrator.password);
      await replaceInput(await page.$('#new-admin-confirm-password'), administrator.password);
      await page.select('#new-admin-level', '1');
      await page.click('#user-management-administrators-panel input[value="user_management"]');
    };
    await clickNamed(page, 'Add administrator');
    await fillAdminCreate();
    const adminCreateBefore = witness.count('POST', adminCreateEndpoint);
    await clickNamed(page, 'Cancel administrator creation');
    assert.equal(witness.count('POST', adminCreateEndpoint), adminCreateBefore);
    assert.equal((await runtime.query('SELECT count(*)::integer AS n FROM identity.users WHERE username=$1',
      [administrator.username])).rows[0].n, 0);
    await clickNamed(page, 'Add administrator');
    await fillAdminCreate();
    await phase('administrator-create-response-await');
    await responseAfter(page, base, 'POST', adminCreateEndpoint,
      () => clickNamed(page, 'Create administrator', { within: '#user-management-administrators-panel' }));
    assert.equal(witness.count('POST', adminCreateEndpoint), adminCreateBefore + 1);
    const newAdminRows = (await runtime.query(`SELECT id FROM identity.users
      WHERE username=$1 AND role='admin' AND admin_level=1`, [administrator.username])).rows;
    assert.equal(newAdminRows.length, 1);
    const adminId = newAdminRows[0].id;
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.admin_permissions
      WHERE admin_id=$1 AND permission_name='user_management' AND is_active=1`, [adminId])).rows[0].n, 1);
    facts.actions.administratorCreate = { cancelNoRequest: true, oneConfirmedRequest: true,
      persisted: true, permissionPersisted: true, targetId: adminId };
    await checkpoint();

    await phase('administrator-edit');
    const editAdmin = async () => {
      const clicked = await page.evaluate(username => {
        const row = [...document.querySelectorAll('#user-management-administrators-panel tr')]
          .find(item => [...item.querySelectorAll('td')]
            .some(cell => cell.textContent.trim() === username));
        const button = [...(row?.querySelectorAll('button') || [])]
          .find(item => item.textContent.trim() === 'Edit');
        if (!button || button.disabled) return false;
        button.click(); return true;
      }, administrator.username);
      assert(clicked, 'New administrator must have rendered Edit action');
    };
    const adminEditEndpoint = `/api/admin/administrators/${adminId}`;
    await page.waitForFunction(username => document.body.innerText.includes(username),
      { timeout: 15000 }, administrator.username);
    await editAdmin();
    const adminEditBefore = witness.count('PUT', adminEditEndpoint);
    await clickInPanel(page, `Edit administrator: ${administrator.username}`, 'Cancel');
    assert.equal(witness.count('PUT', adminEditEndpoint), adminEditBefore);
    await editAdmin();
    const adminEditedEmail = `q05-admin-edited-${nonce}@example.invalid`;
    await replaceInput(await page.$('#edit-admin-email'), adminEditedEmail);
    await phase('administrator-edit-response-await');
    await responseAfter(page, base, 'PUT', adminEditEndpoint,
      () => clickInPanel(page, `Edit administrator: ${administrator.username}`, 'Save administrator', { twice: true }));
    assert.equal(witness.count('PUT', adminEditEndpoint), adminEditBefore + 1);
    assert.equal((await snapshotUser(runtime, adminId)).email, adminEditedEmail);
    facts.actions.administratorEdit = { cancelNoRequest: true, oneConfirmedRequest: true,
      persisted: true, targetId: adminId };
    await checkpoint();

    // A deliberately discarded *response*, after the real mounted PUT returns,
    // is an uncertain outcome. The UI may read current state but must not turn
    // that readback into a repeat of the original mutation.
    await phase('administrator-edit-lost-ack');
    await editAdmin();
    const lostAckEmail = `q05-acklost-${nonce}@example.invalid`;
    await replaceInput(await page.$('#edit-admin-email'), lostAckEmail);
    const beforeLoss = witness.count('PUT', adminEditEndpoint);
    armAcknowledgementLoss('PUT', adminEditEndpoint);
    await phase('administrator-edit-lost-ack-response-await');
    await clickInPanel(page, `Edit administrator: ${administrator.username}`, 'Save administrator');
    await page.waitForFunction(() => document.body.innerText.includes('The update outcome could not be confirmed.'),
      { timeout: 15000 });
    assert.equal(witness.count('PUT', adminEditEndpoint), beforeLoss + 1);
    assert.equal((await snapshotUser(runtime, adminId)).email, lostAckEmail);
    await delay(250);
    assert.equal(witness.count('PUT', adminEditEndpoint), beforeLoss + 1,
      'unknown ACK outcome must not cause an automatic PUT retry');
    facts.actions.administratorEdit.lostAckEffectPersisted = true;
    facts.actions.administratorEdit.unknownUiNoRetry = true;
    facts.lateAck = 'one-response-discarded-after-mounted-effect';
    await checkpoint();

    await clickInPanel(page, `Edit administrator: ${administrator.username}`, 'Close');
    const deactivation = await runAdministratorDeactivationQ05({ page, base, runtime,
      admin, adminId, administrator, adminPassword, token, authorityTab,
      armAcknowledgementLoss, witness, phase, firstStudent, secondStudent,
      onLostAckFailure: async (error, diagnostic) => {
        deactivationLossDiagnostic = diagnostic;
        facts.failure = { phase: facts.phase, primary: q05PrimaryErrorFact(error),
          deactivationLostAck: diagnostic };
        await checkpoint();
      } });
    facts.actions.administratorDeactivation = deactivation.action;
    facts.administratorDeactivationResponseStage = deactivation.responseStage;
    await checkpoint();

    const accountAccess = await runAccountAccessQ05({ page, base, runtime, studentId,
      student, password: nextStudentPassword, token,
      alternateToken: deactivation.alternateToken, authorityTab,
      armAcknowledgementLoss, witness, phase });
    await authorityTab.close();
    authorityTab = null;
    facts.actions.accountLock = accountAccess.lock;
    facts.actions.accountUnlock = accountAccess.unlock;
    await checkpoint();

    // Global visibility is a catalog-wide action, not a single filtered row.
    await phase('global-visibility-disable');
    await waitForPath(page, `${base}/admin/exercises`, 'Exercises Management');
    const visibilityEndpoint = '/api/admin/challenges/bulk-toggle';
    const visibilityBefore = (await runtime.query(`SELECT workshop_key,catalog_active,is_visible,
      show_hints,show_solutions FROM workshop_platform.exercises ORDER BY workshop_key`)).rows;
    const visibilityCount = witness.count('POST', visibilityEndpoint);
    await clickNamed(page, 'Disable All');
    await page.waitForSelector('[aria-label="Confirm all exercise visibility change"]');
    await clickNamed(page, 'Cancel', { within: '[aria-label="Confirm all exercise visibility change"]' });
    assert.equal(witness.count('POST', visibilityEndpoint), visibilityCount);
    assert.deepEqual((await runtime.query(`SELECT workshop_key,catalog_active,is_visible,
      show_hints,show_solutions FROM workshop_platform.exercises ORDER BY workshop_key`)).rows,
    visibilityBefore);
    await clickNamed(page, 'Disable All');
    await phase('global-visibility-disable-response-await');
    await responseAfter(page, base, 'POST', visibilityEndpoint,
      () => clickInPanel(page, 'Disable all exercises?', 'Confirm Disable All', { twice: true }));
    assert.equal(witness.count('POST', visibilityEndpoint), visibilityCount + 1);
    const visibilityAfter = (await runtime.query(`SELECT workshop_key,catalog_active,is_visible,
      show_hints,show_solutions FROM workshop_platform.exercises ORDER BY workshop_key`)).rows;
    assert(visibilityAfter.some(row => row.catalog_active), 'Active catalog exercise required');
    for (const [index, row] of visibilityAfter.entries()) {
      assert.equal(row.is_visible, row.catalog_active ? false : visibilityBefore[index].is_visible);
      assert.equal(row.show_hints, visibilityBefore[index].show_hints);
      assert.equal(row.show_solutions, visibilityBefore[index].show_solutions);
    }
    facts.actions.globalVisibilityDisable = { cancelNoRequest: true, oneConfirmedRequest: true,
      activeRowsHidden: true, otherGatesPreserved: true };
    await checkpoint();

    // Enabling is an intentional exception in this cohort: the real
    // SecureShop-ready predicate is false. Preserve the genuine 409 rather
    // than fabricating readiness or silently re-enabling that application.
    await phase('global-visibility-enable-readiness');
    const secureShopKey = require('../../server/config/secureshopCurriculum').WORKSHOP_KEY;
    assert(visibilityAfter.some(row => row.workshop_key === secureShopKey && row.catalog_active));
    await clickNamed(page, 'Enable All');
    const enableBefore = witness.count('POST', visibilityEndpoint);
    await clickNamed(page, 'Cancel', { within: '[aria-label="Confirm all exercise visibility change"]' });
    assert.equal(witness.count('POST', visibilityEndpoint), enableBefore);
    await clickNamed(page, 'Enable All');
    await phase('global-visibility-enable-response-await');
    const enableResponse = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.origin === base && url.pathname === visibilityEndpoint
        && response.request().method() === 'POST';
    }, { timeout: 15000 });
    await clickNamed(page, 'Confirm Enable All', {
      within: '[aria-label="Confirm all exercise visibility change"]' });
    const rejected = await enableResponse;
    assert.equal(rejected.status(), 409, 'unready SecureShop must reject Enable All');
    const rejectionBody = await rejected.json();
    assert.equal(rejectionBody.code, 'EXERCISE_NOT_READY');
    assert.equal(witness.count('POST', visibilityEndpoint), enableBefore + 1);
    assert.deepEqual((await runtime.query(`SELECT workshop_key,catalog_active,is_visible,
      show_hints,show_solutions FROM workshop_platform.exercises ORDER BY workshop_key`)).rows,
    visibilityAfter);
    facts.actions.globalVisibilityEnable = { cancelNoRequest: true,
      oneConfirmedRequest: true, legitimateReadiness409: true, noEffect: true };
    await checkpoint();

    // Self rotation is last because the acknowledged write revokes the browser
    // administrator session. A fresh login proves the new credential while the
    // old token is denied; neither secret is retained in the journal.
    await phase('self-password-rotate');
    await waitForPath(page, `${base}/admin/settings`, 'Security Settings');
    const selfEndpoint = '/api/admin/account/change-password';
    await clickNamed(page, 'Change Password');
    const selfBefore = witness.count('POST', selfEndpoint);
    await clickInPanel(page, 'Change Password', 'Cancel', { modalHeadingOnly: true });
    assert.equal(witness.count('POST', selfEndpoint), selfBefore);
    await waitForModalHeadingAbsence(page, 'Change Password');
    await clickNamed(page, 'Change Password');
    const selfForm = await formForHeading(page, 'Change Password', { modalHeadingOnly: true });
    const selfInputs = await selfForm.$$('input[type="password"]');
    assert.equal(selfInputs.length, 3);
    const newAdminPassword = `Q05-Admin-Next-${nonce}!`;
    await replaceInput(selfInputs[0], adminPassword);
    await replaceInput(selfInputs[1], newAdminPassword);
    await replaceInput(selfInputs[2], newAdminPassword);
    await selfForm.dispose();
    await phase('self-password-response-await');
    await responseAfter(page, base, 'POST', selfEndpoint,
      () => clickInPanel(page, 'Change Password', 'Change Password',
        { twice: true, modalHeadingOnly: true }));
    assert.equal(witness.count('POST', selfEndpoint), selfBefore + 1);
    const selfCredential = (await runtime.query('SELECT password FROM identity.users WHERE id=$1',
      [admin.id])).rows[0].password;
    assert.equal(await bcrypt.compare(newAdminPassword, selfCredential), true);
    assert.equal(await bcrypt.compare(adminPassword, selfCredential), false);
    assert.equal((await runtime.query(`SELECT count(*)::integer AS n FROM identity.user_sessions
      WHERE user_id=$1 AND is_active=1`, [admin.id])).rows[0].n, 0);
    assert.equal((await fetch(`${base}/api/auth/status`, {
      headers: { authorization: `Bearer ${token}` },
    }).then(response => response.json())).authenticated, false);
    const freshAdminLogin = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'rendered-admin', password: newAdminPassword }) });
    assert.equal(freshAdminLogin.status, 200);
    facts.actions.selfPassword = { cancelNoRequest: true, oneConfirmedRequest: true,
      credentialRotated: true, priorSessionRevoked: true, freshLogin: true };
    await checkpoint();

    assert.deepEqual(await snapshotSiblings(runtime, firstStudent, secondStudent), siblingBefore,
      'Q05 rendered actions must preserve both original learners and their progress');
    facts.siblingsPreserved = true;
    facts.requestCounts = Object.fromEntries(Object.entries(witness.totals())
      .filter(([key]) => /^(POST|PUT|DELETE) \/api\/admin\//.test(key)));
    facts.phase = 'complete';
    facts.status = 'bounded-rendered-manual-actions-observed';
    await checkpoint();
    return facts;
  } catch (error) {
    primaryFailure = error;
    facts.failure = { phase: facts.phase, primary: q05PrimaryErrorFact(error) };
    if (deactivationLossDiagnostic) facts.failure.deactivationLostAck = deactivationLossDiagnostic;
    try { await checkpoint(); } catch { /* Preserve the primary failure. */ }
    Object.assign(facts.failure, {
      studentCreatePostCount: witness.count('POST', '/api/admin/students'),
      studentRosterGetCount: witness.count('GET', '/api/admin/students'),
      rosterGet200AfterCreateSubmitCount: rosterReadbacks.filter(row => row.afterCreateSubmit
        && row.status === 200).length,
      rosterGet200AfterCreateSubmitContainsSyntheticTarget: rosterReadbacks.some(row => row.afterCreateSubmit
        && row.status === 200
        && row.containsSyntheticTarget),
    });
    if (facts.phase === 'student-create-sql-confirmed-await-rendered-row') {
      try { facts.failure.readback = await studentReadbackFlags(page, student.username); }
      catch { facts.failure.readbackUnavailable = true; }
    }
    try { facts.failure.formValidity = await formValidityFlags(page); }
    catch { facts.failure.formValidityUnavailable = true; }
    try { await checkpoint(); } catch { /* Preserve the original failure. */ }
    throw error;
  } finally {
    try {
      if (authorityTab) await authorityTab.close();
    } catch (closeError) {
      if (!primaryFailure) throw closeError;
    } finally {
      page.off('response', onRoster);
      witness.stop();
    }
  }
}

module.exports = { admitQ05, buildInventory, validateLaunchGrant,
  deactivationDiscardFact, createQ05DeactivationAckCapture,
  installQ05DeactivationAckObserver, q05DeactivationResponseIdentity,
  installQ05DeactivationBrowserLoss, installQ05StudentPasswordBrowserLoss,
  q05StudentPasswordResponseWitness, physicalQ05StudentPasswordButton,
  q05PrimaryErrorFact, closeQ05OwnedServer,
  requestWitness, q05ExactResponseWitness, q05DeactivationFailureFact,
  q05RecordDeactivationFailure,
  q05PageTargets, q05AuxiliaryRequestAllowed,
  renderedRowAction, focusQ05MainPage, physicalQ05DeactivationRowAction,
  physicalQ05NamedButton, physicalQ05AccountButton,
  physicalQ05DeactivationButton,
  clickNamed, clickInPanel, formForHeading, waitForModalHeadingAbsence,
  remountQ05StudentPasswordAction,
  studentReadbackFlags, formValidityFlags,
  replaceInput };
