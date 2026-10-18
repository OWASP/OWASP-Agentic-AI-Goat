'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { launchOwnedAssessmentBrowserForTest, createAssessmentDenyProxy,
  PROFILE_NAME, PROCESS_RECEIPT, CLEANUP_RECEIPT } = require('./fixtures/fullBackendAssessmentBrowser');

function controlledBrowserFixture(t, { newPageError, stopError, absent = true } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-assessment-browser-')));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = path.join(root, 'pinned-browser');
  fs.writeFileSync(executable, 'controlled browser fixture', { mode: 0o700 });
  const expectedSha256 = createHash('sha256').update(fs.readFileSync(executable)).digest('hex');
  const child = Object.assign(new EventEmitter(), { pid: 424242, stderr: new PassThrough() });
  let launchedArgs;
  let stopped = false;
  let disconnected = 0;
  const owned = {
    launch(command, args, options) {
      assert.equal(command, executable);
      assert.equal(options.detached, undefined, 'the owned launcher controls detached=false');
      assert.equal(options.cwd, root);
      launchedArgs = args;
      const port = Number(args.find(value => value.startsWith('--remote-debugging-port=')).split('=')[1]);
      process.nextTick(() => child.stderr.write(`DevTools listening on ws://127.0.0.1:${port}/devtools/browser/01234567-89ab-4cde-8fab-0123456789ab\n`));
      return child;
    },
    async stop(value) {
      assert.equal(value, child);
      if (stopError) throw stopError;
      stopped = true;
    },
  };
  const options = { root, admission: { executable }, owned,
    captureIdentity: pid => Object.freeze({ pid, pgid: 99, sessionId: 99, uid: process.getuid(),
      qualificationPid: 99, qualificationPgid: 99, qualificationSessionId: 99, workerPid: process.pid }),
    processAbsent: pid => { assert.equal(pid, child.pid);return absent && stopped; },
    connect: async endpoint => {
      assert.match(endpoint, /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\//);
      return { async newPage() {
        if (newPageError) throw newPageError;
        const proxyOrigin = launchedArgs.find(value => value.startsWith('--proxy-server=')).slice('--proxy-server='.length);
        return { async goto() { const response = await fetch(proxyOrigin);return { status: () => response.status }; },
          async close() {} };
      }, disconnect() { disconnected++; } };
    } };
  return { root, executable, expectedSha256, child, options,
    state: () => ({ launchedArgs, stopped, disconnected }) };
}

test('assessment deny proxy rejects ordinary HTTP, CONNECT and upgrade traffic', async t => {
  const proxy = await createAssessmentDenyProxy();
  t.after(() => proxy.close());
  const response = await fetch(`${proxy.origin}/http://external.invalid/`);
  assert.equal(response.status, 403);
  assert.equal(await response.text(), 'Denied');
  const endpoint = new URL(proxy.origin);
  const exchange = payload => new Promise((resolve, reject) => {
    const socket = net.connect({ host: endpoint.hostname, port: Number(endpoint.port) });
    let output = '';
    socket.setEncoding('utf8');
    socket.once('connect', () => socket.end(payload));
    socket.on('data', chunk => { output += chunk; });
    socket.once('end', () => resolve(output));
    socket.once('error', reject);
  });
  assert.match(await exchange('CONNECT external.invalid:443 HTTP/1.1\r\nHost: external.invalid\r\n\r\n'), /^HTTP\/1\.1 403/);
  assert.match(await exchange('GET / HTTP/1.1\r\nHost: external.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'), /^HTTP\/1\.1 403/);
  assert.deepEqual(proxy.counters(), { denied: 1, connectDenied: 1, upgradeDenied: 1 });
});

test('owned assessment browser uses fixed private artifacts and proves cleanup', async t => {
  const fixture = controlledBrowserFixture(t);
  const { root, expectedSha256, child } = fixture;
  const lifecycle = await launchOwnedAssessmentBrowserForTest(fixture.options, expectedSha256);
  assert.match(lifecycle.endpoint, /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\//);
  assert.ok(fixture.state().launchedArgs.includes(`--user-data-dir=${path.join(root, PROFILE_NAME)}`));
  assert.ok(fixture.state().launchedArgs.includes('--proxy-bypass-list=<-loopback>'));
  assert.ok(fixture.state().launchedArgs.includes('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'));
  assert.equal(fixture.state().disconnected, 1, 'the smoke client disconnects without stopping the browser');
  const processReceipt = JSON.parse(fs.readFileSync(path.join(root, PROCESS_RECEIPT)));
  assert.equal(processReceipt.pid, child.pid);
  assert.equal(processReceipt.profile, path.join(root, PROFILE_NAME));
  assert.equal(processReceipt.executableSha256, expectedSha256);
  await lifecycle.close();
  assert.equal(fixture.state().stopped, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, CLEANUP_RECEIPT))), {
    browserPid: child.pid, pidAbsent: true, profileAbsent: true, closed: true,
  });
  assert.equal(fs.existsSync(path.join(root, PROFILE_NAME)), false);
  await lifecycle.close();
});

test('assessment browser disconnects and cleans up when smoke page creation fails', async t => {
  const fixture = controlledBrowserFixture(t, { newPageError: new Error('controlled newPage failure') });
  await assert.rejects(launchOwnedAssessmentBrowserForTest(fixture.options, fixture.expectedSha256),
    /controlled newPage failure/);
  assert.equal(fixture.state().disconnected, 1);
  assert.equal(fixture.state().stopped, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fixture.root, CLEANUP_RECEIPT))), {
    browserPid: fixture.child.pid, pidAbsent: true, profileAbsent: true, closed: true,
  });
});

test('assessment browser retains its profile and fails cleanup when stop or absence proof fails', async t => {
  for (const failure of [
    { stopError: new Error('controlled stop failure'), absent: true },
    { absent: false },
  ]) {
    const fixture = controlledBrowserFixture(t, failure);
    const lifecycle = await launchOwnedAssessmentBrowserForTest(fixture.options, fixture.expectedSha256);
    await assert.rejects(lifecycle.close(), /Assessment browser cleanup failed/);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fixture.root, CLEANUP_RECEIPT))), {
      browserPid: fixture.child.pid, pidAbsent: false, profileAbsent: false, closed: false,
    });
    assert.equal(fs.existsSync(path.join(fixture.root, PROFILE_NAME)), true);
  }
});
