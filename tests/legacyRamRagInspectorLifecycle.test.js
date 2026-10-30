'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { fork } = require('node:child_process');
const { once } = require('node:events');
const { exportThroughOwnedInspector, tcpOpen } = require('./fixtures/legacyRamRagInspectorLifecycle');

const runtimes = [['current-runtime', process.execPath]];
if (process.env.LEGACY_RAM_RAG_RUNTIME_QUALIFICATION === '1') {
  runtimes.push(
    ['installed-node-26.7', '/Users/averma5/.local/opt/agentic-ai-goat/node-v26.7.0-darwin-arm64/bin/node'],
    ['managed-node-26.9', '/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node'],
  );
}

async function freePort() {
  const server = net.createServer(); server.unref();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function fixture(t, executable) {
  assert.ok(fs.statSync(executable).isFile());
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-rag-inspector-life-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const port = await freePort(), stderr = path.join(root, 'stderr.log'), descriptor = fs.openSync(stderr, 'wx', 0o600);
  const child = fork(path.join(__dirname, 'fixtures/legacyRamRagExportTarget.js'), [], {
    execPath: executable, execArgv: [`--inspect-port=127.0.0.1:${port}`],
    stdio: ['ignore', 'ignore', descriptor, 'ipc'], env: { PATH: path.dirname(executable), HOME: root },
  });
  fs.closeSync(descriptor);
  t.after(async () => { if (child.exitCode === null) { child.send('stop'); await once(child, 'exit'); } });
  let heartbeat = 0; child.on('message', message => { if (message.type === 'heartbeat') heartbeat = message.heartbeat; });
  child.send('ready');
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Fixture readiness timed out')), 5000);
    child.on('message', message => { if (message.type === 'ready') { clearTimeout(timer); resolve(message); } });
  });
  assert.equal(ready.url, undefined); assert.equal(await tcpOpen(port), false, 'inspector must start disabled');
  return { root, port, child, heartbeat: () => heartbeat };
}

for (const [label, executable] of runtimes) {
  test(`${label} enables, exports and closes only its owned inspector while application stays alive`, async t => {
    const owned = await fixture(t, executable), before = owned.heartbeat();
    const receipt = await exportThroughOwnedInspector({ pid: owned.child.pid, port: owned.port,
      expectedModule: path.join(__dirname, '../server/services/ragVectorStore.js'), output: path.join(owned.root, 'archive.json') });
    assert.equal(receipt.pid, owned.child.pid); assert.equal(receipt.sessions, 1);
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(owned.child.exitCode, null); assert.ok(owned.heartbeat() > before);
    assert.equal(await tcpOpen(owned.port), false);
  });

  test(`${label} closes its matching inspector after export failure without stopping application`, async t => {
    const owned = await fixture(t, executable), before = owned.heartbeat();
    await assert.rejects(exportThroughOwnedInspector({ pid: owned.child.pid, port: owned.port,
      expectedModule: path.join(__dirname, '../server/services/ragProgressStore.js'), output: path.join(owned.root, 'archive.json') }),
    /Originating-process export failed/);
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(owned.child.exitCode, null); assert.ok(owned.heartbeat() > before);
    assert.equal(await tcpOpen(owned.port), false); assert.equal(fs.existsSync(path.join(owned.root, 'archive.json')), false);
  });

  test(`${label} rediscovers and closes after failure immediately following SIGUSR1`, async t => {
    const owned = await fixture(t, executable), before = owned.heartbeat();
    await assert.rejects(exportThroughOwnedInspector({ pid: owned.child.pid, port: owned.port,
      expectedModule: path.join(__dirname, '../server/services/ragVectorStore.js'), output: path.join(owned.root, 'archive.json'),
      failurePoint: 'after-signal' }), /Injected lifecycle failure after signal/);
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(owned.child.exitCode, null); assert.ok(owned.heartbeat() > before);
    assert.equal(await tcpOpen(owned.port), false); assert.equal(fs.existsSync(path.join(owned.root, 'archive.json')), false);
  });
}
