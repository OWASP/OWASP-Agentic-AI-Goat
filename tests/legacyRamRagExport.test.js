'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { fork } = require('node:child_process');
const { once } = require('node:events');
const { exportLegacyRamRag, expressionFor, evaluateInspector } = require('./fixtures/legacyRamRagExport');

test('one inspector event exports only the cached legacy RAG singleton Maps without pausing', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-legacy-rag-export-'));
  fs.chmodSync(root, 0o700); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const child = fork(path.join(__dirname, 'fixtures/legacyRamRagExportTarget.js'), [], {
    execArgv: ['--inspect=127.0.0.1:0'], stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    env: { PATH: process.env.PATH, HOME: root },
  });
  t.after(async () => { if (child.exitCode === null) { child.send('stop'); await once(child, 'exit'); } });
  let latestHeartbeat = 0;
  child.on('message', message => { if (message.type === 'heartbeat') latestHeartbeat = message.heartbeat; });
  child.send('ready');
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Fixture readiness timed out')), 5000);
    child.on('message', message => { if (message.type === 'ready') { clearTimeout(timer); resolve(message); } });
  });
  assert.match(ready.url, /^ws:\/\/127\.0\.0\.1:/);
  const moduleFile = path.join(__dirname, '../server/services/ragVectorStore.js');
  await assert.rejects(exportLegacyRamRag({ inspectorUrl: ready.url, output: path.join(root, 'wrong-pid.json'),
    expectedPid: child.pid + 1, expectedModule: moduleFile }), /Originating-process export failed/);
  await assert.rejects(exportLegacyRamRag({ inspectorUrl: ready.url, output: path.join(root, 'wrong-module.json'),
    expectedPid: child.pid, expectedModule: path.join(__dirname, '../server/services/ragProgressStore.js') }), /Originating-process export failed/);
  assert.equal(fs.existsSync(path.join(root, 'wrong-pid.json')), false);
  assert.equal(fs.existsSync(path.join(root, 'wrong-module.json')), false);
  const unsafeOutput = path.join(root, 'unsafe-parent.json');
  const unsafeExpression = expressionFor(unsafeOutput, { expectedPid: child.pid, expectedModule: moduleFile });
  fs.chmodSync(root, 0o755);
  await assert.rejects(evaluateInspector({ url: ready.url, expression: unsafeExpression }), /Originating-process export failed/);
  fs.chmodSync(root, 0o700); assert.equal(fs.existsSync(unsafeOutput), false);
  const racedOutput = path.join(root, 'raced.json');
  const racedExpression = expressionFor(racedOutput, { expectedPid: child.pid, expectedModule: moduleFile });
  fs.writeFileSync(racedOutput, 'preexisting', { mode: 0o600, flag: 'wx' });
  await assert.rejects(evaluateInspector({ url: ready.url, expression: racedExpression }), /Originating-process export failed/);
  assert.equal(fs.readFileSync(racedOutput, 'utf8'), 'preexisting');
  const before = latestHeartbeat, output = path.join(root, 'legacy-rag.json');
  const receipt = await exportLegacyRamRag({ inspectorUrl: ready.url, output,
    expectedPid: child.pid, expectedModule: moduleFile });
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.ok(latestHeartbeat > before, 'target event loop must continue after the single evaluation');
  assert.equal(receipt.sessions, 1); assert.equal(receipt.selections, 1); assert.equal(receipt.owners, 1);
  assert.equal(receipt.chunks, 2); assert.equal(receipt.vectors, 768);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  const bytes = fs.readFileSync(output, 'utf8');
  assert.equal(receipt.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
  assert.doesNotMatch(bytes, /DO-NOT-EXPORT|must-not-export|LEGACY_EXPORT_TEST_SECRET|CSRF/);
  const archive = JSON.parse(bytes);
  assert.deepEqual(Object.keys(archive).sort(), ['process', 'runtimeFingerprint', 'scope', 'selections', 'sessions', 'version']);
  assert.equal(archive.runtimeFingerprint, 'a'.repeat(64));
  assert.equal(archive.process.pid, child.pid); assert.equal(archive.process.module, fs.realpathSync(moduleFile));
  assert.deepEqual(archive.sessions.map(({ ownerId, sessionId, filename }) =>
    ({ ownerId, sessionId, filename })), [{ ownerId: '17', sessionId: '11111111-1111-4111-8111-111111111111', filename: 'owned.txt' }]);
  assert.deepEqual(archive.selections, [{ ownerId: '17', sessionId: '11111111-1111-4111-8111-111111111111',
    filename: 'selection-fallback.txt', chunksStored: 2 }]);
  assert.deepEqual(archive.sessions[0].chunks.map(row => [row.chunkIndex, row.text, row.embedding.length]),
    [[0, 'owned first teaching chunk', 384], [1, 'owned second teaching chunk', 384]]);
  await assert.rejects(exportLegacyRamRag({ inspectorUrl: ready.url, output,
    expectedPid: child.pid, expectedModule: moduleFile }), /output must be new/i);
});
