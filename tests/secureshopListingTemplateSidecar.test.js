'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const executorModule = require('../sidecars/sandbox-runner/listing-template/executor');
const strict = require('../sidecars/sandbox-runner/listing-template/strict-helpers');
const { createListingTemplateHttpHandler } = require('../sidecars/sandbox-runner/listing-template/http-handler');
const { createListingTemplateOnlyListener } = require('../sidecars/sandbox-runner/listing-template/listener');
const { normalizeListingTemplateExecution, listingTemplateExecutionDigest, ISOLATION }
  = require('../server/services/secureshopListingTemplateExecutorContract');

const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const source = 'Hello {{ title }}';
const request = normalizeListingTemplateExecution({ version: 1,
  operationId: '123e4567-e89b-42d3-a456-426614174000', productId: 7,
  sourceSha256: digest(source), templateSource: source, title: 'world', description: '', price: 0 });
const attestation = 'listing-template-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n';

function writable(onWrite) { return new Writable({ write(chunk, _encoding, done) { onWrite?.(chunk); done(); } }); }
function fakeSpawn({ rendered = 'Hello world', effect = false, prefix = attestation } = {}) {
  return (_bin, argv) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    const canary = [];
    child.stdio = [null, child.stdout, child.stderr, writable(), writable(), writable(), writable(), writable(),
      writable(chunk => canary.push(Buffer.from(chunk))), writable()];
    child.kill = () => queueMicrotask(() => child.emit('close', 137));
    queueMicrotask(() => {
      const payload = JSON.parse(Buffer.from(argv.at(-2), 'base64').toString('utf8'));
      if (effect) {
        const root = argv[argv.indexOf('--bind') + 1];
        fs.writeFileSync(require('node:path').join(root, 'command-effect'), Buffer.concat(canary), { mode: 0o600 });
      }
      const bytes = Buffer.from(rendered);
      const envelope = { version: 1, operationId: payload.operationId, productId: payload.productId,
        requestSha256: payload.requestSha256, sourceSha256: payload.sourceSha256, isolation: ISOLATION,
        renderedBase64: bytes.toString('base64'), renderedSha256: digest(bytes) };
      child.stdout.end(prefix + argv.at(-1) + Buffer.from(JSON.stringify(envelope)).toString('base64'));
      child.stderr.end(); child.emit('close', 0);
    });
    return child;
  };
}
function executor(options = {}) {
  return executorModule.createListingTemplateExecutor({ spawnSyncImpl: () => ({ status: 0 }),
    existsSync: () => true, spawnImpl: fakeSpawn(options) });
}

test('template package pins separate worker and contract and never alters policy asset contract', () => {
  const assets = executorModule.checkedAssets();
  assert.equal(digest(assets.worker), executorModule.WORKER_SHA256);
  assert.equal(digest(assets.contract), executorModule.CONTRACT_SHA256);
  assert.equal(digest(assets.compiler), strict.COMPILER_SHA256);
  assert.equal(assets.contract.toString('utf8'), fs.readFileSync(require.resolve('../server/services/secureshopListingTemplateExecutorContract'), 'utf8'));
  const argv = executorModule.buildListingTemplateArgv(request, `__LISTING_TEMPLATE_${'a'.repeat(64)}__`, ['/usr']);
  assert.ok(argv.includes('--unshare-net'));
  assert.ok(argv.includes('/opt/listing-template/worker.js'));
  assert.ok(argv.includes('/owned-source/effect-canary'));
  assert.ok(argv.includes('/owned-effect'));
  assert.equal(argv.at(-4), strict.DEFAULT_INIT);
  assert.equal(argv.at(-3), '--render');
});

test('rendered command-looking output is not a command effect; owned canary file is', async () => {
  const textOnly = await executor({ rendered: 'command-effect' }).execute(request);
  assert.equal(textOnly.rendered, 'command-effect');
  assert.equal(textOnly.commandEffectObserved, false);
  assert.equal(executorModule.listingTemplateEffectWitnessFor(textOnly).commandEffectObserved, false);
  const actual = await executor({ effect: true }).execute(request);
  assert.equal(actual.rendered, 'Hello world');
  assert.equal(actual.commandEffectObserved, true);
  assert.match(actual.effectSha256, /^[0-9a-f]{64}$/);
  assert.equal(executorModule.listingTemplateEffectWitnessFor(actual).effectSha256, actual.effectSha256);
  assert.equal(actual.requestSha256, listingTemplateExecutionDigest(request));
});

test('changed init attestation cannot produce a command witness', async () => {
  await assert.rejects(executor({ effect: true, prefix: 'forged\n' + attestation }).execute(request),
    { code: 'LISTING_TEMPLATE_EXECUTION_INVALID' });
});

test('unreadable effect evidence rejects cleanly after namespace drain', async () => {
  let cleanupCalled = false;
  const actual = executorModule.createListingTemplateExecutor({ spawnSyncImpl: () => ({ status: 0 }),
    existsSync: () => true, spawnImpl: fakeSpawn({ effect: true }),
    observeEffect: () => { throw new Error('private filesystem detail'); },
    cleanupEffectRoot: root => { cleanupCalled = true; strict.cleanupEffectRoot(root); } });
  await assert.rejects(actual.execute(request), error => error?.code === 'LISTING_TEMPLATE_EFFECT_UNAVAILABLE'
    && !error.message.includes('private filesystem detail'));
  assert.equal(cleanupCalled, true);
});

test('genuine executor result survives the private witness gate and HTTP contract', async () => {
  const real = executor({ effect: true });
  const handler = createListingTemplateHttpHandler({ executor: real });
  const server = http.createServer((req, res) => handler.handle(req, res));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/secureshop/listing-template-render`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) });
    assert.equal(response.status, 200);
    const value = await response.json();
    assert.equal(value.commandEffectObserved, true);
    assert.equal(value.operationId, request.operationId);
    assert.equal(value.requestSha256, listingTemplateExecutionDigest(request));
  } finally { await handler.close(); await new Promise(resolve => server.close(resolve)); }
});

test('dedicated listener exposes only health and template execution routes', async () => {
  const executable = { isFile: () => true, isSymbolicLink: () => false, uid: 0, gid: 0, mode: 0o555 };
  const listener = createListingTemplateOnlyListener({
    env: { SECURESHOP_LISTING_TEMPLATE_ENABLED: 'true', SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT: '1' },
    lstatSync: () => executable, checkAssets: () => true, strictProbe: () => true,
    createExecutor: () => executor({}),
  });
  await listener.listen(0, '127.0.0.1');
  const origin = `http://127.0.0.1:${listener.server.address().port}`;
  try {
    const health = await fetch(origin + '/health');
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok', listingTemplate: {
      enabled: true, available: true, isolation: ISOLATION } });
    for (const path of ['/exec', '/reset', '/secureshop/policy-render']) {
      const response = await fetch(origin + path);
      assert.equal(response.status, 404);
    }
  } finally { await listener.close(); }
});
