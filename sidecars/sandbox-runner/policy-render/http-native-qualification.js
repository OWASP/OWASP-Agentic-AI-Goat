'use strict';

// Disposable native-only HTTP composition qualification. It is not an entrypoint.
const crypto = require('node:crypto');
const http = require('node:http');
const { createPolicyRenderExecutor, policyRenderEffectWitnessFor, ISOLATION } = require('./executor');
const { createPolicyRenderHttpHandler, MAX_BODY_BYTES } = require('./http-handler');
const { createSecureShopPolicySandboxRuntime } = require('../../../server/services/secureshopPolicySandboxRuntime');

const expression = command => `{{ process.mainModule.require('node:child_process').execFileSync('/bin/sh',['-c',${JSON.stringify(command)}]).toString() }}`;
const request = markdown => ({ operationId: crypto.randomUUID(), name: 'native-http-policy', markdown, targets: ['admin'] });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

async function jsonResponse(response) { return { status: response.status, body: await response.json() }; }
async function raw(url, bytes) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = http.request({ host: target.hostname, port: target.port, path: target.pathname, method: 'POST',
      headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.end(bytes);
  });
}

async function main() {
  const base = createPolicyRenderExecutor({ timeoutMs: 1000, drainGraceMs: 2000 });
  const controls = new Map();
  const observed = new Map();
  const executor = { async render(value, options) {
    const control = controls.get(value.operationId); control?.admitted.resolve();
    options.signal?.addEventListener('abort', () => control?.aborted.resolve(), { once: true });
    try {
      const result = await base.render(value, options);
      observed.set(value.operationId, policyRenderEffectWitnessFor(result));
      return result;
    } finally {
      control?.baseSettled.resolve();
      if (control?.hold) await control.hold.promise;
      control?.finished.resolve();
    }
  } };
  const handler = createPolicyRenderHttpHandler({ executor, maxConcurrent: 1, bodyTimeoutMs: 500 });
  const server = http.createServer(async (req, res) => {
    if (!await handler.handle(req, res)) { res.writeHead(404); res.end(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const url = `${baseUrl}/secureshop/policy-render`;
  const runtime = createSecureShopPolicySandboxRuntime({ baseUrl, timeoutMs: 5000 });

  const inertRequest = request('Returns for {{ store_name }}.');
  const inert = await runtime.render(inertRequest);
  if (inert.rendered !== 'Returns for SecureShop.' || inert.isolation !== ISOLATION || !inert.drained) throw new Error('Backend client composition failed');

  const exploitRequest = request(`${expression('umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect')}http-command-effect`);
  const exploit = await runtime.render(exploitRequest);
  const exploitWitness = observed.get(exploitRequest.operationId);
  if (exploit.rendered !== 'http-command-effect' || !exploitWitness?.commandEffectObserved || !exploitWitness?.workerAttested) throw new Error('HTTP synthetic effect was not independently observed');

  const malformedUtf8 = await raw(url, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]));
  const oversized = await raw(url, Buffer.alloc(MAX_BODY_BYTES + 1, 0x20));
  if (malformedUtf8.status !== 400 || oversized.status !== 413) throw new Error('Malformed HTTP admission was not bounded');

  const slowRequest = request(expression("exec sh -c 'sleep 30 & wait'"));
  const slowControl = { admitted: deferred(), aborted: deferred(), baseSettled: deferred(), finished: deferred() };
  controls.set(slowRequest.operationId, slowControl);
  const slow = fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(slowRequest) });
  await slowControl.admitted.promise;
  const busy = await jsonResponse(await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request('busy')) }));
  const slowResponse = await jsonResponse(await slow);
  if (busy.status !== 503 || busy.body.error !== 'POLICY_RENDER_BUSY' || slowResponse.status !== 503) throw new Error('HTTP capacity bound failed');

  const disconnectRequest = request(expression("exec sh -c 'sleep 30 & wait'"));
  const disconnectControl = { admitted: deferred(), aborted: deferred(), baseSettled: deferred(), finished: deferred(), hold: deferred() };
  controls.set(disconnectRequest.operationId, disconnectControl);
  const disconnected = http.request(url, { method: 'POST', headers: { 'content-type': 'application/json' } });
  disconnected.on('error', () => {}); disconnected.end(JSON.stringify(disconnectRequest));
  await disconnectControl.admitted.promise; disconnected.destroy(); await disconnectControl.aborted.promise;
  await disconnectControl.baseSettled.promise;
  const retained = await jsonResponse(await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request('retained')) }));
  if (retained.status !== 503 || retained.body.error !== 'POLICY_RENDER_BUSY') throw new Error('Disconnect released capacity before executor settlement');
  disconnectControl.hold.resolve(); await disconnectControl.finished.promise;

  const shutdownRequest = request(expression("exec sh -c 'sleep 30 & wait'"));
  const shutdownControl = { admitted: deferred(), aborted: deferred(), baseSettled: deferred(), finished: deferred() };
  controls.set(shutdownRequest.operationId, shutdownControl);
  const pendingShutdown = fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(shutdownRequest) });
  await shutdownControl.admitted.promise;
  const started = Date.now(); await handler.close(); const shutdownDurationMs = Date.now() - started;
  await shutdownControl.baseSettled.promise;
  const shutdownResponse = await jsonResponse(await pendingShutdown);
  if (shutdownResponse.status !== 503 || shutdownDurationMs > 5000) throw new Error('HTTP shutdown did not drain the executor');
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));

  process.stdout.write(JSON.stringify({ version: 1, node: process.version, isolation: ISOLATION,
    runtimeLimitation: 'Qualified on the frozen Linux ARM64 Node 26.9.0 image; AMD64 remains unqualified.',
    backendClient: { exactReceipt: true, boundedResponse: true },
    inert: { renderedSha256: inert.renderedSha256, drained: inert.drained },
    syntheticEffect: { ...exploitWitness, renderedSha256: exploit.renderedSha256 },
    malformedAdmission: { invalidUtf8Status: malformedUtf8.status, oversizedChunkedStatus: oversized.status },
    capacity: { busyStatus: busy.status, busyCode: busy.body.error, timedRenderStatus: slowResponse.status },
    disconnect: { abortObserved: true, executorDrainedBeforeRelease: true, capacityRetainedStatus: retained.status },
    shutdown: { status: shutdownResponse.status, executorDrained: true, durationMs: shutdownDurationMs } }));
}

main().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
