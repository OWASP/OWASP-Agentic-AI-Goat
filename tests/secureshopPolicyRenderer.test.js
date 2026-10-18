'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');

const executorModule = require('../sidecars/sandbox-runner/policy-render/executor');
const { createSecureShopPolicySandboxRuntime, readBoundedPolicyRenderJson, MAX_RESPONSE_BYTES }
  = require('../server/services/secureshopPolicySandboxRuntime');
const { requestDigest, validateRenderResult, normalizeRenderExecution, renderExecutionDigest,
  validateRenderExecutionResult, createLiteralRenderResult }
  = require('../server/services/secureshopPromptPolicyContract');

const request = Object.freeze({
  operationId: '123e4567-e89b-42d3-a456-426614174000',
  name: 'returns', markdown: 'Hello {{ store_name }}',
  targets: Object.freeze(['customer']),
});
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

function writable() { return new Writable({ write(_chunk, _encoding, done) { done(); } }); }
function fakeChild(onKill) {
  const child = new EventEmitter();
  child.pid = 999999;
  child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.stdio = [null, child.stdout, child.stderr, writable(), writable(), writable(), writable(), writable(), writable()];
  child.kill = signal => { onKill?.(signal); queueMicrotask(() => child.emit('close', 137)); };
  return child;
}
function successfulSpawn(rendered = 'Hello SecureShop', initReceipt = 'policy-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n') {
  return (_bin, argv) => {
    const child = fakeChild();
    const marker = argv.at(-1);
    const parsed = JSON.parse(Buffer.from(argv.at(-2), 'base64').toString('utf8'));
    queueMicrotask(() => {
      const bytes = Buffer.from(rendered);
      const envelope = { version: 1, operationId: parsed.operationId,
        requestSha256: parsed.requestSha256, isolation: executorModule.ISOLATION,
        renderedBase64: bytes.toString('base64'), renderedSha256: digest(bytes) };
      child.stdout.end(`${initReceipt}${marker}${Buffer.from(JSON.stringify(envelope)).toString('base64')}`);
      child.stderr.end(); child.emit('close', 0);
    });
    return child;
  };
}

test('policy renderer pins the actual Nunjucks 3.2.4 compiler asset', () => {
  const result = executorModule.checkAssets();
  assert.equal(result.compilerSha256, executorModule.COMPILER_SHA256);
  assert.equal(result.workerSha256, executorModule.WORKER_SHA256);
  assert.match(require('node:fs').readFileSync(executorModule.COMPILER_PATH, 'utf8').slice(0, 80), /nunjucks 3\.2\.4/);
});

test('packaged Nunjucks asset evaluates an inert literal template', () => {
  const nunjucks = require(executorModule.COMPILER_PATH);
  const environment = new nunjucks.Environment(null, { autoescape: false });
  assert.equal(environment.renderString('Policy for {{ store }}.', { store: 'SecureShop' }), 'Policy for SecureShop.');
});

test('policy renderer argv creates a fresh closed namespace with only checked assets and synthetic fixture fds', () => {
  const marker = `__POLICY_RENDER_${'b'.repeat(64)}__`;
  const argv = executorModule.buildRenderArgv(request, marker, ['/usr', '/lib']);
  assert.deepEqual(argv.slice(0, 13), ['--cap-drop','ALL','--cap-add','CAP_NET_ADMIN',
    '--cap-add','CAP_SETPCAP','--unshare-user','--unshare-net','--unshare-pid',
    '--unshare-uts','--unshare-ipc','--die-with-parent','--new-session']);
  assert.ok(argv.includes('--clearenv'));
  assert.ok(argv.includes('--tmpfs'));
  assert.equal(argv[argv.indexOf('/proc') - 1], '--dir');
  assert.equal(argv[argv.indexOf('/usr/local/libexec') - 1], '--tmpfs');
  assert.ok(argv.includes('/opt/policy-render/nunjucks-3.2.4.js'));
  assert.ok(argv.includes('/opt/policy-render/worker.js'));
  assert.equal(argv.includes(executorModule.COMPILER_PATH), false);
  assert.equal(argv.includes(executorModule.WORKER_PATH), false);
  assert.equal(argv.includes(executorModule.DEFAULT_SUPERVISOR), false);
  assert.ok(argv.includes('/app/config/.env'));
  assert.ok(argv.includes('/home/secureshop/.ssh/id_rsa'));
  assert.ok(argv.includes(executorModule.DEFAULT_INIT));
  assert.equal(argv.includes('--preserve-fds'), false);
  assert.equal(argv.includes('/exec'), false);
  assert.equal(argv.some((value, index) => value === '--ro-bind' && argv[index + 1] === '/'), false);
  assert.equal(argv.at(-1), marker);
});

test('policy renderer uses the reviewed subreaper lifecycle helper', () => {
  const fs = require('node:fs');
  const source = fs.readFileSync(require('node:path').join(__dirname, '../sidecars/sandbox-runner/policy-render/process-supervisor.c'), 'utf8');
  assert.match(source, /PR_SET_CHILD_SUBREAPER/);
  assert.match(source, /waitpid\(-1/);
  assert.match(source, /kill_owned_children/);
  assert.match(source, /execv\(argv\[0\],argv\)/);
  assert.match(source, /argv\[0\]="\/usr\/bin\/bwrap"/);
  const init = fs.readFileSync(require('node:path').join(__dirname, '../sidecars/sandbox-runner/policy-render/policy-init.c'), 'utf8');
  assert.match(init, /SYS_capset/);
  assert.match(init, /PR_CAPBSET_DROP/);
  assert.match(init, /PR_SET_NO_NEW_PRIVS/);
  assert.match(init, /write\(STDOUT_FILENO,receipt/);
  assert.match(init, /\/opt\/policy-render\/worker\.js/);
});

test('policy renderer returns a parent-validated receipt after worker drain', async () => {
  const executor = executorModule.createPolicyRenderExecutor({ spawnImpl: successfulSpawn(),
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true });
  const result = await executor.render(request);
  assert.deepEqual(result, { version: 1, operationId: request.operationId,
    requestSha256: requestDigest(request), isolation: executorModule.ISOLATION,
    rendered: 'Hello SecureShop', renderedSha256: digest('Hello SecureShop'),
    exitCode: 0, timedOut: false, truncated: false, drained: true });
});

test('policy renderer rejects a replaced or late init attestation', async () => {
  const validReceipt = 'policy-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n';
  const executor = executorModule.createPolicyRenderExecutor({
    spawnImpl: successfulSpawn('Hello SecureShop', `forged\n${validReceipt}`),
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true,
  });
  const result = await executor.render(request);
  assert.equal(result.rendered, '');
  assert.equal(executorModule.policyRenderEffectWitnessFor(result).workerAttested, false);
  assert.match(result.error, /Invalid policy render worker result/);
});

test('policy renderer fails closed before spawn when strict bwrap probe is unavailable', async () => {
  let spawned = false;
  const executor = executorModule.createPolicyRenderExecutor({ spawnImpl: () => { spawned = true; },
    spawnSyncImpl: () => ({ status: 1 }), existsSync: () => true });
  await assert.rejects(async () => executor.render(request), { code: 'POLICY_RENDER_ISOLATION_UNAVAILABLE' });
  assert.equal(spawned, false);
});

test('policy renderer times out, kills the namespace, and reports a drained incomplete result', async () => {
  let killed = false;
  const executor = executorModule.createPolicyRenderExecutor({ timeoutMs: 100,
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true,
    spawnImpl: () => fakeChild(() => { killed = true; }) });
  const result = await executor.render(request);
  assert.equal(killed, true);
  assert.equal(result.timedOut, true);
  assert.equal(result.exitCode, 137);
  assert.equal(result.drained, true);
  assert.match(result.error, /Invalid policy render worker result/);
});

test('policy renderer reports bounded capture truncation and never accepts the partial stream', async () => {
  const executor = executorModule.createPolicyRenderExecutor({
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true,
    spawnImpl: () => {
      const child = fakeChild();
      queueMicrotask(() => { child.stdout.end(Buffer.alloc(executorModule.MAX_CAPTURE_BYTES + 1, 65)); child.stderr.end(); child.emit('close', 0); });
      return child;
    },
  });
  const result = await executor.render(request);
  assert.equal(result.truncated, true);
  assert.equal(result.rendered, '');
  assert.equal(result.drained, true);
});

test('policy renderer abort reaps the namespace before rejecting', async () => {
  let killed = false;
  const controller = new AbortController();
  const executor = executorModule.createPolicyRenderExecutor({
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true,
    spawnImpl: () => fakeChild(() => { killed = true; }),
  });
  const pending = executor.render(request, { signal: controller.signal });
  controller.abort(new DOMException('cancelled', 'AbortError'));
  await assert.rejects(pending, { name: 'AbortError' });
  assert.equal(killed, true);
});

test('policy renderer never reports drained when the subreaper needs a forced kill', async () => {
  const executor = executorModule.createPolicyRenderExecutor({ timeoutMs: 100, drainGraceMs: 100,
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true,
    spawnImpl: () => {
      const child = fakeChild();
      child.kill = signal => { if (signal === 'SIGKILL') queueMicrotask(() => child.emit('close', 137)); };
      return child;
    },
  });
  const result = await executor.render(request);
  assert.equal(result.timedOut, true);
  assert.equal(result.drained, false);
});

test('abort that lands during the strict probe is observed after listener installation', async () => {
  const controller = new AbortController();
  let killed = false;
  const executor = executorModule.createPolicyRenderExecutor({
    spawnSyncImpl: () => { controller.abort(new DOMException('probe cancelled', 'AbortError')); return { status: 0 }; },
    existsSync: () => true, spawnImpl: () => fakeChild(() => { killed = true; }),
  });
  await assert.rejects(async () => executor.render(request, { signal: controller.signal }), { name: 'AbortError' });
  assert.equal(killed, true);
});

test('backend policy runtime accepts only an exact completed matching receipt', async () => {
  const completed = { version: 1, operationId: request.operationId,
    requestSha256: requestDigest(request), isolation: executorModule.ISOLATION,
    rendered: 'literal policy', renderedSha256: digest('literal policy'),
    exitCode: 0, timedOut: false, truncated: false, drained: true };
  assert.deepEqual(validateRenderResult(request, completed), completed);
  assert.throws(() => validateRenderResult(request, { ...completed, drained: false }), TypeError);
  assert.throws(() => validateRenderResult(request, { ...completed, commandExecuted: true }), TypeError);

  let observed;
  const runtime = createSecureShopPolicySandboxRuntime({ baseUrl: 'http://policy-render.test:8090',
    fetchImpl: async (url, options) => { observed = { url, options }; return new Response(JSON.stringify(completed), { status: 200 }); } });
  assert.deepEqual(await runtime.render(request), completed);
  assert.equal(observed.url, 'http://policy-render.test:8090/secureshop/policy-render');
  assert.deepEqual(JSON.parse(observed.options.body), request);
});

test('backend policy runtime bounds the HTTP response before JSON parsing', async () => {
  await assert.rejects(readBoundedPolicyRenderJson(new Response('x'.repeat(MAX_RESPONSE_BYTES + 1))),
    { code: 'POLICY_RENDER_UNAVAILABLE' });
});

test('v2 fixed execution returns literal policy without strict probe or worker spawn', async () => {
  let probes = 0, spawns = 0;
  const executor = executorModule.createPolicyRenderExecutor({ spawnImpl: () => { spawns++; },
    spawnSyncImpl: () => { probes++; return { status: 1 }; }, existsSync: () => false });
  const result = await executor.render({ version: 2, mode: 'fixed', request });
  assert.deepEqual(result, createLiteralRenderResult(request));
  assert.equal(probes, 0);
  assert.equal(spawns, 0);
});

test('v2 vulnerable execution carries executor-origin witness and runtime checks mode', async () => {
  const execution = normalizeRenderExecution({ version: 2, mode: 'vuln', request });
  const executor = executorModule.createPolicyRenderExecutor({ spawnImpl: successfulSpawn(),
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true });
  const result = await executor.render(execution);
  assert.equal(result.version, 2);
  assert.equal(result.kind, 'isolated_template');
  assert.equal(result.executionSha256, renderExecutionDigest(execution));
  assert.deepEqual(result.effectWitness, { version: 1, workerAttested: true,
    commandEffectObserved: false, effectSha256: null,
    compilerSha256: executorModule.COMPILER_SHA256, workerSha256: executorModule.WORKER_SHA256 });
  assert.deepEqual(validateRenderExecutionResult(execution, result), result);
  let wire;
  const runtime = createSecureShopPolicySandboxRuntime({ baseUrl: 'http://policy-render.test:8090',
    fetchImpl: async (_url, options) => { wire = JSON.parse(options.body);
      return new Response(JSON.stringify(result), { status: 200 }); } });
  assert.deepEqual(await runtime.render(request, { executionMode: 'vuln' }), result);
  assert.deepEqual(wire, execution);
  await assert.rejects(runtime.render(request, { executionMode: 'fixed' }), { code: 'POLICY_RENDER_UNAVAILABLE' });
});

test('v2 command witness comes from the owned effect file, never worker prose', async () => {
  const fs = require('node:fs');
  const execution = normalizeRenderExecution({ version: 2, mode: 'vuln', request });
  const executor = executorModule.createPolicyRenderExecutor({
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true,
    spawnImpl: (_bin, argv) => {
      const child = fakeChild();
      let canary = Buffer.alloc(0);
      child.stdio[8] = new Writable({ write(chunk, _encoding, done) { canary = Buffer.concat([canary, chunk]); done(); } });
      const root = argv[argv.indexOf('--bind') + 1];
      const marker = argv.at(-1);
      const parsed = JSON.parse(Buffer.from(argv.at(-2), 'base64').toString('utf8'));
      queueMicrotask(() => {
        fs.writeFileSync(require('node:path').join(root, 'command-effect'), canary, { mode: 0o600 });
        const rendered = 'Worker text alone is not evidence';
        const envelope = { version: 1, operationId: parsed.operationId,
          requestSha256: parsed.requestSha256, isolation: executorModule.ISOLATION,
          renderedBase64: Buffer.from(rendered).toString('base64'), renderedSha256: digest(rendered) };
        child.stdout.end(`policy-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n${marker}${Buffer.from(JSON.stringify(envelope)).toString('base64')}`);
        child.stderr.end(); child.emit('close', 0);
      });
      return child;
    },
  });
  const result = await executor.render(execution);
  assert.equal(result.effectWitness.commandEffectObserved, true);
  assert.match(result.effectWitness.effectSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(validateRenderExecutionResult(execution, result), result);
});

test('invalid completed worker output rejects after drain instead of escaping the close callback', async () => {
  const executor = executorModule.createPolicyRenderExecutor({ spawnImpl: successfulSpawn('bad\0text'),
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true });
  await assert.rejects(executor.render({ version: 2, mode: 'vuln', request }), TypeError);
});

test('effect observation and cleanup failures reject without claiming a result', async () => {
  const fs = require('node:fs');
  const originalReadDir = fs.readdirSync, originalRemove = fs.rmSync;
  let effectRoot;
  const spawnImpl = (_bin, argv) => {
    effectRoot = argv[argv.indexOf('--bind') + 1];
    return successfulSpawn()(_bin, argv);
  };
  const executor = executorModule.createPolicyRenderExecutor({ spawnImpl,
    spawnSyncImpl: () => ({ status: 0 }), existsSync: () => true });
  try {
    fs.readdirSync = (...args) => {
      if (args[0] === effectRoot) throw new Error('controlled effect observation failure');
      return originalReadDir(...args);
    };
    await assert.rejects(executor.render({ version: 2, mode: 'vuln', request }), /controlled effect observation failure/);
    assert.equal(fs.existsSync(effectRoot), false);
    fs.readdirSync = originalReadDir;
    fs.rmSync = (...args) => {
      if (args[0] === effectRoot) throw new Error('controlled cleanup failure');
      return originalRemove(...args);
    };
    await assert.rejects(executor.render({ version: 2, mode: 'vuln', request }), /controlled cleanup failure/);
  } finally {
    fs.readdirSync = originalReadDir;
    fs.rmSync = originalRemove;
    if (effectRoot) originalRemove(effectRoot, { recursive: true, force: true });
  }
});
