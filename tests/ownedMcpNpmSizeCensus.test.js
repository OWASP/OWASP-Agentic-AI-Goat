'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), path = require('node:path'), os = require('node:os');
const { Readable } = require('node:stream');
const census = require('./postgres/ownedMcpNpmSizeCensus');
const closure = require('./postgres/ownedMcpDependencyClosure');
const { spawnSync } = require('node:child_process'), crypto = require('node:crypto'), vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const lock = () => fs.readFile(path.join(__dirname, '../sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
async function temporary(t) { const root = await fs.mkdtemp(path.join(os.tmpdir(), 'npm-census-')); t.after(() => fs.rm(root, { recursive: true, force: true })); return root; }
function response(changes = {}) { return { status: 200, rawHeaders: ['Content-Length', '100'], headerBytes: 64,
  body: Readable.from([]), closed: Promise.resolve(), destroy() { this.body.destroy(); }, ...changes }; }
test('all122 URLs and124 paths retain exact lock bindings; estimates never grant integrity or build credit', async t => {
  const root = await temporary(t), npmLock = await lock(), expected = closure._internals.npmArtifacts(npmLock), urls = [];
  const receipt = await census.runSizeCensus({ npmLock, directory: path.join(root, 'census'), request: async (url, options) => {
    assert.equal(options.method, 'HEAD'); assert.equal(options.signal.aborted, false); urls.push(url); return response();
  } });
  assert.deepEqual(urls, expected.map(row => row.urls[0])); assert.equal(receipt.requests, 122); assert.equal(receipt.lockPaths, 124);
  assert.equal(receipt.totalEstimatedBytes, 12200); assert.equal(receipt.headerBytes, 122 * 64);
  assert.equal(receipt.artifactBytesVerified, false); assert.equal(receipt.buildApproved, false); assert.equal(receipt.packageBodiesDownloaded, false);
  assert.ok(receipt.artifacts.some(row => row.urls[0].includes('aix-ppc64')));
  assert.deepEqual(JSON.parse(await fs.readFile(path.join(root, 'census/estimates.json'), 'utf8')), receipt);
});
test('missing/conflicting lengths, redirects, bodies and excessive headers fail availability without retry', async t => {
  const root = await temporary(t), npmLock = await lock(); let index = 0;
  for (const changes of [{ rawHeaders: [] }, { rawHeaders: ['Content-Length', '1', 'content-length', '2'] }, { status: 302 },
    { rawHeaders: ['Content-Length', '1', 'Location', 'https://foreign/'] }, { headerBytes: 8193 },
    { rawHeaders: ['Content-Length', '100', 'Content-Encoding', 'gzip'] }, { body: Readable.from([Buffer.from('forbidden')]) }]) {
    const directory = path.join(root, String(index++)); let calls = 0;
    await assert.rejects(census.runSizeCensus({ npmLock, directory, request: async () => { calls++; return response(changes); } }));
    assert.equal(calls, 1); const failure = JSON.parse(await fs.readFile(path.join(directory, 'failure.json'), 'utf8'));
    assert.equal(failure.completed, 0); assert.equal(failure.current.index, 0); assert.equal(failure.qualificationComplete, false);
    assert.deepEqual(await fs.readdir(directory), ['failure.json']);
  }
});
test('cancellation and deadline prevent further HEAD effects; original transport error is retained', async t => {
  const root = await temporary(t), npmLock = await lock(), controller = new AbortController(); controller.abort(); let calls = 0;
  await assert.rejects(census.runSizeCensus({ npmLock, directory: path.join(root, 'aborted'), signal: controller.signal,
    request: async () => { calls++; return response(); } }), { code: 'CENSUS_ABORTED' }); assert.equal(calls, 0);
  const primary = Object.assign(Error('controlled reset'), { code: 'ECONNRESET' });
  await assert.rejects(census.runSizeCensus({ npmLock, directory: path.join(root, 'reset'), request: async () => { throw primary; } }), error => error === primary);
  let clock = 0;
  await assert.rejects(census.runSizeCensus({ npmLock, directory: path.join(root, 'deadline'), now: () => clock,
    request: async () => { clock = 300000; return response(); } }), { code: 'CENSUS_ABORTED' });
});
test('response cleanup debt preserves the original validation failure and cannot publish estimates', async t => {
  const root = await temporary(t), npmLock = await lock(), cleanup = Error('controlled close failure');
  await assert.rejects(census.runSizeCensus({ npmLock, directory: path.join(root, 'debt'), request: async () => response({ status: 302,
    destroy() { throw cleanup; } }) }), error => {
    assert.equal(error.retirementUnproven, true); assert.equal(error.errors[0].code, 'CENSUS_RESPONSE'); assert.equal(error.errors[1], cleanup); return true;
  });
  assert.deepEqual(await fs.readdir(path.join(root, 'debt')), ['failure.json']);
  await assert.rejects(census.runSizeCensus({ npmLock, directory: path.join(root, 'unjoined'), request: async () => response({ closed: new Promise(() => {}) }) }), error => error.retirementUnproven === true);
});
test('closed host census plan preserves private phases and omits all build/load/consumer dispatch', async () => {
  const plan = await census.censusPlan(root, 'e'.repeat(32));
  assert.equal(plan.kind, 'original-npm-head-size-census'); assert.equal(plan.buildApproved, false);
  assert.equal(plan.limits.artifactBudgetProfile, 'default');
  assert.equal(plan.limits.npmStoredBytes, 64 * 1024 ** 2);
  assert.equal(plan.limits.npmWireBytes, 64 * 1024 ** 2);
  assert.equal(plan.limits.acquisitionBytes, 261 * 1024 ** 2);
  assert.deepEqual(Object.keys(plan.commands), ['inventory', 'preflight', 'prepare', 'namespace', 'relayStart', 'daemonStart', 'inspect', 'metadataFetch',
    'startArtifacts', 'retireArtifacts', 'stop', 'evidence', 'retainedExport', 'cleanup', 'censusEvidence']);
  assert.equal(Object.keys(plan.buildSources).length, 20); new vm.Script(plan.guestSource);
  assert.match(plan.guestSource, /runSizeCensus/); assert.doesNotMatch(plan.guestSource, /runSizeCensus\([^)]*method:'GET'/);
  for (const [name, script] of Object.entries(plan.commands)) assert.equal(spawnSync('/bin/sh', ['-n'], { input: script, encoding: 'utf8' }).status, 0, name);
  await require('./postgres/ownedMcpOriginalBuildAdapter')._internals.verifyPlanSources(plan);
  const range = await census.censusPlan(root, 'e'.repeat(32), 'RANGE_0');
  assert.equal(range.mode, 'RANGE_0'); assert.notEqual(range.guestSourceSha256, plan.guestSourceSha256);
  assert.deepEqual(range.limits, plan.limits);
});
test('completed records publish only after fsync and close, never replace existing ready or expose failed partial writes', async t => {
  const directory = await temporary(t), source = await fs.readFile(require.resolve('./postgres/ownedMcpNpmSizeCensus'), 'utf8');
  const localRequire = require('node:module').createRequire(require.resolve('./postgres/ownedMcpNpmSizeCensus'));
  const events = [], module = { exports: {} };
  const fakeFs = { ...fs, open: async (name, ...args) => {
    const handle = await fs.open(name, ...args), sync = handle.sync.bind(handle), close = handle.close.bind(handle);
    handle.sync = async () => { events.push(name.endsWith('.partial') ? 'file-sync' : 'directory-sync');
      if (name.endsWith('.partial')) await assert.rejects(fs.stat(path.join(directory, 'ready.json')), { code: 'ENOENT' });
      await sync(); };
    handle.close = async () => { if (name.endsWith('.partial')) events.push('file-close'); await close(); }; return handle;
  }, link: async (...args) => { events.push('publish'); assert.deepEqual(events, ['file-sync', 'file-close', 'publish']); await fs.link(...args); } };
  new Function('require', 'module', 'exports', source)(id => id === 'node:fs/promises' ? fakeFs : localRequire(id), module, module.exports);
  await module.exports._internals.record(directory, 'ready.json', { complete: true });
  assert.deepEqual(events, ['file-sync', 'file-close', 'publish', 'directory-sync']);
  const original = await fs.readFile(path.join(directory, 'ready.json'));
  await assert.rejects(census._internals.record(directory, 'ready.json', { changed: true }), { code: 'EEXIST' });
  assert.deepEqual(await fs.readFile(path.join(directory, 'ready.json')), original);
  const failed = await temporary(t), primary = Object.assign(Error('controlled write failure'), { code: 'ENOSPC' }), broken = { exports: {} };
  new Function('require', 'module', 'exports', source)(id => id === 'node:fs/promises' ? { ...fs, open: async (name, ...args) => {
    const handle = await fs.open(name, ...args); handle.writeFile = async () => { throw primary; }; return handle;
  } } : localRequire(id), broken, broken.exports);
  await assert.rejects(broken.exports._internals.record(failed, 'ready.json', { complete: true }), error => error === primary);
  assert.deepEqual(await fs.readdir(failed), ['ready.json.partial']);
});
test('census completion accepts atomic ready at terminal transition, rejects failed/running/missing state', async t => {
  for (const scenario of ['ready-before', 'ready-at-exit', 'failed-with-ready', 'missing-ready', 'created', 'still-running', 'inspect-failure']) {
    const directory = await temporary(t); await fs.mkdir(path.join(directory, 'fs/closure'), { recursive: true });
    await fs.writeFile(path.join(directory, 'completed.json'), '{"complete":true}', { mode: 0o400 });
    if (['ready-before', 'failed-with-ready'].includes(scenario)) await fs.copyFile(path.join(directory, 'completed.json'), path.join(directory, 'fs/closure/ready.json'));
    const script = `set -eu
root="$1";cid=controlled
closure_identity(){ return 0; }
sleep(){ return 0; }
docker(){
 case "$*" in
 *State.Running*) ${scenario === 'inspect-failure' ? 'return 19;' : ''} ${scenario === 'ready-at-exit' ? 'cp "$root/completed.json" "$root/fs/closure/ready.json";' : ''} printf '%s\\n' '${scenario === 'still-running' ? 'true' : 'false'}' ;;
 *State.Status*) printf '%s\\n' '${scenario === 'created' ? 'created' : 'exited'}' ;;
 *State.ExitCode*) printf '%s\\n' '${scenario === 'failed-with-ready' ? '1' : '0'}' ;;
 *logs*) return 0 ;;
 *) return 99 ;;
 esac
}
${census._internals.COMPLETION}
printf completed`;
    const result = spawnSync('/bin/sh', ['-c', script, 'controlled-census', directory], { encoding: 'utf8', timeout: 10000 });
    if (['ready-before', 'ready-at-exit'].includes(scenario)) { assert.equal(result.status, 0, scenario); assert.equal(result.stdout, 'completed'); }
    else { assert.notEqual(result.status, 0, scenario); assert.notEqual(result.stdout, 'completed'); }
  }
});
test('owned host census executes closed lifecycle and preserves original failure or exact retirement debt (controlled only)', async t => {
  const adapter = require('./postgres/ownedMcpOriginalBuildAdapter'), npmLock = await lock(), temporaryRoot = await temporary(t);
  const estimates = await census.runSizeCensus({ npmLock, directory: path.join(temporaryRoot, 'estimates'), request: async () => response() });
  const source = await fs.readFile(require.resolve('./postgres/ownedMcpNpmSizeCensus'), 'utf8');
  const localRequire = require('node:module').createRequire(require.resolve('./postgres/ownedMcpNpmSizeCensus'));
  const metadataDirectory = path.join(root, 'tasks/qualification/metadata-85b02bf25ca24ad490ae96b973ff16ad');
  const inventory = JSON.parse(await fs.readFile(path.join(metadataDirectory, 'inventory-before.json'), 'utf8')).text;
  for (const scenario of ['success', 'head', 'receipt', 'retirement', 'export-failure', 'cleanup', 'signal', 'missing-daemon', 'shared-daemon', 'changed-daemon-before', 'changed-daemon-after']) {
    const runId = crypto.randomBytes(16).toString('hex'), plan = await census.censusPlan(root, runId), calls = [];
    const artifact = path.join(temporaryRoot, runId), mapped = value => typeof value === 'string' && (value === plan.spec.artifact || value.startsWith(plan.spec.artifact + '/'))
      ? artifact + value.slice(plan.spec.artifact.length) : value;
    const module = { exports: {} };
    new Function('require', 'module', 'exports', source)(id => id === 'node:fs/promises' ? { ...fs,
      mkdir: (name, ...args) => fs.mkdir(mapped(name), ...args), open: (name, ...args) => fs.open(mapped(name), ...args) } : localRequire(id), module, module.exports);
    const envelope = JSON.parse(JSON.parse(await fs.readFile(path.join(metadataDirectory, 'acquisition-output.json'), 'utf8')).raw);
    envelope.binding = plan.binding; envelope.candidate.retainedMetadata.binding = plan.binding;
    const primary = Object.assign(Error('controlled primary'), { code: 'CONTROLLED_PRIMARY' });
    const runner = async (_plan, name, options) => {
      calls.push(name); await options.diagnosticSink(Buffer.from('controlled diagnostic\n'));
      if (name === 'inventory') return inventory;
      if (name === 'inspect') return JSON.stringify({ ID: scenario === 'missing-daemon' ? '' : scenario === 'shared-daemon' ? require('./postgres/ownedMcpBoundedBuild').PINS.daemon
        : scenario === 'changed-daemon-before' && calls.includes('metadataFetch') || scenario === 'changed-daemon-after' && calls.includes('startArtifacts') ? 'replaced-private-daemon' : 'controlled-private-daemon',
        DockerRootDir: plan.spec.mount + '/data', Driver: 'overlay2', Architecture: 'arm64' });
      if (name === 'metadataFetch') return JSON.stringify(envelope);
      if (name === 'startArtifacts') {
        if (scenario === 'head') throw primary;
        if (scenario === 'signal') process.emit('SIGTERM');
        const receipt = structuredClone(estimates); if (scenario === 'receipt') receipt.artifacts.pop();
        return JSON.stringify({ binding: plan.binding, receipt });
      }
      if (name === 'retireArtifacts') { if (scenario === 'retirement') throw primary; return 'absent\n'; }
      if (name === 'censusEvidence') {
        if (scenario === 'export-failure') throw primary;
        const raw = JSON.stringify({ error: 'CENSUS_LENGTH', current: { index: 0 }, qualificationComplete: false });
        return JSON.stringify({ 'failure.json': scenario === 'head' ? { raw, bytes: Buffer.byteLength(raw), sha256: crypto.createHash('sha256').update(raw).digest('hex') } : null, 'estimates.json': null });
      }
      if (name === 'evidence') return '{}';
      if (name === 'retainedExport') { await options.sink(Buffer.from('controlled archive')); return ''; }
      if (name === 'cleanup') { if (scenario === 'cleanup') throw primary; return 'absent\n'; }
      return '';
    };
    const before = process.listenerCount('SIGTERM');
    const work = module.exports.runOwnedCensus({ root, runId, expectedPlanSha256: adapter.planDigest(plan), runner, verifyHost: async () => {} });
    if (scenario === 'success') {
      const result = await work; assert.equal(result.result.controlled, true); assert.equal(result.result.cleanupVerified, true);
      assert.equal(result.result.daemonId, 'controlled-private-daemon');
      assert.equal(result.result.qualificationComplete, false); assert.equal(result.receipt.artifactBytesVerified, false);
    } else await assert.rejects(work, error => { assert.ok(error instanceof AggregateError); if (scenario === 'head') assert.ok(error.errors.includes(primary)); return true; });
    assert.equal(process.listenerCount('SIGTERM'), before);
    const result = JSON.parse(await fs.readFile(path.join(artifact, 'result.json'), 'utf8'));
    if (scenario === 'retirement') { assert.equal(result.cleanupVerified, false); assert.ok(!calls.includes('stop')); assert.ok(!calls.includes('cleanup')); }
    else { assert.ok(calls.indexOf('retireArtifacts') < calls.indexOf('stop')); }
    if (['missing-daemon', 'shared-daemon', 'changed-daemon-before'].includes(scenario)) assert.ok(!calls.includes('startArtifacts'));
    if (scenario === 'head') {
      const packet = JSON.parse(await fs.readFile(path.join(artifact, 'census-evidence.json'), 'utf8'));
      assert.equal(JSON.parse(packet['failure.json'].raw).error, 'CENSUS_LENGTH');
      assert.ok(calls.indexOf('censusEvidence') < calls.indexOf('cleanup'));
    }
    if (scenario === 'export-failure') { assert.equal(result.cleanupVerified, false); assert.ok(!calls.includes('cleanup')); }
    assert.ok(!calls.some(name => ['build', 'image', 'handoff', 'registryStart'].includes(name)));
  }
});
test('failed length classification is bounded, retained and never includes raw remote header values', async t => {
  const root = await temporary(t), npmLock = await lock(); let index = 0;
  for (const [value, classification] of [[undefined, 'missing'], ['0', 'nonpositive'], ['secret-header-value', 'invalid-decimal'], ['9007199254740992', 'unsafe-integer']]) {
    const directory = path.join(root, String(index++));
    await assert.rejects(census.runSizeCensus({ npmLock, directory, request: async () => response({ rawHeaders: value === undefined ? [] : ['Content-Length', value] }) }), error => {
      assert.equal(error.code, 'CENSUS_LENGTH'); assert.equal(error.censusDiagnostic.headerClass, classification); return true;
    });
    const raw = await fs.readFile(path.join(directory, 'failure.json'), 'utf8'), record = JSON.parse(raw);
    assert.equal(record.current.index, 0); assert.equal(record.current.stage, 'headers'); assert.equal(record.current.status, 200);
    assert.equal(record.headerClass, classification); assert.doesNotMatch(raw, /secret-header-value/);
  }
});
test('explicit one-byte range census covers all122 without HEAD fallback or integrity credit', async t => {
  const directory = await temporary(t), npmLock = await lock(); let calls = 0;
  const range = () => response({ status: 206, rawHeaders: ['Content-Length', '1', 'Content-Range', 'bytes 0-0/100'], headerBytes: 100, body: Readable.from([Buffer.from('x')]) });
  const receipt = await census.runSizeCensus({ npmLock, directory: path.join(directory, 'valid'), mode: 'RANGE_0', request: async (_url, options) => {
    calls++; assert.equal(options.method, 'GET'); assert.equal(options.rangeProbe, true); return range();
  } });
  assert.equal(calls, 122); assert.equal(receipt.packageBodyBytes, 122); assert.equal(receipt.totalEstimatedBytes, 12200); assert.equal(receipt.artifactBytesVerified, false);
  census.validateReceipt(receipt, npmLock, 'RANGE_0'); assert.throws(() => census.validateReceipt(receipt, npmLock, 'HEAD'));
  let index = 0;
  for (const change of [r => r.status = 200, r => r.rawHeaders = ['Content-Length', '1'], r => r.rawHeaders[3] = 'bytes 0-1/100',
    r => r.rawHeaders[3] = 'bytes 0-0/*', r => r.rawHeaders[1] = '2', r => r.body = Readable.from([]), r => r.body = Readable.from([Buffer.from('xx')])]) {
    let requests = 0;
    await assert.rejects(census.runSizeCensus({ npmLock, directory: path.join(directory, String(index++)), mode: 'RANGE_0', request: async () => { requests++; const r = range(); change(r); return r; } }));
    assert.equal(requests, 1);
  }
});
test('actual serialized evidence exporter retains bounded exact bytes and rejects changed file boundaries', async t => {
  const plan = await census.censusPlan(root, 'f'.repeat(32));
  const program = plan.commands.censusEvidence.split("<<'DVAIA_CENSUS_EVIDENCE'\n")[1].split('\nDVAIA_CENSUS_EVIDENCE')[0];
  for (const scenario of ['valid', 'missing', 'mode', 'owner', 'hardlink', 'symlink', 'oversized']) {
    const directory = await temporary(t), file = path.join(directory, 'failure.json');
    const raw = JSON.stringify({ version: 1, error: 'CENSUS_LENGTH', headerClass: 'missing', qualificationComplete: false });
    if (scenario !== 'missing') await fs.writeFile(file, scenario === 'oversized' ? Buffer.alloc(131073) : raw, { mode: scenario === 'mode' ? 0o600 : 0o400 });
    if (scenario === 'hardlink') await fs.link(file, path.join(directory, 'linked'));
    if (scenario === 'symlink') { await fs.rename(file, path.join(directory, 'real')); await fs.symlink(path.join(directory, 'real'), file); }
    // Controlled root ownership only; all other checks execute on actual
    // disposable files. This does not establish native guest ownership.
    const wrapped = `import os,sys\noriginal=os.fstat\ndef controlled(fd):\n values=list(original(fd));values[4]=${scenario === 'owner' ? '9999' : '0'};return os.stat_result(values)\nos.fstat=controlled\nsys.argv=['evidence',sys.argv[1]]\nexec(compile(${JSON.stringify(program)},'<retained-census>','exec'))`;
    const result = spawnSync('/opt/homebrew/bin/python3', ['-I', '-S', '-B', '-c', wrapped, directory], { encoding: 'utf8', timeout: 10000 });
    if (['valid', 'missing'].includes(scenario)) {
      assert.equal(result.status, 0, result.stderr); const packet = JSON.parse(result.stdout);
      if (scenario === 'missing') assert.deepEqual(packet, { 'failure.json': null, 'estimates.json': null });
      else { assert.equal(packet['failure.json'].raw, raw); assert.equal(packet['failure.json'].bytes, Buffer.byteLength(raw));
        assert.equal(packet['failure.json'].sha256, crypto.createHash('sha256').update(raw).digest('hex')); }
    } else { assert.notEqual(result.status, 0, scenario); assert.equal(result.stdout, ''); }
  }
});
