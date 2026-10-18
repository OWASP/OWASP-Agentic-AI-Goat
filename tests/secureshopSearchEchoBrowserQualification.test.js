'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

const sha = value => createHash('sha256').update(value).digest('hex');
const sourceRoot = path.resolve(__dirname, '..');
const moduleFile = path.join(sourceRoot, 'server/services/secureshopSearchEchoBrowserQualification.js');
const source = 'client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx';
const entry = 'client/src/pages/secureshop/searchEchoClientRenderer.jsx';
const artifactRoot = path.join(sourceRoot, 'client/build/secureshop-search-echo-renderer');
const mode = effectiveMode => ({ version: 1, featureId: 'customer_chat',
  policyVersion: 'owned-catalog-and-cart-read-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'customer_chat' } });

function fixture(mutate = () => {}, policyOutput = false) {
  const moduleFile = path.join(sourceRoot, policyOutput
    ? 'server/services/secureshopPolicyOutputBrowserQualification.js'
    : 'server/services/secureshopSearchEchoBrowserQualification.js');
  const source = policyOutput ? 'client/src/pages/secureshop/components/AgentLane/Turn.jsx'
    : 'client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx';
  const entry = policyOutput ? 'client/src/pages/secureshop/policyOutputClientRenderer.jsx'
    : 'client/src/pages/secureshop/searchEchoClientRenderer.jsx';
  const artifactRoot = path.join(sourceRoot, policyOutput
    ? 'client/build/secureshop-policy-output-renderer' : 'client/build/secureshop-search-echo-renderer');
  const script = 'trusted synthetic search echo renderer';
  const sourceBytes = Buffer.from('virtual source');
  const entryBytes = Buffer.from('virtual entry');
  const manifest = { version: 1, component: policyOutput ? 'SecureShop.PolicyFinalResponse' : 'SecureShop.SearchEcho', source,
    sourceSha256: sha(sourceBytes), entry, entrySha256: sha(entryBytes), artifact: 'renderer.js',
    artifactSha256: sha(script) };
  const files = new Map([
    [path.join(sourceRoot, source), sourceBytes],
    [path.join(sourceRoot, entry), entryBytes],
    [path.join(artifactRoot, 'renderer.js'), Buffer.from(script)],
  ]);
  mutate({ manifest, files });
  files.set(path.join(artifactRoot, 'manifest.json'), Buffer.from(JSON.stringify(manifest)));
  const fakeFs = { constants: fs.constants,
    openSync(file, flags) { assert.ok(flags & fs.constants.O_NOFOLLOW); if (!files.has(file)) throw Error('missing'); return file; },
    fstatSync(file) { return { isFile: () => true, size: files.get(file).length }; },
    readFileSync(file) { return files.get(file); }, closeSync() {} };
  let runnerOptions;
  const state = { calls: [], finish: null, delayed: false, closed: false };
  const module = { exports: {} };
  const code = fs.readFileSync(moduleFile, 'utf8');
  vm.runInThisContext(`(function(require,module,__dirname){${code}\n})`)(name => {
    if (name === 'node:fs') return fakeFs;
    if (name === './xssBrowserQualification') return { MAX_HTML_BYTES: 20000,
      createXssBrowserQualification(options) {
        runnerOptions = options;
        return { async qualifyClient(html, config) {
          state.calls.push(['qualify', html, config]);
          const page = { async addScriptTag(input) { state.calls.push(['script', input.content]); },
            async evaluate(fn, value) {
              assert.equal(typeof fn, 'function');
              assert.ok(!fn.toString().includes(html), 'HTML is a data argument, not script source');
              state.calls.push(['mount', value]);
              return state.snapshot;
            } };
          const snapshot = await options.clientMount(page, { html, signal: config.signal, ...(config.captureDom ? { captureDom: true } : {}) });
          const domCapture = config.captureDom ? options.clientDomCapture(snapshot, { originalSourceSha256: sha(html), instrumentedSourceSha256: sha(html), mountedSourceSha256: sha(html) }) : undefined;
          if (state.delayed) await new Promise(resolve => { state.finish = resolve; });
          return { executed: false, targetEventExecuted: false, ...(domCapture ? { domCapture } : {}) };
        }, async close() { state.closed = true; } };
      } };
    if (name === './mcp/protocolContext') return require('../server/services/mcp/protocolContext');
    return require(name);
  }, module, path.dirname(moduleFile));
  return { api: module.exports, files, manifest, state, runnerOptions: () => runnerOptions, script };
}

test('virtual pinned component and renderer hashes are mandatory before a browser runner exists', () => {
  for (const change of [
    value => { value.manifest.sourceSha256 = '0'.repeat(64); },
    value => { value.manifest.entrySha256 = '0'.repeat(64); },
    value => { value.manifest.artifactSha256 = '0'.repeat(64); },
    value => { value.manifest.component = 'Other'; },
    value => { value.manifest.artifact = '../renderer.js'; },
    value => { value.manifest.source = 'client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx'; },
    value => { value.manifest.extra = true; },
  ]) {
    const f = fixture(change);
    assert.throws(() => f.api.createSecureShopSearchEchoBrowserQualification(),
      { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
    assert.equal(f.runnerOptions(), undefined);
  }
});

test('fixed and vulnerable search echoes mount as exact data with a closed current mode capability', async () => {
  const f = fixture();
  const adapter = f.api.createSecureShopSearchEchoBrowserQualification();
  assert.equal(adapter.readComponent().id, 'SecureShop.SearchEcho');
  for (const effectiveMode of ['fixed', 'vuln']) {
    const html = `<img onerror="owned(${effectiveMode})">`;
    const result = await adapter.qualifySearchEcho({ html, modeCapability: mode(effectiveMode) });
    assert.equal(result.renderedSourceSha256, sha(html));
    assert.equal(result.component.sourceSha256, sha('virtual source'));
    assert.equal(result.component.artifactSha256, sha(f.script));
    assert.deepEqual(f.state.calls.at(-1), ['mount', { echoHtml: html, modeCapability: mode(effectiveMode) }]);
    assert.equal(f.state.calls.at(-2)[1], f.script);
  }
  for (const input of [
    { html: 'x', modeCapability: mode('fixed'), renderer: 'forged' },
    { html: 'x', ticketId: 'forbidden-extra-field', modeCapability: mode('fixed') },
    { html: 'x', modeCapability: { ...mode('fixed'), effectiveMode: 'unknown' } },
    { html: 'x', modeCapability: { ...mode('fixed'), scope: { kind: 'launch_feature', id: 'other' } } },
    { html: 'x'.repeat(16385), modeCapability: mode('fixed') },
    { html: '', modeCapability: mode('fixed') },
    { html: '\ud800', modeCapability: mode('fixed') },
    { html: 'x\0y', modeCapability: mode('fixed') },
  ]) await assert.rejects(adapter.qualifySearchEcho(input), { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  await adapter.close();
  assert.equal(f.state.closed, true);
  assert.throws(() => adapter.readComponent(), { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  await assert.rejects(adapter.qualifySearchEcho({ html: 'x', modeCapability: mode('fixed') }),
    { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
});

test('current source drift, cancellation, and concurrent mode calls deny without cross-mode mount', async () => {
  const drift = fixture();
  const stale = drift.api.createSecureShopSearchEchoBrowserQualification();
  drift.files.set(path.join(sourceRoot, source), Buffer.from('changed source'));
  assert.throws(() => stale.readComponent(), { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  await assert.rejects(stale.qualifySearchEcho({ html: 'x', modeCapability: mode('fixed') }),
    { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  const f = fixture();
  const adapter = f.api.createSecureShopSearchEchoBrowserQualification();
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(adapter.qualifySearchEcho({ html: 'x', modeCapability: mode('fixed'), signal: aborted.signal }),
    { name: 'AbortError' });
  assert.equal(f.state.calls.length, 0);
  f.state.delayed = true;
  const first = adapter.qualifySearchEcho({ html: 'fixed body', modeCapability: mode('fixed') });
  while (!f.state.finish) await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(adapter.qualifySearchEcho({ html: 'vuln body', modeCapability: mode('vuln') }),
    { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  assert.equal(f.state.calls.filter(([kind]) => kind === 'mount').length, 1);
  assert.equal(f.state.calls.find(([kind]) => kind === 'mount')[1].modeCapability.effectiveMode, 'fixed');
  f.state.finish();
  await first;
  await adapter.close();
});


test('original source snapshot survives caller mutation and post-execution artifact drift denies', async () => {
  const f = fixture();
  const adapter = f.api.createSecureShopSearchEchoBrowserQualification();
  f.state.delayed = true;
  const input = { html: '<img onerror="original()">', modeCapability: mode('vuln') };
  const original = input.html;
  const first = adapter.qualifySearchEcho(input);
  while (!f.state.finish) await new Promise(resolve => setImmediate(resolve));
  input.html = 'replacement'; input.modeCapability.effectiveMode = 'fixed';
  f.state.finish();
  const result = await first;
  assert.equal(result.renderedSourceSha256, sha(original));
  assert.equal(f.state.calls.find(([kind]) => kind === 'qualify')[2].eventSource, original);
  assert.equal(f.state.calls.find(([kind]) => kind === 'mount')[1].modeCapability.effectiveMode, 'vuln');
  f.state.finish = null;
  const next = adapter.qualifySearchEcho({ html: original, modeCapability: mode('vuln') });
  while (!f.state.finish) await new Promise(resolve => setImmediate(resolve));
  f.files.set(path.join(artifactRoot, 'renderer.js'), Buffer.from('changed artifact'));
  f.state.finish();
  await assert.rejects(next, { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  await adapter.close();
});

test('build config emits exact loader manifest and rejects sources changed during its controlled lifecycle', async () => {
  for (const policyOutput of [false, true]) {
  const source = policyOutput ? 'client/src/pages/secureshop/components/AgentLane/Turn.jsx'
    : 'client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx';
  const entry = policyOutput ? 'client/src/pages/secureshop/policyOutputClientRenderer.jsx'
    : 'client/src/pages/secureshop/searchEchoClientRenderer.jsx';
  const artifactRoot = path.join(sourceRoot, policyOutput
    ? 'client/build/secureshop-policy-output-renderer' : 'client/build/secureshop-search-echo-renderer');
  const filename = path.join(sourceRoot, policyOutput
    ? 'client/vite.policy-output-renderer.config.mjs' : 'client/vite.search-echo-renderer.config.mjs');
  const code = fs.readFileSync(filename, 'utf8').replace(/^import .*;\n/gm, '')
    .replace('import.meta.url', 'configUrl').replace('export default defineConfig', 'return defineConfig');
  const files = new Map([[path.join(sourceRoot, source), Buffer.from('component')],
    [path.join(sourceRoot, entry), Buffer.from('entry')],
    [path.join(artifactRoot, 'renderer.js'), Buffer.from('built artifact')]]);
  const fakeFs = { async readFile(name) { assert.ok(files.has(name)); return files.get(name); },
    async writeFile(name, bytes) { files.set(name, Buffer.from(bytes)); } };
  const factory = vm.runInThisContext(`(function(path,fs,crypto,fileURLToPath,defineConfig,react,process,configUrl){${code}\n})`)(
    path, fakeFs, require('node:crypto'), require('node:url').fileURLToPath, value => value,
    () => ({ name: 'controlled-react-placeholder' }), { env: {} }, require('node:url').pathToFileURL(filename).href);
  assert.throws(() => factory({ command: 'serve' }), /build only/);
  const config = factory({ command: 'build' });
  assert.equal(config.build.outDir, artifactRoot);
  assert.equal(config.build.lib.entry, path.join(sourceRoot, entry));
  assert.equal(config.build.copyPublicDir, false);
  const plugin = config.plugins[1];
  await plugin.buildStart(); await plugin.closeBundle();
  const manifest = JSON.parse(files.get(path.join(artifactRoot, 'manifest.json')));
  assert.deepEqual(manifest, { version: 1, component: policyOutput ? 'SecureShop.PolicyFinalResponse' : 'SecureShop.SearchEcho', source,
    sourceSha256: sha('component'), entry, entrySha256: sha('entry'), artifact: 'renderer.js',
    artifactSha256: sha('built artifact') });
  files.set(path.join(sourceRoot, entry), Buffer.from('changed entry'));
  await assert.rejects(plugin.closeBundle(), /sources changed/);
  }
});


test('opt-in DOM capture is exact, mode-bound, and mandatory only for requested new qualification', async () => {
  const f = fixture();
  f.state.snapshot = {version:1,phase:'react-ref-commit',mode:'vuln',nodes:[
    {path:[],type:1,name:'div',namespace:'http://www.w3.org/1999/xhtml',attributes:[]},
    {path:[0],type:3,text:'plain text'}]};
  const service = f.api.createSecureShopSearchEchoBrowserQualification();
  const value = await service.qualifySearchEcho({html:'plain text',modeCapability:mode('vuln'),captureDom:true});
  assert.equal(value.domCapture.originalSourceSha256,sha('plain text'));
  assert.deepEqual(value.domCapture.snapshot,f.state.snapshot);
  assert.equal(f.state.calls.at(-1)[1].captureDom,true);
  const legacy = await service.qualifySearchEcho({html:'plain text',modeCapability:mode('vuln')});
  assert.equal('domCapture' in legacy,false);
  await assert.rejects(service.qualifySearchEcho({html:'plain text',modeCapability:mode('fixed'),captureDom:true}),
    {code:'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE'});
  f.state.snapshot = null;
  await assert.rejects(service.qualifySearchEcho({html:'plain text',modeCapability:mode('vuln'),captureDom:true}));
  await assert.rejects(service.qualifySearchEcho({html:'plain text',modeCapability:mode('vuln'),captureDom:false}),
    {code:'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE'});
  await service.close();
});


const policyMode = effectiveMode => ({ version: 1, featureId: 'controlled_ssrf',
  policyVersion: 'owned-public-destination-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'controlled_ssrf' } });
test('V27 mounts the exact original final response through the pinned reply renderer in each mode', async () => {
  const f = fixture(() => {}, true);
  const adapter = f.api.createSecureShopPolicyOutputBrowserQualification();
  for (const selected of ['vuln', 'fixed']) {
    const html = '<img src=x onerror="alert(27)">';
    const result = await adapter.qualifyPolicyOutput({ html, modeCapability: policyMode(selected) });
    assert.equal(result.renderedSourceSha256, sha(html));
    assert.equal(result.component.id, 'SecureShop.PolicyFinalResponse');
    assert.deepEqual(f.state.calls.at(-1), ['mount', { html, modeCapability: policyMode(selected) }]);
    assert.equal(f.state.calls.find(row => row[0] === 'qualify')[2].eventSource, html);
  }
  for (const input of [
    { html: 'x', modeCapability: policyMode('fixed'), toolResult: 'forged' },
    { html: 'x', modeCapability: mode('vuln') },
    { html: 'x', modeCapability: { ...policyMode('vuln'), policyVersion: 'stale' } },
    { html: 'x', modeCapability: { ...policyMode('vuln'), scope: { kind: 'launch_feature', id: 'other' } } },
    { html: '', modeCapability: policyMode('vuln') },
    { html: '\ud800', modeCapability: policyMode('vuln') },
    { html: 'x\0y', modeCapability: policyMode('vuln') },
    { html: 'x'.repeat(20001), modeCapability: policyMode('vuln') },
  ]) await assert.rejects(adapter.qualifyPolicyOutput(input),
    { code: 'SECURESHOP_POLICY_OUTPUT_RENDERER_UNAVAILABLE' });
  await adapter.close();
  assert.equal(f.state.closed, true);
  assert.throws(() => adapter.readComponent(), { code: 'SECURESHOP_POLICY_OUTPUT_RENDERER_UNAVAILABLE' });
});
test('V27 refuses changed source, entry or artifact before any browser runner is created', () => {
  for (const field of ['sourceSha256', 'entrySha256', 'artifactSha256']) {
    const f = fixture(({ manifest }) => { manifest[field] = '0'.repeat(64); }, true);
    assert.throws(() => f.api.createSecureShopPolicyOutputBrowserQualification(),
      { code: 'SECURESHOP_POLICY_OUTPUT_RENDERER_UNAVAILABLE' });
    assert.equal(f.runnerOptions(), undefined);
  }
});

test('V27 snapshots original final bytes and rejects concurrent mode changes or artifact drift', async () => {
  const f = fixture(() => {}, true), adapter = f.api.createSecureShopPolicyOutputBrowserQualification();
  f.state.delayed = true;
  const input = { html: '<img src=x onerror="alert(27)">', modeCapability: policyMode('vuln') };
  const original = input.html, pending = adapter.qualifyPolicyOutput(input);
  while (!f.state.finish) await new Promise(resolve => setImmediate(resolve));
  input.html = 'replacement'; input.modeCapability.effectiveMode = 'fixed';
  await assert.rejects(adapter.qualifyPolicyOutput({ html: original, modeCapability: policyMode('fixed') }));
  f.state.finish(); const result = await pending;
  assert.equal(result.renderedSourceSha256, sha(original));
  assert.equal(f.state.calls.find(row => row[0] === 'mount')[1].modeCapability.effectiveMode, 'vuln');
  f.state.finish = null;
  const next = adapter.qualifyPolicyOutput({ html: original, modeCapability: policyMode('vuln') });
  while (!f.state.finish) await new Promise(resolve => setImmediate(resolve));
  f.files.set(path.join(sourceRoot, 'client/build/secureshop-policy-output-renderer/renderer.js'), Buffer.from('changed'));
  f.state.finish(); await assert.rejects(next, { code: 'SECURESHOP_POLICY_OUTPUT_RENDERER_UNAVAILABLE' });
  await adapter.close();
});
