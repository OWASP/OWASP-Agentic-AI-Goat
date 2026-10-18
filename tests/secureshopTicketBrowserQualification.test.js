'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

const sha = value => createHash('sha256').update(value).digest('hex');
const sourceRoot = path.resolve(__dirname, '..');
const moduleFile = path.join(sourceRoot, 'server/services/secureshopTicketBrowserQualification.js');
const source = 'client/src/pages/secureshop/components/AdminTicketBody.jsx';
const entry = 'client/src/pages/secureshop/components/ticketDetailClientRenderer.jsx';
const artifactRoot = path.join(sourceRoot, 'client/build/secureshop-ticket-renderer');
const mode = effectiveMode => ({ version: 1, featureId: 'support_tickets',
  policyVersion: 'owned-ticket-render-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'support_tickets' } });

function fixture(mutate = () => {}) {
  const script = 'trusted synthetic ticket renderer';
  const sourceBytes = Buffer.from('virtual source');
  const entryBytes = Buffer.from('virtual entry');
  const manifest = { version: 1, component: 'SecureShop.AdminTicketBody', source,
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
            } };
          await options.clientMount(page, { html, signal: config.signal });
          if (state.delayed) await new Promise(resolve => { state.finish = resolve; });
          return { executed: false, targetEventExecuted: false };
        }, async close() { state.closed = true; } };
      } };
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
  ]) {
    const f = fixture(change);
    assert.throws(() => f.api.createSecureShopTicketBrowserQualification(),
      { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
    assert.equal(f.runnerOptions(), undefined);
  }
});

test('fixed and vulnerable ticket bodies mount as exact data with a closed current mode capability', async () => {
  const f = fixture();
  const adapter = f.api.createSecureShopTicketBrowserQualification();
  assert.equal(adapter.readComponent().id, 'SecureShop.AdminTicketBody');
  for (const effectiveMode of ['fixed', 'vuln']) {
    const html = `<img onerror="owned(${effectiveMode})">`;
    const result = await adapter.qualifyTicket({ html, ticketId: '37', modeCapability: mode(effectiveMode) });
    assert.equal(result.renderedSourceSha256, sha(html));
    assert.equal(result.component.sourceSha256, sha('virtual source'));
    assert.equal(result.component.artifactSha256, sha(f.script));
    assert.deepEqual(f.state.calls.at(-1), ['mount', { body: html, modeCapability: mode(effectiveMode) }]);
    assert.equal(f.state.calls.at(-2)[1], f.script);
  }
  for (const input of [
    { html: 'x', ticketId: '37', modeCapability: mode('fixed'), renderer: 'forged' },
    { html: 'x', ticketId: '0', modeCapability: mode('fixed') },
    { html: 'x', ticketId: '37', modeCapability: { ...mode('fixed'), effectiveMode: 'unknown' } },
    { html: 'x', ticketId: '37', modeCapability: { ...mode('fixed'), scope: { kind: 'launch_feature', id: 'other' } } },
    { html: 'x'.repeat(20001), ticketId: '37', modeCapability: mode('fixed') },
  ]) await assert.rejects(adapter.qualifyTicket(input), { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
  await adapter.close();
  assert.equal(f.state.closed, true);
  assert.throws(() => adapter.readComponent(), { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
  await assert.rejects(adapter.qualifyTicket({ html: 'x', ticketId: '37', modeCapability: mode('fixed') }),
    { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
});

test('current source drift, cancellation, and concurrent mode calls deny without cross-mode mount', async () => {
  const drift = fixture();
  const stale = drift.api.createSecureShopTicketBrowserQualification();
  drift.files.set(path.join(sourceRoot, source), Buffer.from('changed source'));
  assert.throws(() => stale.readComponent(), { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
  await assert.rejects(stale.qualifyTicket({ html: 'x', ticketId: '3', modeCapability: mode('fixed') }),
    { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
  const f = fixture();
  const adapter = f.api.createSecureShopTicketBrowserQualification();
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(adapter.qualifyTicket({ html: 'x', ticketId: '3', modeCapability: mode('fixed'), signal: aborted.signal }),
    { name: 'AbortError' });
  assert.equal(f.state.calls.length, 0);
  f.state.delayed = true;
  const first = adapter.qualifyTicket({ html: 'fixed body', ticketId: '3', modeCapability: mode('fixed') });
  while (!f.state.finish) await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(adapter.qualifyTicket({ html: 'vuln body', ticketId: '3', modeCapability: mode('vuln') }),
    { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
  assert.equal(f.state.calls.filter(([kind]) => kind === 'mount').length, 1);
  assert.equal(f.state.calls.find(([kind]) => kind === 'mount')[1].modeCapability.effectiveMode, 'fixed');
  f.state.finish();
  await first;
  await adapter.close();
});
