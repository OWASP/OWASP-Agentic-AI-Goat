'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { PassThrough } = require('node:stream');
const root = path.resolve(__dirname, '..');
const { admitV39CurrentHostEvidence, createV39PrivateWriter,
  v39CurrentHostBrowserOptions, createV39BrowserDiagnostic } =
  require('./postgres/secureshopOwnedMcpRegistryRendered.native');

function ownedRun(callback) {
  const run = path.join(root, 'tasks/qualification',
    `owasp-ai-goat-mcp-assembly-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(run, { mode: 0o700 });
  fs.mkdirSync(path.join(run, 'tmp'), { mode: 0o700 });
  const evidencePath = path.join(run, 'candidate-result.json');
  const env = { MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE: '1',
    MCP_DESCRIPTION_V39_EVIDENCE_ROOT: run, TMPDIR: path.join(run, 'tmp'),
    MAC_CHROMIUM_TMPDIR: path.join(run, 'tmp') };
  try { return callback({ run, evidencePath, env }); }
  finally { fs.rmSync(run, { recursive: true, force: false }); }
}

test('V39 current-host evidence admits only a fresh, owned private exact run path', () => {
  ownedRun(({ run, evidencePath, env }) => {
    assert.equal(admitV39CurrentHostEvidence({ env, source: root, evidencePath, enabled: true }), run);
    for (const changed of [
      { env: { ...env, MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE: '0' } },
      { env: { ...env, TMPDIR: path.join(root, 'tasks/tmp') } },
      { env: { ...env, MCP_DESCRIPTION_V39_EVIDENCE_ROOT: path.join(root, 'tasks/tmp') } },
      { evidencePath: path.join(run, 'other.json') },
      { evidencePath: path.join(run, '..', '..', 'escape.json') },
      { enabled: false },
    ]) assert.throws(() => admitV39CurrentHostEvidence({ env, source: root,
      evidencePath, enabled: true, ...changed }));
    fs.writeFileSync(evidencePath, '{}', { mode: 0o600, flag: 'wx' });
    assert.throws(() => admitV39CurrentHostEvidence({ env, source: root, evidencePath, enabled: true }),
      /fresh/);
  });
});

test('V39 private output rejects preexisting files and replacements without following symlinks', () => {
  ownedRun(({ run, evidencePath, env }) => {
    admitV39CurrentHostEvidence({ env, source: root, evidencePath, enabled: true });
    const writer = createV39PrivateWriter(run);
    writer.write('candidate-result.json', '{"status":"running"}\n');
    assert.equal(fs.statSync(evidencePath).mode & 0o777, 0o600);
    writer.write('candidate-result.json', '{"status":"passed"}\n');
    assert.equal(fs.readFileSync(evidencePath, 'utf8'), '{"status":"passed"}\n');
    assert.throws(() => writer.write('../other.json', '{}'), /closed V39/);
    fs.renameSync(evidencePath, path.join(run, 'original-result.json'));
    fs.symlinkSync(path.join(root, 'AGENTS.md'), evidencePath);
    assert.throws(() => writer.write('candidate-result.json', '{}'), /replaced/);
    writer.close();
    fs.symlinkSync(path.join(root, 'AGENTS.md'), path.join(run, 'mcp-description-wire.json'));
    const another = createV39PrivateWriter(run);
    assert.throws(() => another.write('mcp-description-wire.json', '{}'), { code: 'EEXIST' });
    another.close();
  });
});

test('V39 run directory cannot be a symlink or widened', () => {
  ownedRun(({ run, evidencePath, env }) => {
    fs.chmodSync(run, 0o755);
    assert.throws(() => admitV39CurrentHostEvidence({ env, source: root, evidencePath, enabled: true }));
    fs.chmodSync(run, 0o700);
    const alias = path.join(root, 'tasks/qualification', 'owasp-ai-goat-mcp-assembly-symlink');
    fs.symlinkSync(run, alias);
    try { assert.throws(() => admitV39CurrentHostEvidence({ env: { ...env,
      MCP_DESCRIPTION_V39_EVIDENCE_ROOT: alias, TMPDIR: path.join(alias, 'tmp'),
      MAC_CHROMIUM_TMPDIR: path.join(alias, 'tmp') }, source: root,
      evidencePath: path.join(alias, 'candidate-result.json'), enabled: true })); }
    finally { fs.unlinkSync(alias); }
  });
});

test('only admitted V39 current-host browser options use the bounded local sandbox exception', () => {
  ownedRun(({ run }) => {
    const profile = fs.mkdtempSync(path.join(run, 'tmp', 'owasp-ai-goat-mcp-registry-rendered-'));
    const selected = { directory: run, origin: 'http://127.0.0.1:40123', profile,
      executablePath: '/controlled/chrome' };
    const ordinary = v39CurrentHostBrowserOptions({ ...selected, directory: null });
    assert.deepEqual(ordinary, { headless: true, userDataDir: profile,
      executablePath: '/controlled/chrome' });
    const scoped = v39CurrentHostBrowserOptions(selected);
    assert.equal(scoped.args.filter(value => value === '--no-sandbox').length, 1);
    for (const requirement of ['--disable-background-networking',
      '--proxy-server=http://blocked.invalid:9',
      '--proxy-bypass-list=127.0.0.1;localhost;[::1]'])
      assert.ok(scoped.args.includes(requirement));
    assert.ok(scoped.args.some(value => value.startsWith('--host-resolver-rules=MAP * ~NOTFOUND')));
    for (const changed of [
      { origin: 'http://outside.invalid:40123' },
      { origin: 'https://127.0.0.1:40123' },
      { origin: 'http://127.0.0.1:40123/other' },
      { profile: path.join(run, 'other', path.basename(profile)) },
    ]) assert.throws(() => v39CurrentHostBrowserOptions({ ...selected, ...changed }));
  });
});

test('V39 pre-model browser diagnostic is private, phase-ordered and stderr-bounded', () => {
  ownedRun(({ run }) => {
    const writer = createV39PrivateWriter(run);
    const diagnostic = createV39BrowserDiagnostic({ origin: 'http://127.0.0.1:40123',
      write: writer.write });
    const stderr = new PassThrough();
    const child = { pid: 12345, exitCode: null, signalCode: 'SIGTRAP', stderr };
    diagnostic.attach({ process: () => child });
    diagnostic.advance('page-created');
    assert.throws(() => diagnostic.advance('target-guard-ready'));
    stderr.write(Buffer.alloc(20000, 65));
    diagnostic.record(new Error('Viewport session closed'));
    stderr.end();
    const file = path.join(run, 'v39-browser-diagnostic.json');
    const value = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(value.phase, 'page-created');
    assert.equal(value.browserPid, 12345);
    assert.equal(value.browserSignalCodeAtRecord, 'SIGTRAP');
    assert.equal(value.stderrCapture, 'post-launch-through-target-guard');
    assert.equal(value.stderr.length, 16384);
    assert.equal(value.stderrObservedBytes, 16385);
    assert.equal(value.stderrTruncated, true);
    assert.equal(value.failure.message, 'Viewport session closed');
    diagnostic.record(new Error('must not overwrite first observation'));
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).failure.message,
      'Viewport session closed');
    writer.close();
    const successful = createV39BrowserDiagnostic({ origin: 'http://127.0.0.1:40124',
      write: () => {} });
    successful.attach({ process: () => ({ pid: 4321, stderr: new PassThrough() }) });
    for (const phase of ['page-created', 'viewport-ready', 'target-guard-ready'])
      successful.advance(phase);
    successful.record(null);
  });
});
