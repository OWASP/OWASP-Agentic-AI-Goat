'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const { admitQ05CurrentHostEvidence, createQ05PrivateWriter,
  q05CurrentHostBrowserOptions, v39CurrentHostBrowserOptions,
  q05InitialPrivateSave, q05FinalPrivateSave } =
  require('./postgres/secureshopOwnedMcpRegistryRendered.native');

function ownedRun(callback) {
  const run = path.join(root, 'tasks/qualification',
    `dvaia-mcp-assembly-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(run, { mode: 0o700 });
  fs.mkdirSync(path.join(run, 'tmp'), { mode: 0o700 });
  const evidencePath = path.join(run, 'candidate-result.json');
  const env = { MCP_REGISTERED_HANDOFF_Q05_CURRENT_HOST_EVIDENCE: '1',
    MCP_REGISTERED_HANDOFF_Q05_EVIDENCE_ROOT: run, TMPDIR: path.join(run, 'tmp'),
    MAC_CHROMIUM_TMPDIR: path.join(run, 'tmp') };
  try { return callback({ run, evidencePath, env }); }
  finally { fs.rmSync(run, { recursive: true, force: false }); }
}

test('Q05 admits only its fresh canonical owned in-repository result and exact temporary root', () => {
  ownedRun(({ run, evidencePath, env }) => {
    assert.equal(admitQ05CurrentHostEvidence({ env, source: root, evidencePath, enabled: true }), run);
    for (const changed of [
      { env: { ...env, MCP_REGISTERED_HANDOFF_Q05_CURRENT_HOST_EVIDENCE: '0' } },
      { env: { ...env, MCP_DESCRIPTION_V39_CURRENT_HOST_EVIDENCE: '1' } },
      { env: { ...env, MCP_REGISTERED_HANDOFF_Q05_EVIDENCE_ROOT: path.join(root, 'tasks/tmp') } },
      { env: { ...env, TMPDIR: path.join(root, 'tasks/tmp') } },
      { env: { ...env, MAC_CHROMIUM_TMPDIR: path.join(root, 'tasks/tmp') } },
      { evidencePath: path.join(run, 'other.json') },
      { evidencePath: path.join(run, '..', 'foreign', 'candidate-result.json') },
      { enabled: false },
    ]) assert.throws(() => admitQ05CurrentHostEvidence({ env, source: root,
      evidencePath, enabled: true, ...changed }));
    fs.chmodSync(run, 0o755);
    assert.throws(() => admitQ05CurrentHostEvidence({ env, source: root, evidencePath, enabled: true }));
    fs.chmodSync(run, 0o700);
    fs.writeFileSync(evidencePath, '{}', { mode: 0o600, flag: 'wx' });
    assert.throws(() => admitQ05CurrentHostEvidence({ env, source: root, evidencePath, enabled: true }), /fresh/);
  });
  ownedRun(({ run, evidencePath, env }) => {
    const alias = path.join(root, 'tasks/qualification', `dvaia-mcp-assembly-${crypto.randomBytes(4).toString('hex')}`);
    fs.symlinkSync(run, alias);
    try { assert.throws(() => admitQ05CurrentHostEvidence({ env: { ...env,
      MCP_REGISTERED_HANDOFF_Q05_EVIDENCE_ROOT: alias, TMPDIR: path.join(alias, 'tmp'),
      MAC_CHROMIUM_TMPDIR: path.join(alias, 'tmp') }, source: root,
      evidencePath: path.join(alias, 'candidate-result.json'), enabled: true })); }
    finally { fs.unlinkSync(alias); }
  });
});

test('Q05 private writer permits exactly six fixed artifacts and rejects replacement', () => {
  ownedRun(({ run, evidencePath, env }) => {
    admitQ05CurrentHostEvidence({ env, source: root, evidencePath, enabled: true });
    const names = ['candidate-result.json', 'registered-handoff-model.json',
      'registered-handoff-wire.json', 'registered-handoff-committed-loss.json',
      'registered-handoff-qualification.json', 'registered-handoff-receipt.json'];
    const writer = createQ05PrivateWriter(run);
    for (const name of names) {
      writer.write(name, '{"version":1}\n');
      const info = fs.lstatSync(path.join(run, name));
      assert.equal(info.isFile(), true); assert.equal(info.nlink, 1);
      assert.equal(info.mode & 0o777, 0o600);
    }
    writer.write('candidate-result.json', '{"status":"passed"}\n');
    assert.equal(fs.readFileSync(evidencePath, 'utf8'), '{"status":"passed"}\n');
    for (const name of ['../foreign.json', 'mcp-description-wire.json', 'registered-handoff-other.json'])
      assert.throws(() => writer.write(name, '{}'), /closed Q05/);
    fs.renameSync(evidencePath, path.join(run, 'prior-result.json'));
    fs.symlinkSync(path.join(root, 'AGENTS.md'), evidencePath);
    assert.throws(() => writer.write('candidate-result.json', '{}'), /replaced/);
    fs.chmodSync(run, 0o755);
    assert.throws(() => writer.write('registered-handoff-wire.json', '{}'), /owner changed/);
    fs.chmodSync(run, 0o700);
    writer.close();
  });
});

test('Q05 initial save failure closes its writer and retains the exact primary error', async () => {
  let closes = 0;
  const primary = Object.assign(new Error('controlled initial publication failure'), { code: 'EIO' });
  const writer = { close() { closes++; } };
  await assert.rejects(q05InitialPrivateSave(async () => { throw primary; }, writer),
    error => error === primary);
  assert.equal(closes, 1);
});

test('Q05 receipt and close failures retain the original scenario failure and attempt final status save', async () => {
  const primary = Object.assign(new Error('original scenario failed'), { code: 'SCENARIO_PRIMARY' });
  const receiptError = Object.assign(new Error('controlled receipt write failed'), { code: 'EIO' });
  const closeError = Object.assign(new Error('controlled close failed'), { code: 'EBADF' });
  const status = { status: 'passed', cleanupComplete: true, cleanupErrors: [],
    error: { code: 'SCENARIO_PRIMARY', message: 'original scenario failed' } };
  const receipt = { passed: true }; let saves = 0, closes = 0;
  const writer = { write(name) { assert.equal(name, 'registered-handoff-receipt.json'); throw receiptError; },
    close() { closes++; throw closeError; } };
  const failure = await q05FinalPrivateSave({ writer, receiptBytes: '{}\n',
    save: async () => { saves++; assert.equal(status.status, saves === 1 ? 'passed' : 'failed'); },
    status, receipt, primary });
  assert.equal(failure, primary); assert.equal(saves, 2); assert.equal(closes, 1);
  assert.deepEqual(status.cleanupErrors, ['EIO', 'EBADF']);
  assert.deepEqual(status.error, { code: 'SCENARIO_PRIMARY', message: 'original scenario failed' });
  assert.equal(status.cleanupComplete, false); assert.equal(receipt.passed, false);
});

test('Q05 final status publication failure never writes a passed receipt and closes the writer', async () => {
  const primary = Object.assign(new Error('original scenario failed'), { code: 'SCENARIO_PRIMARY' });
  const saveError = Object.assign(new Error('bounded candidate result rejected'), { code: 'EFBIG' });
  const status = { status: 'failed', cleanupComplete: true, cleanupErrors: [],
    error: { code: 'SCENARIO_PRIMARY', message: 'original scenario failed' } };
  const receipt = { passed: false }; let writes = 0, closes = 0;
  const writer = { write() { writes++; }, close() { closes++; } };
  const failure = await q05FinalPrivateSave({ writer, receiptBytes: '{"passed":true}\n',
    save: async () => { throw saveError; }, status, receipt, primary });
  assert.equal(failure, primary);
  assert.equal(writes, 0); assert.equal(closes, 1);
  assert.deepEqual(status.cleanupErrors, ['EFBIG']);
  assert.deepEqual(status.error, { code: 'SCENARIO_PRIMARY', message: 'original scenario failed' });
  assert.equal(status.cleanupComplete, false); assert.equal(receipt.passed, false);
});

test('Q05 writer attempts closure of every retained descriptor after one close throws', () => {
  ownedRun(({ run }) => {
    const writer = createQ05PrivateWriter(run);
    const originalOpen = fs.openSync, originalClose = fs.closeSync;
    const descriptors = []; let closes = 0;
    try {
      fs.openSync = (...args) => { const descriptor = originalOpen(...args); descriptors.push(descriptor); return descriptor; };
      for (const name of ['candidate-result.json', 'registered-handoff-model.json',
        'registered-handoff-wire.json', 'registered-handoff-committed-loss.json',
        'registered-handoff-qualification.json', 'registered-handoff-receipt.json']) writer.write(name, '{}\n');
      fs.closeSync = descriptor => {
        closes++; originalClose(descriptor);
        if (closes === 1) throw Object.assign(new Error('injected post-close failure'), { code: 'EIO' });
      };
      assert.throws(() => writer.close(), { code: 'EIO' });
    } finally { fs.openSync = originalOpen; fs.closeSync = originalClose; }
    assert.equal(closes, 6);
    for (const descriptor of descriptors) assert.throws(() => fs.fstatSync(descriptor), { code: 'EBADF' });
  });
});

test('Q05 browser exception requires admitted owned profile and exact loopback origin', () => {
  ownedRun(({ run }) => {
    const profile = fs.mkdtempSync(path.join(run, 'tmp', 'dvaia-mcp-registry-rendered-'));
    const selected = { directory: run, origin: 'http://127.0.0.1:40123', profile,
      executablePath: '/controlled/chrome' };
    const scoped = q05CurrentHostBrowserOptions(selected);
    assert.equal(scoped.args.filter(value => value === '--no-sandbox').length, 1);
    assert.ok(scoped.args.includes('--proxy-server=http://blocked.invalid:9'));
    assert.ok(scoped.args.some(value => value.startsWith('--host-resolver-rules=MAP * ~NOTFOUND')));
    assert.deepEqual(scoped, v39CurrentHostBrowserOptions(selected));
    assert.deepEqual(v39CurrentHostBrowserOptions({ ...selected, directory: null }),
      { headless: true, userDataDir: profile, executablePath: '/controlled/chrome' });
    for (const changed of [
      { directory: null }, { origin: 'http://outside.invalid:40123' },
      { origin: 'https://127.0.0.1:40123' }, { origin: 'http://127.0.0.1:40123/other' },
      { profile: path.join(run, 'other', path.basename(profile)) },
    ]) assert.throws(() => q05CurrentHostBrowserOptions({ ...selected, ...changed }));
    fs.chmodSync(profile, 0o755);
    assert.throws(() => q05CurrentHostBrowserOptions(selected));
    fs.chmodSync(profile, 0o700);
    fs.chmodSync(path.join(run, 'tmp'), 0o755);
    assert.throws(() => q05CurrentHostBrowserOptions(selected), /owner changed/);
    fs.chmodSync(path.join(run, 'tmp'), 0o700);
  });
});
