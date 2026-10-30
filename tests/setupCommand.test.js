'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { prepareSetupCommandEnv, runSetupCommand } = require('../scripts/lib/setup-command');

test('npm install children opt into system CA only when no explicit CA control exists', () => {
  const base = { PATH: '/bin', CUSTOM: 'keep' };
  assert.equal(prepareSetupCommandEnv('npm', ['ci'], base, { platform: 'darwin', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, '1');
  assert.equal(prepareSetupCommandEnv('npm', ['ci'], base, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, '1');
  assert.equal(prepareSetupCommandEnv('npm', ['install'], base, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, '1');
  assert.equal(prepareSetupCommandEnv('npm', ['i'], base, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, '1');
  assert.equal(prepareSetupCommandEnv('npm', ['ci'], { ...base, NODE_USE_SYSTEM_CA: '0' }, { platform: 'darwin', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, '0');
  for (const nodeOptions of ['--use-openssl-ca', '--use-system-ca=1', '"--use-system-ca"', '--no-use-system-ca']) {
    assert.equal(prepareSetupCommandEnv('npm', ['ci'], { ...base, NODE_OPTIONS: nodeOptions }, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, undefined);
  }
  for (const key of ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'npm_config_cafile', 'NPM_CONFIG_CAFILE', 'npm_config_ca', 'NPM_CONFIG_CA']) {
    assert.equal(prepareSetupCommandEnv('npm', ['ci'], { ...base, [key]: '/tmp/ca.pem' }, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, undefined);
  }
  assert.equal(prepareSetupCommandEnv('npm', ['run', 'install'], base, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, undefined);
  assert.equal(prepareSetupCommandEnv('npm', ['exec', 'install'], base, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, undefined);
  assert.equal(prepareSetupCommandEnv('node', ['ci'], base, { platform: 'linux', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, undefined);
  assert.equal(prepareSetupCommandEnv('npm', ['ci'], base, { platform: 'win32', nodeVersion: '26.10.0' }).NODE_USE_SYSTEM_CA, undefined);
  assert.equal(prepareSetupCommandEnv('npm', ['ci'], base, { platform: 'linux', nodeVersion: '25.0.0' }).NODE_USE_SYSTEM_CA, undefined);
  assert.equal(base.NODE_USE_SYSTEM_CA, undefined);
  assert.equal(base.CUSTOM, 'keep');
});

test('setup command preserves success, nonzero exit, and spawn failures', async () => {
  await runSetupCommand(process.execPath, ['-e', 'process.exit(0)'], process.cwd(), process.env);
  await assert.rejects(runSetupCommand(process.execPath, ['-e', 'process.exit(7)'], process.cwd(), process.env), /failed \(7\)/);
  await assert.rejects(runSetupCommand('/nonexistent/owasp-ai-goat-setup-command', [], process.cwd(), process.env), { code: 'ENOENT' });
});

test('timed out setup waits for a SIGTERM-resistant command to be killed', { skip: process.platform === 'win32' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-setup-stop-'));
  const pidFile = path.join(dir, 'pid');
  try {
    await assert.rejects(runSetupCommand(process.execPath, ['-e',
      "require('fs').writeFileSync(process.argv[1],String(process.pid));process.on('SIGTERM',()=>{});setInterval(()=>{},1000)", pidFile],
    process.cwd(), process.env, { timeoutMs: 500, killGraceMs: 100 }), /timed out/);
    const pid = Number(fs.readFileSync(pidFile, 'utf8'));
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('setup timeout also stops a resistant descendant after its parent exits', { skip: process.platform === 'win32' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-setup-tree-'));
  const childFile = path.join(dir, 'child');
  const parentFile = path.join(dir, 'parent');
  const descendant = "require('fs').writeFileSync(process.argv[1],String(process.pid));process.on('SIGTERM',()=>{});setInterval(()=>{},1000)";
  const parent = `require('fs').writeFileSync(process.argv[1],String(process.pid));require('child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)},process.argv[2]],{stdio:'ignore'});setInterval(()=>{},1000)`;
  try {
    await assert.rejects(runSetupCommand(process.execPath, ['-e', parent, parentFile, childFile],
      process.cwd(), process.env, { timeoutMs: 500, killGraceMs: 100 }), /timed out/);
    const pid = Number(fs.readFileSync(childFile, 'utf8'));
    // The OS may briefly retain the orphan's exit record before reaping it.
    const deadline = Date.now() + 2000;
    while (true) {
      try { process.kill(pid, 0); }
      catch (error) { assert.equal(error.code, 'ESRCH'); break; }
      assert.ok(Date.now() < deadline, 'setup descendant remained after timeout');
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  } finally {
    if (fs.existsSync(parentFile)) {
      try { process.kill(-Number(fs.readFileSync(parentFile, 'utf8')), 'SIGKILL'); }
      catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
