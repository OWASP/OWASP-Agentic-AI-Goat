'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { captureBrowserRecord } = require('./secureshopDarwinBrowserBirth');
function sceneAuditBrowserArgs(env, { workspace, evidencePath, profile, origin }) {
  if (env.SECURESHOP_SCENE_AUDIT_TEST_NO_SANDBOX === undefined) return ['--disable-background-networking'];
  assert.equal(env.SECURESHOP_SCENE_AUDIT_TEST_NO_SANDBOX, '1');
  assert.equal(env.SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE, '1');
  for (const key of ['SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE',
    'SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE', 'SECURESHOP_AUDIT_TIMING_BROWSER_NATIVE']) {
    assert.ok(env[key] === undefined || env[key] === '0', 'V15 cannot mix other audit modes');
  }
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.LIVE_OLLAMA_TEST, '1');
  assert.equal(env.NODE_ENV, 'test');
  assert.equal(env.DVAIA_CURRENT_MAIN_WORKSPACE, workspace);
  assert.equal(workspace, process.cwd());
  const run = path.dirname(evidencePath);
  assert.equal(path.dirname(run), path.join(workspace, 'tasks/qualification'));
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(env.TMPDIR, path.join(run, 'runtime/tmp'));
  assert.equal(path.dirname(profile), env.TMPDIR);
  assert.match(path.basename(profile), /^dvaia-scene-audit-v15-[A-Za-z0-9_-]+$/);
  assert.equal(env.SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH, path.join(run, 'scene-audit-v15-browser-birth.json'));
  assert.equal(env.SECURESHOP_SCENE_AUDIT_BROWSER_ACK_PATH, path.join(run, 'scene-audit-v15-browser-ack.json'));
  assert.match(env.SECURESHOP_SCENE_AUDIT_BROWSER_SHA256, /^[a-f0-9]{64}$/);
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
    path.join(workspace, 'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.ok(path.isAbsolute(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON));
  for (const directory of [run, path.join(run, 'runtime'), env.TMPDIR, profile]) {
    const info = fs.lstatSync(directory);
    assert.ok(info.isDirectory() && !info.isSymbolicLink());
    assert.equal(fs.realpathSync(directory), directory);
    assert.equal(info.uid, process.getuid());
    assert.equal(info.mode & 0o777, 0o700);
  }
  const target = new URL(origin);
  assert.equal(target.origin, origin);
  assert.equal(target.protocol, 'http:');
  assert.equal(target.hostname, '127.0.0.1');
  assert.match(target.port, /^[1-9]\d{0,4}$/);
  return ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
    '--disable-domain-reliability', '--disable-quic',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--proxy-server=http://blocked.invalid:9', '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'];
}
async function acknowledgeSceneAuditBrowser(env, { workspace, browser, profile }) {
  const pid = browser.process()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 1);
  const executablePath = fs.realpathSync(env.PUPPETEER_EXECUTABLE_PATH);
  assert.equal(executablePath, env.PUPPETEER_EXECUTABLE_PATH);
  const record = captureBrowserRecord({ root: workspace, kind: 'scene_audit_v15_browser', pid,
    executablePath, executableSha256: env.SECURESHOP_SCENE_AUDIT_BROWSER_SHA256 });
  const recordPath = env.SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH;
  const temporary = `${recordPath}.${process.pid}.tmp`;
  await fs.promises.writeFile(temporary, `${JSON.stringify(record)}\n`, { flag: 'wx', mode: 0o600 });
  await fs.promises.rename(temporary, recordPath);
  const expected = createHash('sha256').update(await fs.promises.readFile(recordPath)).digest('hex');
  const until = Date.now() + 15000;
  while (Date.now() < until) {
    let value;
    try { value = JSON.parse(await fs.promises.readFile(env.SECURESHOP_SCENE_AUDIT_BROWSER_ACK_PATH, 'utf8')); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await new Promise(resolve => setTimeout(resolve, 25));
      continue;
    }
    const info = await fs.promises.lstat(env.SECURESHOP_SCENE_AUDIT_BROWSER_ACK_PATH);
    assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
      && (info.mode & 0o777) === 0o600);
    assert.deepEqual(value, { schemaVersion: 1, recordSha256: expected, parentPid: process.pid,
      browserPid: pid, profile });
    return;
  }
  throw new Error('V15 independent live browser capture acknowledgement unavailable');
}
module.exports = { sceneAuditBrowserArgs, acknowledgeSceneAuditBrowser };
