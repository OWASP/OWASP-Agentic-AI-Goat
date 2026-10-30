'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { assertNativeEvidencePath } = require('./secureshopNativeEvidencePath');

const RECEIPT = 'merchant-inventory-chat-browser.json';
const PREFIX = 'owasp-ai-goat-role-inventory-';
const MAX_RECEIPT_BYTES = 4096;
const CHROME_ARGS = Object.freeze([
  '--no-sandbox', '--disable-background-networking', '--disable-component-update',
  '--disable-domain-reliability', '--disable-quic',
  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--proxy-server=http://blocked.invalid:9',
  '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]',
]);

function privateDirectory(directory, mode = 0o700) {
  const info = fs.lstatSync(directory);
  assert.ok(info.isDirectory() && !info.isSymbolicLink());
  assert.equal(info.uid, process.getuid());
  assert.equal(info.mode & 0o777, mode);
  assert.equal(fs.realpathSync(directory), directory);
}

function admit(env, { workspace, evidencePath, executablePath }) {
  assert.equal(env.SECURESHOP_MERCHANT_INVENTORY_CHAT_BROWSER_NATIVE, '1');
  assert.notEqual(env.SECURESHOP_STANDALONE_INVENTORY_NATIVE, '1');
  assert.notEqual(env.SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE, '1');
  assert.ok(path.isAbsolute(workspace) && path.resolve(workspace) === workspace);
  assert.ok(path.isAbsolute(executablePath) && fs.realpathSync(executablePath) === executablePath);
  assert.equal(env.PUPPETEER_EXECUTABLE_PATH, executablePath);
  assertNativeEvidencePath(evidencePath, { root: workspace, dockerHost: env.DOCKER_HOST, basename: RECEIPT });
  const owned = evidencePath.startsWith(`${workspace}${path.sep}`);
  if (owned) {
    assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, workspace);
    const run = path.dirname(evidencePath), runtime = path.join(run, 'runtime');
    const temporary = path.join(runtime, 'tmp'), home = path.join(runtime, 'home');
    assert.equal(env.TMPDIR, temporary);
    assert.equal(env.MAC_CHROMIUM_TMPDIR, temporary);
    assert.equal(env.XDG_CACHE_HOME, path.join(home, '.cache'));
    assert.equal(env.XDG_CONFIG_HOME, path.join(home, '.config'));
    for (const directory of [runtime, temporary, home]) privateDirectory(directory);
  }
  return Object.freeze({ owned, workspace, evidencePath, executablePath });
}

function browserArgs(admission, profile, origin) {
  if (!admission.owned) return [];
  const temporary = path.join(path.dirname(admission.evidencePath), 'runtime/tmp');
  assert.equal(path.dirname(profile), temporary);
  assert.match(path.basename(profile), /^owasp-ai-goat-role-inventory-[A-Za-z0-9_-]+$/);
  privateDirectory(profile);
  const url = new URL(origin);
  assert.equal(url.origin, origin);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.port, /^[1-9][0-9]{0,4}$/);
  assert.ok(Number(url.port) <= 65535);
  assert.equal(url.pathname, '/');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  return [...CHROME_ARGS];
}

async function publish(admission, packet) {
  const bytes = JSON.stringify(packet, null, 2);
  if (!admission.owned) return fsp.writeFile(admission.evidencePath, bytes, { flag: 'wx', mode: 0o600 });
  assert.ok(Buffer.byteLength(bytes) <= MAX_RECEIPT_BYTES);
  const handle = await fsp.open(admission.evidencePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  let primary;
  try {
    const info = await handle.stat();
    assert.ok(info.isFile());
    assert.equal(info.uid, process.getuid());
    assert.equal(info.nlink, 1);
    assert.equal(info.mode & 0o777, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) { primary = error; }
  try { await handle.close(); }
  catch (error) {
    if (primary) throw new AggregateError([primary, error], 'Inventory confirmation receipt write/close failed');
    throw error;
  }
  if (primary) throw primary;
}

module.exports = { admit, browserArgs, publish, RECEIPT, PREFIX, CHROME_ARGS };
