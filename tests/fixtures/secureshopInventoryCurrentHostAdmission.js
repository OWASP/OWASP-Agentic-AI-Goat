'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { assertNativeEvidencePath } = require('./secureshopNativeEvidencePath');

const RECEIPT = 'standalone-inventory-browser.json';
const MAX_RECEIPT_BYTES = 1024 * 1024;

function privateEvidence(root, receiptPath) {
  return path.resolve(receiptPath).startsWith(`${root}${path.sep}`);
}

async function privateDirectory(directory) {
  const info = await fs.lstat(directory);
  assert.ok(info.isDirectory() && !info.isSymbolicLink());
  assert.equal(info.uid, process.getuid());
  assert.equal(info.mode & 0o777, 0o700);
  assert.equal(await fs.realpath(directory), directory);
}

function exactLoopbackOrigin(origin) {
  const target = new URL(origin);
  assert.equal(target.origin, origin);
  assert.equal(target.protocol, 'http:');
  assert.equal(target.hostname, '127.0.0.1');
  assert.match(target.port, /^[1-9][0-9]{0,4}$/);
  assert.ok(Number(target.port) <= 65535);
  assert.equal(target.pathname, '/');
  assert.equal(target.search, '');
  assert.equal(target.hash, '');
  assert.equal(target.username, '');
  assert.equal(target.password, '');
}

function admitInventoryEvidence(root, receiptPath) {
  assertNativeEvidencePath(receiptPath, {
    root, dockerHost: process.env.DOCKER_HOST, basename: RECEIPT,
  });
  const owned = privateEvidence(root, receiptPath);
  if (owned) {
    assert.equal(process.env.SECURESHOP_STANDALONE_INVENTORY_NATIVE, '1');
    assert.notEqual(process.env.SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE, '1');
  }
  return owned;
}

async function launchInventoryBrowser({ root, receiptPath, profile, executablePath, origin }) {
  const owned = admitInventoryEvidence(root, receiptPath);
  const ordinary = { headless: true, userDataDir: profile, executablePath };
  if (!owned) return require('puppeteer').launch(ordinary);
  const run = path.dirname(receiptPath);
  const runtime = path.join(run, 'runtime');
  const tmp = path.join(runtime, 'tmp');
  const home = path.join(runtime, 'home');
  assert.equal(root, process.cwd());
  assert.equal(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, root);
  assert.equal(process.env.TMPDIR, tmp);
  assert.equal(process.env.MAC_CHROMIUM_TMPDIR, tmp);
  assert.equal(process.env.XDG_CACHE_HOME, path.join(home, '.cache'));
  assert.equal(process.env.XDG_CONFIG_HOME, path.join(home, '.config'));
  assert.equal(process.env.PUPPETEER_EXECUTABLE_PATH, executablePath);
  assert.ok(path.isAbsolute(executablePath));
  assert.equal(await fs.realpath(executablePath), executablePath);
  await fs.access(executablePath, constants.X_OK);
  for (const directory of [runtime, tmp, home, profile]) await privateDirectory(directory);
  assert.equal(path.dirname(profile), tmp);
  assert.match(path.basename(profile), /^owasp-ai-goat-standalone-inventory-[A-Za-z0-9_-]+$/);
  exactLoopbackOrigin(origin);
  return require('puppeteer').launch({ ...ordinary, args: [
    '--no-sandbox', '--disable-background-networking', '--disable-component-update',
    '--disable-domain-reliability', '--disable-quic',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--proxy-server=http://blocked.invalid:9',
    '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]',
  ] });
}

async function publishInventoryReceipt(root, receiptPath, packet) {
  const owned = admitInventoryEvidence(root, receiptPath);
  const bytes = JSON.stringify(packet, null, 2);
  if (!owned) return fs.writeFile(receiptPath, bytes, { flag: 'wx', mode: 0o600 });
  assert.ok(Buffer.byteLength(bytes) <= MAX_RECEIPT_BYTES);
  const handle = await fs.open(receiptPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
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
    if (primary) throw new AggregateError([primary, error], 'Inventory receipt write and close failed');
    throw error;
  }
  if (primary) throw primary;
}

module.exports = { admitInventoryEvidence, launchInventoryBrowser, publishInventoryReceipt };
