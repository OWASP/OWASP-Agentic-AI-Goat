'use strict';
// Exact current-host counterparts of Inventory's owned browser configuration.
// The maintained launcher still runs Node/Chrome beneath repository-only.sb.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { constants } = require('node:fs');
const { assertNativeEvidencePath } = require('./secureshopNativeEvidencePath');
const SCOPES = Object.freeze({
  'admin-policy-chat-browser': ['SECURESHOP_ADMIN_POLICY_CHAT_BROWSER_NATIVE', 'owasp-ai-goat-role-admin-policy-'],
  'admin-audit-browser': ['SECURESHOP_ADMIN_AUDIT_CHAT_BROWSER_NATIVE', 'owasp-ai-goat-role-admin-audit-'],
  'admin-acl-chat-browser': ['SECURESHOP_ADMIN_ACL_CHAT_BROWSER_NATIVE', 'owasp-ai-goat-q64-admin-acl-'],
});
async function browserArgs({ cohort, root, evidencePath, profile, executablePath, origin }) {
  assert(Object.hasOwn(SCOPES, cohort));
  const [gate, prefix] = SCOPES[cohort];
  assert.equal(process.env[gate], '1');
  assertNativeEvidencePath(evidencePath, { root, dockerHost: process.env.DOCKER_HOST, basename: `${cohort}.json` });
  if (!evidencePath.startsWith(`${root}${path.sep}`)) return [];
  const runtime = path.join(path.dirname(evidencePath), 'runtime'), tmp = path.join(runtime, 'tmp'), home = path.join(runtime, 'home');
  assert.equal(root, process.cwd());
  assert.equal(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, root);
  assert.equal(process.env.TMPDIR, tmp); assert.equal(process.env.MAC_CHROMIUM_TMPDIR, tmp);
  assert.equal(process.env.XDG_CACHE_HOME, path.join(home, '.cache'));
  assert.equal(process.env.XDG_CONFIG_HOME, path.join(home, '.config'));
  assert.equal(process.env.PUPPETEER_EXECUTABLE_PATH, executablePath);
  assert(path.isAbsolute(executablePath)); assert.equal(await fs.realpath(executablePath), executablePath);
  await fs.access(executablePath, constants.X_OK);
  for (const directory of [runtime, tmp, home, profile]) {
    const info = await fs.lstat(directory);
    assert(info.isDirectory() && !info.isSymbolicLink()); assert.equal(info.uid, process.getuid());
    assert.equal(info.mode & 0o777, 0o700); assert.equal(await fs.realpath(directory), directory);
  }
  assert.equal(path.dirname(profile), tmp);
  assert(profile.startsWith(path.join(tmp, prefix)));
  assert.match(path.basename(profile).slice(prefix.length), /^[A-Za-z0-9_-]+$/);
  const target = new URL(origin);
  assert.equal(target.origin, origin); assert.equal(target.protocol, 'http:'); assert.equal(target.hostname, '127.0.0.1');
  assert.match(target.port, /^[1-9][0-9]{0,4}$/); assert(Number(target.port) <= 65535);
  assert.equal(target.pathname, '/'); assert.equal(target.search, ''); assert.equal(target.hash, '');
  assert.equal(target.username, ''); assert.equal(target.password, '');
  return ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
    '--disable-domain-reliability', '--disable-quic',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--proxy-server=http://blocked.invalid:9', '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'];
}
module.exports = { browserArgs };
