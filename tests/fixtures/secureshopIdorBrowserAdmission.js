'use strict';

// Test-only full V12 admission. This does not change either lesson's semantics.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { captureBrowserRecord } = require('./secureshopDarwinBrowserBirth');
const PREFIX = 'SECURESHOP_IDOR_LESSON_';
function browserArgs(env, { workspace, evidencePath, profile, origin }) {
  if (env[`${PREFIX}TEST_NO_SANDBOX`] === undefined) return [];
  assert.equal(env[`${PREFIX}TEST_NO_SANDBOX`], '1');
  assert.equal(env.SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE, '1');
  assert.ok(!env.SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY, 'full cart and order cohort required');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.LIVE_OLLAMA_TEST, '1');
  assert.equal(env.NODE_ENV, 'test');
  assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, workspace);
  assert.equal(workspace, process.cwd());
  const run = path.dirname(evidencePath);
  assert.equal(path.dirname(run), path.join(workspace, 'tasks/qualification'));
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(env.TMPDIR, path.join(run, 'runtime/tmp'));
  assert.equal(path.dirname(profile), env.TMPDIR);
  assert.match(path.basename(profile), /^owasp-ai-goat-customer-idor-browser-[A-Za-z0-9_-]+$/);
  assert.equal(env[`${PREFIX}BROWSER_RECORD_PATH`], path.join(run, 'idor-lesson-browser.json'));
  assert.equal(env[`${PREFIX}BROWSER_ACK_PATH`], path.join(run, 'idor-lesson-browser-ack.json'));
  assert.match(env[`${PREFIX}BROWSER_SHA256`], /^[a-f0-9]{64}$/);
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
async function acknowledgeBrowser(env, { workspace, browser, profile }) {
  const pid = browser.process()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 1);
  const executablePath = fs.realpathSync(env.PUPPETEER_EXECUTABLE_PATH);
  assert.equal(executablePath, env.PUPPETEER_EXECUTABLE_PATH);
  const record = captureBrowserRecord({ root: workspace, kind: 'idor_lesson_browser', pid,
    executablePath, executableSha256: env[`${PREFIX}BROWSER_SHA256`] });
  const recordPath = env[`${PREFIX}BROWSER_RECORD_PATH`];
  const temporaryRecord = `${recordPath}.${process.pid}.tmp`;
  await fs.promises.writeFile(temporaryRecord, `${JSON.stringify(record)}\n`, { flag: 'wx', mode: 0o600 });
  await fs.promises.rename(temporaryRecord, recordPath);
  const expected = createHash('sha256').update(await fs.promises.readFile(recordPath)).digest('hex');
  const until = Date.now() + 15000;
  while (Date.now() < until) {
    let value;
    try { value = JSON.parse(await fs.promises.readFile(env[`${PREFIX}BROWSER_ACK_PATH`], 'utf8')); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await new Promise(resolve => setTimeout(resolve, 25));
      continue;
    }
    const info = await fs.promises.lstat(env[`${PREFIX}BROWSER_ACK_PATH`]);
    assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
      && (info.mode & 0o777) === 0o600);
    assert.deepEqual(value, { schemaVersion: 1, recordSha256: expected, parentPid: process.pid,
      browserPid: pid, profile });
    return;
  }
  throw new Error('V12 independent live browser capture acknowledgement unavailable');
}
async function selectIdorLesson(frame) {
  const selector = 'select[id^="agent-lane-task-customer-"]';
  await frame.waitForSelector(selector, { visible: true });
  await frame.select(selector, 'idor');
  await frame.waitForSelector('section[aria-label="Customer access control lesson"]');
}
async function authenticateOwnerHeaders(composition, headers, expected) {
  // Never emit assertions containing bearer bytes, including on malformed input.
  try {
    if (!/^Bearer [A-Za-z0-9_.-]+$/.test(headers?.authorization || '')
        || !/^[A-Za-z0-9_-]{43}$/.test(headers?.['x-owasp-ai-goat-secureshop-launch'] || '')) throw Error();
    const scope = await composition.launches.resolveCapability(headers['x-owasp-ai-goat-secureshop-launch']);
    const actor = await composition.personaAuth.authenticateBoundToken({
      scope, token: headers.authorization.slice(7),
    });
    const trustedScope = require('../../server/services/secureshopConversationBinding').createLaunchScope(scope);
    if (!Number.isSafeInteger(actor?.user?.id) || actor.user.id < 1 || actor.user.role !== 'customer'
        || typeof actor.jti !== 'string' || !actor.jti || typeof actor.sessionId !== 'string'
        || !actor.sessionId || typeof actor.authorityVersion !== 'string' || !actor.authorityVersion) throw Error();
    const identity = { scope: trustedScope, principalId: actor.user.id, role: actor.user.role,
      jti: actor.jti, sessionId: actor.sessionId, authorityVersion: actor.authorityVersion };
    if (expected && !require('node:util').isDeepStrictEqual(identity, expected)) throw Error();
    return { scope, actor, identity, headers: {
      authorization: headers.authorization, 'x-owasp-ai-goat-secureshop-launch': headers['x-owasp-ai-goat-secureshop-launch'],
    } };
  } catch {
    throw new Error('V12 server-authenticated owner authority changed or is invalid');
  }
}
module.exports = { browserArgs, acknowledgeBrowser, selectIdorLesson, authenticateOwnerHeaders };
