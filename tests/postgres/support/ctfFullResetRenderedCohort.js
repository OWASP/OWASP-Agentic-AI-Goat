'use strict';
// Standalone, disposable Full Reset qualification. Nothing in this module
// writes after CTF authority activation or manufactures model-earned credit.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');

const ROOT = path.resolve(__dirname, '../../..');
const OWNER = 1001, SIBLING = 1002, ADMIN = 1003;
const BIRTH_KIND = 'ctf_full_reset_browser';
const FLAGS = Object.freeze(['--no-sandbox', '--disable-background-networking',
  '--disable-component-update', '--disable-domain-reliability', '--disable-quic',
  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--proxy-server=http://blocked.invalid:9',
  '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]']);
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
function spawnAdmittedBrowser(executable, args, options) {
  // Resolve after the owned CDP allowance has wrapped the child-process API.
  return require('node:child_process').spawn(executable, args, options);
}
function privateDirectory(directory) {
  const info = fs.lstatSync(directory);
  assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid() &&
    (info.mode & 0o777) === 0o700);
  assert.equal(fs.realpathSync(directory), directory);
}
function assertTwoStoreEnvironment(env = process.env) {
  assert.equal(env.CTF_FULL_RESET_RENDERED_ISOLATED, '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  const selected = ['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL',
    'CTF_DATABASE_URL', 'CTF_MIGRATION_DATABASE_URL', 'CTF_DELIVERY_DATABASE_URL'].map(name => new URL(env[name]));
  for (const url of selected) {
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/dvaia_test_ctf_/);
  }
  assert.equal(selected[0].pathname, selected[1].pathname);
  assert.equal(selected[2].pathname, selected[3].pathname);
  assert.equal(selected[2].pathname, selected[4].pathname);
  assert.notEqual(selected[0].pathname, selected[2].pathname);
  assert.equal(decodeURIComponent(selected[4].username), 'dvaia_ctf_delivery');
  assert.equal(env.CTF_FULL_RESET_Q05_RECEIPT,
    path.join(env.CTF_FULL_RESET_RUNTIME_DIRECTORY, 'ctf-full-reset-q05-result.json'));
  assert.equal(env.CTF_CONTENT_SOURCE_ROOT, ROOT);
  assert.equal(env.CTF_CONTENT_RUNTIME_DIRECTORY, env.CTF_FULL_RESET_RUNTIME_DIRECTORY);
  const inventory = fs.readFileSync(env.CTF_CONTENT_SOURCE_INVENTORY);
  assert.equal(sha256(inventory), env.CTF_CONTENT_SOURCE_INVENTORY_SHA256);
  assert.equal(fs.realpathSync(env.CTF_CONTENT_BUILD_DIRECTORY),
    fs.realpathSync(JSON.parse(fs.readFileSync(env.CTF_CONTENT_BUILD_REPORT)).outputRoot));
  assert(fs.existsSync(path.join(env.CTF_CONTENT_BUILD_DIRECTORY, 'index.html')));
  return JSON.parse(inventory);
}
function admitFullResetBrowser(env = process.env) {
  assert.equal(env.CTF_FULL_RESET_RENDERED_ISOLATED, '1');
  assert.equal(env.CTF_FULL_RESET_BROWSER_NATIVE, '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.CTF_FULL_RESET_SOURCE_ROOT, ROOT);
  const run = path.dirname(env.CTF_FULL_RESET_RUNTIME_DIRECTORY);
  assert.equal(path.dirname(run), path.join(ROOT, 'tasks/qualification'));
  assert.match(path.basename(run), /^dvaia-ctf-stages-route-[A-Za-z0-9_-]+$/);
  const runtime = path.join(run, 'runtime'), evidence = path.join(run, 'rendered-evidence');
  const profile = path.join(evidence, 'full-reset-profile');
  assert.equal(env.CTF_FULL_RESET_RUNTIME_DIRECTORY, runtime);
  assert.equal(env.CTF_RENDERED_EVIDENCE, evidence);
  assert.equal(env.CTF_FULL_RESET_Q05_RECEIPT, path.join(runtime, 'ctf-full-reset-q05-result.json'));
  assert.equal(env.CTF_FULL_RESET_BROWSER_RECORD, path.join(evidence, 'full-reset-browser-birth.json'));
  assert.equal(env.CTF_FULL_RESET_BROWSER_ACK, path.join(evidence, 'full-reset-browser-ack.json'));
  assert.equal(env.TMPDIR, path.join(runtime, 'tmp'));
  assert.equal(path.dirname(env.CTF_FULL_RESET_BROWSER_TMP), path.join(ROOT, 'tasks/tmp'));
  assert.match(path.basename(env.CTF_FULL_RESET_BROWSER_TMP), /^f-[A-Za-z0-9_-]{8,}$/);
  assert(Buffer.byteLength(env.CTF_FULL_RESET_BROWSER_TMP) <= 80);
  assert.equal(env.XDG_CACHE_HOME, path.join(runtime, 'cache'));
  assert.equal(env.XDG_CONFIG_HOME, path.join(runtime, 'config'));
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
    path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.equal(fs.realpathSync(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON),
    env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON);
  for (const directory of [path.join(ROOT, 'tasks/qualification'), run, runtime, evidence,
    env.TMPDIR, env.XDG_CACHE_HOME, env.XDG_CONFIG_HOME, env.CTF_FULL_RESET_BROWSER_TMP])
    privateDirectory(directory);
  const executable = env.ANALYTICS_BROWSER_EXECUTABLE;
  assert.equal(executable, env.PUPPETEER_EXECUTABLE_PATH);
  assert(path.isAbsolute(executable) && fs.realpathSync(executable) === executable);
  assert.match(env.ANALYTICS_BROWSER_SHA256, /^[a-f0-9]{64}$/);
  assert.equal(sha256(fs.readFileSync(executable)), env.ANALYTICS_BROWSER_SHA256);
  assert(!fs.existsSync(profile), 'Full Reset browser profile already exists');
  return { run, runtime, evidence, profile, executable };
}

async function launchFullResetBrowser(env = process.env) {
  const admitted = admitFullResetBrowser(env);
  const owner = require('../../fixtures/secureshopAnalyticsBrowserOwner');
  const puppeteer = require('puppeteer');
  fs.mkdirSync(admitted.profile, { mode: 0o700 });
  const args = await puppeteer.defaultArgs({ headless: true, userDataDir: admitted.profile,
    args: ['--remote-debugging-port=0', ...FLAGS] });
  const childEnv = { PATH: '/usr/bin:/bin', TMPDIR: env.CTF_FULL_RESET_BROWSER_TMP,
    TMP: env.CTF_FULL_RESET_BROWSER_TMP, TEMP: env.CTF_FULL_RESET_BROWSER_TMP,
    MAC_CHROMIUM_TMPDIR: env.CTF_FULL_RESET_BROWSER_TMP,
    XDG_CACHE_HOME: env.XDG_CACHE_HOME, XDG_CONFIG_HOME: env.XDG_CONFIG_HOME };
  let child, browser, birth;
  const retire = async () => {
    if (child) {
      await owner.retireChild(child);
      assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' });
    }
    fs.writeFileSync(path.join(admitted.evidence, 'full-reset-cleanup.json'),
      JSON.stringify(owner.profileDisposition(child?.pid ?? null, birth)), { mode: 0o600 });
  };
  try {
    // The owned CDP allowance is installed by the gated integration before
    // this lookup; capturing spawn at module import would bypass its wrapper.
    child = spawnAdmittedBrowser(admitted.executable, args, { detached: false, env: childEnv,
      stdio: ['ignore', 'ignore', 'pipe'] });
    const stderr = path.join(admitted.evidence, 'full-reset-stderr.log');
    fs.writeFileSync(stderr, '', { mode: 0o600 });
    const endpoint = owner.observeBrowserEndpoint(child, chunk => fs.appendFileSync(stderr, chunk));
    endpoint.catch(() => {});
    await owner.bounded(once(child, 'spawn'), 3000, 'Full Reset Chrome spawn deadline');
    const record = require('../../fixtures/secureshopDarwinBrowserBirth').captureBrowserRecord({
      root: ROOT, kind: BIRTH_KIND, pid: child.pid,
      executablePath: admitted.executable, executableSha256: env.ANALYTICS_BROWSER_SHA256 });
    assert.equal(record.schemaVersion, 2);
    assert.equal(record.processes.length, 1);
    birth = record.processes[0];
    assert.equal(birth.pid, child.pid); assert.equal(birth.parentPid, process.pid);
    assert.equal(birth.pgid, process.pid); assert.equal(birth.sessionId, process.pid);
    assert.equal(birth.uid, process.getuid());
    const temporary = `${env.CTF_FULL_RESET_BROWSER_RECORD}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(record)}\n`, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, env.CTF_FULL_RESET_BROWSER_RECORD);
    const recordSha256 = sha256(fs.readFileSync(env.CTF_FULL_RESET_BROWSER_RECORD));
    const until = Date.now() + 15000;
    let ack;
    while (Date.now() < until) {
      try { ack = JSON.parse(fs.readFileSync(env.CTF_FULL_RESET_BROWSER_ACK, 'utf8')); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await new Promise(resolve => setTimeout(resolve, 25)); continue;
      }
      const stat = fs.lstatSync(env.CTF_FULL_RESET_BROWSER_ACK);
      assert(stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() &&
        (stat.mode & 0o777) === 0o600);
      assert.deepEqual(ack, { schemaVersion: 1, recordSha256, parentPid: process.pid,
        browserPid: child.pid, profile: admitted.profile });
      break;
    }
    assert(ack, 'Independent Full Reset live browser acknowledgement unavailable');
    fs.writeFileSync(path.join(admitted.evidence, 'full-reset-process.json'),
      JSON.stringify({ pid: child.pid, profile: admitted.profile,
        executableSha256: env.ANALYTICS_BROWSER_SHA256 }), { mode: 0o600 });
    browser = await owner.bounded(puppeteer.connect({ browserWSEndpoint: await endpoint,
      protocolTimeout: 15000 }), 20000, 'Full Reset Chrome connection deadline');
    const close = browser.close.bind(browser); let closed = false;
    browser.close = async () => {
      if (closed) return; closed = true; let primary;
      try { await owner.bounded(close(), 3000, 'Full Reset Chrome close deadline'); }
      catch (error) { primary = error; }
      try { await retire(); } catch (error) {
        throw new AggregateError([...(primary ? [primary] : []), error], 'Full Reset Chrome cleanup failed');
      }
      if (primary) throw primary;
    };
    return browser;
  } catch (error) {
    try { await retire(); } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'Full Reset Chrome launch cleanup failed');
    }
    throw error;
  }
}

async function seedFullResetPreactivation({ identity, ctf,
  seedDefaults = require('../../../server/database/postgres/ctfDb').seed,
  seedPlatform = require('../../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  const one = async (pool, sql, args = []) => (await pool.query(sql, args)).rows[0];
  const open = await one(ctf, 'SELECT state,operation_id FROM ctf.bootstrap_control WHERE singleton');
  assert.deepEqual(open, { state: 'open', operation_id: null });
  await seedDefaults(ctf);
  const stage = await one(ctf, 'SELECT * FROM ctf.ctf_stages WHERE stage_number=1');
  assert(Number.isSafeInteger(stage?.id) && stage.id > 0);
  const { stageDigest } = require('../../../server/agent-runtime/ctfStageJudge');
  const hash = sha256('controlled full reset payload');
  for (const id of [OWNER, SIBLING, ADMIN]) {
    await identity.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) VALUES($1,$2,$3,$4,$5,$6)",
      [id, `full-reset-${id}`, `full-reset-${id}@fixture.invalid`, '$2b$04$' + 'a'.repeat(53),
        id === ADMIN ? 'admin' : 'student', id === ADMIN ? 1 : 0]);
  }
  await seedPlatform(identity);
  const catalog = await one(identity,
    'SELECT workshop_key FROM workshop_platform.exercises WHERE catalog_active=true ORDER BY workshop_key LIMIT 1');
  assert(catalog?.workshop_key);
  await identity.query('INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation,started_at) VALUES($1,$2,0,clock_timestamp())',
    [SIBLING, catalog.workshop_key]);
  for (const id of [OWNER, SIBLING])
    await ctf.query('INSERT INTO ctf.ctf_participants(id,user_id,username) VALUES($1,$1,$2)',
      [id, `full-reset-${id}`]);
  const progress = await one(ctf,
    "INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,attempts_count) VALUES($1,$2,'in_progress',clock_timestamp(),1) RETURNING id",
    [OWNER, stage.id]);
  await ctf.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at) VALUES($1,$2,'in_progress',clock_timestamp())",
    [SIBLING, stage.id]);
  const attempt = await one(ctf,
    'INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response,was_successful) VALUES($1,$2,1,$3,$4,0) RETURNING id',
    [OWNER, stage.id, 'controlled historical attempt', 'controlled historical response']);
  await ctf.query("INSERT INTO ctf.ctf_events(event_type,participant_id,stage_id,event_data) VALUES('controlled_preexisting',$1,$2,$3)",
    [OWNER, stage.id, '{}']);
  await ctf.query('INSERT INTO ctf.ctf_sessions(participant_id,session_token,is_active) VALUES($1,$2,1)',
    [OWNER, 'controlled-full-reset-ctf-session']);
  await ctf.query('INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,$2,$3)',
    [OWNER, stage.id, 'controlled_full_reset_tag']);
  await ctf.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES($1,$2,$3,$4)',
    [stage.id, hash, 'controlled full reset payload', OWNER]);
  await ctf.query('INSERT INTO ctf.ctf_bans(user_id,reason,banned_by) VALUES($1,$2,$3)',
    [OWNER, 'controlled historical ban', ADMIN]);
  await ctf.query('INSERT INTO ctf.ctf_judgments(run_id,attempt_id,participant_id,stage_id,progress_id,stage_digest,verdict,accepted,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,0,$8)',
    ['controlled-historical-no-model-credit', attempt.id, OWNER, stage.id, progress.id,
      stageDigest(stage), 'fail', JSON.stringify({ fixture: 'preactivation-controlled-history', modelCredit: false })]);
  await ctf.query('INSERT INTO ctf.ctf_stage_teaching_content(stage_id,objective_text,solution_text) VALUES($1,$2,$3)',
    [stage.id, 'Controlled teaching objective', 'Controlled instructor solution']);
  await ctf.query('SELECT ctf.refresh_authorized_leaderboard(clock_timestamp())');
  const tables = ['ctf_attempts', 'ctf_progress', 'ctf_technique_blocklist', 'ctf_leaderboard',
    'ctf_events', 'ctf_sessions', 'ctf_payload_blocklist', 'ctf_participants',
    'ctf_stages', 'ctf_config', 'ctf_stage_teaching_content', 'ctf_bans', 'ctf_judgments'];
  const counts = {};
  for (const table of tables) counts[table] = Number((await one(ctf,
    `SELECT count(*)::int AS n FROM ctf.${table}`)).n);
  for (const [table, count] of Object.entries(counts))
    assert(Number.isSafeInteger(count) && count > 0, `${table} preactivation witness missing`);
  return Object.freeze({ ownerId: OWNER, siblingId: SIBLING, adminId: ADMIN,
    seedProvenance: 'controlled-preactivation-synthetic-not-model-credit',
    modelCalls: 0, judgeCalls: 0, canonicalCredit: false, counts });
}

async function externalFullResetSnapshot({ identity, siblingId = SIBLING }) {
  const rows = async (sql, args = []) => (await identity.query(sql, args)).rows;
  const platform = await rows('SELECT id,username,email,role,admin_level,is_active FROM identity.users WHERE id=$1 ORDER BY id', [siblingId]);
  const workshopSibling = await rows('SELECT user_id,workshop_key,generation,started_at,updated_at FROM workshop_platform.user_state WHERE user_id=$1 ORDER BY workshop_key', [siblingId]);
  assert.equal(platform.length, 1); assert.equal(workshopSibling.length, 1);
  return { platform, workshopSibling };
}

module.exports = { assertTwoStoreEnvironment, admitFullResetBrowser, launchFullResetBrowser, spawnAdmittedBrowser,
  seedFullResetPreactivation, externalFullResetSnapshot, BIRTH_KIND, OWNER, SIBLING, ADMIN };
