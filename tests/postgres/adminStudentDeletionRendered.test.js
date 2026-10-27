'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const express = require('express');
const session = require('express-session');
const test = require('node:test');
const { JSDOM } = require('../../client/node_modules/jsdom');
const { STORES } = require('./adminStudentDeletionRenderedSupport');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { COHORT, deletionStorePlanSha256, deletionPaths, validateDeletionGrant,
  deletionAckFact, createDeletionAckCapture, observeDeletionAck,
  deletionResponseIdentity, installDeletionBrowserLoss, physicalDeleteDialogAction,
  physicalArmDeleteDialog, physicalOpenDeleteStudent, waitForDeletionInputReady,
  waitForDeletionDialogGone, witnessDeletionRequests,
  cleanupDeletionManagedUploads, cleanupPartialDeletionManagedUploads,
  boundedDeletionFailure, assertHeldDeletionFence, preserveFailedDeletionSeedJournal,
  assertDeletionSeedPoolKeys, closeDeletionRenderedServer,
  releaseDeletionReadbackCapacity } =
  require('./adminStudentDeletionRendered.integration.test');

const SHA = '1'.repeat(64);
const NONCE = 'abcdef123456';
const REPO = '/repo';
const run = `${REPO}/tasks/qualification/run-deletion-${NONCE}`;
const env = {
  ADMIN_STUDENT_DELETION_CURRENT_HOST: '1', PG_TEST_DISPOSABLE: 'yes',
  STUDENT_DELETION_EVIDENCE_PATH: `${run}/student-deletion-evidence.json`,
  STUDENT_DELETION_RESOURCE_JOURNAL: `${run}/runtime/tmp/student-deletion-resources.json`,
  ADMIN_STUDENT_DELETION_BROWSER_ACK: `${run}/runtime/browser-ack.json`,
  ADMIN_STUDENT_DELETION_BUILD_DIRECTORY: `${REPO}/client/build`,
  ADMIN_STUDENT_DELETION_BUILD_SHA256: SHA,
  ADMIN_STUDENT_DELETION_SNAPSHOT_SHA256: SHA,
  ADMIN_STUDENT_DELETION_STORE_PLAN_SHA256: SHA,
  PUPPETEER_EXECUTABLE_PATH: '/repo/browser/chrome',
  DVAIA_CHROMIUM_ACTUAL_EXECUTABLE: '/repo/browser/chrome',
};

test('deletion admission binds exact private run, sixteen identities and one closed grant', () => {
  const rows = STORES.map(store => ({ schema: store.schema,
    database: `dvaia_test_student_deletion_${NONCE}_${store.schema}` }));
  assert.match(deletionStorePlanSha256(rows), /^[0-9a-f]{64}$/);
  assert.notEqual(deletionStorePlanSha256(rows), deletionStorePlanSha256([...rows].reverse()));
  const paths = deletionPaths(env, REPO);
  const grant = { version: 1, cohort: COHORT, launcherPid: 101, workerPid: 102,
    nonce: NONCE, workspace: REPO, buildSha256: SHA, snapshotSha256: SHA,
    outerSandbox: 'repository-only', chromium: '/repo/browser/chrome',
    profile: `${run}/runtime/tmp/dvaia-student-deletion-browser-${NONCE}`,
    storePlanSha256: SHA };
  assert.deepEqual(validateDeletionGrant(grant, { env, paths, repo: REPO,
    launcherPid: 101, workerPid: 102 }), {
    admitted: true, nonceSha256: require('node:crypto').createHash('sha256').update(NONCE).digest('hex'),
    profile: grant.profile });
  for (const changed of [
    { ...grant, cohort: 'admin-q05-current-host' },
    { ...grant, workerPid: 103 },
    { ...grant, outerSandbox: 'unrestricted' },
    { ...grant, profile: `${run}/runtime/tmp/dvaia-student-deletion-browser-other` },
    { ...grant, storePlanSha256: '2'.repeat(64) },
    { ...grant, extra: true },
  ]) assert.throws(() => validateDeletionGrant(changed, { env, paths, repo: REPO,
    launcherPid: 101, workerPid: 102 }));
  for (const changed of [
    { ...env, STUDENT_DELETION_EVIDENCE_PATH: '/tmp/run-x/student-deletion-evidence.json' },
    { ...env, STUDENT_DELETION_RESOURCE_JOURNAL: `${run}/other.json` },
    { ...env, PUPPETEER_EXECUTABLE_PATH: '/repo/browser/other' },
  ]) assert.throws(() => deletionPaths(changed, REPO));
});

test('bounded failure evidence omits raw errors, secrets and network addresses', () => {
  const error = Object.assign(new Error('secret and bearer http://127.0.0.1:1234'), {
    code: 'CONNECTION_FAILED', stack: `secret at ${path.join(__dirname,
      'adminStudentDeletionRendered.integration.test.js')}:244:7`,
  });
  assert.deepEqual(boundedDeletionFailure(error, 'physical-cancel'),
    { phase: 'physical-cancel', name: 'Error', code: 'CONNECTION_FAILED',
      frame: { file: 'tests/postgres/adminStudentDeletionRendered.integration.test.js',
        line: 244, column: 7 }, nested: [] });
  assert.throws(() => boundedDeletionFailure(error, 'bad/phase'));
  const cleanup = Object.assign(new Error('secret cleanup'), { code: 'ENOENT' });
  const aggregate = new AggregateError([error, cleanup], 'private cause text');
  aggregate.failureLabels = ['primary', 'empty-owner-cleanup'];
  const fact = boundedDeletionFailure(aggregate, 'seed-controlled-preexisting-lifecycles');
  assert.equal(fact.nested.length, 2);
  assert.deepEqual(fact.nested.map(row => row.label), ['primary', 'empty-owner-cleanup']);
  assert.equal(fact.nested[0].code, 'CONNECTION_FAILED');
  assert.equal(fact.nested[1].code, 'ENOENT');
  assert(!JSON.stringify(fact).includes('secret'));
  assert(!JSON.stringify(fact).includes('127.0.0.1'));
});

test('held-run fence requires advanced durable generation and exact stale-generation error', () => {
  assert.equal(assertHeldDeletionFence({ before: '2', after: '3', error: {
    name: 'AbortError', message: 'Graph generation is no longer current',
  } }), true);
  for (const value of [
    { before: '2', after: '2', error: { name: 'AbortError', message: 'Graph generation is no longer current' } },
    { before: '2', after: '3', error: { name: 'AbortError', message: 'Agent deadline exceeded' } },
    { before: '2', after: '3', error: { name: 'Error', message: 'Graph generation is no longer current' } },
  ]) assert.throws(() => assertHeldDeletionFence(value));
});

test('seed pool preflight accepts real manifest insertion order and rejects missing or extra stores', () => {
  const runtime = { identity: {} }, migration = {};
  for (const store of STORES) {
    if (store.schema !== 'identity') runtime[store.schema] = {};
    if (['identity', 'ctf', 'finflow'].includes(store.schema)) migration[store.schema] = {};
  }
  assert.deepEqual(Object.keys(migration), ['identity', 'finflow', 'ctf'],
    'The actual initializer manifest inserts the three migration stores in this order');
  assert.deepEqual(Object.keys(migration).sort(), ['ctf', 'finflow', 'identity']);
  assert.equal(assertDeletionSeedPoolKeys(runtime, migration), true);
  assert.throws(() => assertDeletionSeedPoolKeys(runtime, { ...migration, stray: {} }));
  const { finflow, ...missing } = migration;
  assert.throws(() => assertDeletionSeedPoolKeys(runtime, missing));
});

test('completed fixture XSS readback retires exactly two reserved slots within the unchanged budget', async () => {
  let reserved = 78, closes = 0;
  const snapshot = () => ({ reserved, allocations: [
    { purpose: 'control', max: reserved - 2 }, { purpose: 'workshop', max: 2 },
  ] });
  const pool = { end: async () => { closes += 1; reserved -= 2; } };
  assert.deepEqual(await releaseDeletionReadbackCapacity({ pool, readSnapshot: snapshot }), {
    reservedBefore: 78, reservedAfter: 76, plannedReadbackPeak: 78,
  });
  assert.equal(closes, 1);
  assert.equal(reserved + 2, 78, 'Two migration max-one readback pools fit without budget increase');
  let insufficient = 78;
  await assert.rejects(releaseDeletionReadbackCapacity({
    pool: { end: async () => { insufficient -= 1; } },
    readSnapshot: () => ({ reserved: insufficient,
      allocations: [{ purpose: 'control', max: insufficient }] }),
  }), /release two slots/);
});

test('owned rendered HTTP cleanup joins the production auth router even if server close fails', async () => {
  const { createPostgresAuthRouter } = require('../../server/routes/postgresAuth');
  const pass = (_request, _response, next) => next();
  const calls = [];
  const makeRouter = () => createPostgresAuthRouter({ adapter: { repository: {} },
    limiters: { loginRateLimiter: pass, registerRateLimiter: pass,
      passwordResetRateLimiter: pass },
    loginRuntime: { snapshot: () => ({}), close: async () => { calls.push('login-runtime-close'); } },
  });
  assert.equal(await closeDeletionRenderedServer({}, makeRouter(), async () => {
    calls.push('http-close');
  }), true);
  assert.deepEqual(calls.sort(), ['http-close', 'login-runtime-close']);
  const failure = new Error('owned HTTP close failed');
  await assert.rejects(closeDeletionRenderedServer({}, makeRouter(), async () => {
    throw failure;
  }), error => error instanceof AggregateError && error.errors[0] === failure);
  assert.equal(calls.filter(value => value === 'login-runtime-close').length, 2,
    'The router must retire its timer and worker runtime despite HTTP cleanup failure');
});

test('exact synthetic managed upload cleanup proves target absence and preserves sibling until verified', async t => {
  const temp = await fs.mkdtemp(path.join(__dirname, '../../tasks/cache/deletion-upload-control-'));
  t.after(async () => fs.rm(temp, { recursive: true, force: true }));
  const managed = path.join(temp, 'server/uploads/managed');
  await fs.mkdir(managed, { recursive: true, mode: 0o700 });
  const intent = 'c73f5211-cf8f-4a4a-a4dc-109bace704d6';
  const siblingId = 98, targetId = 97;
  const body = Buffer.from('Synthetic sibling upload\n');
  const siblingFile = path.join(managed, String(siblingId), intent, 'deletion-owned.txt');
  await fs.mkdir(path.dirname(siblingFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(siblingFile, body, { flag: 'wx', mode: 0o600 });
  const digest = crypto.createHash('sha256').update(body).digest('hex');
  const prepared = { artifacts: { refs: {
    target: { ownerId: targetId, legacyUpload: { intentId: intent, contentSha256: digest } },
    sibling: { ownerId: siblingId, legacyUpload: { intentId: intent, contentSha256: digest } },
  } } };
  const principals = { target: { id: targetId }, sibling: { id: siblingId } };
  const facts = await cleanupDeletionManagedUploads({ prepared, principals, successful: true, root: temp });
  assert.deepEqual(facts, {
    target: { ownerId: targetId,
      filePath: path.join(managed, String(targetId), intent, 'deletion-owned.txt'),
      observedBeforeFixtureCleanup: false, exactFixtureArtifactsRemoved: true },
    sibling: { ownerId: siblingId, filePath: siblingFile,
      observedBeforeFixtureCleanup: true, exactFixtureArtifactsRemoved: true },
  });
  await assert.rejects(fs.lstat(siblingFile), { code: 'ENOENT' });
});

test('managed upload cleanup refuses a mismatched digest or unexpected sibling file without unlinking', async t => {
  const temp = await fs.mkdtemp(path.join(__dirname, '../../tasks/cache/deletion-upload-negative-'));
  t.after(async () => fs.rm(temp, { recursive: true, force: true }));
  const managed = path.join(temp, 'server/uploads/managed');
  await fs.mkdir(managed, { recursive: true, mode: 0o700 });
  const intent = 'c73f5211-cf8f-4a4a-a4dc-109bace704d6';
  const siblingFile = path.join(managed, '98', intent, 'deletion-owned.txt');
  await fs.mkdir(path.dirname(siblingFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(siblingFile, 'Synthetic sibling upload\n', { flag: 'wx', mode: 0o600 });
  const digest = crypto.createHash('sha256').update('Synthetic sibling upload\n').digest('hex');
  const prepared = { artifacts: { refs: {
    target: { ownerId: 97, legacyUpload: { intentId: intent, contentSha256: digest } },
    sibling: { ownerId: 98, legacyUpload: { intentId: intent,
      contentSha256: 'a'.repeat(64) } },
  } } };
  const principals = { target: { id: 97 }, sibling: { id: 98 } };
  await assert.rejects(cleanupDeletionManagedUploads({ prepared, principals,
    successful: true, root: temp }));
  assert.equal(await fs.readFile(siblingFile, 'utf8'), 'Synthetic sibling upload\n');
  prepared.artifacts.refs.sibling.legacyUpload.contentSha256 = digest;
  const extra = path.join(path.dirname(siblingFile), 'unowned.txt');
  await fs.writeFile(extra, 'unowned', { flag: 'wx', mode: 0o600 });
  await assert.rejects(cleanupDeletionManagedUploads({ prepared, principals,
    successful: true, root: temp }), /only its exact recorded artifact/);
  assert.equal(await fs.readFile(siblingFile, 'utf8'), 'Synthetic sibling upload\n');
  assert.equal(await fs.readFile(extra, 'utf8'), 'unowned');
});

test('partial seed cleanup follows only pre-effect admissions for zero, one or two files', async t => {
  const temp = await fs.mkdtemp(path.join(__dirname, '../../tasks/cache/deletion-upload-partial-'));
  t.after(async () => fs.rm(temp, { recursive: true, force: true }));
  const managed = path.join(temp, 'server/uploads/managed');
  await fs.mkdir(managed, { recursive: true, mode: 0o700 });
  const principals = { target: { id: 97 }, sibling: { id: 98 } };
  const reservations = [97, 98].map(ownerId => ({ version: 1, phase: 'reserved',
    kind: 'legacyUpload', ownerId, ownerDirectory: path.join(managed, String(ownerId)) }));
  assert.deepEqual(await cleanupPartialDeletionManagedUploads({ journal: reservations,
    principals, root: temp }), { reservedOwners: 2, admittedFiles: 0,
    removedFiles: 0, ownerDirsAbsent: true });
  const intent = 'c73f5211-cf8f-4a4a-a4dc-109bace704d6';
  const content = Buffer.from('Owned partial synthetic upload\n');
  const digest = crypto.createHash('sha256').update(content).digest('hex');
  const admitted = ownerId => ({ version: 1, phase: 'admitted', kind: 'legacyUpload', ownerId,
    intentId: intent, ownerDirectory: path.join(managed, String(ownerId)),
    filePath: path.join(managed, String(ownerId), intent, 'deletion-owned.txt'),
    contentSha256: digest });
  for (const ownerId of [97, 98]) {
    const entry = admitted(ownerId);
    await fs.mkdir(path.dirname(entry.filePath), { recursive: true, mode: 0o700 });
    await fs.writeFile(entry.filePath, content, { flag: 'wx', mode: 0o600 });
    const journal = [...reservations, ...[97, 98].filter(id => id <= ownerId).map(admitted)];
    if (ownerId === 97) {
      await assert.rejects(cleanupPartialDeletionManagedUploads({ journal: [
        ...reservations, { ...entry, contentSha256: 'a'.repeat(64) },
      ], principals, root: temp }));
      assert.equal(await fs.readFile(entry.filePath, 'utf8'), content.toString('utf8'));
    }
    if (ownerId === 98) {
      const first = admitted(97);
      await fs.mkdir(path.dirname(first.filePath), { recursive: true, mode: 0o700 });
      await fs.writeFile(first.filePath, content, { flag: 'wx', mode: 0o600 });
    }
    assert.deepEqual(await cleanupPartialDeletionManagedUploads({ journal, principals, root: temp }),
      { reservedOwners: 2, admittedFiles: ownerId === 97 ? 1 : 2,
        removedFiles: ownerId === 97 ? 1 : 2, ownerDirsAbsent: true });
    await assert.rejects(fs.lstat(entry.filePath), { code: 'ENOENT' });
  }
});

test('partial cleanup proves missing managed ancestor absent without creating it', async t => {
  const temp = await fs.mkdtemp(path.join(__dirname, '../../tasks/cache/deletion-upload-absent-'));
  t.after(async () => fs.rm(temp, { recursive: true, force: true }));
  await fs.mkdir(path.join(temp, 'server/uploads'), { recursive: true, mode: 0o700 });
  const principals = { target: { id: 97 }, sibling: { id: 98 } };
  const reserved = [97, 98].map(ownerId => ({ version: 1, phase: 'reserved',
    kind: 'legacyUpload', ownerId,
    ownerDirectory: path.join(temp, 'server/uploads/managed', String(ownerId)) }));
  assert.deepEqual(await cleanupPartialDeletionManagedUploads({ journal: reserved,
    principals, root: temp }), { reservedOwners: 2, admittedFiles: 0,
      removedFiles: 0, ownerDirsAbsent: true });
  await assert.rejects(fs.lstat(path.join(temp, 'server/uploads/managed')), { code: 'ENOENT' });
  await assert.rejects(cleanupPartialDeletionManagedUploads({ journal: [
    ...reserved, { version: 1, phase: 'admitted', kind: 'legacyUpload', ownerId: 97 },
  ], principals, root: temp }));
});

test('late seed failure and cleanup wrapper retain exact prewrite artifact journal', async () => {
  const journal = Object.freeze([{ version: 1, phase: 'admitted', kind: 'legacyUpload',
    ownerId: 97, contentSha256: SHA }]);
  const failure = new Error('late post-seed snapshot failure');
  let closeCalls = 0;
  const ctf = { close: async () => { closeCalls += 1; } };
  const late = await preserveFailedDeletionSeedJournal({ error: failure,
    artifacts: { journal, cleanupEmptyOwnerDirs: async () => {} }, ctf });
  assert.equal(late, failure);
  assert.equal(late.artifactJournal, journal);
  assert.equal(closeCalls, 1);
  const cleanupFailure = new Error('owned empty-directory cleanup failed');
  const wrapped = await preserveFailedDeletionSeedJournal({
    error: Object.assign(new Error('artifact seed failure'), { artifactJournal: journal,
      cleanupEmptyOwnerDirs: async () => { throw cleanupFailure; } }),
    ctf,
  });
  assert(wrapped instanceof AggregateError);
  assert.equal(wrapped.artifactJournal, journal);
  assert.equal(wrapped.errors[1], cleanupFailure);
  assert.equal(closeCalls, 2);
});

test('deletion ACK requires actual 200 and canonical completed job UUID', () => {
  const endpoint = '/api/admin/students/29';
  const jobId = 'c73f5211-cf8f-4a4a-a4dc-109bace704d6';
  const body = JSON.stringify({ success: true, message: 'Student deleted successfully', jobId });
  assert.deepEqual(deletionAckFact(200, body, endpoint),
    { status: 200, jobId, serverAcknowledgedCompleted: true });
  const capture = createDeletionAckCapture(endpoint);
  capture.write(Buffer.from(body.slice(0, -1)));
  assert.deepEqual(capture.end(200, Buffer.from(body.slice(-1))),
    { valid: true, fact: { status: 200, jobId, serverAcknowledgedCompleted: true } });
  for (const [status, value, path] of [
    [503, body, endpoint], [200, body, '/api/admin/administrators/29'],
    [200, JSON.stringify({ success: false, jobId }), endpoint],
    [200, JSON.stringify({ success: true, jobId: 'not-a-job' }), endpoint],
    [200, 'x'.repeat(8193), endpoint],
  ]) assert.throws(() => deletionAckFact(status, value, path));
  const invalid = createDeletionAckCapture(endpoint);
  invalid.write('{broken');
  assert.deepEqual(invalid.end(200), { valid: false, reason: 'invalid-ack' });
});

test('deletion ACK observer forwards original write/end and callbacks without emitting secrets', () => {
  const endpoint = '/api/admin/students/29';
  const seen = [], sent = [], callbacks = [];
  const res = { statusCode: 200, getHeader: () => undefined,
    write(chunk, callback) { sent.push(chunk); callback(); return false; },
    end(chunk) { sent.push(chunk); return 'original'; } };
  observeDeletionAck(res, endpoint, result => seen.push(result));
  assert.equal(res.write('{broken', () => callbacks.push('called')), false);
  assert.equal(res.end(), 'original');
  assert.deepEqual(callbacks, ['called']);
  assert.deepEqual(sent, ['{broken', undefined]);
  assert.deepEqual(seen, [{ valid: false, reason: 'invalid-ack' }]);
});

test('deletion observer joins real express-session split ACK and forwards the original JSON', async t => {
  const endpoint = '/api/admin/students/29';
  const jobId = 'c73f5211-cf8f-4a4a-a4dc-109bace704d6';
  const observations = [];
  const app = express();
  app.use((request, response, next) => {
    if (request.method === 'DELETE' && request.path === endpoint)
      observeDeletionAck(response, endpoint, result => observations.push(result));
    next();
  });
  app.use(session({ secret: 'owned-deletion-split-response-control-secret',
    resave: false, saveUninitialized: false }));
  app.get('/seed', (request, response) => {
    request.session.marker = 'owned';
    response.json({ seeded: true });
  });
  app.delete(endpoint, (_request, response) => {
    response.status(200).json({ success: true, message: 'Student deleted successfully', jobId });
  });
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const seed = await fetch(`${base}/seed`);
  assert.equal(seed.status, 200);
  const cookie = seed.headers.get('set-cookie')?.split(';')[0];
  assert(cookie?.startsWith('connect.sid='));
  const reply = await fetch(`${base}${endpoint}`, { method: 'DELETE', headers: { cookie } });
  assert.equal(reply.status, 200);
  assert.deepEqual(await reply.json(),
    { success: true, message: 'Student deleted successfully', jobId });
  assert.deepEqual(observations, [{ valid: true,
    fact: { status: 200, jobId, serverAcknowledgedCompleted: true } }]);
});

test('deletion CDP response loss selects exact DELETE once and rejects wrong status/ACK', async () => {
  const base = 'http://127.0.0.1:43916';
  const endpoint = '/api/admin/students/29';
  const jobId = 'c73f5211-cf8f-4a4a-a4dc-109bace704d6';
  const event = (id, method, url, status = 200) => ({ requestId: id,
    request: { method, url }, responseStatusCode: status });
  const client = new EventEmitter(), calls = [];
  client.send = async (method, args) => { calls.push({ method, args }); };
  client.detach = async () => {};
  const loss = await installDeletionBrowserLoss({ createCDPSession: async () => client },
    base, endpoint, () => ({ status: 200, jobId, serverAcknowledgedCompleted: true }));
  client.emit('Fetch.requestPaused', event('wrong-method', 'GET', `${base}${endpoint}`));
  client.emit('Fetch.requestPaused', event('wrong-target', 'DELETE', `${base}/api/admin/students/30`));
  client.emit('Fetch.requestPaused', event('wrong-origin', 'DELETE', `http://127.0.0.1:43917${endpoint}`));
  client.emit('Fetch.requestPaused', event('exact', 'DELETE', `${base}${endpoint}`));
  client.emit('Fetch.requestPaused', event('second', 'DELETE', `${base}${endpoint}`));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(loss.snapshot(), { selected: true, failed: 1, failure: false });
  assert.deepEqual(calls.filter(row => row.method === 'Fetch.failRequest').map(row => row.args.requestId), ['exact']);
  assert.deepEqual(calls.filter(row => row.method === 'Fetch.continueRequest').map(row => row.args.requestId).sort(),
    ['second', 'wrong-method', 'wrong-origin', 'wrong-target']);
  await loss.close();
  assert.equal(client.listenerCount('Fetch.requestPaused'), 0);
  assert.equal(deletionResponseIdentity(event('x', 'GET', `${base}${endpoint}`), base, endpoint), false);
  assert.throws(() => deletionResponseIdentity(event('x', 'DELETE', `${base}${endpoint}`, 403), base, endpoint));
  const rejected = new EventEmitter(), rejectedCalls = [];
  rejected.send = async (method, args) => { rejectedCalls.push({ method, args }); };
  rejected.detach = async () => {};
  const bad = await installDeletionBrowserLoss({ createCDPSession: async () => rejected },
    base, endpoint, () => null);
  rejected.emit('Fetch.requestPaused', event('bad', 'DELETE', `${base}${endpoint}`, 403));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(rejectedCalls.some(row => row.method === 'Fetch.failRequest'), false);
  await assert.rejects(bad.close());
});

test('browser DELETE witness counts exact dispatch and completion without exposing request data', () => {
  const page = new EventEmitter();
  const endpoint = '/api/admin/students/29';
  const base = 'http://127.0.0.1:43916';
  const witness = witnessDeletionRequests(page, base, endpoint);
  const request = (method, url) => ({ method: () => method, url: () => url });
  const exact = request('DELETE', `${base}${endpoint}`);
  const wrong = request('DELETE', `${base}/api/admin/students/30`);
  page.emit('request', request('GET', `${base}${endpoint}`));
  page.emit('request', request('POST', `${base}/api/auth/login`));
  assert.deepEqual(witness.snapshot(), { requests: 0, failed: 0, finished: 0, unexpected: 0 });
  page.emit('request', wrong);
  page.emit('request', request('POST', `${base}/api/admin/challenges/bulk-toggle`));
  page.emit('request', exact);
  page.emit('requestfailed', exact);
  assert.deepEqual(witness.snapshot(), { requests: 1, failed: 1, finished: 0, unexpected: 2 });
  witness.stop();
  assert.equal(page.listenerCount('request'), 0);
  assert.equal(page.listenerCount('requestfailed'), 0);
  assert.equal(page.listenerCount('requestfinished'), 0);
  page.emit('request', exact);
  assert.deepEqual(witness.snapshot(), { requests: 1, failed: 1, finished: 0, unexpected: 2 });
});

test('deletion dialog requires physical typed DELETE and exact scoped buttons', async () => {
  const dom = new JSDOM(`<table><tr><td>synthetic-student</td><td><button>Delete</button></td></tr></table>
    <div><header><h2>Delete Student</h2></header><p>Username: synthetic-student</p>
    <input id="delete-confirmation"><button>Cancel</button><button>Delete Student</button></div>
    <button>Delete Student</button>`);
  const clicks = [];
  dom.window.document.querySelector('#delete-confirmation').scrollIntoView = () => {};
  const page = { bringToFront: async () => clicks.push('focus'),
    waitForFunction: async () => ({ dispose: async () => {} }),
    evaluateHandle: async (callback, arg) => {
      const prior = global.document;
      global.document = dom.window.document;
      let node;
      try { node = callback(arg); } finally { global.document = prior; }
      return { asElement: () => node && ({
        click: async () => clicks.push(node.tagName === 'INPUT' ? 'input' : node.textContent.trim()),
        type: async value => { node.value += value; clicks.push('typed'); },
        evaluate: async fn => fn(node),
      }), dispose: async () => {} };
    } };
  await physicalOpenDeleteStudent(page, 'synthetic-student');
  assert.deepEqual(clicks.slice(0, 2), ['focus', 'Delete']);
  await physicalDeleteDialogAction(page, 'Delete Student', { typeDelete: true, clickCount: 2 });
  assert.deepEqual(clicks, ['focus', 'Delete', 'focus', 'focus', 'input', 'typed', 'Delete Student']);
  assert.equal(dom.window.document.querySelector('#delete-confirmation').value, 'DELETE');
  dom.window.document.querySelector('#delete-confirmation').value = '';
  await physicalArmDeleteDialog(page);
  assert.equal(dom.window.document.querySelector('#delete-confirmation').value, 'DELETE');
  await physicalDeleteDialogAction(page, 'Cancel');
  assert.equal(clicks.at(-1), 'Cancel');
  dom.window.document.querySelector('div button:last-child').disabled = true;
  await assert.rejects(physicalDeleteDialogAction(page, 'Delete Student'), /One enabled/);
  dom.window.document.querySelector('div').insertAdjacentHTML('beforeend', '<button>Cancel</button>');
  await assert.rejects(physicalDeleteDialogAction(page, 'Cancel'), /One enabled/);
});

test('dialog readiness waits through exiting duplicate and unstable geometry before physical input', async () => {
  const dom = new JSDOM(`<div id="old"><header><h2>Delete Student</h2></header>
    <input id="delete-confirmation"></div><div id="new"><header><h2>Delete Student</h2></header>
    <input id="delete-confirmation"></div>`, { pretendToBeVisual: true });
  const document = dom.window.document;
  const input = document.querySelector('#new input');
  let scrolls = 0, rectReads = 0, inputPolls = 0, gonePolls = 0;
  input.scrollIntoView = () => { scrolls += 1; };
  input.getBoundingClientRect = () => {
    rectReads += 1;
    const left = rectReads === 1 ? 100 : 120;
    return { x: left, y: 100, left, top: 100, width: 200, height: 30 };
  };
  document.elementFromPoint = () => input;
  const prior = { document: global.document, getComputedStyle: global.getComputedStyle,
    requestAnimationFrame: global.requestAnimationFrame, innerWidth: global.innerWidth,
    innerHeight: global.innerHeight };
  global.document = document;
  global.getComputedStyle = () => ({ display: 'block', visibility: 'visible',
    pointerEvents: 'auto', opacity: '1' });
  global.requestAnimationFrame = callback => { callback(); return 1; };
  global.innerWidth = 800;
  global.innerHeight = 600;
  const page = {
    evaluateHandle: async callback => {
      const node = callback();
      return { asElement: () => node && ({ evaluate: fn => fn(node) }), dispose: async () => {} };
    },
    waitForFunction: async (predicate, _options) => {
      for (let attempt = 0; attempt < 6; attempt += 1) {
        if (await predicate()) return { dispose: async () => {} };
        if (document.querySelector('#old')) document.querySelector('#old').remove();
        else if (input.isConnected) inputPolls += 1;
        else gonePolls += 1;
      }
      throw new Error('controlled physical readiness did not settle');
    },
  };
  try {
    await waitForDeletionInputReady(page);
    assert.equal(scrolls, 1);
    assert(rectReads >= 4 && inputPolls >= 1,
      'The actual readiness predicate must reject unstable geometry before succeeding');
    // The cancellation predicate must observe the old dialog still mounted,
    // then require its actual removal rather than an immediate stale match.
    const wait = page.waitForFunction;
    page.waitForFunction = async predicate => {
      gonePolls += 1;
      assert.equal(await predicate(), false);
      document.querySelector('#new').remove();
      assert.equal(await predicate(), true);
      return { dispose: async () => {} };
    };
    await waitForDeletionDialogGone(page);
    assert.equal(gonePolls, 1);
    page.waitForFunction = wait;
  } finally {
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete global[key]; else global[key] = value;
    }
    dom.window.close();
  }
});
