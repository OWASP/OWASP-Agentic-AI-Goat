'use strict';
// A separate Q05 facet. The ten-content receipt is validated before this
// destructive operation and is never reinterpreted as post-reset state.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const POST_PATH = '/api/ctf/admin/reset';
const TOKEN = 'RESET_CTF_CONFIRM';
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const CLEARED = Object.freeze(['ctf_attempts', 'ctf_progress', 'ctf_technique_blocklist',
  'ctf_leaderboard', 'ctf_events', 'ctf_sessions', 'ctf_payload_blocklist', 'ctf_participants']);
const RETAINED = Object.freeze(['ctf_stages', 'ctf_config', 'ctf_stage_teaching_content',
  'ctf_bans', 'ctf_judgments']);
const IMMUTABLE_BOOTSTRAP = Object.freeze(['sessions', 'pages', 'imports']);
const FACTS = Object.freeze(['wrongTokenNoPost', 'cancelNoPost', 'cancelNoEffect',
  'dialogAbaNoPost', 'dialogAbaNoEffect', 'onePhysicalPost', 'capturedAuthorityAndBody',
  'canonicalOperationApplied', 'removedCountMatches', 'mutableCtfCleared',
  'mutableIdentityMemoryCleared',
  'retainedCtfUnchanged', 'historicalIdentityEvidencePreserved',
  'platformAndWorkshopSiblingPreserved', 'unknownUiNoReference', 'noAutomaticRetry']);
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const stringify = rows => JSON.stringify(rows);

function assertNonvacuousResetSeed(before) {
  exactKeys(before.cleared, CLEARED);
  exactKeys(before.retained, RETAINED);
  exactKeys(before.immutableBootstrap, IMMUTABLE_BOOTSTRAP);
  exactKeys(before.adaptiveMemory, ['technique', 'payload']);
  const clearedRows = Object.fromEntries(CLEARED.map(table => [table, before.cleared[table].length]));
  const retainedRows = Object.fromEntries(RETAINED.map(table => [table, before.retained[table].length]));
  const immutableBootstrapRows = Object.fromEntries(IMMUTABLE_BOOTSTRAP.map(table =>
    [table, before.immutableBootstrap[table].length]));
  const mutableIdentityMemoryRows = Object.fromEntries(['technique', 'payload'].map(kind =>
    [kind, before.adaptiveMemory[kind].length]));
  for (const [table, count] of Object.entries(clearedRows))
    assert(Number.isSafeInteger(count) && count > 0, `${table} must be populated before Full Reset`);
  for (const table of ['ctf_stages', 'ctf_config', 'ctf_stage_teaching_content', 'ctf_bans', 'ctf_judgments'])
    assert(Number.isSafeInteger(retainedRows[table]) && retainedRows[table] > 0,
      `${table} must be populated to prove retention`);
  for (const [table, count] of Object.entries(immutableBootstrapRows))
    assert(Number.isSafeInteger(count) && count > 0, `immutable bootstrap ${table} must be populated`);
  for (const [kind, count] of Object.entries(mutableIdentityMemoryRows))
    assert(Number.isSafeInteger(count) && count > 0, `${kind} identity memory must be populated`);
  return { clearedRows, retainedRows, immutableBootstrapRows, mutableIdentityMemoryRows };
}

// Called only after the owned browser/page is retired. The final readback is
// separate from the immediate post-projection check so late effects cannot
// inherit an earlier success fact.
async function assertFullResetTerminal({ instructor, seen, serverWitness, ledger,
  snapshot, externalSnapshot, after, outsideAfter, unexpectedApiPaths, tokenA }) {
  assert.equal(instructor.isClosed(), true, 'Browser page must retire before final proof');
  assert.equal(ledger.length, 0, 'Full Reset must not invoke a provider');
  assert.deepEqual(seen.mutations, [`POST ${POST_PATH}`], 'Unexpected or replayed browser mutation');
  assert.equal(seen.posts, 1);
  assert.deepEqual(seen.paths, [POST_PATH]);
  assert.equal(seen.body.length, 1);
  assert.equal(seen.body[0].bearer, `Bearer ${tokenA}`);
  assert.deepEqual(seen.body[0].value, { confirm: TOKEN });
  assert.deepEqual(unexpectedApiPaths, []);
  const finalServer = serverWitness.snapshot();
  assert.equal(finalServer.requests, 1);
  assert.equal(finalServer.responses, 1);
  assert.equal(finalServer.finished, 1);
  assert.equal(finalServer.invalid, false);
  assert(validServerBody(finalServer.status, finalServer.body));
  assert.deepEqual(await snapshot(), after, 'Late CTF/identity state drift');
  assert.deepEqual(await externalSnapshot(), outsideAfter, 'Late external owner/sibling state drift');
  return finalServer;
}

function validServerBody(status, body) {
  if (status === 200) return body && !Array.isArray(body) &&
    Object.keys(body).sort().join(',') === 'message' && body.message === 'CTF reset successfully';
  if (status === 202) return body && !Array.isArray(body) &&
    Object.keys(body).sort().join(',') === 'message,operationId,pending,success' &&
    body.success === false && body.pending === true && UUID.test(body.operationId) &&
    body.message === 'CTF operation is pending. No completion is being reported.';
  return false;
}

// Install BEFORE the canonical router. Observe the real response without
// changing its bytes, status, callbacks, or delivery. Never retain headers.
function createFullResetServerWitness() {
  const state = { requests: 0, responses: 0, finished: 0, status: null, body: null, invalid: false };
  const middleware = (req, res, next) => {
    if (req.method !== 'POST' || req.path !== POST_PATH) return next();
    state.requests++;
    const original = res.json;
    res.json = function observedJson(body) {
      state.responses++;
      state.status = res.statusCode;
      state.invalid ||= !validServerBody(res.statusCode, body);
      if (!state.invalid) state.body = structuredClone(body);
      return original.call(this, body);
    };
    res.once('finish', () => { state.finished++; });
    next();
  };
  return { middleware, snapshot: () => structuredClone(state) };
}

function createFullResetResponseLoss({ session, origin }) {
  assert(session?.send && session?.on && session?.off);
  const observations = { paused: 0, failed: 0, continued: 0 };
  const tasks = new Set();
  let active = false, reserved = false, failure = null;
  const listener = event => {
    const task = (async () => {
      const url = new URL(event.request.url);
      const match = active && url.origin === origin && url.pathname === POST_PATH &&
        event.request.method === 'POST' && event.responseStatusCode !== undefined;
      if (match && !reserved) {
        reserved = true;
        assert([200, 202].includes(event.responseStatusCode));
        observations.paused++;
        await session.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        observations.failed++;
        return;
      }
      observations.continued++;
      await session.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => {
      failure = error;
      await session.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    tasks.add(task); void task.finally(() => tasks.delete(task));
  };
  return {
    observations,
    async start() {
      assert(!active); active = true; session.on('Fetch.requestPaused', listener);
      try { await session.send('Fetch.enable', { patterns: [{ urlPattern: origin + POST_PATH, requestStage: 'Response' }] }); }
      catch (error) { active = false; session.off('Fetch.requestPaused', listener); await session.detach?.(); throw error; }
    },
    async stop() {
      active = false;
      try { await session.send('Fetch.disable'); await Promise.all([...tasks]); }
      finally { session.off('Fetch.requestPaused', listener); await session.detach?.(); }
      if (failure) throw failure;
    },
  };
}

function assertFullResetReceipt(r) {
  exactKeys(r, ['version', 'profile', 'modelCalls', 'judgeCalls', 'actorId', 'sessionId',
    'path', 'dialogAbaEventsObserved', 'requestCounts', 'responseStage', 'serverResponse', 'operation', 'pre', 'facts', 'excluded',
    'unexpectedApiPaths', 'stage']);
  assert.equal(r.version, 2); assert.equal(r.profile, 'ctf-full-reset-q05');
  assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0);
  assert.match(r.actorId, DECIMAL); assert.match(r.sessionId, DECIMAL);
  assert.equal(r.path, POST_PATH);
  assert.equal(r.dialogAbaEventsObserved, 2);
  exactKeys(r.requestCounts, ['wrongToken', 'cancel', 'dialogAba', 'browserPost', 'serverPost',
    'browserFailed', 'browserFinished', 'serverFinished']);
  assert.deepEqual(r.requestCounts, { wrongToken: 0, cancel: 0, dialogAba: 0,
    browserPost: 1, serverPost: 1, browserFailed: 1, browserFinished: 0, serverFinished: 1 });
  assert.deepEqual(r.responseStage, { paused: 1, failed: 1, continued: 0 });
  exactKeys(r.serverResponse, ['status', 'body', 'lossPhase']);
  assert(validServerBody(r.serverResponse.status, r.serverResponse.body));
  assert.equal(r.serverResponse.lossPhase, 'after-real-http-response-before-browser-consumption');
  exactKeys(r.operation, ['operationId', 'sequence', 'removedParticipants', 'sameIdHarnessGets']);
  assert.match(r.operation.operationId, UUID); assert.match(r.operation.sequence, DECIMAL);
  assert(Number.isSafeInteger(r.operation.removedParticipants) && r.operation.removedParticipants > 0);
  assert(Number.isSafeInteger(r.operation.sameIdHarnessGets) && r.operation.sameIdHarnessGets >= 0);
  if (r.serverResponse.status === 202) {
    assert.equal(r.serverResponse.body.operationId, r.operation.operationId);
    assert(r.operation.sameIdHarnessGets >= 1);
  } else assert.equal(r.operation.sameIdHarnessGets, 0);
  exactKeys(r.pre, ['clearedRows', 'retainedRows', 'immutableBootstrapRows', 'mutableIdentityMemoryRows']);
  exactKeys(r.pre.clearedRows, CLEARED);
  exactKeys(r.pre.retainedRows, RETAINED);
  exactKeys(r.pre.immutableBootstrapRows, IMMUTABLE_BOOTSTRAP);
  exactKeys(r.pre.mutableIdentityMemoryRows, ['technique', 'payload']);
  for (const count of Object.values(r.pre.clearedRows))
    assert(Number.isSafeInteger(count) && count > 0);
  for (const count of Object.values(r.pre.retainedRows))
    assert(Number.isSafeInteger(count) && count > 0);
  for (const count of Object.values(r.pre.immutableBootstrapRows))
    assert(Number.isSafeInteger(count) && count > 0);
  for (const count of Object.values(r.pre.mutableIdentityMemoryRows))
    assert(Number.isSafeInteger(count) && count > 0);
  assert.equal(r.pre.clearedRows.ctf_participants, r.operation.removedParticipants);
  exactKeys(r.facts, FACTS);
  for (const key of FACTS) assert.equal(r.facts[key], true, key);
  assert.deepEqual(r.excluded, ['browser-acknowledged-success', 'browser-operation-id-recovery',
    'ctf-sibling-preservation', 'ban-deletion', 'judgment-deletion', 'immutable-evidence-deletion',
    'model-grading', 'full-Q05-denominator']);
  assert.deepEqual(r.unexpectedApiPaths, []); assert.equal(r.stage, 'complete');
  return true;
}

async function runFullResetRenderedFacet({ i, c, origin, instructor, action, click, pointer,
  mounted, admin, adapter, request, serverWitness, externalSnapshot, ledger,
  receiptPath, runtimeDirectory, unexpectedApiPaths }) {
  assert.equal(path.resolve(receiptPath), path.join(fs.realpathSync(runtimeDirectory), 'ctf-full-reset-q05-result.json'));
  assert.equal(typeof externalSnapshot, 'function');
  assert.equal(typeof serverWitness?.snapshot, 'function');
  const r = { version: 2, profile: 'ctf-full-reset-q05', modelCalls: 0, judgeCalls: 0,
    actorId: null, sessionId: null, path: POST_PATH, dialogAbaEventsObserved: 0,
    requestCounts: { wrongToken: 0, cancel: 0, dialogAba: 0, browserPost: 0,
      serverPost: 0, browserFailed: 0, browserFinished: 0, serverFinished: 0 },
    responseStage: null, serverResponse: null, operation: null, pre: null, facts: {},
    excluded: ['browser-acknowledged-success', 'browser-operation-id-recovery',
      'ctf-sibling-preservation', 'ban-deletion', 'judgment-deletion', 'immutable-evidence-deletion',
      'model-grading', 'full-Q05-denominator'], unexpectedApiPaths: [], stage: 'start' };
  const save = () => fs.writeFileSync(receiptPath, JSON.stringify(r, null, 2), { mode: 0o600 });
  const step = name => { assert.equal(ledger.length, 0); r.stage = name; save(); };
  save();
  const tokenA = mounted.adminToken, tokenB = admin.headers.authorization.slice(7);
  assert(tokenA && tokenB && tokenA !== tokenB);
  const authority = await adapter.validateSession(tokenA);
  assert(authority?.user?.id > 0 && authority?.session?.id > 0);
  assert.notEqual(String(authority.user.id), String(admin.user.id));
  r.actorId = String(authority.user.id); r.sessionId = String(authority.session.id);
  const rows = async (pool, sql, values = []) => (await pool.query(sql, values)).rows;
  const snapshot = async () => {
    const cleared = {};
    for (const table of CLEARED) cleared[table] = await rows(c.runtime, `SELECT to_jsonb(t)::text AS value FROM ctf.${table} t ORDER BY id`);
    const retained = {};
    for (const table of RETAINED) {
      const order = table === 'ctf_config' ? 'key' : table === 'ctf_stage_teaching_content' ? 'stage_id' :
        table === 'ctf_judgments' ? 'run_id' : 'id';
      retained[table] = await rows(c.runtime, `SELECT to_jsonb(t)::text AS value FROM ctf.${table} t ORDER BY ${order}`);
    }
    const immutableBootstrap = {};
    for (const [name, order] of Object.entries({ sessions: 'operation_id',
      pages: 'operation_id,table_name,page_number', imports: 'operation_id,table_name,page_number' }))
      immutableBootstrap[name] = await rows(i.migration,
        `SELECT to_jsonb(t)::text AS value FROM identity.ctf_bootstrap_${name} t ORDER BY ${order}`);
    const adaptiveMemory = {};
    for (const kind of ['technique', 'payload']) adaptiveMemory[kind] = await rows(i.migration,
      'SELECT to_jsonb(t)::text AS value FROM identity.ctf_adaptive_memory t WHERE kind=$1 ORDER BY memory_id', [kind]);
    return { cleared, retained, immutableBootstrap, adaptiveMemory,
      decisions: await rows(i.migration, 'SELECT to_jsonb(t)::text AS value FROM identity.ctf_decisions t ORDER BY sequence'),
      outbox: await rows(i.migration, 'SELECT sequence::text,operation_id::text,kind,actor_id::text,session_id::text,state,canonical_command,canonical_result,command_hash,result_hash FROM identity.ctf_outbox ORDER BY sequence'),
      bindings: await rows(i.migration, 'SELECT owner_id::text,active,participant_id::text FROM identity.ctf_participant_bindings ORDER BY owner_id') };
  };
  const before = structuredClone(await snapshot()), outsideBefore = structuredClone(await externalSnapshot());
  assert(outsideBefore?.platform && outsideBefore?.workshopSibling);
  assert(Object.keys(outsideBefore.platform).length && Object.keys(outsideBefore.workshopSibling).length);
  r.pre = assertNonvacuousResetSeed(before);
  const seen = { posts: 0, failed: 0, finished: 0, body: [], paths: [], mutations: [] };
  const onRequest = req => {
    const url = new URL(req.url());
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method()) && url.pathname.startsWith('/api/ctf/'))
      seen.mutations.push(`${req.method()} ${url.origin === origin ? url.pathname + url.search : 'wrong-origin'}`);
    if (req.method() === 'POST' && url.pathname === POST_PATH) {
      seen.posts++; seen.paths.push(url.origin === origin ? url.pathname + url.search : 'wrong-origin');
      let body = null;
      try { body = JSON.parse(req.postData() || ''); } catch { /* Exact body assertion fails. */ }
      seen.body.push({ value: body, bearer: req.headers().authorization || null });
    }
  };
  const onFailed = req => { if (req.method() === 'POST' && new URL(req.url()).pathname === POST_PATH) seen.failed++; };
  const onFinished = req => { if (req.method() === 'POST' && new URL(req.url()).pathname === POST_PATH) seen.finished++; };
  instructor.on('request', onRequest); instructor.on('requestfailed', onFailed); instructor.on('requestfinished', onFinished);
  const visibleDialog = async () => {
    const ready = await action(() => instructor.waitForFunction(() => {
      const matches = [...document.querySelectorAll('[role="alertdialog"]')].filter(d =>
        d.querySelector('h2')?.textContent.trim() === 'Reset the entire CTF?');
      return matches.length === 1 && matches[0].textContent.includes('participants') &&
        [...matches[0].querySelectorAll('button')].filter(b => b.textContent.trim() === 'Confirm reset' && !b.disabled).length === 1;
    }, { polling: 100, timeout: 15000 })); await ready.dispose();
  };
  const noDialog = async () => {
    const gone = await action(() => instructor.waitForFunction(() =>
      ![...document.querySelectorAll('[role="alertdialog"]')].some(d =>
        d.querySelector('h2')?.textContent.trim() === 'Reset the entire CTF?'),
    { polling: 100, timeout: 15000 })); await gone.dispose();
  };
  const typed = async value => {
    const h = await action(() => instructor.$('input[placeholder="RESET_CTF_CONFIRM"]'));
    try {
      assert(h?.asElement()); await pointer(instructor, h, action);
      const beforeValue = await h.evaluate(e => e.value);
      await action(() => h.press('A', { commands: ['SelectAll'], text: '' }));
      assert.deepEqual(await h.evaluate(e => [e.selectionStart, e.selectionEnd]), [0, beforeValue.length]);
      await action(() => h.press('Backspace'));
      assert.equal(await h.evaluate(e => e.value), '');
      await action(() => h.type(value)); assert.equal(await h.evaluate(e => e.value), value);
    } finally { await h?.dispose(); }
  };
  const serverCount = () => serverWitness.snapshot().requests;
  const noEffect = async () => assert.deepEqual(await snapshot(), before);
  let other, loss, completed = false;
  try {
    step('wrong-token');
    await action(() => instructor.goto(origin + '/admin/ctf-management', { waitUntil: 'domcontentloaded' }));
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Danger Zone');
    await typed('WRONG_CTF_CONFIRM');
    assert.equal(await action(() => instructor.evaluate(() => [...document.querySelectorAll('button')]
      .filter(b => b.textContent.trim() === 'Full CTF Reset' && b.disabled).length)), 1);
    r.requestCounts.wrongToken = seen.posts;
    r.facts.wrongTokenNoPost = r.requestCounts.wrongToken === 0 &&
      seen.mutations.length === 0 && serverCount() === 0;
    assert(r.facts.wrongTokenNoPost); save();
    step('cancel'); await typed(TOKEN); await click(instructor, 'button', 'Full CTF Reset');
    await visibleDialog(); await click(instructor, '[role="alertdialog"] button', 'Cancel'); await noDialog();
    r.requestCounts.cancel = seen.posts;
    r.facts.cancelNoPost = r.requestCounts.cancel === 0 &&
      seen.mutations.length === 0 && serverCount() === 0;
    await noEffect(); r.facts.cancelNoEffect = true;
    assert(r.facts.cancelNoPost); save();
    step('dialog-aba'); await click(instructor, 'button', 'Full CTF Reset'); await visibleDialog();
    other = await action(() => instructor.browserContext().newPage());
    await action(() => other.setRequestInterception(true));
    other.on('request', req => { const url = new URL(req.url());
      return url.origin === origin || ['about:', 'data:', 'blob:'].includes(url.protocol) ? req.continue() : req.abort(); });
    await action(() => other.goto(origin + '/api/ctf/config', { waitUntil: 'domcontentloaded' }));
    await action(() => instructor.evaluate(() => { window.__ctfFullResetStorageEvents = 0;
      window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfFullResetStorageEvents++; }); }));
    await action(() => other.evaluate(([b, a]) => { localStorage.setItem('token', b); localStorage.setItem('token', a); }, [tokenB, tokenA]));
    const events = await action(() => instructor.waitForFunction(() => window.__ctfFullResetStorageEvents >= 2,
      { polling: 100, timeout: 15000 })); await events.dispose();
    r.dialogAbaEventsObserved = await action(() => instructor.evaluate(() => window.__ctfFullResetStorageEvents));
    assert.equal(r.dialogAbaEventsObserved, 2);
    await noDialog(); await action(() => other.close()); other = null;
    r.requestCounts.dialogAba = seen.posts;
    r.facts.dialogAbaNoPost = r.requestCounts.dialogAba === 0 &&
      seen.mutations.length === 0 && serverCount() === 0;
    await noEffect(); r.facts.dialogAbaNoEffect = true;
    assert(r.facts.dialogAbaNoPost); save();
    step('confirm-lost-response');
    await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Danger Zone');
    await typed(TOKEN); await click(instructor, 'button', 'Full CTF Reset'); await visibleDialog();
    loss = createFullResetResponseLoss({ session: await action(() => instructor.createCDPSession()), origin });
    await loss.start();
    await click(instructor, '[role="alertdialog"] button', 'Confirm reset');
    const parked = await action(() => instructor.waitForFunction(() => {
      const notices = [...document.querySelectorAll('[role="status"]')].filter(n =>
        n.textContent.includes('Outcome unknown because the response was lost. Do not resubmit automatically.'));
      return notices.length === 1 &&
        ![...notices[0].querySelectorAll('button')].some(button => button.textContent.trim() === 'Check status') &&
        [...notices[0].querySelectorAll('button')].some(button => button.textContent.trim() === 'Dismiss pending result');
    }, { polling: 100, timeout: 15000 })); await parked.dispose();
    r.facts.unknownUiNoReference = true;
    assert.deepEqual(loss.observations, { paused: 1, failed: 1, continued: 0 });
    const server = serverWitness.snapshot();
    assert.equal(server.requests, 1); assert.equal(server.responses, 1); assert.equal(server.finished, 1);
    assert.equal(server.invalid, false); assert(validServerBody(server.status, server.body));
    r.serverResponse = { status: server.status, body: server.body,
      lossPhase: 'after-real-http-response-before-browser-consumption' };
    const deadline = Date.now() + 15000;
    let outbox;
    for (;;) {
      const result = await rows(i.migration, "SELECT sequence::text,operation_id::text,actor_id::text,session_id::text,kind,state,canonical_command,canonical_result,command_hash,result_hash FROM identity.ctf_outbox WHERE kind='global_reset' AND sequence>$1 ORDER BY sequence", [before.outbox.at(-1)?.sequence || '0']);
      if (result.length === 1 && result[0].state === 'applied') { outbox = result[0]; break; }
      if (Date.now() >= deadline) throw Error('Full CTF Reset projection deadline');
      await sleep(50);
    }
    assert.equal(outbox.actor_id, r.actorId); assert.equal(outbox.session_id, r.sessionId);
    assert.equal(crypto.createHash('sha256').update(outbox.canonical_command).digest('hex'), outbox.command_hash);
    const command = JSON.parse(outbox.canonical_command);
    assert.equal(command.kind, 'global_reset'); assert.equal(command.operationId, outbox.operation_id);
    assert.deepEqual(command.body, {}); assert.equal(command.actorId, r.actorId);
    assert.equal(command.scope.ownerId, null); assert.equal(command.scope.stageId, null);
    const projection = await rows(c.runtime, 'SELECT sequence::text,operation_id::text,kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1', [outbox.operation_id]);
    assert.deepEqual(projection, [{ sequence: outbox.sequence, operation_id: outbox.operation_id,
      kind: outbox.kind, command_hash: outbox.command_hash,
      canonical_result: outbox.canonical_result, result_hash: outbox.result_hash }]);
    const result = JSON.parse(outbox.canonical_result);
    assert.equal(crypto.createHash('sha256').update(outbox.canonical_result).digest('hex'), outbox.result_hash);
    assert.equal(result.data?.removedParticipants, r.pre.clearedRows.ctf_participants);
    r.operation = { operationId: outbox.operation_id, sequence: outbox.sequence,
      removedParticipants: result.data.removedParticipants, sameIdHarnessGets: 0 };
    if (server.status === 202) {
      assert.equal(server.body.operationId, outbox.operation_id);
      const sameId = await request('GET', `/operations/${outbox.operation_id}`,
        { headers: { authorization: `Bearer ${tokenA}` } });
      assert.equal(sameId.status, 200); assert.deepEqual(sameId.body, { message: 'CTF reset successfully' });
      r.operation.sameIdHarnessGets = 1; // Harness-only: browser received no reference.
    }
    r.facts.canonicalOperationApplied = true;
    r.facts.removedCountMatches = true;
    const after = structuredClone(await snapshot()), outsideAfter = structuredClone(await externalSnapshot());
    assert.equal(ledger.length, 0, 'Full Reset dispatch must not invoke a provider');
    r.facts.mutableCtfCleared = CLEARED.every(table => after.cleared[table].length === 0);
    r.facts.mutableIdentityMemoryCleared = ['technique', 'payload'].every(kind =>
      after.adaptiveMemory[kind].length === 0);
    r.facts.retainedCtfUnchanged = RETAINED.every(table => stringify(after.retained[table]) === stringify(before.retained[table]));
    r.facts.historicalIdentityEvidencePreserved = IMMUTABLE_BOOTSTRAP.every(name =>
      stringify(after.immutableBootstrap[name]) === stringify(before.immutableBootstrap[name])) &&
      stringify(after.decisions) === stringify(before.decisions) &&
      stringify(after.outbox.slice(0, before.outbox.length)) === stringify(before.outbox) &&
      before.bindings.length === after.bindings.length &&
      before.bindings.every(row => after.bindings.some(current => current.owner_id === row.owner_id &&
        current.participant_id === row.participant_id && current.active === false));
    r.facts.platformAndWorkshopSiblingPreserved = stringify(outsideAfter) === stringify(outsideBefore);
    assert(r.facts.mutableCtfCleared && r.facts.mutableIdentityMemoryCleared &&
      r.facts.retainedCtfUnchanged &&
      r.facts.historicalIdentityEvidencePreserved && r.facts.platformAndWorkshopSiblingPreserved);
    r.facts.capturedAuthorityAndBody = seen.body.length === 1 && seen.body[0].bearer === `Bearer ${tokenA}` &&
      stringify(seen.body[0].value) === stringify({ confirm: TOKEN });
    assert(r.facts.capturedAuthorityAndBody);
    r.facts.onePhysicalPost = seen.posts === 1 &&
      stringify(seen.mutations) === stringify([`POST ${POST_PATH}`]) &&
      seen.paths.length === 1 && seen.paths[0] === POST_PATH;
    assert(r.facts.onePhysicalPost); save();
    const lossObservation = { ...loss.observations };
    await loss.stop(); loss = null;
    assert.deepEqual(lossObservation, { paused: 1, failed: 1, continued: 0 });
    r.responseStage = lossObservation;
    completed = true;
    return async () => {
      try {
        const finalServer = await assertFullResetTerminal({ instructor, seen, serverWitness,
          ledger, snapshot, externalSnapshot, after, outsideAfter, unexpectedApiPaths, tokenA });
        r.modelCalls = ledger.length; r.judgeCalls = ledger.length;
        r.requestCounts = { wrongToken: r.requestCounts.wrongToken, cancel: r.requestCounts.cancel,
          dialogAba: r.requestCounts.dialogAba,
          browserPost: seen.posts, serverPost: finalServer.requests,
          browserFailed: seen.failed, browserFinished: seen.finished, serverFinished: finalServer.finished };
        r.facts.onePhysicalPost = seen.posts === 1 &&
          stringify(seen.mutations) === stringify([`POST ${POST_PATH}`]) &&
          seen.paths.length === 1 && seen.paths[0] === POST_PATH;
        r.facts.capturedAuthorityAndBody = seen.body.length === 1 && seen.body[0].bearer === `Bearer ${tokenA}` &&
          stringify(seen.body[0].value) === stringify({ confirm: TOKEN });
        r.facts.noAutomaticRetry = seen.posts === 1 && finalServer.requests === 1;
        r.unexpectedApiPaths = [...unexpectedApiPaths]; r.stage = 'complete';
        assert.deepEqual(lossObservation, { paused: 1, failed: 1, continued: 0 });
        assertFullResetReceipt(r); save();
      } catch (error) { r.stage = 'late-request-failed'; save(); throw error; }
      finally { instructor.off('request', onRequest); instructor.off('requestfailed', onFailed);
        instructor.off('requestfinished', onFinished); seen.body.length = 0; }
    };
  } finally {
    if (other) await other.close();
    if (!completed) { if (loss) await loss.stop(); instructor.off('request', onRequest);
      instructor.off('requestfailed', onFailed); instructor.off('requestfinished', onFinished);
      seen.body.length = 0; r.unexpectedApiPaths = [...unexpectedApiPaths]; save(); }
  }
}

module.exports = { runFullResetRenderedFacet, assertFullResetReceipt,
  createFullResetServerWitness, createFullResetResponseLoss, validServerBody,
  assertNonvacuousResetSeed, assertFullResetTerminal,
  CLEARED, RETAINED, IMMUTABLE_BOOTSTRAP, POST_PATH, TOKEN };
