'use strict';
// Separate controlled Q05 facet. It does not amend the original 55 content facts.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const TARGET = 2;
const SIBLING = 3;
const PUT_PATH = `/api/ctf/admin/stages/${TARGET}`;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const FACTS = Object.freeze(['cancelNoPut', 'cancelNoEffect', 'dialogAbaNoPut',
  'dialogAbaNoEffect', 'confirmedOnePhysicalPut', 'capturedBearerAndBody',
  'canonicalProjectionApplied', 'targetAvailabilityChanged',
  'nonAvailabilityFieldsUnchanged', 'siblingPreserved', 'restoreContentEquivalent',
  'noModelOrJudge']);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
const withoutAvailability = row => Object.fromEntries(Object.entries(row).filter(([key]) => key !== 'is_active'));

function exactPhysicalStageActivePut(seen, bearer, nextActive) {
  return seen.puts === 1 && seen.paths.length === 1 && seen.paths[0] === PUT_PATH &&
    seen.physical.length === 1 && seen.physical[0].bearer === bearer &&
    seen.physical[0].body && !Array.isArray(seen.physical[0].body) &&
    Object.keys(seen.physical[0].body).length === 1 &&
    seen.physical[0].body.is_active === nextActive;
}
async function validatedStageActiveBearer(token, adapter, actorId, sessionId) {
  assert.equal(typeof token, 'string');
  assert(token.length > 0 && token.length <= 8192);
  const current = await adapter.validateSession(token);
  assert.equal(String(current?.user?.id), String(actorId));
  assert.equal(String(current?.session?.id), String(sessionId));
  return `Bearer ${token}`;
}
function findStageSwitch(id, scope = document) {
  const rows = [...scope.querySelectorAll('tbody tr')].filter(row =>
    row.children[0]?.textContent.trim() === String(id) &&
    row.children[1]?.textContent.trim().length > 0);
  if (rows.length !== 1) return null;
  const switches = [...rows[0].querySelectorAll('button[role="switch"]')].filter(item =>
    !item.disabled && ['true', 'false'].includes(item.getAttribute('aria-checked')));
  return switches.length === 1 ? switches[0] : null;
}
function assertOperation(value) {
  exactKeys(value, ['originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId',
    'sequence', 'browserAckOperationId', 'ackMessage']);
  assert([200, 202].includes(value.originalStatus));
  assert.equal(value.resolvedStatus, 200);
  assert(Number.isSafeInteger(value.sameIdGets) && value.sameIdGets >=
    (value.originalStatus === 202 ? 1 : 0));
  assert.match(value.operationId, UUID);
  assert.match(value.sequence, DECIMAL);
  if (value.originalStatus === 202) {
    assert.equal(value.browserAckOperationId, value.operationId);
    assert.equal(value.ackMessage, null);
  } else {
    assert.equal(value.sameIdGets, 0);
    assert.equal(value.browserAckOperationId, null);
    assert.equal(value.ackMessage, 'Stage updated');
  }
}
function assertStageActiveReceipt(r) {
  exactKeys(r, ['version', 'profile', 'targetStageId', 'siblingStageId', 'mountedActorId',
    'mountedSessionId', 'originalActive', 'confirmedActive', 'observedPath',
    'browserPuts', 'fixtureRestorePuts', 'dialogTimeAba', 'confirmed', 'restore',
    'facts', 'excluded', 'unexpectedApiPaths', 'stage', 'modelCalls', 'judgeCalls']);
  assert.equal(r.version, 1); assert.equal(r.profile, 'ctf-stage-active-q05');
  assert.equal(r.targetStageId, TARGET); assert.equal(r.siblingStageId, SIBLING);
  assert.match(r.mountedActorId, DECIMAL); assert.match(r.mountedSessionId, DECIMAL);
  assert.equal(r.originalActive, 1); assert.equal(r.confirmedActive, 0);
  assert.equal(r.observedPath, PUT_PATH); assert.equal(r.browserPuts, 1);
  assert.equal(r.fixtureRestorePuts, 1);
  assert.deepEqual(r.dialogTimeAba, { eventsObserved: 2, noPut: true });
  assertOperation(r.confirmed);
  exactKeys(r.restore, ['scope', 'originalStatus', 'resolvedStatus', 'sameIdGets',
    'operationId', 'sequence', 'browserAckOperationId', 'ackMessage']);
  assert.equal(r.restore.scope, 'content-equivalence-only');
  assertOperation(Object.fromEntries(Object.entries(r.restore).filter(([key]) => key !== 'scope')));
  assert.notEqual(r.confirmed.operationId, r.restore.operationId);
  assert(BigInt(r.restore.sequence) > BigInt(r.confirmed.sequence));
  exactKeys(r.facts, FACTS);
  for (const name of FACTS) assert.equal(r.facts[name], true, name);
  assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0);
  assert.deepEqual(r.excluded, ['byte-identical-undo', 'provenance-rollback', 'model-qualification']);
  assert.deepEqual(r.unexpectedApiPaths, []);
  assert.equal(r.stage, 'complete');
  return true;
}

async function finishStageActiveOwnedPhase({ other, instructor, onRequest, onResponse,
  seen, receipt, save, unexpectedApiPaths, completed, primary }) {
  const cleanupErrors = [];
  if (other) {
    try { await other.close(); } catch (error) { cleanupErrors.push(error); }
  }
  // A close error converts a prospective successful return into failure. The
  // owner still must drop listeners and the captured browser bearer.
  if (!completed || cleanupErrors.length) {
    try { instructor.off('request', onRequest); } catch (error) { cleanupErrors.push(error); }
    try { instructor.off('response', onResponse); } catch (error) { cleanupErrors.push(error); }
    try {
      seen.physical.length = 0;
      receipt.browserPuts = seen.puts;
      receipt.unexpectedApiPaths = [...unexpectedApiPaths];
      if (completed) receipt.stage = 'cleanup-failed';
    } catch (error) { cleanupErrors.push(error); }
    try { save(); } catch (error) { cleanupErrors.push(error); }
  }
  if (cleanupErrors.length) {
    throw new AggregateError(primary ? [primary, ...cleanupErrors] : cleanupErrors,
      'Stage-active owned cleanup failed', { cause: primary });
  }
}
async function recoverStageActiveRestore({ request, admin, operationId,
  now = Date.now, pause = sleep }) {
  assert.match(operationId, UUID);
  const started = now();
  for (let reads = 1; reads <= 32; reads++) {
    if (now() - started >= 30000) throw Error('Stage-active restore 30-second deadline');
    const recovered = await request('GET', `/operations/${operationId}`, admin);
    if (recovered.status === 200) {
      assert.deepEqual(recovered.body, { message: 'Stage updated' });
      return reads;
    }
    assert.equal(recovered.status, 202);
    if (now() - started >= 30000) throw Error('Stage-active restore 30-second deadline');
    if (reads === 32) throw Error('Stage-active restore exhausted 32 same-ID GETs');
    await pause(100);
  }
  throw Error('Stage-active restore bounded loop failed');
}
function preserveStageActiveFailure(primary, receipt, save) {
  receipt.stage = 'late-request-failed';
  try { save(); } catch (saveError) {
    throw new AggregateError([primary, saveError], 'Stage-active failure receipt could not be saved',
      { cause: primary });
  }
  throw primary;
}

async function runStageActiveRenderedFacet({ i, c, origin, instructor, action, click, pointer,
  admin, mounted, adapter, request, ledger, receiptPath, unexpectedApiPaths, runtimeDirectory }) {
  assert.equal(path.resolve(receiptPath), path.join(fs.realpathSync(runtimeDirectory), 'ctf-stage-active-q05-result.json'));
  const r = { version: 1, profile: 'ctf-stage-active-q05', targetStageId: TARGET,
    siblingStageId: SIBLING, mountedActorId: null, mountedSessionId: null,
    originalActive: null, confirmedActive: 0, observedPath: null,
    browserPuts: 0, fixtureRestorePuts: 0,
    dialogTimeAba: { eventsObserved: 0, noPut: false }, confirmed: null, restore: null,
    facts: {}, excluded: ['byte-identical-undo', 'provenance-rollback', 'model-qualification'],
    unexpectedApiPaths: [], stage: 'start', modelCalls: 0, judgeCalls: 0 };
  const save = () => fs.writeFileSync(receiptPath, JSON.stringify(r, null, 2), { mode: 0o600 });
  save();
  const tokenA = mounted.adminToken, tokenB = admin.headers.authorization.slice(7);
  assert.notEqual(tokenA, tokenB);
  const mountedAuthority = await adapter.validateSession(tokenA);
  assert(mountedAuthority?.user?.id > 0 && mountedAuthority?.session?.id > 0);
  assert.notEqual(String(mountedAuthority.user.id), String(admin.user.id));
  r.mountedActorId = String(mountedAuthority.user.id);
  r.mountedSessionId = String(mountedAuthority.session.id);
  assert.equal((await request('GET', '/admin/stages', { headers: { authorization: `Bearer ${tokenA}` } })).status, 200);
  const stageRow = async id => {
    const row = (await c.runtime.query('SELECT to_jsonb(s)::text AS stage FROM ctf.ctf_stages s WHERE id=$1', [id])).rows[0];
    assert(row?.stage); return JSON.parse(row.stage);
  };
  const targetBefore = await stageRow(TARGET), siblingBefore = await stageRow(SIBLING);
  assert.equal(targetBefore.stage_number, TARGET);
  assert.equal(siblingBefore.stage_number, SIBLING);
  assert.equal(targetBefore.is_active, 1, 'Stage-active facet needs a genuinely active seeded target');
  r.originalActive = targetBefore.is_active;
  const sequence = async () => (await i.migration.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const rowsAfter = after => i.migration.query("SELECT sequence::text,operation_id::text,actor_id::text,session_id::text,kind,state,canonical_command,command_hash,canonical_result,result_hash FROM identity.ctf_outbox WHERE sequence>$1 AND kind='catalog_mutation' AND canonical_command::jsonb->'scope'->>'stageId'=$2 ORDER BY sequence", [after, String(TARGET)]);
  const initialSequence = await sequence();
  const verifyOutbox = async (after, active, actorId, sessionId) => {
    const deadline = Date.now() + 10000;
    let values;
    for (;;) {
      values = (await rowsAfter(after)).rows;
      if (values.length === 1 && values[0].state === 'applied') break;
      if (Date.now() >= deadline) throw Error('Stage-active projection deadline');
      await sleep(50);
    }
    const row = values[0];
    assert.equal(row.actor_id, String(actorId)); assert.equal(row.session_id, String(sessionId));
    assert.equal(crypto.createHash('sha256').update(row.canonical_command).digest('hex'), row.command_hash);
    const command = JSON.parse(row.canonical_command);
    assert.equal(command.operationId, row.operation_id);
    assert.equal(command.kind, 'catalog_mutation'); assert.equal(command.scope.stageId, String(TARGET));
    assert.equal(command.body.action, 'update'); assert.deepEqual(command.body.fields, { is_active: active });
    const projection = (await c.runtime.query('SELECT sequence::text,operation_id::text,kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1', [row.operation_id])).rows[0];
    assert.deepEqual(projection, { sequence: row.sequence, operation_id: row.operation_id, kind: row.kind,
      command_hash: row.command_hash, canonical_result: row.canonical_result, result_hash: row.result_hash });
    return row;
  };
  const seen = { puts: 0, paths: [], physical: [], gets: [] };
  const operationResponses = [];
  const onRequest = req => {
    const url = new URL(req.url());
    if (req.method() === 'PUT' && url.pathname.startsWith('/api/ctf/admin/')) {
      seen.paths.push(url.pathname);
      if (url.origin === origin && url.pathname === PUT_PATH) {
        seen.puts++;
        let body = null;
        try { body = JSON.parse(req.postData() || ''); } catch { /* Exact request check rejects malformed JSON. */ }
        seen.physical.push({ body, bearer: req.headers().authorization || null });
      }
    }
    if (req.method() === 'GET' && url.origin === origin && /^\/api\/ctf\/operations\//.test(url.pathname)) seen.gets.push(url.pathname);
  };
  const onResponse = response => {
    const url = new URL(response.url());
    if (url.origin === origin && response.request().method() === 'GET' && /^\/api\/ctf\/operations\//.test(url.pathname))
      operationResponses.push({ path: url.pathname, status: response.status(), response });
  };
  instructor.on('request', onRequest); instructor.on('response', onResponse);
  const switchHandle = async () => {
    const ready = await action(() => instructor.waitForFunction(id => {
      const rows = [...document.querySelectorAll('tbody tr')].filter(row =>
        row.children[0]?.textContent.trim() === String(id));
      return rows.length === 1 && [...rows[0].querySelectorAll('button[role="switch"]')].filter(button => !button.disabled).length === 1;
    }, { polling: 100, timeout: 15000 }, TARGET)); await ready.dispose();
    return action(() => instructor.evaluateHandle(findStageSwitch, TARGET));
  };
  const openReview = async () => {
    const h = await switchHandle();
    try { assert(h.asElement()); await pointer(instructor, h, action); } finally { await h.dispose(); }
    const ready = await action(() => instructor.waitForFunction(() =>
      [...document.querySelectorAll('[role="dialog"]')].filter(dialog =>
        dialog.querySelector('h3')?.textContent.trim() === 'Deactivate CTF stage' &&
        dialog.textContent.includes('Stored progress and attempts are not reset.') &&
        [...dialog.querySelectorAll('button')].filter(button =>
          button.textContent.trim() === 'Confirm Deactivate' && !button.disabled).length === 1).length === 1,
    { polling: 100, timeout: 15000 })); await ready.dispose();
  };
  const noDialog = async () => {
    const gone = await action(() => instructor.waitForFunction(() =>
      ![...document.querySelectorAll('[role="dialog"]')].some(dialog =>
        dialog.querySelector('h3')?.textContent.trim() === 'Deactivate CTF stage'),
    { polling: 100, timeout: 15000 })); await gone.dispose();
  };
  const browserRecovery = async operationId => {
    const operationPath = `/api/ctf/operations/${operationId}`;
    const deadline = Date.now() + 30000;
    let checks = 0;
    for (;;) {
      const observed = operationResponses.find(item => item.path === operationPath && item.status === 200);
      if (observed) {
        assert.deepEqual(await observed.response.json(), { message: 'Stage updated' });
        const reads = seen.gets.filter(item => item === operationPath).length;
        assert(reads >= 1); return reads;
      }
      if (Date.now() >= deadline) throw Error('Stage-active same-ID recovery deadline');
      const available = await action(() => instructor.evaluate(() =>
        [...document.querySelectorAll('[role="status"] button')].filter(item =>
          item.textContent.trim() === 'Check status' && !item.disabled).length === 1));
      if (available && checks < 3) { await click(instructor, '[role="status"] button', 'Check status'); checks++; }
      await sleep(100);
    }
  };
  let completed = false, other, confirmedBearer, restoredOutbox, primary;
  try {
    r.stage = 'cancel'; save();
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Levels');
    await openReview();
    await click(instructor, '[role="dialog"] button', 'Cancel'); await noDialog();
    r.facts.cancelNoPut = seen.paths.length === 0 && (await rowsAfter(initialSequence)).rows.length === 0;
    r.facts.cancelNoEffect = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.cancelNoPut && r.facts.cancelNoEffect); save();
    r.stage = 'dialog-aba'; save(); await openReview();
    other = await action(() => instructor.browserContext().newPage());
    await action(() => other.setRequestInterception(true));
    other.on('request', req => { const url = new URL(req.url());
      return url.origin === origin || ['about:', 'data:', 'blob:'].includes(url.protocol) ? req.continue() : req.abort(); });
    await action(() => other.goto(`${origin}/api/ctf/config`, { waitUntil: 'domcontentloaded' }));
    await action(() => instructor.evaluate(() => { window.__ctfStageActiveEvents = 0;
      window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfStageActiveEvents++; }); }));
    await action(() => other.evaluate(([b, a]) => { localStorage.setItem('token', b); localStorage.setItem('token', a); }, [tokenB, tokenA]));
    const observed = await action(() => instructor.waitForFunction(() =>
      (window.__ctfStageActiveEvents || 0) >= 2, { polling: 100, timeout: 15000 })); await observed.dispose();
    r.dialogTimeAba.eventsObserved = await action(() => instructor.evaluate(() => window.__ctfStageActiveEvents || 0));
    assert.equal(r.dialogTimeAba.eventsObserved, 2);
    await noDialog(); await action(() => other.close()); other = null;
    r.dialogTimeAba.noPut = seen.paths.length === 0 && (await rowsAfter(initialSequence)).rows.length === 0;
    r.facts.dialogAbaNoPut = r.dialogTimeAba.noPut;
    r.facts.dialogAbaNoEffect = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.dialogAbaNoPut && r.facts.dialogAbaNoEffect); save();
    r.stage = 'confirm'; save();
    await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Levels');
    await openReview();
    confirmedBearer = await validatedStageActiveBearer(
      await action(() => instructor.evaluate(() => localStorage.getItem('token'))),
      adapter, r.mountedActorId, r.mountedSessionId);
    const beforeConfirm = await sequence();
    const responsePromise = action(() => instructor.waitForResponse(response =>
      new URL(response.url()).origin === origin && new URL(response.url()).pathname === PUT_PATH &&
      response.request().method() === 'PUT', { timeout: 15000 }));
    await click(instructor, '[role="dialog"] button', 'Confirm Deactivate');
    const response = await responsePromise;
    assert([200, 202].includes(response.status()));
    const browserAck = await response.json();
    const outbox = await verifyOutbox(beforeConfirm, 0, r.mountedActorId, r.mountedSessionId);
    if (response.status() === 200) assert.deepEqual(browserAck, { message: 'Stage updated' });
    else { assert.equal(browserAck?.pending, true); assert.equal(browserAck.operationId, outbox.operation_id); }
    const sameIdGets = response.status() === 202 ? await browserRecovery(outbox.operation_id) : 0;
    r.confirmed = { originalStatus: response.status(), resolvedStatus: 200, sameIdGets,
      operationId: outbox.operation_id, sequence: outbox.sequence,
      browserAckOperationId: response.status() === 202 ? browserAck.operationId : null,
      ackMessage: response.status() === 200 ? browserAck.message : null };
    r.observedPath = seen.paths[0] || null;
    r.facts.confirmedOnePhysicalPut = exactPhysicalStageActivePut(seen, confirmedBearer, 0);
    r.facts.capturedBearerAndBody = r.facts.confirmedOnePhysicalPut;
    r.facts.canonicalProjectionApplied = true;
    assert(r.facts.confirmedOnePhysicalPut); save();
    const applied = await stageRow(TARGET);
    r.facts.targetAvailabilityChanged = applied.is_active === 0;
    r.facts.nonAvailabilityFieldsUnchanged = JSON.stringify(withoutAvailability(applied)) ===
      JSON.stringify(withoutAvailability(targetBefore));
    r.facts.siblingPreserved = JSON.stringify(await stageRow(SIBLING)) === JSON.stringify(siblingBefore);
    assert(r.facts.targetAvailabilityChanged && r.facts.nonAvailabilityFieldsUnchanged &&
      r.facts.siblingPreserved); save();
    r.stage = 'explicit-content-restore'; save();
    const beforeRestore = await sequence();
    const restoreResponse = await request('PUT', PUT_PATH.replace('/api/ctf', ''), admin, { is_active: 1 });
    r.fixtureRestorePuts++;
    assert([200, 202].includes(restoreResponse.status));
    restoredOutbox = await verifyOutbox(beforeRestore, 1, admin.user.id, admin.identitySession.id);
    let restoreGets = 0;
    if (restoreResponse.status === 200) assert.deepEqual(restoreResponse.body, { message: 'Stage updated' });
    else {
      assert.equal(restoreResponse.body?.pending, true);
      assert.equal(restoreResponse.body.operationId, restoredOutbox.operation_id);
      restoreGets = await recoverStageActiveRestore({ request, admin,
        operationId: restoredOutbox.operation_id });
    }
    r.restore = { scope: 'content-equivalence-only', originalStatus: restoreResponse.status,
      resolvedStatus: 200, sameIdGets: restoreGets, operationId: restoredOutbox.operation_id,
      sequence: restoredOutbox.sequence,
      browserAckOperationId: restoreResponse.status === 202 ? restoreResponse.body.operationId : null,
      ackMessage: restoreResponse.status === 200 ? restoreResponse.body.message : null };
    r.facts.restoreContentEquivalent = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.restoreContentEquivalent);
    assert.equal(JSON.stringify(await stageRow(SIBLING)), JSON.stringify(siblingBefore));
    r.facts.noModelOrJudge = ledger.length === 0;
    assert(r.facts.noModelOrJudge);
    r.browserPuts = seen.puts; r.unexpectedApiPaths = [...unexpectedApiPaths];
    r.stage = 'complete'; assertStageActiveReceipt(r); save(); completed = true;
    return async () => {
      r.browserPuts = seen.puts; r.observedPath = seen.paths[0] || null;
      r.facts.confirmedOnePhysicalPut = exactPhysicalStageActivePut(seen, confirmedBearer, 0);
      r.facts.capturedBearerAndBody = r.facts.confirmedOnePhysicalPut;
      r.facts.noModelOrJudge = ledger.length === 0;
      r.unexpectedApiPaths = [...unexpectedApiPaths];
      try {
        assertStageActiveReceipt(r);
        assert.equal(JSON.stringify(await stageRow(TARGET)), JSON.stringify(targetBefore));
        assert.equal(JSON.stringify(await stageRow(SIBLING)), JSON.stringify(siblingBefore));
        assert.equal((await rowsAfter(restoredOutbox.sequence)).rows.length, 0);
        save();
      } catch (error) { preserveStageActiveFailure(error, r, save); }
      finally { seen.physical.length = 0; instructor.off('request', onRequest); instructor.off('response', onResponse); }
    };
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    await finishStageActiveOwnedPhase({ other, instructor, onRequest, onResponse,
      seen, receipt: r, save, unexpectedApiPaths, completed, primary });
  }
}

module.exports = { runStageActiveRenderedFacet, assertStageActiveReceipt,
  exactPhysicalStageActivePut, findStageSwitch, validatedStageActiveBearer,
  finishStageActiveOwnedPhase, recoverStageActiveRestore,
  preserveStageActiveFailure, FACTS, PUT_PATH };
