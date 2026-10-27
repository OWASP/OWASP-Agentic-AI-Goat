'use strict';
// Separate, bounded Q05 facet. The ten-content receipt and its 55 projections are untouched.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const CONTENT_FIELDS = Object.freeze(['stage_name', 'stage_description', 'hints', 'teaching_objective', 'solution_content']);
const FACTS = Object.freeze(['cancelNoPut', 'cancelNoEffect', 'dialogAbaNoPut', 'dialogAbaNoEffect',
  'confirmedOnePhysicalPut', 'physicalRequestFiveFieldsAndBearer', 'fiveFieldsExact',
  'canonicalProjectionApplied', 'actorSessionBound', 'learnerMutationDenied',
  'guardianAndScoringUnchanged', 'siblingPreserved', 'adminHintsAndSolutionVisible',
  'learnerObjectiveVisible', 'learnerRawHintsAndSolutionAbsent', 'restoreContentEquivalent',
  'restorationGuardianAndScoringUnchanged']);
const POLICY_FIELDS = Object.freeze(['ai_guardian_name', 'ai_guardian_personality', 'system_prompt',
  'success_criteria', 'defense_style', 'adaptive_mode', 'level_score', 'time_bonus_seconds',
  'feedback_mode', 'max_attempts', 'is_active']);
const TARGET = 2;
const SIBLING = 3;
const PUT_PATH = `/api/ctf/admin/stages/${TARGET}/content`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
function exactPhysicalTeachingPut(requests, bearer, fields) {
  return Boolean(requests.length === 1 && requests[0].bearer === bearer &&
    requests[0].body && !Array.isArray(requests[0].body) &&
    Object.keys(requests[0].body).sort().join(',') === [...CONTENT_FIELDS].sort().join(',') &&
    CONTENT_FIELDS.every(field => requests[0].body[field] === fields[field]));
}
function exactFinalTeachingPut(seen, bearer, fields) {
  return Boolean(seen.puts === 1 && seen.paths.length === 1 && seen.paths[0] === PUT_PATH &&
    exactPhysicalTeachingPut(seen.physicalRequests, bearer, fields));
}
async function replacePhysicalTeachingField(handle, action, label, value) {
  const before = await handle.evaluate(element => element.value);
  assert.equal(typeof before, 'string', `Teaching field ${label} must be editable`);
  // Chromium's editor command is explicit: a host OS Meta+A shortcut did not select the
  // existing controlled input in the native run. A raw keydown sends no replacement text.
  await action(() => handle.press('A', { commands: ['SelectAll'], text: '' }));
  const selected = await handle.evaluate(element => [element.selectionStart, element.selectionEnd, element.value]);
  assert.deepEqual(selected, [0, before.length, before], `Teaching field ${label} must be fully selected`);
  await action(() => handle.press('Backspace'));
  assert.equal(await handle.evaluate(element => element.value), '', `Teaching field ${label} must be cleared by keyboard`);
  await action(() => handle.type(value));
  assert.equal(await handle.evaluate(element => element.value), value);
}

function assertOperation(value) {
  exactKeys(value, ['originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId', 'sequence',
    'browserAckOperationId', 'ackMessage']);
  assert([200, 202].includes(value.originalStatus));
  assert.equal(value.resolvedStatus, 200);
  assert(Number.isSafeInteger(value.sameIdGets) && value.sameIdGets >= (value.originalStatus === 202 ? 1 : 0));
  assert.match(value.operationId, UUID);
  assert.match(value.sequence, DECIMAL);
  if (value.originalStatus === 202) {
    assert.equal(value.browserAckOperationId, value.operationId);
    assert.equal(value.ackMessage, null);
  } else {
    assert.equal(value.browserAckOperationId, null);
    assert.equal(value.ackMessage, 'Stage updated');
    assert.equal(value.sameIdGets, 0);
  }
}

function assertTeachingSaveReceipt(r) {
  exactKeys(r, ['version', 'profile', 'modelCalls', 'judgeCalls', 'targetStageId', 'siblingStageId',
    'mountedActorId', 'mountedSessionId', 'observedPath', 'browserPuts', 'fixtureDeniedPuts', 'fixtureRestorePuts',
    'dialogTimeAba', 'confirmed', 'restore', 'facts', 'excluded', 'unexpectedApiPaths', 'stage']);
  assert.equal(r.version, 1); assert.equal(r.profile, 'ctf-teaching-save-q05');
  assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0);
  assert.equal(r.targetStageId, TARGET); assert.equal(r.siblingStageId, SIBLING);
  assert.match(r.mountedActorId, DECIMAL); assert.match(r.mountedSessionId, DECIMAL);
  assert.equal(r.observedPath, PUT_PATH);
  assert.equal(r.browserPuts, 1); assert.equal(r.fixtureDeniedPuts, 1); assert.equal(r.fixtureRestorePuts, 1);
  exactKeys(r.dialogTimeAba, ['eventsObserved', 'noPut']);
  assert.equal(r.dialogTimeAba.eventsObserved, 2); assert.equal(r.dialogTimeAba.noPut, true);
  assertOperation(r.confirmed);
  exactKeys(r.restore, ['scope', 'originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId', 'sequence',
    'browserAckOperationId', 'ackMessage']);
  assert.equal(r.restore.scope, 'content-equivalence-only');
  assertOperation(Object.fromEntries(Object.entries(r.restore).filter(([key]) => key !== 'scope')));
  assert.notEqual(r.confirmed.operationId, r.restore.operationId);
  assert(BigInt(r.restore.sequence) > BigInt(r.confirmed.sequence));
  exactKeys(r.facts, FACTS); for (const key of FACTS) assert.equal(r.facts[key], true, key);
  assert.deepEqual(r.excluded, ['byte-identical-undo', 'provenance-rollback']);
  assert.deepEqual(r.unexpectedApiPaths, []);
  assert.equal(r.stage, 'complete');
  return true;
}

async function runTeachingSaveRenderedFacet({ i, c, origin, instructor, action, click, pointer,
  admin, mounted, adapter, request, userRequest, ledger, receiptPath, unexpectedApiPaths,
  runtimeDirectory }) {
  assert.equal(path.resolve(receiptPath), path.join(fs.realpathSync(runtimeDirectory), 'ctf-teaching-save-q05-result.json'));
  const r = { version: 1, profile: 'ctf-teaching-save-q05', modelCalls: 0, judgeCalls: 0,
    targetStageId: TARGET, siblingStageId: SIBLING, mountedActorId: null, mountedSessionId: null,
    observedPath: null, browserPuts: 0, fixtureDeniedPuts: 0, fixtureRestorePuts: 0,
    dialogTimeAba: { eventsObserved: 0, noPut: false }, confirmed: null, restore: null,
    facts: {}, excluded: ['byte-identical-undo', 'provenance-rollback'], unexpectedApiPaths: [], stage: 'start' };
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
  assert.equal((await request('GET', '/admin/stages', admin)).status, 200);
  const stageRow = async id => {
    const row = (await c.runtime.query('SELECT to_jsonb(s)::text AS stage FROM ctf.ctf_stages s WHERE id=$1', [id])).rows[0];
    assert(row?.stage);
    const teaching = (await c.runtime.query('SELECT objective_text,solution_text FROM ctf.ctf_stage_teaching_content WHERE stage_id=$1', [id])).rows;
    return { stage: row.stage, teaching: JSON.stringify(teaching) };
  };
  const targetBefore = await stageRow(TARGET), siblingBefore = await stageRow(SIBLING);
  const original = JSON.parse(targetBefore.stage), originalTeaching = JSON.parse(targetBefore.teaching)[0];
  assert.equal(original.stage_number, TARGET);
  const originalFields = { stage_name: original.stage_name, stage_description: original.stage_description,
    hints: original.hints, teaching_objective: originalTeaching?.objective_text || '',
    solution_content: originalTeaching?.solution_text || '' };
  const authored = { stage_name: 'Q05 rendered teaching title', stage_description: 'Q05 rendered learner description',
    hints: JSON.stringify(['Q05 first hint', 'Q05 second hint', 'Q05 third hint']),
    teaching_objective: 'Q05 rendered learner objective', solution_content: 'Q05 admin-only instructor solution' };
  const rowsAfter = sequence => i.migration.query("SELECT sequence::text,operation_id::text,actor_id::text,session_id::text,kind,state,canonical_command,command_hash,canonical_result,result_hash FROM identity.ctf_outbox WHERE sequence>$1 AND kind='catalog_mutation' AND canonical_command::jsonb->'scope'->>'stageId'=$2 ORDER BY sequence", [sequence, String(TARGET)]);
  const maxSequence = async () => (await i.migration.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const initialSequence = await maxSequence();
  const verifyOutbox = async (afterSequence, expectedFields, actorId, sessionId, expectedCount = 1) => {
    const deadline = Date.now() + 10000;
    let values;
    for (;;) {
      values = (await rowsAfter(afterSequence)).rows;
      if (values.length === expectedCount && values.every(row => row.state === 'applied')) break;
      if (Date.now() >= deadline) throw Error('Teaching Save projection deadline');
      await sleep(50);
    }
    const row = values[0];
    assert.equal(row.kind, 'catalog_mutation'); assert.equal(row.actor_id, String(actorId));
    assert.equal(row.session_id, String(sessionId));
    assert.equal(crypto.createHash('sha256').update(row.canonical_command).digest('hex'), row.command_hash);
    const command = JSON.parse(row.canonical_command);
    assert.equal(command.operationId, row.operation_id); assert.equal(command.kind, 'catalog_mutation');
    assert.equal(command.scope.stageId, String(TARGET)); assert.equal(command.body.action, 'update');
    assert.deepEqual(command.body.fields, expectedFields);
    const receipt = (await c.runtime.query('SELECT sequence::text,operation_id::text,kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1', [row.operation_id])).rows[0];
    assert.deepEqual(receipt, { sequence: row.sequence, operation_id: row.operation_id, kind: row.kind,
      command_hash: row.command_hash, canonical_result: row.canonical_result, result_hash: row.result_hash });
    return row;
  };
  const seen = { puts: 0, paths: [], physicalRequests: [], gets: [] };
  const onRequest = req => {
    const url = new URL(req.url());
    if (req.method() === 'PUT' && url.pathname.startsWith('/api/ctf/admin/')) {
      seen.paths.push(url.pathname);
      if (url.origin === origin && url.pathname === PUT_PATH) {
        seen.puts++;
        let body = null;
        try { body = JSON.parse(req.postData() || ''); } catch { /* Malformed request fails the later exact-body assertion. */ }
        seen.physicalRequests.push({ body, bearer: req.headers().authorization || null });
      }
    }
    if (req.method() === 'GET' && url.origin === origin && /^\/api\/ctf\/operations\//.test(url.pathname)) seen.gets.push(url.pathname);
  };
  const operationResponses = [];
  const onResponse = response => {
    const url = new URL(response.url());
    if (url.origin === origin && response.request().method() === 'GET' && /^\/api\/ctf\/operations\//.test(url.pathname))
      operationResponses.push({ path: url.pathname, status: response.status(), response });
  };
  instructor.on('request', onRequest);
  instructor.on('response', onResponse);
  const find = async fn => action(() => instructor.waitForFunction(fn, { polling: 100, timeout: 15000 }, TARGET));
  const openEditor = async () => {
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Levels');
    const h = await find(id => {
      const rows = [...document.querySelectorAll('tbody tr')].filter(row => row.children[0]?.textContent.trim() === String(id));
      return rows.length === 1 && !document.querySelector('section[aria-label="Teaching content editor"]') ? rows[0] : null;
    });
    try { await pointer(instructor, h, action); } finally { await h.dispose(); }
    const ready = await action(() => instructor.waitForFunction(() => document.querySelectorAll('section[aria-label="Teaching content editor"]').length === 1,
      { polling: 100, timeout: 15000 })); await ready.dispose();
  };
  const fill = async (label, value) => {
    const h = await action(() => instructor.evaluateHandle(text => {
      const editor = document.querySelector('section[aria-label="Teaching content editor"]');
      const matches = [...(editor?.querySelectorAll('label') || [])].filter(node => node.textContent.trim() === text);
      return matches.length === 1 ? matches[0].parentElement.querySelector('input,textarea') : null;
    }, label));
    try {
      assert(h.asElement(), `Teaching field ${label} missing`);
      await pointer(instructor, h, action);
      await replacePhysicalTeachingField(h, action, label, value);
    } finally { await h.dispose(); }
  };
  const fillFive = async () => {
    for (const [label, field] of [['Stage Name', 'stage_name'], ['Learner Description', 'stage_description'],
      ['Hints (ordered JSON array)', 'hints'], ['Learner Objective', 'teaching_objective'],
      ['Instructor Solution (admin only)', 'solution_content']]) await fill(label, authored[field]);
  };
  const review = async () => {
    await click(instructor, 'button', 'Save teaching content');
    const ready = await action(() => instructor.waitForFunction(() => {
      const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(d => d.querySelector('h3')?.textContent.trim() === 'Save CTF teaching content');
      return dialogs.length === 1 && dialogs[0].textContent.includes('Guardian policy') && dialogs[0].textContent.includes('scoring') &&
        [...dialogs[0].querySelectorAll('button')].filter(b => b.textContent.trim() === 'Confirm Teaching Save' && !b.disabled).length === 1;
    }, { polling: 100, timeout: 15000 })); await ready.dispose();
  };
  const noDialog = async () => { const gone = await action(() => instructor.waitForFunction(() =>
    ![...document.querySelectorAll('[role="dialog"]')].some(d => d.querySelector('h3')?.textContent.trim() === 'Save CTF teaching content'),
  { polling: 100, timeout: 15000 })); await gone.dispose(); };
  const browserRecovery = async operationId => {
    const operationPath = `/api/ctf/operations/${operationId}`;
    const deadline = Date.now() + 30000;
    let checks = 0;
    for (;;) {
      const observed = operationResponses.find(item => item.path === operationPath && item.status === 200);
      if (observed) {
        assert.deepEqual(await observed.response.json(), { message: 'Stage updated' });
        const reads = seen.gets.filter(item => item === operationPath).length;
        assert(reads >= 1);
        return reads;
      }
      if (Date.now() >= deadline) throw Error('Teaching Save same-ID browser recovery deadline');
      const available = await action(() => instructor.evaluate(() =>
        [...document.querySelectorAll('[role="status"] button')].filter(button =>
          button.textContent.trim() === 'Check status' && !button.disabled).length === 1));
      if (available && checks < 3) { await click(instructor, '[role="status"] button', 'Check status'); checks++; }
      await sleep(100);
    }
  };
  let completed = false, other;
  try {
    r.stage = 'cancel'; save();
    await openEditor(); await fillFive(); await review();
    await click(instructor, '[role="dialog"] button', 'Cancel'); await noDialog();
    r.facts.cancelNoPut = seen.puts === 0 && (await rowsAfter(initialSequence)).rows.length === 0;
    r.facts.cancelNoEffect = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.cancelNoPut && r.facts.cancelNoEffect); save();
    r.stage = 'dialog-aba'; save(); await review();
    other = await action(() => instructor.browserContext().newPage());
    await action(() => other.setRequestInterception(true));
    other.on('request', req => { const url = new URL(req.url()); return url.origin === origin || ['about:', 'data:', 'blob:'].includes(url.protocol) ? req.continue() : req.abort(); });
    await action(() => other.goto(`${origin}/api/ctf/config`, { waitUntil: 'domcontentloaded' }));
    await action(() => instructor.evaluate(() => { window.__ctfTeachingStorageEvents = 0;
      window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfTeachingStorageEvents++; }); }));
    await action(() => other.evaluate(([b, a]) => { localStorage.setItem('token', b); localStorage.setItem('token', a); }, [tokenB, tokenA]));
    const observed = await action(() => instructor.waitForFunction(() => (window.__ctfTeachingStorageEvents || 0) >= 2, { polling: 100, timeout: 15000 })); await observed.dispose();
    r.dialogTimeAba.eventsObserved = await action(() => instructor.evaluate(() => window.__ctfTeachingStorageEvents || 0));
    assert.equal(r.dialogTimeAba.eventsObserved, 2);
    await noDialog(); await action(() => other.close()); other = null;
    r.dialogTimeAba.noPut = seen.puts === 0 && (await rowsAfter(initialSequence)).rows.length === 0;
    r.facts.dialogAbaNoPut = r.dialogTimeAba.noPut;
    r.facts.dialogAbaNoEffect = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.dialogAbaNoPut && r.facts.dialogAbaNoEffect); save();
    r.stage = 'confirm'; save();
    await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
    await openEditor(); await fillFive(); await review();
    const priorSequence = await maxSequence();
    const responsePromise = action(() => instructor.waitForResponse(response =>
      new URL(response.url()).origin === origin && new URL(response.url()).pathname === PUT_PATH && response.request().method() === 'PUT', { timeout: 15000 }));
    await click(instructor, '[role="dialog"] button', 'Confirm Teaching Save');
    const response = await responsePromise;
    assert([200, 202].includes(response.status()));
    const browserAck = await response.json();
    const outbox = await verifyOutbox(priorSequence, authored, r.mountedActorId, r.mountedSessionId);
    if (response.status() === 200) assert.deepEqual(browserAck, { message: 'Stage updated' });
    else { assert.equal(browserAck?.pending, true); assert.equal(browserAck.operationId, outbox.operation_id); }
    const browserGetCount = response.status() === 202 ? await browserRecovery(outbox.operation_id) : 0;
    r.confirmed = { originalStatus: response.status(), resolvedStatus: 200, sameIdGets: browserGetCount,
      operationId: outbox.operation_id, sequence: outbox.sequence,
      browserAckOperationId: response.status() === 202 ? browserAck.operationId : null,
      ackMessage: response.status() === 200 ? browserAck.message : null };
    r.facts.confirmedOnePhysicalPut = exactFinalTeachingPut(seen, `Bearer ${tokenA}`, authored);
    r.observedPath = seen.paths[0] || null;
    r.facts.physicalRequestFiveFieldsAndBearer = exactPhysicalTeachingPut(seen.physicalRequests, `Bearer ${tokenA}`, authored);
    // The bearer and submitted body are an in-memory comparison only, never receipt fields.
    r.facts.fiveFieldsExact = true; r.facts.canonicalProjectionApplied = true; r.facts.actorSessionBound = true;
    assert(r.facts.confirmedOnePhysicalPut && r.facts.physicalRequestFiveFieldsAndBearer); save();
    const after = await stageRow(TARGET), stored = JSON.parse(after.stage), teaching = JSON.parse(after.teaching);
    assert.equal(teaching.length, 1);
    for (const field of ['stage_name', 'stage_description', 'hints']) assert.equal(stored[field], authored[field]);
    assert.equal(teaching[0].objective_text, authored.teaching_objective);
    assert.equal(teaching[0].solution_text, authored.solution_content);
    r.facts.guardianAndScoringUnchanged = POLICY_FIELDS.every(field => stored[field] === original[field]);
    r.facts.siblingPreserved = JSON.stringify(await stageRow(SIBLING)) === JSON.stringify(siblingBefore);
    assert(r.facts.guardianAndScoringUnchanged && r.facts.siblingPreserved); save();
    const adminStages = await request('GET', '/admin/stages', admin);
    const solutions = await request('GET', '/admin/solutions', admin);
    const learner = await userRequest(3002), learnerStages = await request('GET', '/stages', learner);
    const beforeDenied = await stageRow(TARGET), beforeDeniedSequence = await maxSequence();
    const denied = await request('PUT', `/admin/stages/${TARGET}/content`, learner, authored);
    r.fixtureDeniedPuts++;
    r.facts.learnerMutationDenied = denied.status === 403 &&
      (await rowsAfter(beforeDeniedSequence)).rows.length === 0 &&
      JSON.stringify(await stageRow(TARGET)) === JSON.stringify(beforeDenied) &&
      JSON.stringify(await stageRow(SIBLING)) === JSON.stringify(siblingBefore);
    assert(r.facts.learnerMutationDenied);
    assert.equal(adminStages.status, 200); assert.equal(solutions.status, 200); assert.equal(learnerStages.status, 200);
    assert.equal((await request('GET', '/admin/solutions', learner)).status, 403);
    const adminRow = adminStages.body.stages.find(row => Number(row.id) === TARGET);
    const learnerRow = learnerStages.body.stages.find(row => Number(row.id) === TARGET);
    const solution = solutions.body.levels.find(row => Number(row.level) === TARGET);
    r.facts.adminHintsAndSolutionVisible = adminRow?.hints === authored.hints && adminRow.solution_content === authored.solution_content &&
      solution?.instructorSolution === authored.solution_content;
    r.facts.learnerObjectiveVisible = learnerRow?.teaching_objective === authored.teaching_objective && learnerRow.stage_name === authored.stage_name && learnerRow.stage_description === authored.stage_description;
    r.facts.learnerRawHintsAndSolutionAbsent = learnerRow && !Object.hasOwn(learnerRow, 'hints') &&
      !Object.hasOwn(learnerRow, 'solution_content') && !JSON.stringify(learnerStages.body).includes(authored.solution_content) &&
      !JSON.stringify(learnerStages.body).includes('Q05 first hint');
    assert(r.facts.adminHintsAndSolutionVisible && r.facts.learnerObjectiveVisible && r.facts.learnerRawHintsAndSolutionAbsent); save();
    r.stage = 'explicit-content-restore'; save();
    const beforeRestore = await maxSequence();
    const restoreResponse = await request('PUT', `/admin/stages/${TARGET}/content`, admin, originalFields);
    r.fixtureRestorePuts++;
    assert([200, 202].includes(restoreResponse.status));
    const restoredOutbox = await verifyOutbox(beforeRestore, originalFields, admin.user.id, admin.identitySession.id);
    let sameIdGets = 0;
    if (restoreResponse.status === 200) assert.deepEqual(restoreResponse.body, { message: 'Stage updated' });
    else {
      assert.equal(restoreResponse.body?.pending, true);
      assert.equal(restoreResponse.body.operationId, restoredOutbox.operation_id);
      const deadline = Date.now() + 30000;
      for (;;) {
        const recovered = await request('GET', `/operations/${restoredOutbox.operation_id}`, admin);
        sameIdGets++;
        if (recovered.status === 200) { assert.deepEqual(recovered.body, { message: 'Stage updated' }); break; }
        assert.equal(recovered.status, 202);
        if (Date.now() >= deadline) throw Error('Teaching Save restore same-ID recovery deadline');
        await sleep(100);
      }
    }
    r.restore = { scope: 'content-equivalence-only', originalStatus: restoreResponse.status, resolvedStatus: 200, sameIdGets,
      operationId: restoredOutbox.operation_id, sequence: restoredOutbox.sequence,
      browserAckOperationId: restoreResponse.status === 202 ? restoreResponse.body.operationId : null,
      ackMessage: restoreResponse.status === 200 ? restoreResponse.body.message : null };
    const restored = await stageRow(TARGET), restoredStage = JSON.parse(restored.stage), restoredTeaching = JSON.parse(restored.teaching)[0];
    r.facts.restoreContentEquivalent = CONTENT_FIELDS.every(field =>
      field === 'teaching_objective' ? restoredTeaching?.objective_text === originalFields[field] :
        field === 'solution_content' ? restoredTeaching?.solution_text === originalFields[field] : restoredStage[field] === originalFields[field]);
    r.facts.restorationGuardianAndScoringUnchanged = POLICY_FIELDS.every(field => restoredStage[field] === original[field]);
    assert(r.facts.restoreContentEquivalent && r.facts.restorationGuardianAndScoringUnchanged);
    assert.equal(JSON.stringify(await stageRow(SIBLING)), JSON.stringify(siblingBefore));
    r.browserPuts = seen.puts; r.unexpectedApiPaths = [...unexpectedApiPaths];
    assert.equal(ledger.length, 0);
    r.stage = 'complete'; assertTeachingSaveReceipt(r); save(); completed = true;
    return async () => { r.browserPuts = seen.puts; r.observedPath = seen.paths[0] || null;
      r.facts.confirmedOnePhysicalPut = exactFinalTeachingPut(seen, `Bearer ${tokenA}`, authored);
      r.facts.physicalRequestFiveFieldsAndBearer = exactPhysicalTeachingPut(seen.physicalRequests, `Bearer ${tokenA}`, authored);
      r.unexpectedApiPaths = [...unexpectedApiPaths];
      try { assertTeachingSaveReceipt(r); save(); }
      catch (error) { r.stage = 'late-request-failed'; save(); throw error; }
      finally { seen.physicalRequests.length = 0; instructor.off('request', onRequest); instructor.off('response', onResponse); } };
  } finally {
    if (other) await other.close();
    if (!completed) { instructor.off('request', onRequest); r.browserPuts = seen.puts;
      instructor.off('response', onResponse); seen.physicalRequests.length = 0;
      r.unexpectedApiPaths = [...unexpectedApiPaths]; save(); }
  }
}

module.exports = { runTeachingSaveRenderedFacet, assertTeachingSaveReceipt, exactPhysicalTeachingPut,
  exactFinalTeachingPut, replacePhysicalTeachingField, CONTENT_FIELDS, PUT_PATH };
