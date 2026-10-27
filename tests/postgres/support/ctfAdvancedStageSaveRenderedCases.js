'use strict';
// Separate Q05 facet: never alter the original ten-content/55-fact receipt.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { replacePhysicalTeachingField } = require('./ctfTeachingSaveRenderedCases');

const FIELDS = Object.freeze(['stage_name', 'stage_description', 'system_prompt', 'success_criteria',
  'hints', 'defense_style', 'adaptive_mode', 'level_score', 'feedback_mode']);
const FACTS = Object.freeze(['cancelNoPut', 'cancelNoEffect', 'dialogAbaNoPut', 'dialogAbaNoEffect',
  'confirmedOnePhysicalPut', 'nineFieldsAndCapturedBearer', 'canonicalProjectionApplied',
  'policyAndScoreChanged', 'siblingPreserved', 'restoreContentEquivalent', 'noModelOrJudge']);
const TARGET = 2;
const SIBLING = 3;
const PUT_PATH = `/api/ctf/admin/stages/${TARGET}`;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
const comparableFields = row => Object.fromEntries(FIELDS.map(key => [key, row[key]]));

function exactPhysicalAdvancedPut(seen, bearer, expected) {
  return seen.puts === 1 && seen.paths.length === 1 && seen.paths[0] === PUT_PATH &&
    seen.physical.length === 1 && seen.physical[0].bearer === bearer &&
    seen.physical[0].body && !Array.isArray(seen.physical[0].body) &&
    Object.keys(seen.physical[0].body).sort().join(',') === [...FIELDS].sort().join(',') &&
    FIELDS.every(key => seen.physical[0].body[key] === expected[key]);
}
async function validatedAdvancedBrowserBearer(token, adapter, actorId, sessionId) {
  assert.equal(typeof token, 'string');
  assert(token.length > 0 && token.length <= 8192);
  const current = await adapter.validateSession(token);
  assert.equal(String(current?.user?.id), String(actorId));
  assert.equal(String(current?.session?.id), String(sessionId));
  return `Bearer ${token}`;
}
function findAdvancedInput(text, scope = document) {
  const headings = [...scope.querySelectorAll('h3')].filter(item =>
    item.textContent.trim() === 'Advanced stage controls');
  if (headings.length !== 1) return null;
  const heading = headings[0];
  const row = heading.closest('tr');
  // Teaching fields precede this heading in the same table row. DOM position 4
  // is DOCUMENT_POSITION_FOLLOWING, so only the Advanced section is eligible.
  const labels = [...(row?.querySelectorAll('label') || [])].filter(item =>
    (heading.compareDocumentPosition(item) & 4) !== 0 && item.textContent.trim() === text);
  return labels.length === 1 ? labels[0].parentElement.querySelector('input,textarea') : null;
}
async function replacePhysicalAdvancedScore(handle, action, value) {
  const before = await handle.evaluate(element => element.value);
  assert.equal(typeof before, 'string', 'Advanced score must be editable');
  // A controlled number input maps an empty value back to 0. Backspace after
  // SelectAll therefore inserts that 0 before typing and yields 0157.
  // Typing while the original value remains selected replaces it atomically.
  await action(() => handle.press('A', { commands: ['SelectAll'], text: '' }));
  await action(() => handle.type(String(value)));
  assert.equal(await handle.evaluate(element => element.value), String(value));
}
function assertOperation(value) {
  exactKeys(value, ['originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId', 'sequence',
    'browserAckOperationId', 'ackMessage']);
  assert([200, 202].includes(value.originalStatus));
  assert.equal(value.resolvedStatus, 200);
  assert(Number.isSafeInteger(value.sameIdGets) && value.sameIdGets >= (value.originalStatus === 202 ? 1 : 0));
  assert.match(value.operationId, UUID); assert.match(value.sequence, DECIMAL);
  if (value.originalStatus === 202) {
    assert.equal(value.browserAckOperationId, value.operationId);
    assert.equal(value.ackMessage, null);
  } else {
    assert.equal(value.browserAckOperationId, null);
    assert.equal(value.ackMessage, 'Stage updated');
    assert.equal(value.sameIdGets, 0);
  }
}
function assertAdvancedStageSaveReceipt(receipt) {
  exactKeys(receipt, ['version', 'profile', 'targetStageId', 'siblingStageId', 'mountedActorId',
    'mountedSessionId', 'observedPath', 'browserPuts', 'fixtureRestorePuts', 'dialogTimeAba',
    'confirmed', 'restore', 'facts', 'excluded', 'unexpectedApiPaths', 'stage', 'modelCalls', 'judgeCalls']);
  assert.equal(receipt.version, 1); assert.equal(receipt.profile, 'ctf-advanced-stage-save-q05');
  assert.equal(receipt.targetStageId, TARGET); assert.equal(receipt.siblingStageId, SIBLING);
  assert.match(receipt.mountedActorId, DECIMAL); assert.match(receipt.mountedSessionId, DECIMAL);
  assert.equal(receipt.observedPath, PUT_PATH); assert.equal(receipt.browserPuts, 1);
  assert.equal(receipt.fixtureRestorePuts, 1);
  assert.deepEqual(receipt.dialogTimeAba, { eventsObserved: 2, noPut: true });
  assertOperation(receipt.confirmed);
  exactKeys(receipt.restore, ['scope', 'originalStatus', 'resolvedStatus', 'sameIdGets',
    'operationId', 'sequence', 'browserAckOperationId', 'ackMessage']);
  assert.equal(receipt.restore.scope, 'content-equivalence-only');
  assertOperation(Object.fromEntries(Object.entries(receipt.restore).filter(([key]) => key !== 'scope')));
  assert.notEqual(receipt.confirmed.operationId, receipt.restore.operationId);
  assert(BigInt(receipt.restore.sequence) > BigInt(receipt.confirmed.sequence));
  exactKeys(receipt.facts, FACTS);
  for (const name of FACTS) assert.equal(receipt.facts[name], true, name);
  assert.equal(receipt.modelCalls, 0); assert.equal(receipt.judgeCalls, 0);
  assert.deepEqual(receipt.excluded, ['byte-identical-undo', 'provenance-rollback', 'model-qualification']);
  assert.deepEqual(receipt.unexpectedApiPaths, []);
  assert.equal(receipt.stage, 'complete');
  return true;
}

async function runAdvancedStageSaveRenderedFacet({ i, c, origin, instructor, action, click, pointer,
  admin, mounted, adapter, request, ledger, receiptPath, unexpectedApiPaths, runtimeDirectory }) {
  assert.equal(path.resolve(receiptPath), path.join(fs.realpathSync(runtimeDirectory), 'ctf-advanced-stage-save-q05-result.json'));
  const r = { version: 1, profile: 'ctf-advanced-stage-save-q05', targetStageId: TARGET,
    siblingStageId: SIBLING, mountedActorId: null, mountedSessionId: null,
    observedPath: null, browserPuts: 0, fixtureRestorePuts: 0,
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
  const original = comparableFields(targetBefore);
  assert(FIELDS.every(key => Object.hasOwn(original, key)), 'Advanced stage fields must exist');
  assert(['none', 'technique', 'payload', 'hybrid'].includes(original.adaptive_mode));
  assert(['full', 'reason', 'silent'].includes(original.feedback_mode));
  assert(Number.isSafeInteger(original.level_score) && original.level_score >= 0 && original.level_score <= 999993);
  assert.equal(typeof original.defense_style, 'string');
  assert.equal(typeof original.hints, 'string');
  const authored = { ...original, stage_name: 'Q05 advanced stage title',
    stage_description: 'Q05 advanced learner description',
    system_prompt: 'Q05 controlled guardian policy',
    success_criteria: 'Q05 controlled success criterion',
    hints: JSON.stringify(['Q05 advanced hint']),
    defense_style: '[]', level_score: Number(original.level_score) + 7 };
  assert.notEqual(authored.system_prompt, original.system_prompt);
  assert.notEqual(authored.success_criteria, original.success_criteria);
  assert.notEqual(authored.level_score, original.level_score);
  const maxSequence = async () => (await i.migration.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const rowsAfter = sequence => i.migration.query("SELECT sequence::text,operation_id::text,actor_id::text,session_id::text,kind,state,canonical_command,command_hash,canonical_result,result_hash FROM identity.ctf_outbox WHERE sequence>$1 AND kind='catalog_mutation' AND canonical_command::jsonb->'scope'->>'stageId'=$2 ORDER BY sequence", [sequence, String(TARGET)]);
  const initialSequence = await maxSequence();
  const verifyOutbox = async (afterSequence, fields, actorId, sessionId) => {
    const deadline = Date.now() + 10000;
    let values;
    for (;;) {
      values = (await rowsAfter(afterSequence)).rows;
      if (values.length === 1 && values[0].state === 'applied') break;
      if (Date.now() >= deadline) throw Error('Advanced Save projection deadline');
      await sleep(50);
    }
    const row = values[0];
    assert.equal(row.actor_id, String(actorId)); assert.equal(row.session_id, String(sessionId));
    assert.equal(crypto.createHash('sha256').update(row.canonical_command).digest('hex'), row.command_hash);
    const command = JSON.parse(row.canonical_command);
    assert.equal(command.operationId, row.operation_id);
    assert.equal(command.kind, 'catalog_mutation'); assert.equal(command.scope.stageId, String(TARGET));
    assert.equal(command.body.action, 'update'); assert.deepEqual(command.body.fields, fields);
    const projection = (await c.runtime.query('SELECT sequence::text,operation_id::text,kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1', [row.operation_id])).rows[0];
    assert.deepEqual(projection, { sequence: row.sequence, operation_id: row.operation_id, kind: row.kind,
      command_hash: row.command_hash, canonical_result: row.canonical_result, result_hash: row.result_hash });
    return row;
  };
  const seen = { puts: 0, paths: [], physical: [], gets: [] };
  const onRequest = req => {
    const url = new URL(req.url());
    if (req.method() === 'PUT' && url.pathname.startsWith('/api/ctf/admin/')) {
      seen.paths.push(url.pathname);
      if (url.origin === origin && url.pathname === PUT_PATH) {
        seen.puts++;
        let body = null;
        try { body = JSON.parse(req.postData() || ''); } catch { /* Exact body check rejects malformed JSON. */ }
        seen.physical.push({ body, bearer: req.headers().authorization || null });
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
  instructor.on('request', onRequest); instructor.on('response', onResponse);
  const find = fn => action(() => instructor.waitForFunction(fn, { polling: 100, timeout: 15000 }, TARGET));
  const openEditor = async () => {
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Levels');
    const h = await find(id => {
      const rows = [...document.querySelectorAll('tbody tr')].filter(row => row.children[0]?.textContent.trim() === String(id));
      return rows.length === 1 && ![...document.querySelectorAll('h3')].some(item => item.textContent.trim() === 'Advanced stage controls') ? rows[0] : null;
    });
    try { await pointer(instructor, h, action); } finally { await h.dispose(); }
    const ready = await action(() => instructor.waitForFunction(() =>
      [...document.querySelectorAll('h3')].filter(item => item.textContent.trim() === 'Advanced stage controls').length === 1,
    { polling: 100, timeout: 15000 })); await ready.dispose();
  };
  const fill = async (label, value) => {
    const h = await action(() => instructor.evaluateHandle(findAdvancedInput, label));
    try {
      assert(h.asElement(), `Advanced field ${label} missing`);
      await pointer(instructor, h, action);
      await replacePhysicalTeachingField(h, action, label, value);
    } finally { await h.dispose(); }
  };
  const fillScore = async value => {
    const h = await action(() => instructor.evaluateHandle(() => {
      const heading = [...document.querySelectorAll('h3')].find(item => item.textContent.trim() === 'Advanced stage controls');
      const label = [...(heading?.closest('tr')?.querySelectorAll('label') || [])].find(item => item.textContent.trim() === 'Level Score');
      return label?.parentElement.querySelector('input[type="number"]') || null;
    }));
    try {
      assert(h.asElement(), 'Advanced score missing');
      await pointer(instructor, h, action);
      await replacePhysicalAdvancedScore(h, action, value);
    } finally { await h.dispose(); }
  };
  const fillNine = async () => {
    for (const [label, field] of [['Stage Name', 'stage_name'], ['Description', 'stage_description'],
      ['System Prompt', 'system_prompt'], ['Success Criteria', 'success_criteria'],
      ['Hints (JSON array)', 'hints'], ['Defense Style (JSON)', 'defense_style']])
      if (authored[field] !== original[field]) await fill(label, authored[field]);
    await fillScore(authored.level_score);
  };
  const review = async () => {
    await click(instructor, 'button', 'Save');
    const ready = await action(() => instructor.waitForFunction(() => {
      const dialogs = [...document.querySelectorAll('[role="dialog"]')].filter(item =>
        item.querySelector('h3')?.textContent.trim() === 'Save advanced CTF stage controls');
      return dialogs.length === 1 && dialogs[0].textContent.includes('guardian') &&
        dialogs[0].textContent.includes('scoring') &&
        [...dialogs[0].querySelectorAll('button')].filter(item =>
          item.textContent.trim() === 'Confirm Advanced Save' && !item.disabled).length === 1;
    }, { polling: 100, timeout: 15000 })); await ready.dispose();
  };
  const noDialog = async () => {
    const gone = await action(() => instructor.waitForFunction(() =>
      ![...document.querySelectorAll('[role="dialog"]')].some(item =>
        item.querySelector('h3')?.textContent.trim() === 'Save advanced CTF stage controls'),
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
      if (Date.now() >= deadline) throw Error('Advanced Save same-ID browser recovery deadline');
      const available = await action(() => instructor.evaluate(() =>
        [...document.querySelectorAll('[role="status"] button')].filter(item =>
          item.textContent.trim() === 'Check status' && !item.disabled).length === 1));
      if (available && checks < 3) { await click(instructor, '[role="status"] button', 'Check status'); checks++; }
      await sleep(100);
    }
  };
  let completed = false, other, confirmedBearer;
  try {
    r.stage = 'cancel'; save();
    await openEditor(); await fillNine(); await review();
    await click(instructor, '[role="dialog"] button', 'Cancel'); await noDialog();
    r.facts.cancelNoPut = seen.puts === 0 && (await rowsAfter(initialSequence)).rows.length === 0;
    r.facts.cancelNoEffect = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.cancelNoPut && r.facts.cancelNoEffect); save();
    r.stage = 'dialog-aba'; save(); await review();
    other = await action(() => instructor.browserContext().newPage());
    await action(() => other.setRequestInterception(true));
    other.on('request', req => { const url = new URL(req.url());
      return url.origin === origin || ['about:', 'data:', 'blob:'].includes(url.protocol) ? req.continue() : req.abort(); });
    await action(() => other.goto(`${origin}/api/ctf/config`, { waitUntil: 'domcontentloaded' }));
    await action(() => instructor.evaluate(() => { window.__ctfAdvancedStorageEvents = 0;
      window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfAdvancedStorageEvents++; }); }));
    await action(() => other.evaluate(([b, a]) => { localStorage.setItem('token', b); localStorage.setItem('token', a); }, [tokenB, tokenA]));
    const observed = await action(() => instructor.waitForFunction(() =>
      (window.__ctfAdvancedStorageEvents || 0) >= 2, { polling: 100, timeout: 15000 })); await observed.dispose();
    r.dialogTimeAba.eventsObserved = await action(() => instructor.evaluate(() => window.__ctfAdvancedStorageEvents || 0));
    assert.equal(r.dialogTimeAba.eventsObserved, 2);
    await noDialog(); await action(() => other.close()); other = null;
    r.dialogTimeAba.noPut = seen.puts === 0 && (await rowsAfter(initialSequence)).rows.length === 0;
    r.facts.dialogAbaNoPut = r.dialogTimeAba.noPut;
    r.facts.dialogAbaNoEffect = JSON.stringify(await stageRow(TARGET)) === JSON.stringify(targetBefore);
    assert(r.facts.dialogAbaNoPut && r.facts.dialogAbaNoEffect); save();
    r.stage = 'confirm'; save();
    await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
    await openEditor(); await fillNine(); await review();
    confirmedBearer = await validatedAdvancedBrowserBearer(
      await action(() => instructor.evaluate(() => localStorage.getItem('token'))),
      adapter, r.mountedActorId, r.mountedSessionId);
    const priorSequence = await maxSequence();
    const responsePromise = action(() => instructor.waitForResponse(response =>
      new URL(response.url()).origin === origin && new URL(response.url()).pathname === PUT_PATH &&
      response.request().method() === 'PUT', { timeout: 15000 }));
    await click(instructor, '[role="dialog"] button', 'Confirm Advanced Save');
    const response = await responsePromise;
    assert([200, 202].includes(response.status()));
    const browserAck = await response.json();
    const outbox = await verifyOutbox(priorSequence, authored, r.mountedActorId, r.mountedSessionId);
    if (response.status() === 200) assert.deepEqual(browserAck, { message: 'Stage updated' });
    else { assert.equal(browserAck?.pending, true); assert.equal(browserAck.operationId, outbox.operation_id); }
    const sameIdGets = response.status() === 202 ? await browserRecovery(outbox.operation_id) : 0;
    r.confirmed = { originalStatus: response.status(), resolvedStatus: 200, sameIdGets,
      operationId: outbox.operation_id, sequence: outbox.sequence,
      browserAckOperationId: response.status() === 202 ? browserAck.operationId : null,
      ackMessage: response.status() === 200 ? browserAck.message : null };
    r.observedPath = seen.paths[0] || null;
    r.facts.confirmedOnePhysicalPut = exactPhysicalAdvancedPut(seen, confirmedBearer, authored);
    r.facts.nineFieldsAndCapturedBearer = r.facts.confirmedOnePhysicalPut;
    r.facts.canonicalProjectionApplied = true;
    assert(r.facts.confirmedOnePhysicalPut); save();
    const applied = await stageRow(TARGET);
    r.facts.policyAndScoreChanged = FIELDS.every(key => applied[key] === authored[key]) &&
      applied.system_prompt !== original.system_prompt &&
      applied.success_criteria !== original.success_criteria &&
      applied.level_score !== original.level_score;
    r.facts.siblingPreserved = JSON.stringify(await stageRow(SIBLING)) === JSON.stringify(siblingBefore);
    assert(r.facts.policyAndScoreChanged && r.facts.siblingPreserved); save();
    r.stage = 'explicit-content-restore'; save();
    const beforeRestore = await maxSequence();
    const restoreResponse = await request('PUT', PUT_PATH.replace('/api/ctf', ''), admin, original);
    r.fixtureRestorePuts++;
    assert([200, 202].includes(restoreResponse.status));
    const restoredOutbox = await verifyOutbox(beforeRestore, original, admin.user.id, admin.identitySession.id);
    let restoreGets = 0;
    if (restoreResponse.status === 200) assert.deepEqual(restoreResponse.body, { message: 'Stage updated' });
    else {
      assert.equal(restoreResponse.body?.pending, true);
      assert.equal(restoreResponse.body.operationId, restoredOutbox.operation_id);
      const deadline = Date.now() + 30000;
      for (;;) {
        const recovered = await request('GET', `/operations/${restoredOutbox.operation_id}`, admin);
        restoreGets++;
        if (recovered.status === 200) { assert.deepEqual(recovered.body, { message: 'Stage updated' }); break; }
        assert.equal(recovered.status, 202);
        if (Date.now() >= deadline) throw Error('Advanced Save restore same-ID recovery deadline');
        await sleep(100);
      }
    }
    r.restore = { scope: 'content-equivalence-only', originalStatus: restoreResponse.status,
      resolvedStatus: 200, sameIdGets: restoreGets, operationId: restoredOutbox.operation_id,
      sequence: restoredOutbox.sequence,
      browserAckOperationId: restoreResponse.status === 202 ? restoreResponse.body.operationId : null,
      ackMessage: restoreResponse.status === 200 ? restoreResponse.body.message : null };
    const restored = await stageRow(TARGET);
    r.facts.restoreContentEquivalent = FIELDS.every(key => restored[key] === original[key]);
    assert(r.facts.restoreContentEquivalent);
    assert.equal(JSON.stringify(await stageRow(SIBLING)), JSON.stringify(siblingBefore));
    r.facts.noModelOrJudge = ledger.length === 0;
    assert(r.facts.noModelOrJudge);
    r.browserPuts = seen.puts; r.unexpectedApiPaths = [...unexpectedApiPaths];
    r.stage = 'complete'; assertAdvancedStageSaveReceipt(r); save(); completed = true;
    return async () => {
      r.browserPuts = seen.puts; r.observedPath = seen.paths[0] || null;
      r.facts.confirmedOnePhysicalPut = exactPhysicalAdvancedPut(seen, confirmedBearer, authored);
      r.facts.nineFieldsAndCapturedBearer = r.facts.confirmedOnePhysicalPut;
      r.unexpectedApiPaths = [...unexpectedApiPaths];
      r.facts.noModelOrJudge = ledger.length === 0;
      try {
        assertAdvancedStageSaveReceipt(r);
        assert.equal(JSON.stringify(await stageRow(SIBLING)), JSON.stringify(siblingBefore));
        const terminalTarget = await stageRow(TARGET);
        assert(FIELDS.every(key => terminalTarget[key] === original[key]));
        assert.equal((await rowsAfter(restoredOutbox.sequence)).rows.length, 0);
        save();
      } catch (error) { r.stage = 'late-request-failed'; save(); throw error; }
      finally { seen.physical.length = 0; instructor.off('request', onRequest); instructor.off('response', onResponse); }
    };
  } finally {
    if (other) await other.close();
    if (!completed) {
      instructor.off('request', onRequest); instructor.off('response', onResponse);
      seen.physical.length = 0; r.browserPuts = seen.puts;
      r.unexpectedApiPaths = [...unexpectedApiPaths]; save();
    }
  }
}

module.exports = { runAdvancedStageSaveRenderedFacet, assertAdvancedStageSaveReceipt,
  exactPhysicalAdvancedPut, validatedAdvancedBrowserBearer, findAdvancedInput,
  replacePhysicalAdvancedScore, FIELDS, FACTS, PUT_PATH };
