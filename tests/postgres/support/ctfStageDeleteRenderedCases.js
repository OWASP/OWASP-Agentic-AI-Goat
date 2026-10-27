'use strict';
// Separate controlled Q05 facet. The ten canonical stages and original content
// receipt are not modified. This module is deliberately not wired into native.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const STAGE_NUMBER = 11;
const STAGE_ORDER = 0; // No predecessor can be required for canonical start.
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const FACTS = Object.freeze(['cancelNoDelete', 'cancelNoEffect', 'dialogAbaNoDelete',
  'dialogAbaNoEffect', 'confirmedOnePhysicalDelete', 'capturedBearerAndEmptyBody',
  'canonicalCreateAndStart', 'progressAndEventPopulated', 'canonicalDeleteProjection',
  'progressAndEventCascaded', 'identityBindingTombstoned', 'canonicalTenAndSiblingPreserved',
  'historyPreserved', 'noModelOrJudge']);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const stagePath = id => `/api/ctf/admin/stages/${id}`;
const clone = value => JSON.parse(JSON.stringify(value));

function assertOwnedStageSelection(stages, stageNumber = STAGE_NUMBER, stageOrder = STAGE_ORDER) {
  assert(Array.isArray(stages) && stages.length === 10);
  assert.deepEqual(stages.map(row => row.stage_number).sort((a, b) => a - b),
    Array.from({ length: 10 }, (_, n) => n + 1));
  assert(!stages.some(row => row.stage_number === stageNumber));
  assert(stages.every(row => Number.isInteger(row.stage_order) && row.stage_order > stageOrder),
    'Owned stage order must have no prerequisite predecessor');
  return true;
}

function exactPhysicalStageDelete(seen, targetPath, bearer) {
  return seen.deletes === 1 && seen.paths.length === 1 &&
    seen.paths[0] === `DELETE ${targetPath}` &&
    seen.physical.length === 1 && seen.physical[0].bearer === bearer &&
    [null, ''].includes(seen.physical[0].body);
}

function recordStageDeleteConfirmation(receipt, seen, targetPath, bearer, recoveryPath = null) {
  receipt.browserDeletes = seen.deletes;
  receipt.observedPath = seen.paths.length === 1 && seen.paths[0] === `DELETE ${targetPath}`
    ? targetPath : null;
  receipt.facts.confirmedOnePhysicalDelete = exactPhysicalStageDelete(seen, targetPath, bearer) &&
    (recoveryPath === null ? seen.gets.length === 0
      : seen.gets.length > 0 && seen.gets.every(item => item === recoveryPath));
  receipt.facts.capturedBearerAndEmptyBody = receipt.facts.confirmedOnePhysicalDelete;
}

async function openStageDeleteReview({ instructor, action, pointer, click,
  stageNumber, stageName }) {
  const row = await action(() => instructor.waitForFunction(({ number, name }) => {
    const rows = [...document.querySelectorAll('tbody tr')].filter(item =>
      item.children[0]?.textContent.trim() === String(number) &&
      item.children[1]?.textContent.trim() === name);
    return rows.length === 1 && rows[0].getClientRects().length ? rows[0] : false;
  }, { polling: 100, timeout: 15000 }, { number: stageNumber, name: stageName }));
  try {
    const expanded = await action(() => row.evaluate(item => {
      const editor = item.nextElementSibling;
      if (!editor || editor.children.length !== 1 ||
        editor.children[0].getAttribute('colspan') !== '7') return false;
      return [...editor.querySelectorAll('button')].filter(button =>
        button.textContent.trim() === 'Delete' && !button.disabled &&
        button.getClientRects().length).length === 1;
    }));
    if (!expanded) await pointer(instructor, row, action);
  } finally { await row.dispose(); }
  await click(instructor, 'button', 'Delete');
  const dialog = await action(() => instructor.waitForFunction(name =>
    [...document.querySelectorAll('[role="dialog"]')].filter(item =>
      item.querySelector('h3')?.textContent.trim() === 'Delete CTF stage' &&
      item.textContent.includes(`Permanently delete "${name}"?`) &&
      [...item.querySelectorAll('button')].filter(button =>
        button.textContent.trim() === 'Confirm Delete' && !button.disabled).length === 1).length === 1,
  { polling: 100, timeout: 15000 }, stageName)); await dialog.dispose();
}

function assertOwnedCreateResponse(body, createdId) {
  assert.deepEqual(body, { message: 'Stage created', id: createdId });
}

function assertOwnedStartResponse(body, createdId) {
  assert.equal(body?.message, 'Stage started successfully');
  assert.equal(body.stage?.id, createdId);
  assert.equal(body.stage?.stage_number, STAGE_NUMBER);
  assert.equal(body.attemptsSoFar, 0);
  assert.equal(body.hintsUsed, 0);
  assert.equal(body.alreadyCompleted, undefined);
}

function assessStageDeleteReadback({ createdId, baselineStages, remainingStages,
  targetStage, preProgressCount, preEventCount, postProgress, postEvents, siblingBefore,
  siblingAfter, binding, operationId, sequence, retainedOperations }) {
  assert(Number.isSafeInteger(createdId) && createdId > 10);
  assert(Number.isSafeInteger(preProgressCount) && preProgressCount >= 0);
  assert(Number.isSafeInteger(preEventCount) && preEventCount >= 0);
  assert(Array.isArray(postProgress) && Array.isArray(postEvents));
  const nonvacuous = preProgressCount > 0 && preEventCount > 0;
  return {
    nonvacuous,
    cascaded: nonvacuous && postProgress.length === 0 && postEvents.length === 0,
    tombstoned: binding?.active === false &&
      binding.applied_operation_id === operationId && binding.applied_sequence === sequence,
    canonicalTenAndSiblingPreserved: targetStage === null &&
      JSON.stringify(remainingStages) === JSON.stringify(baselineStages) &&
      JSON.stringify(siblingAfter) === JSON.stringify(siblingBefore),
    historyPreserved: Array.isArray(retainedOperations) &&
      retainedOperations.includes(operationId),
  };
}

function assertOperation(value, message) {
  exactKeys(value, ['originalStatus', 'resolvedStatus', 'sameIdGets', 'operationId',
    'sequence', 'browserAckOperationId', 'ackMessage']);
  assert([200, 202].includes(value.originalStatus));
  assert.equal(value.resolvedStatus, 200);
  assert(Number.isSafeInteger(value.sameIdGets) && value.sameIdGets >= 0 && value.sameIdGets <= 32);
  assert.match(value.operationId, UUID); assert.match(value.sequence, DECIMAL);
  if (value.originalStatus === 202) {
    assert(value.sameIdGets >= 1); assert.equal(value.browserAckOperationId, value.operationId);
    assert.equal(value.ackMessage, null);
  } else {
    assert.equal(value.sameIdGets, 0); assert.equal(value.browserAckOperationId, null);
    assert.equal(value.ackMessage, message);
  }
}

function assertStageDeleteReceipt(r) {
  exactKeys(r, ['version', 'profile', 'stageNumber', 'stageOrder', 'targetStageId',
    'mountedActorId', 'mountedSessionId', 'learnerActorId', 'learnerSessionId',
    'observedPath', 'browserDeletes', 'setup', 'confirmed', 'dialogTimeAba',
    'preProgressRows', 'preEventRows', 'facts', 'excluded', 'unexpectedApiPaths',
    'stage', 'modelCalls', 'judgeCalls']);
  assert.equal(r.version, 1); assert.equal(r.profile, 'ctf-stage-delete-q05');
  assert.equal(r.stageNumber, STAGE_NUMBER); assert.equal(r.stageOrder, STAGE_ORDER);
  assert(Number.isSafeInteger(r.targetStageId) && r.targetStageId > 10 && r.targetStageId <= 2147483647);
  for (const key of ['mountedActorId', 'mountedSessionId', 'learnerActorId', 'learnerSessionId'])
    assert.match(r[key], DECIMAL);
  assert.equal(r.observedPath, stagePath(r.targetStageId)); assert.equal(r.browserDeletes, 1);
  exactKeys(r.setup, ['create', 'start']);
  assertOperation(r.setup.create, 'Stage created'); assertOperation(r.setup.start, 'Stage started successfully');
  assertOperation(r.confirmed, 'Stage deleted');
  assert.equal(new Set([r.setup.create.operationId, r.setup.start.operationId,
    r.confirmed.operationId]).size, 3);
  assert(BigInt(r.setup.create.sequence) < BigInt(r.setup.start.sequence));
  assert(BigInt(r.setup.start.sequence) < BigInt(r.confirmed.sequence));
  assert.deepEqual(r.dialogTimeAba, { eventsObserved: 2, noDelete: true });
  assert(Number.isSafeInteger(r.preProgressRows) && r.preProgressRows > 0);
  assert(Number.isSafeInteger(r.preEventRows) && r.preEventRows > 0);
  exactKeys(r.facts, FACTS); for (const fact of FACTS) assert.equal(r.facts[fact], true, fact);
  assert.deepEqual(r.excluded, ['attempts-nonvacuity', 'judgment-deletion', 'model-qualification',
    'byte-identical-database-undo']);
  assert.deepEqual(r.unexpectedApiPaths, []); assert.equal(r.stage, 'complete');
  assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0);
  return true;
}

async function recoverSameOperation({ request, req, operationId, message, now = Date.now,
  sleep = pause, validateBody = () => {} }) {
  assert.match(operationId, UUID);
  const deadline = now() + 30000;
  for (let count = 1; count <= 32 && now() <= deadline; count++) {
    const response = await request('GET', `/operations/${operationId}`, req);
    if (response.status === 200) {
      assert.equal(response.body?.message, message);
      validateBody(response.body);
      return count;
    }
    assert.equal(response.status, 202);
    assert.equal(response.body?.operationId, operationId);
    if (count < 32) await sleep(100);
  }
  throw Error('Stage-delete same-ID recovery exhausted');
}

// A cleanup is a distinct, recorded catalog operation only when no browser
// DELETE was dispatched. An uncertain browser DELETE is never retried here.
async function cleanupOwnedStage({ createdId, createAttempted = false, browserDeletes, exists, request, admin,
  verify, journal }) {
  if (!createdId) return { status: createAttempted
    ? 'create-outcome-unresolved-no-cleanup' : 'nothing-created' };
  assert(Number.isSafeInteger(createdId) && createdId > 10);
  if (browserDeletes !== 0) return { status: 'browser-delete-uncertain-no-retry' };
  if (!await exists(createdId)) return { status: 'already-absent-no-retry' };
  journal({ kind: 'distinct-setup-cleanup-intent', targetStageId: createdId });
  const response = await request('DELETE', `/admin/stages/${createdId}`, admin, {});
  journal({ kind: 'distinct-setup-cleanup', targetStageId: createdId,
    originalStatus: response.status, operationId: response.status === 202 ? response.body?.operationId : null });
  assert([200, 202].includes(response.status));
  if (response.status === 202) await recoverSameOperation({ request, req: admin,
    operationId: response.body.operationId, message: 'Stage deleted' });
  else assert.deepEqual(response.body, { message: 'Stage deleted' });
  await verify(createdId);
  return { status: 'distinct-canonical-cleanup' };
}

async function validatedBearer(token, adapter, actorId, sessionId) {
  assert.equal(typeof token, 'string'); assert(token.length > 0 && token.length <= 8192);
  const current = await adapter.validateSession(token);
  assert.equal(String(current?.user?.id), String(actorId));
  assert.equal(String(current?.session?.id), String(sessionId));
  return `Bearer ${token}`;
}

function retireStageDeleteListeners({ instructor, onRequest, onResponse, seen, primary }) {
  const errors = [];
  seen.physical.length = 0;
  if (onRequest) try { instructor.off('request', onRequest); } catch (error) { errors.push(error); }
  if (onResponse) try { instructor.off('response', onResponse); } catch (error) { errors.push(error); }
  if (errors.length) {
    const failure = new AggregateError(primary ? [primary, ...errors] : errors,
      'Stage-delete listener retirement failed');
    if (primary) failure.cause = primary;
    throw failure;
  }
}

async function runStageDeleteRenderedFacet({ i, c, origin, instructor, action, click, pointer,
  admin, mounted, adapter, request, userRequest, ledger, receiptPath,
  unexpectedApiPaths, runtimeDirectory, onOwnedStageCreated }) {
  assert.equal(typeof onOwnedStageCreated, 'function');
  assert.equal(path.resolve(receiptPath), path.join(fs.realpathSync(runtimeDirectory),
    'ctf-stage-delete-q05-result.json'));
  const r = { version: 1, profile: 'ctf-stage-delete-q05', stageNumber: STAGE_NUMBER,
    stageOrder: STAGE_ORDER, targetStageId: null, mountedActorId: null,
    mountedSessionId: null, learnerActorId: null, learnerSessionId: null,
    observedPath: null, browserDeletes: 0, setup: null, confirmed: null,
    dialogTimeAba: { eventsObserved: 0, noDelete: false }, preProgressRows: 0,
    preEventRows: 0, facts: {}, excluded: ['attempts-nonvacuity', 'judgment-deletion',
      'model-qualification', 'byte-identical-database-undo'], unexpectedApiPaths: [],
    stage: 'start', modelCalls: 0, judgeCalls: 0 };
  const save = () => fs.writeFileSync(receiptPath, JSON.stringify(r, null, 2), { mode: 0o600 });
  save();
  const tokenA = mounted.adminToken, tokenB = admin.headers.authorization.slice(7);
  assert.notEqual(tokenA, tokenB);
  const actor = await adapter.validateSession(tokenA);
  assert(actor?.user?.id > 0 && actor?.session?.id > 0);
  assert.notEqual(String(actor.user.id), String(admin.user.id));
  r.mountedActorId = String(actor.user.id); r.mountedSessionId = String(actor.session.id);
  const sequence = async () => (await i.migration.query(
    'SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const outboxAfter = after => i.migration.query(`SELECT sequence::text,operation_id::text,
    actor_id::text,session_id::text,kind,state,canonical_command,command_hash,
    canonical_result,result_hash FROM identity.ctf_outbox WHERE sequence>$1 ORDER BY sequence`, [after]);
  const stageRow = async id => (await c.runtime.query(
    'SELECT to_jsonb(s)::text AS stage FROM ctf.ctf_stages s WHERE id=$1', [id])).rows[0]?.stage ?? null;
  const stageRows = async () => (await c.runtime.query(
    'SELECT to_jsonb(s)::text AS stage FROM ctf.ctf_stages s ORDER BY stage_number')).rows.map(x => x.stage);
  const progressRows = async id => (await c.runtime.query(
    'SELECT to_jsonb(p)::text AS row FROM ctf.ctf_progress p WHERE stage_id=$1 ORDER BY id', [id])).rows.map(x => x.row);
  const eventRows = async id => (await c.runtime.query(
    'SELECT to_jsonb(e)::text AS row FROM ctf.ctf_events e WHERE stage_id=$1 ORDER BY id', [id])).rows.map(x => x.row);
  const binding = async id => (await i.migration.query(
    'SELECT active,applied_sequence::text,applied_operation_id::text FROM identity.ctf_stage_bindings WHERE stage_id=$1', [id])).rows[0];
  const judgments = async () => (await c.runtime.query(
    'SELECT to_jsonb(j)::text AS row FROM ctf.ctf_judgments j ORDER BY run_id')).rows.map(x => x.row);
  const baseline = await stageRows();
  assertOwnedStageSelection(baseline.map(JSON.parse));
  const beforeJudgments = await judgments();
  const siblingBefore = clone((await c.runtime.query(
    'SELECT to_jsonb(p)::text AS row FROM ctf.ctf_progress p WHERE participant_id=1001 ORDER BY id')).rows);
  const historyBefore = await sequence();
  const stageName = 'Q05 controlled owned deletion stage';
  const fields = Object.freeze({ stage_number: STAGE_NUMBER, stage_order: STAGE_ORDER,
    stage_name: stageName, success_criteria: 'Q05_OWNED_STAGE_SECRET', hints: '[]',
    defense_style: '[]', adaptive_mode: 'none', is_active: 1 });
  const verifyMutation = async ({ after, kind, action, stageId, actorId, sessionId }) => {
    const deadline = Date.now() + 10000;
    for (;;) {
      const rows = (await outboxAfter(after)).rows.filter(row => {
        if (row.kind !== kind) return false;
        const command = JSON.parse(row.canonical_command);
        return kind !== 'catalog_mutation' || command.body.action === action;
      });
      if (rows.length === 1 && rows[0].state === 'applied') {
        const row = rows[0], command = JSON.parse(row.canonical_command);
        assert.equal(row.actor_id, String(actorId)); assert.equal(row.session_id, String(sessionId));
        assert.equal(command.operationId, row.operation_id);
        assert.equal(sha(row.canonical_command), row.command_hash);
        if (kind === 'catalog_mutation') {
          assert.equal(command.body.action, action);
          if (action === 'create') { assert.deepEqual(command.body.fields, fields); assert.equal(command.scope.stageId, null); }
          else { assert.equal(command.scope.stageId, String(stageId)); assert.deepEqual(command.body.fields, {}); }
        } else {
          assert.equal(command.scope.stageId, String(stageId));
          assert.equal(command.scope.ownerId, String(actorId));
          assert.deepEqual(command.body, {});
        }
        const projection = (await c.runtime.query(`SELECT sequence::text,operation_id::text,
          kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts
          WHERE operation_id=$1`, [row.operation_id])).rows[0];
        assert.deepEqual(projection, { sequence: row.sequence, operation_id: row.operation_id,
          kind: row.kind, command_hash: row.command_hash,
          canonical_result: row.canonical_result, result_hash: row.result_hash });
        return row;
      }
      if (Date.now() >= deadline) throw Error('Stage-delete projection deadline');
      await pause(50);
    }
  };
  const envelope = async (response, outbox, message, req, validateBody) => {
    assert([200, 202].includes(response.status));
    let sameIdGets = 0;
    if (response.status === 202) {
      assert.equal(response.body?.pending, true);
      assert.equal(response.body.operationId, outbox.operation_id);
      sameIdGets = await recoverSameOperation({ request, req,
        operationId: outbox.operation_id, message, validateBody });
    } else {
      assert.equal(response.body?.message, message);
      validateBody(response.body);
    }
    return { originalStatus: response.status, resolvedStatus: 200, sameIdGets,
      operationId: outbox.operation_id, sequence: outbox.sequence,
      browserAckOperationId: response.status === 202 ? response.body.operationId : null,
      ackMessage: response.status === 200 ? message : null };
  };
  const seen = { deletes: 0, paths: [], physical: [], gets: [] };
  const operationResponses = [];
  let createdId = null, createOperationId = null, createAttempted = false;
  let other = null, onRequest = null;
  let onResponse = null, completed = false;
  let primary = null;
  try {
    r.stage = 'canonical-create'; save();
    const beforeCreate = await sequence();
    createAttempted = true;
    const create = await request('POST', '/admin/stages', admin, fields);
    assert([200, 202].includes(create.status));
    if (create.status === 202 && typeof create.body?.operationId === 'string')
      createOperationId = create.body.operationId;
    // Keep the genuine acknowledged target for exact cleanup even if a later
    // outbox/projection assertion fails. A 202 without an ID is unresolved.
    if (create.status === 200 && Number.isSafeInteger(create.body?.id)) {
      createdId = create.body.id; r.targetStageId = createdId; save();
    }
    const created = await verifyMutation({ after: beforeCreate, kind: 'catalog_mutation',
      action: 'create', actorId: admin.user.id, sessionId: admin.identitySession.id });
    const projection = JSON.parse(created.canonical_result);
    const projectedId = Number(projection?.data?.stageId);
    if (createdId !== null) assert.equal(createdId, projectedId);
    createdId = projectedId;
    assert(Number.isSafeInteger(createdId) && createdId > 10 && createdId <= 2147483647);
    r.targetStageId = createdId; save();
    const createOp = await envelope(create, created, 'Stage created', admin,
      body => assertOwnedCreateResponse(body, createdId));
    assert.equal(JSON.parse(await stageRow(createdId)).stage_number, STAGE_NUMBER);
    assert.equal((await binding(createdId))?.active, true);
    onOwnedStageCreated(createdId);
    r.stage = 'canonical-learner-start'; save();
    const learner = await userRequest(3011);
    r.learnerActorId = String(learner.user.id);
    r.learnerSessionId = String(learner.identitySession.id);
    const learnerAuthority = await adapter.validateSession(
      learner.headers.authorization.slice(7));
    assert.equal(String(learnerAuthority?.user?.id), r.learnerActorId);
    assert.equal(String(learnerAuthority?.session?.id), r.learnerSessionId);
    const participant = (await i.migration.query(`SELECT b.participant_id::text,
      b.active,b.banned,b.owner_generation::text,a.owner_generation::text AS current_generation
      FROM identity.ctf_participant_bindings b JOIN identity.ctf_authority a
      ON a.scope_key='owner:'||b.owner_id WHERE b.owner_id=$1`, [3011])).rows[0];
    assert.equal(participant?.active, true);
    assert.equal(participant?.banned, false);
    assert.equal(participant.owner_generation, participant.current_generation);
    assert.equal((await c.runtime.query(`SELECT is_active FROM ctf.ctf_participants
      WHERE id=$1 AND user_id=$2`, [participant.participant_id, 3011])).rows[0]?.is_active, 1);
    const beforeStart = await sequence();
    const start = await request('POST', `/stage/${createdId}/start`, learner, {});
    const started = await verifyMutation({ after: beforeStart, kind: 'start',
      stageId: createdId, actorId: learner.user.id, sessionId: learner.identitySession.id });
    const startOp = await envelope(start, started, 'Stage started successfully', learner,
      body => assertOwnedStartResponse(body, createdId));
    r.setup = { create: createOp, start: startOp };
    r.preProgressRows = (await progressRows(createdId)).length;
    r.preEventRows = (await eventRows(createdId)).length;
    r.facts.canonicalCreateAndStart = true;
    r.facts.progressAndEventPopulated = r.preProgressRows > 0 && r.preEventRows > 0;
    assert(r.facts.progressAndEventPopulated); save();
    const beforeTarget = await stageRow(createdId);
    const targetPath = stagePath(createdId);
    onRequest = req => {
      const url = new URL(req.url());
      if (url.origin === origin && req.method() === 'GET' &&
        /^\/api\/ctf\/operations\//.test(url.pathname)) seen.gets.push(url.pathname);
      if (url.origin !== origin || !url.pathname.startsWith('/api/ctf/admin/')) return;
      if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method())) return;
      seen.paths.push(`${req.method()} ${url.pathname}`);
      if (req.method() === 'DELETE' && url.pathname === targetPath) {
        seen.deletes++;
        seen.physical.push({ body: req.postData() ?? null,
          bearer: req.headers().authorization || null });
      }
    };
    onResponse = response => {
      const url = new URL(response.url());
      if (url.origin === origin && response.request().method() === 'GET' &&
        /^\/api\/ctf\/operations\//.test(url.pathname))
        operationResponses.push({ path: url.pathname, status: response.status(), response });
    };
    instructor.on('request', onRequest); instructor.on('response', onResponse);
    const openReview = () => openStageDeleteReview({ instructor, action, pointer, click,
      stageNumber: STAGE_NUMBER, stageName });
    const noDialog = async () => {
      const gone = await action(() => instructor.waitForFunction(() =>
        ![...document.querySelectorAll('[role="dialog"]')].some(item =>
          item.querySelector('h3')?.textContent.trim() === 'Delete CTF stage'),
      { polling: 100, timeout: 15000 })); await gone.dispose();
    };
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Levels');
    r.stage = 'cancel'; save(); await openReview();
    await click(instructor, '[role="dialog"] button', 'Cancel'); await noDialog();
    r.facts.cancelNoDelete = seen.paths.length === 0;
    r.facts.cancelNoEffect = await stageRow(createdId) === beforeTarget;
    assert(r.facts.cancelNoDelete && r.facts.cancelNoEffect); save();
    r.stage = 'dialog-aba'; save(); await openReview();
    other = await action(() => instructor.browserContext().newPage());
    await action(() => other.setRequestInterception(true));
    other.on('request', req => { const url = new URL(req.url());
      return url.origin === origin || ['about:', 'data:', 'blob:'].includes(url.protocol)
        ? req.continue() : req.abort(); });
    await action(() => other.goto(`${origin}/api/ctf/config`, { waitUntil: 'domcontentloaded' }));
    await action(() => instructor.evaluate(() => { window.__ctfStageDeleteEvents = 0;
      window.addEventListener('storage', event => { if (event.key === 'token') window.__ctfStageDeleteEvents++; }); }));
    await action(() => other.evaluate(([b, a]) => { localStorage.setItem('token', b);
      localStorage.setItem('token', a); }, [tokenB, tokenA]));
    const observed = await action(() => instructor.waitForFunction(() =>
      (window.__ctfStageDeleteEvents || 0) >= 2, { polling: 100, timeout: 15000 }));
    await observed.dispose();
    r.dialogTimeAba.eventsObserved = await action(() => instructor.evaluate(() =>
      window.__ctfStageDeleteEvents || 0));
    assert.equal(r.dialogTimeAba.eventsObserved, 2);
    await noDialog(); await other.close(); other = null;
    r.dialogTimeAba.noDelete = seen.paths.length === 0;
    r.facts.dialogAbaNoDelete = r.dialogTimeAba.noDelete;
    r.facts.dialogAbaNoEffect = await stageRow(createdId) === beforeTarget;
    assert(r.facts.dialogAbaNoDelete && r.facts.dialogAbaNoEffect); save();
    r.stage = 'confirm'; save(); await action(() => instructor.reload({ waitUntil: 'domcontentloaded' }));
    await click(instructor, 'nav[aria-label="CTF admin sections"] button', 'Levels');
    await openReview();
    const bearer = await validatedBearer(await action(() => instructor.evaluate(() =>
      localStorage.getItem('token'))), adapter, r.mountedActorId, r.mountedSessionId);
    const beforeDelete = await sequence();
    const responsePromise = action(() => instructor.waitForResponse(response => {
      const url = new URL(response.url()); return url.origin === origin &&
        url.pathname === targetPath && response.request().method() === 'DELETE';
    }, { timeout: 15000 }));
    await click(instructor, '[role="dialog"] button', 'Confirm Delete');
    const response = await responsePromise;
    assert([200, 202].includes(response.status()));
    const ack = await response.json();
    const deleted = await verifyMutation({ after: beforeDelete, kind: 'catalog_mutation',
      action: 'delete', stageId: createdId, actorId: r.mountedActorId,
      sessionId: r.mountedSessionId });
    let reads = 0;
    if (response.status() === 200) assert.deepEqual(ack, { message: 'Stage deleted' });
    else {
      assert.equal(ack?.pending, true); assert.equal(ack.operationId, deleted.operation_id);
      const recoveryPath = `/api/ctf/operations/${deleted.operation_id}`;
      const deadline = Date.now() + 30000;
      let checks = 0;
      for (;;) {
        const observed = operationResponses.find(item => item.path === recoveryPath && item.status === 200);
        if (observed) {
          assert.deepEqual(await observed.response.json(), { message: 'Stage deleted' });
          reads = seen.gets.filter(item => item === recoveryPath).length;
          assert(reads >= 1); break;
        }
        if (Date.now() >= deadline) throw Error('Stage-delete browser recovery deadline');
        const button = await action(() => instructor.evaluate(() =>
          [...document.querySelectorAll('[role="status"] button')].some(item =>
            item.textContent.trim() === 'Check status' && !item.disabled)));
        if (button && checks < 3) {
          await click(instructor, '[role="status"] button', 'Check status'); checks++;
        }
        await pause(100);
      }
      assert(seen.gets.every(item => item === recoveryPath), 'Wrong operation recovery target');
    }
    r.confirmed = { originalStatus: response.status(), resolvedStatus: 200,
      sameIdGets: reads, operationId: deleted.operation_id, sequence: deleted.sequence,
      browserAckOperationId: response.status() === 202 ? ack.operationId : null,
      ackMessage: response.status() === 200 ? ack.message : null };
    recordStageDeleteConfirmation(r, seen, targetPath, bearer,
      response.status() === 202 ? `/api/ctf/operations/${deleted.operation_id}` : null);
    r.facts.canonicalDeleteProjection = true;
    const tombstone = await binding(createdId);
    const retained = (await i.migration.query(`SELECT operation_id::text FROM identity.ctf_outbox
      WHERE sequence>$1 AND state='applied'`, [historyBefore])).rows.map(row => row.operation_id);
    const readback = assessStageDeleteReadback({ createdId, baselineStages: baseline,
      remainingStages: await stageRows(), targetStage: await stageRow(createdId),
      preProgressCount: r.preProgressRows, preEventCount: r.preEventRows,
      postProgress: await progressRows(createdId), postEvents: await eventRows(createdId),
      siblingBefore, siblingAfter: (await c.runtime.query(`SELECT to_jsonb(p)::text AS row
        FROM ctf.ctf_progress p WHERE participant_id=1001 ORDER BY id`)).rows,
      binding: tombstone, operationId: deleted.operation_id, sequence: deleted.sequence,
      retainedOperations: retained });
    r.facts.progressAndEventCascaded = readback.cascaded;
    r.facts.identityBindingTombstoned = readback.tombstoned;
    r.facts.canonicalTenAndSiblingPreserved = readback.canonicalTenAndSiblingPreserved;
    r.facts.historyPreserved = readback.historyPreserved &&
      [created.operation_id, started.operation_id].every(id => retained.includes(id));
    r.facts.noModelOrJudge = ledger.length === 0 &&
      JSON.stringify(await judgments()) === JSON.stringify(beforeJudgments);
    for (const fact of FACTS) assert.equal(r.facts[fact], true, fact);
    r.unexpectedApiPaths = [...unexpectedApiPaths];
    r.stage = 'complete'; assertStageDeleteReceipt(r); save(); completed = true;
    return async () => {
      let terminalError = null;
      try {
        recordStageDeleteConfirmation(r, seen, targetPath, bearer,
          response.status() === 202 ? `/api/ctf/operations/${deleted.operation_id}` : null);
        r.facts.noModelOrJudge = ledger.length === 0 &&
          JSON.stringify(await judgments()) === JSON.stringify(beforeJudgments);
        const terminalBinding = await binding(createdId);
        const terminalRetained = (await i.migration.query(`SELECT operation_id::text
          FROM identity.ctf_outbox WHERE sequence>$1 AND state='applied'`,
        [historyBefore])).rows.map(row => row.operation_id);
        const terminal = assessStageDeleteReadback({ createdId, baselineStages: baseline,
          remainingStages: await stageRows(), targetStage: await stageRow(createdId),
          preProgressCount: r.preProgressRows, preEventCount: r.preEventRows,
          postProgress: await progressRows(createdId), postEvents: await eventRows(createdId),
          siblingBefore, siblingAfter: (await c.runtime.query(`SELECT to_jsonb(p)::text AS row
            FROM ctf.ctf_progress p WHERE participant_id=1001 ORDER BY id`)).rows,
          binding: terminalBinding, operationId: deleted.operation_id,
          sequence: deleted.sequence, retainedOperations: terminalRetained });
        r.facts.progressAndEventCascaded = terminal.cascaded;
        r.facts.identityBindingTombstoned = terminal.tombstoned;
        r.facts.canonicalTenAndSiblingPreserved = terminal.canonicalTenAndSiblingPreserved;
        r.facts.historyPreserved = terminal.historyPreserved &&
          [created.operation_id, started.operation_id].every(id => terminalRetained.includes(id));
        const later = (await outboxAfter(deleted.sequence)).rows.filter(row => {
          if (row.kind !== 'catalog_mutation') return false;
          return JSON.parse(row.canonical_command).scope.stageId === String(createdId);
        });
        assert.equal(later.length, 0, 'Late mutation of the deleted stage');
        const terminalDelete = await verifyMutation({ after: beforeDelete,
          kind: 'catalog_mutation', action: 'delete', stageId: createdId,
          actorId: r.mountedActorId, sessionId: r.mountedSessionId });
        assert.equal(terminalDelete.operation_id, deleted.operation_id);
        r.unexpectedApiPaths = [...unexpectedApiPaths];
        assertStageDeleteReceipt(r);
        save();
      } catch (error) {
        r.stage = 'late-validation-failed';
        r.failure = { name: /^[A-Za-z]+Error$/.test(error?.name) ? error.name : 'Error' };
        try { save(); } catch (saveError) {
          const aggregate = new AggregateError([error, saveError],
            'Stage-delete final receipt unavailable'); aggregate.cause = error;
          terminalError = aggregate;
        }
        terminalError ||= error;
      } finally {
        retireStageDeleteListeners({ instructor, onRequest, onResponse, seen,
          primary: terminalError });
      }
      if (terminalError) throw terminalError;
    };
  } catch (error) {
    primary = error;
    r.stage = 'failed'; r.failure = { name: /^[A-Za-z]+Error$/.test(error?.name) ? error.name : 'Error' };
    try { save(); } catch (saveError) {
      const aggregate = new AggregateError([error, saveError], 'Stage-delete failure receipt unavailable');
      aggregate.cause = error; primary = aggregate;
    }
    throw primary;
  } finally {
    const cleanupErrors = [];
    if (other) try { await other.close(); } catch (error) { cleanupErrors.push(error); }
    if (!completed) {
      if (onRequest) try { instructor.off('request', onRequest); } catch (error) { cleanupErrors.push(error); }
      if (onResponse) try { instructor.off('response', onResponse); } catch (error) { cleanupErrors.push(error); }
      seen.physical.length = 0;
      if (createdId === null && createOperationId && UUID.test(createOperationId)) {
        try {
          const row = (await i.migration.query(`SELECT actor_id::text,session_id::text,
            kind,state,canonical_command,canonical_result FROM identity.ctf_outbox
            WHERE operation_id=$1`, [createOperationId])).rows[0];
          if (row?.state === 'applied') {
            const command = JSON.parse(row.canonical_command);
            assert.equal(row.actor_id, String(admin.user.id));
            assert.equal(row.session_id, String(admin.identitySession.id));
            assert.equal(row.kind, 'catalog_mutation');
            assert.equal(command.operationId, createOperationId);
            assert.equal(command.body.action, 'create');
            assert.deepEqual(command.body.fields, fields);
            const projectedId = Number(JSON.parse(row.canonical_result)?.data?.stageId);
            assert(Number.isSafeInteger(projectedId) && projectedId > 10);
            createdId = projectedId;
            r.targetStageId = createdId;
            save();
          } else if (row) r.setupCleanup = { status: 'create-unresolved-no-cleanup' };
        } catch (error) { cleanupErrors.push(error); }
      }
      try {
        const result = await cleanupOwnedStage({ createdId, browserDeletes: seen.deletes,
          createAttempted, exists: async id => {
            const raw = await stageRow(id);
            if (raw === null) return false;
            const row = JSON.parse(raw);
            assert.equal(row.stage_number, STAGE_NUMBER);
            assert.equal(row.stage_name, stageName);
            return true;
          }, request, admin,
          verify: async id => {
            assert.equal(await stageRow(id), null);
            assert.deepEqual(await stageRows(), baseline);
          },
          journal: value => { r.setupCleanup = value; save(); } });
        r.setupCleanup = result;
      } catch (error) { cleanupErrors.push(error); }
      try { save(); } catch (error) { cleanupErrors.push(error); }
    }
    if (cleanupErrors.length) {
      const combined = primary ? [primary, ...cleanupErrors] : cleanupErrors;
      const failure = new AggregateError(combined, 'Stage-delete cleanup failed');
      if (primary) failure.cause = primary;
      throw failure;
    }
  }
}

module.exports = { runStageDeleteRenderedFacet, assertStageDeleteReceipt,
  assertOwnedStageSelection, exactPhysicalStageDelete, recoverSameOperation,
  cleanupOwnedStage, validatedBearer, assessStageDeleteReadback, retireStageDeleteListeners,
  assertOwnedCreateResponse, assertOwnedStartResponse, recordStageDeleteConfirmation,
  openStageDeleteReview, FACTS, STAGE_NUMBER, STAGE_ORDER };
