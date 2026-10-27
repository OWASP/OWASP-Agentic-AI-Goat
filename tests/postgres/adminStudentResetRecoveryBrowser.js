'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// This hook changes delivery only, after Chromium has received the real HTTP 200.
// It never supplies a reset response or substitutes a service/repository result.
function resetResponseIdentity(event, endpoint) {
  if (event.request.method !== 'POST' || event.request.url !== endpoint) return null;
  const headers = Object.fromEntries(Object.entries(event.request.headers).map(([k,v]) => [k.toLowerCase(),v]));
  assert.match(headers['x-reset-operation-id'] || '', UUID);
  assert.equal(event.responseStatusCode, 200, 'loss may be injected only after real successful reset');
  return headers['x-reset-operation-id'];
}
async function installOneResponseLoss(page, endpoint) {
  const client = await page.createCDPSession();
  let dropped = false, failure;
  const tasks = new Set();
  const onPaused = event => {
    const work = (async () => {
      const id = resetResponseIdentity(event, endpoint);
      if (id && !dropped) {
        dropped = id;
        await client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
      } else await client.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(async error => {
      failure = error;
      await client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
    });
    tasks.add(work); void work.finally(() => tasks.delete(work));
  };
  client.on('Fetch.requestPaused', onPaused);
  await client.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
  return {
    operationId() { if (failure) throw failure; assert.ok(dropped, 'successful response was not dropped'); return dropped; },
    async close() {
      await client.send('Fetch.disable');
      await Promise.all([...tasks]);
      client.off('Fetch.requestPaused', onPaused);
      await client.detach();
      if (failure) throw failure;
    },
  };
}
async function clickReset(page) {
  const selector = 'button[title="Erase all Sensitive Info workshop progress for this student"]';
  await page.waitForSelector(selector, { visible: true, timeout: 10000 });
  const control = await page.$(selector);
  await control.evaluate(element => element.scrollIntoView({ block: 'center' }));
  assert.equal(await control.evaluate(element => {
    const r = element.getBoundingClientRect(), s = getComputedStyle(element);
    return !element.disabled && Number(s.opacity) > 0 && element.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));
  }), true);
  await control.click(); // Existing window.confirm is accepted by the owning harness.
}
function assertReplayPreserved({ originalId, replayId, before, after, siblingBefore, siblingAfter }) {
  assert.match(originalId, UUID); assert.equal(replayId, originalId);
  assert.deepEqual(after, before, 'retry must preserve resumed state and original completed journal');
  assert.deepEqual(siblingAfter, siblingBefore, 'retry must preserve sibling state');
}
module.exports = { resetResponseIdentity, installOneResponseLoss, clickReset, assertReplayPreserved };

function assertCompletedCleanupReceipts(snapshot, operationId, ownerId, fromGeneration) {
  const reset = snapshot.resets.find(row => row.operation_id === operationId);
  assert.ok(reset, 'durable reset operation must exist');
  assert.equal(reset.status, 'completed');
  assert.equal(Number(reset.owner_id), ownerId);
  assert.equal(Number(reset.from_generation), fromGeneration);
  assert.equal(Number(reset.to_generation), fromGeneration + 1);
  const expectedKeys = Number(reset.plan_version) === 2
    ? ['finflow_store'] : Number(reset.plan_version) === 1
      ? ['finflow_store', 'legacy_store'] : null;
  assert.ok(expectedKeys, 'reset plan must be a supported durable version');
  const steps = snapshot.steps.filter(row => row.operation_id === operationId);
  assert.deepEqual(steps.map(row => row.step_key).sort(), expectedKeys);
  assert.ok(steps.every(row => row.status === 'completed'));
  const receipts = snapshot.receipts.filter(row => row.operation_id === operationId);
  assert.deepEqual(receipts.map(row => row.step_key).sort(), expectedKeys,
    'every applicable completed reset step must have a published cleanup receipt');
  assert.ok(receipts.every(row => Number(row.owner_id) === ownerId
    && Number(row.from_generation) === fromGeneration
    && Number(row.to_generation) === fromGeneration + 1
    && Number.isFinite(Date.parse(row.completed_at))),
  'published cleanup receipts must bind the exact owner, operation and generation');
  return true;
}
module.exports.assertCompletedCleanupReceipts = assertCompletedCleanupReceipts;

function resetReadinessSnapshot() {
  const button = document.querySelector('button[title="Erase all Sensitive Info workshop progress for this student"]');
  const refresh = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Refresh');
  const text = document.body.innerText;
  return { resetPresent: Boolean(button), resetDisabled: button ? button.disabled : null,
    refreshPresent: Boolean(refresh), refreshDisabled: refresh ? refresh.disabled : null,
    loadingText: /loading/i.test(text), resettingText: /resetting/i.test(text),
    spinnerPresent: Boolean(document.querySelector('[role="progressbar"]')) };
}
module.exports.resetReadinessSnapshot = resetReadinessSnapshot;

async function runRecoveryScenario({ page, base, target, sibling, support,
  requireControlledCompletion = false, record = async () => {} }) {
  const evidence = { status: 'running', phases: [] };
  const browserDeadline = setTimeout(() => { void page.close().catch(() => {}); }, 120000);
  const checkpoint = async (phase, values) => { evidence.phases.push({ phase, ...values }); await record(evidence); };
  const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const endpoint = `${base}/api/admin/students/${target}/workshops/sensitive_info_disclosure/reset`;
  const ids = [], requestStatuses = [];
  const onResponse = response => {
    const url = response.url();
    const kind = url === endpoint ? 'reset' : url === `${base}/api/admin/student-workshop-view/${target}` ? 'student-view' : null;
    if (kind) { requestStatuses.push({ kind, status: response.status() }); if (requestStatuses.length > 30) requestStatuses.shift(); }
  };
  const onRequest = request => {
    if (request.url() === endpoint && request.method() === 'POST') ids.push(request.headers()['x-reset-operation-id']);
  };
  let confirmationFailure;
  const onDialog = dialog => {
    if (dialog.type() !== 'confirm' || !dialog.message().startsWith('Reset Sensitive Info Workshop Progress for ')) {
      confirmationFailure = new Error('Unexpected reset confirmation'); void dialog.dismiss();
    } else void dialog.accept();
  };
  const open = async () => {
    await page.goto(`${base}/admin/student-workshop-view?studentId=${target}`, { waitUntil: 'networkidle0', timeout: 15000 });
    await page.waitForSelector('button[title="Erase all Sensitive Info workshop progress for this student"]', { visible: true, timeout: 10000 });
  };
  const acknowledgedClick = async () => {
    const controller = new AbortController();
    const response = page.waitForResponse(r => r.url() === endpoint && r.request().method() === 'POST',
      { timeout: 15000, signal: controller.signal });
    try {
      const [reply] = await Promise.all([response, clickReset(page)]);
      assert.equal(reply.status(), 200);
      await page.waitForFunction(() => {
        const button = document.querySelector('button[title="Erase all Sensitive Info workshop progress for this student"]');
        return Boolean(button && !button.disabled);
      },
        { timeout: 10000 });
    } catch (error) {
      const readiness = await page.evaluate(resetReadinessSnapshot).catch(() => ({ snapshotUnavailable: true }));
      await checkpoint('acknowledged-click-failed', { readiness, requestStatuses: [...requestStatuses] });
      throw error;
    } finally { controller.abort(); await response.catch(() => {}); }
  };
  page.on('request', onRequest); page.on('response', onResponse); page.on('dialog', onDialog);
  let loss;
  try {
    await support.resume(target, 'before-reset'); await support.resume(sibling, 'sibling-preserved');
    const initial = await support.snapshot(target), siblingBefore = await support.snapshot(sibling);
    assert.ok(initial.tools.length && initial.time.length && siblingBefore.tools.length);
    if (requireControlledCompletion) assert.equal(initial.completions.length, 1,
      'only the controlled preexisting completion is seeded');
    await checkpoint('baseline', { targetSha256: digest(initial), siblingSha256: digest(siblingBefore) });
    await open(); assert.equal(ids.length, 0, 'mount must not issue reset');
    loss = await installOneResponseLoss(page, endpoint);
    await clickReset(page);
    await page.waitForFunction(() => document.body.innerText.includes('Reset completion is uncertain.'), { timeout: 20000 });
    const first = loss.operationId(); await loss.close(); loss = null;
    assert.equal(ids.length, 1); assert.equal(ids[0], first);
    const cleared = await support.snapshot(target);
    await checkpoint('successful-response-dropped', { operationId: first, snapshotSha256: digest(cleared), generation: cleared.state[0]?.generation });
    assert.equal(cleared.state[0].generation, initial.state[0].generation + 1);
    assert.equal(cleared.tools.length, 0); assert.equal(cleared.time.length, 0);
    if (requireControlledCompletion) assert.equal(cleared.completions.length, 0);
    assert.equal(cleared.resets.length, 1); assert.equal(cleared.resets[0].operation_id, first);
    assertCompletedCleanupReceipts(cleared, first, target, initial.state[0].generation);
    assert.deepEqual(await support.snapshot(sibling), siblingBefore);
    await support.resume(target, 'after-lost-response-resumed');
    const resumed = await support.snapshot(target); assert.ok(resumed.tools.length && resumed.time.length);
    await checkpoint('resumed', { snapshotSha256: digest(resumed), nonemptyTools: resumed.tools.length, nonemptyTime: resumed.time.length });
    await open(); assert.equal(ids.length, 1, 'remount must not issue reset');
    await acknowledgedClick();
    assert.equal(ids.length, 2);
    const afterReplay = await support.snapshot(target);
    assertReplayPreserved({ originalId: first, replayId: ids[1], before: resumed, after: afterReplay,
      siblingBefore, siblingAfter: await support.snapshot(sibling) });
    await checkpoint('replay-preserved', { operationId: ids[1], snapshotSha256: digest(afterReplay), siblingSha256: digest(await support.snapshot(sibling)) });
    await acknowledgedClick(); assert.equal(ids.length, 3); assert.notEqual(ids[2], first); assert.match(ids[2], UUID);
    const final = await support.snapshot(target);
    assert.equal(final.state[0].generation, resumed.state[0].generation + 1);
    assert.equal(final.tools.length, 0); assert.equal(final.time.length, 0);
    if (requireControlledCompletion) assert.equal(final.completions.length, 0);
    assert.equal(final.resets.length, 2);
    assert.deepEqual(final.resets.find(row => row.operation_id === first), cleared.resets[0]);
    assert.deepEqual(final.steps.filter(row => row.operation_id === first), cleared.steps);
    assert.deepEqual(final.receipts.filter(row => row.operation_id === first), cleared.receipts);
    assert.ok(final.resets.every(row => row.status === 'completed'));
    assertCompletedCleanupReceipts(final, ids[2], target, resumed.state[0].generation);
    assert.deepEqual(await support.snapshot(sibling), siblingBefore);
    if (confirmationFailure) throw confirmationFailure;
    evidence.status = 'passed';
    await checkpoint('new-explicit-reset', { operationId: ids[2], snapshotSha256: digest(final), generation: final.state[0].generation });
    return { ...evidence, requestOperationIds: ids, realResetPostCount: 3,
      originalGeneration: initial.state[0].generation, finalGeneration: final.state[0].generation,
      replayPreservedResumedState: true, siblingPreserved: true, modelCalls: 0,
      ackLoss: { method: 'POST', path: new URL(endpoint).pathname,
        phase: 'after-real-http-200-before-browser-consumption' },
      markerProvenance: 'controlled repository activity; no objective completion claim' };
  } catch (error) {
    evidence.status = 'failed'; evidence.error = error.message; await record(evidence); throw error;
  } finally {
    clearTimeout(browserDeadline);
    if (loss) await loss.close();
    page.off('request', onRequest); page.off('response', onResponse); page.off('dialog', onDialog);
  }
}
module.exports.runRecoveryScenario = runRecoveryScenario;

const snapshotSha256 = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function clickWithResetDialog(page, action) {
  let finish, fail;
  const handled = new Promise((resolve, reject) => { finish = resolve; fail = reject; });
  const onDialog = dialog => {
    Promise.resolve().then(async () => {
      assert.equal(dialog.type(), 'confirm');
      assert.match(dialog.message(), /^Reset Sensitive Info Workshop Progress for /);
      await action(dialog);
    }).then(finish, fail);
  };
  page.once('dialog', onDialog);
  const timeout = setTimeout(() => fail(new Error('Reset confirmation did not appear')), 10000);
  try { await Promise.all([clickReset(page), handled]); }
  finally { clearTimeout(timeout); page.off('dialog', onDialog); }
}

function createStudentResetQ05Receipt({ target, sibling, cancelBefore, cancelAfter,
  authorityBefore, authorityAfter, recovery, deniedResetPostCount }) {
  assert(Number.isSafeInteger(target) && target > 0 && Number.isSafeInteger(sibling) && sibling > 0 && target !== sibling);
  assert.equal(deniedResetPostCount, 1);
  assert.equal(recovery?.status, 'passed');
  assert.equal(recovery?.requestOperationIds?.length, 3);
  assert.equal(recovery.realResetPostCount, 3);
  assert.match(recovery.requestOperationIds[0], UUID);
  assert.equal(recovery.requestOperationIds[1], recovery.requestOperationIds[0]);
  assert.match(recovery.requestOperationIds[2], UUID);
  assert.notEqual(recovery.requestOperationIds[2], recovery.requestOperationIds[0]);
  assert.equal(recovery.replayPreservedResumedState, true);
  assert.equal(recovery.siblingPreserved, true);
  assert.equal(recovery.modelCalls, 0);
  assert.deepEqual(recovery.ackLoss, { method: 'POST',
    path: `/api/admin/students/${target}/workshops/sensitive_info_disclosure/reset`,
    phase: 'after-real-http-200-before-browser-consumption' });
  assert.equal(recovery.finalGeneration, recovery.originalGeneration + 2);
  const phase = name => {
    const found = recovery.phases.find(item => item.phase === name);
    assert.ok(found, `Missing reset phase ${name}`);
    return found;
  };
  const baseline = phase('baseline'), resumed = phase('resumed'), replay = phase('replay-preserved');
  assert.equal(snapshotSha256(cancelBefore), snapshotSha256(cancelAfter));
  assert.equal(snapshotSha256(authorityBefore), snapshotSha256(authorityAfter));
  assert.equal(resumed.snapshotSha256, replay.snapshotSha256);
  assert.equal(baseline.siblingSha256, replay.siblingSha256);
  return {
    version: 1, status: 'bounded-rendered-student-reset-observed',
    workshopKey: 'sensitive_info_disclosure', targetId: target, siblingId: sibling,
    modelCalls: 0, judgeCalls: 0, canonicalCredit: false,
    seedProvenance: 'controlled-preexisting-completion-not-model-credit',
    facts: {
      cancelNoRequest: true, cancelStateUnchanged: true,
      stagedAuthorityDenied: true, stagedAuthorityNoEffect: true,
      completionSeeded: true, completionCleared: true, timeCleared: true,
      toolActivityCleared: true, durableStepsCompleted: true,
      cleanupReceiptsCompleted: true, lostAckEffectPersisted: true,
      unknownUiNoAutomaticRetry: true, remountNoRequest: true,
      sameIdReplayPreservedResumedState: true, originalReceiptsUnchanged: true,
      newExplicitOperation: true, siblingPreserved: true,
    },
    requestOperationIds: recovery.requestOperationIds,
    realResetPostCount: recovery.realResetPostCount,
    deniedResetPostCount,
    originalGeneration: recovery.originalGeneration,
    finalGeneration: recovery.finalGeneration,
    ackLoss: recovery.ackLoss,
    snapshots: {
      cancel: { before: snapshotSha256(cancelBefore), after: snapshotSha256(cancelAfter) },
      stagedAuthority: { before: snapshotSha256(authorityBefore), after: snapshotSha256(authorityAfter) },
      replay: { before: resumed.snapshotSha256, after: replay.snapshotSha256 },
      sibling: { before: baseline.siblingSha256, after: replay.siblingSha256 },
    },
    excluded: ['bulk-reset', 'other-workshop-reset', 'student-deletion',
      'nonempty-backup-traversal-cleanup', 'inflight-model-cancellation',
      'model-grading', 'full-Q05-denominator'],
  };
}
module.exports.createStudentResetQ05Receipt = createStudentResetQ05Receipt;

async function runStudentResetQ05Scenario({ page, base, target, sibling, support,
  revoke, restore, recover = runRecoveryScenario, record = async () => {} }) {
  const endpoint = `${base}/api/admin/students/${target}/workshops/sensitive_info_disclosure/reset`;
  const open = async () => {
    await page.goto(`${base}/admin/student-workshop-view?studentId=${target}`,
      { waitUntil: 'networkidle0', timeout: 15000 });
    await page.waitForSelector('button[title="Erase all Sensitive Info workshop progress for this student"]',
      { visible: true, timeout: 10000 });
  };
  let resetPosts = 0;
  const partial = { status: 'running', phase: 'fixture-seed', phases: [] };
  const checkpoint = async (phase, values = {}) => {
    partial.phase = phase;
    partial.phases.push({ phase, ...values });
    await record({ ...partial, resetPosts });
  };
  const onRequest = request => { if (request.url() === endpoint && request.method() === 'POST') resetPosts++; };
  page.on('request', onRequest);
  try {
    await support.seedControlledCompletion(target);
    await support.seedControlledCompletion(sibling);
    await support.resume(target, 'controlled-before-cancel');
    await support.resume(sibling, 'controlled-sibling-preserved');
    const cancelBefore = await support.snapshot(target), siblingBefore = await support.snapshot(sibling);
    assert.equal(cancelBefore.completions.length, 1);
    assert.ok(cancelBefore.time.length && cancelBefore.tools.length);
    await checkpoint('controlled-preexisting-state', { targetSha256: snapshotSha256(cancelBefore),
      siblingSha256: snapshotSha256(siblingBefore), completionCount: cancelBefore.completions.length,
      toolActivityCount: cancelBefore.tools.length, timeRows: cancelBefore.time.length });
    await open();
    await clickWithResetDialog(page, dialog => dialog.dismiss());
    assert.equal(resetPosts, 0, 'Cancel must not issue a reset POST');
    const cancelAfter = await support.snapshot(target);
    assert.deepEqual(cancelAfter, cancelBefore);
    assert.deepEqual(await support.snapshot(sibling), siblingBefore);
    await checkpoint('cancel-no-request', { before: snapshotSha256(cancelBefore),
      after: snapshotSha256(cancelAfter) });

    await open();
    await checkpoint('authority-dialog-staged');
    const authorityBefore = await support.snapshot(target);
    const deniedController = new AbortController();
    const deniedResponse = page.waitForResponse(response => response.url() === endpoint
      && response.request().method() === 'POST' && response.status() === 403,
    { timeout: 15000, signal: deniedController.signal });
    try {
      await Promise.all([deniedResponse, clickWithResetDialog(page, async dialog => {
        await revoke();
        await dialog.accept();
      })]);
    } finally {
      deniedController.abort();
      await deniedResponse.catch(() => {});
      await restore();
    }
    assert.equal(resetPosts, 1, 'a staged confirmation must reach the real denied POST exactly once');
    const authorityAfter = await support.snapshot(target);
    assert.deepEqual(authorityAfter, authorityBefore, '403 must have no reset effect');
    assert.deepEqual(await support.snapshot(sibling), siblingBefore);
    await checkpoint('authority-denied', { statusCode: 403,
      before: snapshotSha256(authorityBefore), after: snapshotSha256(authorityAfter) });
    page.off('request', onRequest);

    const recovery = await recover({ page, base, target, sibling, support,
      requireControlledCompletion: true,
      record: async evidence => {
        partial.phase = 'recovery-' + (evidence.phases.at(-1)?.phase || evidence.status);
        partial.recovery = { status: evidence.status, phases: evidence.phases,
          requestOperationIds: evidence.requestOperationIds || [] };
        await record({ ...partial, resetPosts });
      } });
    const receipt = createStudentResetQ05Receipt({ target, sibling, cancelBefore,
      cancelAfter, authorityBefore, authorityAfter, recovery, deniedResetPostCount: resetPosts });
    await record(receipt);
    return receipt;
  } catch (error) {
    await record({ ...partial, status: 'failed', resetPosts,
      failure: { phase: partial.phase, errorName: error?.name || 'Error' } });
    throw error;
  } finally {
    page.off('request', onRequest);
    await restore();
  }
}
module.exports.runStudentResetQ05Scenario = runStudentResetQ05Scenario;

async function runAccessDenialScenario({ page, base, target, sibling, support, revoke, restore, announce, record = async () => {} }) {
  const selector = 'button[title="Erase all Sensitive Info workshop progress for this student"]';
  const endpoint = `${base}/api/admin/student-workshop-view/${target}`;
  const before = await support.snapshot(target), siblingBefore = await support.snapshot(sibling);
  let resetPosts = 0;
  const onRequest = request => { if (request.method() === 'POST' && request.url().endsWith('/workshops/sensitive_info_disclosure/reset')) resetPosts++; };
  page.on('request', onRequest);
  const evidence = { status: 'running', background: true, modelCalls: 0 };
  try {
    await page.waitForSelector(selector, { visible: true, timeout: 10000 });
    // Establish a real poll baseline before changing its canonical revision.
    await page.waitForResponse(r => new URL(r.url()).pathname === '/api/changes/revisions' && r.status() === 200, { timeout: 25000 });
    const controller = new AbortController();
    const denied = page.waitForResponse(r => r.url() === endpoint && r.request().method() === 'GET' && r.status() === 403,
      { timeout: 25000, signal: controller.signal });
    try {
      await Promise.all([denied, (async () => { await revoke(); await announce(); })()]);
    } finally { controller.abort(); await denied.catch(() => {}); }
    await page.waitForFunction(() => document.body.innerText.includes('Student workshop data is no longer accessible.')
      && !document.querySelector('button[title="Erase all Sensitive Info workshop progress for this student"]'), { timeout: 10000 });
    evidence.deniedStatus = 403; evidence.privateDetailCleared = true; evidence.resetControlAbsent = true;
    await record(evidence);
    await restore();
    const controller2 = new AbortController();
    const authorized = page.waitForResponse(r => r.url() === endpoint && r.request().method() === 'GET' && r.status() === 200,
      { timeout: 10000, signal: controller2.signal });
    try {
      await Promise.all([authorized, (async () => {
        const buttons = await page.$$('button');
        for (const button of buttons) if (await button.evaluate(e => e.textContent.trim() === 'Refresh')) { await button.click(); return; }
        throw Error('Refresh control absent');
      })()]);
    } finally { controller2.abort(); await authorized.catch(() => {}); }
    await page.waitForSelector(selector, { visible: true, timeout: 10000 });
    assert.deepEqual(await support.snapshot(target), before);
    assert.deepEqual(await support.snapshot(sibling), siblingBefore);
    assert.equal(resetPosts, 0);
    Object.assign(evidence, { status: 'passed', authorizedStatus: 200, targetUnchanged: true, siblingUnchanged: true, resetPosts });
    await record(evidence); return evidence;
  } catch (error) { evidence.status = 'failed'; evidence.error = error.message; await record(evidence); throw error;
  } finally { page.off('request', onRequest); await restore(); }
}
module.exports.runAccessDenialScenario = runAccessDenialScenario;

async function runRosterDenialScenario({ page, base, target, sibling, support, privateUsername, revoke, restore, record = async () => {} }) {
  const endpoint = `${base}/api/admin/users`;
  const before = await support.snapshot(target), siblingBefore = await support.snapshot(sibling);
  const evidence = { status: 'running', modelCalls: 0 };
  const rosterText = () => page.evaluate(() => {
    const heading = [...document.querySelectorAll('h3')].find(e => e.textContent.includes('Active Users & Their Activity'));
    if (!heading) throw Error('Roster section absent');
    return heading.parentElement.parentElement.innerText;
  });
  const observe = async (status, action) => {
    const controller = new AbortController();
    const pending = page.waitForResponse(r => new URL(r.url()).pathname === new URL(endpoint).pathname
      && r.request().method() === 'GET' && r.status() === status, { timeout: 15000, signal: controller.signal });
    try { await Promise.all([pending, action()]); }
    finally { controller.abort(); await pending.catch(() => {}); }
  };
  const refresh = async () => {
    const button = await page.evaluateHandle(() => {
      const heading = [...document.querySelectorAll('h3')].find(e => e.textContent.includes('Active Users & Their Activity'));
      return heading?.parentElement.querySelector('button');
    });
    const element = button.asElement(); assert.ok(element, 'Roster Refresh absent');
    await element.evaluate(e => e.scrollIntoView({ block: 'center' }));
    assert.equal(await element.evaluate(e => { const r = e.getBoundingClientRect(); return !e.disabled && e.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)); }), true);
    try { await element.click(); } finally { await button.dispose(); }
  };
  try {
    await observe(200, () => page.goto(`${base}/admin/activity`, { waitUntil: 'domcontentloaded', timeout: 15000 }));
    await page.waitForFunction(name => {
      const h = [...document.querySelectorAll('h3')].find(e => e.textContent.includes('Active Users & Their Activity'));
      return h?.parentElement.parentElement.innerText.includes(name);
    }, { timeout: 10000 }, privateUsername);
    assert.ok((await rosterText()).includes(privateUsername));
    await revoke(); await observe(403, refresh);
    await page.waitForFunction(name => {
      const h = [...document.querySelectorAll('h3')].find(e => e.textContent.includes('Active Users & Their Activity'));
      const text = h?.parentElement.parentElement.innerText || '';
      return text.includes('Active user data is no longer accessible.') && !text.includes(name);
    }, { timeout: 10000 }, privateUsername);
    evidence.deniedStatus = 403; evidence.privateRosterCleared = true; await record(evidence);
    await restore(); await observe(200, refresh);
    await page.waitForFunction(name => {
      const h = [...document.querySelectorAll('h3')].find(e => e.textContent.includes('Active Users & Their Activity'));
      const text = h?.parentElement.parentElement.innerText || '';
      return text.includes(name) && !text.includes('no longer accessible');
    }, { timeout: 10000 }, privateUsername);
    assert.deepEqual(await support.snapshot(target), before); assert.deepEqual(await support.snapshot(sibling), siblingBefore);
    Object.assign(evidence, { status: 'passed', restoredStatus: 200, targetUnchanged: true, siblingUnchanged: true });
    await record(evidence); return evidence;
  } catch (error) { evidence.status = 'failed'; evidence.error = error.message; await record(evidence); throw error;
  } finally { await restore(); }
}
module.exports.runRosterDenialScenario = runRosterDenialScenario;

async function runInspectorDenialScenario({ page, base, target, runId, receiptText, revoke, restore, snapshot, record = async () => {} }) {
  const before = await snapshot(); const evidence = { status: 'running', modelCalls: 0, receiptProvenance: 'controlled persisted inconclusive fixture; not model or credit proof' };
  const shell = '[aria-label="Administrator agent run inspector"]'; let posts = 0;
  const onRequest = request => { if (request.method() === 'POST') posts++; };
  page.on('request', onRequest);
  const observe = async (status, action) => {
    const controller = new AbortController();
    const pending = page.waitForResponse(r => new URL(r.url()).pathname === '/api/admin/agent-runs'
      && r.request().method() === 'GET' && r.status() === status, { timeout: 15000, signal: controller.signal });
    try { await Promise.all([pending, action()]); } finally { controller.abort(); await pending.catch(() => {}); }
  };
  const refresh = async () => {
    const buttons = await page.$$(`${shell} button`);
    for (const button of buttons) if (await button.evaluate(e => e.textContent.trim() === 'Refresh')) {
      await button.evaluate(e => e.scrollIntoView({ block: 'center' }));
      assert.equal(await button.evaluate(e => { const r=e.getBoundingClientRect(); return !e.disabled && e.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)); }), true);
      await button.click(); return;
    }
    throw Error('Inspector Refresh absent');
  };
  try {
    await observe(200, () => page.goto(`${base}/admin/agent-runs`, { waitUntil: 'domcontentloaded', timeout: 15000 }));
    await observe(200, () => page.type('[aria-label="Owner ID"]', String(target)));
    const visible = () => page.waitForFunction((selector, id, text) => {
      const e=document.querySelector(selector);return Boolean(e?.innerText.includes(id) && e.innerText.includes(text));
    }, { timeout: 10000 }, shell, runId, receiptText);
    await visible();
    await revoke(); await observe(403, refresh);
    await page.waitForFunction((selector, id, text) => {
      const e=document.querySelector(selector); return Boolean(e && !e.innerText.includes(id) && !e.innerText.includes(text)
        && !e.querySelector('[aria-label="Authoritative Judge receipts"]'));
    }, { timeout: 10000 }, shell, runId, receiptText);
    evidence.deniedStatus=403; evidence.privateDetailRetired=true; await record(evidence);
    await restore(); await observe(200, refresh); await visible();
    assert.deepEqual(await snapshot(), before); assert.equal(posts,0);
    Object.assign(evidence,{ status:'passed',restoredStatus:200,immutableRunsAndReceipts:true,postCount:posts });
    await record(evidence); return evidence;
  } catch(error) { evidence.status='failed';evidence.error=error.message;await record(evidence);throw error;
  } finally { page.off('request',onRequest);await restore(); }
}
module.exports.runInspectorDenialScenario=runInspectorDenialScenario;
