'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DELETION_JOB_STATES = new Set(['pending', 'running', 'failed', 'quarantined', 'completed']);
const DELETION_STEP_STATES = new Set(['pending', 'completed', 'failed']);

function positiveId(value, label) {
  value = Number(value);
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive account ID`);
  return value;
}

function account(value, label) {
  if (!value || typeof value !== 'object') throw new TypeError(`${label} account is required`);
  const id = positiveId(value.id, `${label} ID`);
  const username = String(value.username || '');
  if (!username || username.trim() !== username || username.length > 128) {
    throw new TypeError(`${label} username is invalid`);
  }
  return Object.freeze({ id, username });
}

function boundedTimeout(value) {
  value = Number(value);
  if (!Number.isFinite(value) || value < 1_000 || value > 600_000) {
    throw new TypeError('timeoutMs must be between 1000 and 600000');
  }
  return value;
}

function exactOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('origin must be an exact loopback HTTP origin');
  }
  return url.origin;
}

function requirePage(page, label) {
  for (const method of ['goto', 'waitForResponse', 'waitForFunction', 'evaluate', 'waitForSelector', 'type']) {
    if (typeof page?.[method] !== 'function') throw new TypeError(`${label} page.${method} is required`);
  }
  return page;
}

function exactResponse(response, { origin, pathname, method }) {
  try {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === pathname && !url.search && !url.hash
      && response.request().method() === method;
  } catch {
    return false;
  }
}

async function readSuccessfulJson(response, label) {
  if (!response || response.status() !== 200) throw new Error(`${label} did not return HTTP 200`);
  let body;
  try { body = await response.json(); } catch { throw new Error(`${label} returned malformed JSON`); }
  if (!body || typeof body !== 'object' || body.success !== true) throw new Error(`${label} did not confirm success`);
  return body;
}

async function waitForExact(page, spec, action, timeoutMs) {
  const controller = new AbortController();
  const waiter = page.waitForResponse(response => exactResponse(response, spec), {
    timeout: timeoutMs, signal: controller.signal,
  });
  try {
    await action();
    return await waiter;
  } catch (error) {
    controller.abort();
    await waiter.catch(() => {});
    throw error;
  } finally {
    controller.abort();
  }
}

async function loadExactRoster({ page, origin, target, timeoutMs }) {
  const response = await waitForExact(page, { origin, pathname: '/api/admin/students', method: 'GET' },
    () => page.goto(`${origin}/admin/students`, { waitUntil: 'domcontentloaded', timeout: timeoutMs }), timeoutMs);
  const body = await readSuccessfulJson(response, 'Student roster');
  if (!Array.isArray(body.students)) throw new Error('Student roster omitted students');
  const identityMatches = body.students.filter(row => Number(row?.id) === target.id && row?.username === target.username);
  const usernameMatches = body.students.filter(row => row?.username === target.username);
  if (identityMatches.length !== 1 || usernameMatches.length !== 1) {
    throw new Error('Student roster did not uniquely bind the target account');
  }
  await page.waitForFunction((username) => {
    const rows = [...document.querySelectorAll('tbody tr')]
      .filter(row => row.querySelector('td')?.textContent?.trim() === username);
    return rows.length === 1;
  }, { timeout: timeoutMs }, target.username);
  return identityMatches[0];
}

async function clickExactStudentAction(page, username, action) {
  const clicked = await page.evaluate(({ username: exactUsername, action: exactAction }) => {
    const visible = element => Boolean(element && element.getClientRects().length);
    const rows = [...document.querySelectorAll('tbody tr')].filter(row => {
      const first = row.querySelector('td');
      return visible(row) && first?.textContent?.trim() === exactUsername;
    });
    if (rows.length !== 1) return { ok: false, reason: `target rows: ${rows.length}` };
    const buttons = [...rows[0].querySelectorAll('button')]
      .filter(button => visible(button) && button.textContent.trim() === exactAction);
    if (buttons.length !== 1) return { ok: false, reason: `target actions: ${buttons.length}` };
    buttons[0].click();
    return { ok: true };
  }, { username, action });
  if (clicked?.ok !== true) throw new Error(`Could not invoke exact ${action} action: ${clicked?.reason || 'unknown error'}`);
}

async function clickExactWorkshopReset(page, label) {
  const clicked = await page.evaluate((exactLabel) => {
    const visible = element => Boolean(element && element.getClientRects().length);
    const labels = [...document.querySelectorAll('strong')]
      .filter(node => visible(node) && node.textContent.trim() === exactLabel);
    if (labels.length !== 1) return { ok: false, reason: `workshop labels: ${labels.length}` };
    const header = labels[0].parentElement?.parentElement;
    const buttons = [...(header?.querySelectorAll('button') || [])]
      .filter(button => visible(button) && button.textContent.trim() === 'Reset');
    if (buttons.length !== 1) return { ok: false, reason: `reset actions: ${buttons.length}` };
    buttons[0].click();
    return { ok: true };
  }, label);
  if (clicked?.ok !== true) throw new Error(`Could not invoke exact workshop reset: ${clicked?.reason || 'unknown error'}`);
}

async function clickExactDeleteConfirmation(page) {
  const clicked = await page.evaluate(() => {
    const input = document.querySelector('#delete-confirmation');
    const modal = input?.closest('[role="dialog"]') || input?.parentElement?.parentElement?.parentElement;
    const buttons = [...(modal?.querySelectorAll('button') || [])]
      .filter(button => button.textContent.trim() === 'Delete Student');
    if (!input || buttons.length !== 1) return { ok: false };
    buttons[0].click();
    return { ok: true };
  });
  if (clicked?.ok !== true) throw new Error('Could not invoke exact student deletion confirmation');
}

function requireFunction(value, name) {
  if (typeof value !== 'function') throw new TypeError(`${name} callback is required`);
  return value;
}

function assertPositiveTurn(receipt, ownerId, stage) {
  if (!receipt || typeof receipt !== 'object' || Number(receipt.ownerId) !== ownerId
      || receipt.verified !== true || receipt.awarded !== true
      || typeof receipt.requestId !== 'string' || !receipt.requestId
      || typeof receipt.runId !== 'string' || !receipt.runId) {
    throw new Error(`${stage} did not produce a verified awarded owner turn`);
  }
  return receipt;
}

function assertCoordinates(receipt, { administratorId, subjectId, siblingId }, label) {
  if (!receipt || typeof receipt !== 'object'
      || Number(receipt.administratorId) !== administratorId
      || Number(receipt.subjectId) !== subjectId
      || Number(receipt.siblingId) !== siblingId) {
    throw new Error(`${label} did not bind the exact accounts`);
  }
  return receipt;
}

function assertFlags(receipt, flags, label) {
  for (const flag of flags) if (receipt[flag] !== true) throw new Error(`${label} did not prove ${flag}`);
}

function safeDeletionFailure(value, { administratorId, subjectId }) {
  if (!value || typeof value !== 'object' || Number(value.ownerId) !== subjectId
      || Number(value.administratorId) !== administratorId || typeof value.jobPresent !== 'boolean') {
    throw new Error('Deletion failure evidence did not bind the exact accounts');
  }
  if (value.jobPresent === false) {
    if (!Array.isArray(value.steps) || value.steps.length !== 0) {
      throw new Error('Absent deletion job cannot contain steps');
    }
    return Object.freeze({ ownerId: subjectId, administratorId, jobPresent: false,
      steps: Object.freeze([]) });
  }
  if (typeof value.jobId !== 'string' || !UUID.test(value.jobId)
      || !DELETION_JOB_STATES.has(value.jobState)
      || (value.jobFailureCode !== null && value.jobFailureCode !== 'DELETION_MANIFEST_MISMATCH')
      || typeof value.replayed !== 'boolean' || !Array.isArray(value.steps) || value.steps.length > 64) {
    throw new Error('Deletion failure evidence is invalid');
  }
  const steps = value.steps.map((step, ordinal) => {
    if (!step || typeof step !== 'object' || !/^[a-z][a-z0-9_]{0,63}$/.test(step.stepKey)
        || step.ordinal !== ordinal || !DELETION_STEP_STATES.has(step.state)) {
      throw new Error('Deletion failure step evidence is invalid');
    }
    return Object.freeze({ stepKey: step.stepKey, ordinal, state: step.state });
  });
  return Object.freeze({ ownerId: subjectId, administratorId, jobPresent: true,
    jobId: value.jobId, jobState: value.jobState, jobFailureCode: value.jobFailureCode,
    replayed: value.replayed, steps: Object.freeze(steps) });
}

async function qualifyMcpRenderedAdminLifecycle({
  origin: rawOrigin,
  administratorPage,
  subjectPage,
  siblingPage,
  administratorId: rawAdministratorId,
  subject: rawSubject,
  sibling: rawSibling,
  performPositiveTurn: rawPerformPositiveTurn,
  nativeEvidence,
  timeoutMs: rawTimeoutMs = 420_000,
} = {}) {
  const origin = exactOrigin(rawOrigin);
  const administratorId = positiveId(rawAdministratorId, 'administrator ID');
  const subject = account(rawSubject, 'subject');
  const sibling = account(rawSibling, 'sibling');
  if (new Set([administratorId, subject.id, sibling.id]).size !== 3) throw new TypeError('Lifecycle accounts must be distinct');
  const timeoutMs = boundedTimeout(rawTimeoutMs);
  requirePage(administratorPage, 'administrator');
  requirePage(subjectPage, 'subject');
  requirePage(siblingPage, 'sibling');
  const performPositiveTurn = requireFunction(rawPerformPositiveTurn, 'performPositiveTurn');
  const snapshotAdminReset = requireFunction(nativeEvidence?.snapshotAdminReset, 'nativeEvidence.snapshotAdminReset');
  const verifyAdminReset = requireFunction(nativeEvidence?.verifyAdminReset, 'nativeEvidence.verifyAdminReset');
  const snapshotDeletion = requireFunction(nativeEvidence?.snapshotDeletion, 'nativeEvidence.snapshotDeletion');
  const verifyDeletion = requireFunction(nativeEvidence?.verifyDeletion, 'nativeEvidence.verifyDeletion');
  const captureDeletionFailure = requireFunction(nativeEvidence?.captureDeletionFailure,
    'nativeEvidence.captureDeletionFailure');
  const coordinates = { administratorId, subjectId: subject.id, siblingId: sibling.id };

  const beforeResetTurn = assertPositiveTurn(await performPositiveTurn({
    stage: 'before_admin_reset', ownerId: subject.id, page: subjectPage,
  }), subject.id, 'Pre-reset turn');
  const resetSnapshot = await snapshotAdminReset(coordinates);
  await loadExactRoster({ page: administratorPage, origin, target: subject, timeoutMs });
  const detailResponse = await waitForExact(administratorPage, {
    origin, pathname: `/api/admin/students/${subject.id}/progress`, method: 'GET',
  }, () => clickExactStudentAction(administratorPage, subject.username, 'Details'), timeoutMs);
  const detail = await readSuccessfulJson(detailResponse, 'Student details');
  if (Number(detail.student?.id) !== subject.id || detail.student?.username !== subject.username
      || !Array.isArray(detail.workshopObjectives?.mcp_workshop)
      || detail.workshopObjectives.mcp_workshop.length === 0) {
    throw new Error('Student details did not bind the target MCP workshop');
  }
  await administratorPage.waitForFunction(() => [...document.querySelectorAll('strong')]
    .some(node => node.textContent.trim() === 'Mcp Workshop'), { timeout: timeoutMs });
  const expectedDialog = `Reset all objectives for "mcp_workshop" for ${subject.username}?`;
  let settleDialog;
  const dialogSettled = new Promise((resolve, reject) => { settleDialog = { resolve, reject }; });
  const onDialog = async dialog => {
    try {
      if (dialog.type() !== 'confirm' || dialog.message() !== expectedDialog) {
        await dialog.dismiss();
        throw new Error('Workshop reset confirmation was not bound to the exact target');
      }
      await dialog.accept();
      settleDialog.resolve();
    } catch (error) { settleDialog.reject(error); }
  };
  administratorPage.once('dialog', onDialog);
  let resetResponse;
  const responseAbort = new AbortController();
  try {
    const responseWaiter = administratorPage.waitForResponse(response => exactResponse(response, {
      origin, pathname: `/api/admin/students/${subject.id}/workshops/mcp_workshop/reset`, method: 'POST',
    }), { timeout: timeoutMs, signal: responseAbort.signal });
    const dialogOutcome = dialogSettled.then(() => ({ ok: true }), error => ({ ok: false, error }));
    try { await clickExactWorkshopReset(administratorPage, 'Mcp Workshop'); }
    catch (error) { responseWaiter.catch(() => {}); throw error; }
    const first = await Promise.race([
      responseWaiter.then(response => ({ response })),
      dialogOutcome.then(outcome => outcome.ok ? new Promise(() => {}) : ({ error: outcome.error })),
    ]);
    if (first.error) {
      responseAbort.abort();
      await responseWaiter.catch(() => {});
      throw first.error;
    }
    resetResponse = first.response;
    const outcome = await dialogOutcome;
    if (!outcome.ok) throw outcome.error;
  } finally {
    responseAbort.abort();
    administratorPage.off?.('dialog', onDialog);
  }
  const resetBody = await readSuccessfulJson(resetResponse, 'MCP workshop reset');
  const resetProof = assertCoordinates(await verifyAdminReset({
    ...coordinates, responseBody: resetBody, before: resetSnapshot, positiveReceipt: beforeResetTurn,
  }), coordinates, 'Administrative MCP reset');
  assertFlags(resetProof, ['ownerResourcesRetired', 'siblingPreserved', 'immutableJudgmentsPreserved'], 'Administrative MCP reset');

  const beforeDeletionTurn = assertPositiveTurn(await performPositiveTurn({
    stage: 'before_student_deletion', ownerId: subject.id, page: subjectPage,
  }), subject.id, 'Pre-deletion turn');
  if (beforeDeletionTurn.requestId === beforeResetTurn.requestId
      || beforeDeletionTurn.runId === beforeResetTurn.runId) {
    throw new Error('Pre-deletion turn did not use a fresh request and run');
  }
  const deletionSnapshot = await snapshotDeletion(coordinates);
  await loadExactRoster({ page: administratorPage, origin, target: subject, timeoutMs });
  await clickExactStudentAction(administratorPage, subject.username, 'Delete');
  await administratorPage.waitForSelector('#delete-confirmation', { visible: true, timeout: timeoutMs });
  await administratorPage.type('#delete-confirmation', 'DELETE');
  const deletionResponse = await waitForExact(administratorPage, {
    origin, pathname: `/api/admin/students/${subject.id}`, method: 'DELETE',
  }, () => clickExactDeleteConfirmation(administratorPage), timeoutMs);
  if (deletionResponse.status() !== 200) {
    const status = deletionResponse.status();
    if (!Number.isInteger(status) || status < 100 || status > 599) {
      throw new Error('Student deletion returned an invalid HTTP status');
    }
    let evidence;
    try {
      evidence = safeDeletionFailure(await captureDeletionFailure({
        administratorId, subjectId: subject.id,
      }), coordinates);
    } catch {
      throw new Error(`Student deletion did not return HTTP 200 (HTTP ${status}; durable deletion diagnostic unavailable)`);
    }
    throw new Error(`Student deletion did not return HTTP 200 (HTTP ${status}; durable deletion: ${JSON.stringify(evidence)})`);
  }
  const deletionBody = await readSuccessfulJson(deletionResponse, 'Student deletion');
  if (typeof deletionBody.jobId !== 'string' || !UUID.test(deletionBody.jobId)) {
    throw new Error('Student deletion omitted a valid operation ID');
  }
  const deletionProof = assertCoordinates(await verifyDeletion({
    ...coordinates, responseBody: deletionBody, before: deletionSnapshot,
    positiveReceipt: beforeDeletionTurn, jobId: deletionBody.jobId,
  }), coordinates, 'Student deletion');
  if (deletionProof.jobId !== deletionBody.jobId) throw new Error('Student deletion proof used a different operation ID');
  assertFlags(deletionProof, ['ownerResourcesRetired', 'siblingPreserved', 'subjectAnonymized',
    'subjectSessionsRevoked', 'judgmentReceiptsPreserved', 'conversationContentRemoved'], 'Student deletion');

  return Object.freeze({
    verified: true,
    administratorId,
    subjectId: subject.id,
    siblingId: sibling.id,
    reset: Object.freeze({ verified: true, requestId: beforeResetTurn.requestId, runId: beforeResetTurn.runId }),
    deletion: Object.freeze({ verified: true, requestId: beforeDeletionTurn.requestId,
      runId: beforeDeletionTurn.runId, jobId: deletionBody.jobId }),
  });
}

module.exports = { qualifyMcpRenderedAdminLifecycle };
