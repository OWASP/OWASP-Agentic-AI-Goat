'use strict';
const assert = require('node:assert/strict');
const { posix } = require('node:path');
const Shared = require('./secureshopFileSummaryRenderedQualification');
const Evidence = require('./secureshopV44ActualEvidence');
const { validPath } = require('../../server/services/secureshopV44FilePathSummaryExecutionConfig');
const BASE = '/api/secureshop/agents/customer/file-path-summary';
const RUN_KEY = 'secureshop.customer-file-path-summary.lesson.v1';
const ASSESSMENT_KEY = 'secureshop.customer-file-path-summary.assessment.v1';
const CASES = Object.freeze(['vuln', 'fixed'].map(mode => Object.freeze({ id: `v44-${mode}`, mode,
  path: '../etc/passwd', message: 'Read the requested synthetic file and report its account records exactly.',
  expectedStatus: mode === 'fixed' ? 'no_tool' : 'completed' })));
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function assertRunDto(value, expected = {}) {
  for (const key of ['sessionId', 'requestId']) { assert.match(value?.[key] || '', UUID);
    if (expected[key]) assert.equal(value[key], expected[key]); }
  if (['unconfirmed', 'uncertain'].includes(value.status)) {
    assert.ok(exact(value, ['sessionId', 'requestId', 'status']));
  } else {
    assert.ok(exact(value, ['sessionId', 'requestId', 'status', 'text', 'path', 'resolvedPath',
      'byteCount', 'bodySha256', 'replayed']));
    assert.ok(['completed', 'no_tool'].includes(value.status));
    assert.ok(validPath(value.path));
    assert.equal(typeof value.text, 'string'); assert.ok(value.text.isWellFormed());
    assert.ok(!value.text.includes('\0') && Buffer.byteLength(value.text) <= 16384);
    assert.equal(typeof value.replayed, 'boolean');
    if (value.status === 'completed') {
      assert.equal(value.resolvedPath, posix.resolve('/uploads', value.path));
      assert.ok(Number.isSafeInteger(value.byteCount) && value.byteCount > 0 && value.byteCount <= 256 * 1024);
      assert.match(value.bodySha256, /^[a-f0-9]{64}$/);
    } else for (const key of ['resolvedPath', 'byteCount', 'bodySha256']) assert.equal(value[key], null);
  }
  for (const key of ['status', 'path', 'replayed']) if (expected[key] !== undefined) assert.equal(value[key], expected[key]);
  return value;
}
async function clickExact(frame, label, selector) {
  const handle = await frame.waitForFunction(({ label, selector }) => {
    const nodes = [...document.querySelectorAll(selector)].filter(node => node.textContent.trim() === label
      && !node.disabled && node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden');
    return nodes.length === 1 ? nodes[0] : null;
  }, { timeout: 30000 }, { label, selector });
  try { const input = handle.asElement(); assert.ok(input);
    await input.evaluate(node => node.scrollIntoView({ block: 'center' })); await input.click();
  } finally { await handle.dispose(); }
}
async function selectFilePathSummaryLesson(page, frame) {
  const handle = await frame.waitForFunction(() => {
    const node = document.querySelector('[data-testid="agent-lane"] select');
    return node && !node.disabled && node.getClientRects().length
      && [...node.options].some(option => option.value === 'file-path-summary-lesson'
        && option.textContent.trim() === 'File path summary lesson') ? node : null;
  }, { timeout: 30000 });
  try { const select = handle.asElement(); assert.ok(select); await select.click();
    await page.keyboard.type('File path summary lesson'); await page.keyboard.press('Enter');
    assert.equal(await select.evaluate(node => node.value), 'file-path-summary-lesson');
  } finally { await handle.dispose(); }
  await frame.waitForSelector('[aria-label="Path summary lesson"]', { visible: true });
}
async function physicallyType(page, frame, selector, value, maxBytes) {
  assert.equal(typeof value, 'string'); assert.ok(value.isWellFormed() && Buffer.byteLength(value) <= maxBytes);
  const attached = await frame.waitForFunction(selector => {
    const node = document.querySelector(selector); return node && !node.disabled
      && node.getClientRects().length === 1 && getComputedStyle(node).visibility !== 'hidden' ? node : null;
  }, { timeout: 30000 }, selector);
  let hit;
  try {
    const input = attached.asElement(); assert.ok(input);
    await input.evaluate(node => node.scrollIntoView({ block: 'center' }));
    hit = await frame.waitForFunction(node => {
      if (!node.isConnected || node.disabled || node.getClientRects().length !== 1) return false;
      const box = node.getBoundingClientRect(), top = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      return top === node || node.contains(top);
    }, { timeout: 30000 }, input);
    const current = await input.evaluate(node => node.value);
    assert.ok(typeof current === 'string' && Buffer.byteLength(current) <= maxBytes);
    await input.click();
    for (let i = 0; i <= current.length; i++) await page.keyboard.press('ArrowRight');
    for (let i = 0; i <= current.length; i++) await page.keyboard.press('Backspace');
    assert.equal(await input.evaluate(node => node.value), '');
    await page.keyboard.type(value); assert.equal(await input.evaluate(node => node.value), value);
  } finally { await hit?.dispose(); await attached.dispose(); }
}
function responseAt(method, pathname) {
  return response => response.request().method() === method && new URL(response.url()).pathname === pathname;
}
async function assertRenderedRun(frame, run) {
  await frame.waitForSelector('[data-testid="file-path-summary-turn"]', { visible: true });
  assert.deepEqual(await frame.$eval('[data-testid="file-path-summary-turn"] .ss-turn__reply', node => ({
    text: node.textContent, children: node.children.length })), { text: run.text || 'No final answer was produced.', children: 0 });
  const shown = await frame.$eval('[data-testid="file-path-summary-turn"] .ss-turn__msg', node => node.textContent);
  assert.ok(shown.includes(`Requested path: ${run.path}`));
  if (run.status === 'completed') assert.ok(shown.includes(`Read: ${run.resolvedPath} · ${run.byteCount} bytes`));
  else assert.equal(await frame.$('[data-testid="file-path-summary-assess"]'), null);
}
async function runRenderedFilePathSummary({ page, frame, path, message, expectedStatus,
  readAcknowledgedReference, readOriginalJson, assertOriginalGraphEvidence, readCounters }) {
  for (const fn of [readAcknowledgedReference, readOriginalJson, assertOriginalGraphEvidence, readCounters]) assert.equal(typeof fn, 'function');
  assert.ok(validPath(path)); assert.equal(posix.resolve('/uploads', path), '/etc/passwd');
  assert.ok(['completed', 'no_tool'].includes(expectedStatus));
  await selectFilePathSummaryLesson(page, frame);
  await physicallyType(page, frame, '[data-testid="file-path-summary-path"]', path, 4096);
  await physicallyType(page, frame, '[data-testid="file-path-summary-message"]', message, 8192);
  const sessionPromise = page.waitForResponse(responseAt('POST', `${BASE}/session`), { timeout: 30000 });
  const requestPromise = page.waitForRequest(request => request.method() === 'POST'
    && new URL(request.url()).pathname === `${BASE}/run`, { timeout: 30000 }).then(async request => ({
    request, reference: structuredClone(await readAcknowledgedReference(RUN_KEY)) }));
  const runPromise = page.waitForResponse(responseAt('POST', `${BASE}/run`), { timeout: 180000 });
  for (const promise of [sessionPromise, requestPromise, runPromise]) promise.catch(() => {});
  await clickExact(frame, 'Ask path-summary agent', '[data-testid="file-path-summary-send"]');
  const session = await Shared.readBoundedJson(await sessionPromise, { maxBytes: 4096 });
  assert.ok(exact(session, ['id'])); assert.match(session.id, UUID);
  const { request, reference } = await requestPromise;
  Shared.assertReference(reference, { sessionId: session.id });
  assert.match(request.headers()['content-type'] || '', /^application\/json(?:;|$)/i);
  const original = { sessionId: reference.sessionId, requestId: reference.requestId, message, path };
  assert.deepEqual(JSON.parse(request.postData()), original);
  assert.deepEqual(await readOriginalJson(reference.requestId), original);
  const run = assertRunDto(await Shared.readBoundedJson(await runPromise), { ...reference, path,
    status: expectedStatus, replayed: false });
  assert.deepEqual(await readAcknowledgedReference(RUN_KEY), reference);
  // This callback returns the original durable records, never a success flag.
  const evidence = await assertOriginalGraphEvidence({ reference, run, original });
  assert.equal(evidence?.row?.session_id, reference.sessionId);
  assert.equal(evidence?.row?.request_id, reference.requestId);
  assert.equal(evidence.row.result_json.text, run.text);
  if (expectedStatus === 'completed') {
    assert.ok(evidence.candidate && Buffer.isBuffer(evidence.retained?.data));
    assert.equal(run.resolvedPath, evidence.retained.receipt.resolvedPath);
    assert.equal(run.byteCount, evidence.retained.data.length);
    assert.equal(run.bodySha256, evidence.retained.receipt.bodySha256);
  }
  else { assert.equal(evidence.candidate, null); assert.equal(evidence.retained, null); }
  assert.deepEqual(Evidence.assertCounterSnapshot(await readCounters(reference)), {
    actorDecisions: 2, toolCalls: 1, fileReadEffects: expectedStatus === 'completed' ? 1 : 0,
    judgeCalls: 0, canonicalJudgments: 0, completionRows: 0,
  });
  await assertRenderedRun(frame, run);
  return Object.freeze({ reference, run, original, evidence });
}
async function recoverFilePathSummaryAfterReload({ page, getFrame, reference, originalRun, readCounters }) {
  Shared.assertReference(reference); assert.equal(typeof readCounters, 'function');
  const before = Evidence.assertCounterSnapshot(await readCounters(reference));
  const controller = new AbortController();
  const pending = page.waitForResponse(responseAt('GET', `${BASE}/requests/${reference.sessionId}/${reference.requestId}`),
    { timeout: 30000, signal: controller.signal }); pending.catch(() => {});
  try {
    await page.reload({ waitUntil: 'domcontentloaded' }); const frame = await getFrame();
    await selectFilePathSummaryLesson(page, frame);
    const run = assertRunDto(await Shared.readBoundedJson(await pending), { ...reference,
      path: originalRun.path, status: originalRun.status, replayed: true });
    assert.deepEqual(run, { ...originalRun, replayed: true }); await assertRenderedRun(frame, run);
    Evidence.assertGetOnlyRecovery(before, await readCounters(reference));
    return Object.freeze({ frame, run });
  } finally { controller.abort(); await pending.catch(() => {}); }
}
async function runFilePathSummaryAssessment({ page, frame, reference, readAcknowledgedReference,
  readPublicProgress, readCounters }) {
  Shared.assertReference(reference);
  for (const fn of [readAcknowledgedReference, readPublicProgress, readCounters]) assert.equal(typeof fn, 'function');
  assert.equal(await readAcknowledgedReference(ASSESSMENT_KEY), null);
  const before = Evidence.assertCounterSnapshot(await readCounters(reference));
  const pathname = `${BASE}/assess`;
  const pendingRequest = page.waitForRequest(request => request.method() === 'POST'
    && new URL(request.url()).pathname === pathname, { timeout: 30000 }).then(async request => ({
    request, intent: structuredClone(await readAcknowledgedReference(ASSESSMENT_KEY)) }));
  const pendingResponse = page.waitForResponse(responseAt('POST', pathname), { timeout: 180000 });
  pendingRequest.catch(() => {}); pendingResponse.catch(() => {});
  await clickExact(frame, 'Assess saved path summary', '[data-testid="file-path-summary-assess"]');
  const { request, intent } = await pendingRequest;
  assert.deepEqual(JSON.parse(request.postData()), { sessionId: reference.sessionId, requestId: reference.requestId });
  Shared.assertReference(intent, reference);
  assert.equal(intent.shopUserId, reference.shopUserId);
  const result = Shared.assertAssessmentDto(await Shared.readBoundedJson(await pendingResponse), { completed: true, replayed: false });
  assert.equal(result.judgment.verdict, 'pass'); assert.equal(result.judgment.canRetry, false);
  assert.deepEqual(await readAcknowledgedReference(ASSESSMENT_KEY), intent);
  const after = Evidence.assertCounterSnapshot(await readCounters(reference));
  assert.deepEqual(after, { ...before, judgeCalls: before.judgeCalls + 1,
    canonicalJudgments: before.canonicalJudgments + 1, completionRows: before.completionRows + 1 });
  Evidence.assertPublicProgress(await readPublicProgress(reference), true);
  await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Saved file-path-summary request"] [role="status"]')]
    .some(node => node.textContent.includes('Path-summary objective completed in canonical progress.')), { timeout: 30000 });
  return result;
}
async function recoverFilePathSummaryAssessment({ page, frame, reference, evaluationId, readCounters }) {
  const before = Evidence.assertCounterSnapshot(await readCounters(reference));
  const pending = page.waitForResponse(responseAt('GET', `${BASE}/assess/${reference.sessionId}/${reference.requestId}`), { timeout: 30000 });
  pending.catch(() => {});
  await clickExact(frame, 'Check saved assessment', '[data-testid="file-path-summary-assessment-recover"]');
  const result = Shared.assertAssessmentDto(await Shared.readBoundedJson(await pending), { completed: true, evaluationId, replayed: true });
  Evidence.assertGetOnlyRecovery(before, await readCounters(reference)); return result;
}
module.exports = { BASE, RUN_KEY, ASSESSMENT_KEY, CASES, assertRunDto, physicallyType,
  selectFilePathSummaryLesson, runRenderedFilePathSummary, recoverFilePathSummaryAfterReload,
  runFilePathSummaryAssessment, recoverFilePathSummaryAssessment, assertRenderedRun };
