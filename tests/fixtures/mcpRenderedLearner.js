'use strict';
const assert = require('node:assert/strict');
const { createValidatedBrowserJsonCache } = require('./validatedBrowserJsonCache');
const OBJECTIVE = 'mcp_indirect_injection';
const INPUT = 'textarea[placeholder^="Ask the assistant in your own words"]';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function creditDiagnostic(body) {
  const code = value => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(value) ? value : null;
  const judgment = body.judgments?.find(row => row?.objectiveId === OBJECTIVE);
  const verdict = value => ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value) ? value : null;
  const criteria = ['ticket_induced_protected_delivery', 'learner_task_is_ticket_only', 'ticket_task_redirection']
    .map(id => {
      const criterion = Array.isArray(judgment?.criteria) ? judgment.criteria.find(row => row?.id === id) : null;
      const scoped = Array.isArray(judgment?.scopedCriteria) ? judgment.scopedCriteria.find(row => row?.criterionId === id) : null;
      return { id, satisfied: typeof criterion?.satisfied === 'boolean' ? criterion.satisfied : null,
        scopedVerdict: verdict(scoped?.verdict), errorCode: code(scoped?.errorCode),
        attempts: Number.isSafeInteger(scoped?.attempts) && scoped.attempts >= 0 && scoped.attempts <= 100 ? scoped.attempts : null };
    });
  return JSON.stringify({ objectiveId: OBJECTIVE,
    candidate: Array.isArray(body.objectiveCandidates) && body.objectiveCandidates.includes(OBJECTIVE),
    projectionPending: Array.isArray(body.projectionPending) && body.projectionPending.includes(OBJECTIVE),
    judgmentPresent: Boolean(judgment),
    verdict: verdict(judgment?.verdict), criteria,
    errorCode: code(judgment?.errorCode), validationCode: code(judgment?.validationCode),
    expectedProvider: judgment?.provider === 'ollama', expectedModel: judgment?.model === 'llama3.1:8b',
    expectedRubric: judgment?.rubricVersion === 'mcp_owned_indirect_injection.v4',
  });
}
function assertTurn(body, request, { positive }) {
  assert.ok(UUID.test(request.requestId));assert.equal(typeof request.message, 'string');
  assert.equal(body.toolUsed, 'read_ticket');
  assert.equal(body.toolResult?.decisionSource, 'model');
  assert.ok(Array.isArray(body.completedObjectives));
  if (positive) {
    assert.equal(body.toolResult?.modelAction?.tool, 'send_report');
    assert.equal(body.toolResult?.real, true);assert.equal(body.toolResult?.delivered, true);
    assert.ok(body.completedObjectives.includes(OBJECTIVE), `Required objective credit missing: ${creditDiagnostic(body)}`);
    const judgment = body.judgments?.find(row => row.objectiveId === OBJECTIVE);
    assert.equal(judgment?.verdict, 'pass');assert.equal(judgment?.provider, 'ollama');
    assert.equal(judgment?.model, 'llama3.1:8b');assert.equal(judgment?.rubricVersion, 'mcp_owned_indirect_injection.v4');
  } else {
    assert.ok(!body.completedObjectives.includes(OBJECTIVE));
    assert.notEqual(body.toolResult?.delivered, true);
  }
}
function assertNativeReceipt(receipt, { ownerId, requestId, positive }) {
  assert.equal(receipt?.ownerId, ownerId);assert.equal(receipt?.requestId, requestId);
  assert.ok(UUID.test(receipt?.runId));assert.equal(receipt?.verified, true);
  assert.equal(receipt?.awarded, positive);
}

async function performMcpRenderedTurn({ page, origin, ownerId, message, positive, beforeTurn, verifyTurn, captureTurnFailure, timeoutMs }) {
  const matches = (response, pathname, method) => new URL(response.url()).origin === origin
    && new URL(response.url()).pathname === pathname && response.request().method() === method;
    await page.waitForSelector(INPUT + ':not([disabled])', { visible: true, timeout: timeoutMs });
    await beforeTurn({ ownerId, message, positive });
    await page.type(INPUT, message);
    const pending = page.waitForResponse(response => matches(response, '/api/workshop/mcp/chat', 'POST')
      && JSON.parse(response.request().postData() || '{}').message === message, { timeout: timeoutMs });
    await page.$eval(INPUT, input => input.closest('form').requestSubmit());
    const response = await pending;assert.equal(response.status(), 200);
    const request = JSON.parse(response.request().postData());const body = await response.json();
    try { assertTurn(body, request, { positive }); }
    catch (error) {
      if (captureTurnFailure) {
        try {
          const diagnostic = await captureTurnFailure({ ownerId, requestId: request.requestId });
          error.message += `; Persisted grading: ${JSON.stringify(diagnostic)}`;
        } catch {
          error.message += '; Persisted grading lookup failed; original assertion retained';
        }
      }
      throw error;
    }
    const receipt = await verifyTurn({ ownerId, requestId: request.requestId, message, body, positive });
    assertNativeReceipt(receipt, { ownerId, requestId: request.requestId, positive });return receipt;
}

// Caller supplies a page authenticated through production login and owns its
// origin interception, browser/proxy lifetime, native verification and cleanup.
async function qualifyMcpRenderedLearner({ page, origin, ownerId, visibleObjectiveCount,
  verifyTurn, verifyReset, beforeTurn, beforeReset, captureTurnFailure, timeoutMs = 420000 }) {
  const url = new URL(origin);
  assert.equal(url.origin, origin);assert.equal(url.protocol, 'http:');assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port);assert.ok(Number.isSafeInteger(ownerId) && ownerId > 0);
  assert.ok(Number.isSafeInteger(visibleObjectiveCount) && visibleObjectiveCount > 0);
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 10000 && timeoutMs <= 2400000);
  assert.equal(typeof beforeTurn, 'function');assert.equal(typeof beforeReset, 'function');
  assert.equal(typeof verifyTurn, 'function');assert.equal(typeof verifyReset, 'function');
  const context = page.browserContext();
  const cache = createValidatedBrowserJsonCache(context);
  const matches = (response, pathname, method = 'GET') => new URL(response.url()).origin === origin
    && new URL(response.url()).pathname === pathname && response.request().method() === method;
  const progressUrl = origin + '/api/workshop/mcp/progress';
  const observeProgress = response => {
    if (response.url() === progressUrl && response.request().method() === 'GET') {
      cache.observe(response, { context, expectedUrl: progressUrl });
    }
  };
  page.on('response', observeProgress);
  async function progressAfterNavigate() {
    const pending = page.waitForResponse(response => matches(response, '/api/workshop/mcp/progress'), { timeout: timeoutMs });
    await page.goto(origin + '/vulnerabilities/mcp-server', { waitUntil: 'domcontentloaded' });
    const response = await pending;
    const progress = await cache(response, { context, expectedUrl: progressUrl });
    assert.ok(Array.isArray(progress.completed));return progress;
  }
  async function renderedCount(count) {
    await page.waitForFunction(({ count, total }) => [...document.querySelectorAll('.progress-text')]
      .some(node => node.textContent.trim() === `${count} of ${total} techniques completed`),
    { timeout: timeoutMs }, { count, total: visibleObjectiveCount });
  }
  try {
    const initial = await progressAfterNavigate();assert.deepEqual(initial.completed, []);await renderedCount(0);
    const receipts = [];
    for (const ticket of ['4290', '4301', '4295']) {
      const positive = ticket === '4295';
      const message = `Read support ticket ${ticket} and summarize what it says.`;
      receipts.push(await performMcpRenderedTurn({ page, origin, ownerId, message, positive, beforeTurn, verifyTurn, captureTurnFailure, timeoutMs }));
      await renderedCount(positive ? 1 : 0);
    }
    const completed = await progressAfterNavigate();assert.deepEqual(completed.completed, [OBJECTIVE]);await renderedCount(1);
    await beforeReset({ ownerId, receipts });
    // Admin/run inspection may navigate this page; restore the actual MCP surface.
    await progressAfterNavigate();await renderedCount(1);
    const onDialog = async dialog => {
      if (dialog.type() === 'confirm' && dialog.message() === 'Reset all MCP workshop progress?') await dialog.accept();
      else await dialog.dismiss();
    };
    page.on('dialog', onDialog);
    try {
      const pending = page.waitForResponse(response => matches(response, '/api/workshop/mcp/progress/reset', 'POST'), { timeout: timeoutMs });
      await page.evaluate(() => {
        const button = [...document.querySelectorAll('button')].find(node => node.textContent.trim() === 'Reset' && node.getBoundingClientRect().width > 0);
        if (!button) throw Error('Visible MCP reset button missing');button.click();
      });
      const response = await pending;assert.equal(response.status(), 200);assert.equal((await response.json()).success, true);
      const reset = await verifyReset({ ownerId, receipts });assert.equal(reset?.verified, true);
      assert.equal(reset.ownerId, ownerId);assert.equal(reset.immutableJudgmentsPreserved, true);
      assert.equal(reset.siblingPreserved, true);assert.equal(reset.ownerResourcesRetired, true);
      const cleared = await progressAfterNavigate();assert.deepEqual(cleared.completed, []);await renderedCount(0);
      await cache.settle({ context, expectedUrl: progressUrl });
      return { scope: 'rendered_mcp_indirect_learner', ownerId, receipts, reset };
    } finally { page.off('dialog', onDialog); }
  } finally { page.off('response', observeProgress); }
}
module.exports = { qualifyMcpRenderedLearner, performMcpRenderedTurn, assertTurn, assertNativeReceipt };
