'use strict';
// Controlled projection qualification only. Real JWT/recovery/denial routes;
// ONLY initial chat response is synthetic. Never call a provider or Judge.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const key = 'direct_prompt_injection';
const chatPath = '/api/workshop/prompt-injection/chat';
function observedResponse(page, predicate) {
  const response = page.waitForResponse(predicate);
  // Observe immediately even if the following pointer action throws. Awaiting
  // the original promise still propagates its timeout to the fixture caller.
  response.catch(() => {});
  return response;
}
function assertReceiptProjection(rows, expectedIds = []) {
  assert.deepEqual(rows.map(row => row.evaluation_id).sort(), [...expectedIds].sort());
  for (const row of rows) {
    assert.equal(row.family, 'DPI');
    assert.equal(row.disposition, 'grading_unqualified');
    assert.equal(row.verdict, 'pass');
    assert.equal(row.result_json.provider, 'fixture');
    assert.equal(row.result_json.model, 'fixture');
  }
  return { noJudgeReceipts: rows.length === 0, syntheticJudgeReceipts: rows.length,
    actualJudgeCalls: 0 };
}
function syntheticChatBody(receipt) {
  const judgment = require('../../server/agent-runtime/dpiSemanticCreditPolicy').projectJudgment(receipt);
  assert.equal(receipt.disposition, 'grading_unqualified');
  return { response: 'Synthetic retained actor response; no inference.', completed: false,
    judgment: { ...judgment, evaluationId: receipt.evaluationId, canRetry: false } };
}
async function prepareContainment({ identity, migration, student, sibling, admin }) {
  const repo = require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identity);
  const receipts = {};
  for (const objectiveId of ['virtualization', 'obfuscation']) {
    const scope = { userId: student.id, evaluationId: randomUUID(), workshopKey: key, objectiveId,
      family: 'DPI', scenario: 'aws_assistant', rubricVersion: 'synthetic-rendered-v1',
      evidenceDigest: 'a'.repeat(64), runId: null, mode: 'vuln' };
    await repo.beginEvaluation(scope);
    receipts[objectiveId] = await repo.recordVerdict({ ...scope, result: {
      family: 'DPI', scenario: scope.scenario, objectiveId, rubricVersion: scope.rubricVersion,
      evidenceDigest: scope.evidenceDigest, runId: null, mode: 'vuln', verdict: 'pass',
      criteria: [{ id: 'observed', satisfied: true, evidenceRefs: ['synthetic'] }],
      explanation: 'Synthetic raw pass, not a semantic qualification.', provider: 'fixture', model: 'fixture', usage: null,
    } });
    assert.equal(receipts[objectiveId].disposition, 'grading_unqualified');
  }
  const owner = JSON.stringify(['ARIA', String(student.id)]), foreign = JSON.stringify(['ARIA', String(sibling.id)]);
  await identity.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1),($2) ON CONFLICT DO NOTHING', [owner, foreign]);
  const runId = randomUUID(), foreignRunId = randomUUID(), marker = 'private-projection-' + randomUUID();
  await identity.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,model) VALUES($1,$2,0,'running',$3)", [runId, owner, marker]);
  await identity.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')", [foreignRunId, foreign]);
  const snapshot = async () => (await identity.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id', [student.id])).rows;
  const before = await snapshot();
  return { receipts, runId, foreignRunId, marker,
    revokeStudent: () => migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE user_id=$1', [student.id]),
    revokeAdmin: () => migration.query("UPDATE identity.admin_permissions SET is_active=0 WHERE admin_id=$1 AND permission_name='view_analytics'", [admin.id]),
    verify: async () => {
      assert.deepEqual(await snapshot(), before);
      assert.equal((await identity.query('SELECT count(*)::integer AS n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2', [student.id, key])).rows[0].n, 0);
    },
  };
}
async function qualifyContainment({ origin, root, student, admin, password, fixture }) {
  const browser = await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(root, 'dpicontainment');
  const deadline = setTimeout(() => browser.close().catch(() => {}), 180000);
  const requests = [], responses = [], errors = [], screenshots = []; let intercepted = 0;
  const phases = []; let activePage;
  const phase = (name, page) => { activePage = page; phases.push({ name, path: new URL(page.url()).pathname }); if (phases.length > 80) phases.shift(); };
  const pointer = async (page, element) => {
    await page.bringToFront();
    await element.evaluate(e => e.scrollIntoView({ block: 'center', inline: 'nearest' }));
    await page.waitForFunction(require('./dpiCaptureReadiness').captureReady, { polling: 'raf' }, element, true);
    await element.click();
  };
  const click = async (page, selector) => { phase('pointer:' + selector, page); const e = await page.waitForSelector(selector, { visible: true }); await pointer(page, e); };
  const refresh = async page => { phase('refresh', page); const button = await page.evaluateHandle(() => [...document.querySelectorAll('button')].find(e => e.textContent.trim() === 'Refresh')); assert.ok(button.asElement()); await pointer(page, button.asElement()); };
  const api = (page, url) => page.evaluate(async url => { const r = await fetch(url, { headers: { authorization: 'Bearer ' + localStorage.getItem('token') } }); return { status: r.status, body: await r.json() }; }, url);
  async function login(user, label, expectedPath) {
    const context = await browser.createBrowserContext(), page = await context.newPage();
    await page.setViewport({ width: 1440, height: 1100 }); page.setDefaultTimeout(15000);
    page.on('pageerror', e => errors.push(e.message));
    page.on('response', r => responses.push({ path: new URL(r.url()).pathname, status: r.status() }));
    await page.setRequestInterception(true);
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.protocol === 'data:') return void request.continue();
      if (url.origin !== origin) { requests.push({ blocked: url.origin }); return void request.abort('blockedbyclient'); }
      if (url.pathname === chatPath) {
        const body = JSON.parse(request.postData() || '{}');
        const receipt = fixture.receipts[body.activeObjectiveId];
        if (request.method() !== 'POST' || !receipt) return void request.abort('blockedbyclient');
        intercepted++;
        return void request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(syntheticChatBody(receipt)) });
      }
      requests.push({ path: url.pathname, method: request.method() });
      void request.continue();
    });
    phase(label + ':login-navigation', page);
    await page.bringToFront(); await page.goto(origin + '/workshop-login');
    phase(label + ':login-fields', page);
    const usernameField = await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
    const passwordField = await page.waitForSelector('input[placeholder="Enter your password"]', { visible: true });
    await usernameField.type(user.username); await passwordField.type(password);
    const loginResponse = observedResponse(page, r => new URL(r.url()).pathname === '/api/auth/login' && r.request().method() === 'POST');
    await click(page, 'button[type="submit"]'); phase(label + ':login-response', page); assert.equal((await loginResponse).status(), 200);
    phase(label + ':login-redirect', page);
    await page.waitForFunction(require('./dpiCaptureReadiness').authenticatedRouteReady, {}, expectedPath);
    return page;
  }
  async function shot(page, name, selector, text) {
    phase('capture:' + name, page);
    await page.bringToFront();
    const handle = await page.waitForFunction((selector, text) => [...document.querySelectorAll(selector)].find(e => e.textContent.includes(text)), {}, selector, text);
    const element = handle.asElement(); assert.ok(element);
    await element.evaluate(e => e.scrollIntoView({ block: 'center', inline: 'nearest' }));
    await page.waitForFunction(require('./dpiCaptureReadiness').captureReady, { polling: 'raf' }, element);
    const file = path.join(root, name + '.png');
    await page.screenshot({ path: file, fullPage: false }); screenshots.push(file);
    const crop = path.join(root, name + '-message.png');
    await element.screenshot({ path: crop }); screenshots.push(crop);
    await handle.dispose();
  }
  try {
    const page = await login(student, 'student', '/workshop-dashboard'), adminPage = await login(admin, 'delegated-admin', '/admin/dashboard');
    for (const objective of ['virtualization', 'obfuscation']) {
      phase('objective:' + objective, page);
      await page.bringToFront(); await page.goto(origin + '/vulnerabilities/direct-prompt-injection');
      await click(page, `[data-testid="objective-card-${objective}"]`);
      await page.type('textarea', 'Synthetic pending projection fixture');
      const pending = observedResponse(page, r => new URL(r.url()).pathname === chatPath);
      await click(page, 'button[type="submit"]'); phase('synthetic-chat-response:' + objective, page); assert.equal((await pending).status(), 200);
      await page.waitForFunction(() => document.body.innerText.includes('no completion was awarded'));
      assert.doesNotMatch(await page.$eval(`[data-testid="objective-card-${objective}"]`, e => e.innerText), /COMPLETED|DONE/);
      assert.equal(await page.$('.Toastify__toast--success'), null);
      await shot(page, 'dpi-pending-' + objective, '[data-testid="active-transcript"] .message-content', 'no completion was awarded');
    }
    assert.equal(intercepted, 2);
    phase('navigate:/workshop-dashboard', page); await page.goto(origin + '/workshop-dashboard');
    await page.waitForFunction(() => /0\s*[/]\s*8|0 of 8/.test(document.body.innerText));
    const stats = await api(page, '/api/workshop/student/stats'); assert.equal(stats.status, 200); assert.equal(stats.body.completedObjectives, 0);
    phase('navigate:/workshop/agent-runs', page); await page.goto(origin + '/workshop/agent-runs');
    await page.waitForSelector('[aria-label="Recent evaluation recovery"]');
    for (const receipt of Object.values(fixture.receipts)) {
      const read = await api(page, '/api/agent-runs/judgments');
      assert.equal(read.status, 200);
      const item = read.body.judgments.find(j => j.evaluationId === receipt.evaluationId);
      assert.equal(item.gradingStatus, 'pending'); assert.equal(item.canRetry, false);
    }
    await refresh(page); phase('recovery-reload', page); await page.reload();
    await page.waitForFunction(() => document.body.innerText.includes('Grading pending qualification; no completion awarded.'));
    assert.equal(await page.$('[data-testid^="judge-retry-"]'), null);
    await shot(page, 'dpi-inspector-pending-recovery', '[aria-label="Recent evaluation recovery"] span', 'Grading pending qualification; no completion awarded.');
    await click(page, `[data-run-id="${fixture.runId}"]`);
    await page.waitForFunction(marker => document.body.innerText.includes(marker), {}, fixture.marker);
    const foreign = await api(page, '/api/agent-runs/' + fixture.foreignRunId);
    assert.equal(foreign.status, 404);
    assert.equal(await page.$(`[data-run-id="${fixture.foreignRunId}"]`), null);
    await fixture.revokeStudent(); await refresh(page);
    await page.waitForFunction(() => !document.querySelector('[aria-label="Recent evaluation recovery"]'));
    await page.waitForFunction(marker => !document.body.innerText.includes(marker), {}, fixture.marker);
    assert.ok(responses.some(r => r.path.startsWith('/api/agent-runs') && r.status === 401));
    phase('navigate:/admin/agent-runs', adminPage); await adminPage.goto(origin + '/admin/agent-runs');
    await click(adminPage, `[data-run-id="${fixture.runId}"]`);
    await adminPage.waitForFunction(marker => document.body.innerText.includes(marker), {}, fixture.marker);
    await fixture.revokeAdmin(); await refresh(adminPage);
    await adminPage.waitForFunction(marker => !document.body.innerText.includes(marker), {}, fixture.marker);
    assert.ok(responses.some(r => r.path.startsWith('/api/admin/agent-runs') && r.status === 403));
    await fixture.verify();
    assert.deepEqual(errors, []); assert.equal(requests.some(r => r.blocked), false);
    assert.equal(requests.some(r => r.path === chatPath), false, 'No initial chat reaches backend/provider');
    return { status: 'passed', syntheticInitialResponses: intercepted, genuineInference: 0, realJwt: true,
      pendingRecovery: true, renderedDenialStatuses: [401, 403], foreignReadStatus: 404, screenshots };
  } catch (error) {
    let diagnostics = null, failureScreenshot = null;
    if (activePage && !activePage.isClosed()) {
      let timer;
      try {
        await Promise.race([(async () => {
          diagnostics = await activePage.evaluate(() => ({ path: location.pathname, visibility: document.visibilityState,
            fields: [...document.querySelectorAll('input,textarea')].map(e => ({ tag: e.tagName, type: e.type, populated: Boolean(e.value), disabled: e.disabled, valid: e.validity.valid })),
            submits: [...document.querySelectorAll('button[type="submit"]')].map(e => ({ disabled: e.disabled, rect: e.getBoundingClientRect().toJSON() })) }));
          // Failure-only sanitation: do not retain password or other field values in pixels.
          await activePage.evaluate(() => { for (const e of document.querySelectorAll('input,textarea')) e.value = ''; });
          failureScreenshot = path.join(root, 'dpi-containment-failure.png');
          await activePage.screenshot({ path: failureScreenshot, fullPage: false });
        })(), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Bounded failure capture timeout')), 3000); })]);
      } catch (captureError) { diagnostics = { ...diagnostics, captureError: captureError.message }; }
      finally { clearTimeout(timer); }
    }
    fs.writeFileSync(path.join(root, 'dpi-containment-browser-error.json'), JSON.stringify({ error: error.message, phases, diagnostics, failureScreenshot, intercepted, requests, responses, errors }), { mode: 0o600 });
    throw error;
  } finally { clearTimeout(deadline); await browser.close(); }
}
module.exports = { syntheticChatBody, prepareContainment, qualifyContainment, observedResponse, assertReceiptProjection };
