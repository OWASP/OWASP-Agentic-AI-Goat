'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const IDS = Object.freeze(Array.from({ length: 9 }, (_, i) => 'objective_' + (i + 1)));
function admitContent(rows) {
  assert.deepEqual(rows.map(row => row.objective_id), IDS);
  for (const row of rows) {
    assert.equal(typeof row.label, 'string'); assert(row.label.length);
    assert.equal(row.catalog_active, true); assert.equal(row.is_enabled, true);
    assert(Array.isArray(row.hint_content?.hints) && row.hint_content.hints.length > 0);
    assert.equal(typeof row.solution_content?.title, 'string'); assert(row.solution_content.title.length);
    assert.equal(typeof row.solution_content.approach, 'string'); assert(row.solution_content.approach.length);
  }
  return rows;
}
function allowedRequest(url, origin, count) {
  try { const u = new URL(url); return Number.isInteger(count) && count > 0 && count <= 1000
    && (u.origin === origin || ['data:', 'about:', 'blob:'].includes(u.protocol))
    && !/\/(chat|complete|evaluate|reset)$/.test(u.pathname); } catch { return false; }
}
function learnerCard({ label, clickKind = null }) {
  const names = [...document.querySelectorAll('.obj-name')].filter(e => [...e.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim() === label);
  if (names.length !== 1) return false;
  const card = names[0].closest('.obj-content'), wrapper = card?.parentElement;
  if (!wrapper || wrapper.querySelector('.status-badge')?.textContent.trim() !== 'COMPLETED') return false;
  if (clickKind) { const buttons = [...card.querySelectorAll('button')].filter(b => b.textContent.trim() === clickKind && !b.disabled); if (buttons.length !== 1) return false; buttons[0].click(); }
  return true;
}
function solutionMatches({ value, admin = false }) {
  const headings = [...document.querySelectorAll(admin ? 'h2,h3' : 'h3')].filter(e => e.textContent.trim() === (admin ? value.title : 'Solution: ' + value.title));
  if (headings.length !== 1) return false;
  let container = headings[0].parentElement;
  const closeText = admin ? 'Close Preview' : 'Close';
  while (container && ![...container.querySelectorAll('button')].some(b => b.textContent.trim() === closeText)) container = container.parentElement;
  if (!container) return false;
  if (!admin) container = container.parentElement;
  const norm = v => String(v).replace(/\s+/g, ' ').trim(), text = norm(container.textContent);
  const values = [value.title, value.difficulty, value.approach, ...(value.hints || []), ...(value.tips || []), ...(value.examples || []).flatMap(e => typeof e === 'string' ? [e] : [e.prompt, e.explanation])].filter(v => typeof v === 'string' && v.length);
  return values.every(v => text.includes(norm(v)));
}
function assertReceipt(proof) {
  assert.equal(proof.modelCalls, 0); assert.equal(proof.genuineCredit, 0); assert.equal(proof.controlledProjectionCount, 9);
  assert.deepEqual(proof.cases.map(row => row.id), IDS);
  for (const row of proof.cases) for (const flag of ['label', 'hint', 'solution', 'adminPreview', 'completedProjection']) assert.equal(row[flag], true);
  for (const flag of ['canonicalAuth', 'threeStudentViews', 'dbDerivedTotalsAndTime', 'objectiveHideRestore', 'independentHintSolutionControls', 'deniedStudentAdmin', 'siblingIsolation', 'adminStudentProjection', 'configurationRestored', 'projectionRestored', 'immutableEvidencePreserved', 'browserRetired']) assert.equal(proof[flag], true);
  assert.equal(proof.completed, 9); assert.equal(proof.total, 9);
  assert(Number.isInteger(proof.requests.browser) && proof.requests.browser > 0 && proof.requests.browser <= 1000);
  assert(Number.isInteger(proof.requests.api) && proof.requests.api >= 0 && proof.requests.api <= 40);
  return proof;
}
async function qualifyExcessiveAgencyFullAppParity({ backendPort, token, siblingToken, adminToken, studentId, title, runtimeRoot, contentRows = null }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  process.env.PORT = String(backendPort);
  const main = process.env.EA_PARITY_MAIN === '1';
  if (main) admitContent(contentRows);
  const completed = main ? contentRows.length : 1, total = main ? contentRows.length : 9;
  const requests = { browser: 0, api: 0 }, cases = [];
  const clientRoot = path.resolve('client');
  let vite; let browser; let browserPid; let learner; let sibling; let admin;
  const adminMutations = []; const gateSteps = []; let primary; let deadline; let timedOut = false; let receipt;
  try {
    let origin;
    if (main) {
      origin = `http://127.0.0.1:${backendPort}`;
      browser = await require('./secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(runtimeRoot, 'browser');
    } else {
    const { createServer } = await import(pathToFileURL(path.join(clientRoot, 'node_modules/vite/dist/node/index.js')));
    vite = await createServer({ root: clientRoot, configFile: path.join(clientRoot, 'vite.config.mjs'),
      configLoader: 'native', cacheDir: path.join(runtimeRoot, 'ea-parity-vite-cache'),
      server: { host: '127.0.0.1', port: 0, strictPort: false, fs: { allow: [clientRoot, fs.realpathSync(path.join(clientRoot, 'node_modules'))] } } });
    await vite.listen();
    origin = `http://127.0.0.1:${vite.httpServer.address().port}`;
    browser = await require('puppeteer').launch({ headless: true }); browserPid = browser.process().pid;
    }
    if (main) deadline = setTimeout(() => { timedOut = true; browser?.close().catch(() => {}); }, 540000);
    const makePage = async bearer => {
      const context = await browser.createBrowserContext(); const page = await context.newPage();
      await page.setViewport({ width: 1440, height: 1000 });
      await page.evaluateOnNewDocument(value => localStorage.setItem('token', value), bearer);
      await page.setRequestInterception(true);
      page.on('request', request => { requests.browser++; const allowed = main ? allowedRequest(request.url(), origin, requests.browser) : request.url().startsWith(origin + '/') || /^(data|about|blob):/.test(request.url()); (allowed ? request.continue() : request.abort()).catch(() => {}); });
      return page;
    };
    learner = await makePage(token); sibling = await makePage(siblingToken); admin = await makePage(adminToken);
    admin.on('request', request => {
      if (request.url().includes('/api/admin/') && ['POST', 'PATCH'].includes(request.method())) {
        let body = null; try { body = JSON.parse(request.postData() || 'null'); } catch { body = 'non-json'; }
        adminMutations.push({ url: new URL(request.url()).pathname, method: request.method(), body, status: null });
      }
    });
    admin.on('response', response => {
      const pathName = new URL(response.url()).pathname;
      const pending = [...adminMutations].reverse().find(item => item.url === pathName && item.status === null);
      if (pending) pending.status = response.status();
    });
    const assertLearnerTotals = async (page, completed, total) => {
      for (const route of ['/workshop-dashboard', '/workshop/challenges', '/workshop/progress']) {
        await page.bringToFront(); await page.goto(origin + route);
        await page.waitForFunction((name, count, maximum) => document.body.innerText.includes(name)
          && new RegExp(`${count}\\s*\\/\\s*${maximum}|${count} of ${maximum}`).test(document.body.innerText),
        { timeout: 45000 }, title, completed, total);
        if (route === '/workshop/progress') assert.equal(new URL(page.url()).pathname, '/workshop-dashboard');
      }
    };
    await assertLearnerTotals(learner, completed, total); await assertLearnerTotals(sibling, 0, total);
    assert.match(await learner.$eval('body', element => element.innerText), /1m|60s|1 min/i);

    assert.equal((await learner.evaluate(async bearer => fetch('/api/admin/exercises', { headers: { Authorization: `Bearer ${bearer}` } }).then(r => r.status), token)), 403);
    await admin.goto(origin + '/admin/exercises'); const card = '[data-exercise-key="excessive_agency"]';
    await admin.waitForSelector(card, { timeout: 45000 });
    await admin.$eval(card, element => Array.from(element.querySelectorAll('button')).find(button => button.textContent.includes('Manage Objectives')).click());
    await admin.waitForSelector('[data-objective-id="objective_9"]');
    assert.equal(await admin.$$eval('[data-objective-id]', elements => elements.length), 9);
    const click = async (selector, expectedLabel = null) => {
      await admin.bringToFront(); await admin.waitForSelector(selector);
      const label = await admin.$eval(selector, element => { element.scrollIntoView({ block: 'center' }); return element.parentElement?.textContent?.trim() || ''; });
      if (expectedLabel) assert.ok(label.includes(expectedLabel), `expected ${expectedLabel} control, got ${label}`);
      await admin.waitForFunction(selector => { const element = document.querySelector(selector); if (!element) return false; const box = element.getBoundingClientRect(); const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2); return (hit === element || element.contains(hit)) && box.width > 0 && box.height > 0; }, {}, selector);
      await admin.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      await admin.click(selector);
    };
    const recordGates = async step => {
      const gates = await admin.evaluate(async () => {
        const [snapshotResponse, statusResponse] = await Promise.all([fetch('/api/workshop/config/snapshot'), fetch('/api/solutions/excessive-agency/status')]);
        const snapshot = await snapshotResponse.json(); const status = await statusResponse.json();
        return { showHints: snapshot.exercises.excessive_agency.showHints, showSolutions: snapshot.exercises.excessive_agency.showSolutions,
          hintVisible: snapshot.exercises.excessive_agency.objectives.objective_9.hintVisible,
          solutionVisible: snapshot.exercises.excessive_agency.objectives.objective_9.solutionVisible,
          statusObjective9: status.objectives.objective_9 };
      });
      gateSteps.push({ step, ...gates }); return gates;
    };
    const setMasterGate = async ({ selector, label, field, desired, step }) => {
      const current = await recordGates(`before-${step}`);
      if (current[field] !== desired) await click(selector, label);
      await waitGate(field, desired); return recordGates(step);
    };
    if (main) {
      const { hintModalStep } = require('./finflowTraversalContentBrowser');
      await learner.goto(origin + '/vulnerabilities/excessive-agency');
      await learner.locator('::-p-text(Login as Alice)').setTimeout(45000).click();
      for (const row of contentRows) {
        await learner.bringToFront();
        await learner.waitForFunction(learnerCard, { timeout: 15000 }, { label: row.label });
        assert.equal(await learner.evaluate(learnerCard, { label: row.label, clickKind: 'Hint' }), true);
        for (let count = 1; count <= row.hint_content.hints.length; count++) {
          await learner.waitForFunction(hintModalStep, { timeout: 15000 }, { content: row.hint_content, count });
          if (count < row.hint_content.hints.length) assert.equal(await learner.evaluate(hintModalStep, { content: row.hint_content, count, advance: true }), true);
        }
        await learner.click('[role="dialog"][data-help-kind="hint"] button[aria-label="Close hint"]');
        await learner.waitForSelector('[role="dialog"][data-help-kind="hint"]', { hidden: true });
        assert.equal(await learner.evaluate(learnerCard, { label: row.label, clickKind: 'Solution' }), true);
        await learner.waitForFunction(solutionMatches, { timeout: 15000 }, { value: row.solution_content });
        await learner.evaluate(() => { const b = [...document.querySelectorAll('button')].filter(e => e.textContent.trim() === 'Close'); if (b.length !== 1) throw Error('Unique solution close required'); b[0].click(); });
        await learner.waitForFunction(() => ![...document.querySelectorAll('h3')].some(e => e.textContent.startsWith('Solution: ')));
        await admin.bringToFront();
        await admin.waitForFunction(({ id, label }) => { const row = document.querySelector('[data-objective-id="' + id + '"]'); return row && [...row.querySelectorAll('[title]')].some(e => e.title === label); }, {}, { id: row.objective_id, label: row.label });
        await admin.click('[data-objective-id="' + row.objective_id + '"] button[title="Preview Solution"]');
        await admin.waitForFunction(solutionMatches, { timeout: 15000 }, { value: row.solution_content, admin: true });
        await admin.evaluate(() => { const b = [...document.querySelectorAll('button')].filter(e => e.textContent.trim() === 'Close Preview'); if (b.length !== 1) throw Error('Unique preview close required'); b[0].click(); });
        await admin.waitForFunction(() => ![...document.querySelectorAll('button')].some(e => e.textContent.trim() === 'Close Preview'));
        cases.push({ id: row.objective_id, label: true, hint: true, solution: true, adminPreview: true, completedProjection: true });
      }
    }
    await click('[data-objective-id="objective_9"] [data-control="visible"]');
    await assertLearnerTotals(learner, completed - 1, total - 1); await assertLearnerTotals(sibling, 0, total - 1);
    await click('[data-objective-id="objective_9"] [data-control="visible"]');
    await assertLearnerTotals(learner, completed, total); await assertLearnerTotals(sibling, 0, total);

    await admin.$$eval('button', elements => elements.find(button => button.textContent === 'Done').click());
    await admin.waitForSelector('[data-objective-id="objective_9"]', { hidden: true });
    const waitGate = async (field, value) => admin.waitForFunction(async (fieldName, expected) => {
      const response = await fetch('/api/workshop/config/snapshot');
      return (await response.json()).exercises.excessive_agency[fieldName] === expected;
    }, {}, field, value);
    await setMasterGate({ selector: card + ' [data-control="solutions"]', label: 'Solutions', field: 'showSolutions', desired: false, step: 'after-solutions-off' });
    await setMasterGate({ selector: card + ' [data-control="hints"]', label: 'Hints', field: 'showHints', desired: true, step: 'after-hints-on' });
    await learner.goto(origin + '/vulnerabilities/excessive-agency');
    await learner.locator('::-p-text(Login as Alice)').setTimeout(45000).click();
    await learner.waitForFunction(() => document.body.innerText.includes('Exercise Objectives'), { timeout: 45000 });
    assert.equal(await learner.$$eval('button', elements => elements.some(element => element.textContent.trim().endsWith('Solution'))), false);
    assert.equal(await learner.$$eval('button', elements => elements.some(element => element.textContent.trim() === 'Hint')), true);
    await setMasterGate({ selector: card + ' [data-control="solutions"]', label: 'Solutions', field: 'showSolutions', desired: true, step: 'after-solutions-on' });
    await setMasterGate({ selector: card + ' [data-control="hints"]', label: 'Hints', field: 'showHints', desired: false, step: 'after-hints-off' });
    await learner.reload(); await learner.locator('::-p-text(Login as Alice)').setTimeout(45000).click();
    await learner.waitForFunction(() => document.body.innerText.includes('Exercise Objectives'), { timeout: 45000 });
    assert.equal(await learner.$$eval('button', elements => elements.some(element => element.textContent.trim().endsWith('Solution'))), true);
    assert.equal(await learner.$$eval('button', elements => elements.some(element => element.textContent.trim() === 'Hint')), false);

    await admin.goto(origin + '/admin/student-workshop-view?studentId=' + studentId);
    await admin.waitForFunction(({ name, completed, total }) => document.body.innerText.includes(name) && new RegExp(`${completed}\\s*\\/\\s*${total}|${completed} of ${total}`).test(document.body.innerText), { timeout: 45000 }, { name: title, completed, total });
    assert.match(await admin.$eval('body', element => element.innerText), /1m|60s|1 min/i);
    await learner.screenshot({ path: path.join(runtimeRoot, 'ea-learner-parity.png'), fullPage: true });
    await admin.screenshot({ path: path.join(runtimeRoot, 'ea-admin-parity.png'), fullPage: true });
    receipt = { modelCalls: 0, canonicalAuth: true, threeStudentViews: true, dbDerivedTotalsAndTime: true,
      objectiveHideRestore: true, independentHintSolutionControls: true, deniedStudentAdmin: true,
      siblingIsolation: true, adminStudentProjection: true, completed, total, adminMutations, gateSteps, ...(main ? { profile: 'ea-nine-content', actualModelProof: false, genuineCredit: 0, controlledProjectionCount: 9, completionScope: 'Controlled completion projections only; no earned credit', cases, requests } : {}) };
    return receipt;
  } catch (error) {
    primary = timedOut ? new Error('EA nine content deadline', { cause: error }) : error;
    for (const [name, page] of [['learner', learner], ['sibling', sibling], ['admin', admin]]) if (page) {
      await page.screenshot({ path: path.join(runtimeRoot, `ea-${name}-failure.png`), fullPage: true }).catch(() => {});
      fs.writeFileSync(path.join(runtimeRoot, `ea-${name}-failure.txt`), await page.$eval('body', element => element.innerText).catch(() => 'unavailable'));
    }
    fs.writeFileSync(path.join(runtimeRoot, 'ea-gate-network-failure.json'), JSON.stringify({ adminMutations, gateSteps }, null, 2));
    throw primary;
  } finally {
    clearTimeout(deadline);
    const cleanup = await Promise.allSettled([Promise.resolve().then(() => browser?.close()), Promise.resolve().then(() => vite?.close())]);
    const failures = cleanup.filter(r => r.status === 'rejected').map(r => r.reason);
    if (receipt && !failures.length) receipt.browserRetired = true;
    if (failures.length) throw new AggregateError([...(primary ? [primary] : []), ...failures], 'EA browser cleanup failed');
    if (browserPid) { let absent = false; try { process.kill(browserPid, 0); } catch (error) { if (error.code === 'ESRCH') absent = true; } assert.equal(absent, true); }
  }
}

module.exports = { IDS, admitContent, allowedRequest, learnerCard, solutionMatches, assertReceipt, qualifyExcessiveAgencyFullAppParity };
