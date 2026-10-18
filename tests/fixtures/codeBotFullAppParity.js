'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

async function qualifyCodeBotFullAppParity({ backendPort, token, siblingToken, adminToken, studentId, title, labels, runId, runtimeRoot }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  process.env.PORT = String(backendPort);
  const clientRoot = path.resolve('client');
  const { createServer } = await import(pathToFileURL(path.join(clientRoot, 'node_modules/vite/dist/node/index.js')));
  let vite; let browser; let browserPid; let learner; let sibling; let admin;
  try {
    vite = await createServer({ root: clientRoot, configFile: path.join(clientRoot, 'vite.config.mjs'), configLoader: 'native',
      cacheDir: path.join(runtimeRoot, 'codebot-parity-vite-cache'), server: { host: '127.0.0.1', port: 0, strictPort: false,
        fs: { allow: [clientRoot, fs.realpathSync(path.join(clientRoot, 'node_modules'))] } } });
    await vite.listen(); const origin = `http://127.0.0.1:${vite.httpServer.address().port}`;
    browser = await require('puppeteer').launch({ headless: true }); browserPid = browser.process().pid;
    const makePage = async bearer => { const context = await browser.createBrowserContext(); const page = await context.newPage();
      await page.setViewport({ width: 1440, height: 1000 }); await page.evaluateOnNewDocument(value => localStorage.setItem('token', value), bearer);
      await page.setRequestInterception(true); page.on('request', request => request.url().startsWith(origin + '/') || /^(data|about|blob):/.test(request.url()) ? request.continue() : request.abort()); return page; };
    learner = await makePage(token); sibling = await makePage(siblingToken); admin = await makePage(adminToken);
    const assertTotals = async (page, completed, total) => { for (const route of ['/workshop-dashboard', '/workshop/challenges', '/workshop/progress']) {
      await page.goto(origin + route); await page.waitForFunction((name, count, maximum) => document.body.innerText.includes(name)
        && new RegExp(`${count}\\s*\\/\\s*${maximum}|${count} of ${maximum}`).test(document.body.innerText), { timeout: 45000 }, title, completed, total);
      if (route === '/workshop/progress') assert.equal(new URL(page.url()).pathname, '/workshop-dashboard'); } };
    await assertTotals(learner, 1, 6); await assertTotals(sibling, 0, 6);
    assert.match(await learner.$eval('body', element => element.innerText), /1m|60s|1 min/i);
    assert.equal(await learner.evaluate(async bearer => fetch('/api/admin/exercises', { headers: { Authorization: `Bearer ${bearer}` } }).then(r => r.status), token), 403);
    assert.equal(await learner.evaluate(async ({ id, bearer }) => fetch('/api/agent-runs/' + id,
      { headers: { Authorization: `Bearer ${bearer}` } }).then(r => r.status), { id: runId, bearer: token }), 200);
    assert.equal(await sibling.evaluate(async ({ id, bearer }) => fetch('/api/agent-runs/' + id,
      { headers: { Authorization: `Bearer ${bearer}` } }).then(r => r.status), { id: runId, bearer: siblingToken }), 404);

    const card = '[data-exercise-key="supply_chain_rce"]';
    await admin.goto(origin + '/admin/exercises'); await admin.waitForSelector(card, { timeout: 45000 });
    const click = async selector => { await admin.bringToFront(); await admin.waitForSelector(selector); await admin.$eval(selector, e => e.scrollIntoView({ block: 'center' }));
      await admin.waitForFunction(value => { const e = document.querySelector(value); if (!e) return false; const b = e.getBoundingClientRect(); const h = document.elementFromPoint(b.x + b.width / 2, b.y + b.height / 2); return (h === e || e.contains(h)) && b.width > 0; }, {}, selector);
      await admin.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))); await admin.click(selector); };
    const waitGate = (field, value) => admin.waitForFunction(async (name, expected) => {
      const exercise = (await (await fetch('/api/workshop/config/snapshot')).json()).exercises.supply_chain_rce;
      const objectiveField = name === 'showHints' ? 'hintVisible' : 'solutionVisible';
      return exercise[name] === expected && exercise.objectives.clean_request[objectiveField] === expected;
    }, {}, field, value);
    await admin.$eval(card, element => Array.from(element.querySelectorAll('button')).find(button => button.textContent.includes('Manage Objectives')).click());
    await admin.waitForSelector('[data-objective-id="clean_request"]'); assert.equal(await admin.$$eval('[data-objective-id]', e => e.length), 6);
    await click('[data-objective-id="clean_request"] [data-control="visible"]'); await assertTotals(learner, 0, 5);
    await learner.goto(origin + '/workshop/supply-chain'); await learner.waitForFunction((visibleLabel) => document.body.innerText.includes(visibleLabel)
      && /0 of 5 objectives completed/.test(document.body.innerText), { timeout: 45000 }, labels.tool_list);
    assert.equal((await learner.$eval('body', e => e.innerText)).includes(labels.clean_request), false);
    await click('[data-objective-id="clean_request"] [data-control="visible"]'); await assertTotals(learner, 1, 6);
    await admin.$$eval('button', e => e.find(button => button.textContent === 'Done').click()); await admin.waitForSelector('[data-objective-id="clean_request"]', { hidden: true });

    const setGate = async (selector, field, desired) => { const current = await admin.evaluate(async name => (await (await fetch('/api/workshop/config/snapshot')).json()).exercises.supply_chain_rce[name], field); if (current !== desired) await click(selector); await waitGate(field, desired); };
    await setGate(card + ' [data-control="solutions"]', 'showSolutions', false); await setGate(card + ' [data-control="hints"]', 'showHints', true);
    await learner.goto(origin + '/workshop/supply-chain'); await learner.waitForFunction(() => Array.from(document.querySelectorAll('button')).some(button => button.textContent.trim() === 'Hint'), { timeout: 45000 });
    assert.equal(await learner.$$eval('button', e => e.some(button => button.textContent.includes('View Solution'))), false);
    await setGate(card + ' [data-control="solutions"]', 'showSolutions', true); await setGate(card + ' [data-control="hints"]', 'showHints', false);
    await learner.reload(); await learner.waitForFunction(() => Array.from(document.querySelectorAll('button')).some(button => button.textContent.includes('View Solution')), { timeout: 45000 });
    assert.equal(await learner.$$eval('button', e => e.some(button => button.textContent.trim() === 'Hint')), false);

    await admin.goto(origin + '/admin/student-workshop-view?studentId=' + studentId); await admin.waitForFunction((name) => document.body.innerText.includes(name) && /1\s*\/\s*6|1 of 6/.test(document.body.innerText), { timeout: 45000 }, title);
    await admin.goto(origin + '/admin/agent-runs'); await admin.waitForSelector(`[data-run-id="${runId}"]`, { timeout: 45000 });
    await admin.click(`[data-run-id="${runId}"]`);
    await admin.waitForFunction(id => document.body.innerText.includes(id) && document.body.innerText.includes('node_end')
      && !document.body.innerText.includes('Loading timeline…'), { timeout: 45000 }, runId);
    const facts = await admin.$$eval('div', elements => Object.fromEntries(elements.flatMap(element => {
      const label = element.querySelector(':scope > label'); const strong = element.querySelector(':scope > strong');
      return label && strong ? [[label.textContent.trim().toLowerCase(), strong.textContent.trim()]] : [];
    })));
    assert.equal(facts.agent, 'CodeBot'); assert.equal(facts['decision source'], 'controlled-projection'); assert.equal(facts['last node'], 'respond');
    await learner.screenshot({ path: path.join(runtimeRoot, 'codebot-learner-parity.png'), fullPage: true });
    await admin.screenshot({ path: path.join(runtimeRoot, 'codebot-admin-parity.png'), fullPage: true });
    return { modelCalls: 0, controlledProjectionOnly: true, renderedRouteComposition: true, fullSixteenStoreStartup: false,
      canonicalAuth: true, threeStudentViews: true, dbDerivedTotalsAndTime: true,
      objectiveHideRestore: true, challengePageVisibility: true, independentHintSolutionControls: true, deniedStudentAdmin: true,
      siblingIsolation: true, learnerOwnRunDetail: true, siblingRunDenied: true, adminStudentProjection: true,
      adminRunProjection: true, completed: 1, total: 6, runId };
  } catch (error) {
    if (learner) {
      const status = await learner.evaluate(async () => {
        const [solutions, hints, snapshot] = await Promise.all([
          fetch('/api/solutions/supply-chain/status').then(r => r.json()).catch(() => null),
          fetch('/api/hints/supply_chain_rce/status').then(r => r.json()).catch(() => null),
          fetch('/api/workshop/config/snapshot').then(r => r.json()).catch(() => null),
        ]); return { solutions, hints, exercise: snapshot?.exercises?.supply_chain_rce || null };
      }).catch(() => null);
      fs.writeFileSync(path.join(runtimeRoot, 'codebot-gate-failure.json'), JSON.stringify(status, null, 2));
      await learner.screenshot({ path: path.join(runtimeRoot, 'codebot-learner-failure.png'), fullPage: true }).catch(() => {});
    }
    throw error;
  } finally {
    await browser?.close(); await vite?.close();
    if (browserPid) { let absent = false; try { process.kill(browserPid, 0); } catch (error) { if (error.code === 'ESRCH') absent = true; } assert.equal(absent, true); }
  }
}

module.exports = { qualifyCodeBotFullAppParity };
