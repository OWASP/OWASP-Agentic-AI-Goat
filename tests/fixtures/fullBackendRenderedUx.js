'use strict';

const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

const KEY = 'sql_injection_workshop';
const OBJECTIVE = 'sqli_1';
const ADMIN = `/api/admin/exercises/${KEY}/objectives/${OBJECTIVE}`;
const HINT = `/api/hints/${KEY}/${OBJECTIVE}`;
const SOLUTION = `/api/solutions/sql-injection/${OBJECTIVE}`;
const CHECKS = Object.freeze([
  'instructorAuthored', 'objectiveVisibility', 'exerciseVisibility',
  'effectiveHintGate', 'effectiveSolutionGate',
  'masterHintGate', 'masterSolutionGate', 'learnerHelpDialogs',
  'representativeWidths', 'progressLibraryParity', 'ownerModeIsolation', 'scopedResetIsolation',
  'studentMutationDenied', 'catalogRestored', 'sessionsPreserved', 'fixedCsrfEffectIsolation',
]);

function assertWorkshopUxReceipt(receipt) {
  assert.equal(receipt?.scope, 'rendered_platform_workshop_ux');
  assert.equal(receipt?.passed, true);
  assert.equal(receipt?.actualModelProof, false);
  assert.equal(receipt?.controlledProjectionOnly, true);
  assert.deepEqual(Object.keys(receipt.checks || {}).sort(), [...CHECKS].sort());
  for (const key of CHECKS) assert.equal(receipt.checks[key], true, `UX check ${key} must pass`);
  return receipt;
}

function assertChallengeParity(challenges, progress, stats, { label, description }) {
  assert.deepEqual(progress.challenges, challenges.challenges);
  const rows = challenges.challenges;
  assert.equal(stats.totalObjectives, rows.reduce((sum, row) => sum + row.objectiveCount, 0));
  assert.equal(stats.completedObjectives, rows.reduce((sum, row) => sum + row.completedObjectiveCount, 0));
  assert.equal(stats.totalTime, rows.reduce((sum, row) => sum + row.timeSpentSeconds, 0));
  const sql = rows.find(row => row.workshopKey === KEY);
  assert.ok(sql, 'SQL workshop must be visible in the learner catalog');
  const objective = sql.objectives.find(row => row.id === OBJECTIVE);
  assert.equal(objective?.label, label);
  assert.equal(objective?.description, description);
  assert.equal(objective?.text, label);
  assert.equal(sql.objectiveCount, sql.objectives.length);
  assert.equal(sql.completedObjectiveCount, sql.objectives.filter(row => row.completed).length);
  return sql;
}

async function browserApi(page, token, path, method = 'GET', body) {
  return page.evaluate(async ({ token, path, method, body }) => {
    const response = await fetch(path, {
      method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(['POST', 'PUT', 'PATCH'].includes(method) ? { body: JSON.stringify(body ?? {}) } : {}),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  }, { token, path, method, body });
}

async function ok(page, token, path, method = 'GET', body) {
  const result = await browserApi(page, token, path, method, body);
  assert.equal(result.status, 200, `${method} ${path}: ${JSON.stringify(result.body)}`);
  return result.body;
}

// Real authenticated HTTP and PostgreSQL effects in the owned main cohort;
// forged requests are rejected before provider dispatch, so this is not model proof.
async function qualifyFixedCsrf({ learner, sibling }) {
  const api = '/api/workshop/csrf';
  const beforeMode = await ok(sibling.page, sibling.token, api + '/mode');
  const progress = async person => {
    const snapshot = await ok(person.page, person.token, '/api/workshop/progress');
    const row = snapshot.challenges.find(item => item.workshopKey === 'csrf_workshop');
    assert.ok(row, 'Canonical CSRF catalog must be present');
    return row.objectives.map(item => ({ id: item.id, completed: item.completed }));
  };
  const ownerProgress = await progress(learner), siblingProgress = await progress(sibling);
  const selected = await ok(learner.page, learner.token, api + '/mode', 'POST', { mode: 'fixed' });
  assert.equal(selected.effectiveMode, 'fixed');
  for (const tab of ['get', 'post', 'xss', 'indirect']) {
    const url = api + '/victim-state?tab=' + tab;
    const before = (await ok(learner.page, learner.token, url)).state;
    const siblingBefore = (await ok(sibling.page, sibling.token, url)).state;
    const status = await learner.page.evaluate(async ({ token, api, tab }) => {
      const response = await fetch(api + '/agent-action', { method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ tab, message: 'change my email to attacker@example.test' }).toString() });
      await response.text();
      return response.status;
    }, { token: learner.token, api, tab });
    assert.equal(status, 403, `Fixed ${tab} forged action must be rejected`);
    const after = (await ok(learner.page, learner.token, url)).state;
    for (const field of ['profile', 'security', 'account', 'baseline', 'defenses'])
      assert.deepEqual(after[field], before[field], `${tab} ${field} must be unchanged`);
    assert.equal(after.attackLog.length, before.attackLog.length + 1);
    assert.equal(after.attackLog.at(-1).blocked, true, '403 must come from the actual teaching defense');
    assert.deepEqual((await ok(sibling.page, sibling.token, url)).state, siblingBefore);
  }
  assert.deepEqual(await progress(learner), ownerProgress);
  assert.deepEqual(await progress(sibling), siblingProgress);
  assert.deepEqual(await ok(sibling.page, sibling.token, api + '/mode'), beforeMode);
}

async function replaceField(page, selector, value) {
  await page.waitForSelector(selector, { visible: true });
  const element = await page.$(selector);
  assert.ok(element);
  try {
    await element.evaluate(node => { node.focus(); node.select(); });
    await element.press('Backspace');
    assert.equal(await element.evaluate(node => node.value), '');
    await element.type(value);
    assert.equal(await element.evaluate(node => node.value), value);
  } finally { await element.dispose(); }
}

async function clickScoped(page, selector) {
  await page.waitForSelector(selector, { visible: true });
  await page.click(selector);
}

async function clickButtonText(page, text, scope = 'document') {
  const selector = await page.evaluate(({ text, scope }) => {
    const root = scope === 'document' ? document : document.querySelector(scope);
    const button = [...(root?.querySelectorAll('button') || [])].find(candidate =>
      candidate.textContent.trim() === text && !candidate.disabled && candidate.getClientRects().length);
    if (!button) throw Error(`Visible ${text} button is unavailable`);
    button.setAttribute('data-rendered-ux-click', 'selected');
    return '[data-rendered-ux-click="selected"]';
  }, { text, scope });
  try { await page.click(selector); }
  finally { await page.evaluate(() => document.querySelector('[data-rendered-ux-click="selected"]')
    ?.removeAttribute('data-rendered-ux-click')); }
}

async function clickObjectiveControl(page, slot, expectedPath, wait) {
  const row = `[data-objective-id="${OBJECTIVE}"]`;
  const selector = `${row} > div:nth-child(${slot}) > div`;
  const before = await page.$eval(selector, element => getComputedStyle(element).backgroundColor);
  const pending = wait(page, response => new URL(response.url()).pathname === expectedPath
    && response.request().method() === 'POST');
  await clickScoped(page, selector);
  assert.equal((await pending).status(), 200);
  await page.waitForFunction(({ selector, before }) => {
    const element = document.querySelector(selector);
    return element && getComputedStyle(element).backgroundColor !== before;
  }, {}, { selector, before });
}

async function clickMasterControl(page, card, kind, wait) {
  const path = `/api/admin/challenges/${kind}/toggle`;
  const selector = `${card} [data-control="${kind}"]`;
  const before = await page.$eval(selector, element => getComputedStyle(element).backgroundColor);
  const pending = wait(page, response => new URL(response.url()).pathname === path
    && response.request().method() === 'POST');
  await clickScoped(page, selector);
  assert.equal((await pending).status(), 200);
  await page.waitForFunction(({ selector, before }) => {
    const element = document.querySelector(selector);
    return element && getComputedStyle(element).backgroundColor !== before;
  }, {}, { selector, before });
}

async function gates(page, token, { hint, solution }) {
  const snapshot = await ok(page, token, '/api/workshop/config/snapshot');
  const target = snapshot.exercises[KEY].objectives[OBJECTIVE];
  assert.equal(target.hintVisible, hint);
  assert.equal(target.solutionVisible, solution);
  assert.equal((await browserApi(page, token, HINT)).status, hint ? 200 : 403);
  assert.equal((await browserApi(page, token, SOLUTION)).status, solution ? 200 : 403);
}

async function learnerWorkshop(page, origin, { label, description, hint, solution }) {
  await page.goto(origin + '/workshop/sql', { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(({ label, description, hint, solution }) => {
    const row = [...document.querySelectorAll('.obj-name')].find(node => node.textContent.trim() === label)?.closest('.obj-content');
    if (!row || !row.querySelector('.obj-technique')?.textContent.includes(description)) return false;
    return Boolean(row.querySelector('[data-testid="hint-button-sqli_1"]')) === hint
      && Boolean(row.querySelector('[data-testid="solution-button-sqli_1"]')) === solution;
  }, {}, { label, description, hint, solution });
}

async function assertControlFits(page, selector) {
  await page.waitForSelector(selector, { visible: true });
  assert.equal(await page.$eval(selector, element => {
    const rectangle = element.getBoundingClientRect();
    return rectangle.width > 0 && rectangle.x >= -1 && rectangle.right <= innerWidth + 1;
  }), true, `${selector} must fit the rendered viewport`);
}

async function clickExerciseVisibility(page, card, wait) {
  const selector = `${card} [data-control="active"]`;
  const before = await page.$eval(selector, element => getComputedStyle(element).backgroundColor);
  const pending = wait(page, response => new URL(response.url()).pathname === '/api/admin/challenges/toggle'
    && response.request().method() === 'POST');
  await clickScoped(page, selector);
  assert.equal((await pending).status(), 200);
  await page.waitForFunction(({ selector, before }) => {
    const element = document.querySelector(selector);
    return element && getComputedStyle(element).backgroundColor !== before;
  }, {}, { selector, before });
}

async function loadRawGates(page, token) {
  const [snapshot, objectives] = await Promise.all([
    ok(page, token, '/api/workshop/config/snapshot'),
    ok(page, token, `/api/admin/workshops/${KEY}/objectives`),
  ]);
  const exercise = snapshot.exercises[KEY];
  return {
    isVisible: exercise.isVisible, showHints: exercise.showHints, showSolutions: exercise.showSolutions,
    objectives: Object.fromEntries(objectives.objectives.map(row => [row.objective_id, {
      objectiveEnabled: row.is_enabled,
      hintEnabled: row.hint_enabled,
      solutionEnabled: row.solutions_enabled,
    }])),
  };
}

async function restoreGates(page, token, original) {
  // Master mutations cascade by design. Restore them first, then each original
  // per-objective gate; a final master-off preserves the all-off case.
  for (const [kind, field] of [['hints', 'hintEnabled'], ['solutions', 'solutionEnabled']]) {
    await ok(page, token, `/api/admin/exercises/${KEY}/${kind}`, 'PATCH', { enabled: true });
    for (const [id, row] of Object.entries(original.objectives)) {
      await ok(page, token, `/api/admin/exercises/${KEY}/objectives/${id}/${kind === 'hints' ? 'hint' : 'solution'}`,
        'PATCH', { enabled: row[field] });
    }
    if (!original[kind === 'hints' ? 'showHints' : 'showSolutions'])
      await ok(page, token, `/api/admin/exercises/${KEY}/${kind}`, 'PATCH', { enabled: false });
  }
  for (const [id, row] of Object.entries(original.objectives))
    await ok(page, token, `/api/admin/exercises/${KEY}/objectives/${id}`, 'PATCH', { enabled: row.objectiveEnabled });
  await ok(page, token, `/api/admin/exercises/${KEY}`, 'PATCH', { enabled: original.isVisible });
}

// Called only from the main-backend-auth rendered branch, whose caller owns the
// disposable PostgreSQL stores, authenticated pages, proxy, and browser cleanup.
async function qualifyRenderedWorkshopUx({ origin, admin, learner, sibling, wait }) {
  const { page: adminPage, token: adminToken } = admin;
  const { page: learnerPage, token: learnerToken } = learner;
  const { page: siblingPage, token: siblingToken } = sibling;
  const original = await loadRawGates(adminPage, adminToken);
  const metadata = (await ok(adminPage, adminToken, ADMIN)).objective;
  const hint = (await ok(adminPage, adminToken, ADMIN + '/hint')).hint;
  const solution = (await ok(adminPage, adminToken, ADMIN + '/solution')).solution;
  assert.equal(hint.authored, true, 'The seeded SQL hint must be restorable');
  assert.equal(solution.authored, true, 'The seeded SQL solution must be restorable');
  assert.ok(Array.isArray(hint.hints) && hint.hints.length);
  assert.ok(typeof solution.approach === 'string' && solution.approach.length);
  const modeBefore = (await ok(learnerPage, learnerToken, '/api/workshop/sql/mode')).mode;
  const siblingMode = (await ok(siblingPage, siblingToken, '/api/workshop/sql/mode')).mode;
  const originalViewport = learnerPage.viewport();
  const suffix = randomUUID().slice(0, 8);
  const authored = {
    label: `Instructor UX objective ${suffix}`, description: `Instructor UX description ${suffix}`,
    hintTitle: `Instructor UX hint ${suffix}`, hintText: `Instructor UX hint step ${suffix}`,
    solutionTitle: `Instructor UX solution ${suffix}`, solutionApproach: `Instructor UX approach ${suffix}`,
  };
  const checks = Object.fromEntries(CHECKS.map(key => [key, false]));
  let primaryError;
  try {
    await ok(adminPage, adminToken, `/api/admin/exercises/${KEY}`, 'PATCH', { enabled: true });
    await ok(adminPage, adminToken, ADMIN, 'PATCH', { enabled: true });
    await ok(adminPage, adminToken, `/api/admin/exercises/${KEY}/hints`, 'PATCH', { enabled: true });
    await ok(adminPage, adminToken, `/api/admin/exercises/${KEY}/solutions`, 'PATCH', { enabled: true });
    await ok(adminPage, adminToken, ADMIN + '/hint', 'PATCH', { enabled: true });
    await ok(adminPage, adminToken, ADMIN + '/solution', 'PATCH', { enabled: true });

    const roster = await ok(adminPage, adminToken, '/api/admin/challenges');
    const challenge = roster.challenges.find(row => row.workshopKey === KEY);
    assert.ok(challenge);
    const card = `[data-exercise-key="${challenge.key}"]`;
    await adminPage.goto(origin + '/admin/exercises', { waitUntil: 'domcontentloaded' });
    await adminPage.waitForSelector(card, { visible: true });
    await clickButtonText(adminPage, 'Manage Objectives', card);
    await adminPage.waitForSelector(`[data-objective-id="${OBJECTIVE}"]`, { visible: true });
    const edit = async (trigger, dialog, fields, path) => {
      await clickScoped(adminPage, `[data-objective-id="${OBJECTIVE}"] ${trigger}`);
      await adminPage.waitForSelector(dialog, { visible: true });
      for (const [selector, value] of fields) await replaceField(adminPage, selector, value);
      const pending = wait(adminPage, response => new URL(response.url()).pathname === path
        && response.request().method() === 'PUT');
      await clickButtonText(adminPage, 'Save Changes', dialog);
      assert.equal((await pending).status(), 200);
      await adminPage.waitForFunction(selector => !document.querySelector(selector), {}, dialog);
    };
    await edit('button[title="Edit Objective"]', `[role="dialog"][aria-label="Edit objective ${OBJECTIVE}"]`, [
      [`[role="dialog"][aria-label="Edit objective ${OBJECTIVE}"] input`, authored.label],
      [`[role="dialog"][aria-label="Edit objective ${OBJECTIVE}"] textarea`, authored.description],
    ], ADMIN);
    await edit('button[title="Edit Hint"]', `[role="dialog"][aria-labelledby="prompt-injection-hint-editor-title"]`, [
      ['#prompt-injection-hint-title', authored.hintTitle],
      ['#prompt-injection-hint-0', authored.hintText],
    ], ADMIN + '/hint');
    await edit('button[aria-label^="Edit solution teaching content for"]', `[role="dialog"][aria-label="Edit solution for ${OBJECTIVE}"]`, [
      [`[role="dialog"][aria-label="Edit solution for ${OBJECTIVE}"] input`, authored.solutionTitle],
      [`[role="dialog"][aria-label="Edit solution for ${OBJECTIVE}"] > label:nth-of-type(3) textarea`, authored.solutionApproach],
    ], ADMIN + '/solution');
    assert.equal((await ok(adminPage, adminToken, ADMIN)).objective.label, authored.label);
    assert.equal((await ok(adminPage, adminToken, ADMIN)).objective.description, authored.description);
    assert.equal((await ok(adminPage, adminToken, ADMIN + '/hint')).hint.hints[0], authored.hintText);
    assert.equal((await ok(adminPage, adminToken, ADMIN + '/solution')).solution.approach, authored.solutionApproach);
    checks.instructorAuthored = true;

    await gates(learnerPage, learnerToken, { hint: true, solution: true });
    await learnerPage.setViewport({ width: 1280, height: 800 });
    await learnerWorkshop(learnerPage, origin, { ...authored, hint: true, solution: true });
    await assertControlFits(learnerPage, `[data-testid="hint-button-${OBJECTIVE}"]`);
    await clickScoped(learnerPage, `[data-testid="hint-button-${OBJECTIVE}"]`);
    await learnerPage.waitForFunction(text => document.querySelector('[data-testid="objective-help-modal"][data-help-kind="hint"]')?.textContent.includes(text), {}, authored.hintText);
    await clickScoped(learnerPage, '[aria-label="Close hint"]');
    await clickScoped(learnerPage, `[data-testid="solution-button-${OBJECTIVE}"]`);
    await learnerPage.waitForFunction(text => document.querySelector('[data-testid="objective-help-modal"][data-help-kind="solution"]')?.textContent.includes(text), {}, authored.solutionApproach);
    await clickScoped(learnerPage, '[aria-label="Close solution"]');
    checks.learnerHelpDialogs = true;
    await learnerPage.setViewport({ width: 390, height: 844, isMobile: true, hasTouch: true });
    await assertControlFits(learnerPage, `[data-testid="hint-button-${OBJECTIVE}"]`);
    await assertControlFits(learnerPage, '[data-workshop-mode-control]');
    await clickScoped(learnerPage, `[data-testid="hint-button-${OBJECTIVE}"]`);
    await learnerPage.waitForFunction(text => document.querySelector('[data-testid="objective-help-modal"][data-help-kind="hint"]')?.textContent.includes(text), {}, authored.hintText);
    await assertControlFits(learnerPage, '[data-testid="objective-help-modal"]');
    await clickScoped(learnerPage, '[aria-label="Close hint"]');
    checks.representativeWidths = true;

    await clickObjectiveControl(adminPage, 3, `/api/admin/workshops/${KEY}/hints/${OBJECTIVE}/toggle`, wait);
    await gates(learnerPage, learnerToken, { hint: false, solution: true });
    await learnerWorkshop(learnerPage, origin, { ...authored, hint: false, solution: true });
    await clickObjectiveControl(adminPage, 3, `/api/admin/workshops/${KEY}/hints/${OBJECTIVE}/toggle`, wait);
    checks.effectiveHintGate = true;
    await clickObjectiveControl(adminPage, 4, '/api/admin/sql-injection-workshop/solutions/toggle', wait);
    await gates(learnerPage, learnerToken, { hint: true, solution: false });
    await learnerWorkshop(learnerPage, origin, { ...authored, hint: true, solution: false });
    await clickObjectiveControl(adminPage, 4, '/api/admin/sql-injection-workshop/solutions/toggle', wait);
    checks.effectiveSolutionGate = true;

    await clickObjectiveControl(adminPage, 2, `/api/admin/workshops/${KEY}/objectives/${OBJECTIVE}/toggle`, wait);
    const hiddenObjective = (await ok(learnerPage, learnerToken, '/api/workshop/config/snapshot')).exercises[KEY].objectives[OBJECTIVE];
    assert.equal(hiddenObjective.isVisible, false);
    await gates(learnerPage, learnerToken, { hint: false, solution: false });
    await learnerPage.goto(origin + '/workshop/sql', { waitUntil: 'domcontentloaded' });
    await learnerPage.waitForFunction(text => document.body.innerText.includes('Exercise Objectives')
      && ![...document.querySelectorAll('.obj-name')].some(node => node.textContent.trim() === text), {}, authored.label);
    await clickObjectiveControl(adminPage, 2, `/api/admin/workshops/${KEY}/objectives/${OBJECTIVE}/toggle`, wait);
    await gates(learnerPage, learnerToken, { hint: true, solution: true });
    checks.objectiveVisibility = true;

    await clickButtonText(adminPage, 'Done');
    await adminPage.waitForFunction(() => !document.querySelector('[data-objective-id="sqli_1"]'));
    await clickExerciseVisibility(adminPage, card, wait);
    assert.equal((await ok(learnerPage, learnerToken, '/api/workshop/config/snapshot')).exercises[KEY].isVisible, false);
    assert.equal((await ok(learnerPage, learnerToken, '/api/workshop/challenges')).challenges.some(row => row.workshopKey === KEY), false);
    await clickExerciseVisibility(adminPage, card, wait);
    assert.equal((await ok(learnerPage, learnerToken, '/api/workshop/config/snapshot')).exercises[KEY].isVisible, true);
    checks.exerciseVisibility = true;
    await clickMasterControl(adminPage, card, 'hints', wait);
    await gates(learnerPage, learnerToken, { hint: false, solution: true });
    await clickMasterControl(adminPage, card, 'hints', wait);
    checks.masterHintGate = true;
    await clickMasterControl(adminPage, card, 'solutions', wait);
    await gates(learnerPage, learnerToken, { hint: true, solution: false });
    await clickMasterControl(adminPage, card, 'solutions', wait);
    checks.masterSolutionGate = true;

    const siblingProgress = await ok(siblingPage, siblingToken, '/api/workshop/progress');

    const challenges = await ok(learnerPage, learnerToken, '/api/workshop/challenges');
    const progress = await ok(learnerPage, learnerToken, '/api/workshop/progress');
    const stats = await ok(learnerPage, learnerToken, '/api/workshop/student/stats');
    const sql = assertChallengeParity(challenges, progress, stats, authored);
    await learnerPage.goto(origin + '/workshop/challenges', { waitUntil: 'domcontentloaded' });
    await learnerPage.waitForFunction(text => document.body.innerText.includes(text), {}, authored.label);
    await learnerPage.goto(origin + '/workshop-dashboard', { waitUntil: 'domcontentloaded' });
    await learnerPage.waitForFunction(({ done, total }) => [...document.querySelectorAll('span')].some(node =>
      node.parentElement?.textContent.trim() === `${done} / ${total}`
      && node.parentElement.previousElementSibling?.textContent.trim() === 'Objectives'), {}, { done: stats.completedObjectives, total: stats.totalObjectives });
    await learnerPage.goto(origin + '/workshop/progress', { waitUntil: 'domcontentloaded' });
    await learnerPage.waitForFunction(() => location.pathname === '/workshop-dashboard');
    assert.ok(sql.objectiveCount > 0);
    checks.progressLibraryParity = true;

    await learnerWorkshop(learnerPage, origin, { ...authored, hint: true, solution: true });
    const alternate = modeBefore === 'vuln' ? 'fixed' : 'vuln';
    const modePending = wait(learnerPage, response => new URL(response.url()).pathname === '/api/workshop/sql/mode'
      && response.request().method() === 'POST');
    await clickScoped(learnerPage, `[data-workshop-mode-control] button:not([aria-pressed="true"])`);
    assert.equal((await modePending).status(), 200);
    assert.equal((await ok(learnerPage, learnerToken, '/api/workshop/sql/mode')).mode, alternate);
    await learnerPage.waitForSelector(`[data-workshop-mode-control][data-workshop-mode="${alternate}"]`);
    assert.equal((await ok(siblingPage, siblingToken, '/api/workshop/sql/mode')).mode, siblingMode);
    checks.ownerModeIsolation = true;
    const restoreModePending = wait(learnerPage, response => new URL(response.url()).pathname === '/api/workshop/sql/mode'
      && response.request().method() === 'POST');
    await clickScoped(learnerPage, `[data-workshop-mode-control] button:not([aria-pressed="true"])`);
    assert.equal((await restoreModePending).status(), 200);
    assert.equal((await ok(learnerPage, learnerToken, '/api/workshop/sql/mode')).mode, modeBefore);
    await learnerPage.waitForSelector(`[data-workshop-mode-control][data-workshop-mode="${modeBefore}"]`);

    const beforeReset = await ok(learnerPage, learnerToken, '/api/workshop/progress');
    const beforeSql = beforeReset.challenges.find(row => row.workshopKey === KEY);
    assert.ok(beforeSql.completedObjectiveCount > 0, 'Controlled populated SQL completion required for reset proof');
    const resetPending = wait(learnerPage, response => new URL(response.url()).pathname === '/api/workshop/sql/reset'
      && response.request().method() === 'POST');
    await clickButtonText(learnerPage, 'Reset chat, cart & progress');
    await learnerPage.waitForSelector('[role="alertdialog"]', { visible: true });
    assert.match(await learnerPage.$eval('[role="alertdialog"]', node => node.textContent), /Reset chat, cart & progress\?/);
    await clickButtonText(learnerPage, 'Confirm reset', '[role="alertdialog"]');
    assert.equal((await resetPending).status(), 200);
    const afterReset = await ok(learnerPage, learnerToken, '/api/workshop/progress');
    const afterSql = afterReset.challenges.find(row => row.workshopKey === KEY);
    assert.equal(afterSql.completedObjectiveCount, 0);
    assert.deepEqual(await ok(siblingPage, siblingToken, '/api/workshop/progress'), siblingProgress);
    checks.scopedResetIsolation = true;
    assert.equal((await browserApi(learnerPage, learnerToken, ADMIN, 'PUT', { label: 'forbidden' })).status, 403);
    checks.studentMutationDenied = true;
    assert.equal((await browserApi(learnerPage, learnerToken, '/api/agent-runs')).status, 200);
    assert.equal((await browserApi(siblingPage, siblingToken, '/api/agent-runs')).status, 200);
    checks.sessionsPreserved = true;
    await qualifyFixedCsrf({ learner, sibling });
    checks.fixedCsrfEffectIsolation = true;
  } catch (error) { primaryError = error; throw error; } finally {
    let restoreError;
    try {
      if (originalViewport) await learnerPage.setViewport(originalViewport);
      await ok(adminPage, adminToken, ADMIN, 'PUT', {
        label: metadata.label, description: metadata.description, category: metadata.category,
      });
      await ok(adminPage, adminToken, ADMIN + '/hint', 'PUT', { title: hint.title, hints: hint.hints });
      await ok(adminPage, adminToken, ADMIN + '/solution', 'PUT', {
        title: solution.title, approach: solution.approach,
      });
      await restoreGates(adminPage, adminToken, original);
      const restored = await loadRawGates(adminPage, adminToken);
      assert.deepEqual(restored, original);
      const reloaded = (await ok(adminPage, adminToken, ADMIN)).objective;
      assert.equal(reloaded.label, metadata.label);
      assert.equal(reloaded.description, metadata.description);
      assert.deepEqual((await ok(adminPage, adminToken, ADMIN + '/hint')).hint.hints, hint.hints);
      assert.equal((await ok(adminPage, adminToken, ADMIN + '/solution')).solution.approach, solution.approach);
      checks.catalogRestored = true;
      // Mode restoration is owner-scoped and independent of catalog restoration.
      if ((await ok(learnerPage, learnerToken, '/api/workshop/sql/mode')).mode !== modeBefore)
        await ok(learnerPage, learnerToken, '/api/workshop/sql/mode', 'POST', { mode: modeBefore });
    } catch (error) { restoreError = error; }
    if (restoreError) throw new AggregateError([...(primaryError ? [primaryError] : []), restoreError], 'Rendered UX fixture restoration failed');
  }
  const receipt = { scope: 'rendered_platform_workshop_ux', passed: true,
    controlledProjectionOnly: true, actualModelProof: false, checks };
  return assertWorkshopUxReceipt(receipt);
}

module.exports = { qualifyRenderedWorkshopUx, assertWorkshopUxReceipt, assertChallengeParity, CHECKS };
