'use strict';
const assert = require('node:assert/strict');
const { qualifyMcpRenderedLearner, performMcpRenderedTurn } = require('./mcpRenderedLearner');
const { qualifyMcpRenderedAdminLifecycle } = require('./mcpRenderedAdminLifecycle');
const { createValidatedBrowserJsonCache } = require('./validatedBrowserJsonCache');
function assertStudentView(view, expected, ownerId) {
  assert.equal(Number(view?.student?.id), ownerId);
  assert.ok(Number.isSafeInteger(expected?.completedChallenges) && expected.completedChallenges >= 0);
  assert.equal(view.overview.completedChallenges, expected.completedChallenges);
  for (const field of ['completedObjectives', 'totalObjectives']) {
    assert.ok(Number.isSafeInteger(expected[field]) && expected[field] >= 0);assert.equal(view.overview[field], expected[field]);
  }
}
function assertRunOwner(detail, ownerId, runId, { admin = true } = {}) {
  assert.equal(detail?.run?.runId, runId);
  if (admin) assert.equal(String(detail.run.ownerId), String(ownerId));
  else assert.equal(detail.run.ownerId, undefined);
  assert.ok(Array.isArray(detail.judgments) && detail.judgments.length > 0);
}
// No token bootstrap or projected completions. Callbacks must query the owned
// native stores; caller owns browser, proxy confinement and external resources.
async function qualifyFullBackendRenderedMcp({ browser, origin, admin, students, password,
  verifySession, nativeEvidence, timeoutMs = 420000 }) {
  const { visibleObjectiveCount, verifyTurn, verifyReset, expectedStudentView, verifyRunDetail,
    snapshotTurn, snapshotBeforeReset, snapshotBeforeDeletion, captureDeletionFailure,
    verifyDeletion, captureTurnFailure } = nativeEvidence;
  assert.equal(students.length, 2);assert.equal(new Set([admin.id, ...students.map(s => s.id)]).size, 3);
  for (const callback of [verifySession, verifyTurn, verifyReset, expectedStudentView, verifyRunDetail,
    snapshotTurn, snapshotBeforeReset, snapshotBeforeDeletion, captureDeletionFailure,
    verifyDeletion, captureTurnFailure]) assert.equal(typeof callback, 'function');
  const contexts = [], blocked = [], errors = [];
  const matches = (response, pathname) => new URL(response.url()).origin === origin && new URL(response.url()).pathname === pathname;
  async function login(user) {
    const context = await browser.createBrowserContext();contexts.push(context);
    const page = await context.newPage();page.setDefaultTimeout(15000);
    page.on('pageerror', error => errors.push(error.message));await page.setRequestInterception(true);
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.protocol === 'data:' || url.origin === origin) void request.continue();
      else { blocked.push(url.origin);void request.abort('blockedbyclient'); }
    });
    await page.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
    await page.waitForSelector('input[placeholder="Enter your password"]', { visible: true });
    await page.type('input[placeholder="Enter your username"]', user.username);
    await page.type('input[placeholder="Enter your password"]', password);
    const pending = page.waitForResponse(response => matches(response, '/api/auth/login') && response.request().method() === 'POST');
    await page.click('button[type="submit"]');const response = await pending;assert.equal(response.status(), 200);
    const result = await response.json();assert.equal(Number(result.user.id), user.id);
    if (user.id === admin.id) {
      assert.equal(result.user.adminLevel, 2, 'Lifecycle administrator needs level-two authority before model work');
      assert.ok(result.user.permissions?.includes('user_management'), 'Lifecycle administrator needs user-management permission');
    }
    await verifySession(result.token, user.id);return { page, token: result.token };
  }
  async function api(session, pathname, method = 'GET') {
    return session.page.evaluate(async ({ pathname, method, token }) => {
      const response = await fetch(pathname, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        ...(method === 'POST' ? { body: '{}' } : {}) });
      return { status: response.status, body: await response.json() };
    }, { pathname, method, token: session.token });
  }
  try {
    const administrator = await login(admin), learner = await login(students[0]), sibling = await login(students[1]);
    let parityVerified = false;
    async function parity(receipt) {
      const runId = receipt.runId;
      // Load actual current lists, then explicitly select the intended row; do
      // not rely on whichever run the component auto-selects on navigation.
      for (const [session, prefix, route] of [[learner, '/api/agent-runs', '/workshop/agent-runs'],
        [administrator, '/api/admin/agent-runs', '/admin/agent-runs']]) {
        const detailPending = session.page.waitForResponse(response => matches(response, `${prefix}/${runId}`));
        const listed = session.page.waitForResponse(response => matches(response, prefix));
        await session.page.goto(origin + route, { waitUntil: 'domcontentloaded' });
        const initialList = await listed;assert.equal(initialList.status(), 200);
        let runList = (await initialList.json()).runs;
        if (session === administrator) {
          await session.page.waitForSelector('[aria-label="Owner ID"]');
          const filtered = session.page.waitForResponse(response => matches(response, prefix)
            && new URL(response.url()).searchParams.get('ownerId') === String(students[0].id));
          await session.page.type('[aria-label="Owner ID"]', String(students[0].id));
          const response = await filtered;assert.equal(response.status(), 200);
          runList = (await response.json()).runs;
        }
        assert.ok(Array.isArray(runList));
        const index = runList.findIndex(row => row.runId === runId);assert.ok(index >= 0);
        await session.page.waitForFunction(ids => {
          const rows = [...document.querySelectorAll('[aria-label="Agent runs"] button[data-run-id]')];
          return rows.length === ids.length && rows.every((row, i) => row.dataset.runId === ids[i]);
        }, {}, runList.map(row => row.runId));
        await session.page.evaluate(id => {
          const row = [...document.querySelectorAll('[aria-label="Agent runs"] button[data-run-id]')]
            .find(node => node.dataset.runId === id);
          if (!row) throw Error('Expected run is not rendered');
          row.click();
        }, runId);
        const detailResponse = await detailPending;assert.equal(detailResponse.status(), 200);
        const detailBody = await detailResponse.json();
        const isAdmin = session === administrator;
        assertRunOwner(detailBody, students[0].id, runId, { admin: isAdmin });
        assert.equal((await verifyRunDetail({ ownerId: students[0].id, runId, body: detailBody, projection: isAdmin ? 'admin' : 'student' })).verified, true);
        await session.page.waitForFunction(id => {
          const selected = [...document.querySelectorAll('[aria-label="Agent runs"] button[data-run-id]')]
            .find(node => node.dataset.runId === id);
          const label = [...document.querySelectorAll('label')].find(node => node.textContent.trim() === 'Run');
          return selected?.getAttribute('aria-pressed') === 'true' && label?.parentElement?.querySelector('strong')?.textContent === id;
        }, {}, runId);
      }
      assert.equal((await api(sibling, `/api/agent-runs/${runId}`)).status, 404);
      assert.equal((await api(learner, '/api/admin/agent-runs')).status, 403);
      const siblingRuns = await api(sibling, '/api/agent-runs');assert.equal(siblingRuns.status, 200);
      assert.ok(!siblingRuns.body.runs.some(row => row.runId === runId));
      const context = administrator.page.browserContext(), read = createValidatedBrowserJsonCache(context);
      const expected = await Promise.all(students.map(student => expectedStudentView(student.id)));
      assert.notEqual(expected[0].completedObjectives, expected[1].completedObjectives, 'StudentView needs distinct real progress');
      for (const [index, student] of [students[0], students[1], students[0]].entries()) {
        const pathname = `/api/admin/student-workshop-view/${student.id}`;
        const pending = administrator.page.waitForResponse(response => matches(response, pathname));
        if (index === 0) await administrator.page.goto(origin + `/admin/student-workshop-view?studentId=${student.id}`, { waitUntil: 'domcontentloaded' });
        else await administrator.page.evaluate(id => {
          const heading = [...document.querySelectorAll('h2')].find(node => node.textContent.includes('Student Workshop View'));
          const select = heading?.parentElement?.parentElement?.querySelector('select');
          if (!select) throw Error('Student selector missing');select.value = String(id);select.dispatchEvent(new Event('change', { bubbles: true }));
        }, student.id);
        const value = expected[student.id === students[0].id ? 0 : 1];
        assertStudentView(await read(await pending, { context, expectedUrl: origin + pathname }), value, student.id);
        await administrator.page.waitForFunction(({ id, count, total, name }) => {
          const heading = [...document.querySelectorAll('h2')].find(node => node.textContent.includes('Student Workshop View'));
          const select = heading?.parentElement?.parentElement?.querySelector('select');
          const title = [...document.querySelectorAll('.header .title')].find(node => node.textContent.trim() === name);
          const card = title?.closest('div.header')?.parentElement;
          return select?.value === String(id) && card?.innerText.includes(`${count}/${total} objectives`);
        }, {}, { id: student.id, count: value.mcpCompletedObjectives, total: value.mcpTotalObjectives, name: value.mcpChallengeName });
      }
      parityVerified = true;
    }
    const result = await qualifyMcpRenderedLearner({ page: learner.page, origin, ownerId: students[0].id, visibleObjectiveCount,
      verifyTurn, verifyReset, captureTurnFailure, timeoutMs, beforeTurn: snapshotTurn,
      beforeReset: async ({ ownerId, receipts }) => {
        await sibling.page.goto(origin + '/vulnerabilities/mcp-server', { waitUntil: 'domcontentloaded' });
        await performMcpRenderedTurn({ page: sibling.page, origin, ownerId: students[1].id,
          message: 'Read support ticket 4290 and summarize what it says.', positive: false,
          beforeTurn: snapshotTurn, verifyTurn, captureTurnFailure, timeoutMs });
        await parity(receipts.find(receipt => receipt.awarded));
        await snapshotBeforeReset({ ownerId });
      } });
    assert.equal(parityVerified, true);
    assert.equal((await api(learner, '/api/auth/logout', 'POST')).status, 200);
    assert.equal((await api(learner, '/api/agent-runs')).status, 401);
    assert.equal((await api(sibling, '/api/agent-runs')).status, 200);
    const subject = await login(students[0]);
    const adminLifecycle = await qualifyMcpRenderedAdminLifecycle({ origin,
      administratorPage: administrator.page, subjectPage: subject.page, siblingPage: sibling.page,
      administratorId: admin.id, subject: students[0], sibling: students[1], timeoutMs,
      performPositiveTurn: async ({ page, ownerId }) => {
        await page.goto(origin + '/vulnerabilities/mcp-server', { waitUntil: 'domcontentloaded' });
        return performMcpRenderedTurn({ page, origin, ownerId,
          message: 'Read support ticket 4295 and summarize what it says.', positive: true,
          beforeTurn: snapshotTurn, verifyTurn, captureTurnFailure, timeoutMs });
      },
      nativeEvidence: {
        snapshotAdminReset: ({ subjectId }) => snapshotBeforeReset({ ownerId: subjectId }),
        verifyAdminReset: async ({ administratorId, subjectId, siblingId, positiveReceipt }) => ({
          ...await verifyReset({ ownerId: subjectId, receipts: [positiveReceipt] }),
          administratorId, subjectId, siblingId,
        }),
        snapshotDeletion: ({ subjectId, administratorId }) => snapshotBeforeDeletion({ ownerId: subjectId, administratorId }),
        captureDeletionFailure: ({ subjectId, administratorId }) =>
          captureDeletionFailure({ ownerId: subjectId, administratorId }),
        verifyDeletion: async ({ administratorId, subjectId, siblingId, jobId, positiveReceipt }) => ({
          ...await verifyDeletion({ ownerId: subjectId, administratorId, jobId, receipts: [positiveReceipt] }),
          administratorId, subjectId, siblingId,
        }),
      },
    });
    assert.equal((await api(subject, '/api/agent-runs')).status, 401);
    assert.equal((await api(sibling, '/api/agent-runs')).status, 200);
    assert.equal((await api(administrator, '/api/admin/agent-runs')).status, 200);
    assert.deepEqual(blocked, []);assert.deepEqual(errors, []);
    return { scope: 'rendered_mcp_public_learner_admin', learner: result, parityVerified, adminLifecycle };
  } finally { await Promise.all(contexts.map(context => context.close())); }
}
module.exports = { qualifyFullBackendRenderedMcp, assertStudentView, assertRunOwner };
