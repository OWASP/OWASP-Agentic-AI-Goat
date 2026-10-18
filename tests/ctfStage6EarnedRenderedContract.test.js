'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { qualifyStage6EarnedRendered, submitStage6CandidateInBrowser,
  retireStage6Browser, createIdentityPage, retireStage6ReadbackBrowser,
  adminLeaderboardRowVisible, adminStage6AttemptVisible } =
  require('./fixtures/ctfStage6EarnedRendered');

test('admin predicates bind exact leaderboard Stages cell and full Stage 6 payload title', () => {
  const previous = global.document;
  const cell = (value, title) => ({ textContent: value,
    getAttribute: key => key === 'title' ? title : null });
  const leaderboard = { querySelectorAll: () => [cell('#1'), cell('owner'), cell('—'),
    cell('6'), cell('1h'), cell('6'), cell('100%'), cell('100'), cell('Reset')] };
  const payload = 'a genuine Stage 6 candidate that is longer than sixty visible characters';
  const attempt = { querySelectorAll: () => [cell('now'), cell('owner'), cell('#6 Guardian'),
    cell(payload.slice(0, 60), payload), cell('—'), cell('No'), cell('Success')] };
  try {
    global.document = { querySelectorAll: () => [leaderboard] };
    assert.equal(adminLeaderboardRowVisible({ name: 'owner', completed: 6 }), true);
    assert.equal(adminLeaderboardRowVisible({ name: 'owner', completed: 5 }), false);
    assert.equal(adminLeaderboardRowVisible({ name: 'sibling', completed: 6 }), false);
    global.document = { querySelectorAll: () => [attempt] };
    assert.equal(adminStage6AttemptVisible({ name: 'owner', payload, stage: 6 }), true);
    assert.equal(adminStage6AttemptVisible({ name: 'owner', payload: payload.slice(0, 60), stage: 6 }), false);
    assert.equal(adminStage6AttemptVisible({ name: 'owner', payload, stage: 7 }), false);
  } finally {
    if (previous === undefined) delete global.document;
    else global.document = previous;
  }
});

test('readback uses distinct browser contexts and retires page, context, then browser serially', async () => {
  const contexts = [], order = [];
  const browser = {
    createBrowserContext: async () => {
      const id = contexts.length + 1;
      const context = {
        id,
        newPage: async () => ({ id, close: async () => { order.push(`page${id}`); } }),
        close: async () => { order.push(`context${id}`); },
      };
      return context;
    },
    close: async () => { order.push('browser'); },
  };
  const pages = [];
  for (let i = 0; i < 3; i += 1) pages.push(await createIdentityPage(browser, contexts));
  assert.equal(new Set(contexts).size, 3);
  assert.deepEqual(pages.map(page => page.id), [1, 2, 3]);
  assert.deepEqual(await retireStage6ReadbackBrowser({ pages, contexts, browser }), []);
  assert.deepEqual(order, ['page1', 'page2', 'page3', 'context1', 'context2', 'context3', 'browser']);
});

test('readback cleanup still retires contexts and browser if a page fails to close', async () => {
  const order = [], failure = Error('page close failed');
  const failures = await retireStage6ReadbackBrowser({
    pages: [{ close: async () => { order.push('page'); throw failure; } }],
    contexts: [{ close: async () => { order.push('context'); } }],
    browser: { close: async () => { order.push('browser'); } },
  });
  assert.deepEqual(failures, [failure]);
  assert.deepEqual(order, ['page', 'context', 'browser']);
});

test('earned Stage 6 browser rejects nonpass and unaccepted judgments before browser or network', async () => {
  const oldDisposable = process.env.PG_TEST_DISPOSABLE;
  const oldRendered = process.env.CTF_STAGE6_EARNED_RENDERED;
  process.env.PG_TEST_DISPOSABLE = 'yes';
  process.env.CTF_STAGE6_EARNED_RENDERED = '1';
  const args = {
    origin: 'http://127.0.0.1:1', stage6: { id: 6, stage_number: 6 },
    stage7: { id: 7, stage_number: 7 }, resetOwner: async () => {},
    authorityApplication: { runtime: { readiness: async () => ({ runtimeReady: true }) } },
    acceptedJudgment: { verdict: 'fail', accepted: 0, stage_id: 6,
      metadata: JSON.stringify({ guardian: { provider: 'ollama', model: 'llama3.1:8b' } }) },
  };
  try {
    const active = args.authorityApplication;
    args.authorityApplication = null;
    await assert.rejects(qualifyStage6EarnedRendered(args), /activated current CTF authority application required/);
    args.authorityApplication = active;
    await assert.rejects(qualifyStage6EarnedRendered(args), /canonical genuine Judge pass required/);
    args.acceptedJudgment.verdict = 'pass';
    await assert.rejects(qualifyStage6EarnedRendered(args), /accepted Stage 6 judgment required/);
    args.acceptedJudgment.accepted = 1;
    args.acceptedJudgment.metadata = JSON.stringify({ guardian: { provider: 'mock', model: 'fixture' } });
    await assert.rejects(qualifyStage6EarnedRendered(args), /'mock' !== 'ollama'/);
  } finally {
    if (oldDisposable === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = oldDisposable;
    if (oldRendered === undefined) delete process.env.CTF_STAGE6_EARNED_RENDERED;
    else process.env.CTF_STAGE6_EARNED_RENDERED = oldRendered;
  }
});

test('browser cleanup ends case, closes page, then attempts Chrome even if page close fails', async () => {
  const order = [], failedPage = Error('page already closed');
  const failures = await retireStage6Browser({
    afterSubmit: async () => { order.push('case'); },
    page: { close: async () => { order.push('page'); throw failedPage; } },
    browser: { close: async () => { order.push('browser'); } },
  });
  assert.deepEqual(order, ['case', 'page', 'browser']);
  assert.deepEqual(failures, [failedPage]);
});

test('same-attempt browser submission denies invalid stage and callback contract before launch', async () => {
  const oldDisposable = process.env.PG_TEST_DISPOSABLE;
  const oldRendered = process.env.CTF_STAGE6_EARNED_RENDERED;
  process.env.PG_TEST_DISPOSABLE = 'yes';
  process.env.CTF_STAGE6_EARNED_RENDERED = '1';
  const args = { origin: 'http://127.0.0.1:1', stage6: { id: 9, stage_number: 9 },
    payload: 'fixed candidate', beforeSubmit: async () => {}, afterSubmit: async () => {} };
  try {
    await assert.rejects(submitStage6CandidateInBrowser(args), /9 !== 6/);
    args.stage6.stage_number = 6;
    args.payload = ' fixed candidate ';
    await assert.rejects(submitStage6CandidateInBrowser(args), /expression evaluated to a falsy value/);
    args.payload = 'fixed candidate';
    args.afterSubmit = null;
    await assert.rejects(submitStage6CandidateInBrowser(args),
      error => error.code === 'ERR_ASSERTION' && /'object'/.test(error.message));
  } finally {
    if (oldDisposable === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = oldDisposable;
    if (oldRendered === undefined) delete process.env.CTF_STAGE6_EARNED_RENDERED;
    else process.env.CTF_STAGE6_EARNED_RENDERED = oldRendered;
  }
});
