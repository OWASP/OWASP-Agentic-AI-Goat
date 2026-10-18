'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { effectiveXssMode, renderChatHtml, renderEmailDocument,
  assertXssAttemptModeCurrent } = require('../server/services/xssModePolicy');
const { runXssWorkshopGraph } = require('../server/agent-runtime/xssWorkshopGraph');
const { createXssObjectiveGrader } = require('../server/services/xssObjectiveGrader');
const { createXssEmailObjectiveGrader } = require('../server/services/xssEmailObjectiveGrader');

const payload = `<img src=x onerror="alert('owned')"> & <script>alert(2)</script>`;

test('historical null mode stays vulnerable and fixed mode makes chat and document HTML inert', () => {
  assert.equal(effectiveXssMode(null), 'vuln');
  assert.equal(renderChatHtml(payload, null), payload);
  assert.equal(renderEmailDocument(payload, 'vuln'), payload);
  const chat = renderChatHtml(payload, 'fixed');
  const document = renderEmailDocument(payload, 'fixed');
  assert.equal(chat.includes('<img'), false);
  assert.equal(chat.includes('<script'), false);
  assert.match(chat, /&lt;img/);
  assert.match(chat, /&amp;/);
  assert.equal(document.includes(payload), false);
  assert.match(document, /<pre[^>]*>&lt;img/);
  assert.equal(document.includes('<script'), false);
  assert.throws(() => effectiveXssMode('other'), /Unsupported/);
});

test('mode fence binds owner, workshop, generation and stamp before publication', async () => {
  const attempt = { generation: 4, mode: 'fixed', modeStamp: 'stamp-1' };
  const calls = [];
  const execution = { check: async () => calls.push('check') };
  const readScope = async (owner, key) => {
    calls.push(`${owner}:${key}`);
    return { ...attempt };
  };
  await assertXssAttemptModeCurrent({ ownerId: 17, workshopKey: 'xss_workshop', attempt,
    execution, readScope });
  assert.deepEqual(calls, ['check', '17:xss_workshop', 'check']);
  for (const scope of [{ ...attempt, modeStamp: 'stamp-2' }, { ...attempt, generation: 5 },
    { ...attempt, mode: 'vuln' }]) {
    await assert.rejects(assertXssAttemptModeCurrent({ ownerId: 17, workshopKey: 'xss_workshop',
      attempt, execution, readScope: async () => scope }), { code: 'XSS_MODE_STALE', statusCode: 409 });
  }
});

function graphDependencies(responses, toolResult) {
  let index = 0;
  return { aiService: { chatWithMessages: async () => ({ response: responses[index++],
      provider: 'ollama', model: 'fixture-model' }) },
    parseToolCall: response => response.startsWith('{') ? JSON.parse(response) : null,
    executeXssTool: async () => toolResult,
    detectXss: value => /onerror/.test(value), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '' };
}

test('fixed reflected, stored and email chat preserve source for model/evidence but publish inert content', async () => {
  const base = { message: 'show', clientCompleted: [], userKey: '17', systemPrompt: 'fixture',
    sharklaserEmail: 'student@example.test' };
  const reflected = await runXssWorkshopGraph({ ...base, exerciseId: 'reflected', mode: 'fixed' },
    graphDependencies([payload]));
  assert.equal(reflected.mode, 'fixed');
  assert.equal(reflected.response.includes('<img'), false);
  assert.equal(reflected.responseText, payload);
  assert.equal(reflected.grading.llmResponse, payload);
  assert.equal(reflected.xssDetected, false);

  const stored = await runXssWorkshopGraph({ ...base, message: 'show my profile', exerciseId: 'stored_user', mode: 'fixed' },
    graphDependencies(['{"tool":"getProfile"}', 'Here is the profile.'],
      { profile: { name: 'Student', bio: payload, website: 'https://example.test' } }));
  assert.equal(stored.response.includes('<img'), false);
  assert.match(stored.response, /&lt;img/);
  assert.match(stored.responseText, /<img/);
  assert.equal(stored.grading.toolResult.profile.bio, payload);

  const email = await runXssWorkshopGraph({ ...base, exerciseId: 'email', mode: 'fixed' },
    graphDependencies(['{"tool":"getEmail","args":{"sender":"student@example.test"}}',
      'Here is your email.'], { email: { sender: 'student@example.test', body: payload } }));
  assert.equal(email.response.includes('<img'), false);
  assert.match(email.response, /&lt;img/);
  assert.match(email.responseText, /<img/);
  assert.equal(email.grading.toolResult.email.body, payload);
});

test('fixed attacks do not call a vulnerable Judge or browser and cannot award credit', async () => {
  let calls = 0;
  const browserQualification = { qualify: async () => { calls++; return { executed: true }; }, close() {} };
  const completionService = { evaluate: async () => { calls++; return { completed: true }; } };
  const execution = { check: async () => {} };
  const grader = createXssObjectiveGrader({ postgres: true, completionService, browserQualification });
  const grade = await grader.evaluate({ userId: 17, objectiveId: 'xss_r3', exerciseId: 'reflected',
    response: renderChatHtml(payload, 'fixed'), grading: { modelSucceeded: true },
    execution, attempt: { mode: 'fixed', generation: 1 } });
  assert.equal(grade.completed, false);
  assert.equal(grade.judgment.mode, 'fixed');
  const builder = createXssEmailObjectiveGrader({ canonical: { evaluate: async () => { calls++; } },
    browserQualification, persistCompletion: async () => { calls++; },
    persistJudgment: async () => { calls++; } });
  const builderGrade = await builder.evaluate({ userId: 17, requestedLevel: 1,
    persistedHtml: payload, execution, attempt: { mode: 'fixed' } });
  assert.deepEqual(builderGrade.completedLevels, []);
  assert.equal(builderGrade.judgments[0].mode, 'fixed');
  assert.equal(calls, 0);
});
