'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const { createXssObjectiveGrader } = require('../server/services/xssObjectiveGrader');
const { createXssBrowserQualification } = require('../server/services/xssBrowserQualification');
const { createXssEmailDispatch } = require('../server/services/xssEmailDispatch');
const xssEmailCodec = require('../server/services/xssEmailCodec');

const payload = '<img src=x onerror=alert(1)>';
const clean = { name: 'Student', bio: 'clean', website: 'https://example.com' };
const dirty = { ...clean, bio: payload };
const positives = {
  xss_r1: { exerciseId: 'reflected', message: 'format hello', response: '<div>hello</div>', grading: { modelSucceeded: true } },
  xss_r2: { exerciseId: 'reflected', message: 'format <b>hello</b>', response: '<div><b>hello</b></div>', grading: { modelSucceeded: true } },
  xss_r3: { exerciseId: 'reflected', message: payload, response: `<div>${payload}</div>`, grading: { modelSucceeded: true } },
  xss_s1: { exerciseId: 'stored_user', message: 'show profile', response: 'Profile details', grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: clean } } },
  xss_s2: { exerciseId: 'stored_user', message: `set bio ${payload}`, response: 'updated', grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } }, profileReadback: dirty },
  xss_s3: { exerciseId: 'stored_user', message: 'show profile', response: `Profile ${payload}`, grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: dirty } } },
  xss_g1: { exerciseId: 'stored_llm', message: 'what can you do?', response: 'I generate QA HTML.', grading: { modelSucceeded: true }, profileBefore: clean, profileReadback: clean },
  xss_g2: { exerciseId: 'stored_llm', message: 'save the generated sample', response: 'saved', grading: { modelSucceeded: true, toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } }, profileReadback: dirty },
  xss_g3: { exerciseId: 'stored_llm', message: 'show profile', response: `Profile ${payload}`, grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: dirty } } },
  xss_e1: { exerciseId: 'email', message: 'list emails', response: 'Inbox empty', grading: { toolCall: { tool: 'listEmails' }, toolResult: { emails: [] } }, configuredInbox: 'student@sharklasers.com' },
};
const negatives = {
  xss_r1: { ...positives.xss_r1, grading: { modelSucceeded: false } },
  xss_r2: { ...positives.xss_r2, response: '<div>&lt;b&gt;hello&lt;/b&gt;</div>' },
  xss_r3: { ...positives.xss_r3, response: '<script>alert(1)</script>' },
  xss_s1: { ...positives.xss_s1, grading: { toolCall: { tool: 'getProfile' }, toolResult: { error: 'unavailable' } } },
  xss_s2: { ...positives.xss_s2, profileReadback: clean },
  xss_s3: { ...positives.xss_s3, response: 'Profile clean', grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: clean } } },
  xss_g1: { ...positives.xss_g1, profileReadback: dirty },
  xss_g2: { ...positives.xss_g2, message: `save ${payload}` },
  xss_g3: { ...positives.xss_g3, response: 'Profile clean', grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: clean } } },
  xss_e1: { ...positives.xss_e1, configuredInbox: '' },
};

test('local Ollama 8B qualifies the ten non-dispatch XSS objective positive and negative receipts', {
  skip: process.env.RUN_LIVE_JUDGE !== '1', timeout: 600000,
}, async t => {
  const judge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
    model: 'llama3.1:8b', baseURL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434' }) });
  const browserQualification = createXssBrowserQualification();
  t.after(() => browserQualification.close());
  const completionService = {
    beginAttempt: async ({ userId, workshopKey, objectiveId, execution }) => ({ userId, workshopKey, objectiveId, generation: 1, runId: execution.runId }),
    evaluate: async input => {
      const judgment = await judge(input);
      return { judgment, completed: judgment.verdict === 'pass' };
    },
  };
  for (const [positive, fixtures] of [[true, positives], [false, negatives]]) {
    for (const [objectiveId, fixture] of Object.entries(fixtures)) {
      await t.test(`${objectiveId} ${positive ? 'positive' : 'negative'}`, async () => {
        const grader = createXssObjectiveGrader({ postgres: true, completionService, browserQualification });
        const execution = { ownerId: '17', runId: `xss-live-${objectiveId}-${positive ? 'p' : 'n'}`,
          signal: new AbortController().signal, check: async () => {}, emit: async () => {} };
        const attempt = await grader.begin(17, objectiveId, execution);
        const grade = await grader.evaluate({ userId: 17, objectiveId, ...fixture, execution, attempt });
        t.diagnostic(JSON.stringify(require('./fixtures/judgeDiagnostic').judgeDiagnostic({family:'XSS',id:objectiveId,expected:positive?'pass':'not_pass',judgment:grade.judgment})));
        assert.equal(grade.judgment.provider, 'ollama');
        assert.equal(grade.judgment.model, 'llama3.1:8b');
        if (positive) assert.equal(grade.judgment.verdict, 'pass', JSON.stringify(grade.judgment));
        else assert.notEqual(grade.judgment.verdict, 'pass', JSON.stringify(grade.judgment));
      });
    }
  }
});

async function mintEmailFixtures(execution, objectiveId) {
  const recipient = 'student@sharklasers.com';
  const sender = 'sender@fixture.invalid';
  const rows = [];
  let outbound;
  const dispatch = createXssEmailDispatch({
    repository: {
      async append(record) { const row = { ...record, omitted: false }; rows.push(row); return row; },
      async list() { return rows.slice(); },
    },
    transport: {
      getStatus: () => ({ targetEmail: sender }),
      async sendEmail(to, subject, body, ownerKey, options) {
        outbound = { to, subject, body, ownerKey, html: options.html };
        return { success: true, messageId: '<live-owned@fixture.invalid>', sentTo: to, sentFrom: sender,
          accepted: [to], rejected: [], smtpAccepted: true, deliveryConfirmed: false };
      },
    },
    mailbox: {
      canonicalize: value => value.trim().toLowerCase(),
      async fetchEmails() { return { success: true, emails: [{ id: 'owned-inbox', subject: outbound.subject }] }; },
      async fetchEmail() { return { success: true, email: { id: 'owned-inbox', subject: outbound.subject,
        from: sender, htmlBody: outbound.html } }; },
    },
    codec: xssEmailCodec,
    expectedSender: sender,
  });
  const scope = { userId: 17, generation: 1, execution };
  const delivery = await dispatch.send(scope, { recipient, payload });
  if (objectiveId === 'xss_e2') {
    return {
      positive: { exerciseId: 'email', message: 'send selected payload', response: '', delivery },
      negative: { exerciseId: 'email', message: 'send selected payload', response: '', delivery: { ...delivery } },
    };
  }
  const retrieved = await dispatch.retrieve(scope, { recipient });
  const response = `Summary ${retrieved.email.body}`;
  return {
    positive: { exerciseId: 'email', message: 'read sender', response,
      grading: { toolCall: { tool: 'getEmail' }, toolResult: { email: retrieved.email } } },
    negative: { exerciseId: 'email', message: 'read sender', response,
      grading: { toolCall: { tool: 'getEmail' }, toolResult: { email: { ...retrieved.email } } } },
  };
}

test('local Ollama 8B judges opaque current dispatch proofs for revised e2 and e3 rubrics', {
  skip: process.env.RUN_LIVE_XSS_EMAIL_DISPATCH !== '1', timeout: 300000,
}, async t => {
  const judge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
    model: 'llama3.1:8b', baseURL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434' }) });
  const actualBrowser = createXssBrowserQualification();
  t.after(() => actualBrowser.close());
  let browserCalls = 0;
  const browserQualification = {
    qualify: async (...args) => { browserCalls += 1; return actualBrowser.qualify(...args); },
    close: () => actualBrowser.close(),
  };
  const completionService = {
    beginAttempt: async ({ userId, workshopKey, objectiveId, execution }) => ({
      userId, workshopKey, objectiveId, generation: 1, runId: execution.runId,
    }),
    evaluate: async input => {
      const judgment = await judge(input);
      return { judgment, completed: judgment.verdict === 'pass' };
    },
  };
  for (const objectiveId of ['xss_e2', 'xss_e3']) {
    await t.test(objectiveId, async t => {
      const execution = { ownerId: '17', runId: `xss-live-${objectiveId}`, generation: 1,
        ownerKey: JSON.stringify(['XSS', '17']), durableGeneration: 1,
        signal: new AbortController().signal, check: async () => {}, emit: async () => {},
        effect: async (_key, callback) => callback() };
      const fixtures = await mintEmailFixtures(execution, objectiveId);
      const grader = createXssObjectiveGrader({ postgres: true, completionService, browserQualification });
      const attempt = await grader.begin(17, objectiveId, execution);
      for (const positive of [true, false]) {
        const beforeBrowser = browserCalls;
        const grade = await grader.evaluate({ userId: 17, objectiveId,
          ...(positive ? fixtures.positive : fixtures.negative), execution, attempt });
        t.diagnostic(JSON.stringify(require('./fixtures/judgeDiagnostic').judgeDiagnostic({ family: 'XSS', id: objectiveId,
          expected: positive ? 'pass' : 'not_pass', judgment: grade.judgment })));
        assert.equal(grade.judgment.provider, 'ollama');
        assert.equal(grade.judgment.model, 'llama3.1:8b');
        if (positive) assert.equal(grade.judgment.verdict, 'pass', JSON.stringify(grade.judgment));
        else {
          assert.notEqual(grade.judgment.verdict, 'pass', JSON.stringify(grade.judgment));
          assert.equal(browserCalls, beforeBrowser, 'forged raw email must not reach browser qualification');
        }
      }
    });
  }
});
