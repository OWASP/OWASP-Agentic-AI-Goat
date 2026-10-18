'use strict';
const { controlledObjectiveGraph } = require('./helpers/controlledObjectiveBoundary');

const assert = require('node:assert/strict');
const test = require('node:test');
const { runEmailSendGraph: runEmailSendGraphRuntime } = require('../server/agent-runtime/indirectEmailDeliveryGraph');
const runEmailSendGraph = controlledObjectiveGraph(runEmailSendGraphRuntime);

test('Email delivery preserves an immutable provider receipt while adding grading results', async () => {
  const receipt = Object.freeze({ messageId: 'frozen-mailpit-id', success: true, provider: 'mailpit' });
  let sends = 0;
  const result = await runEmailSendGraph({
    userKey: 'owner-a',
    recipientEmail: 'fixture@example.invalid',
    emailBody: 'controlled exact body',
    scenario: 'custom',
    platformUserId: 7,
  }, {
    gmailService: { sendEmail: async () => { sends += 1; return receipt; } },
    logSentEmail: async () => {},
    objectiveJudge: async packet => ({
      verdict: 'pass',
      objectiveId: packet.rubric.objectiveId,
      provider: 'explicit-test-fixture',
    }),
    markEmailAgentObjectiveComplete: async () => ({ projectionPending: false }),
  });

  assert.equal(sends, 1);
  assert.notEqual(result, receipt);
  assert.equal(result.messageId, receipt.messageId);
  assert.equal(result.objectiveCompleted, 2);
  assert.equal(result.judgments.length, 1);
  assert.deepEqual(receipt, { messageId: 'frozen-mailpit-id', success: true, provider: 'mailpit' });
});
