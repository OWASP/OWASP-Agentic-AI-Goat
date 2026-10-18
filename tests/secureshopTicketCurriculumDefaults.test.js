'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const curriculum = require('../server/config/secureshopCurriculum');

const id = 'ss_ticket_stored_browser_execution';

test('ticket browser curriculum default is disabled and describes only the supported evidence mechanism', () => {
  const objective = curriculum.OBJECTIVES.find(value => value.id === id);
  assert.deepEqual(curriculum.EXERCISES.find(value => value.id === 'ss_ticket_browser'), {
    id: 'ss_ticket_browser',
    title: 'Observe a customer-confirmed support ticket in the actual admin viewer',
    objectiveIds: [id],
  });
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(objective?.qualification, 'native-browser-judge');
  assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective?.evidence || '', /bound_ticket_browser/);
  assert.match(objective?.evidence || '', /secureshop-ticket-browser-v2/);
  assert.match(objective?.evidence || '', /server-issued.*reference.*exact current human request/);
  assert.match(objective?.evidence || '', /secureshop-ticket-browser-v1/);
  assert.match(objective?.evidence || '', /Historical.*packets retain/);
  assert.match(objective?.evidence || '', /stored_ticket_executed/);
  assert.match(objective?.evidence || '', /support\.ticket_prepare/);
  assert.match(objective?.evidence || '', /SecureShop\.AdminTicketBody/);
  assert.match(objective?.evidence || '', /Fixed mode.*no credit/);
  const hints = curriculum.HINTS[id].hints.join(' ');
  assert.match(hints, /disabled by default/i);
  assert.match(hints, /actual rendered qualification remains pending/i);
  const example = curriculum.SOLUTIONS[id].examples[0];
  assert.match(example.action, /Open support ticket once/);
  assert.match(example.action, /separate same-tenant administrator session/);
  assert.match(example.explanation, /IDs-only confirmed immutable ticket/);
  assert.match(example.explanation, /canonical Judge/i);
});
