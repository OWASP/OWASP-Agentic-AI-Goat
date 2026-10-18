'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createExcessiveAgencyLabDb } = require('../server/database/excessiveAgencyLabDb');
const { createExcessiveAgencyToolRouter } = require('../server/services/excessiveAgencyToolRouter');

const context = labMode => ({ sessionUserId: 'alice', scenario: 'B', labMode });

test('vulnerable cancellation persists a foreign order transition and one full refund', async () => {
  const database = createExcessiveAgencyLabDb();
  const router = createExcessiveAgencyToolRouter(database);
  const before = database.getOrder('order-bob-1');
  assert.equal(before.status, 'completed');
  assert.equal(database.getAllRefunds().length, 0);

  const result = await router.executeTool('cancelOrder', {
    orderId: before.orderId,
    reason: 'learner selected foreign cancellation',
  }, context('vuln'));

  assert.equal(result.cancelled, true);
  assert.equal(result.order.status, 'cancelled');
  assert.match(result._warning, /bob.*without authorization/i);
  assert.equal(database.getOrder(before.orderId).status, 'cancelled');
  assert.deepEqual(database.getOrdersByUser('bob').find(order => order.orderId === before.orderId).status, 'cancelled');
  const refunds = database.getRefundsByOrder(before.orderId);
  assert.equal(refunds.length, 1);
  assert.equal(refunds[0].amountCents, before.amountCents);
  assert.equal(refunds[0].status, 'approved');
  assert.equal(refunds[0].requestedBy, 'alice');

  const repeated = await router.executeTool('cancelOrder', { orderId: before.orderId }, context('vuln'));
  assert.equal(repeated.success, false);
  assert.equal(repeated.code, 'ORDER_NOT_CANCELLABLE');
  assert.match(repeated.error, /no longer completed/);
  assert.equal(database.getRefundsByOrder(before.orderId).length, 1);
});

test('fixed cancellation denial changes neither order nor refund ledger', async () => {
  const database = createExcessiveAgencyLabDb();
  const router = createExcessiveAgencyToolRouter(database);
  const result = await router.executeTool('cancelOrder', {
    orderId: 'order-bob-1', reason: 'must remain denied',
  }, context('fixed'));
  assert.match(result.error, /not permitted/i);
  assert.equal(database.getOrder('order-bob-1').status, 'completed');
  assert.equal(database.getRefundsByOrder('order-bob-1').length, 0);
});
