'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

function fixture() {
  return {
    state: { nextId: 1, tickets: [] },
    methods: {
      async support_openTicket_2({ state }, customerId, subject, body) {
        const row = { id: state.nextId++, customer_id: customerId, subject, body, status: 'open' };
        state.tickets.push(row);
        return { lastInsertRowid: row.id };
      },
      async support_refundRequest_3({ state }, customerId, subject, body, status) {
        const row = { id: state.nextId++, customer_id: customerId, subject, body, status };
        state.tickets.push(row);
        return { lastInsertRowid: row.id };
      },
    },
  };
}

test('support open_ticket persists stored-XSS bytes verbatim', async () => {
  await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
    const { openTicket } = scope.loadFresh('agent-host/agents/support/tools/index.js');
    const payload = `<img src=x onerror=alert('xss')>`;
    assert.deepEqual(await openTicket({ subject: 'help', body: payload }, { userId: 1 }),
      { ok: true, ticket_id: 1, subject: 'help', body: payload });
    assert.equal(scope.commerceState.tickets[0].body, payload);
    assert.deepEqual(scope.calls[0].args, [1, 'help', payload]);
  });
});

test('support refund_request preserves derived ticket fields and output', async () => {
  await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
    const { refundRequest } = scope.loadFresh('agent-host/agents/support/tools/index.js');
    const result = await refundRequest({ order_id: 100, reason: 'damaged in shipping' }, { userId: 7 });
    assert.deepEqual(result, { ok: true, ticket_id: 1, order_id: 100, reason: 'damaged in shipping' });
    assert.deepEqual(scope.calls[0].args,
      [7, 'refund request for order 100', 'Reason: damaged in shipping', 'refund_pending']);
    assert.deepEqual(scope.commerceState.tickets[0], {
      id: 1,
      customer_id: 7,
      subject: 'refund request for order 100',
      body: 'Reason: damaged in shipping',
      status: 'refund_pending',
    });
  });
 });
