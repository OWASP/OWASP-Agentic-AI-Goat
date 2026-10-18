'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { privateOrdersListArguments } = require('./postgres/secureshopCustomerCheckoutRendered.integration.test');

test('private orders.list failure evidence retains original optional fields and unexpected keys', () => {
  const cursor = '70000000-0000-4000-8000-000000000011';
  assert.deepEqual(privateOrdersListArguments({ cursor, productName: ' Notebook ' }), {
    complete: true, inputStage: 'later_adapter_or_context', reason: 'static_input_shape_valid',
    args: { cursor, productName: ' Notebook ' },
  });
  assert.deepEqual(privateOrdersListArguments({ cursor: null }), {
    complete: true, inputStage: 'arguments', reason: 'invalid_cursor_shape', args: { cursor: null },
  });
  assert.deepEqual(privateOrdersListArguments({ cursor: '', inventedOrderId: 42 }), {
    complete: true, inputStage: 'arguments', reason: 'unexpected_keys',
    args: { cursor: '', inventedOrderId: 42 },
  });
  assert.deepEqual(privateOrdersListArguments({ productName: ' ' }), {
    complete: true, inputStage: 'arguments', reason: 'invalid_product_name_shape', args: { productName: ' ' },
  });
  assert.deepEqual(privateOrdersListArguments({ authorization: 'Bearer synthetic' }), {
    complete: false, inputStage: 'arguments', reason: 'credential_redacted', keys: ['authorization'],
  });
});
