'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopIdorLessonTools, projectIdorLessonObservation } =
  require('../server/services/secureshopIdorLessonTools');

const id = '11111111-1111-4111-8111-111111111111';
const other = '22222222-2222-4222-8222-222222222222';
const scope = { launchId: id, scenarioId: other, generation: 1,
  platformOwnerId: 1, platformSessionId: 2 };
const scene = createSceneBinding({ ...scope, targetId: id }, {
  sceneId: other, sceneGeneration: 1, grantId: id, execution: scope,
  withLease: work => work(),
});
const origin = { sessionId: id, requestId: other, runId: id,
  step: 1, callId: 'model-call', toolKey: 'lesson.order_status' };
const order = { orderId: 42, shopUserId: 99, totalAmount: '12.50', status: 'shipped',
  paymentMethod: 'Private synthetic method', paymentStatus: 'approved',
  shippingAddress: 'Synthetic address for the reserved victim',
  subtotalAmount: '12.50', discountAmount: '0.00', couponCode: null, couponPercent: null,
  orderDate: '2026-10-12T00:00:00.000000Z', updatedAt: '2026-10-12T00:00:00.000000Z',
  item: { orderItemId: 8, productId: 9, productName: 'Synthetic item', quantity: 1,
    price: '12.50', discountAmount: '0.00' } };
const receipt = result => ({ operationId: id, action: 'order_status', numericId: 42,
  turnOrigin: origin, result });
const decoded = value => JSON.parse(value.content[0].text);

test('model-selected lesson read uses exact reserved ID and branded scene/persona effect order', async () => {
  const events = [];
  const tools = createSecureShopIdorLessonTools({
    repository: { execute(input) { events.push('repository');
      assert.equal(input.retainedScene, scene); assert.equal(input.action, 'order_status');
      assert.equal(input.numericId, 42); assert.deepEqual(input.turnOrigin, origin);
      return receipt({ status: 'disclosed', order }); } },
    scope, persona: { id: 7, role: 'customer' },
    personaSession: { sessionId: id, authorityVersion: '1' }, retainedScene: scene,
    modeToken: Object.freeze({ snapshot: { featureId: 'customer_idor' } }),
    personaFence: { withCrossStoreEffect(work) { events.push('effect'); return work(); } },
    selected: { action: 'order_status', numericId: 42 },
    context: { sessionId: id, requestId: other, runId: id },
    async checkCurrent() { events.push('current'); },
  });
  assert.deepEqual(Object.keys(tools), ['lesson.order_status']);
  assert.deepEqual(events, []);
  const value = await tools['lesson.order_status']({ numericId: 42 },
    { step: 1, callId: 'model-call', tool: 'lesson.order_status' });
  assert.deepEqual(events, ['current', 'effect', 'repository', 'current']);
  assert.deepEqual(decoded(value), { operationId: id, action: 'order_status', numericId: 42,
    status: 'disclosed', order: { orderId: 42, totalAmount: '12.50', status: 'shipped',
      paymentMethod: 'Private synthetic method', paymentStatus: 'approved',
      shippingAddress: 'Synthetic address for the reserved victim' } });
  assert.equal(value.content[0].text.includes('shopUserId'), false);
});

test('fixed denial is a completed observation with no private result; altered original data is rejected', () => {
  const fixed = projectIdorLessonObservation(receipt({ status: 'denied', order: null }),
    'order_status', 42, origin);
  assert.deepEqual(decoded(fixed), { operationId: id, action: 'order_status', numericId: 42, status: 'denied' });
  assert.equal(fixed.isError, undefined);
  assert.throws(() => projectIdorLessonObservation(receipt({ status: 'denied', order }),
    'order_status', 42, origin), { code: 'IDOR_LESSON_UNAVAILABLE' });
  assert.throws(() => projectIdorLessonObservation(receipt({ status: 'disclosed', order: {
    ...order, shippingAddress: 'changed', extra: 'leak',
  } }), 'order_status', 42, origin), { code: 'IDOR_LESSON_UNAVAILABLE' });
  assert.throws(() => projectIdorLessonObservation(receipt({ status: 'disclosed', order }),
    'order_status', 43, origin), { code: 'IDOR_LESSON_UNAVAILABLE' });
});
