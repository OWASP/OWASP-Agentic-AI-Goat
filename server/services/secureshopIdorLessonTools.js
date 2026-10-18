'use strict';

const { withSceneLease } = require('./secureshopSceneBinding');
const { IDOR_LESSON_TOOLS, normalizeIdorLessonSelection,
  normalizeIdorLessonTurnOrigin } = require('./secureshopIdorLessonContract');

function unavailable() {
  return Object.assign(new Error('Isolated access-control lesson unavailable'), {
    code: 'IDOR_LESSON_UNAVAILABLE', executionBoundary: true,
  });
}
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
}
function text(value, maximum) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')
      || Buffer.byteLength(value, 'utf8') > maximum) throw unavailable();
  return value;
}
function observation(value) {
  const encoded = JSON.stringify(value);
  if (!encoded || Buffer.byteLength(encoded, 'utf8') > 8192) throw unavailable();
  return Object.freeze({ content: Object.freeze([{ type: 'text', text: encoded }]) });
}
function selectedOrder(order, numericId) {
  if (!exact(order, ['orderId', 'shopUserId', 'totalAmount', 'subtotalAmount',
    'discountAmount', 'couponCode', 'couponPercent', 'status', 'paymentMethod',
    'paymentStatus', 'shippingAddress', 'orderDate', 'updatedAt', 'item'])
      || order.orderId !== numericId || !Number.isSafeInteger(order.shopUserId)
      || order.shopUserId < 1 || order.couponCode !== null || order.couponPercent !== null
      || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(order.orderDate)
      || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(order.updatedAt)
      || !exact(order.item, ['orderItemId','productId','productName','quantity','price','discountAmount'])
      || ![order.item.orderItemId,order.item.productId,order.item.quantity]
        .every(value => Number.isSafeInteger(value) && value > 0)) throw unavailable();
  const totalAmount = text(order.totalAmount, 64);
  if (!/^\d{1,18}(?:\.\d{1,2})?$/.test(totalAmount)) throw unavailable();
  for (const amount of [order.subtotalAmount,order.discountAmount,order.item.price,
    order.item.discountAmount]) {
    if (!/^\d{1,18}(?:\.\d{1,2})?$/.test(text(amount,64))) throw unavailable();
  }
  text(order.item.productName, 512);
  return Object.freeze({ orderId: numericId, totalAmount,
    status: text(order.status, 128), paymentMethod: text(order.paymentMethod, 128),
    paymentStatus: text(order.paymentStatus, 128),
    shippingAddress: text(order.shippingAddress, 2048) });
}
function project(receipt, action, numericId, turnOrigin) {
  if (!receipt || typeof receipt !== 'object' || receipt.action !== action
      || receipt.numericId !== numericId
      || typeof receipt.operationId !== 'string'
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(receipt.operationId)
      || !exact(receipt.turnOrigin, ['sessionId', 'requestId', 'runId', 'step', 'callId', 'toolKey'])
      || Object.keys(turnOrigin).some(key => receipt.turnOrigin[key] !== turnOrigin[key])
      || !receipt.result || typeof receipt.result !== 'object') throw unavailable();
  const status = receipt.result.status;
  if (status === 'denied') {
    if (action === 'cart_remove' && (!exact(receipt.result, ['status', 'preimage']) || receipt.result.preimage !== null)
        || action === 'order_status' && (!exact(receipt.result, ['status', 'order']) || receipt.result.order !== null)) throw unavailable();
    return observation({ operationId: receipt.operationId, action, numericId, status: 'denied' });
  }
  if (action === 'cart_remove') {
    if (status !== 'deleted' || !exact(receipt.result, ['status', 'preimage'])
        || receipt.result.preimage?.cartItemId !== numericId) throw unavailable();
    return observation({ operationId: receipt.operationId, action, numericId, status: 'deleted' });
  }
  if (status !== 'disclosed' || !exact(receipt.result, ['status', 'order'])) throw unavailable();
  return observation({ operationId: receipt.operationId, action, numericId,
    status: 'disclosed', order: selectedOrder(receipt.result.order, numericId) });
}

function createSecureShopIdorLessonTools({ repository, scope, persona, personaSession,
  retainedScene, modeToken, personaFence, selected, context, checkCurrent,
  onReceipt, signal } = {}) {
  if (typeof repository?.execute !== 'function' || typeof personaFence?.withCrossStoreEffect !== 'function'
      || typeof checkCurrent !== 'function'
      || onReceipt !== undefined && typeof onReceipt !== 'function'
      || persona?.role !== 'customer'
      || !context || !scope || !retainedScene || !modeToken) throw new TypeError('Isolated lesson tool authority required');
  const choice = normalizeIdorLessonSelection(selected);
  const run = action => async (args, invocation) => {
    if (action !== choice.action || !exact(args, ['numericId'])
        || args.numericId !== choice.numericId) {
      return Object.freeze({ ...observation({ status: 'denied', code: 'LESSON_SELECTION_MISMATCH' }), isError: true });
    }
    const turnOrigin = normalizeIdorLessonTurnOrigin({ sessionId: context.sessionId,
      requestId: context.requestId, runId: context.runId,
      step: invocation?.step, callId: invocation?.callId, toolKey: invocation?.tool }, action);
    signal?.throwIfAborted();
    await checkCurrent();
    const receipt = await withSceneLease(retainedScene, () => personaFence.withCrossStoreEffect(() =>
      repository.execute({ scope, persona, personaSession, retainedScene, modeToken,
        action, numericId: choice.numericId, requestId: context.requestId, turnOrigin, signal })));
    await checkCurrent();
    signal?.throwIfAborted();
    const value = project(receipt, action, choice.numericId, turnOrigin);
    onReceipt?.(Object.freeze({ receipt, origin: turnOrigin, observation: value }));
    return value;
  };
  // PersonaToolDispatch requires an explicit mode for every local entry.
  // Only the server-selected lesson action enters this turn's tool map.
  return Object.freeze({ [IDOR_LESSON_TOOLS[choice.action]]: run(choice.action) });
}

module.exports = { createSecureShopIdorLessonTools, projectIdorLessonObservation: project };
