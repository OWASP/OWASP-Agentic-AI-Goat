'use strict';
function invalid(message) { return Object.assign(new TypeError(message), { code: 'INVALID_ARGUMENT' }); }
function wrap(value, isError = false) {
  const result = { content: Object.freeze([{ type: 'text', text: JSON.stringify(value) }]) };
  if (isError) result.isError = true;
  return Object.freeze(result);
}
function orderId(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw invalid('order_id is invalid');
  return value;
}
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every(key => keys.includes(key));
}
function createSecureShopBoundRefundTools({ repository, commerce, binding, persona, scope, checkCurrent, resolveTarget,
  mode = 'vuln', fixedIntent = null } = {}) {
  if (typeof repository?.create !== 'function' || typeof commerce?.order !== 'function'
      || typeof checkCurrent !== 'function' || typeof resolveTarget !== 'function'
      || persona?.role !== 'customer' || !['vuln', 'fixed'].includes(mode)) throw new TypeError('Bound refund tool dependencies required');
  if (fixedIntent !== null
      && (!exact(fixedIntent, ['orderId', 'reason'])
        || !Number.isSafeInteger(fixedIntent.orderId) || fixedIntent.orderId < 1
        || typeof fixedIntent.reason !== 'string' || !fixedIntent.reason.trim()
        || Buffer.byteLength(fixedIntent.reason, 'utf8') > 4096)) throw new TypeError('Refund intent is invalid');
  // The historical parameter name is retained for the runtime interface. It
  // carries private human intent in both modes, never model-confirmed intent.
  const refundIntent = fixedIntent && Object.freeze({ orderId: fixedIntent.orderId,
    reason: fixedIntent.reason });
  // This state is intentionally scoped to one model turn. A refund decision
  // must follow an owned order_status observation from the same conversation;
  // a manifest description alone is not an enforcement boundary.
  let observedOrderId = null;
  const getTarget = async () => { await checkCurrent(scope); const target = await resolveTarget(scope); await checkCurrent(scope); return target; };
  const refund = async (args = {}, invocation) => {
    if (!exact(args, ['order_id', 'reason']) || !Number.isSafeInteger(args.order_id)
      || args.order_id < 1 || typeof args.reason !== 'string' || !args.reason.trim()
      || Buffer.byteLength(args.reason, 'utf8') > 4096) return wrap({ ok: false, code: 'INVALID_TOOL_ARGUMENTS' }, true);
    if (!refundIntent) return wrap({ ok: false, code: 'REFUND_REQUEST_UNCLEAR' }, true);
    if (args.order_id !== refundIntent.orderId) return wrap({ ok: false, code: 'REQUESTED_ORDER_MISMATCH' }, true);
    if (observedOrderId !== args.order_id) return wrap({ ok: false, code: 'ORDER_STATUS_REQUIRED' }, true);
    if (args.reason !== refundIntent.reason) return wrap({ ok: false, code: 'REQUESTED_REASON_MISMATCH' }, true);
    try {
      const target = await getTarget();
      const result = await repository.create(target, { shopUserId: persona.id, orderId: orderId(args.order_id),
        requestId: binding.requestId, runId: binding.runId,
        reason: refundIntent.reason }, invocation);
      return wrap(result);
    } catch (error) {
      if (error?.executionBoundary || ['SHOP_AUTH_INVALID','PERSONA_EFFECT_OUTCOME_UNCERTAIN','REFUND_OPERATION_CONFLICT','STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'PRODUCT_TARGET_UNAVAILABLE'].includes(error?.code)) throw error;
      return wrap({ ok: false, code: error?.code || 'REFUND_REQUEST_FAILED', error: 'refund request unavailable' }, true);
    }
  };
  const status = async (args = {}) => {
    if (!exact(args, ['order_id']) || !Number.isSafeInteger(args.order_id) || args.order_id < 1) {
      return wrap({ ok: false, code: 'INVALID_TOOL_ARGUMENTS' }, true);
    }
    if (!refundIntent) return wrap({ ok: false, code: 'REFUND_REQUEST_UNCLEAR' }, true);
    if (args.order_id !== refundIntent.orderId) return wrap({ ok: false, code: 'REQUESTED_ORDER_MISMATCH' }, true);
    try {
      await getTarget();
      // The product target may have been born under an earlier launch. Commerce
      // resolves that target under the current execution grant itself.
      const result = await commerce.order({ scope, persona, orderId: orderId(args.order_id) });
      if (!result?.order) return wrap({ ok: false, code: 'ORDER_NOT_FOUND' }, true);
      const foundOrderId = Number(result.order.id);
      if (!Number.isSafeInteger(foundOrderId) || foundOrderId !== args.order_id) {
        return wrap({ ok: false, code: 'ORDER_STATUS_UNAVAILABLE' }, true);
      }
      if (mode === 'fixed' && (result.order.payment_status !== 'approved'
          || result.order.status === 'cancelled')) {
        return wrap({ ok: false, code: 'REFUND_NOT_ELIGIBLE' }, true);
      }
      observedOrderId = foundOrderId;
      return wrap({ ok: true, order: mode === 'fixed'
        ? { id: foundOrderId, status: result.order.status || null,
          payment_status: result.order.payment_status }
        : result.order });
    } catch (error) {
      if (error?.executionBoundary || ['SHOP_AUTH_INVALID','PERSONA_EFFECT_OUTCOME_UNCERTAIN','REFUND_OPERATION_CONFLICT','STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'PRODUCT_TARGET_UNAVAILABLE'].includes(error?.code)) throw error;
      return wrap({ ok: false, code: error?.code || 'ORDER_UNAVAILABLE' }, true);
    }
  };
  return Object.freeze({ 'support.refund_request': refund, 'support.order_status': status });
}
module.exports = { createSecureShopBoundRefundTools };
