'use strict';

async function prepareOrderStatusDependencies({ runtime, lifecycle } = {}) {
  const service = runtime?.service;
  if (runtime?.admissions !== true || typeof runtime.assertReady !== 'function'
    || !['provision', 'lookupOrderStatus', 'readOrderStatusReceipt', 'readOrderStatusReference']
      .every(method => typeof service?.[method] === 'function')
    || !require('./secureshopAnalyticsLifecycle').isAnalyticsLifecycleFor(lifecycle, service)) {
    throw Object.assign(new Error('Order status runtime unavailable'), { code: 'ORDER_STATUS_RUNTIME_UNAVAILABLE' });
  }
  await runtime.assertReady();
  return Object.freeze({ service });
}

module.exports = { prepareOrderStatusDependencies };
