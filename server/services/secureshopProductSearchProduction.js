'use strict';

async function prepareProductSearchDependencies({ runtime, lifecycle } = {}) {
  const service = runtime?.service;
  if (runtime?.admissions !== true || typeof runtime.assertReady !== 'function'
    || !['provision', 'searchProducts', 'readProductSearchReceipt', 'readProductSearchReference']
      .every(method => typeof service?.[method] === 'function')
    || !require('./secureshopAnalyticsLifecycle').isAnalyticsLifecycleFor(lifecycle, service)) {
    throw Object.assign(new Error('Product search runtime unavailable'), { code: 'PRODUCT_SEARCH_RUNTIME_UNAVAILABLE' });
  }
  await runtime.assertReady();
  return Object.freeze({ service });
}

module.exports = { prepareProductSearchDependencies };
