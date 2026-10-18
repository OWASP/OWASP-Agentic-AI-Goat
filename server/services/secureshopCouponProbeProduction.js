'use strict';

async function prepareCouponProbeDependencies({ runtime, lifecycle, commercePool } = {}) {
  const service = runtime?.service;
  if (runtime?.admissions !== true || typeof runtime.assertReady !== 'function'
    || typeof commercePool?.query !== 'function'
    || !['lookupCouponProbe', 'readCouponProbeReceipt', 'readCouponProbeReference']
      .every(method => typeof service?.[method] === 'function')
    || !require('./secureshopAnalyticsLifecycle').isAnalyticsLifecycleFor(lifecycle, service)) {
    throw Object.assign(new Error('Coupon probe runtime unavailable'), { code: 'COUPON_RUNTIME_UNAVAILABLE' });
  }
  await runtime.assertReady();
  return Object.freeze({ service, readCoupons: async () => {
    const { rows } = await commercePool.query(
      'SELECT id,code,discount_percent,active FROM secureshop.coupons ORDER BY id LIMIT 65');
    return rows.map(({ id, code, discount_percent, active }) => ({ id, code, discount_percent, active }));
  } });
}

module.exports = { prepareCouponProbeDependencies };
