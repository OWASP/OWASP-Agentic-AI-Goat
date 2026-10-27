'use strict';

function recoveredOrderVisible(surface, expected) {
  if (!surface || !expected || !Number.isSafeInteger(expected.orderId)
    || expected.orderId < 1 || !Number.isSafeInteger(expected.totalCents)
    || expected.totalCents < 0) return false;
  const sentence = `Your order #${expected.orderId} is confirmed for $${
    (expected.totalCents / 100).toFixed(2)}. This receipt was confirmed from saved orders.`;
  return surface.heading === 'Order placed.'
    && surface.confirmation === sentence
    && surface.confirmVisible === false;
}

module.exports = { recoveredOrderVisible };
