'use strict';
const DAY = 86400000;
function reportingWindow(days = 30, now = Date.now()) {
  if (!Number.isInteger(days) || days < 7 || days > 365 || !Number.isFinite(now)) {
    throw Object.assign(new Error('Invalid merchant reporting window'), { code: 'INVALID_ARGUMENT' });
  }
  const today = Math.floor(now / DAY) * DAY;
  return Object.freeze({ days, cutoff: new Date(today - (days - 1) * DAY).toISOString(),
    previousCutoff: new Date(today - (2 * days - 1) * DAY).toISOString(),
    until: new Date(today + DAY).toISOString() });
}
function projectMerchantMetrics(data, window, retailerId) {
  const amount = value => {
    const n = Number(value);
    if (!Number.isFinite(n) || n < 0) throw new Error('Invalid stored merchant metric');
    return n;
  };
  const count = value => {
    const n = amount(value);
    if (!Number.isSafeInteger(n)) throw new Error('Invalid stored merchant count');
    return n;
  };
  const daily = new Map(data.days.map(row => [row.day, row]));
  const series = Array.from({ length: window.days }, (_, i) => {
    const day = new Date(Date.parse(window.cutoff) + i * DAY).toISOString().slice(0, 10);
    const row = daily.get(day);
    return { day, revenue: row ? amount(row.revenue) : 0, orders: row ? count(row.orders) : 0 };
  });
  const revenue = amount(data.current.revenue), orders = count(data.current.orders);
  const previousRevenue = amount(data.previous.revenue), previousOrders = count(data.previous.orders);
  const aov = orders ? revenue / orders : 0, previousAov = previousOrders ? previousRevenue / previousOrders : 0;
  const delta = (current, previous) => previous ? +((current - previous) / previous * 100).toFixed(1) : null;
  const provenance = { basis: 'noncancelled_nonrefunded_order_lines', timezone: 'UTC',
    windowStart: window.cutoff, windowEndExclusive: window.until, modelUsed: false };
  return { kpis: { ok: true, retailer_id: retailerId,
    revenue: { value: revenue, delta_pct: delta(revenue, previousRevenue), spark: series.map(row => row.revenue) },
    orders: { value: orders, delta_pct: delta(orders, previousOrders), spark: series.map(row => row.orders) },
    aov: { value: aov, delta_pct: delta(aov, previousAov) },
    top_product: data.top ? { id: count(data.top.id), name: data.top.name, revenue: amount(data.top.revenue) } : null,
    provenance }, salesChart: { ok: true, retailer_id: retailerId, days: window.days, series, provenance } };
}
module.exports = { reportingWindow, projectMerchantMetrics };
