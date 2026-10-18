const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * inventory tools — stock_levels, reorder_suggestion, set_stock.
 *
 * @intentional-vulnerability broken-access-inventory
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/inventory/tools/index.js
 * intentional — set_stock does NOT check that ctx.userId owns the product
 * (products.retailer_id). Any merchant (or any authenticated caller via the
 * REST endpoint) can rewrite stock on any product.
 */



async function stock_levels(_args = {}, _ctx = {}) {
  const db = null;
  const rows = await commerce.inventory_stock_levels_1();
  const lowStock = rows.filter(r => (Number(r.stock_quantity) || 0) < 5);
  return { items: rows, low_stock: lowStock, count: rows.length };
}

async function reorder_suggestion({ product_id } = {}, _ctx = {}) {
  const db = null;
  const row = await commerce.inventory_reorder_suggestion_2(product_id);
  if (!row) return { ok: false, error: 'unknown product_id' };
  const target = Math.max(20, Math.ceil(Number(row.units_sold || 0) * 1.4));
  const reorder = Math.max(0, target - Number(row.stock_quantity || 0));
  return { ok: true, product_id, current: row.stock_quantity, units_sold: row.units_sold, suggested_reorder: reorder };
}

async function set_stock({ product_id, qty } = {}, _ctx = {}) {
  if (product_id == null || qty == null) return { ok: false, error: 'product_id and qty required' };
  const db = null;
  // intentional — teaches broken-access-inventory: no retailer_id check.
  const info = await commerce.inventory_set_stock_3(Number(qty), product_id);
  return { ok: info.changes > 0, product_id, new_qty: Number(qty) };
}

module.exports = { stock_levels, reorder_suggestion, set_stock };
