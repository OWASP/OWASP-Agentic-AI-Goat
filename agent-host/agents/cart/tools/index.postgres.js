const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * cart tools — add, remove, view, apply_coupon.
 *
 * @intentional-vulnerability idor-cart
 * @teaches OWASP-Web:A01
 * @intentional-vulnerability sqli-blind-boolean
 * @teaches OWASP-Web:A03
 * intentional — cart.remove does no ownership check (IDOR)
 * intentional — cart.apply_coupon concatenates code into WHERE (SQLi blind)
 */



async function add({ product_id, qty = 1 }, ctx = {}) {
  const uid = ctx.userId || 0;
  const db = null;
  const info = await commerce.cart_add_1(uid, product_id, qty);
  return { ok: true, cart_item_id: info.lastInsertRowid, product_id, qty };
}

async function remove({ cart_item_id }, _ctx = {}) {
  const db = null;
  // intentional — teaches idor-cart: no user_id filter in DELETE
  const info = await commerce.cart_remove_2(cart_item_id);
  return { ok: info.changes > 0, deleted: info.changes };
}

async function view(_args, ctx = {}) {
  const uid = ctx.userId || 0;
  const db = null;
  const rows = await commerce.cart_view_3(uid);
  const subtotal = rows.reduce((s, r) => s + (Number(r.price) || 0) * r.quantity, 0);
  return { items: rows, subtotal: Number(subtotal.toFixed(2)) };
}

async function applyCoupon({ code }, _ctx = {}) {
  const db = null;
  // intentional — teaches sqli-blind-boolean: code concatenated into WHERE
  const sql = `SELECT id, code, discount_percent, active FROM coupons WHERE code = '${code}' AND active = 1 LIMIT 1`;
  let row = null;
  let error = null;
  try {
    row = await commerce.readTeachingQuery(sql, "get");
  } catch (e) {
    error = e.message;
  }
  if (row) {
    return { valid: true, code: row.code, discount_percent: row.discount_percent };
  }
  return { valid: false, code, discount_percent: 0, error };
}

module.exports = { add, remove, view, applyCoupon };
