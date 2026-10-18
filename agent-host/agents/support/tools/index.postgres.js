const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * support tools — order_status, open_ticket, refund_request.
 *
 * @intentional-vulnerability idor-order-status
 * @teaches OWASP-Web:A01
 * @intentional-vulnerability sqli-error-based
 * @teaches OWASP-Web:A03
 * @intentional-vulnerability xss-stored-ticket
 * @teaches OWASP-Web:A03
 * intentional — order_status has no user_id filter and concatenates raw order_id
 *              open_ticket stores body verbatim; merchant dashboard renders it via innerHTML
 */



async function orderStatus({ order_id }, _ctx = {}) {
  const db = null;
  // intentional — teaches sqli-error-based + idor-order-status:
  // raw concat into WHERE + no owner filter. SQLite surfaces CAST errors verbatim.
  const sql = `SELECT id, customer_id, total_amount, status, payment_method, payment_status, shipping_address, order_date FROM orders WHERE id = ${order_id} LIMIT 1`;
  try {
    const row = await commerce.readTeachingQuery(sql, "get");
    if (!row) return { order: null, sql };
    return { order: row, sql };
  } catch (e) {
    // Error text intentionally surfaces so error-based SQLi leaks column values
    return { error: e.message, sql };
  }
}

async function openTicket({ subject, body }, ctx = {}) {
  const db = null;
  const uid = ctx.userId || 0;
  // intentional — teaches xss-stored-ticket: body persisted verbatim
  const info = await commerce.support_openTicket_2(uid, subject || '', body || '');
  return { ok: true, ticket_id: info.lastInsertRowid, subject, body };
}

async function refundRequest({ order_id, reason }, ctx = {}) {
  const db = null;
  const uid = ctx.userId || 0;
  const subj = `refund request for order ${order_id}`;
  const body = `Reason: ${reason || 'not provided'}`;
  const info = await commerce.support_refundRequest_3(uid, subj, body, 'refund_pending');
  return { ok: true, ticket_id: info.lastInsertRowid, order_id, reason: reason || null };
}

module.exports = { orderStatus, openTicket, refundRequest };
