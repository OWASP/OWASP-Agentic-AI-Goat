'use strict';

const PRODUCT_COLUMNS = `
  id, name, description, description_html, price, category, image_url,
  stock_quantity, retailer_id, status, template_source, created_at, updated_at`;

const REVIEW_COLUMNS = `
  id, product_id, author_id, body, rating, status, moderator_kind,
  moderator_notes, created_at, moderated_at`;

const PRODUCT_SORTS = Object.freeze({
  updated_desc: 'updated_at DESC',
  updated_asc: 'updated_at ASC',
  price_desc: 'price DESC',
  price_asc: 'price ASC',
  stock_desc: 'stock_quantity DESC',
  stock_asc: 'stock_quantity ASC',
  name_asc: 'name ASC',
  name_desc: 'name DESC',
});

function asNumber(value) {
  return Number(value || 0);
}

function productDto(row) {
  return { ...row, price: row.price === null ? null : Number(row.price) };
}

function createSecureShopMerchantRepository({ commercePool, agentsPool }) {
  if (!commercePool || !agentsPool) throw new Error('merchant repository requires commerce and agents pools');

  return {
    async listProducts({ retailerId, status, category, search, sort, limit, offset }) {
      const orderBy = PRODUCT_SORTS[sort] || PRODUCT_SORTS.updated_desc;
      const params = [retailerId, status, category, search, limit, offset];
      const where = `
        ($1::integer IS NULL OR retailer_id = $1)
        AND ($2::text IS NULL OR status = $2)
        AND ($3::text IS NULL OR category = $3)
        AND ($4::text IS NULL OR name ILIKE '%' || $4 || '%')`;
      const [items, count, categories] = await Promise.all([
        commercePool.query(`SELECT ${PRODUCT_COLUMNS} FROM secureshop.products WHERE ${where} ORDER BY ${orderBy} LIMIT $5 OFFSET $6`, params),
        commercePool.query(`SELECT COUNT(*)::integer AS n FROM secureshop.products WHERE ${where}`, params.slice(0, 4)),
        commercePool.query(`SELECT DISTINCT category FROM secureshop.products WHERE category IS NOT NULL AND ($1::integer IS NULL OR retailer_id = $1) ORDER BY category`, [retailerId]),
      ]);
      return {
        rows: items.rows.map(productDto),
        total: asNumber(count.rows[0]?.n),
        categories: categories.rows.map((row) => row.category),
      };
    },

    async setProductCategory(productId, category) {
      await commercePool.query('UPDATE secureshop.products SET category=$1, updated_at=now() WHERE id=$2', [String(category), productId]);
    },

    async archiveProduct(productId) {
      const result = await commercePool.query("UPDATE secureshop.products SET status='archived', updated_at=now() WHERE id=$1", [productId]);
      return result.rowCount;
    },

    async listReviews({ status, productId, minRating, maxRating, limit, offset }) {
      const params = [status, productId, minRating, maxRating, limit, offset];
      const where = `
        ($1::text IS NULL OR status = $1)
        AND ($2::integer IS NULL OR product_id = $2)
        AND ($3::integer IS NULL OR rating >= $3)
        AND ($4::integer IS NULL OR rating <= $4)`;
      const [items, totals, count] = await Promise.all([
        commercePool.query(`SELECT ${REVIEW_COLUMNS} FROM secureshop.reviews WHERE ${where} ORDER BY created_at DESC LIMIT $5 OFFSET $6`, params),
        commercePool.query('SELECT status, COUNT(*)::integer AS n FROM secureshop.reviews GROUP BY status'),
        commercePool.query(`SELECT COUNT(*)::integer AS n FROM secureshop.reviews WHERE ${where}`, params.slice(0, 4)),
      ]);
      return {
        rows: items.rows,
        total: asNumber(count.rows[0]?.n),
        counts: Object.fromEntries(totals.rows.map((row) => [row.status, asNumber(row.n)])),
      };
    },

    async overview({ retailerId, cutoff, previousCutoff }) {
      const currentScope = '($2::integer IS NULL OR p.retailer_id = $2)';
      const current = await commercePool.query(`
        SELECT COALESCE(SUM(oi.quantity * oi.price), 0) AS revenue,
               COUNT(DISTINCT o.id)::integer AS orders,
               COUNT(DISTINCT o.customer_id)::integer AS buyers
        FROM secureshop.orders o
        LEFT JOIN secureshop.order_items oi ON oi.order_id = o.id
        LEFT JOIN secureshop.products p ON p.id = oi.product_id
        WHERE (o.order_date IS NULL OR o.order_date >= $1) AND ${currentScope}
      `, [cutoff, retailerId]);
      const previous = await commercePool.query(`
        SELECT COALESCE(SUM(oi.quantity * oi.price), 0) AS revenue,
               COUNT(DISTINCT o.id)::integer AS orders
        FROM secureshop.orders o
        LEFT JOIN secureshop.order_items oi ON oi.order_id = o.id
        LEFT JOIN secureshop.products p ON p.id = oi.product_id
        WHERE o.order_date IS NOT NULL AND o.order_date >= $2 AND o.order_date < $1
          AND ($3::integer IS NULL OR p.retailer_id = $3)
      `, [cutoff, previousCutoff, retailerId]);
      const top = await commercePool.query(`
        SELECT p.id, p.name, COALESCE(SUM(oi.quantity * oi.price), 0) AS revenue
        FROM secureshop.products p
        LEFT JOIN secureshop.order_items oi ON oi.product_id = p.id
        LEFT JOIN secureshop.orders o ON o.id = oi.order_id
        WHERE (o.order_date IS NULL OR o.order_date >= $1)
          AND ($2::integer IS NULL OR p.retailer_id = $2)
        GROUP BY p.id ORDER BY revenue DESC LIMIT 1
      `, [cutoff, retailerId]);
      const days = await commercePool.query(`
        SELECT to_char(o.order_date AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
               COALESCE(SUM(oi.quantity * oi.price), 0) AS revenue,
               COUNT(DISTINCT o.id)::integer AS orders
        FROM secureshop.orders o
        LEFT JOIN secureshop.order_items oi ON oi.order_id = o.id
        LEFT JOIN secureshop.products p ON p.id = oi.product_id
        WHERE o.order_date IS NOT NULL AND o.order_date >= $1
          AND ($2::integer IS NULL OR p.retailer_id = $2)
        GROUP BY day ORDER BY day
      `, [cutoff, retailerId]);
      return { current: current.rows[0], previous: previous.rows[0], top: top.rows[0], days: days.rows };
    },

    async salesChart({ retailerId, cutoff }) {
      const result = await commercePool.query(`
        SELECT to_char(o.order_date AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
               COALESCE(SUM(oi.quantity * oi.price), 0) AS revenue,
               COUNT(DISTINCT o.id)::integer AS orders
        FROM secureshop.orders o
        LEFT JOIN secureshop.order_items oi ON oi.order_id = o.id
        LEFT JOIN secureshop.products p ON p.id = oi.product_id
        WHERE o.order_date IS NOT NULL AND o.order_date >= $1
          AND ($2::integer IS NULL OR p.retailer_id = $2)
        GROUP BY day ORDER BY day
      `, [cutoff, retailerId]);
      return result.rows;
    },

    async latestMerchantTrace({ userId, role, limit }) {
      const result = await agentsPool.query(`
        SELECT t.id, t.session_id, t.step, t.actor, t.kind, t.agent_ns, t.tool_name,
               t.params_json, t.result_json, t.latency_ms, t.provider, t.ts
        FROM secureshop_agents.agent_trace t
        INNER JOIN secureshop_agents.agent_sessions s ON s.id = t.session_id
        WHERE s.user_id = $1 AND s.role = $2
          AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'
        ORDER BY t.ts DESC, t.id DESC LIMIT $3
      `, [userId, role, limit]);
      return result.rows;
    },

    async merchantTrace(sessionId) {
      const result = await agentsPool.query(`
        SELECT t.id, t.session_id, t.step, t.actor, t.kind, t.agent_ns, t.tool_name,
               t.params_json, t.result_json, t.latency_ms, t.tokens_in, t.tokens_out, t.provider, t.ts
        FROM secureshop_agents.agent_trace t
        INNER JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
        WHERE t.session_id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'
        ORDER BY t.ts ASC, t.id ASC
      `, [sessionId]);
      return result.rows;
    },
  };
}

module.exports = { createSecureShopMerchantRepository, PRODUCT_SORTS };
