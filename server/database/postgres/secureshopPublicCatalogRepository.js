'use strict';

const { consistentRead } = require('./workshopPlatformSupport');

// Shared synthetic commerce data only. No owner snapshots, users, tool calls or
// provisioning are reachable from these reads. HTML is teaching product data;
// the guest storefront renders it inside the existing opaque frame.
const PRODUCT_FIELDS = Object.freeze(['id', 'name', 'description', 'description_html',
  'price', 'category', 'image_url', 'stock_quantity', 'status', 'avg_rating', 'review_count', 'images']);
const REVIEW_FIELDS = Object.freeze(['id', 'body', 'rating', 'status', 'created_at', 'author_name']);
const PRODUCT_COLUMNS = `p.id,left(p.name,512) AS name,left(p.description,16384) AS description,
  left(p.description_html,16384) AS description_html,p.price,left(p.category,100) AS category,
  left(p.image_url,2048) AS image_url,p.stock_quantity,p.status,
  COALESCE((SELECT round(avg(r.rating),2) FROM secureshop.reviews r
    WHERE r.product_id=p.id AND r.status='approved'),0) AS avg_rating,
  (SELECT count(*)::integer FROM secureshop.reviews r
    WHERE r.product_id=p.id AND r.status='approved') AS review_count,
  ARRAY(SELECT left(i.path,2048) FROM secureshop.product_images i
    WHERE i.product_id=p.id ORDER BY i.id LIMIT 12) AS images`;
const SORTS = Object.freeze({ default: 'p.id ASC', price_asc: 'p.price ASC,p.id ASC',
  price_desc: 'p.price DESC,p.id ASC', newest: 'p.created_at DESC,p.id DESC', deals: 'p.price ASC,p.id ASC' });
const FILTER = `p.status='active' AND ($1::text IS NULL OR p.category=$1)
  AND ($2::text IS NULL OR p.name ILIKE $2 ESCAPE '\\' OR p.description ILIKE $2 ESCAPE '\\')
  AND ($3::integer IS NULL OR COALESCE((SELECT avg(r.rating) FROM secureshop.reviews r
    WHERE r.product_id=p.id AND r.status='approved'),0) >= $3)
  AND ($4::numeric IS NULL OR p.price <= $4)`;
const pick = (row, fields) => Object.fromEntries(fields.map(field => [field, row[field] ?? null]));
function product(row) {
  const result = pick(row, PRODUCT_FIELDS);
  for (const field of ['price', 'avg_rating', 'review_count']) result[field] = Number(result[field] || 0);
  result.images = Array.isArray(result.images) ? result.images : [];
  if (!result.images.length && result.image_url) result.images = [result.image_url];
  return result;
}
const searchPattern = search => search ? `%${search.replace(/[\\%_]/g, '\\$&')}%` : null;

function createSecureShopPublicCatalogRepository(pool) {
  if (!pool?.query || !pool?.connect) throw new TypeError('Public commerce PostgreSQL pool required');
  const read = work => consistentRead(pool, work);
  const active = async (client, id) => (await client.query(
    "SELECT id FROM secureshop.products WHERE id=$1 AND status='active'", [id])).rows.length > 0;
  return Object.freeze({
    browse({ category = null, search = null, minRating = null, maxPrice = null,
      sort = 'default', limit = 24, offset = 0 } = {}) {
      const order = SORTS[sort];
      if (!order) throw new TypeError('Unknown public catalog sort');
      return read(async client => {
        const values = [category, searchPattern(search), minRating, maxPrice];
        const total = Number((await client.query(`SELECT count(*)::integer AS total
          FROM secureshop.products p WHERE ${FILTER}`, values)).rows[0]?.total || 0);
        const products = (await client.query(`SELECT ${PRODUCT_COLUMNS}
          FROM secureshop.products p WHERE ${FILTER} ORDER BY ${order} LIMIT $5 OFFSET $6`,
        [...values, limit, offset])).rows.map(product);
        return { products, count: products.length, total };
      });
    },
    product(id) {
      return read(async client => {
        const row = (await client.query(`SELECT ${PRODUCT_COLUMNS} FROM secureshop.products p
          WHERE p.id=$1 AND p.status='active'`, [id])).rows[0];
        return row ? { product: product(row) } : null;
      });
    },
    reviews(id, { limit = 10, offset = 0 } = {}) {
      return read(async client => {
        if (!await active(client, id)) return null;
        const total = Number((await client.query(`SELECT count(*)::integer AS total
          FROM secureshop.reviews WHERE product_id=$1 AND status='approved'`, [id])).rows[0]?.total || 0);
        const reviews = (await client.query(`SELECT r.id,left(r.body,16384) AS body,r.rating,
          r.status,r.created_at,'Customer'::text AS author_name FROM secureshop.reviews r
          WHERE r.product_id=$1 AND r.status='approved'
          ORDER BY r.created_at DESC,r.id DESC LIMIT $2 OFFSET $3`, [id, limit, offset])).rows
          .map(row => pick(row, REVIEW_FIELDS));
        return { reviews, total };
      });
    },
    related(id, { limit = 4 } = {}) {
      return read(async client => {
        if (!await active(client, id)) return null;
        const results = (await client.query(`SELECT ${PRODUCT_COLUMNS} FROM secureshop.products p
          WHERE p.status='active' AND p.id<>$1
            AND p.category=(SELECT category FROM secureshop.products WHERE id=$1 AND status='active')
          ORDER BY p.id LIMIT $2`, [id, limit])).rows.map(product);
        return { results, recommendation: '' };
      });
    },
    categories() {
      return read(async client => ({ categories: (await client.query(`SELECT c.id,left(c.name,100) AS name,
        left(c.description,2048) AS description FROM secureshop.categories c
        WHERE EXISTS(SELECT 1 FROM secureshop.products p WHERE p.category=c.name AND p.status='active')
        ORDER BY c.name,c.id LIMIT 100`)).rows.map(row => pick(row, ['id', 'name', 'description'])) }));
    },
  });
}

module.exports = { createSecureShopPublicCatalogRepository };
