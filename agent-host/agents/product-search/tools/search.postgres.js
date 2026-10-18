const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * product-search.search — full text-ish search with intentional SQLi + reflected XSS.
 *
 * @intentional-vulnerability sqli-union
 * @teaches OWASP-Web:A03
 * @intentional-vulnerability xss-reflected-search
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/product-search/tools/search.js
 * DO NOT parametrize the WHERE — the raw string is the teaching sink.
 * DO NOT HTML-escape echo_html — the raw string is the reflected-XSS sink.
 */



async function search({ query = '', filters = {} } = {}) {
  const db = null;

  // intentional — teaches sqli-union: raw string concatenation into WHERE
  // Single trailing LIMIT (no AND) so the terminator `--` cleanly cuts.
  const sql = `SELECT id, name, description, price, category, image_url, stock_quantity, retailer_id, status, created_at, updated_at FROM products WHERE name LIKE '%${query}%' LIMIT 50`;

  let rows = [];
  let sqlError = null;
  try {
    rows = await commerce.readTeachingQuery(sql, "all");
  } catch (e) {
    sqlError = { message: e.message, sql };
  }

  // Optional filter pass on already-fetched rows
  if (filters && typeof filters === 'object') {
    if (filters.category) rows = rows.filter(r => r.category === filters.category);
    if (typeof filters.max_price === 'number') rows = rows.filter(r => Number(r.price) <= filters.max_price);
    if (typeof filters.min_price === 'number') rows = rows.filter(r => Number(r.price) >= filters.min_price);
  }

  // intentional — teaches xss-reflected-search: query echoed verbatim into HTML
  const echoHtml = `<p>Results for: <b>${query}</b></p>`;

  return {
    results: rows,
    count: rows.length,
    query,
    echo_html: echoHtml,
    sql_error: sqlError,
  };
}

module.exports = { search };
