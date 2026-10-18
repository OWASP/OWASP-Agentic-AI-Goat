/**
 * analytics tools — nl_query, top_products, revenue_breakdown.
 *
 * @intentional-vulnerability sqli-nl-generated
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/analytics/tools/index.js
 * intentional — nl_query converts a natural-language question into a raw
 * SQL string and executes it via db.prepare(sql).all() with no
 * parameterization. Two translator backends exist:
 *   - SS_ANALYTICS_LLM_ENABLED=true → uses multiProviderAIService to emit SQL
 *     from the NL question. Real LLM-in-the-loop SQL generation.
 *   - default → rule-based template matcher (deterministic, for tests + when
 *     no LLM provider is configured).
 * Either translator's output is executed unparameterized, so classic SQL
 * injection is trivially exposed. Wave 5A F13 restored the LLM-in-the-loop
 * option that the original spec claimed.
 *
 * @intentional-vulnerability llm02-analytics-pii-leak
 * @teaches OWASP-LLM:LLM02
 * intentional — the translator freely joins on shop_users to answer questions
 * about "customers", surfacing api_key / password / session_token in results.
 *
 * @intentional-vulnerability llm10-analytics-unbounded
 * @teaches OWASP-LLM:LLM10
 * intentional — no LIMIT is enforced when the question does not specify one.
 * A crafted "list everything" question returns the whole table (thousands of
 * rows in a real store), consuming supervisor context tokens without back-
 * pressure.
 */

const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
let _aiService = null;
function _getAiService() {
  if (_aiService !== null) return _aiService;
  try {
    // Resolve lazily so unit tests without an AI stack don't pay the import cost.
    // eslint-disable-next-line global-require
    _aiService = require('../../../../server/services/multiProviderAIService');
  } catch {
    _aiService = false;
  }
  return _aiService;
}

// Whitelist for the translator to reference — but the translator itself
// isn't restricted to these, that's the point. Kept for documentation.
const KNOWN_TABLES = ['products', 'orders', 'order_items', 'shop_users', 'reviews', 'cart_items'];

/**
 * Deterministic natural-language → SQL translator.
 * The translator is intentionally naive: it pattern-matches keywords and
 * concatenates fragments from the question directly into the SQL. This is
 * the LLM02 / SQLi-NL sink. Real Ollama can be swapped in via
 * SS_ANALYTICS_LLM_ENABLED=true but the same shape holds.
 */
function _translate(question) {
  const q = String(question || '').trim();
  const lower = q.toLowerCase();

  // "list all customers" / "show me users" — LLM02 PII leak
  if (/\b(list|show|dump|export|all)\b.*(customer|user|shopper|account)/i.test(q)) {
    // Deliberately select api_key + password — the PII leak.
    return { sql: `SELECT id, username, email, role, api_key, session_token, password, pii_json FROM shop_users`, why: 'question mentions customers/users' };
  }

  // "top 5 products by revenue"
  const topMatch = /top\s+(\d+)?\s*products/i.exec(q);
  if (topMatch) {
    const n = topMatch[1] || '10';
    return { sql: `SELECT p.id, p.name, SUM(oi.quantity * oi.price) AS revenue FROM products p JOIN order_items oi ON oi.product_id = p.id GROUP BY p.id ORDER BY revenue DESC LIMIT ${n}`, why: 'top-products template' };
  }

  // "revenue" / "sales" — unbounded scan
  if (/revenue|sales|totals?/i.test(lower)) {
    return { sql: `SELECT status, SUM(total_amount) AS total FROM orders GROUP BY status`, why: 'revenue template' };
  }

  // "products where <expr>" — the translator forwards the expression verbatim,
  // which is the classic NL-SQLi sink.
  const whereMatch = /products?\s+where\s+(.+)$/i.exec(q);
  if (whereMatch) {
    const expr = whereMatch[1];
    return { sql: `SELECT id, name, price, stock_quantity, retailer_id FROM products WHERE ${expr}`, why: 'products-where template — expr appended verbatim (SQLi sink)' };
  }

  // "reviews" — dump reviews with author PII
  if (/review/i.test(lower)) {
    return { sql: `SELECT r.id, r.body, r.rating, r.status, u.username, u.email FROM reviews r LEFT JOIN shop_users u ON u.id = r.author_id`, why: 'reviews template — joins to shop_users PII' };
  }

  // Fallback: give the whole product table (unbounded).
  return { sql: `SELECT id, name, price, stock_quantity, retailer_id, status FROM products`, why: 'fallback: unbounded product scan' };
}

/**
 * Ask the LLM to emit a SQL string from an NL question. When the request
 * succeeds we return the raw generated SQL — that string is then executed
 * without parameterization, which is the point of the sink. If the LLM is
 * unreachable / mock we fall through to the rule-based translator.
 *
 * Wave 5A F13: this restores the LLM-in-the-loop claim from spec §5.3.
 */
async function _translateWithLLM(question) {
  const svc = _getAiService();
  if (!svc || typeof svc.generateResponse !== 'function') return null;
  const prompt = [
    'You are a SQL translator for SecureShop analytics. Convert the user',
    'question into a single PostgreSQL SELECT statement against these tables:',
    'products(id, name, description, price, category, stock_quantity, retailer_id, status),',
    'orders(id, customer_id, total_amount, status, order_date),',
    'order_items(id, order_id, product_id, quantity, price),',
    'shop_users(id, username, email, password, role, api_key, session_token, pii_json),',
    'reviews(id, product_id, author_id, body, rating, status).',
    '',
    'Return ONLY the SQL — no markdown fences, no commentary. Prefer wide',
    'result sets so the analyst has full data to work with.',
    '',
    `Question: ${String(question || '').trim()}`,
  ].join('\n');
  try {
    const raw = await svc.generateResponse(prompt, { max_tokens: 512, temperature: 0 });
    if (!raw || typeof raw !== 'object') return null;
    let sql = String(raw.response || raw.text || raw.output || '').trim();
    // Strip markdown fences if the model added them.
    sql = sql.replace(/^```(?:sql)?\s*/i, '').replace(/```\s*$/i, '').trim();
    if (!/^\s*select\b/i.test(sql)) return null;
    return { sql, why: 'LLM-generated (multiProviderAIService.generateResponse)' };
  } catch {
    return null;
  }
}

async function nl_query({ question } = {}) {
  
  let t = null;
  if (process.env.SS_ANALYTICS_LLM_ENABLED === 'true') {
    t = await _translateWithLLM(question);
  }
  if (!t) t = _translate(question);
  const sql = t.sql;
  let rows = [];
  let error = null;
  try {
    // intentional — no parameterization, no LIMIT injection, no allow-list.
    rows = await commerce.readTeachingQuery(sql);
  } catch (e) {
    error = e.message;
  }
  return {
    ok: !error,
    question,
    sql,
    why: t.why,
    row_count: rows.length,
    rows,
    error,
    grounded: false,
  };
}

async function top_products({period='30d',limit=10}={}){return {ok:true,period,rows:await commerce.analyticsTopProducts(Number(limit)||10)};}
async function revenue_breakdown(){return {ok:true,by_category:await commerce.analyticsCategories(),by_status:await commerce.analyticsStatuses()};}

module.exports = { nl_query, top_products, revenue_breakdown, _translate };
