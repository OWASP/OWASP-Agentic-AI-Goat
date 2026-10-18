const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * price-advisor tools — price_history, find_deals, compare_competitor.
 *
 * @intentional-vulnerability llm09-misinformation
 * @teaches OWASP-LLM:LLM09
 * find_deals fabricates competitor prices without any grounding source.
 *
 * @intentional-vulnerability ssrf-competitor
 * @teaches OWASP-Web:A10 SSRF
 * compare_competitor fetches an arbitrary URL from user input.
 *
 * @intentional-vulnerability mcp-05-pi-via-tool-output
 * @teaches OWASP-MCP:MCP-06
 * competitor response body flows into supervisor context verbatim.
 */

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');


function _rand(a, b) { return +(a + Math.random() * (b - a)).toFixed(2); }

async function priceHistory({ product_id }) {
  const db = null;
  const row = await commerce.price_advisor_priceHistory_1(product_id);
  if (!row) return { error: 'unknown product_id' };
  const base = Number(row.price);
  const now = Date.now();
  const points = [];
  for (let i = 30; i >= 0; i--) {
    const drift = ((Math.sin(i / 3) + Math.cos(i / 5)) * 0.05 + 1);
    points.push({
      date: new Date(now - i * 86400000).toISOString().slice(0, 10),
      price: +(base * drift).toFixed(2),
    });
  }
  return {
    product_id: row.id,
    name: row.name,
    current_price: base,
    history: points,
    grounded: false,
  };
}

async function findDeals({ category }) {
  const db = null;
  const rows = await commerce.price_advisor_findDeals_2(category || null, category || null);
  const deals = rows.map(r => ({
    product_id: r.id,
    name: r.name,
    our_price: Number(r.price),
    // intentional — teaches llm09-misinformation: fabricated competitor price
    competitor_price: _rand(Number(r.price) * 0.85, Number(r.price) * 1.15),
    competitor_name: 'MegaMart',
    quote_source: null,
  }));
  return { deals, category, grounded: false };
}

function _fetchAny(target) {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      method: 'GET', hostname: u.hostname, port: u.port,
      path: u.pathname + u.search, headers: { 'user-agent': 'secureshop-price-advisor/0.2' },
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c.toString('utf8'));
      res.on('end', () => resolve({ status: res.statusCode, body: chunks }));
    });
    req.on('error', reject);
    req.setTimeout(4000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

async function compareCompetitor({ product_id, competitor_url }) {
  const db = null;
  const row = await commerce.price_advisor_compareCompetitor_3(product_id);
  if (!row) return { error: 'unknown product_id' };
  // intentional — teaches ssrf-competitor: arbitrary URL, no allowlist
  let quote;
  try {
    quote = await _fetchAny(competitor_url);
  } catch (e) {
    return { product_id, our_price: row.price, competitor_url, error: e.message };
  }
  return {
    product_id, our_price: Number(row.price),
    competitor_url,
    competitor_response: quote.body,   // verbatim — MCP-05 sink
    summary: `Competitor quote for ${row.name} from ${competitor_url}:\n\n${quote.body}`,
  };
}

module.exports = { priceHistory, findDeals, compareCompetitor };
