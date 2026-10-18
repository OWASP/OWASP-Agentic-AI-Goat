const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm10-analytics-unbounded
 * @teaches OWASP-LLM:LLM10
 * @location agent-host/agents/analytics/tools/index.js
 * Fallback nl_query returns an unbounded product scan with NO LIMIT clause.
 * With a wider product table this consumes supervisor context without
 * back-pressure.
 */
test('llm10-analytics-unbounded: fallback question emits SQL with no LIMIT', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    // Add extra rows so unboundedness is measurable
    await s.query(
      `INSERT INTO secureshop.products (name, price, category, status, stock_quantity)
       SELECT 'FloodProduct' || n, $1, $2, 'active', 1 FROM generate_series(0, 49) AS n`,
      [1.00, 'Home'],
    );

    const { nl_query } = require(path.join(REPO, 'agent-host/agents/analytics/tools/index.js'));
    const r = await nl_query({ question: 'anything at all' });
    assert.equal(r.ok, true);
    assert.doesNotMatch(r.sql, /\bLIMIT\b/i, 'SQL must not carry a LIMIT');
    assert.ok(r.rows.length >= 50, `unbounded scan returned ${r.rows.length} rows`);
  } finally {
  }
});
