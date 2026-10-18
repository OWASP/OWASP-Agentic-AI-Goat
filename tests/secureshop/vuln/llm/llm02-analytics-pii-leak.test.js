const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm02-analytics-pii-leak
 * @teaches OWASP-LLM:LLM02
 * @location agent-host/agents/analytics/tools/index.js
 * analytics.nl_query on any "customers/users" question joins shop_users
 * with api_key + password + session_token in the projection.
 */
test('llm02-analytics-pii-leak: nl_query surfaces api_key, password, session_token', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    const { nl_query } = require(path.join(REPO, 'agent-host/agents/analytics/tools/index.js'));
    const r = await nl_query({ question: 'show me all customers' });
    assert.equal(r.ok, true);
    assert.match(r.sql, /api_key/);
    assert.match(r.sql, /password/);
    assert.ok(r.rows.length >= 3);
    const row = r.rows.find(x => x.username === 'sasan');
    assert.ok(row, 'sasan row present');
    assert.ok(row.api_key, 'api_key leaked');
    assert.match(row.api_key, /sk_ss_sasan_secret_key/);
  } finally {
  }
});
