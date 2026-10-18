/**
 * @intentional-vulnerability sqli-time-based
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/audit/tools/index.js
 *
 * audit.search_by_user builds `WHERE ... LIKE '%${u}%'` via string
 * concatenation. The PostgreSQL payload closes the LIKE string and invokes
 * pg_sleep through a scalar subquery. A clean negative lookup establishes the
 * same-run baseline; the injected lookup must retain both the absolute delay
 * and a material delay above that baseline.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');
const elapsedMs = start => Number(process.hrtime.bigint() - start) / 1e6;

test('sqli-time-based: search_by_user executes injected PostgreSQL pg_sleep', async () => {
  const shop = await seedShop();
  let agents;
  try {
    agents = await seedAgents();
    purgeToolCaches();
    const agentsStore = require(path.join(REPO, 'server/database/postgres/secureshopAgentsDb.js'))
      .getSecureShopAgentsDb();
    await agentsStore.appendAudit({
      event_id: 'sqli-time-baseline',
      actor: 'alice',
      action: 'login',
      target: 'api',
      params_json: '{}',
    });

    const { search_by_user } = require(path.join(REPO, 'agent-host/agents/audit/tools/index.js'));
    await search_by_user({ username: 'alice' }); // warm the same real query path

    const baselineStart = process.hrtime.bigint();
    const baseline = await search_by_user({ username: 'definitely-no-such-user' });
    const baselineDurationMs = elapsedMs(baselineStart);
    assert.equal(baseline.ok, true, `negative baseline failed: ${baseline.error}`);
    assert.equal(baseline.count, 0, 'negative baseline must not select an audit event');

    const injected = "x' OR (SELECT 1 FROM pg_sleep(0.08))=1 --";
    const injectedStart = process.hrtime.bigint();
    const result = await search_by_user({ username: injected });
    const injectedDurationMs = elapsedMs(injectedStart);

    assert.equal(result.ok, true, `injected query failed: ${result.error}`);
    assert.ok(result.sql.includes(injected), 'SQL string contains the pg_sleep fragment verbatim');
    assert.ok(result.events.some(event => event.actor === 'alice'), 'injected predicate selected an otherwise unrelated row');
    assert.ok(injectedDurationMs >= 70,
      `80ms pg_sleep must produce at least 70ms elapsed; observed ${injectedDurationMs.toFixed(2)}ms`);
    assert.ok(injectedDurationMs - baselineDurationMs >= 50,
      `injected query must exceed baseline by at least 50ms; baseline=${baselineDurationMs.toFixed(2)}ms injected=${injectedDurationMs.toFixed(2)}ms`);
  } finally {
    try { await agents?.close(); } finally { await shop.close(); }
  }
});
