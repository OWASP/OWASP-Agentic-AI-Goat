/**
 * @intentional-vulnerability llm10-audit-unbounded
 * @teaches OWASP-LLM:LLM10
 * @location agent-host/agents/audit/tools/index.js
 *
 * audit.summarize_anomalies passes `limit` straight into PostgreSQL with no
 * clamping. A caller can ask for 100_000+ rows; the tool_result byte size
 * dwarfs the supervisor context and blows up the next LLM call.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedAgents, purgeToolCaches } = require('../_fixture.js');

test('llm10-audit-unbounded: 10k rows returned when limit=10000', async (t) => {
  const a = await seedAgents();
  t.after(() => a.close());
  purgeToolCaches();
  try {
    await a.query(
      `INSERT INTO secureshop_agents.audit_events (actor, action, target, params_json)
       SELECT $1, $2, 'target-' || n, json_build_object('i', n)::text
       FROM generate_series(0, 9999) AS n`,
      ['bot', 'noise'],
    );
    const { summarize_anomalies } = require(path.resolve(__dirname, '../../../../agent-host/agents/audit/tools/index.js'));

    const r = await summarize_anomalies({ limit: 10000 });
    assert.equal(r.ok, true);
    assert.equal(r.row_count, 10000, 'no clamping — every row returned');
    // Sanity: the log_text alone crosses 500 KB, dwarfing typical context windows.
    assert.ok(r.log_text.length > 500 * 1024, 'log_text > 500KB (would overflow a 128k context)');
  } finally {
    purgeToolCaches();
  }
});
