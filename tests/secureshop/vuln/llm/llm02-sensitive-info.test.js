const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm02-sensitive-info
 * @teaches OWASP-LLM:LLM02
 * @location agent-host/agents/user-management/tools/index.js
 * lookup returns the full user row including bcrypt hash, session_token, api_key, pii_json.
 * That same tool is reachable from the customer supervisor (per LLM06); this
 * test proves LLM02 in isolation.
 */
test('llm02-sensitive-info: user-management.lookup returns bcrypt hash + api_key + session_token', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  const a = await seedAgents();
  t.after(() => a.close());
  purgeToolCaches();
  try {
    const { lookup } = require(path.join(REPO, 'agent-host/agents/user-management/tools/index.js'));
    const r = await lookup({ username: 'sasan' });
    assert.equal(r.username, 'sasan');
    assert.match(r.password, /bcrypt_hash_sasan/, 'password hash leaks');
    assert.match(r.api_key, /sk_ss_sasan_secret_key_deadbeef/);
    assert.match(r.session_token, /sess_sasan_deadbeef/);
    assert.match(r.pii_json, /555-0001/);
  } finally {
  }
});
