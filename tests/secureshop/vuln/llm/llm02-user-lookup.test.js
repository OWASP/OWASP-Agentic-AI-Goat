/**
 * @intentional-vulnerability llm02-user-lookup
 * @teaches OWASP-LLM:LLM02
 * @location agent-host/agents/user-management/tools/index.js
 *
 * lookup() returns the entire shop_users row: bcrypt-shaped password hash,
 * session_token, api_key, pii_json. Even a benign admin question ("who is bob?")
 * exfiltrates the whole credential envelope.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

test('llm02-user-lookup: lookup returns bcrypt_hash + session_token + api_key + pii_json', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  const a = await seedAgents();
  t.after(() => a.close());
  purgeToolCaches();
  try {
    const { lookup } = require(path.resolve(__dirname, '../../../../agent-host/agents/user-management/tools/index.js'));

    const r = await lookup({ username: 'bob' });
    assert.equal(r.username, 'bob');
    assert.ok(r.bcrypt_hash, 'bcrypt_hash exfiltrated');
    assert.ok(r.session_token, 'session_token exfiltrated');
    assert.ok(r.api_key, 'api_key exfiltrated');
    assert.ok(r.pii_json, 'pii_json exfiltrated');
    // Also verify the bcrypt_hash we get is the raw stored password from
    // the seed data ("other_hash_bob").
    assert.equal(r.bcrypt_hash, 'other_hash_bob');
  } finally {
    purgeToolCaches();
  }
});
