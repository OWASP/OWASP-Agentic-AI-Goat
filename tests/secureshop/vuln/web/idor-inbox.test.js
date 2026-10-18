const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability idor-inbox
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/email/tools/index.js
 *
 * read_inbox(user_id) trusts any user_id. There is no session/JWT check, no
 * cross-check that the caller owns the account. Bob asks for Alice's inbox
 * → gets it.
 */
test('idor-inbox: read_inbox(user_id) returns any user\'s emails with no auth', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { send, read_inbox } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    // Send an email to alice
    await send({ to: 'alice@x.local', subject: 'secret', body_markdown: 'You won the lottery.', from: 'ops@shop.local' });
    // Attacker asks for alice's inbox by her user_id (2)
    const inbox = await read_inbox({ user_id: 2 });
    assert.equal(inbox.ok, true);
    assert.equal(inbox.email, 'alice@x.local');
    assert.ok(inbox.emails.length >= 1, 'attacker retrieved alice\'s inbox');
    assert.match(JSON.stringify(inbox.emails), /You won the lottery/, 'private email body leaks');
  } finally {
    await s.close();
  }
});
