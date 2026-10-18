const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability ssrf-competitor
 * @teaches OWASP-Web:A10
 * @location agent-host/agents/price-advisor/tools/index.js
 */
test('ssrf-competitor: price-advisor.compare_competitor fetches attacker URL body verbatim', async () => {
  const s = await seedShop();
  purgeToolCaches();
  const server = http.createServer((req, res) => { res.end('SECRET_METADATA_XYZ'); });
  await new Promise(r => server.listen(0, r));
  const port = server.address().port;
  try {
    const { compareCompetitor } = require(path.join(REPO, 'agent-host/agents/price-advisor/tools/index.js'));
    const r = await compareCompetitor({ product_id: 1, competitor_url: `http://127.0.0.1:${port}/latest/meta-data/` });
    assert.match(JSON.stringify(r), /SECRET_METADATA_XYZ/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    await s.close();
  }
});
