const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability ssrf-return-policy
 * @teaches OWASP-Web:A10
 * @location agent-host/agents/summarizer/tools/explain_return_policy.js
 */
test('ssrf-return-policy: summarizer.explain_return_policy fetches arbitrary URL', async () => {
  const s = await seedShop();
  purgeToolCaches();
  const server = http.createServer((req, res) => { res.end('METADATA_LEAK_return'); });
  await new Promise(r => server.listen(0, r));
  const port = server.address().port;
  try {
    const { explainReturnPolicy } = require(path.join(REPO, 'agent-host/agents/summarizer/tools/explain_return_policy.js'));
    const r = await explainReturnPolicy({ policy_url: `http://127.0.0.1:${port}/metadata` });
    assert.match(JSON.stringify(r), /METADATA_LEAK_return/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    await s.close();
  }
});
