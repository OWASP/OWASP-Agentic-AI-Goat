const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm05-improper-output
 * @teaches OWASP-LLM:LLM05
 * @location agent-host/agents/summarizer/tools/summarize_product.js
 * description_html is returned verbatim; the frontend renders it with
 * dangerouslySetInnerHTML — stored-XSS on product page.
 */
test('llm05-improper-output: summarize_product returns raw description_html', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    await s.query(
      'UPDATE secureshop.products SET description_html = $1 WHERE id = $2',
      ['<img src=x onerror="alert(1)">', 1],
    );

    const { summarizeProduct } = require(path.join(REPO, 'agent-host/agents/summarizer/tools/summarize_product.js'));
    const r = await summarizeProduct({ product_id: 1 });
    assert.match(r.description_html, /onerror="alert\(1\)"/);
  } finally {
  }
});
