const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm01-indirect-pi-product
 * @teaches OWASP-LLM:LLM01
 * @location agent-host/agents/summarizer/tools/summarize_product.js
 * The product description contains a hidden [SYSTEM: ...] block. Because the
 * summarizer returns the description verbatim, the payload flows into the
 * supervisor context.
 */
test('llm01-indirect-pi-product: summarize_product returns payload embedded in description', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    const { summarizeProduct } = require(path.join(REPO, 'agent-host/agents/summarizer/tools/summarize_product.js'));
    const r = await summarizeProduct({ product_id: 1 });
    assert.match(JSON.stringify(r), /DV-AI\{leak-via-desc\}/);
  } finally {
  }
});
