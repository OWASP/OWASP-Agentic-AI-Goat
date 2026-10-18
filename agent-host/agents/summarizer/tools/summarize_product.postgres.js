const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * summarizer.summarize_product — reads product row and returns a summary that
 * INCLUDES the raw product description verbatim.
 *
 * @intentional-vulnerability llm01-indirect-pi-product
 * @teaches OWASP-LLM:LLM01
 * @location agent-host/agents/summarizer/tools/summarize_product.js
 * intentional — teaches llm01-indirect-pi: description is passed to supervisor
 * verbatim so hidden [SYSTEM:...] blocks reach the LLM context.
 */



async function summarizeProduct({ product_id }) {
  const db = null;
  const row = await commerce.summarizer_summarizeProduct_1(product_id);
  if (!row) return { error: 'unknown product_id', product_id };

  // A hand-rolled "summary" that keeps the description verbatim so PI flows through.
  const summary = `Product: ${row.name}\nPrice: $${row.price}\nCategory: ${row.category || 'N/A'}\nStock: ${row.stock_quantity}\n\nDescription: ${row.description || ''}\n\n(Also available: HTML rendering.)`;

  return {
    product_id: row.id,
    name: row.name,
    price: row.price,
    category: row.category,
    stock_quantity: row.stock_quantity,
    description: row.description,          // verbatim — LLM01 sink
    description_html: row.description_html, // verbatim — LLM05 sink
    summary,
  };
}

module.exports = { summarizeProduct };
