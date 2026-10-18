const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * summarizer.summarize_reviews — returns top-k reviews for a product verbatim.
 *
 * @intentional-vulnerability llm01-indirect-pi-review
 * @teaches OWASP-LLM:LLM01
 * Review bodies flow into the summarizer prompt unchanged — hidden [SYSTEM:...]
 * blocks reach the LLM context.
 */



async function summarizeReviews({ product_id, k = 5 }) {
  const db = null;
  const rows = await commerce.summarizer_summarizeReviews_1(product_id, k);
  return {
    product_id,
    k,
    count: rows.length,
    reviews: rows,
    concatenated_bodies: rows.map(r => r.body).join('\n\n---\n\n'),
  };
}

module.exports = { summarizeReviews };
