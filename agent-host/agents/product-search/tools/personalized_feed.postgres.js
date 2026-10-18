const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * product-search.personalized_feed — a lightly-personalized feed for a user.
 *
 * For M2 this is intentionally simple: category-weighted top products, no
 * grounding by real purchase history. LLM09 misinformation-adjacent because
 * "personalized" is not truly personal.
 */



async function personalizedFeed({ user_id }) {
  const db = null;
  const rows = await commerce.product_search_personalizedFeed_1();
  return { feed: rows, count: rows.length, user_id };
}

module.exports = { personalizedFeed };
