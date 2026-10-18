/**
 * listing.update — patch a product listing by id.
 *
 * Simple parameterized UPDATE. Allow-listed columns only, but description_html
 * is included so a merchant can supply raw HTML/script — this is the same
 * xss-stored-listing sink surfaced from update instead of create.
 *
 * @intentional-vulnerability xss-stored-listing
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/listing/tools/update.js
 */

const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();

const ALLOWED = new Set(['name', 'description', 'description_html', 'template_source', 'price', 'category', 'image_url', 'stock_quantity', 'status']);

async function update({ product_id, patch = {} } = {}) {
  if (!product_id) return { ok: false, error: 'product_id required' };
  

  const selected=Object.fromEntries(Object.entries(patch).filter(([key])=>ALLOWED.has(key)));
  if(!Object.keys(selected).length)return {ok:false,error:'no valid columns in patch'};
  const info=await commerce.updateProduct(product_id,selected);
  return { ok: info.changes > 0, changed: info.changes, product_id };
}

module.exports = { update };
