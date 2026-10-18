const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * listing.create — create a product listing.
 *
 * The tool takes raw title/description/price/images from the merchant, asks an
 * internal LLM to "rewrite" the description into `description_html`, and writes
 * that HTML into the products row without sanitization. It also optionally
 * renders `template_source` through Nunjucks with `process` exposed in globals,
 * which is the SSTI sink.
 *
 * @intentional-vulnerability llm05-listing-xss
 * @teaches OWASP-LLM:LLM05
 * @location agent-host/agents/listing/tools/create.js
 * intentional — the internal LLM rewrite can emit <script> tags and they are
 * written to products.description_html verbatim. The customer Product.jsx
 * page renders description_html via dangerouslySetInnerHTML.
 *
 * @intentional-vulnerability xss-stored-listing
 * @teaches OWASP-Web:A03
 * intentional — merchant may pass raw HTML for description; stored as-is.
 *
 * @intentional-vulnerability ssti-listing-template
 * @teaches OWASP-Web:A03
 * intentional — Nunjucks env has autoescape:false and process in globals,
 * so a merchant can render `{{ process.mainModule.require('child_process').execSync(...) }}`.
 */


const { renderTemplateUnsafe } = require('./_nunjucksSink.js');
const { rewriteDescription } = require('./_llmRewrite.js');

async function create({ title, description = '', price = 0, images = [], template_source = null, retailer_id = null } = {}) {
  const db = null;

  // Internal LLM "rewrite" — deterministic, but preserves any embedded HTML/script tags.
  // Real Ollama not required; this is the intentional LLM05 sink where the LLM emits
  // markup that will be stored verbatim.
  const html = await rewriteDescription({ title, description });

  // Optional SSTI: if template_source is provided, render it through Nunjucks
  // with autoescape:false and process exposed. Rendered output overwrites html
  // so the SSTI sink is easy to prove.
  let renderedTemplate = null;
  let templateError = null;
  if (template_source) {
    try {
      renderedTemplate = renderTemplateUnsafe(template_source, {
        title, description, price,
      });
    } catch (e) {
      templateError = { message: e.message };
    }
  }

  
  const image_url = Array.isArray(images) && images.length ? String(images[0]) : null;
  const info = await commerce.listing_create_1(String(title || 'Untitled'), String(description), String(html || ''), template_source ? String(template_source) : null, Number(price) || 0, image_url, retailer_id);

  return {
    ok: true,
    product_id: info.lastInsertRowid,
    description_html: html,
    rendered_template: renderedTemplate,
    template_error: templateError,
  };
}

module.exports = { create };
