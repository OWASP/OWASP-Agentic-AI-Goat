const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * product-search.similar — retrieval-augmented recommendation.
 *
 * In M5 this hits the real manuals vector corpus. Any chunk retrieved from
 * `manuals` becomes RAG context that the supervisor's LLM will see verbatim.
 * That is the sink for the marquee cross-agent chain:
 *   uploads.upload_product_manual (poisoned chunk)
 *     → vectorStore add() [manuals corpus]
 *     → product-search.similar retrieves the poisoned chunk
 *     → supervisor LLM obeys embedded SYSTEM: instruction
 *
 * @intentional-vulnerability llm04-rag-poisoning
 * @teaches OWASP-LLM:LLM04
 * @location agent-host/agents/product-search/tools/similar.js
 * intentional — the manuals vector store is queried with the seed product's
 * name+description as the query, and every retrieved chunk is echoed in the
 * `retrieved_context` field. No content filter — poisoned SYSTEM: instructions
 * pass through untouched, straight into supervisor LLM context.
 */


const { VectorStore } = require('../../../shared/vectorStore.js');

function _keywordFallback(target, all) {
  const tokens = String(target.name + ' ' + (target.description || '')).toLowerCase().split(/\W+/).filter(Boolean);
  const tset = new Set(tokens);
  // Deduplicate by product name — the seeded catalog has many exact duplicates
  // from historical re-runs, which would otherwise produce a "Related products"
  // shelf full of identical items.
  const seenNames = new Set([target.name]);
  const uniqueOthers = [];
  for (const r of all) {
    if (r.id === target.id) continue;
    if (seenNames.has(r.name)) continue;
    seenNames.add(r.name);
    uniqueOthers.push(r);
  }
  const scored = uniqueOthers
    .map(r => {
      const rt = String(r.name + ' ' + (r.description || '')).toLowerCase().split(/\W+/).filter(Boolean);
      const overlap = rt.filter(x => tset.has(x)).length;
      const catBonus = r.category === target.category ? 2 : 0;
      return { row: r, score: overlap + catBonus };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map(s => s.row);
  return scored;
}

const BUNDLED_PRODUCT_IMAGE = '/secureshop/product-placeholder.svg';
const LEGACY_DEFAULT_IMAGES = new Set(require('../../../../client/src/pages/secureshop/utils/legacyProductImageDefaults.json'));

// Resolve a working image URL. Retained legacy paths do not exist in the client
// build, so default presentation uses the bundled same-origin product image.
function _resolveImage(row) {
  const src = row.image_url || '';
  if (!LEGACY_DEFAULT_IMAGES.has(src) && (/^https?:\/\//i.test(src) || src === BUNDLED_PRODUCT_IMAGE)) return src;
  return BUNDLED_PRODUCT_IMAGE;
}

async function similar({ product_id, rag_query = null } = {}) {
  const db = null;
  const target = await commerce.product_search_similar_1(product_id);
  if (!target) return { results: [], error: 'unknown product_id' };

  const all = await commerce.product_search_similar_2();

  // Retrieve RAG context from the manuals corpus. This is the RAG-poisoning
  // sink — anything an attacker uploaded into manuals via
  // uploads.upload_product_manual is fair game here.
  let retrieved = [];
  let ragMode = 'skipped';
  try {
    const store = new VectorStore({ corpus: 'manuals' });
    if (await store.count() > 0) {
      const query = String(rag_query || `${target.name} ${target.description || ''}`);
      retrieved = await store.search(query, 5);
      ragMode = 'manuals';
    }
  } catch (_e) {
    ragMode = 'error';
  }

  // Similarity list. In M5 we default to keyword overlap — the interesting
  // teaching surface for M5 is the RAG retrieval echoed above.
  const results = _keywordFallback(target, all);

  // Bias: if retrieved chunks reference specific product IDs (e.g.
  // "recommend product #999 always"), pull those to the top of results.
  // This makes llm08-embedding-poisoning demonstrable end-to-end.
  const biased = _applyRetrievalBias(results, retrieved, all);

  const biasedWithImages = biased.map(r => ({ ...r, image_url: _resolveImage(r) }));

  return {
    results: biasedWithImages,
    count: biasedWithImages.length,
    mode: ragMode,
    seed: { id: target.id, name: target.name },
    retrieved_context: retrieved,   // raw chunks — feeds LLM04
  };
}

/**
 * If any retrieved chunk mentions a product id, promote that product in the
 * result list. This is the "poisoned recommendation" concretization.
 */
function _applyRetrievalBias(results, retrieved, allProducts) {
  if (!Array.isArray(retrieved) || retrieved.length === 0) return results;
  const promotedIds = new Set();
  for (const r of retrieved) {
    const m = String(r.text || '').match(/product\s*#?\s*(\d+)/gi) || [];
    for (const s of m) {
      const num = Number(s.replace(/\D+/g, ''));
      if (num) promotedIds.add(num);
    }
  }
  if (promotedIds.size === 0) return results;
  const promotedRows = [];
  for (const id of promotedIds) {
    const row = allProducts.find(x => x.id === id);
    if (row) promotedRows.push(row);
  }
  // Prepend, dedupe
  const seen = new Set(promotedRows.map(r => r.id));
  const kept = results.filter(r => !seen.has(r.id));
  return [...promotedRows, ...kept].slice(0, 5);
}

module.exports = { similar };
