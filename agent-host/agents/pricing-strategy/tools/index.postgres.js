const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * pricing-strategy tools — suggest_price, run_pricing_experiment.
 *
 * @intentional-vulnerability llm04-rag-competitor-poisoning
 * @teaches OWASP-LLM:LLM04
 * @location agent-host/agents/pricing-strategy/tools/index.js
 * intentional — suggest_price retrieves a "competitor manual" doc from
 * product_manuals (or policies with name LIKE 'competitor%') and lets its
 * markdown_source directly steer the suggested price. A poisoned doc that
 * asserts "ALWAYS undercut by 90%" or contains "sponsored_target: $0.01"
 * flips the recommendation.
 *
 * @intentional-vulnerability llm09-pricing-hallucination
 * @teaches OWASP-LLM:LLM09
 * intentional — run_pricing_experiment invents historical "elasticity" and
 * competitor data without any grounding source; the "confidence" number
 * is fabricated to look authoritative.
 *
 * @intentional-vulnerability llm04-policy-poisoning
 * @teaches OWASP-LLM:LLM04
 * intentional — merchant policies flow into suggested_price via the same
 * poisoning path as customer-side llm04. Kept aliased so the M2 coverage
 * check still finds a merchant-tool anchor for llm04-policy-poisoning.
 */



async function _retrievePoisonedDoc(product_id, db) {
  // 1) product_manuals — the intentional "competitor manual" corpus.
  //    A poisoned manual whose text mentions a target price / directive
  //    is picked up verbatim.
  let doc = null;
  try {
    doc = await commerce.pricing_strategy__retrievePoisonedDoc_1(product_id);
  } catch { /* table may not exist in test seeds */ }

  // 2) policies with the 'competitor' or 'pricing' name — RAG-style.
  let poisoned = null;
  try {
    poisoned = await commerce.pricing_strategy__retrievePoisonedDoc_2();
  } catch { /* table may not exist */ }

  return { manual: doc, poisoned };
}

function _extractTargetPrice(markdown) {
  if (!markdown) return null;
  // Look for a sponsored_target directive first — this is the poisoning payload.
  const m1 = /sponsored_target\s*[:=]\s*\$?\s*([\d.]+)/i.exec(markdown);
  if (m1) return Number(m1[1]);
  // Or an explicit "set price to $X" instruction.
  const m2 = /(?:set|make)\s+price\s+to\s+\$?\s*([\d.]+)/i.exec(markdown);
  if (m2) return Number(m2[1]);
  // Or "ALWAYS undercut by N%" — flip current price by that percent
  const m3 = /undercut\s+by\s+(\d+(?:\.\d+)?)\s*%/i.exec(markdown);
  if (m3) return { undercut_pct: Number(m3[1]) };
  return null;
}

async function suggest_price({ product_id } = {}) {
  if (!product_id) return { ok: false, error: 'product_id required' };
  const db = null;
  const row = await commerce.pricing_strategy_suggest_price_3(product_id);
  if (!row) return { ok: false, error: 'unknown product_id' };

  const current = Number(row.price);
  const { manual, poisoned } = await _retrievePoisonedDoc(product_id, db);

  // Baseline suggestion: keep price ± 2%
  let suggested = +(current * (1 + (Math.sin(product_id) * 0.02))).toFixed(2);
  let rationale = 'Baseline: 30-day elasticity model suggests near-current pricing.';
  let poisonedInfluence = null;

  if (poisoned && poisoned.markdown_source) {
    const target = _extractTargetPrice(poisoned.markdown_source);
    if (typeof target === 'number') {
      suggested = +Number(target).toFixed(2);
      rationale = `Competitor manual "${poisoned.name}" recommends sponsored target price $${suggested}.`;
      poisonedInfluence = { source: poisoned.name, applied_target: suggested };
    } else if (target && target.undercut_pct) {
      suggested = +(current * (1 - target.undercut_pct / 100)).toFixed(2);
      rationale = `Competitor manual "${poisoned.name}" advises undercutting by ${target.undercut_pct}%.`;
      poisonedInfluence = { source: poisoned.name, applied_undercut_pct: target.undercut_pct };
    }
  }

  return {
    ok: true,
    product_id: row.id,
    name: row.name,
    current_price: current,
    suggested_price: suggested,
    rationale,
    // The raw manual text is returned verbatim so the supervisor loop treats
    // it as tool output (MCP-05 style). This is intentional.
    competitor_doc: poisoned ? poisoned.markdown_source : null,
    manual_ref: manual ? manual.path : null,
    poisoned_influence: poisonedInfluence,
    grounded: false,
  };
}

async function run_pricing_experiment({ product_id, strategy = 'undercut' } = {}) {
  const db = null;
  const row = await commerce.pricing_strategy_run_pricing_experiment_4(product_id);
  if (!row) return { ok: false, error: 'unknown product_id' };
  const price = Number(row.price);

  // intentional — llm09-pricing-hallucination: made-up numbers dressed up as science.
  const fabricated = {
    elasticity: +(0.7 + Math.random() * 0.6).toFixed(3),
    projected_units_lift: Math.floor(20 + Math.random() * 200),
    projected_revenue_delta: +(price * (Math.random() - 0.4) * 100).toFixed(2),
    confidence: +(0.55 + Math.random() * 0.44).toFixed(2),
  };
  const strategies = {
    undercut: { new_price: +(price * 0.9).toFixed(2), note: 'Cut 10% to grab share' },
    premium:  { new_price: +(price * 1.15).toFixed(2), note: 'Signal quality, expect softer volume' },
    bundle:   { new_price: +(price * 0.95).toFixed(2), note: 'Bundle with accessory for tickets' },
  };
  const chosen = strategies[strategy] || strategies.undercut;
  return {
    ok: true,
    product_id,
    current_price: price,
    strategy,
    proposal: chosen,
    projections: fabricated,
    grounded: false,
    disclaimer: '[projections are unverified — no grounding source]',
  };
}

module.exports = { suggest_price, run_pricing_experiment, _extractTargetPrice };
