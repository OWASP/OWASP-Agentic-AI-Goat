/**
 * Internal LLM "rewrite" for listing.create. Tries the multiProviderAIService
 * for real completions; falls back to a deterministic passthrough that keeps
 * any inline HTML tags so the LLM05 sink is provable even without Ollama.
 *
 * @intentional-vulnerability llm05-listing-xss
 * @teaches OWASP-LLM:LLM05
 * @location agent-host/agents/listing/tools/_llmRewrite.js
 * intentional — the LLM output is NOT sanitized before insertion into
 * products.description_html; script/img/onerror all flow through.
 */

let multiProvider = null;
try {
  multiProvider = require('../../../../server/services/multiProviderAIService.js');
} catch { multiProvider = null; }

async function rewriteDescription({ title, description }) {
  const desc = String(description || '');
  const t = String(title || '');
  // If the description already contains HTML/script, preserve it (the sink).
  if (/<script|<img|<iframe|<svg|onerror=|onload=/i.test(desc)) {
    return `<p><strong>${t}</strong></p>\n<div class="ai-rewrite">${desc}</div>`;
  }

  // Try a real LLM call, but never let a network failure block the tool call.
  if (multiProvider && typeof multiProvider.generateResponse === 'function' && process.env.SS_LISTING_LLM_ENABLED === 'true') {
    try {
      const prompt = `You are a marketing copywriter. Rewrite the following product description as marketing HTML. Preserve any embedded HTML tags exactly.\n\nTITLE: ${t}\nDESCRIPTION: ${desc}\n\nHTML output:`;
      const out = await multiProvider.generateResponse(prompt, { max_tokens: 400, timeout: 3000 });
      const html = typeof out === 'string' ? out : (out && out.text) || '';
      if (html) return html;
    } catch { /* fall through */ }
  }

  // Deterministic passthrough — this is the intentional teaching path.
  return `<p><strong>${t}</strong></p>\n<div class="ai-rewrite">${desc || 'No description provided.'}</div>`;
}

module.exports = { rewriteDescription };
