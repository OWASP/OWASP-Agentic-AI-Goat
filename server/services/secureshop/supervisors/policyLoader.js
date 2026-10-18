'use strict';

/**
 * Policy loader — reads active PostgreSQL policies and injects them into the
 * supervisor system prompt on every turn.
 *
 * @intentional-vulnerability llm04-policy-poisoning
 * @teaches OWASP-LLM:LLM04
 * @location server/services/secureshop/supervisors/policyLoader.js
 *
 * intentional — the markdown_source field is concatenated verbatim.
 */

async function loadForRole(role, _opts = {}) {
  const { rows } = await require('../../../database/postgres/secureshopPools')
    .getCommercePool()
    .query('SELECT id,name,markdown_source,injected_into_json FROM secureshop.policies');
  return rows.filter((row) => {
    try { return JSON.parse(row.injected_into_json || '[]').includes(role); }
    catch { return false; }
  });
}

async function buildPolicyBlock(role, opts = {}) {
  return formatPolicyBlock(await loadForRole(role, opts));
}

function formatPolicyBlock(policies) {
  if (!policies.length) return '';
  const parts = policies.map((policy) => `## Policy: ${policy.name}\n\n${policy.markdown_source}`);
  return `--- ACTIVE POLICIES (${policies.length}) ---\n\n${parts.join('\n\n')}\n\n--- END POLICIES ---`;
}

module.exports = { loadForRole, buildPolicyBlock };
