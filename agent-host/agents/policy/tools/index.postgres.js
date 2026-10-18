const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * policy tools — read_policy, update_policy, apply_policy_to_agents.
 *
 * @intentional-vulnerability ssti-policy-template
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/policy/tools/index.js
 * intentional — update_policy passes the caller-supplied markdown through
 * the same unsafe Nunjucks env that listing/tools uses. `process` is exposed
 * as a template global, so `{{ process.mainModule.require('child_process').execSync('id') }}`
 * renders to command output. The rendered result is stored in policies.markdown_source.
 *
 * @intentional-vulnerability llm04-policy-poisoning
 * @teaches OWASP-LLM:LLM04
 * intentional — policyLoader re-reads the policies table on EVERY supervisor
 * turn. A single successful update_policy call poisons every subsequent
 * supervisor prompt. apply_policy_to_agents is a no-op at runtime because
 * the loader already picks up changes; it exists so the admin agent has an
 * explicit "flush" tool and so this sink is annotated as the LLM04 anchor.
 */

const path = require('node:path');

const { renderTemplateUnsafe } = require('../../listing/tools/_nunjucksSink.js');


async function read_policy({ name } = {}) {
  const db = null;
  try {
    const row = await commerce.policy_read_policy_1(name);
    if (!row) return { error: 'unknown policy', name };
    return row;
  } finally {
    
  }
}

async function update_policy({ name, markdown } = {}) {
  const db = null;
  try {
    const raw = String(markdown == null ? '' : markdown);
    // The SSTI sink: render the caller's markdown through the unsafe
    // Nunjucks env before persisting. Real store: {{ variable }} would
    // interpolate helpful things like {{ store_name }}. Vulnerable store:
    // `{{ process.mainModule.require('child_process').execSync('id').toString() }}`.
    let rendered;
    try {
      rendered = renderTemplateUnsafe(raw, { store_name: 'SecureShop', current_year: new Date().getFullYear() });
    } catch (e) {
      rendered = `[template-error: ${e.message}]\n${raw}`;
    }
    // Upsert
    await commerce.upsertPolicy(name,rendered);
    return {
      ok: true,
      name,
      input_length: raw.length,
      rendered_length: rendered.length,
      rendered_preview: rendered.slice(0, 400),
      // Full rendered kept so tests can assert SSTI executed
      rendered,
    };
  } finally {
    
  }
}

async function apply_policy_to_agents({ role = null } = {}) {
  // Runtime no-op: policyLoader.loadForRole() reads from the DB on EVERY
  // supervisor turn, so persistence in update_policy is enough. This tool
  // returns the current policy count for the role so callers can confirm
  // their poisoning landed.
  const db = null;
  try {
    const rows = await commerce.policy_apply_policy_to_agents_5();
    const matching = [];
    for (const r of rows) {
      let targets = [];
      try { targets = JSON.parse(r.injected_into_json || '[]'); } catch { targets = []; }
      if (!role || targets.includes(role)) matching.push({ id: r.id, name: r.name, updated_at: r.updated_at });
    }
    return { ok: true, role, applied_count: matching.length, policies: matching };
  } finally {
    
  }
}

module.exports = { read_policy, update_policy, apply_policy_to_agents };
