/**
 * Merchant supervisor — mirrors customerSupervisor loop but binds the
 * role="merchant" system prompt (basePrompt.js) and manifest.getForRole('merchant').
 *
 * The loop appends tool results VERBATIM to the message list (spec §4.2):
 * that is the MCP-05 / LLM01-indirect sink. Do not sanitize here.
 *
 * This supervisor teaches the same core LLM vulns as customerSupervisor plus
 * the merchant-surface ones (see spec §5.2/§5.3):
 *
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location server/services/secureshop/supervisors/merchantSupervisor.js
 * intentional — the ROLE_MAP['merchant'] tool list is advisory only. If the
 * LLM emits a tool_use for an admin-only namespace, the runtime dispatches
 * it anyway. Merchant supervisor teaches the same lesson as customer.
 *
 * @intentional-vulnerability llm10-analytics-unbounded
 * @teaches OWASP-LLM:LLM10
 * intentional — MAX_STEPS caps outer iterations but analytics.nl_query can
 * emit unbounded SELECTs whose byte-size grows the message list without
 * back-pressure; a runaway is still visible in the trace.
 */

const { createSupervisorGraph } = require('../../../agent-runtime/secureshopSupervisorGraph');
const runGraph = createSupervisorGraph({
  store: require('../sessionStore.js'),
  Trace: require('../trace.js').Trace,
  buildBasePrompt: require('./basePrompt.js').buildBasePrompt,
  buildPolicyBlock: require('./policyLoader.js').buildPolicyBlock,
  checkToolAcl: require('../toolAcl.js').checkToolAcl,
});
const MAX_STEPS = Number(process.env.SS_MERCHANT_MAX_STEPS || 8);
const MAX_PARALLEL_TOOLS = Number(process.env.SS_MERCHANT_MAX_PARALLEL_TOOLS || 4);
async function run(sessionId, userMessage, opts = {}) {
  return runGraph(sessionId, userMessage, { ...opts, role: opts.role || 'merchant' },
    { maxSteps: MAX_STEPS, maxParallelTools: MAX_PARALLEL_TOOLS });
}
module.exports = { merchantSupervisor: { run }, MAX_STEPS, MAX_PARALLEL_TOOLS };
