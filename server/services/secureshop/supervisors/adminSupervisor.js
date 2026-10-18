/**
 * Admin supervisor — mirrors customer/merchantSupervisor. Binds the role="admin"
 * system prompt (basePrompt.js) and manifest.getForRole('admin') tool list.
 *
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location server/services/secureshop/supervisors/adminSupervisor.js
 * intentional — the ROLE_MAP['admin'] tool list is advisory only. The runtime
 * dispatches any tool_use the LLM emits, even if it targets an out-of-role
 * namespace. The admin supervisor is *especially* dangerous here because its
 * prompt already contains every high-privilege tool — one bad injection walks
 * off with the whole platform.
 *
 * @intentional-vulnerability llm07-system-prompt-leak
 * @teaches OWASP-LLM:LLM07
 * intentional — no output filter; the assistant may forward the admin system
 * prompt (including concatenated poisoned policies from policyLoader) verbatim.
 *
 * @intentional-vulnerability llm10-audit-unbounded
 * @teaches OWASP-LLM:LLM10
 * intentional — MAX_STEPS caps outer iterations but audit.summarize_anomalies
 * accepts an unbounded `limit`; its tool_result byte size can dwarf the
 * message list and blow up the next LLM call.
 */

const { createSupervisorGraph } = require('../../../agent-runtime/secureshopSupervisorGraph');
const runGraph = createSupervisorGraph({
  store: require('../sessionStore.js'),
  Trace: require('../trace.js').Trace,
  buildBasePrompt: require('./basePrompt.js').buildBasePrompt,
  buildPolicyBlock: require('./policyLoader.js').buildPolicyBlock,
  checkToolAcl: require('../toolAcl.js').checkToolAcl,
});
const MAX_STEPS = Number(process.env.SS_ADMIN_MAX_STEPS || 8);
const MAX_PARALLEL_TOOLS = Number(process.env.SS_ADMIN_MAX_PARALLEL_TOOLS || 4);
async function run(sessionId, userMessage, opts = {}) {
  return runGraph(sessionId, userMessage, { ...opts, role: opts.role || 'admin' },
    { maxSteps: MAX_STEPS, maxParallelTools: MAX_PARALLEL_TOOLS });
}
module.exports = { adminSupervisor: { run }, MAX_STEPS, MAX_PARALLEL_TOOLS };
