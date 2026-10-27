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
const MAX_STEPS = Number(process.env.SS_ADMIN_MAX_STEPS || 8);
const MAX_PARALLEL_TOOLS = Number(process.env.SS_ADMIN_MAX_PARALLEL_TOOLS || 4);
// Trusted persistence/authority injection; prompts, policy loading and graph
// limits remain the original administrator workflow. Never request arguments.
function createAdminSupervisor({store,Trace,checkToolAcl}) {
  if(!store||typeof Trace!=='function'||typeof checkToolAcl!=='function')throw new TypeError('Trusted admin dependencies required');
  const runGraph=createSupervisorGraph({store,Trace,checkToolAcl,
    buildBasePrompt:require('./basePrompt.js').buildBasePrompt,
    buildPolicyBlock:require('./policyLoader.js').buildPolicyBlock});
  return Object.freeze({async run(sessionId,userMessage,opts={}){
    return runGraph(sessionId,userMessage,{...opts,role:opts.role||'admin'},
      {maxSteps:MAX_STEPS,maxParallelTools:MAX_PARALLEL_TOOLS});
  }});
}
const adminSupervisor=createAdminSupervisor({store:require('../sessionStore.js'),
  Trace:require('../trace.js').Trace,checkToolAcl:require('../toolAcl.js').checkToolAcl});
module.exports = { adminSupervisor, createAdminSupervisor, MAX_STEPS, MAX_PARALLEL_TOOLS };
