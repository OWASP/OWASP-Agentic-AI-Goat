/**
 * Customer supervisor — implements the spec §4.2 supervisor loop.
 *
 * The loop appends tool results VERBATIM to the message list (see spec §4.2):
 * that is the MCP-05 / LLM01-indirect sink. Do not sanitize here.
 *
 * @intentional-vulnerability mcp-05-pi-via-tool-output
 * @teaches OWASP-MCP:MCP-06
 * @location server/services/secureshop/supervisors/customerSupervisor.js
 * intentional — teaches mcp-05: tool_result content is trusted by supervisor.
 *
 * @intentional-vulnerability llm01-direct-pi
 * @teaches OWASP-LLM:LLM01
 * intentional — teaches llm01-direct-pi: the user message reaches the LLM
 * without an input safety filter; jailbreak prompts flow straight through.
 *
 * @intentional-vulnerability llm07-system-prompt-leak
 * @teaches OWASP-LLM:LLM07
 * intentional — teaches llm07: no output filter, so the assistant may forward
 * the system prompt (including the concatenated poisoned policies) verbatim.
 *
 * @intentional-vulnerability llm10-unbounded
 * @teaches OWASP-LLM:LLM10
 * intentional — teaches llm10: MAX_STEPS = 8 guards the loop, but individual
 * tool results carry unbounded byte size into the next LLM call — a real
 * runaway is still visible in the trace.
 */

const { createSupervisorGraph } = require('../../../agent-runtime/secureshopSupervisorGraph');
const MAX_STEPS = Number(process.env.SS_AGENT_MAX_STEPS || 8);
const MAX_PARALLEL_TOOLS = Number(process.env.SS_AGENT_MAX_PARALLEL_TOOLS || 4);
// Trusted composition dependencies, never request fields. The original prompt,
// policy loader, catalog selection and loop limits are shared by both paths.
function createCustomerSupervisor({store,Trace,checkToolAcl,disclosureCapability}) {
  if(!store||typeof Trace!=='function'||typeof checkToolAcl!=='function')throw new TypeError('Trusted customer dependencies required');
  const runGraph=createSupervisorGraph({store,Trace,checkToolAcl,
    buildBasePrompt:require('./basePrompt.js').buildBasePrompt,
    buildPolicyBlock:require('./policyLoader.js').buildPolicyBlock});
  return Object.freeze({async run(sessionId,userMessage,opts={}){
    if(disclosureCapability!==undefined){
      const boundary=require('../../secureshopCustomerDisclosureAuthority').disclosureFor(disclosureCapability,
        {sessionId,role:opts.role||'customer',callerId:opts.callerId});
      await boundary.check();
      const protectedGraph=createSupervisorGraph({store,Trace,checkToolAcl,
        buildBasePrompt:boundary.buildBasePrompt,buildPolicyBlock:boundary.buildPolicyBlock});
      return protectedGraph(sessionId,userMessage,{...opts,role:'customer',manifest:boundary.manifest,
        provider:boundary.provider(opts.provider,opts.check||boundary.check)},
        {maxSteps:MAX_STEPS,maxParallelTools:MAX_PARALLEL_TOOLS});
    }
    return runGraph(sessionId,userMessage,{...opts,role:opts.role||'customer'},
      {maxSteps:MAX_STEPS,maxParallelTools:MAX_PARALLEL_TOOLS});
  }});
}
const customerSupervisor=createCustomerSupervisor({store:require('../sessionStore.js'),
  Trace:require('../trace.js').Trace,checkToolAcl:require('../toolAcl.js').checkToolAcl});
module.exports = { customerSupervisor, createCustomerSupervisor, MAX_STEPS, MAX_PARALLEL_TOOLS };
