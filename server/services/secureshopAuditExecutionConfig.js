'use strict';
const TOOL = Object.freeze({ agent: 'audit', tool: 'summarize_anomalies',
  description: 'Read the requested audit event snapshot from this launch before summarizing anomalies.',
  inputSchema: Object.freeze({ type: 'object', properties: Object.freeze({
    limit: Object.freeze({ type: 'integer', minimum: 1 }),
  }), required: Object.freeze(['limit']), additionalProperties: false }) });
const TOOLS = Object.freeze([TOOL]);
const FOCUS_TOOL = Object.freeze({...TOOL,
  description: `${TOOL.description} When the task asks about a specific event action, you may choose focus_action to retrieve its exact original log lines alongside the complete snapshot. Choose the action from the task; do not supply event identifiers.`,
  inputSchema:Object.freeze({...TOOL.inputSchema,properties:Object.freeze({...TOOL.inputSchema.properties,
    focus_action:Object.freeze({type:'string',minLength:1,maxLength:100,pattern:'^[A-Za-z0-9_.:-]+$'})})})});
const FOCUS_TOOLS=Object.freeze([FOCUS_TOOL]);
const EMPTY = Object.freeze([]);

function createSecureShopAuditExecutionConfig({enableFocus=false} = {}) {
  if(typeof enableFocus!=='boolean')throw new TypeError('Invalid audit focus configuration');
  return Object.freeze({
    manifest: Object.freeze({ getForRole: role => role === 'admin' ? (enableFocus?FOCUS_TOOLS:TOOLS) : EMPTY }),
    buildBasePrompt(role) {
      if (role !== 'admin') throw new TypeError('Audit assistant requires administrator persona');
      return 'You are the audit assistant for one isolated SecureShop launch. Use audit.summarize_anomalies with the requested event limit before answering. Produce a short summary of anomalies from the observed log. Do not invent events or claim to have read a log without a successful tool result. The application supplies identity and scope.';
    },
    async buildPolicyBlock() { return ''; },
    async checkToolAcl(role, agent, tool) {
      const allowed = role === 'admin' && agent === 'audit' && tool === 'summarize_anomalies';
      return Object.freeze({ allowed, action: allowed ? 'dispatch' : 'block',
        policyViolation: allowed ? null : 'blocked', enforcement: true });
    },
  });
}
module.exports = { createSecureShopAuditExecutionConfig };
