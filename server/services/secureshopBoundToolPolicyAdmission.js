'use strict';

const { createBoundAclResolver } = require('./secureshopBoundAclRegistry');

// Construct only in server composition. Model arguments never select a workflow
// or replace the declaration captured by this closure.
function createBoundToolPolicyAdmission({ repository, workflow, declaredTools, admittedMcp } = {}) {
  if (typeof repository?.admitTool !== 'function') throw new TypeError('Policy repository required');
  const declaration = structuredClone({ workflow, declaredTools, admittedMcp });
  const resolver = createBoundAclResolver(declaration);
  return async function admit(input) {
    const captured = structuredClone(input);
    const tool = resolver.resolve(captured.agent, captured.tool);
    if (!tool || !resolver.isRoleApplicable(captured.persona?.role)) {
      throw Object.assign(new Error('Policy tool unavailable'), { code: 'ACL_TOOL_UNAVAILABLE' });
    }
    const receipt = await repository.admitTool({
      scope: captured.scope, persona: captured.persona, personaSession: captured.personaSession,
      runId: captured.runId, invocationId: captured.invocationId,
      agent: captured.agent, tool: captured.tool, args: captured.args,
      ...structuredClone(declaration),
    });
    if (!receipt || receipt.runId !== captured.runId || receipt.invocationId !== captured.invocationId
      || receipt.toolKey !== tool.toolKey || receipt.registrySha256 !== resolver.registrySha256) {
      throw Object.assign(new Error('Policy receipt binding mismatch'), { code: 'SECURESHOP_INVALID_POLICY_ADMISSION' });
    }
    return Object.freeze(structuredClone(receipt));
  };
}

module.exports = { createBoundToolPolicyAdmission };
