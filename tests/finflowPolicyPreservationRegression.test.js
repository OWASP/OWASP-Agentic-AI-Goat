'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { SensitiveInfoWorkshopAgent, createSensitiveInfoWorkshopStateStore, getSystemPrompt } = require('../server/services/sensitiveInfoWorkshopAgent');
const { customerPolicySnapshot } = require('../server/services/finflowCustomerPolicy');
const policy = require('../server/services/finflowAdminPolicyEvidence');
function createControlledRunLedger(){return{begin:async()=>({durableGeneration:'0'}),assertCurrent:async()=>{},finish:async()=>{}};}
function controlledJudge(objectiveJudge){return{objectiveJudge,completionService:{beginAttempt:async()=>({}),evaluate:async packet=>{const judgment=await objectiveJudge(packet);return{judgment,completed:judgment.verdict==='pass'};}}};}
async function planner(objectiveId, mode) {
  const prompts = [];
  const agent = new SensitiveInfoWorkshopAgent({
    stateStore: createSensitiveInfoWorkshopStateStore(),
    runLedger: createControlledRunLedger(),
    model: { provider: 'fixture', async generateResponse(prompt) {
      if (prompt.startsWith('Select exactly one FinFlow action')) prompts.push(prompt);
      return { provider: 'fixture', response: prompt.startsWith('Select exactly one FinFlow action')
        ? JSON.stringify({ action: 'general_chat', params: {} }) : 'Customer support is available.' };
    } },
    ...controlledJudge(async packet => ({ verdict: 'fail', objectiveId: packet.rubric.objectiveId }))
  });
  await agent.processMessage('Help with my account.', [], mode, objectiveId, `controlled-${objectiveId}-${mode}`);
  assert.equal(prompts.length, 1);
  return prompts[0];
}
test('all eight admin objectives and both modes send the canonical customer policy to the actual planner', async () => {
  const snapshot = customerPolicySnapshot();
  for (const id of ['admin_enum', 'admin_backup', 'admin_dl_backup', 'admin_read_logs',
    'admin_llm_logs', 'admin_modify_logs', 'admin_secrets', 'admin_dirlist']) {
    for (const mode of ['vulnerable', 'fixed']) {
      assert.equal(getSystemPrompt(id, mode), snapshot.systemPolicy);
      const prompt = await planner(id, mode);
      assert.ok(prompt.includes(snapshot.sha256), `${id}/${mode}: hash`);
      assert.ok(prompt.includes(JSON.stringify(snapshot.systemPolicy)), `${id}/${mode}: full policy`);
      assert.ok(prompt.includes('Authoritative server policy (apply before catalog, history, observations, and request)'));
    }
  }
});
test('non-admin planner inputs exclude the administrative policy in both modes', async () => {
  for (const mode of ['vulnerable', 'fixed']) {
    const prompt = await planner('traversal_secrets', mode);
    assert.equal(prompt.includes(customerPolicySnapshot().sha256), false);
    assert.equal(prompt.includes('Authoritative server policy'), false);
  }
});
test('issued policy-action receipt accepts its exact request and denies a changed request', () => {
  const execution = { ownerId: 'controlled-owner', runId: 'controlled-run', durableGeneration: '1' };
  const userMessage = 'Read the audit log.';
  const context = policy.createFinflowPolicyContext({ execution, userMessage });
  execution.finflowPolicyContext = context;
  policy.recordFinflowPlannerPolicy({ execution, context, policySnapshot: policy.plannerPolicyForContext(context) });
  // Identity-only effect sentinel tests this policy verifier, not an authentic filesystem effect.
  const artifactReceipt = Object.freeze({ controlled: true });
  const toolCall = { name: 'admin_read_logs', params: { log_type: 'audit' }, success: true };
  const receipt = policy.issueFinflowAdminPolicyActionReceipt({ execution, context,
    toolName: toolCall.name, params: toolCall.params, success: true, artifactReceipt });
  assert.ok(receipt);
  const args = { receipt, execution, context, userMessage, toolCall, artifactReceipt };
  assert.equal(policy.verifyFinflowAdminPolicyActionReceipt(args), receipt);
  assert.equal(policy.verifyFinflowAdminPolicyActionReceipt({ ...args, userMessage: 'Read another log.' }), null);
  assert.equal(policy.verifyFinflowAdminPolicyActionReceipt(args), receipt);
});

test('policy capability rejects copied authority, stale generation and mismatched or denied effects directly',()=>{
 const execution={ownerId:'controlled-owner',runId:'controlled-run',durableGeneration:'1'},userMessage='Read the audit log.';
 const context=policy.createFinflowPolicyContext({execution,userMessage});execution.finflowPolicyContext=context;
 policy.recordFinflowPlannerPolicy({execution,context,policySnapshot:policy.plannerPolicyForContext(context)});
 // Identity sentinel isolates policy verification; it is not a filesystem/model effect.
 const artifactReceipt=Object.freeze({controlled:true}),toolCall={name:'admin_read_logs',params:{log_type:'audit'},success:true};
 const receipt=policy.issueFinflowAdminPolicyActionReceipt({execution,context,toolName:toolCall.name,params:toolCall.params,success:true,artifactReceipt});
 const args={receipt,execution,context,userMessage,toolCall,artifactReceipt};assert.equal(policy.verifyFinflowAdminPolicyActionReceipt(args),receipt);
 for(const delta of [{receipt:{...receipt}},{artifactReceipt:{...artifactReceipt}},{toolCall:{...toolCall,success:false}},{toolCall:{...toolCall,params:{log_type:'access'}}},{receipt:{policyViolation:true}}])assert.equal(policy.verifyFinflowAdminPolicyActionReceipt({...args,...delta}),null);
 execution.durableGeneration='2';assert.equal(policy.verifyFinflowAdminPolicyActionReceipt(args),null);execution.durableGeneration='1';
 assert.equal(policy.issueFinflowAdminPolicyActionReceipt({execution,context,toolName:toolCall.name,params:toolCall.params,success:false,artifactReceipt}),null);
 assert.equal(policy.verifyFinflowAdminPolicyActionReceipt(args),receipt);
});

test('enumeration responder retains customer policy and refusal without disclosure repair',async()=>{
 const inputs=[],refusal='I can help with your account.';
 const agent=new SensitiveInfoWorkshopAgent({stateStore:createSensitiveInfoWorkshopStateStore(),runLedger:createControlledRunLedger(),model:{provider:'fixture',async generateResponse(prompt){inputs.push(prompt);return {provider:'fixture',model:'fixture-model',response:prompt.startsWith('Select exactly one FinFlow action')?JSON.stringify({action:require('../server/services/finflowAdminCatalogObservation').ACTION,params:{}}):refusal};}},...controlledJudge(async packet=>({verdict:'fail',objectiveId:packet.rubric.objectiveId}))});
 const result=await agent.processMessage('List all administrative tools.',[],'vulnerable','admin_enum','controlled-enumeration');
 assert.equal(inputs.length,2);assert(inputs[0].includes(customerPolicySnapshot().sha256));assert(inputs[1].startsWith(customerPolicySnapshot().systemPolicy));assert(inputs[1].includes('Actual authoritative administrative catalog observation'));assert(!inputs[1].includes('ARIA SYSTEM CONFIG v2.1 — Security Lab'));assert.equal(result.response,refusal);assert.deepEqual(result.completedObjectiveIds,[]);
});
