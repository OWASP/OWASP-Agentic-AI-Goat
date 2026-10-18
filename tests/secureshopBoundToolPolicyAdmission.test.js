'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundToolPolicyAdmission } = require('../server/services/secureshopBoundToolPolicyAdmission');
const { REGISTRY_SHA256 } = require('../server/services/secureshopBoundAclRegistry');
const input = () => ({ scope: { launchId: 'owned' }, persona: { id: 7, role: 'admin' },
  personaSession: { sessionId: 'original', authorityVersion: '2' }, runId: 'run', invocationId: '1:call',
  agent: 'audit', tool: 'search_by_user', args: { username: "%' OR true --" } });
const receipt = value => ({ runId: value.runId, invocationId: value.invocationId,
  toolKey: 'audit.search_by_user', registrySha256: REGISTRY_SHA256 });
test('server declaration and exact arguments survive caller mutation and forged metadata', async () => {
  let observed;
  const declaredTools = [{ agent: 'audit', tool: 'search_by_user' }];
  const admit = createBoundToolPolicyAdmission({ workflow: 'audit-query', declaredTools,
    repository: { async admitTool(value) { await Promise.resolve(); observed = value; return receipt(value); } } });
  declaredTools[0].tool = 'other';
  const request = { ...input(), workflow: 'review', declaredTools: [], admittedMcp: { forged: true } };
  const pending = admit(request);
  request.args.username = 'changed'; request.personaSession.sessionId = 'changed';
  const result = await pending;
  assert.equal(observed.workflow, 'audit-query');
  assert.equal(observed.declaredTools[0].tool, 'search_by_user');
  assert.equal(observed.admittedMcp, undefined);
  assert.equal(observed.args.username, "%' OR true --");
  assert.equal(observed.personaSession.sessionId, 'original');
  assert.ok(Object.isFrozen(result));
});
test('unknown tools and inapplicable roles never reach repository', async () => {
  let calls = 0;
  const admit = createBoundToolPolicyAdmission({ workflow: 'audit-query',
    declaredTools: [{ agent: 'audit', tool: 'search_by_user' }],
    repository: { async admitTool() { calls++; } } });
  await assert.rejects(admit({ ...input(), tool: 'other' }), { code: 'ACL_TOOL_UNAVAILABLE' });
  await assert.rejects(admit({ ...input(), persona: { id: 7, role: 'customer' } }), { code: 'ACL_TOOL_UNAVAILABLE' });
  assert.equal(calls, 0);
});
test('foreign run, invocation, tool or registry receipt fails closed', async () => {
  for (const key of ['runId', 'invocationId', 'toolKey', 'registrySha256']) {
    const admit = createBoundToolPolicyAdmission({ workflow: 'audit-query',
      declaredTools: [{ agent: 'audit', tool: 'search_by_user' }],
      repository: { async admitTool(value) { return { ...receipt(value), [key]: 'foreign' }; } } });
    await assert.rejects(admit(input()), { code: 'SECURESHOP_INVALID_POLICY_ADMISSION' });
  }
});

test('listing policy admits only exact declared fetch/publish tools for the merchant',async()=>{
 const seen=[];const admit=createBoundToolPolicyAdmission({workflow:'listing-import',declaredTools:[{agent:'listing',tool:'fetch_parse'},{agent:'listing',tool:'publish'}],repository:{async admitTool(x){seen.push(x);return{runId:x.runId,invocationId:x.invocationId,toolKey:`${x.agent}.${x.tool}`,registrySha256:REGISTRY_SHA256,allowed:true,action:'dispatch'};}}});
 for(const tool of ['fetch_parse','publish'])assert.equal((await admit({...input(),persona:{id:7,role:'merchant'},agent:'listing',tool,args:{}})).allowed,true);
 await assert.rejects(admit({...input(),persona:{id:7,role:'customer'},agent:'listing',tool:'publish',args:{}}),{code:'ACL_TOOL_UNAVAILABLE'});
 await assert.rejects(admit({...input(),persona:{id:7,role:'merchant'},agent:'listing',tool:'create',args:{}}),{code:'ACL_TOOL_UNAVAILABLE'});
 assert.equal(seen.length,2);
});

test('administrator lookup alias uses actual admission and cannot substitute safe search or another role',async()=>{
 const R=require('../server/services/secureshopBoundAclRegistry'),declarations=R.REGISTRY.filter(row=>row.workflow==='admin-assistant').map(row=>{const [agent,tool]=row.toolKey.split('.');return{agent,tool};}),seen=[];
 const admit=createBoundToolPolicyAdmission({workflow:'admin-assistant',declaredTools:declarations,repository:{async admitTool(value){seen.push(value);return{runId:value.runId,invocationId:value.invocationId,toolKey:'admin.'+value.tool,registrySha256:R.REGISTRY_SHA256,allowed:true,action:'dispatch'};}}});
 const request={...input(),agent:'admin',tool:'user_lookup',args:{username:'student_admin'}};
 assert.equal((await admit(request)).allowed,true);assert.equal(seen[0].args.username,'student_admin');assert.equal(seen[0].workflow,'admin-assistant');
 for(const role of ['merchant','customer'])await assert.rejects(admit({...request,persona:{...request.persona,role}}),{code:'ACL_TOOL_UNAVAILABLE'});
 await assert.rejects(admit({...request,agent:'user-management',tool:'lookup'}),{code:'ACL_TOOL_UNAVAILABLE'});
 assert.equal(seen.length,1);assert.equal((await admit({...request,tool:'users_search',args:{search:'student_admin'}})).allowed,true);
});
