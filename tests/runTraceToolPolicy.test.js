'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const traces=require('../server/agent-runtime/runTraceStore');
const receipt=()=>({admissionId:randomUUID(),runId:randomUUID(),invocationId:'1:selected-call',toolKey:'audit.search_by_user',policyVersion:'3',registrySha256:'b'.repeat(64),enforcement:true,allowed:false,action:'block',policyViolation:'denied-by-acl'});
test('policy metadata survives coordinator and ledger repeated projection without credentials or args',()=>{
 const r=receipt(),data={tool:r.toolKey,policyAdmission:r,args:{username:'sensitive'},personaSession:{sessionId:'private'},token:'private'};
 const projected=traces.traceData(data);assert.deepEqual(projected,{tool:r.toolKey,policyAdmission:r});assert.deepEqual(traces.traceData(projected),projected);
 const context={runId:r.runId,ownerKey:'owned',generation:0};traces.begin(context);traces.append(context,{node:'owned_audit_tool_policy',type:'decision',data:projected});const run=traces.getRun(context.runId,context.ownerKey);assert.equal(run.events[0].type,'decision');assert.deepEqual(run.events[0].data,projected);r.action='dispatch';assert.equal(run.events[0].data.policyAdmission.action,'block');
});
test('unknown nested fields, malformed IDs, oversized policy versions and contradictory outcomes are omitted',()=>{
 for(const patch of [{args:{}},{token:'private'},{runId:'foreign'},{invocationId:'raw payload'},{toolKey:'audit.secret/value'},{policyVersion:'0'},{policyVersion:'9223372036854775808'},{registrySha256:'invalid'},{action:'dispatch'},{allowed:'true'},{enforcement:'false'},{policyViolation:null}])assert.deepEqual(traces.traceData({policyAdmission:{...receipt(),...patch}}),{});
});
test('legacy trace metadata is unchanged when no policy receipt is supplied',()=>{assert.deepEqual(traces.traceData({provider:'mock',model:'controlled',tool:'audit.search_by_user',args:'private'}),{provider:'mock',model:'controlled',tool:'audit.search_by_user'});});
