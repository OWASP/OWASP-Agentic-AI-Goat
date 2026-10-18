'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createOwnedAuditDecisionGraph,witnessFor}=require('../server/services/secureshopOwnedAuditDecisionGraph');
const raw="' UNION ALL SELECT synthetic --";
function fixture(){const runId=randomUUID(),traces=[];let queries=0;const selected={provider:'mock',model:'controlled',mocked:true,tool_uses:[{id:'selected',name:'audit.search_by_user',args:{username:raw}}]};return{runId,traces,selected,get queries(){return queries;},graph:createOwnedAuditDecisionGraph({provider:{chat:async()=>selected,finalResponse:async()=>({text:'Observed policy outcome',provider:'mock',model:'controlled',mocked:true})}}),input:{message:'Fixed synthetic query',boundary:{identity:{runId},check:async()=>{},effect:async(_key,work)=>work(),trace:async item=>traces.push(item)},query:async value=>{queries++;assert.equal(value,raw);return{rows:[]};}}};}
function receipt(f,context,enforcement=false){return{admissionId:randomUUID(),runId:f.runId,invocationId:`${context.step}:${context.callId}`,toolKey:'audit.search_by_user',policyVersion:'2',registrySha256:'a'.repeat(64),enforcement,allowed:false,action:enforcement?'block':'dispatch',policyViolation:'denied-by-acl'};}
test('advisory preserves exact snapshotted arguments; enforced and fixed modes never query or mint witness',async()=>{
 for(const mode of ['advisory','enforced','fixed']){const f=fixture();let calls=0;const result=await f.graph.run({...f.input,mode:mode==='fixed'?'fixed':'vuln',toolPolicyAdmission:async context=>{calls++;assert.ok(Object.isFrozen(context.args));assert.equal(context.args.username,raw);f.selected.tool_uses[0].args.username='mutated during await';return receipt(f,context,mode==='enforced');}});assert.equal(calls,mode==='fixed'?0:1);assert.equal(f.queries,mode==='advisory'?1:0);assert.equal(f.traces.length,mode==='fixed'?0:1);if(f.traces.length){assert.equal(f.traces[0].type,'decision');assert.deepEqual(require('../server/agent-runtime/runTraceStore').traceData(f.traces[0].data),f.traces[0].data);}assert.equal(witnessFor(result),null);}
});
test('malformed or foreign policy receipt denies before query',async()=>{
 for(const patch of [{runId:randomUUID()},{toolKey:'audit.other'},{invocationId:'1:other'},{policyVersion:'0'},{extra:'forged'}]){const f=fixture();await assert.rejects(f.graph.run({...f.input,toolPolicyAdmission:async c=>({...receipt(f,c),...patch})}),{code:'SECURESHOP_INVALID_POLICY_ADMISSION'});assert.equal(f.queries,0);}
});
test('authority loss after admission denies dispatch and trace publication',async()=>{const f=fixture();let revoked=false;f.input.boundary.check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};await assert.rejects(f.graph.run({...f.input,toolPolicyAdmission:async c=>{revoked=true;return receipt(f,c);}}),{code:'SHOP_AUTH_INVALID'});assert.equal(f.queries,0);assert.equal(f.traces.length,0);});
test('application policy callback receives captured original credential and canonical run, never caller replacements',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},session={sessionId:randomUUID(),authorityVersion:'2'},runId=randomUUID();
 const originalSession={...session};let received;
 const fence={binding:Object.freeze({...scope,personaId:9,role:'admin',...session}),assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>work({})};
 const {createOwnedAuditSearchApplication}=require('../server/services/secureshopOwnedAuditSearchApplication');
 const app=createOwnedAuditSearchApplication({launches:{assertCurrent:async()=>{}},personaAuthority:{capture:async()=>fence},
  journal:{claim:async()=>({status:'claimed',claimId:randomUUID()}),complete:async()=>{},completeWithClient:async()=>{},markUncertain:async()=>{}},
  turns:{run:async(_id,_binding,_persona,options,work)=>{await options.admit();session.sessionId=randomUUID();session.authorityVersion='99';return work({identity:{runId},check:async()=>{},effect:async(_key,fn)=>fn()});}},
  beginAssessment:async()=>({mode:'vuln',consume:async()=>({passed:false})}),
  decisionGraph:{run:async({toolPolicyAdmission})=>{await toolPolicyAdmission(Object.freeze({step:1,callId:'selected',args:Object.freeze({username:raw})}));return{text:'controlled blocked'};}},
  toolPolicyAdmission:async input=>{received=input;return{};}});
 await app.runAgent({scope,persona:{id:9,role:'admin'},personaSession:session,sessionId:randomUUID(),requestId:randomUUID(),message:'controlled'});
 assert.deepEqual(received.personaSession,originalSession);assert.deepEqual(received.scope,scope);assert.equal(received.runId,runId);assert.equal(received.invocationId,'1:selected');assert.deepEqual(received.persona,{id:9,role:'admin'});assert.deepEqual(received.args,{username:raw});
});
test('policy transition during held model selection is read at dispatch',async()=>{
 const f=fixture(),entered=Promise.withResolvers(),release=Promise.withResolvers();let enforced=false;
 const graph=createOwnedAuditDecisionGraph({provider:{chat:async()=>{entered.resolve();await release.promise;return f.selected;},finalResponse:async()=>({text:'blocked',mocked:true})}});
 const pending=graph.run({...f.input,toolPolicyAdmission:async c=>receipt(f,c,enforced)});
 await entered.promise;enforced=true;release.resolve();await pending;assert.equal(f.queries,0);assert.equal(f.traces[0].data.policyAdmission.action,'block');
});
