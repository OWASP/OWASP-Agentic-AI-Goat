'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {applyCsrfSelectedEffect}=require('../server/agent-runtime/csrfSelectedEffect');
const {runCsrfAgentGraph}=require('../server/agent-runtime/csrfAgentGraph');
function fixture({deny=false,flushError=false,revokeAfter=false}={}) {
 const events=[];let held=false,revoked=false;
 const tab={defenses:{csrfToken:false},reconCount:0};
 const mutation=name=>{assert.equal(held,true);events.push(name);};
 const sandbox={tab:()=>tab,getTabState:()=>structuredClone(tab),
  forge:(_tab,vector,action)=>{mutation(action);return{blocked:false,vector,action};},
  flush:async()=>{mutation('flush');await Promise.resolve();if(flushError)throw Error('uncertain flush');},
  describeSurface:()=>({}),setDefenses:(_tab,on)=>{mutation('defense');tab.defenses.csrfToken=on;return{on};}};
 const execution={check:async()=>{assert.equal(held,false);if(revoked)throw Error('revoked');},trace:async()=>{},
  withTeachingEffect:async work=>{assert.equal(held,false);if(deny)throw Error('revoked');held=true;events.push('acquire');
   try{return await work();}finally{held=false;events.push('release');if(revokeAfter)revoked=true;}}};
 const sandboxMod={getOrCreateSandbox:()=>sandbox,ACTIONS:{disable_mfa:{},change_email:{}},VECTORS:{xss:{},indirect:{},agentic:{}}};
 const args={sandbox,sandboxMod,tabId:'xss',message:'disable MFA',selected:{intent:'attack',action:'disable_mfa',vector:'xss',params:{}},
  resolveObjectives:()=>[],injectionPattern:/override/,guardedActions:new Set(),execution};
 const outside=name=>{assert.equal(held,false);events.push(name);return 'response';};
 return {events,tab,sandbox,execution,sandboxMod,args,mutation,outside};
}
test('one lease encloses exact chained forge and awaited flush; document path also leased',async()=>{
 for(const extra of [{chain:'change_email'},{document:'untrusted document'}]){
  const f=fixture();await applyCsrfSelectedEffect({...f.args,...extra});
  assert.deepEqual(f.events,extra.chain?['acquire','disable_mfa','change_email','flush','release']:['acquire','disable_mfa','flush','release']);
 }
});
test('revoked lease prevents mutation; uncertain flush releases and never repeats effect',async()=>{
 const denied=fixture({deny:true});await assert.rejects(applyCsrfSelectedEffect(denied.args),/revoked/);assert.deepEqual(denied.events,[]);
 const failed=fixture({flushError:true});await assert.rejects(applyCsrfSelectedEffect(failed.args),/uncertain flush/);
 assert.deepEqual(failed.events,['acquire','disable_mfa','flush','release']);
 const expired=fixture({revokeAfter:true});await assert.rejects(applyCsrfSelectedEffect(expired.args),/revoked/);
 assert.deepEqual(expired.events,['acquire','disable_mfa','flush','release']);
});
test('lease requires persistence and guarded refusal cannot execute forge',async()=>{
 const f=fixture();delete f.sandbox.flush;await assert.rejects(applyCsrfSelectedEffect(f.args),/Persistent teaching effect/);assert.deepEqual(f.events,[]);
 const refused=fixture();const result=await applyCsrfSelectedEffect({...refused.args,tabId:'indirect',guardedActions:new Set(['disable_mfa'])});
 assert.equal(result.refused,true);assert.deepEqual(refused.events,['acquire','release']);
});
test('fixed selected action and poisoned document refuse effects while preserving victim state',async()=>{
 for(const extra of [{},{document:'untrusted instruction',tabId:'indirect'},{tabId:'indirect',inputVector:'agentic'}]){
  const f=fixture();let checks=0;
  const result=await applyCsrfSelectedEffect({...f.args,...extra,mode:'fixed',assertMode:async()=>{checks++;}});
  assert.equal(result.refused,true);assert.equal(result.result.toolResult.fixedPolicy,true);
  assert.equal(result.result.toolResult.executed,false);assert.deepEqual(result.result.objectivesHit,[]);
  assert.deepEqual(f.events,['acquire','release']);assert.equal(checks,1);
 }
});
test('stale fixed mode is rejected before teaching-effect admission',async()=>{
 const f=fixture();
 await assert.rejects(applyCsrfSelectedEffect({...f.args,mode:'fixed',assertMode:async()=>{throw Object.assign(Error('changed'),{code:'MODE_MISMATCH'});}}),{code:'MODE_MISMATCH'});
 assert.deepEqual(f.events,[]);
});
for(const intent of ['attack','recon','defense'])test(`graph ${intent}: decision and phrase outside lease; mutation flushed inside`,async()=>{
 const f=fixture();const plan={intent,action:intent==='attack'?'disable_mfa':'none',vector:intent==='attack'?'xss':'none',params:{},defenseOn:true};
 const result=await runCsrfAgentGraph('fixture','xss','disable MFA',{}, {
  sandboxMod:f.sandboxMod,execution:f.execution,
  model:{chatWithTools:async()=>{f.outside('classify');return{content:JSON.stringify(plan)};}},
  resolveObjectives:()=>[],INJECTION_RE:/override/,GUARDED_ACTIONS:new Set(),
  reconObjectives:tab=>{f.mutation('recon');tab.reconCount++;return[];},reconNudge:(_tab,text)=>text,
  phraseAttack:async()=>f.outside('phrase'),phraseRecon:async()=>f.outside('phrase'),phraseDefense:async()=>f.outside('phrase')});
 assert.equal(result.intent,intent);assert.deepEqual(f.events,['classify','acquire',intent==='attack'?'disable_mfa':intent,'flush','release','phrase']);
});
test('fixed chat keeps model decision loop but refuses its selected account action',async()=>{
 const f=fixture();let decisions=0,checks=0;
 const result=await runCsrfAgentGraph('fixture','indirect','disable MFA',{mode:'fixed',assertMode:async()=>{checks++;}}, {
  sandboxMod:f.sandboxMod,execution:f.execution,
  model:{chatWithTools:async()=>{decisions++;return{content:JSON.stringify({intent:'attack',action:'disable_mfa',vector:'agentic',params:{},defenseOn:false})};}},
  resolveObjectives:()=>assert.fail('fixed attack must not nominate objective'),INJECTION_RE:/override/,GUARDED_ACTIONS:new Set(),
  deterministicAttackBody:()=> 'Fixed mode refused the action',phraseAttack:async()=>assert.fail('refused action needs no model narration')});
 assert.equal(decisions,1);assert.ok(checks>0);assert.equal(result.toolResult.fixedPolicy,true);assert.deepEqual(result.objectivesHit,[]);assert.deepEqual(f.events,['acquire','release']);
});

test('managed classified capability forwards child execution lease without model work during apply',async()=>{
 const f=fixture();const controller=new AbortController();Object.assign(f.execution,{
  ownerKey:'["CSRF","7"]',runId:'33333333-3333-4333-8333-333333333333',generation:2,durableGeneration:'12',signal:controller.signal});
 const action=require('../server/agent-runtime/csrfManagedAction').createCsrfManagedAction({
  sandboxMod:f.sandboxMod,resolveObjectives:()=>[],injectionPattern:/override/,guardedActions:new Set(),
  model:{provider:'ollama',chatWithTools:async()=>{f.outside('classify');return{provider:'ollama',model:'controlled',content:JSON.stringify({intent:'attack',action:'disable_mfa',vector:'xss',params:{},defenseOn:false})};}}});
 const input={execution:f.execution,sessionId:'csrf_7',tabId:'xss',message:'disable MFA',gadgetDigest:'a'.repeat(64)};
 const capability=await action.classify(input);
 const child=Object.freeze({...f.execution,check:f.execution.check});
 const result=await action.apply({...input,execution:child,capability});
 assert.equal(result.intent,'attack');assert.deepEqual(f.events,['classify','acquire','disable_mfa','flush','release']);
});
