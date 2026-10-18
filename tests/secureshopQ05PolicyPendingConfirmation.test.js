'use strict';
// Controlled original role graph proposals. No actual model, renderer or credit.
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {fixture,launch,session}=require('./secureshopBoundRoleChat.test');

async function prepared(action){
 const f=fixture('admin',{enablePolicyChat:true,jsonbResults:true});
 const conversation=await f.runtime.createSession(launch,f.actor,session);
 const base={scope:launch,persona:f.actor,personaSession:session,sessionId:conversation.id,stream:{send(){}}};
 const listId=randomUUID();f.decide('admin.policies_search',{});
 await f.runtime.run({...base,requestId:listId,message:'Find Shipping policy'});
 const page=await f.runtime.readRequest(launch,f.actor,session,conversation.id,listId);
 const choiceId=page.cards[0].choiceId,requestId=randomUUID(),markdown='# Reviewed Shipping candidate';
 f.decide(`admin.policy_${action}_prepare`,{choiceId,patch:{markdown}});
 const before=structuredClone(f.policyState);
 await f.runtime.run({...base,requestId,message:`${action==='edit'?'Change':'Preview'} Shipping with exact markdown ${markdown}`,
  selection:{choiceId,intent:`policy_${action}`}});
 const saved=await f.runtime.readRequest(launch,f.actor,session,conversation.id,requestId);
 assert.equal(saved.policyProposal.action,action);
 assert.equal(saved.policyProposal.after.markdown,markdown);
 assert.equal(saved.policyProposal.before.markdown,'# Shipping');
 assert.equal(f.policyCallsObserved.confirms,0);
 assert.deepEqual(f.policyState,before,'successful prepare must not mutate the policy head or candidate');
 return{f,base,requestId,saved,before};
}
for(const action of ['edit','preview'])for(const transition of ['grant','scene-generation']){
 test(`Q05 pending policy ${action} rejects actual ${transition} change before adapter admission`,async()=>{
  const {f,base,requestId,saved,before}=await prepared(action);
  const original=f.savedTurn(requestId),modelBefore=[f.modelCalls,f.finalCalls];
  if(transition==='grant')f.rotateGrant();else f.advanceSceneGeneration();
  await assert.rejects(f.runtime.confirmPolicy({...base,requestId,proposalId:saved.policyProposal.proposalId}),
   error=>['ROLE_PROPOSAL_STALE','ROLE_TURN_STALE','SHOP_SCENE_STALE'].includes(error.code));
  assert.equal(f.policyCallsObserved.confirms,0,'neither renderer nor mutation adapter may be entered');
  assert.deepEqual(f.policyState,before);
  assert.deepEqual(f.savedTurn(requestId),original,'the original saved proposal is not rewritten to the new grant');
  assert.deepEqual([f.modelCalls,f.finalCalls],modelBefore);
 });
}
