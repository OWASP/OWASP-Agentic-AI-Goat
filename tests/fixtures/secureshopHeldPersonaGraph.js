'use strict';
const {randomUUID}=require('node:crypto');
const {createBoundAgentRunner}=require('../../server/services/secureshopBoundAgentRunner');
// Actual bound runner/LangGraph with explicitly controlled provider and memory
// turn/conversation journal. Persona authority/effect transaction may be native.
function startHeldPersonaGraph({scope,persona,fence,onEffect=async()=>{}}){
 let release,entered;const gate=new Promise(r=>{release=r;}),ready=new Promise(r=>{entered=r;});let effectCalls=0;
 const messages=[],sessionId=randomUUID(),requestId=randomUUID();
 const runner=createBoundAgentRunner({
  turns:{run:async(_id,_binding,_persona,_options,work)=>work({check:async()=>{},effect:async(_key,callback)=>callback(),identity:{runId:randomUUID(),ownerKey:'controlled-native',durableGeneration:'1'}})},
  conversations:{assertOwned:async()=>{},getMessages:async()=>messages},
  repository:{appendMessage:async(_id,_binding,row)=>messages.push(row),getTokens:async()=>0,addTokens:async()=>{},appendTraces:async()=>{}},
  journal:{claim:async()=>({status:'claimed',claimId:requestId}),complete:async()=>{},markUncertain:async()=>{}},
  buildBasePrompt:()=> 'Controlled decision gate',buildPolicyBlock:async()=>'',checkToolAcl:async()=>({action:'dispatch',policyViolation:null}),
  provider:{chat:async()=>{entered();await gate;return{stop_reason:'tool_use',tool_uses:[{id:'owned-1',name:'owned.mutate',args:{}}]};}},
  pool:{callTool:async()=>{throw Error('No remote fixture tools');}},
  manifest:{getForRole:()=>[{name:'owned.mutate',description:'owned local fixture effect',input_schema:{type:'object'}}]},
  createLocalTools:async()=>({'owned.mutate':async(args,{client,authority})=>{effectCalls++;return onEffect(client,authority,args);}}),
  capturePersonaAuthority:async()=>fence,personaLocalToolModes:{'owned.mutate':'local_transaction'},limits:{maxSteps:1,maxParallelTools:1}
 });
 const running=runner.run({scope,persona,sessionId,requestId,message:'Controlled held decision'});
 // Attach handler immediately; caller still observes rejection through running.
 running.catch(()=>{});
 return{ready,release,running,effectCalls:()=>effectCalls};
}
module.exports={startHeldPersonaGraph};
