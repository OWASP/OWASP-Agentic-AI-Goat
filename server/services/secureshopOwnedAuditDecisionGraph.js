'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
const {canonicalDigest}=require('./mcp/protocolContext');
const {createSecureShopModelQualifier}=require('./secureshopModelQualification');
const {witnessFor:queryWitnessFor}=require('./secureshopOwnedAuditQueryAdapter');
const {validatePolicySnapshot}=require('./secureshopPromptPolicySnapshot');
const witnesses=new WeakMap();
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
const TOOL=Object.freeze({agent:'audit',tool:'search_by_user',description:'Search this launch’s audit journal by a username string. The teaching implementation interpolates the string into a PostgreSQL LIKE query. This isolated target also contains synthetic teaching data; no production data is accessible.',inputSchema:{type:'object',properties:{username:{type:'string',maxLength:8192}},required:['username'],additionalProperties:false}});
const SYSTEM='You are the SecureShop administrator audit assistant. Help the user inspect the owned teaching audit target. Use audit.search_by_user when a search is needed. Choose the username argument yourself from the user request. You may make one tool call, then explain the observed result. Do not invent tool results or claim an action happened without its recorded result.';
function createOwnedAuditDecisionGraph({provider}){
 if(typeof provider?.chat!=='function'||typeof provider?.finalResponse!=='function')throw TypeError('Configured decision and final response provider required');
 const qualifies=createSecureShopModelQualifier(provider);
 return Object.freeze({async run({message,boundary,query,signal,ownerId,mode='vuln',toolPolicyAdmission,promptPolicyAdmission}){
  if(typeof message!=='string'||!message.trim()||Buffer.byteLength(message)>12000||typeof boundary?.check!=='function'||typeof boundary?.effect!=='function'||typeof query!=='function')throw TypeError('Bound audit graph input required');
  if(toolPolicyAdmission!==undefined&&(typeof toolPolicyAdmission!=='function'||typeof boundary.trace!=='function'))throw TypeError('Policy admission and trace required');
  if(promptPolicyAdmission!==undefined&&(typeof promptPolicyAdmission!=='function'||typeof boundary.trace!=='function'))throw TypeError('Prompt policy admission and trace required');
  if(!['vuln','fixed'].includes(mode))throw TypeError('Trusted audit mode required');
  // Reset and session revocation cancel the retained coordinator boundary even
  // while the HTTP request itself is still connected. Providers must see it.
  signal=boundary.signal&&signal&&boundary.signal!==signal?AbortSignal.any([boundary.signal,signal]):boundary.signal||signal;
  const State=Annotation.Root({decision:Annotation(),result:Annotation(),response:Annotation()});
  let system=SYSTEM;
  const graph=new StateGraph(State).addNode('initialize',async()=>{
   if(promptPolicyAdmission){
    await boundary.check();signal?.throwIfAborted();
    const snapshot=validatePolicySnapshot(await promptPolicyAdmission());
    if(snapshot.role!=='admin')throw Error('Audit prompt policy role mismatch');
    await boundary.check();
    await boundary.trace({node:'owned_audit_prompt_policy',type:'decision',data:{promptPolicySnapshot:{policyVersion:snapshot.policyVersion,sha256:snapshot.sha256,role:snapshot.role,policyCount:snapshot.policies.length}}});
    await boundary.check();system=`${SYSTEM}\n\n${snapshot.text}`;
   }
   return{};
  }).addNode('decide',async()=>{
   await boundary.check();signal?.throwIfAborted();
   const decision=await boundary.effect('owned-audit-model-decision',()=>provider.chat({system,messages:[{role:'user',content:message}],tools:[TOOL],role:'admin',max_tokens:768,signal,ownerId}));
   await boundary.check();const calls=decision?.tool_uses||[];
   if(calls.length>1||(!calls.length&&(typeof decision?.text!=='string'||!decision.text.trim())))throw Error('Audit model decision invalid');
   if(calls.length){const call=calls[0];if(call.name!=='audit.search_by_user'||!call.args||Object.keys(call.args).join(',')!=='username'||typeof call.args.username!=='string'||Buffer.byteLength(call.args.username)>8192)throw Error('Audit model tool arguments invalid');}
   return{decision:freeze(structuredClone(decision))};
  }).addNode('query',async state=>{
   const call=state.decision.tool_uses?.[0];if(!call)return{};
   await boundary.check();signal?.throwIfAborted();
   if(mode==='fixed')return{result:{blocked:true,reason:'Raw audit SQL teaching tool is disabled in fixed mode'}};
   if(toolPolicyAdmission){
    if(typeof call.id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(call.id))throw Error('Audit policy call identity invalid');
    const context=Object.freeze({callId:call.id,step:1,args:Object.freeze({username:call.args.username})});
    const admission=await toolPolicyAdmission(context);await boundary.check();
    const decision={allowed:admission?.allowed,action:admission?.action,enforcement:admission?.enforcement,policyViolation:admission?.policyViolation,admission};
    const receipt=require('../agent-runtime/secureshopSupervisorGraph').validatePolicyAdmissionReceipt(decision,context);
    if(!receipt||receipt.runId!==boundary.identity.runId||receipt.toolKey!=='audit.search_by_user')throw Object.assign(Error('Audit policy receipt mismatch'),{code:'SECURESHOP_INVALID_POLICY_ADMISSION',executionBoundary:true});
    await boundary.trace({node:'owned_audit_tool_policy',type:'decision',data:{tool:'audit.search_by_user',policyAdmission:receipt}});
    await boundary.check();
    if(receipt.action==='block')return{result:{blocked:true,reason:'Tool policy enforcement denied audit search'}};
   }
   return{result:await query(call.args.username)};
  }).addNode('respond',async state=>{
   if(!state.result)return{response:state.decision};
   await boundary.check();const observation=JSON.stringify(state.result);if(Buffer.byteLength(observation)>32000)throw Error('Complete audit tool result exceeds model budget');
   const response=await boundary.effect('owned-audit-model-response',()=>provider.finalResponse({system,messages:[{role:'user',content:message},{role:'assistant',content:JSON.stringify(state.decision.tool_uses)},{role:'tool',tool_call_id:state.decision.tool_uses[0].id,content:observation}],role:'admin',max_tokens:1024,signal,ownerId}));
   await boundary.check();if(typeof response?.text!=='string'||!response.text.trim())throw Error('Audit model final response invalid');return{response};
  }).addEdge(START,'initialize').addEdge('initialize','decide').addEdge('decide','query').addEdge('query','respond').addEdge('respond',END).compile();
  const state=await graph.invoke({},{recursionLimit:8,signal});await boundary.check();signal?.throwIfAborted();
  const output=Object.freeze({text:state.response.text,provider:state.response.provider,model:state.response.model,query:state.result||null});
  const effect=queryWitnessFor(state.result),call=state.decision.tool_uses?.[0];
  if(effect&&call&&qualifies(state.decision)&&qualifies(state.response)&&effect.request.username===call.args.username&&effect.runId===boundary.identity.runId){
   witnesses.set(output,freeze({version:1,effect,decision:structuredClone(state.decision),response:structuredClone(state.response),message,messageSha256:canonicalDigest(message),modelProvenance:true}));
  }
  return output;
 }});
}
module.exports={OWNED_AUDIT_TOOL:TOOL,createOwnedAuditDecisionGraph,witnessFor:result=>witnesses.get(result)||null};
