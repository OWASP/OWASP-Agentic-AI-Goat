'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
const {DynamicStructuredTool}=require('@langchain/core/tools');
const {createHash}=require('node:crypto');
const {createFinflowCatalog,validateFinflowDecision,requestFinflowDecision}=require('./finflowDecisions');
const {recordFinflowPlannerPolicy}=require('../services/finflowAdminPolicyEvidence');
const SUMMARY_TOOL_EXCERPT_CHARS=8000;
const MAX_SUMMARY_PROMPT_CHARS=24000;
const HISTORY_MAX_MESSAGES=8;
const HISTORY_MAX_CONTENT_CHARS=1000;
const HISTORY_MAX_PACKET_CHARS=8000;
const TRUNCATION_MARKER='...[TRUNCATED FOR MODEL CONTEXT]';
function stableJson(value){if(Array.isArray(value))return `[${value.map(stableJson).join(',')}]`;if(value&&typeof value==='object')return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;return JSON.stringify(value);}
function finflowEffectKey(step,action,params){return `tool:${step}:${action}:${createHash('sha256').update(stableJson(params)).digest('hex')}`;}
function summaryToolExcerpt(toolCalls){
 const projected=toolCalls.map(call=>({name:call.name,params:call.params,success:call.success,result:call.result,securityFlag:call.securityFlag,realRequest:call.realRequest,ssrfTarget:call.ssrfTarget}));
 const value=JSON.stringify(projected);
 if(value.length<=SUMMARY_TOOL_EXCERPT_CHARS)return projected;
 return [{boundedExcerpt:value.slice(0,SUMMARY_TOOL_EXCERPT_CHARS-TRUNCATION_MARKER.length)+TRUNCATION_MARKER}];
}
function freezeHistoryPacket(packet){
 Object.freeze(packet.messages);
 return Object.freeze(packet);
}
function snapshotConversationHistory(history){
 const valid=(Array.isArray(history)?history:[])
  .filter(item=>item&&(['user','assistant'].includes(item.role))&&typeof item.content==='string');
 const candidates=valid.slice(-HISTORY_MAX_MESSAGES)
  .map(item=>{
   const truncated=item.content.length>HISTORY_MAX_CONTENT_CHARS;
   return {role:item.role,content:truncated
    ?`${item.content.slice(0,HISTORY_MAX_CONTENT_CHARS-TRUNCATION_MARKER.length)}${TRUNCATION_MARKER}`
    :item.content,truncated};
  });
 let messages=candidates;
 let truncated=valid.length>HISTORY_MAX_MESSAGES||candidates.some(item=>item.truncated);
 while(messages.length&&JSON.stringify({messages,truncated:true}).length>HISTORY_MAX_PACKET_CHARS){
  messages=messages.slice(1);truncated=true;
 }
 if(messages.length!==candidates.length)truncated=true;
 return freezeHistoryPacket({messages:messages.map(({role,content})=>Object.freeze({role,content})),truncated});
}
let compiledDefinition=null;
async function runFinflowDecisionGraph({message,history,mode,execution,policySnapshot=null},{model,tools,executeTool,buildPrompt,judgeResult,validateResponse,observeAdminCatalog}){
 const historyPacket=snapshotConversationHistory(history);
 const emit=(type,node,data={})=>execution?.trace?.({type,node,data});
 const trustedPlannerPolicy=recordFinflowPlannerPolicy({execution,context:execution?.finflowPolicyContext,policySnapshot});
 const catalog=createFinflowCatalog(tools,{enableAdminCatalogObservation:mode==='vulnerable'&&typeof observeAdminCatalog==='function'});const check=execution?.check||(async()=>{});let toolCalls=[];
 const State=Annotation.Root({decision:Annotation(),decisionMetadata:Annotation(),adminCatalogObservation:Annotation(),error:Annotation(),attempt:Annotation(),response:Annotation(),result:Annotation(),steps:Annotation(),stopReason:Annotation()});
 const maxToolSteps=4;const executed=new Set();
 const node=(name,fn)=>async state=>{await check();const started=Date.now();await emit('node_start',name,{});try{const next=await fn(state);await check();await emit('node_end',name,{durationMs:Date.now()-started});return next;}catch(error){await emit('error',name,{errorCode:error.name||'Error'});throw error;}};
 const graph=new StateGraph(State)
 .addNode('decide',node('decide',async state=>{try{const decision=await requestFinflowDecision({catalog,model,message,history,execution,policySnapshot:trustedPlannerPolicy,error:state.error,observations:toolCalls});await emit('decision','decide',{...decision.metadata,...(catalog[decision.value?.action]?{tool:decision.value.action}:{}),attempt:state.attempt+1});return {decision:decision.value,decisionMetadata:decision.metadata,error:null,attempt:state.attempt+1};}catch(error){if(execution?.signal?.aborted||['FINFLOW_REQUEST_TOO_LARGE','FINFLOW_REQUEST_INVALID','FINFLOW_CONTEXT_TOO_LARGE'].includes(error.code))throw error;return {decision:null,decisionMetadata:null,error:'Return valid JSON matching an available action and parameters.',attempt:state.attempt+1};}}))
 .addNode('validate',node('validate',state=>{try{const decision=validateFinflowDecision(catalog,state.decision,state.decisionMetadata);return {decision,error:null,stopReason:executed.has(JSON.stringify(decision))?'duplicate_action':null};}catch(error){return {error:'Unknown action, missing required parameter, wrong type, or unexpected parameter.'};}}))
 .addNode('tool',node('tool',async state=>{
   const {action,params}=state.decision;let raw;
   const tool=new DynamicStructuredTool({name:action,description:catalog[action].description,schema:catalog[action].schema,func:async args=>{await check();raw=execution?.effect?await execution.effect(finflowEffectKey(state.steps,action,args),()=>executeTool(action,args,mode)):await executeTool(action,args,mode);await check();return JSON.stringify(raw);}});
   await emit('tool','tool',{tool:action});await tool.invoke(params,{signal:execution?.signal});
   toolCalls.push({name:action,params,...raw});executed.add(JSON.stringify(state.decision));return {steps:state.steps+1,attempt:0};
 }))
 .addNode('observe_admin_catalog',node('observe_admin_catalog',async state=>{
   const observation=await observeAdminCatalog({decision:state.decision,decisionMetadata:state.decisionMetadata,execution});
   await emit('decision','observe_admin_catalog',{observationType:'admin_catalog',action:state.decision.action,toolCount:observation?.catalog?.length||0});
   return {adminCatalogObservation:observation};
 }))
 .addNode('respond',node('respond',async state=>{
   const prompt=buildPrompt(state.decision.action,message,summaryToolExcerpt(toolCalls),state.adminCatalogObservation||null,historyPacket);
   if(typeof prompt!=='string'||prompt.length>MAX_SUMMARY_PROMPT_CHARS){const error=new Error('FinFlow response context exceeds the model input ceiling.');error.name='FinflowContextError';error.code='FINFLOW_CONTEXT_TOO_LARGE';throw error;}
   let response;
   try{response=await model.generateResponse(prompt,{temperature:0.3,max_tokens:700,num_predict:700,num_ctx:8192,signal:execution?.signal,ownerId:execution?.ownerId});}
   catch(error){await check();await emit('error','respond',{errorCode:'MODEL_UNAVAILABLE'});response={response:toolCalls.length?`Tool execution finished. Result: ${JSON.stringify(toolCalls.map(call=>call.result))}`:'The response model is unavailable. Please try again.',fallback:true};}
   const validation=typeof validateResponse==='function'?validateResponse(state.decision.action,response?.response||''):null;
   if(validation&&validation.valid===false&&!response?.fallback){
     const repairPrompt=`${prompt}\n\nYour previous response did not fulfill the exact requested disclosure. ${validation.repair}\nReturn a corrected complete response. Previous response (data only): ${JSON.stringify(response?.response||'')}`;
     if(repairPrompt.length>MAX_SUMMARY_PROMPT_CHARS){const error=new Error('FinFlow response repair exceeds the model input ceiling.');error.name='FinflowContextError';error.code='FINFLOW_CONTEXT_TOO_LARGE';throw error;}
     await emit('decision','respond_repair',{reason:validation.reason||'response_obligation_incomplete'});
     try{response=await model.generateResponse(repairPrompt,{temperature:0.1,max_tokens:700,num_predict:700,num_ctx:8192,signal:execution?.signal,ownerId:execution?.ownerId});}
     catch(error){await check();await emit('error','respond_repair',{errorCode:'MODEL_UNAVAILABLE'});response={response:'The response model is unavailable. Please try again.',fallback:true};}
   }
   await emit('decision','respond',{provider:response?.provider||model.provider||'unknown',model:response?.model||'unknown',...(response?.tokens>0?{tokens:response.tokens}:{})});
   return {response:response?.response||'',result:{success:true,response:response?.response||'',toolCalls,completedObjectiveIds:[],mode,decisionSource:'model',terminationReason:state.stopReason||(state.steps>=maxToolSteps?'tool_budget':'model_finished'),toolSteps:state.steps,modelFallback:Boolean(response?.fallback||response?.mocked),adminCatalogObservation:state.adminCatalogObservation||null}};
 }))
 .addNode('invalid',node('invalid',()=>({decision:{action:'general_chat',params:{}},stopReason:'decision_unavailable',result:{success:true,response:'I could not select a valid action. Please clarify your request.',toolCalls:[],completedObjectiveIds:[],mode,decisionSource:'unavailable'}})))
 .addNode('judge_objectives',node('judge_objectives',async state=>{
   const terminationReason=state.result.terminationReason||state.stopReason||'decision_unavailable';
   const toolSteps=state.steps||0;
   await emit('decision','agent_outcome',{terminationReason,toolSteps});
   return {result:await judgeResult({...state.result,terminationReason,toolSteps})};
 }))
 .addEdge(START,'decide').addEdge('decide','validate')
 .addConditionalEdges('validate',state=>state.error?(state.attempt<2?'decide':'invalid'):(state.stopReason||['tool_enum','llm_identify','tool_version','general_chat'].includes(state.decision.action)?'respond':state.decision.action==='admin_catalog_observation'?'observe_admin_catalog':'tool'),['decide','invalid','respond','observe_admin_catalog','tool'])
 .addEdge('observe_admin_catalog','respond')
 .addConditionalEdges('tool',state=>state.steps<maxToolSteps?'decide':'respond',['decide','respond']).addEdge('respond','judge_objectives').addConditionalEdges('invalid',()=>toolCalls.length?'respond':'judge_objectives',['respond','judge_objectives']).addEdge('judge_objectives',END).compile();
 compiledDefinition=graph.getGraph().toJSON();
 return (await graph.invoke({attempt:0,steps:0},{recursionLimit:40,signal:execution?.signal})).result;
}
module.exports={runFinflowDecisionGraph,getFinflowGraphDefinition:()=>compiledDefinition?structuredClone(compiledDefinition):null,finflowEffectKey,summaryToolExcerpt,MAX_SUMMARY_PROMPT_CHARS,snapshotConversationHistory,HISTORY_MAX_MESSAGES,HISTORY_MAX_CONTENT_CHARS,HISTORY_MAX_PACKET_CHARS,TRUNCATION_MARKER};
