'use strict';
const {checkOwnerRun,getOwnerExecution}=require('./ownerWorkflowRoutes');
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
const confusedDeputyObservation=require('../services/mcp/confusedDeputyObservation');
const commandObservation=require('../services/mcp/commandObservation');
async function runMcpWorkshopGraph({message,sandbox,conversationHistory},{detectIntent,phraseRecon,formatCatalog,phraseReply,resolveInjectionIntent,executeTool,detectObjectives,model,listTools,adoptCatalog,execution=getOwnerExecution()}) {
 const observed=(name,fn)=>async state=>{await checkOwnerRun();await execution?.check?.();await execution?.trace?.({node:name,type:'node_start',data:{toolSteps:observations.length,decisionCalls}});try{const result=await fn(state);await checkOwnerRun();await execution?.check?.();await execution?.trace?.({node:name,type:'node_end',data:{toolSteps:observations.length,decisionCalls}});return result;}catch(error){await execution?.trace?.({node:name,type:'error',data:{errorCode:'MCP_NODE_FAILED'}});throw error;}};
 let admittedDecision=null,tool,params,intent,toolResult=null,objectivesHit=[],response,catalog,decisionSource='unavailable',stopReason=null;
 const observations=[],calls=new Set();
 const MAX_TOOL_STEPS=4;
 let decisionCalls=0;
 let registrationResult=null;
 const decisionModel=model&&{provider:model.provider,chatWithTools:async(...args)=>{
  if(decisionCalls>=8)throw Object.assign(Error('Decision budget exhausted'),{code:'MCP_DECISION_LIMIT'});
  decisionCalls++;return model.chatWithTools(...args);
 }};
 const remember=()=>{const ids=intent==='recon'?(decisionSource==='model'?['mcp_recon']:[]):detectObjectives(intent,toolResult);observations.push({toolUsed:tool,params:{...params},intent,toolResult,...(registrationResult?{registrationResult}:{}),objectivesHit:ids,decisionSource,auditEnabled:sandbox.auditEnabled!==false});objectivesHit=[...new Set([...objectivesHit,...ids])];};
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
 .addNode('classify',observed('classify',async()=>{ await checkOwnerRun();if(model?.provider==='mock'){({tool,params,intent}=detectIntent(message));decisionSource='scripted';catalog=null;await execution?.trace?.({node:'classify',type:'decision',data:{decisionSource,tool:tool||'none'}});}else{catalog=await (listTools?listTools():sandbox.toolListTools());admittedDecision=await require('./mcpDecision').decideMcp({model:decisionModel,message,catalog,execution,observations,conversationHistory});({tool,params,intent,decisionSource}=admittedDecision);}if(intent==='recon')tool='list_tools';
 if(!tool){stopReason=decisionSource==='unavailable'?'model_unavailable':'model_finished';return {next:'phrase'};}
 const signature=JSON.stringify([tool,Object.entries(params||{}).sort(([a],[b])=>a.localeCompare(b))]);
 if(calls.has(signature)){stopReason='repeated_call';return {next:'phrase'};}
 calls.add(signature);return {next:intent==='recon'?'catalog':'injection_decision'};}))
 .addNode('catalog',observed('catalog',async()=>{ await checkOwnerRun();if(!catalog)catalog=await (listTools?listTools():sandbox.toolListTools());tool='list_tools';const value={tool,args:{},output:formatCatalog(catalog),blocked:false,objective:null,achieved:false,catalog};toolResult=adoptCatalog?adoptCatalog(catalog,value):value;remember();return {};}))
 .addNode('phrase_catalog',observed('phrase_catalog',async()=>{ await checkOwnerRun();response=observations.length>1?await phraseReply(message,toolResult,observations,{requireRealModel:objectivesHit.includes('mcp_recon')}):await phraseRecon(catalog,{requireRealModel:objectivesHit.includes('mcp_recon')});return {};}))
 .addNode('injection_decision',observed('injection_decision',async()=>{ await checkOwnerRun();toolResult=await resolveInjectionIntent(intent,params,sandbox,message);return {next:toolResult?'grade':'tool'};}))
 .addNode('tool',observed('tool',async()=>{ await checkOwnerRun();await execution?.check?.();toolResult=await require('../services/mcp/protectedDecisionAdmission').withDecision(admittedDecision,execution,()=>executeTool(tool,params,sandbox,{effectKey:`mcp_tool_${observations.length}_${tool}`}));if(tool==='send_report')confusedDeputyObservation.bindModelDecision(toolResult,{decisionSource,tool,args:params,execution});if(tool==='fetch_url')require('../services/mcp/ownedHttpToolAdapter').bindModelDecision(toolResult,{decisionSource,tool,args:params,execution});if(tool==='run_command')commandObservation.bindModelDecision(toolResult,{decisionSource,tool,args:params,execution});if(tool==='register_server'||/^shadow_[a-f0-9]{32}_read_policy$/.test(tool)){require('../services/mcp/ownedShadowToolAdapter').bindModelDecision(toolResult,{decisionSource,tool,args:params,execution,registrationResult});if(tool==='register_server')registrationResult=toolResult;}return {};}))
 .addNode('grade',observed('grade',async()=>{ await checkOwnerRun();remember();return {};}))
 .addNode('phrase',observed('phrase',async()=>{ await checkOwnerRun();response=await phraseReply(message,toolResult,observations,{requireRealModel:objectivesHit.includes('mcp_recon')});return {};}))
 .addEdge(START,'classify').addConditionalEdges('classify',s=>s.next,['catalog','injection_decision','phrase'])
 .addConditionalEdges('catalog',()=> 'phrase_catalog',['phrase_catalog','classify']).addEdge('phrase_catalog',END)
 .addConditionalEdges('injection_decision',s=>s.next,['grade','tool']).addEdge('tool','grade').addConditionalEdges('grade',()=>{if(model?.provider==='mock')return 'phrase';if(toolResult?.observationSource){stopReason='compound_action_finished';return 'phrase';}if(observations.length>=MAX_TOOL_STEPS){stopReason='step_limit';return 'phrase';}return 'classify';},['classify','phrase']).addEdge('phrase',END).compile();
 await graph.invoke({},{recursionLimit:40});await execution?.check?.();await execution?.trace?.({node:'terminal',type:'decision',data:{terminationReason:({repeated_call:'duplicate_action',step_limit:'tool_budget',model_unavailable:'decision_unavailable'})[stopReason]||stopReason||'scripted_finished',decisionSource,stopReason:stopReason||'scripted_finished',toolSteps:observations.length,decisionCalls,maxToolSteps:MAX_TOOL_STEPS,maxDecisionCalls:8}});const last=observations.at(-1);return {response,intent:last?.intent||intent,toolUsed:last?.toolUsed||null,toolResult:last?.toolResult||toolResult,objectivesHit,decisionSource:last?.decisionSource||decisionSource,toolObservations:observations,stopReason,decisionCalls};
}
module.exports={runMcpWorkshopGraph};
