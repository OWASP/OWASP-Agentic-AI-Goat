'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
async function runCtfGuardianGraph(stage,payload,{generate,runOutputDefenses,normalizedContains,execution,outputModel,lessonReceipt}) {
 let aiResponse,processedResponse,wasSuccessful;
 const graph=new StateGraph(Annotation.Root({}))
 .addNode('guardian',async()=>{aiResponse=await generate(stage,payload);return {};})
 .addNode('output_defenses',async()=>{processedResponse=await runOutputDefenses(stage,aiResponse,{execution,model:outputModel,lessonReceipt});return {};})
 .addNode('grade_visible_response',()=>{wasSuccessful=normalizedContains(processedResponse,stage.success_criteria);return {};})
 .addEdge(START,'guardian').addEdge('guardian','output_defenses').addEdge('output_defenses','grade_visible_response').addEdge('grade_visible_response',END).compile();
 await graph.invoke({});return {aiResponse,processedResponse,wasSuccessful};
}
module.exports={runCtfGuardianGraph};
