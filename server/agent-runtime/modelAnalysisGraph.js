'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
/** Separate provider inference from deterministic parsing/grading. Callers keep
 * their original prompts, teaching payloads and offline exception branches. */
async function runModelAnalysisGraph(generate,analyze) {
 let result,output;
 const graph=new StateGraph(Annotation.Root({}))
 .addNode('model',async()=>{result=await generate();return {};})
 .addNode('analyze',async()=>{output=await analyze(result);return {};})
 .addEdge(START,'model').addEdge('model','analyze').addEdge('analyze',END).compile();
 await graph.invoke({});return output;
}
module.exports={runModelAnalysisGraph};
