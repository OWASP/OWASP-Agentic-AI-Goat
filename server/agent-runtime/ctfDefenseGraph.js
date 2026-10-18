'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
async function runCtfDefenseGraph(stage,value,{output=false,inputHandlers={},outputHandlers={}}) {
 let layers;try{layers=JSON.parse(stage.defense_style||'[]');}catch{layers=[];}
 // Retain the configured order, including repeated layers and unknown no-ops.
 let index=0,processed=value,result={blocked:false};
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
 .addNode('next_layer',()=>({next:index<layers.length?'apply_layer':END}))
 .addNode('apply_layer',async()=>{
 const layer=layers[index++];
 if(output){if(outputHandlers[layer])processed=await outputHandlers[layer](processed,stage);}
 else if(inputHandlers[layer]){const checked=await inputHandlers[layer](value,stage);if(checked.blocked){result={...checked,blocked:true,reason:checked.reason,layer};return {next:END};}}
 return {next:'next_layer'};
 })
 .addEdge(START,'next_layer').addConditionalEdges('next_layer',s=>s.next,['apply_layer',END])
 .addConditionalEdges('apply_layer',s=>s.next,['next_layer',END]).compile();
 await graph.invoke({}, {recursionLimit:Math.max(4,layers.length*2+3)});return output?processed:result;
}
module.exports={runCtfDefenseGraph};
