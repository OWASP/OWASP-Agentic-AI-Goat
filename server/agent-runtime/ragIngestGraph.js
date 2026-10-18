'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
async function runRagIngestGraph({userKey,sessionId,buffer,filename,displayFilename,platformUserId},{ragVectorStore,durableRagStore,markRagObjectiveComplete,execution,objectiveJudge,completionService}) {
 let evaluate;const judgments=[];
 if(durableRagStore && typeof durableRagStore.ingestAndSelect !== 'function') throw new TypeError('Bound durable RAG store required');
 let chunksStored,documentReceipt,replayed=false,currentlySelected,replayObservation;const check=async()=>{if(execution)await execution.check();};
 const graph=new StateGraph(Annotation.Root({}))
 .addNode('store_document',async()=>{await check();if(durableRagStore){const stored=await durableRagStore.ingestAndSelect({documentId:sessionId,operationId:execution?.runId,sourceBuffer:buffer,filename:displayFilename,ingestionKind:'upload'});chunksStored=stored.chunksStored;documentReceipt=stored.receipt;replayed=stored.replayed===true;currentlySelected=stored.currentlySelected;replayObservation=stored.observation;}else({chunksStored}=await ragVectorStore.storeDocument(userKey,sessionId,buffer,filename));await check();return {};})
 .addNode('select_session',async()=>{await check();if(!durableRagStore)await ragVectorStore.setCurrentSession(userKey,sessionId,displayFilename,chunksStored);return {};})
 .addNode('grade_upload',async()=>{await check();if(replayed)return {};evaluate=await require('./indirectObjectiveJudge').beginIpiEvaluation({platformUserId,execution,judge:objectiveJudge,completionService});const ids=['rag_upload'];if(!filename.toLowerCase().endsWith('.pdf'))ids.push('rag_clean_doc');
 for(const id of ids){const outcome=await evaluate(id,[{id:'document',source:'tool_result',content:id==='rag_upload'?{filename,chunksStored}:{filename,chunksStored,text:buffer.toString('utf8')}},...(documentReceipt?[{id:'document_receipt',source:'tool_result',content:documentReceipt}]:[])],{chunks_stored:chunksStored>0,...(id==='rag_clean_doc'?{document_content_present:buffer.length>0,text_document:!filename.toLowerCase().endsWith('.pdf')}: {})});judgments.push(outcome.judgment);if(outcome.completed)await markRagObjectiveComplete(userKey,id,platformUserId,{durable:outcome.durable});}return {};})
 .addEdge(START,'store_document').addEdge('store_document','select_session').addEdge('select_session','grade_upload').addEdge('grade_upload',END).compile();
 try {
  await graph.invoke({});
 } catch(error) {
  if(error?.name==='AbortError' && !durableRagStore) {
   try { await ragVectorStore.deleteSession(userKey,sessionId); }
   catch(cleanupError) { error.cleanupError=cleanupError;error.cleanupUncertain=true; }
  }
  throw error;
 }
 return {judgments,...(documentReceipt?{document_receipt:documentReceipt,replayed,currently_selected:currentlySelected,...(replayObservation?{replay_observation:replayObservation}:{})}:{}),session_id:sessionId,chunks_stored:chunksStored,filename:displayFilename};
}
module.exports={runRagIngestGraph};
