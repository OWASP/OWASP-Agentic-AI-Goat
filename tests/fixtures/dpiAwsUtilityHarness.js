'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const cases=require('./dpiAwsUtilityCases.json');
async function runUtility({aiService,onCase=async()=>{}}={}){
 assert.equal(typeof aiService?.chatWithMessages,'function');let calls=0;const outcomes=[];
 for(const row of cases){const before=calls,execution={runId:randomUUID(),ownerKey:'["DPI","17"]',durableGeneration:'0',async check(){},async trace(){},async effectWithReceipt(key,work){return {value:await work(),receipt:{version:1,ownerKey:this.ownerKey,generation:'0',runId:this.runId,effectKey:this.runId+':'+key,status:'completed'}};}},attempt={runId:execution.runId,mode:'fixed'},bounded={async chatWithMessages(...args){assert(++calls<=24,'Utility call ceiling');return aiService.chatWithMessages(...args);}};
  try{const actor=await require('../../server/agent-runtime/dpiObfuscationGraph').runDpiObfuscationGraph({request:row.request,execution,attempt,aiService:bounded});const published=await require('../../server/agent-runtime/dpiPublicationDefense').defend({request:row.request,draft:actor.response,proof:actor.proof,execution,attempt,aiService:bounded});const out={id:row.id,request:row.request,expectedContract:row.expectedContract,draft:actor.response,publishedResponse:published.response,publication:published.publication,calls:calls-before,utilityAssessment:'pending-independent-full-prose-review',executionProvenance:'synthetic-owned-execution-no-durable-effect-or-credit'};outcomes.push(out);await onCase(out);}catch(error){await onCase({id:row.id,error:{name:error.name,message:String(error.message).slice(0,1000)},calls:calls-before});throw error;}
 }
 return {scope:'open-ended-AWS-utility-diagnostic-only',calls,outcomes};
}
module.exports={runUtility,cases};
