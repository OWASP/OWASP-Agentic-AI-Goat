'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const express=require('express');
const {createPostgresAgentRunReadRepository,ownerKey}=require('../server/database/postgres/agentRunReadRepository');
const {createAgentRunsRouter}=require('../server/routes/agentRuns');

test('mounted Agent Runs read projects terminal Pricing grounding audit without source or answer text',async()=>{
 const runId=randomUUID(),conversationId=randomUUID(),ownerId=17;
 const sourceQuote=JSON.stringify({grounded:false,projections:{projected_revenue_delta:965.97}});
 const claimQuote='The experiment projects an estimated $965.97 increase.';
 const result={sourceInstruction:{classification:'generated_unverified'},relation:'projection_or_estimate',
  claimQuote,sourceQuote,sourceSha256:createHash('sha256').update(sourceQuote).digest('hex'),sourceGrounded:false};
 const run={runId,ownerKey:ownerKey('SecureShopBoundConversation',conversationId),generation:0,status:'completed',
  startedAt:new Date().toISOString(),finishedAt:new Date().toISOString()};
 const judgment={userId:ownerId,evaluationId:randomUUID(),runId,workshopKey:'secureshop_agent_security',
  objectiveId:'ss_pricing_false_grounding',family:'SecureShop',scenario:'bound_pricing',
  rubricVersion:'secureshop-pricing-grounding-v2',evidenceDigest:'a'.repeat(64),generation:0,
  mode:'vuln',canonicalMode:'vuln',verdict:'fail',disposition:'not_pass',
  criteria:[{id:'false_grounding',satisfied:false,evidenceRefs:[],citations:[]}],
  semanticObservation:result,comparisonVersion:'pricing-grounding-comparison-v1',
  comparisonStages:[{stage:'source',attempts:0,provider:'server',model:null,completed:true},
   {stage:'effect',attempts:1,provider:'ollama',model:'llama3.1:8b',completed:true}]};
 const pool={async query(sql,args){
  if(sql.includes('FROM graph_runtime.runs WHERE run_id=$1'))return{rows:[run]};
  if(sql.includes('FROM graph_runtime.events'))return{rows:[]};
  if(sql.includes('FROM workshop_platform.objective_judgments')){
   assert.deepEqual(args,[String(ownerId),runId]);return{rows:[judgment]};
  }
  throw Error('Unexpected read query');
 }};
 const ownership={async resolve(id){assert.equal(id,conversationId);return{ownerId};}};
 const repository=createPostgresAgentRunReadRepository(pool,{secureShopOwnership:ownership});
 const auth=(req,_res,next)=>{req.user={id:Number(req.headers.authorization?.replace('Bearer ',''))};next();};
 const app=express();app.use('/api/agent-runs',createAgentRunsRouter({repository,authenticateToken:auth,receiptAdapters:{}}));
 const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
 try{
  const url=`http://127.0.0.1:${server.address().port}/api/agent-runs/${runId}`;
  const response=await fetch(url,{headers:{authorization:`Bearer ${ownerId}`}});
  assert.equal(response.status,200);const body=await response.json();assert.equal(body.judgments.length,1);
  const projected=body.judgments[0];assert.equal(projected.verdict,'fail');assert.equal(projected.disposition,'not_pass');
  assert.equal(projected.semanticObservation.relation,'projection_or_estimate');
  assert.equal(projected.semanticObservation.sourceSha256,result.sourceSha256);
  assert.deepEqual(projected.comparisonStages.map(stage=>[stage.stage,stage.attempts]),[['source',0],['effect',1]]);
  assert(!JSON.stringify(body).includes(sourceQuote));assert(!JSON.stringify(body).includes(claimQuote));
  assert.equal((await fetch(url,{headers:{authorization:'Bearer 18'}})).status,404);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
