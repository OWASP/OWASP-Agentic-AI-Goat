'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const Module=require('node:module');
const {createObjectiveGradingCore,createDeferredObjectiveGrading}=require('../server/services/objectiveGradingCore');
const {createAgentRunsRouter}=require('../server/routes/agentRuns');
const {createMemoryAgentRunReadRepository}=require('../server/database/postgres/agentRunReadRepository');
const evaluationId='10000000-0000-4000-8000-000000000001';

test('mounted judgment routes use only the installed core and authenticated owner',async t=>{
 const calls=[],facade=createDeferredObjectiveGrading();let storeAccess=0,modelAccess=0;
 const originalLoad=Module._load;
 Module._load=function(request,...args){if(/(?:postgresPlatformStores|postgresIdentityAdapter|authDb)(?:\.js)?$/.test(request))throw Error('Unexpected fallback store import');return originalLoad.call(this,request,...args);};
 t.after(()=>{Module._load=originalLoad;});
 const app=express();app.use(express.json());
 app.use('/api/agent-runs',createAgentRunsRouter({repository:createMemoryAgentRunReadRepository({snapshot:()=>[]}),receiptAdapters:{},
  authenticateToken(req,res,next){const id=({'Bearer owner-seven':7,'Bearer owner-eight':8})[req.get('authorization')];if(!id)return res.status(401).json({error:'Authentication required'});req.user={id};next();},
  listJudgments:facade.listJudgments,regrade:facade.regrade}));
 const server=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const request=async(path,{token='owner-seven',body}={})=>{const result=await fetch(`http://127.0.0.1:${server.address().port}/api/agent-runs${path}`,{method:body===undefined?'GET':'POST',headers:{...(token?{authorization:`Bearer ${token}`} : {}),'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return{status:result.status,body:await result.json()};};
 const retryPath=`/judgments/${evaluationId}/retry`;
 assert.equal((await request('/judgments')).status,503);
 const earlyRetry=await request(retryPath,{body:{}});assert.equal(earlyRetry.status,503);assert.equal(earlyRetry.body.code,'GRADE_STORE_NOT_READY');assert.equal(calls.length,0);
 const identityPool={query(){storeAccess++;throw Error('Unexpected SQL');},connect(){storeAccess++;throw Error('Unexpected SQL connection');}};
 const receipts={async listRecoverable(input){calls.push(['list',input]);return[{evaluationId,userId:input.userId,canRetry:false}];}};
 let completion;
 const core=createObjectiveGradingCore({identityPool,progress:{getGeneration:async()=>0},judge:async()=>{modelAccess++;throw Error('Unexpected model');}}, {
  createObjectiveJudgmentRepository(pool){assert.equal(pool,identityPool);calls.push(['constructRepository']);return receipts;},
  createObjectiveCompletionService(options){assert.equal(options.receipts,receipts);assert.equal(Object.hasOwn(options,'capturePersonaEvaluation'),false);completion={retry:async()=>{throw Error('Controlled regrade seam only');}};return completion;},
  createObjectiveRegradeService(options){assert.equal(options.receipts,receipts);assert.equal(options.completion,completion);return async input=>{calls.push(['retry',input]);return{replayed:true};};},
 });facade.install(core);
 assert.equal(calls.filter(row=>row[0]==='constructRepository').length,1);
 assert.deepEqual(await request('/judgments'),{status:200,body:{judgments:[{evaluationId,userId:7,canRetry:false}]}});
 assert.deepEqual(calls.at(-1),['list',{userId:7,judgeVersion:require('../server/agent-runtime/objectiveJudge').JUDGE_VERSION}]);
 assert.equal((await request(retryPath,{token:'owner-eight',body:{}})).status,200);
 assert.deepEqual(calls.at(-1),['retry',{userId:8,evaluationId}]);
 const before=calls.length;
 for(const token of [null,'forged']){
  assert.equal((await request('/judgments',{token})).status,401);
  assert.equal((await request(retryPath,{token,body:{}})).status,401);
 }
 assert.equal((await request('/judgments?ownerId=8')).status,400);
 assert.equal((await request('/?ownerId=8')).status,400);
 assert.equal((await request(retryPath,{body:{userId:8}})).status,400);
 assert.equal((await request(retryPath,{body:{evidence:'forged',verdict:'pass'}})).status,400);
 assert.equal((await request('/judgments/not-a-uuid/retry',{body:{}})).status,400);
 assert.equal(calls.length,before);assert.equal(storeAccess,0);assert.equal(modelAccess,0);
});
