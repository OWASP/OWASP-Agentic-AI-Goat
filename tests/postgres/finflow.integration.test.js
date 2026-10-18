'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPool}=require('../../server/database/postgres');
const {createFinflowWorkshopDb,OBJECTIVE_IDS}=require('../../server/database/postgres/sensitiveInfoWorkshopDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_FINFLOW_TEST_RUNTIME_URL;
test('FinFlow PG preserves18 objectives, idempotent owner progress and transactional native reset',{skip:!enabled},async()=>{
 const pool=createPool(process.env,'PG_FINFLOW_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_FINFLOW_TEST_MIGRATION_URL');
 try{
  const store=createFinflowWorkshopDb(pool);await store.initialize(migration);await store.initialize(migration);
  assert.equal(OBJECTIVE_IDS.length,18);await store.ensureObjectives('alice');await store.ensureObjectives('bob');
  assert.equal((await store.getProgress('alice')).length,18);
  for(const id of OBJECTIVE_IDS){assert.equal((await store.completeObjective('alice',id)).changes,1);assert.equal((await store.completeObjective('alice',id)).changes,0);}
  assert.ok((await store.getProgress('alice')).every(row=>row.completed));assert.ok((await store.getProgress('bob')).every(row=>!row.completed));
  await assert.rejects(store.completeObjective('alice','unknown'));
  await store.logToolCall('alice',{name:'admin_view_config',params:{file:"'; DROP TABLE finflow.progress;--"},result:'synthetic challenge result',mode:'vulnerable'});
  await store.logToolCall('bob',{name:'get_transaction_history',params:{},result:'fixture',mode:'fixed'});
  await store.resetUser('alice');assert.deepEqual(await store.getProgress('alice'),[]);assert.equal((await store.getProgress('bob')).length,18);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM finflow.tool_log WHERE user_id=$1',['alice'])).rows[0].n,0);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM finflow.tool_log WHERE user_id=$1',['bob'])).rows[0].n,1);
  await assert.rejects(pool.query('CREATE TABLE finflow.forbidden(id int)'),/permission denied/);
  const Module=require('node:module'),load=Module._load;const express=require('express');
  const objectives=OBJECTIVE_IDS.map(id=>({id,label:id}));let resetCanonical=0;
  const agent={runUserExclusive:async(owner,fn)=>fn({}, {check:async()=>{}}),resetUserExclusive:async(owner,fn)=>fn(),processMessage:async()=>({success:true,response:'fixture',completedObjectiveIds:[OBJECTIVE_IDS[0]],durableGrading:true,judgments:[{objectiveId:OBJECTIVE_IDS[0],verdict:'pass'}],toolCalls:[{name:'admin_view_config',params:{},result:'fixture'}]})};
  Module._load=function(request,parent,isMain){
    if(parent?.filename===require.resolve('../../server/routes/sensitiveInfoWorkshop')){
      if(request==='../services/finflowAgentResourceComposition')return{configuredFinflowAgentResources:()=>({assertReady:async()=>{}})};
      if(request==='../services/finflowObjectiveAdmission')return{createWorkshopObjectiveAdmission:()=>({admit:async objectiveId=>({generalChat:!objectiveId,objectiveId})})};
      if(request==='../services/postgresPlatformStores')return{getPostgresPlatformStores:()=>({})};
      if(request==='../services/sensitiveInfoPresentation')return{readSensitiveInfoPresentation:async()=>({progress:objectives,ssrfExamples:{}})};
    }
    if(request==='../database/sensitiveInfoWorkshopDb')return store;
    if(request==='../services/sensitiveInfoWorkshopAgent')return {SensitiveInfoWorkshopAgent:function(){return agent;},OBJECTIVES:objectives,resetWorkshopState:()=>{},createSensitiveInfoWorkshopStateStore:()=>({resetUser:()=>{}}),getConfiguredSsrfExamples:()=>({})};
    if(request==='../middleware/adminAuth')return {authenticateToken:(req,res,next)=>{req.user={id:99};next();}};
    if(request==='../services/workshopModeService')return {getMode:async()=> 'vulnerable'};
    if(request==='../services/workshopModeHandlers')return {createWorkshopModeHandlers:()=>({get:(req,res)=>res.json({}),set:(req,res)=>res.json({})})};
    if(request==='../utils/progressSync')return {syncWorkshopStarted:async()=>{},syncObjectiveComplete:()=>{throw Error('No unjudged canonical completion');},checkAndMarkWorkshopComplete:async()=>{},resetWorkshopProgress:async()=>{resetCanonical++;}};
    return load.call(this,request,parent,isMain);
  };
  let router;try{delete require.cache[require.resolve('../../server/routes/sensitiveInfoWorkshop')];router=require('../../server/routes/sensitiveInfoWorkshop');}catch(error){Module._load=load;throw error;}
  // Controlled admission/resource/presentation fixtures keep this suite scoped to native storage and HTTP.
  // This storage/HTTP contract uses a controlled reset coordinator; full cross-store reset has its own native suite.
  const resetComposition=require('../../server/services/sensitiveInfoResetComposition');
  const originalResetComposition=resetComposition.getSensitiveInfoResetComposition;
  resetComposition.getSensitiveInfoResetComposition=async()=>({reset:{reset:async owner=>{await store.resetUser(String(owner));resetCanonical++;await store.ensureObjectives(String(owner));return {status:'completed'};}}});
  const app=express();app.use(express.json());app.use(router);const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  try{
    const url=`http://127.0.0.1:${server.address().port}`;
    assert.equal((await fetch(url+'/init',{method:'POST'})).status,200);assert.equal((await store.getProgress('99')).length,18);
    const chat=await fetch(url+'/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userMessage:'fixture'})});assert.equal(chat.status,200);assert.deepEqual((await chat.json()).newlyCompletedObjectives,[OBJECTIVE_IDS[0]]);
    assert.equal((await fetch(url+'/progress/reset',{method:'POST'})).status,200);assert.equal(resetCanonical,1);assert.ok((await store.getProgress('99')).every(row=>!row.completed));
  }finally{Module._load=load;resetComposition.getSensitiveInfoResetComposition=originalResetComposition;await new Promise(resolve=>server.close(resolve));}

 }finally{await Promise.all([pool.end(),migration.end()]);}
});
