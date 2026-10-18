'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const Module=require('node:module');const path=require('node:path');
const routePath=path.resolve(__dirname,'../server/routes/excessiveAgencyLab.js');
async function mounted(graphResults){
 const initial=Module._load;const state={conversations:{get:async()=>[],set:async()=>{}},database:{getUserProgress:async()=>({}),getStats:async()=>({})},toolRouter:{}};
 const coordinator={run:async(_owner,_options,work)=>work({runId:'owned-run',ownerKey:'owner',generation:0,signal:new AbortController().signal,check:async()=>{},trace:async()=>{}}),reset:async(_owner,work)=>work()};
 Module._load=function(request,parent,isMain){
  if(request==='../agent-runtime/runCoordinator')return{createRunCoordinator:()=>coordinator};
  if(request==='../agent-runtime/ownerWorkflowRoutes')return{ownerWorkflowRoute:(_coordinator,ownerFor,handler)=>async(req,res,next)=>coordinator.run(ownerFor(req),{},()=>handler(req,res,next)),checkOwnerRun:async()=>{}};
  if(request==='../middleware/adminAuth')return{authenticateToken:(req,_res,next)=>{req.user={id:41};next();}};
  if(request==='../services/excessiveAgencyAttendeeLabStore')return{excessiveAgencyAttendeeLabStore:{resolveSession:async()=>({labUser:{userId:'alice'},state}),getOrCreate:async()=>state}};
  if(request==='../services/multiProviderAIService')return{};
  if(request==='../utils/contextLogger')return{error:()=>{}};
  if(request==='../services/workshopModeService')return{getMode:async()=> 'vuln'};
  if(request==='../services/workshopModeHandlers')return{createWorkshopModeHandlers:()=>({get:(_q,r)=>r.json({mode:'vuln'}),set:(_q,r)=>r.json({mode:'vuln'})})};
  if(request==='../services/workshopConfigService')return{createWorkshopConfigService:()=>({getSnapshot:async()=>({exercises:{excessive_agency:{objectives:{}}}})})};
  if(request==='../utils/progressSync')return{syncObjectiveComplete:async()=>{},checkAndMarkWorkshopComplete:async()=>{},resetWorkshopProgress:async()=>{},getUserWorkshopProgress:async()=>[]};
  if(request==='../agent-runtime/excessiveAgencyGraph')return{runExcessiveAgencyGraph:async()=>graphResults.shift()};
  return initial.call(this,request,parent,isMain);
 };
 delete require.cache[routePath];let server;
 try{const express=require('express');const app=express();app.use(express.json());app.use('/api/excessive-agency',require(routePath));server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});return{base:`http://127.0.0.1:${server.address().port}`,close:()=>new Promise(resolve=>server.close(()=>{Module._load=initial;delete require.cache[routePath];resolve();}))};}
 catch(error){Module._load=initial;delete require.cache[routePath];throw error;}
}
test('mounted chat returns ordered safe DTOs and final compatibility execution',async()=>{
 const observations=[{index:0,effectId:'private-1',rawDecisionResponse:'private decision',decision:{provider:'private'},toolCall:{tool:'listNotes',args:{userId:'bob'}},toolResult:{success:true,notes:[{id:'n1'}]}},{index:1,effectId:'private-2',rawDecisionResponse:'private decision 2',decision:{provider:'private'},toolCall:{tool:'deleteNote',args:{noteId:'n1'}},toolResult:{success:false,error:'Access denied'}}];
 const app=await mounted([{finalResponse:'done',toolCall:observations[1].toolCall,toolResult:observations[1].toolResult,toolObservations:observations,judgments:[],completedObjectiveIds:[],projectionPending:[]}]);
 try{const response=await fetch(app.base+'/api/excessive-agency/chat',{method:'POST',headers:{'content-type':'application/json','x-lab-session':'session'},body:JSON.stringify({message:'do both'})});const body=await response.json();assert.equal(response.status,200);assert.deepEqual(body.toolExecutions.map(v=>[v.id,v.sequence,v.tool,v.success]),[['observation-1',1,'listNotes',true],['observation-2',2,'deleteNote',false]]);assert.deepEqual(body.toolExecution,body.toolExecutions[1]);assert.equal(body.toolExecutions[1].result.error,'Access denied');assert.equal(JSON.stringify(body).includes('private decision'),false);assert.equal(JSON.stringify(body).includes('effectId'),false);}finally{await app.close();}
});
test('mounted no-action chat returns authoritative empty list and null compatibility field',async()=>{
 const app=await mounted([{finalResponse:'hello',toolCall:null,toolResult:null,toolObservations:[],judgments:[],completedObjectiveIds:[],projectionPending:[]}]);
 try{const response=await fetch(app.base+'/api/excessive-agency/chat',{method:'POST',headers:{'content-type':'application/json','x-lab-session':'session'},body:JSON.stringify({message:'hello'})});const body=await response.json();assert.equal(response.status,200);assert.deepEqual(body.toolExecutions,[]);assert.equal(body.toolExecution,null);}finally{await app.close();}
});

test('mounted route retains final compatibility DTO for a legacy graph result',async()=>{
 const app=await mounted([{finalResponse:'legacy',toolCall:{tool:'listNotes',args:{userId:'alice'}},toolResult:{success:true},judgments:[],completedObjectiveIds:[],projectionPending:[]}]);
 try{const response=await fetch(app.base+'/api/excessive-agency/chat',{method:'POST',headers:{'content-type':'application/json','x-lab-session':'session'},body:JSON.stringify({message:'legacy'})});const body=await response.json();assert.equal(response.status,200);assert.equal(body.toolExecutions.length,1);assert.deepEqual(body.toolExecution,body.toolExecutions[0]);assert.equal(body.toolExecution.tool,'listNotes');}finally{await app.close();}
});
