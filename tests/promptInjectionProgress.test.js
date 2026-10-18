'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPostgresPromptInjectionProgressService,PromptInjectionProgressError}=require('../server/services/promptInjectionProgressService');
const workshop='direct_prompt_injection',owner={userId:71,userKey:'71'};
function fixture(){
 const calls=[],state=new Map([[71,{objectives:[{id:'jailbreak',completed:true,completedAt:'2026-08-05T10:00:00.000Z'}],count:1}],[72,{objectives:[{id:'interact',completed:true}],count:2}]]);
 const exercise={isVisible:true,objectives:{interact:{isVisible:true},jailbreak:{isVisible:true},ghost:{isVisible:true}}};
 let resetError;
 const progress={getWorkshopProgress:async(user,key)=>{assert.equal(key,workshop);calls.push(['read',user]);return structuredClone(state.get(user));},
 resetWorkshopProgress:async(user,key)=>{assert.equal(key,workshop);calls.push(['reset',user]);if(resetError)throw resetError;state.set(user,{objectives:[],count:0});},
 syncObjectiveComplete:async()=>assert.fail('Service must not write completion without Judge receipt')};
 const pool={query:async(sql,args)=>{assert.match(sql,/activity_count/);assert.deepEqual(args.slice(1),[workshop,'interact']);calls.push(['counter',args[0]]);return {rows:[{activity_count:state.get(args[0])?.count||0}]};}};
 const service=createPostgresPromptInjectionProgressService({pool,progress,config:{getSnapshot:async()=>({exercises:{[workshop]:exercise}})}});
 return {service,calls,state,exercise,failReset(error){resetError=error;}};
}
test('PostgreSQL progress derives visible canonical counts, timestamps and receipt-backed practice counter',async()=>{
 const f=fixture(),before=structuredClone(f.state),result=await f.service.getProgress(owner);
 assert.equal(result.objectiveCount,2);assert.equal(result.completedObjectiveCount,1);assert.equal(result.workshopStatus,'in_progress');
 assert.deepEqual(result.objectives.jailbreak,{completed:true,interactionCount:0,completedAt:'2026-08-05T10:00:00.000Z'});
 assert.deepEqual(result.objectives.interact,{completed:false,interactionCount:1,completedAt:null});assert.equal(result.objectives.ghost,undefined);
 assert.deepEqual(await f.service.getProgress(owner),result);assert.deepEqual(f.state,before);
 f.exercise.objectives.jailbreak.isVisible=false;assert.equal((await f.service.getProgress(owner)).completedObjectiveCount,0);
 f.state.get(71).objectives.push({id:'interact',completed:true,completedAt:'later'});f.state.get(71).count=2;
 assert.equal((await f.service.getProgress(owner)).workshopStatus,'completed');
});
test('owner identity and objective visibility deny before progress writes',async()=>{
 const f=fixture();
 for(const input of [{userId:0,userKey:'0'},{userId:71,userKey:'72'}])await assert.rejects(f.service.getProgress(input),error=>error instanceof PromptInjectionProgressError);
 assert.deepEqual(f.calls,[]);
 await assert.rejects(f.service.assertObjectiveEnabled('ghost'),error=>error.code==='UNKNOWN_OBJECTIVE');
 f.exercise.objectives.jailbreak.isVisible=false;
 await assert.rejects(f.service.completeObjective({...owner,objectiveId:'jailbreak'}),error=>error.code==='OBJECTIVE_DISABLED');
 f.exercise.isVisible=false;
 await assert.rejects(f.service.recordValidInteraction(owner),error=>error.code==='WORKSHOP_DISABLED');
 assert.deepEqual(await f.service.getProgress(owner),{objectives:{},objectiveCount:0,completedObjectiveCount:0,completed:false,workshopStatus:'not_started'});
 assert.deepEqual(f.calls,[]);
});
test('client completion and practice interactions cannot replace accepted Judge receipts',async()=>{
 const f=fixture(),before=structuredClone(f.state);
 await assert.rejects(f.service.completeObjective({...owner,objectiveId:'jailbreak',label:'untrusted label'}),error=>error.code==='JUDGED_ATTEMPT_REQUIRED'&&error.statusCode===409);
 await assert.rejects(f.service.recordValidInteraction(owner),error=>error.code==='JUDGED_ATTEMPT_REQUIRED');
 assert.deepEqual(f.state,before);assert.deepEqual(f.calls,[]);
});
test('reset delegates exactly one canonical owner scope, then reads current state without touching sibling',async()=>{
 const f=fixture(),sibling=structuredClone(f.state.get(72));
 const result=await f.service.resetProgress(owner);
 assert.equal(result.completedObjectiveCount,0);assert.equal(result.objectives.interact.interactionCount,0);
 assert.deepEqual(f.calls,[['reset',71],['read',71],['counter',71]]);assert.deepEqual(f.state.get(72),sibling);
});
test('canonical reset failure propagates without optimistic local clearing or followup reads',async()=>{
 const f=fixture(),before=structuredClone(f.state),error=Error('Controlled lifecycle fence rejection');f.failReset(error);
 await assert.rejects(f.service.resetProgress(owner),actual=>actual===error);
 assert.deepEqual(f.calls,[['reset',71]]);assert.deepEqual(f.state,before);
});
test('PostgreSQL factory rejects incomplete stores and retired SQLite constructor is absent',()=>{
 assert.throws(()=>createPostgresPromptInjectionProgressService({}),/PostgreSQL platform stores/);
 assert.equal(require('../server/services/promptInjectionProgressService').createPromptInjectionProgressService,undefined);
});
