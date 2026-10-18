'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPostgresWorkshopResetService}=require('../server/services/postgresWorkshopResetService');
const {createAdminWorkshopResetHandlers}=require('../server/services/adminWorkshopResetService');
function fixture(){
 const events=[];let failPreflight=false,failProgress=false;
 const adapter={requiresResetAuthority:true,async preflight(){events.push('preflight');if(failPreflight)throw Error('Controlled unavailable');},async reset(owner,work){events.push(['coordinator',owner]);return work({async check(){events.push('check');}});},async clear(owner){events.push(['clear',owner]);}};
 const service=createPostgresWorkshopResetService({adapters:{direct_prompt_injection:adapter},progress:{async resetWorkshopProgress(owner,key){events.push(['progress',owner,key]);if(failProgress)throw Error('Controlled canonical failure');}},withStudentResetAdmission:async(owner,work)=>{events.push(['admission',owner]);return work();}});
 return{service,events,failPreflight(){failPreflight=true;},failProgress(){failProgress=true;}};
}
const response=()=>({statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}});
test('actual PostgreSQL reset factory admits and fences only the requested owner before canonical reset',async()=>{
 const f=fixture();await f.service.resetStudent({userId:7,workshopKey:'direct_prompt_injection'});
 assert.deepEqual(f.events,['preflight',['admission',7],['coordinator','7'],'check',['clear','7'],'check',['progress',7,'direct_prompt_injection'],'check']);
});
test('invalid owner, missing adapter and failed preflight cannot clear challenge or progress',async()=>{
 const f=fixture();await assert.rejects(f.service.resetStudent({userId:-1,workshopKey:'direct_prompt_injection'}),{code:'AUTH_REQUIRED'});assert.deepEqual(f.events,[]);
 await assert.rejects(f.service.resetStudent({userId:7,workshopKey:'unknown'}),{code:'RESET_STORAGE_NOT_READY'});assert.deepEqual(f.events,[]);
 f.failPreflight();await assert.rejects(f.service.resetStudent({userId:7,workshopKey:'direct_prompt_injection'}),/Controlled unavailable/);assert.deepEqual(f.events,['preflight']);
});
test('canonical failure after challenge clear remains explicit partial failure without revision success',async()=>{
 const f=fixture();f.failProgress();const revisions=[],res=response();
 const handlers=createAdminWorkshopResetHandlers({service:f.service,recordChange:async change=>revisions.push(change),logger:{error(){}}});
 await handlers.resetStudent({params:{studentId:'7',workshopKey:'direct_prompt_injection'}},res);
 assert.equal(res.statusCode,503);assert.equal(res.body.success,false);assert.equal(res.body.code,'RESET_PARTIAL_FAILURE');assert.deepEqual(revisions,[]);assert(f.events.some(e=>Array.isArray(e)&&e[0]==='clear'));
});
test('retained handler publishes user and workshop revisions only after awaited reset',async()=>{
 const events=[],res=response();const handlers=createAdminWorkshopResetHandlers({service:{async resetStudent(input){await Promise.resolve();events.push(['reset',input]);}},recordChange:async change=>events.push(['revision',change])});
 await handlers.resetStudent({params:{studentId:'7',workshopKey:'direct_prompt_injection'}},res);
 assert.equal(res.body.success,true);assert.deepEqual(events,[['reset',{userId:7,workshopKey:'direct_prompt_injection'}],['revision',{type:'progressReset',targetUserId:7,workshopKey:'direct_prompt_injection'}],['revision',{type:'progressReset',workshopKey:'direct_prompt_injection'}]]);
});
test('retained bulk handler requires confirmation and preserves typed committed errors',async()=>{
 let calls=0;const handlers=createAdminWorkshopResetHandlers({service:{async resetAll(){calls++;throw Object.assign(Error('Lifecycle completion pending'),{statusCode:503,code:'RESET_PENDING',committed:true});}},recordChange:async()=>assert.fail('No success revision'),logger:{error(){}}});
 let res=response();await handlers.resetAll({body:{}},res);assert.equal(res.statusCode,400);assert.equal(calls,0);
 res=response();await handlers.resetAll({body:{confirmText:'RESET_ALL_PROGRESS'}},res);assert.equal(calls,1);assert.deepEqual(res.body,{success:false,error:'Lifecycle completion pending',code:'RESET_PENDING',committed:true});
 assert.equal(require('../server/services/adminWorkshopResetService').createAdminWorkshopResetService,undefined);
});
