'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPostgresWorkshopResetService}=require('../server/services/postgresWorkshopResetService');
const keys=['xss_email_builder','xss_workshop'];
function fixture(){
 const calls=[],begins=[],scopes=[];let cohort,fail=false;
 const journal={
  async begin(input){begins.push(input);if(!cohort)cohort={requestKind:input.requestKind,workshopKeys:input.workshopKeys,children:input.workshopKeys.map((workshopKey,ordinal)=>({workshopKey,ordinal,ownerId:7,childOperationId:`child-${ordinal}`,state:'pending'}))};return structuredClone(cohort);},
  async claim({ordinal,replaySafe}){assert.equal(replaySafe,true);cohort.children[ordinal].state='started';return{state:'started',leaseToken:'lease'};},
  async finish({ordinal,completed}){cohort.children[ordinal].state=completed?'completed':'uncertain';},
 };
 const service=createPostgresWorkshopResetService({
  adapters:Object.fromEntries(keys.map(key=>[key,{bulkResetReplaySafe:async()=>true,resetAdministrativeOwner:async(owner,input)=>{calls.push({key,owner,operationId:input.operationId});if(fail&&key==='xss_workshop'){fail=false;throw Error('controlled interruption');}}}])),
  bulkJournal:{withOperation:async(op,work)=>work(journal),listPending:async(authority,scope)=>{scopes.push({authority,scope});return[];}},
  resolveBulkActor:async()=>({actorId:2,sessionId:'3'}),
 });
 return{service,calls,begins,scopes,interrupt(){fail=true;}};
}
test('combined admin reset journals canonical family children in a single cohort and replays only unfinished children',async()=>{
 const f=fixture();f.interrupt();
 await assert.rejects(f.service.resetWorkshop({workshopKey:'xss_combined',operationId:'parent'}),/controlled interruption/);
 assert.deepEqual(f.begins[0],{operationId:'parent',requestKind:'workshop',workshopKeys:keys,actorId:2,sessionId:'3'});
 const result=await f.service.resetWorkshop({workshopKey:'xss_combined',operationId:'parent'});
 assert.deepEqual(result.workshopKeys,keys);assert(result.children.every(c=>c.state==='completed'));
 assert.deepEqual(f.calls,[{key:keys[0],owner:7,operationId:'child-0'},{key:keys[1],owner:7,operationId:'child-1'},{key:keys[1],owner:7,operationId:'child-1'}]);
 await f.service.resetWorkshop({workshopKey:'xss_combined',operationId:'parent'});assert.equal(f.calls.length,3);
});
test('single-family reset keeps its existing canonical scope',async()=>{
 const f=fixture();await f.service.resetWorkshop({workshopKey:'xss_workshop',operationId:'single'});
 assert.deepEqual(f.begins[0].workshopKeys,['xss_workshop']);assert.equal(f.calls.length,1);assert.equal(f.calls[0].key,'xss_workshop');
});
test('combined alias is not a student or individual administrative reset adapter and requires durable bulk storage',async()=>{
 const f=fixture();
 for(const method of ['resetStudent','resetAdministrativeStudent'])await assert.rejects(f.service[method]({workshopKey:'xss_combined',userId:7}),{code:'RESET_STORAGE_NOT_READY'});
 assert.throws(()=>f.service.assertSupported('xss_combined'),{code:'RESET_STORAGE_NOT_READY'});
 const service=createPostgresWorkshopResetService({adapters:{},listUserIds:async()=>assert.fail('must not use nondurable inventory')});
 await assert.rejects(service.resetWorkshop({workshopKey:'xss_combined',operationId:'combined'}),{code:'RESET_STORAGE_NOT_READY'});
});
test('pending combined recovery retains database scoped filtering before result limits',async()=>{
 const f=fixture(),scope={requestKind:'workshop',workshopKey:'xss_combined'};
 await f.service.listPendingBulkResets({scope});assert.deepEqual(f.scopes,[{authority:{actorId:2,sessionId:'3'},scope}]);
});
test('combined reset and recovery require upgraded readiness before journal admission',async()=>{
 const blocked=Object.assign(Error('Unified XSS reset requires pending database migration 0156'),{code:'RESET_STORAGE_NOT_READY'});
 const service=createPostgresWorkshopResetService({adapters:{},bulkJournal:{assertCombinedReady:async()=>{throw blocked;},withOperation:()=>assert.fail('no cohort'),listPending:()=>assert.fail('no pending lookup')},resolveBulkActor:async()=>({})});
 await assert.rejects(service.resetWorkshop({workshopKey:'xss_combined',operationId:'parent'}),error=>error===blocked);
 await assert.rejects(service.listPendingBulkResets({scope:{requestKind:'workshop',workshopKey:'xss_combined'}}),error=>error===blocked);
});
