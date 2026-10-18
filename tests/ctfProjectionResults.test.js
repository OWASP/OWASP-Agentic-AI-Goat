'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {buildCtfLifecycleCommand}=require('../server/services/ctfLifecycleCommands');
const {buildCtfProjectionResult:build,validateCtfProjectionResult:validate}=require('../server/services/ctfProjectionResults');
const command=buildCtfLifecycleCommand('start',{}, {actorId:'1',operationId:'11111111-1111-1111-1111-111111111111',occurredAt:'2026-09-26T00:00:00.000Z',scope:{ownerId:'1',ownerGeneration:'0',participantId:'2',stageId:'3',stageRevision:'0',progressId:null,globalRevision:'0'}});
const data={progressId:'4',status:'in_progress',startedAt:command.occurredAt,completedAt:null,completionTime:null,attemptsCount:0,failedAttempts:0,successfulAttempts:0,hintsUsed:0,hintPenaltyTotal:0};
test('strict receipt roundtrip retains exact canonical bytes and bigint sequence',()=>{
 const r=build(command,'9007199254740993',data);assert.deepEqual(validate(command,'9007199254740993',r.canonicalResult,r.resultHash),r);
});
test('wrong fields/types/impossible dates/completion contradictions fail before receipt write',()=>{
 for(const delta of [{unknown:1},{progressId:4},{startedAt:'2026-02-30T00:00:00.000Z'},{completedAt:command.occurredAt},{status:'completed'},{attemptsCount:-1}])assert.throws(()=>build(command,'1',{...data,...delta}));
});
test('different tuple, duplicate envelope key and changed bytes fail canonical replay',()=>{
 const r=build(command,'1',data);
 assert.throws(()=>validate(command,'2',r.canonicalResult,r.resultHash));
 assert.throws(()=>validate(command,'1',r.canonicalResult.replace('{','{"version":1,'),r.resultHash));
 assert.throws(()=>validate(command,'1',r.canonicalResult+' ',r.resultHash));
});

test('microsecond start and registration receipts preserve exact precision and old millisecond bytes',()=>{
 for(const startedAt of ['2026-09-26T00:00:00.123456Z','2026-09-26T00:00:00.123Z']){
  const r=build(command,'1',{...data,startedAt});assert.equal(r.value.data.startedAt,startedAt);assert.deepEqual(validate(command,'1',r.canonicalResult,r.resultHash),r);
 }
 const r=build(command,'1',{...data,status:'completed',startedAt:'2026-09-26T00:00:00.123456Z',completedAt:'2026-09-26T00:01:00.654321Z',completionTime:'60000'});assert.equal(r.value.data.completedAt,'2026-09-26T00:01:00.654321Z');
 const registration=buildCtfLifecycleCommand('register',{username:'owned',email:null,teamName:null,teachingSessionToken:'owned',clientIp:null,userAgent:null},{actorId:'1',operationId:command.operationId,occurredAt:command.occurredAt,scope:{...command.scope,participantId:null,stageId:null,stageRevision:null}});
 assert.equal(build(registration,'1',{admitted:true,reason:null,participantId:'2',recovered:true,active:true,banned:false,registeredAt:'2026-09-26T00:00:00.123456Z'}).value.data.registeredAt,'2026-09-26T00:00:00.123456Z');
 for(const startedAt of ['2026-02-30T00:00:00.123456Z','2026-09-26T24:00:00.123456Z','2026-09-26T00:00:00.1234Z','2026-09-26T00:00:00.1234567Z','2026-09-26T00:00:00.123456+00:00'])assert.throws(()=>build(command,'1',{...data,startedAt}));
 const changed=r.canonicalResult.replace('.123456Z','.123457Z');assert.throws(()=>validate(command,'1',changed,r.resultHash));
});
