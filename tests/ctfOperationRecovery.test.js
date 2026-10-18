'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {createCtfOperationRecoveryRepository}=require('../server/database/postgres/ctfOperationRecoveryRepository');
const {buildCtfLifecycleCommand,canonicalCtfJson}=require('../server/services/ctfLifecycleCommands');
const {buildCtfProjectionResult}=require('../server/services/ctfProjectionResults');
const op='00000000-0000-0000-0000-000000000001',args={operationId:op,session:{actorId:7,sessionId:8,rawToken:'original'}};
const command=buildCtfLifecycleCommand('ban',{reason:'fixture'},{operationId:op,actorId:'7',occurredAt:'2026-09-27T00:00:00.000Z',scope:{ownerId:'9',ownerGeneration:'0',globalRevision:'0',stageId:null,stageRevision:null,progressId:null,participantId:null}});
const {commandHash,...content}=command,receipt=buildCtfProjectionResult(command,'1',{ownerId:'9',banned:true});
const row={actorId:'7',sessionId:'8',state:'applied',sequence:'1',currentState:false,canonicalCommand:canonicalCtfJson(content),commandHash,canonicalResult:receipt.canonicalResult,resultHash:receipt.resultHash};
function f(value=row,error){const calls=[];return{calls,repo:createCtfOperationRecoveryRepository({async connect(){return{async query(sql,params){calls.push({sql,params});if(params&&error)throw error;return{rows:[{operation:value}]};},release(){}};}})};}
test('exact receipt remains historical and binds original token/session',async()=>{const x=f(),r=await x.repo.readAuthorized(args);assert.equal(r.currentState,false);assert.deepEqual(r.command,command);assert.deepEqual(x.calls.find(v=>v.params).params,[op,7,8,createHash('sha256').update('original').digest('hex')]);assert.equal(x.calls.at(-1).sql,'COMMIT');});
test('unknown/foreign SQL null is nonleaking; authorization errors are not pending',async()=>{assert.equal(await f(null).repo.readAuthorized(args),null);for(const code of ['28000','42501']){const error=Object.assign(Error('denied'),{code});await assert.rejects(f(null,error).repo.readAuthorized(args),e=>e===error);}});
test('wrong session, changed command bytes/hash and forged receipt reject',async()=>{for(const changed of [{sessionId:'99'},{currentState:true},{canonicalCommand:row.canonicalCommand+' '},{resultHash:'f'.repeat(64)},{canonicalResult:null}])await assert.rejects(f({...row,...changed}).repo.readAuthorized(args));});
test('pending operation is readable but cannot masquerade as a receipt',async()=>{const r=await f({...row,state:'pending',canonicalResult:null,resultHash:null}).repo.readAuthorized(args);assert.equal(r.state,'pending');assert.equal(r.currentState,false);assert.equal(r.canonicalResult,null);});

test('blocked operation is historical only with no invented applied receipt',async()=>{const r=await f({...row,state:'blocked',canonicalResult:null,resultHash:null}).repo.readAuthorized(args);assert.equal(r.state,'blocked');assert.equal(r.currentState,false);assert.equal(r.canonicalResult,null);});
