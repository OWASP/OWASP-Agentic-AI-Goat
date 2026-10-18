'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfBlockedPredefenseRepository}=require('../server/database/postgres/ctfBlockedPredefenseRepository');
const {buildCtfLifecycleCommand,canonicalCtfJson}=require('../server/services/ctfLifecycleCommands');
const runId='00000000-0000-0000-0000-000000000001',operationId='00000000-0000-0000-0000-000000000002',session={actorId:'7',sessionId:'8',rawToken:'synthetic'};
function fixture({mismatch=false,fail=false}={}){const calls=[],body={admissionOperationId:runId,matchedPayloadHash:null,attemptNumber:1,payload:'synthetic 🌍 payload',response:null,responseTime:0,teachingSessionToken:null,techniqueTag:'other',techniqueConfidence:1e-7,reason:'Blocked "input"\nfixture',payloadHash:null};const {commandHash,...command}=buildCtfLifecycleCommand('record_blocked_attempt',body,{actorId:'7',operationId,occurredAt:'2026-09-27T00:00:00.000Z',scope:{ownerId:'7',ownerGeneration:'1',globalRevision:'0',stageRevision:'0',stageId:'1',participantId:'9',progressId:'10'}});let borrows=0;const pool={async connect(){borrows++;return{async query(sql,args){calls.push({sql,args});if(sql.includes('prepare_'))return{rows:[{value:{operationId:mismatch?runId:operationId,command,replayed:false,currentState:false}}]};if(sql.includes('enqueue_')){if(fail)throw Object.assign(Error('SQL denied'),{code:'42501'});return{rows:[{value:{operationId,replayed:false,currentState:false}}]};}return{rows:[]};},release(){}};}};return{pool,calls,command,get borrows(){return borrows;}};}
test('same transaction validates SQL-derived body and uses JS exact Unicode/numeric canonical bytes',async()=>{const f=fixture();assert.equal((await createCtfBlockedPredefenseRepository(f.pool).enqueueFromClaim({runId,session})).operationId,operationId);assert.equal(f.borrows,1);const q=f.calls.find(c=>c.sql.includes('enqueue_'));assert.equal(q.args[4],canonicalCtfJson(f.command));assert(q.args[4].includes('1e-7'));assert.equal(f.calls.filter(c=>c.sql==='COMMIT').length,1);});
test('mismatched reserved operation denies before enqueue and rolls back',async()=>{const f=fixture({mismatch:true});await assert.rejects(createCtfBlockedPredefenseRepository(f.pool).enqueueFromClaim({runId,session}),/PREPARATION_INVALID/);assert(!f.calls.some(c=>c.sql.includes('enqueue_')));assert(f.calls.some(c=>c.sql==='ROLLBACK'));});
test('SQL rejection cannot trigger another command or callback retry',async()=>{const f=fixture({fail:true});await assert.rejects(createCtfBlockedPredefenseRepository(f.pool).enqueueFromClaim({runId,session}),{code:'42501'});assert.equal(f.calls.filter(c=>c.sql.includes('enqueue_')).length,1);assert(!f.calls.some(c=>c.sql==='COMMIT'));});
test('forward SQL repair changes only blocked expected-key ordering and preserves every exact key set',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const read=name=>fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations',name),'utf8');
 const previous=read('0105_ctf_lifecycle_projection.sql'),forward=read('0114_ctf_blocked_predefense_command.sql');
 const extract=(source,prefix)=>{const start=source.indexOf(prefix+' identity.enqueue_ctf_user_command(');assert(start>=0);const end=source.indexOf('\nEND; $$;',start);assert(end>start);return source.slice(start,end+10);};
 const before=extract(previous,'CREATE FUNCTION'),after=extract(forward,'CREATE OR REPLACE FUNCTION');
 const old="'responseTime','techniqueConfidence','techniqueTag','teachingSessionToken'",fixed="'responseTime','teachingSessionToken','techniqueConfidence','techniqueTag'";
 assert.equal(after,before.replace('CREATE FUNCTION','CREATE OR REPLACE FUNCTION').replace(old,fixed));
 const line=after.split('\n').find(line=>line.trim().startsWith('expected_keys:=CASE'));
 for(const match of line.matchAll(/WHEN '([^']+)' THEN ARRAY\[([^\]]*)\]/g)){
  const keys=[...match[2].matchAll(/'([^']+)'/g)].map(item=>item[1]);
  assert.deepEqual(keys,[...keys].sort(),match[1]);assert.equal(new Set(keys).size,keys.length);
 }
 const blocked=[...line.match(/WHEN 'record_blocked_attempt' THEN ARRAY\[([^\]]*)\]/)[1].matchAll(/'([^']+)'/g)].map(item=>item[1]);
 assert.deepEqual(blocked,Object.keys(fixture().command.body).sort());
});
