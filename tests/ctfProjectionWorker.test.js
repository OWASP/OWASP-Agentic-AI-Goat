'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {withCtfTransaction}=require('../server/database/postgres/ctfLifecycleRepository');
const {projectCtfBatch}=require('../server/services/ctfProjectionWorker');
const {buildCtfLifecycleCommand}=require('../server/services/ctfLifecycleCommands');
const command=buildCtfLifecycleCommand('config_mutation',{key:'ctf_enabled',value:'true'},{actorId:'1',operationId:'11111111-1111-1111-1111-111111111111',occurredAt:'2026-09-26T00:00:00.000Z',scope:{ownerId:null,ownerGeneration:null,participantId:null,stageId:null,stageRevision:null,progressId:null,globalRevision:'0'}});
const event={command,sequence:'1',ownerGenerationAfter:null,registrationDisposition:null,registrationParticipantBefore:null};
function pool(){
 const trace=[];let borrowed=0,receipt=null,mutations=0,applied='0';
 const db={async connect(){borrowed++;return{release(){borrowed--;},async query(sql,args){trace.push(sql);
  if(sql.startsWith('SELECT * FROM ctf.projection_cursor'))return{rows:[{initialized:true,applied_sequence:applied}]};
  if(sql.startsWith('SELECT * FROM ctf.projection_receipts'))return{rows:receipt?[receipt]:[]};
  if(sql.startsWith('SELECT * FROM ctf.projection_scopes'))return{rows:[{scope_key:'global',revision:'0'}]};
  if(sql.startsWith('UPDATE ctf.ctf_config'))mutations++;
  if(sql.startsWith('INSERT INTO ctf.projection_receipts'))receipt={sequence:args[0],operation_id:args[1],command_hash:args[3],canonical_result:args[4],result_hash:args[5]};
  if(sql.startsWith('UPDATE ctf.projection_cursor'))applied=args[0];
  return{rows:[],rowCount:1};}};}};
 return{db,trace,borrowed:()=>borrowed,mutations:()=>mutations};
}
test('worker releases each store before acknowledgment and never automatically retries lost ack',async()=>{
 const p=pool();let tries=0;
 const identity={async next(){assert.equal(p.borrowed(),0);return event;},async acknowledge(){assert.equal(p.borrowed(),0);tries++;throw new Error('ack connection lost');}};
 await assert.rejects(projectCtfBatch({identity,ctfPool:p.db}),/ack connection lost/);
 assert.equal(tries,1);assert.equal(p.mutations(),1);assert.equal(p.borrowed(),0);
 // A separate explicit recovery call sees the stored receipt, not another effect.
 identity.acknowledge=async()=>({state:'applied'});
 await projectCtfBatch({identity,ctfPool:p.db,maxEvents:1});assert.equal(p.mutations(),1);
});
test('closed worker max events and blocked acknowledgment stop delivery',async()=>{
 const p=pool();let reads=0;
 const identity={async next(){reads++;return event;},async acknowledge(){return{state:'blocked'};}};
 const r=await projectCtfBatch({identity,ctfPool:p.db,maxEvents:4});assert.equal(reads,1);assert.equal(r[0].state,'blocked');
 await assert.rejects(projectCtfBatch({identity,ctfPool:p.db,maxEvents:17}),/bounds/);
});
test('late pool acquisition is released after finite timeout without executing work',async()=>{
 let resolve,released=0,worked=false;
 const db={connect:()=>new Promise(r=>{resolve=r;})};
 await assert.rejects(withCtfTransaction(db,()=>{worked=true;},{acquireMs:5,timeoutMs:30}),/interrupted/);
 resolve({release(discard){assert.equal(discard,true);released++;},query(){throw new Error('not reached');}});
 await new Promise(r=>setImmediate(r));assert.equal(released,1);assert.equal(worked,false);
});
test('cancellation discards connection and suppresses later SQL in interrupted transaction',async()=>{
 const c=new AbortController();let releases=0,queries=0,continueWork;
 const db={async connect(){return{release(discard){assert.equal(discard,true);releases++;},async query(){queries++;return{rows:[]};}};}};
 const run=withCtfTransaction(db,async client=>{await new Promise(r=>{continueWork=r;});await client.query('SHOULD_NOT_EXECUTE');},{signal:c.signal});
 while(!continueWork)await new Promise(r=>setImmediate(r));c.abort();await assert.rejects(run,/interrupted/);const count=queries;continueWork();
 await new Promise(r=>setImmediate(r));assert.equal(queries,count);assert.equal(releases,1);
});

test('no acknowledgment before CTF COMMIT and ambiguous COMMIT is not retried',async()=>{
 const p=pool();let commitStarted,finishCommit,acks=0,connects=0;
 const original=p.db.connect.bind(p.db);
 p.db.connect=async()=>{connects++;const client=await original(),query=client.query.bind(client);client.query=async(sql,args)=>{
  if(sql==='COMMIT'){commitStarted=true;await new Promise((_,reject)=>{finishCommit=()=>reject(new Error('ambiguous commit'));});}
  return query(sql,args);
 };return client;};
 const identity={async next(){return event;},async acknowledge(){acks++;return{state:'applied'};}};
 const run=projectCtfBatch({identity,ctfPool:p.db});
 while(!commitStarted)await new Promise(r=>setImmediate(r));assert.equal(acks,0);finishCommit();
 await assert.rejects(run,/ambiguous commit/);assert.equal(connects,1);assert.equal(acks,0);assert.equal(p.mutations(),1);assert.equal(p.borrowed(),0);
});
test('abort during pending acquisition discards eventual client and never runs callback',async()=>{
 const controller=new AbortController();let resolve,released=0;
 const db={connect:()=>new Promise(r=>{resolve=r;})};
 const run=withCtfTransaction(db,()=>assert.fail('work must not execute'),{signal:controller.signal});
 while(!resolve)await new Promise(r=>setImmediate(r));controller.abort();await assert.rejects(run,/interrupted/);
 resolve({release(discard){assert.equal(discard,true);released++;}});await new Promise(r=>setImmediate(r));assert.equal(released,1);
});
test('two workers serialize the same event and replay exact receipt under the database lock',async()=>{
 const p=pool(),original=p.db.connect.bind(p.db);let tail=Promise.resolve(),acks=0;
 p.db.connect=async()=>{
  const c=await original(),query=c.query.bind(c),release=c.release.bind(c);let unlock;
  c.query=async(sql,args)=>{if(sql.startsWith('SELECT pg_advisory_xact_lock')){const prior=tail;tail=new Promise(r=>{unlock=r;});await prior;}return query(sql,args);};
  c.release=(...args)=>{release(...args);unlock?.();};return c;
 };
 const identity={async next(){return event;},async acknowledge(){acks++;return{state:'applied'};}};
 const results=await Promise.all([projectCtfBatch({identity,ctfPool:p.db,maxEvents:1}),projectCtfBatch({identity,ctfPool:p.db,maxEvents:1})]);
 assert.equal(results.length,2);assert.equal(acks,2);assert.equal(p.mutations(),1);assert.equal(p.borrowed(),0);
});

test('forged registration disposition/generation tuple is rejected before any CTF query',async()=>{
 const {applyCtfProjection}=require('../server/database/postgres/ctfProjectionRepository');
 const registration=buildCtfLifecycleCommand('register',{username:'learner',email:null,teamName:null,teachingSessionToken:'synthetic',clientIp:null,userAgent:null},{actorId:'1',operationId:command.operationId,occurredAt:command.occurredAt,scope:{...command.scope,ownerId:'1',ownerGeneration:'5'}});
 const client={release(){},query(){assert.fail('forged tuple reached CTF');}};
 const good={command:registration,sequence:'1',ownerGenerationAfter:'6',registrationDisposition:'new',registrationParticipantBefore:null};
 for(const delta of [{ownerGenerationAfter:'5'},{registrationDisposition:'active_recovery'},{registrationParticipantBefore:'2'},{registrationDisposition:null}])await assert.rejects(applyCtfProjection(client,{...good,...delta}),/DRIFT/);
});

test('resumed progress receipt reads exact SQL clocks instead of truncated pg Date values',async()=>{
 const {applyCtfProjection}=require('../server/database/postgres/ctfProjectionRepository');
 const {types}=require('pg');
 for(const completed of [false,true]){
  const started='2026-09-26T00:00:00.123456Z',ended='2026-09-26T00:01:00.654321Z';
  const truncated=types.getTypeParser(1184)('2026-09-26 00:00:00.123456+00');assert.equal(truncated.toISOString(),'2026-09-26T00:00:00.123Z');
  const cmd=buildCtfLifecycleCommand('start',{}, {actorId:'1',operationId:command.operationId,occurredAt:command.occurredAt,scope:{ownerId:'1',ownerGeneration:'0',participantId:'2',stageId:'3',stageRevision:'0',progressId:null,globalRevision:'0'}});
  const ev={command:cmd,sequence:'1',ownerGenerationAfter:'0',registrationDisposition:null,registrationParticipantBefore:null};let stored=null,reads=0;
  const client={release(){},async query(sql,args){
   if(sql.startsWith('SELECT * FROM ctf.projection_cursor'))return{rows:[{initialized:true,applied_sequence:'0'}]};
   if(sql.startsWith('SELECT * FROM ctf.projection_receipts'))return{rows:stored?[stored]:[]};
   if(sql.startsWith('SELECT * FROM ctf.projection_scopes'))return{rows:[{scope_key:'global',revision:'0'},{scope_key:'stage:3',revision:'0'},{scope_key:'owner:1',revision:'0',owner_generation:'0'}]};
   if(sql.includes('FROM ctf.ctf_progress WHERE participant_id')){reads++;assert(sql.includes('SS.US'));assert(sql.includes('AS receipt_started_at'));assert(sql.includes('AS receipt_completed_at'));return{rows:[{id:4,status:completed?'completed':'in_progress',started_at:truncated,completed_at:completed?new Date(ended):null,receipt_started_at:started,receipt_completed_at:completed?ended:null,completion_time:completed?'60000':null,attempts_count:3,failed_attempts:0,successful_attempts:0,hints_used:0,hint_penalty_total:0}]};}
   if(sql.startsWith('INSERT INTO ctf.projection_receipts'))stored={sequence:args[0],operation_id:args[1],command_hash:args[3],canonical_result:args[4],result_hash:args[5]};
   return{rows:[],rowCount:1};
  }};
  const receipt=await applyCtfProjection(client,ev);assert.equal(receipt.value.data.startedAt,started);assert.equal(receipt.value.data.completedAt,completed?ended:null);const before=reads;assert.deepEqual(await applyCtfProjection(client,ev),receipt);assert.equal(reads,before);
 }
});
