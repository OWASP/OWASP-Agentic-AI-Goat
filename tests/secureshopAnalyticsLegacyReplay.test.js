'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {EventEmitter}=require('node:events');
const {createOwnedAnalyticsService}=require('../sidecars/analytics-sql-target/service');
const {request,hash}=require('../sidecars/analytics-sql-target/contract');

const uuid=n=>`${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`;
const identity={systemIdentifier:'123456789012',controlDatabase:'dvaia_analytics_control_123456abcdef',clusterName:'dvaia-owned-analytics-123456abcdef'};
const scope={launchId:uuid(1),scenarioId:uuid(2),generation:1,platformOwnerId:11,platformSessionId:12};
const target={targetId:uuid(3),scope,sourceManifestSha256:'a'.repeat(64)};
const input={target,operationId:uuid(4),runId:uuid(5),requestId:uuid(6),sessionId:uuid(7),callId:'call-1',sql:'SELECT 1'};
const legacyHash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');

function fixture(row){
 let connects=0,queries=0;
 const client=Object.assign(new EventEmitter(),{
  async query(sql){
   if(sql.includes('pg_try_advisory_lock'))return{rows:[{held:true}]};
   if(sql.includes('pg_advisory_unlock'))return{rows:[{released:true}]};
   if(sql.startsWith('SELECT target_id,scope,source_manifest_sha256,state'))return{rows:[{target_id:target.targetId,scope:target.scope,source_manifest_sha256:target.sourceManifestSha256,state:'ready'}]};
   if(sql.startsWith('SELECT request_sha256,state,receipt,result_sha256')){queries++;return{rows:[row]};}
   throw Error('Unexpected journal query: '+sql);
  },release(){}
 });
 const controlPool={async connect(){connects++;return client;},async query(sql){
  if(sql.includes('pg_control_system'))return{rows:[{database:identity.controlDatabase,cluster:identity.clusterName,system_identifier:identity.systemIdentifier}]};
  if(sql.includes('FROM pg_database'))return{rows:[{datname:identity.controlDatabase,datallowconn:true,public_connect:false}]};
  throw Error('Unexpected control query: '+sql);
 }};
 const service=createOwnedAnalyticsService({controlPool,identity,createPool(){throw Error('SQL must not execute on replay');},connection:{host:'controlled.invalid'}});
 return{service,counts:()=>({connects,queries})};
}

test('completed pre-canonical Analytics operation replays without SQL; changed request conflicts',async()=>{
 const historical=legacyHash(request(input));
 assert.notEqual(historical,hash(request(input)));
 const receipt={version:1,operationId:input.operationId,result:{sql:input.sql,rows:[]}};
 const f=fixture({request_sha256:historical,state:'completed',receipt,result_sha256:'b'.repeat(64)});
 assert.strictEqual(await f.service.execute(input),receipt);
 await assert.rejects(f.service.execute({...input,sql:'SELECT 2'}),{code:'ANALYTICS_QUERY_CONFLICT'});
 await assert.rejects(f.service.execute({...input,target:{...target,scope:{...scope,platformOwnerId:99}}}),{code:'ANALYTICS_TARGET_INVALID'});
 await assert.rejects(f.service.execute({...input,target:{...target,scope:{...scope,platformSessionId:99}}}),{code:'ANALYTICS_TARGET_INVALID'});
 await assert.rejects(f.service.execute({...input,mode:{version:1,mode:'fixed',generation:1,modeStamp:'changed'}}),{code:'ANALYTICS_QUERY_CONFLICT'});
 assert.deepEqual(f.counts(),{connects:5,queries:3});
 const current=fixture({request_sha256:hash(request(input)),state:'completed',receipt,result_sha256:'b'.repeat(64)});
 assert.strictEqual(await current.service.execute(input),receipt);
 assert.deepEqual(current.counts(),{connects:1,queries:1});
});

test('matching pre-canonical pending Analytics operation stays uncertain without SQL',async()=>{
 const f=fixture({request_sha256:legacyHash(request(input)),state:'pending',receipt:null,result_sha256:null});
 await assert.rejects(f.service.execute(input),{code:'ANALYTICS_QUERY_UNCERTAIN'});
 assert.deepEqual(f.counts(),{connects:1,queries:1});
});
