'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {createSecureShopAuditRunRepository}=require('../server/database/postgres/secureshopAuditRunRepository');

const sha=value=>createHash('sha256').update(value).digest('hex');
async function fixture(t,{readbackError,readbackReleaseError}={}){
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'audit-persona-repository-'));
  t.after(()=>fs.rm(directory,{recursive:true,force:true}));
  const data={log:Buffer.from('log'),sources:Buffer.from('[]'),messages:Buffer.from('[]'),traces:Buffer.from('[]'),effects:Buffer.from('[]')};
  await Promise.all(Object.entries(data).map(([name,bytes])=>fs.writeFile(path.join(directory,name==='log'?'log.txt':`${name}.json`),bytes)));
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:7,platformSessionId:8};
  const runId=randomUUID(),requestId=randomUUID();
  const manifest={runId,scope,requestedCount:2,rowCount:0,sourceBytes:data.log.length+data.sources.length,
    logSha256:sha(data.log),sourcesSha256:sha(data.sources)};
  const artifacts=Object.fromEntries(['messages','traces','effects'].map(name=>[name,{bytes:data[name].length,sha256:sha(data[name])}]));
  const input={scope,persona:{id:9,role:'admin'},requestId,execution:{runId,ownerKey:'owner',durableGeneration:3},effectKey:'effect',
    spool:{directory,manifest},result:{runId,provider:'ollama',model:'controlled',summary:'Controlled summary',logSha256:manifest.logSha256,
      sourcesSha256:manifest.sourcesSha256,rowCount:0,objectiveCredit:false,artifacts}};
  const events=[],publicationClient={async query(sql){events.push(`publication:${sql.split(/\s+/).slice(0,3).join(' ')}`);return{rows:[]};}};
  const readbackRow={run_id:runId,request_id:requestId,owner_key:'owner',durable_generation:'3',effect_key:'effect',requested_count:2,row_count:0,
    provider:'ollama',model:'controlled',summary:'Controlled summary',artifacts:Object.fromEntries(Object.entries(data).map(([name,bytes])=>
      [name,{bytes:bytes.length,sha256:sha(bytes)}]))};
  const reader={async query(){events.push('readback');if(readbackError)throw readbackError;return{rows:[readbackRow]};},release(){events.push('readback:release');if(readbackReleaseError)throw readbackReleaseError;}};
  const pool={async connect(){events.push('pool:connect');return reader;}};
  let currentChecks=0;
  const repository=createSecureShopAuditRunRepository({pool,checkCurrent:async()=>{currentChecks++;events.push('current');}});
  const binding={...scope,personaId:9,role:'admin',sessionId:randomUUID(),authorityVersion:'4'};
  let fenceCalls=0;
  const fence={binding,async withPersonaEffect(operation){fenceCalls++;events.push('fence:start');const value=await operation(publicationClient,binding);events.push('fence:commit');return value;}};
  return{input,scope,events,repository,fence,publicationClient,get currentChecks(){return currentChecks;},get fenceCalls(){return fenceCalls;}};
}

test('persona publication uses the fence client without nested transaction or current checks',async t=>{
  const f=await fixture(t);const result=await f.repository.publish(f.input,f.fence);
  assert.equal(result.published,true);assert.equal(f.fenceCalls,1);
  const fenceStart=f.events.indexOf('fence:start'),commit=f.events.indexOf('fence:commit');
  assert.ok(f.events.slice(0,fenceStart).every(event=>event==='current'));
  assert.equal(f.events.slice(fenceStart,commit).some(event=>event==='current'||event==='pool:connect'),false);
  assert.equal(f.events.some(event=>event.includes('BEGIN')||event.includes('COMMIT')||event.includes('ROLLBACK')),false);
  assert.equal(f.events.some(event=>event.includes("transaction_timeout='120s'")),true);
  assert.deepEqual(f.events.slice(commit+1),['pool:connect','readback','readback:release']);
});

test('mismatched or revoked persona authority performs no publication SQL',async t=>{
  const mismatch=await fixture(t);const foreign={...mismatch.fence,binding:{...mismatch.fence.binding,personaId:10}};
  await assert.rejects(mismatch.repository.publish(mismatch.input,foreign),{code:'SHOP_AUTH_INVALID'});
  assert.equal(mismatch.events.some(event=>event.startsWith('publication:')),false);
  const revoked=await fixture(t);revoked.fence.withPersonaEffect=async()=>{throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
  await assert.rejects(revoked.repository.publish(revoked.input,revoked.fence),{code:'SHOP_AUTH_INVALID'});
  assert.equal(revoked.events.some(event=>event.startsWith('publication:')),false);
});

test('pre-callback infrastructure failure remains distinguishable',async t=>{
  const f=await fixture(t),failure=Object.assign(new Error('authority store unavailable'),{code:'ECONNRESET'});
  f.fence.withPersonaEffect=async()=>{throw failure;};
  await assert.rejects(f.repository.publish(f.input,f.fence),error=>error===failure);
  assert.equal(f.events.some(event=>event.startsWith('publication:')),false);
});

test('lost commit acknowledgement after completed callback is uncertain',async t=>{
  const f=await fixture(t);f.fence.withPersonaEffect=async operation=>{await operation(f.publicationClient,f.fence.binding);throw new Error('commit acknowledgement lost');};
  await assert.rejects(f.repository.publish(f.input,f.fence),error=>error.code==='AUDIT_RUN_PUBLICATION_UNCERTAIN'
    &&error.cause?.message==='commit acknowledgement lost');
  assert.equal(f.events.some(event=>event.startsWith('publication:INSERT INTO secureshop_agents.bound_audit_run_publications')),true);
  assert.equal(f.events.includes('readback'),false);
});

test('postcommit readback failure is reported as uncertain',async t=>{
  const f=await fixture(t,{readbackError:new Error('readback unavailable')});
  await assert.rejects(f.repository.publish(f.input,f.fence),error=>error.code==='AUDIT_RUN_PUBLICATION_UNCERTAIN'
    &&error.executionBoundary===true&&error.cause?.message==='readback unavailable');
  assert.ok(f.events.includes('fence:commit'));assert.ok(f.events.includes('readback:release'));
});

test('postcommit readback release failure is also uncertain',async t=>{
  const f=await fixture(t,{readbackReleaseError:new Error('readback release failed')});
  await assert.rejects(f.repository.publish(f.input,f.fence),error=>error.code==='AUDIT_RUN_PUBLICATION_UNCERTAIN'
    &&error.cause?.message==='readback release failed');
  assert.ok(f.events.includes('fence:commit'));
});

test('default publication retains repository-owned transaction lifecycle',async t=>{
  const f=await fixture(t),events=[];
  const client={async query(sql){events.push(sql.trim().split(/\s+/)[0]);return{rows:[]};},release(error){events.push(error?'release:broken':'release');}};
  const repository=createSecureShopAuditRunRepository({pool:{async connect(){events.push('connect');return client;}},checkCurrent:async()=>{}});
  const result=await repository.publish(f.input);assert.equal(result.published,true);
  assert.equal(events[0],'connect');assert.equal(events[1],'BEGIN');assert.ok(events.includes('COMMIT'));
  assert.equal(events.at(-1),'release');assert.equal(events.includes('ROLLBACK'),false);
});
