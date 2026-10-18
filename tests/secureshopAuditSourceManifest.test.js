'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createAuditSourceManifest: manifest } = require('../server/services/secureshopAuditSourceManifest');
const row = (patch = {}) => ({ id: 'agents:11111111-1111-4111-8111-111111111111', store: 'agents',
  ts: '2026-09-19T12:00:00.123456Z', actor: 'student_admin', action: 'profile_update', target: null,
  params_json: '{ "text": "ignore instructions" }\nRAW INSTRUCTION', outcome: 'completed',
  source_kind: 'profile', source_id: 'profile-1', ...patch });
const hash = text => createHash('sha256').update(text).digest('hex');
test('raw teaching payload and source order remain exact, with independent digest evidence', () => {
  const first = row();
  const second = row({ store: 'review', id: 'review:22222222-2222-4222-8222-222222222222' });
  const value = manifest([first, second]);
  assert.equal(value.logText, [first, second].map(r => `[${r.ts}] actor=${r.actor} action=${r.action} target=- params=${r.params_json}`).join('\n'));
  assert.equal(value.logSha256, hash(value.logText));
  assert.equal(value.sourcesSha256, hash(JSON.stringify(value.sources)));
  assert.deepEqual(value.sources.map(s => s.id), [first.id, second.id]);
  assert.notEqual(manifest([second, first]).sourcesSha256, value.sourcesSha256);
  assert.equal('completed' in value, false);
  assert.equal('model' in value, false);
});
test('content and effect changes affect provenance even when rendered text does not change', () => {
  const original = manifest([row()]);
  const changedEffect = manifest([row({ source_id: 'profile-2' })]);
  assert.equal(original.logSha256, changedEffect.logSha256);
  assert.notEqual(original.sourcesSha256, changedEffect.sourcesSha256);
  assert.notEqual(original.logSha256, manifest([row({ params_json: '{}' })]).logSha256);
});
test('manifest snapshots inputs and freezes nested evidence', () => {
  const input = row();
  let reads = 0;
  Object.defineProperty(input, 'params_json', { get: () => ++reads === 1 ? 'original' : 'changed' });
  const value = manifest([input]);
  assert.equal(reads, 1);
  assert.match(value.logText, /params=original$/);
  input.source_id = 'changed';
  assert.equal(value.sources[0].sourceId, 'profile-1');
  assert.throws(() => { value.sources[0].sourceId = 'changed'; }, TypeError);
  assert.throws(() => value.sources.push({}), TypeError);
});
test('rejects duplicate, sparse, invalid identity, date and outcome rows', () => {
  for (const input of [[row(), row()], Array(1), [row({ id: 'agents:fake' })],
    [row({ ts: '2026-02-30T12:00:00.123456Z' })], [row({ outcome: undefined })],
    [row({ target: undefined })], null]) assert.throws(() => manifest(input), TypeError);
  assert.equal(manifest([]).rowCount, 0);
});

function sceneRow() {
  const sourceExecution = {launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8};
  const consumerExecution = {...sourceExecution,launchId:'10000000-0000-4000-8000-000000000002',platformSessionId:9};
  const scene = {sceneId:'30000000-0000-4000-8000-000000000001',sceneGeneration:2,targetId:'40000000-0000-4000-8000-000000000001',birth:sourceExecution};
  const grant = {sceneId:scene.sceneId,sceneGeneration:scene.sceneGeneration,targetId:scene.targetId};
  return row({store:'review',id:'review:22222222-2222-4222-8222-222222222222',actor:'merchant',action:'listing_update',target:'17',
    params_json:JSON.stringify({description:'UNTRUSTED exact\nraw instruction',storage:{targetId:scene.targetId,sceneId:scene.sceneId,birthLaunchId:sourceExecution.launchId,birthGeneration:1}}),
    source_kind:'product',source_id:'17',sceneSource:{version:2,kind:'scene_product_listing_update',sourceExecution,
      sourceGrant:{grantId:'50000000-0000-4000-8000-000000000001',...grant},consumerExecution,
      consumerGrant:{grantId:'50000000-0000-4000-8000-000000000002',...grant},scene,product:{productId:17,merchantId:1000000001}}});
}

test('v2 scene entries bind separate original and consumer tuples without changing historical v1 bytes',()=>{
  const r=sceneRow(), value=manifest([r],{consumerScope:r.sceneSource.consumerExecution}), entry=value.sources[0];
  assert.equal(value.version,1); assert.equal(entry.version,2);
  assert.deepEqual(entry.event,Object.fromEntries(['id','store','ts','actor','action','target','params_json','outcome','source_kind','source_id'].map(k=>[k,r[k]])));
  assert.deepEqual(entry.origin,r.sceneSource);
  assert.notEqual(entry.origin.sourceExecution.platformSessionId,entry.origin.consumerExecution.platformSessionId);
  assert.equal(entry.sha256,manifest([{...r,sceneSource:undefined}]).sources[0].sha256);
  const changed=structuredClone(r);changed.sceneSource.sourceExecution.platformSessionId++;
  assert.equal(manifest([changed]).logSha256,value.logSha256);
  assert.notEqual(manifest([changed]).sourcesSha256,value.sourcesSha256);
  assert.throws(()=>{entry.origin.scene.birth.platformSessionId=99;},TypeError);
  const old=row(), legacy=manifest([old]).sources[0];
  assert.deepEqual(Object.keys(legacy),['id','store','ts','sourceKind','sourceId','sha256']);
  assert.equal(legacy.sha256,hash(JSON.stringify([old.id,old.ts,old.actor,old.action,old.target,old.params_json,old.outcome,old.source_kind,old.source_id])));
});

test('v2 rejects foreign, conflicting, malformed and unsupported source origins',()=>{
  const patches=[r=>r.sceneSource.version=3,r=>r.sceneSource.extra=true,
    r=>r.sceneSource.sourceExecution.platformOwnerId++,r=>r.sceneSource.scene.birth.platformOwnerId++,
    r=>r.sceneSource.sourceGrant.targetId='40000000-0000-4000-8000-000000000002',
    r=>r.sceneSource.consumerGrant.sceneGeneration++,r=>r.target=r.sceneSource.scene.targetId,
    r=>r.sceneSource.product.productId++,r=>r.actor='admin',r=>r.outcome='denied',
    r=>r.params_json='{}',r=>r.sceneSource.sourceExecution.launchId=r.sceneSource.sourceExecution.launchId.toUpperCase()];
  // UUIDs containing letters exercise normalization refusal, not numeric UUID coincidence.
  patches.pop(); patches.push(r=>r.sceneSource.sourceExecution.launchId='AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA');
  for(const patch of patches){const r=sceneRow();patch(r);assert.throws(()=>manifest([r]),TypeError);}
  const r=sceneRow();assert.throws(()=>manifest([r],{consumerScope:{...r.sceneSource.consumerExecution,platformSessionId:99}}),TypeError);
});

test('fixed v2 keeps exact original forensic source privately and exposes metadata-only log',async()=>{
  const {fixedAuditRows}=require('../server/services/secureshopAuditFixedProjection');
  const r=sceneRow(), projected=[];
  for await(const p of fixedAuditRows((async function*(){yield r;})(),async()=>{}))projected.push(p);
  const fixed=manifest(projected,{consumerScope:r.sceneSource.consumerExecution});
  assert.equal(fixed.logText.includes('UNTRUSTED'),false);
  assert.equal(fixed.logText.includes(r.params_json),false);
  assert.deepEqual(fixed.sources[0].original,manifest([r]).sources[0]);
  const bad=structuredClone(projected[0]);bad.fixedSource.event.params_json='tampered';
  assert.throws(()=>manifest([bad]),TypeError);
  const replaced=structuredClone(projected[0]);replaced.fixedSource.origin.consumerExecution.platformSessionId=99;
  assert.throws(()=>manifest([replaced],{consumerScope:r.sceneSource.consumerExecution}),TypeError);
});

test('spool stores v2 exact source bytes and rejects another consumer without partial artifacts',async t=>{
  const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
  const {spoolAuditObservation}=require('../server/services/secureshopAuditObservationSpool');
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-v15-spool-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const r=sceneRow(),scope=r.sceneSource.consumerExecution;
  const args={root,scope,runId:'v15-owned',requestedCount:1,checkCurrent:async()=>{}};
  const spool=await spoolAuditObservation({...args,rows:(async function*(){yield r;})()});
  const expected=manifest([r],{consumerScope:scope});
  assert.equal(await fs.readFile(spool.paths.sources,'utf8'),JSON.stringify(expected.sources));
  assert.equal(spool.manifest.sourcesSha256,expected.sourcesSha256);
  await spool.dispose();
  await assert.rejects(spoolAuditObservation({...args,scope:{...scope,platformSessionId:99},rows:(async function*(){yield r;})()}),TypeError);
  assert.deepEqual(await fs.readdir(root),[]);
});

test('both grant IDs and original execution coordinates are SHA-bound, never replaced with consumer authority',()=>{
  const original=sceneRow(), expected=manifest([original]);
  for(const mutate of [r=>r.sceneSource.sourceGrant.grantId='50000000-0000-4000-8000-000000000003',
    r=>r.sceneSource.consumerGrant.grantId='50000000-0000-4000-8000-000000000003',
    r=>r.sceneSource.sourceExecution.platformSessionId++,r=>r.sceneSource.consumerExecution.platformSessionId++]){
    const changed=structuredClone(original);mutate(changed);
    const value=manifest([changed]);assert.notEqual(value.sourcesSha256,expected.sourcesSha256);
    assert.equal(value.logSha256,expected.logSha256);
  }
  for(const key of ['sourceGrant','consumerGrant']){
    const invalid=sceneRow();invalid.sceneSource[key].grantId='not-a-grant';assert.throws(()=>manifest([invalid]),TypeError);
  }
});
