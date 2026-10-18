'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash,randomUUID}=require('node:crypto');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {assertCanonicalCase,assertRegisteredAssessmentScope,assertForeignOperationConflict,mountMailDisclosureStatic,selectStandaloneDisclosureActors,standaloneDisclosureAssessmentDependencies,enableStandaloneDisclosureObjective,assertIdentityActivityVisible,observeIdentityLeaseWait,createStandaloneDisclosureScenes}=require('./postgres/secureshopMailBrowser.integration.test');
test('foreign saved mail operation is denied by exact SQL ownership conflict before browser work',()=>{
 const response={status:409,value:{ok:false,error:'Bound mail unavailable'}};
 assert.doesNotThrow(()=>assertForeignOperationConflict(response,[{code:'23505'}]));
 for(const bad of [{status:503,value:response.value},
  {status:409,value:{ok:false,error:'Bound mail unavailable',terminalRejected:true}}])
  assert.throws(()=>assertForeignOperationConflict(bad,[{code:'23505'}]));
 assert.throws(()=>assertForeignOperationConflict(response,[{code:'MAIL_EVIDENCE_UNAVAILABLE'}]));
 assert.throws(()=>assertForeignOperationConflict(response,[]));
});
test('registered assessment compares canonical launch identity from rich saved and active scopes',()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,
  platformOwnerId:17,platformSessionId:23};
 assert.doesNotThrow(()=>assertRegisteredAssessmentScope({...scope,credentialVersion:4,
  expiresAt:'2026-10-12T00:00:00.000Z'}, {...scope,status:'active',credentialVersion:5}));
 assert.throws(()=>assertRegisteredAssessmentScope({...scope,generation:4},scope));
 assert.throws(()=>assertRegisteredAssessmentScope({...scope,platformSessionId:24},scope));
 assert.throws(()=>assertRegisteredAssessmentScope({...scope,platformOwnerId:18},scope));
});
function fixture(){const html='<img src="owned">',receipt={runId:'run',ownerKey:'owner',generation:2,effectKey:'effect',status:'completed'};return {expected:{evaluationId:'evaluation',messageId:7,userId:3,html},snapshot:{judgments:[{evaluation_id:'evaluation',user_id:3,run_id:'run',packet:JSON.stringify({evidence:[{id:'mail_browser',content:{sendReceipt:{email_id:7},htmlSha256:createHash('sha256').update(html).digest('hex'),effectReceipt:receipt}}]})}],effects:[{run_id:'run',owner_key:'owner',generation:'2',effect_key:'effect',status:'completed'}]}};}
test('owned persisted packet binds exact saved bytes and completed effect',()=>{const f=fixture();assertCanonicalCase(f.snapshot,f.expected);});
test('foreign, missing, duplicate or incomplete effects cannot establish browser evidence',()=>{for(const change of [f=>f.snapshot.effects=[],f=>f.snapshot.effects.push({...f.snapshot.effects[0]}),f=>f.snapshot.effects[0].owner_key='other',f=>f.snapshot.effects[0].status='pending',f=>f.expected.html='changed',f=>f.expected.messageId=8,f=>f.expected.userId=4]){const f=fixture();change(f);assert.throws(()=>assertCanonicalCase(f.snapshot,f.expected));}});
test('opaque SecureShop frame receives CORS-enabled static modules without widening API CORS',async t=>{
 const build=fs.mkdtempSync(path.join(os.tmpdir(),'m23-static-'));
 fs.mkdirSync(path.join(build,'assets'));
 fs.writeFileSync(path.join(build,'index.html'),'<html>parent</html>');
 fs.writeFileSync(path.join(build,'secureshop-frame.html'),'<script type="module" crossorigin src="/assets/frame.js"></script>');
 fs.writeFileSync(path.join(build,'assets/frame.js'),'export const ready=true;');
 const express=require('express'),app=express();
 app.get('/api/check',(_request,response)=>response.json({ok:true}));
 mountMailDisclosureStatic(app,build,express);
 const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
 t.after(async()=>{await new Promise(resolve=>server.close(resolve));fs.rmSync(build,{recursive:true,force:true});});
 const origin=`http://127.0.0.1:${server.address().port}`;
 for(const route of ['/secureshop-frame.html','/assets/frame.js']){
  const response=await fetch(origin+route,{headers:{origin:'null'}});
  assert.equal(response.status,200);assert.equal(response.headers.get('access-control-allow-origin'),'*');
 }
 const api=await fetch(origin+'/api/check',{headers:{origin:'null'}});
 assert.equal(api.status,200);assert.equal(api.headers.get('access-control-allow-origin'),null);
});
test('stalled scene resolution records same-role waits and migration-visible locks',async t=>{
 const evidence=fs.mkdtempSync(path.join(os.tmpdir(),'m23-identity-wait-'));
 t.after(()=>fs.rmSync(evidence,{recursive:true,force:true}));
 const runtime={totalCount:4,idleCount:0,waitingCount:3};
 let observed=0,locked=0;
 const observer={async query(sql){observed++;assert.match(sql,/pg_blocking_pids\(pid\)/);
  assert.match(sql,/pg_stat_activity/);return {rows:[{pid:41,usename:'owned_runtime',
   state:'active',wait_event_type:'Lock',wait_event:'advisory',blocking_pids:[42]}]};}};
 const migration={async query(sql){locked++;assert.match(sql,/pg_locks/);
  return {rows:[{pid:41,locktype:'advisory',granted:false}]};}};
 const value=await observeIdentityLeaseWait({runtime,observer,migration,evidence,label:'merchant',afterMs:1,
  work:()=>new Promise(resolve=>setTimeout(()=>resolve('retained'),20))});
 assert.equal(value,'retained');assert.equal(observed,1);assert.equal(locked,1);
 const snapshot=JSON.parse(fs.readFileSync(path.join(evidence,
  'standalone-disclosure-identity-lease-merchant.json')));
 assert.deepEqual(snapshot.pool,{total:4,idle:0,waiting:3});
 assert.deepEqual(snapshot.activity[0].blocking_pids,[42]);
 assert.deepEqual(snapshot.locks,[{pid:41,locktype:'advisory',granted:false}]);
 assert.equal(fs.statSync(path.join(evidence,
  'standalone-disclosure-identity-lease-merchant.json')).mode&0o077,0);
});
test('identity activity preflight proves runtime-session state is visible to separate same-role pool',async()=>{
 let released=false;
 const runtime={async connect(){return {async query(){return {rows:[{pid:41,usename:'owned_runtime'}]};},
  release(){released=true;}};}};
 const observer={async query(sql,values){assert.match(sql,/pg_stat_activity/);
  assert.deepEqual(values,[41]);return {rows:[{pid:41,usename:'owned_runtime',
   state:'idle',backend_type:'client backend'}]};}};
 await assertIdentityActivityVisible({runtime,observer});assert.equal(released,true);
 await assert.rejects(assertIdentityActivityVisible({runtime,observer:{async query(){return {rows:[
  {pid:41,usename:'owned_runtime',state:null,backend_type:null}]};}}}));
});
test('standalone disclosure constructs its scene repository with the owned dedicated provision pool',()=>{
 let connects=0;
 const identity={async connect(){connects++;throw Error('Construction must not check out control');}};
 const provision={async connect(){connects++;throw Error('Construction must not check out provision');}};
 const lease={async connect(){connects++;throw Error('Construction must not check out graph lease');}};
 const review={async query(){throw Error('Construction must not query review');}};
 const launches={async assertCurrent(){throw Error('Construction must not check launch');}};
 const scenes=createStandaloneDisclosureScenes({identity,provision,lease,review,launches});
 assert.equal(typeof scenes.withProvisionLease,'function');assert.equal(connects,0);
 assert.throws(()=>createStandaloneDisclosureScenes({identity,lease,review,launches}),
  /Distinct scene control, provision, and graph lease pools required/);
});
test('standalone disclosure seeds only exact same-owner admitted mail actors',()=>{
 const principal=(name,id,role,tenantId='owned')=>({ownerId:17,tenantId,
  shopUserId:id,username:name,email:`${name}@example.invalid`,role});
 const principals={merchant:principal('merchant',1000000001,'merchant'),
  foreign:principal('foreign',1000000002,'customer'),
  empty:principal('empty',1000000003,'customer'),
  sibling:principal('sibling',1000000004,'merchant','peer')};
 const rows=Object.values(principals).slice(0,3).map(p=>({id:p.shopUserId,
  username:p.username,email:p.email,role:p.role}));
 const actors=selectStandaloneDisclosureActors(rows,principals);
 assert.equal(actors.foreign.id,1000000002);
 assert.equal(actors.empty.email,'empty@example.invalid');
 assert.equal(actors.sibling.id,1000000004);
 assert.throws(()=>selectStandaloneDisclosureActors(rows.filter(row=>row.id!==1000000002),principals),
  /foreign needs its exact admitted mail actor/);
 assert.throws(()=>selectStandaloneDisclosureActors(rows.map(row=>row.id===1000000002
  ?{...row,email:'other@example.invalid'}:row),principals),
  /foreign needs its exact admitted mail actor/);
 assert.throws(()=>selectStandaloneDisclosureActors([...rows,{id:1000000004,
  username:'sibling',email:'sibling@example.invalid',role:'merchant'}],principals),
  /Sibling must not appear in merchant mail actors/);
 assert.throws(()=>selectStandaloneDisclosureActors(rows,{...principals,
  foreign:{...principals.foreign,ownerId:19}}),/foreign must share the merchant scene owner/);
});
test('registered mail assessment uses tenant publication mode before legacy progress',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
  platformOwnerId:17,platformSessionId:23};
 let publicationReads=0,legacyReads=0;
 const grading={assessmentDependencies:{progress:{async getEvaluationScope(){legacyReads++;
  throw Error('Registered shop owner cannot enter workshop user_state');}}}};
 const modeRepository={async getEvaluationScope(ownerId,key,current){publicationReads++;
  assert.equal(ownerId,17);assert.equal(key,'secureshop_agent_security');
  assert.deepEqual(current,scope);
  return {generation:1,mode:'vuln',modeStamp:'tenant-mode-stamp'};}};
 const judge=async()=>{throw Error('No Judge in controlled mode projection');};
 const dependencies=standaloneDisclosureAssessmentDependencies({grading,judge,modeRepository});
 assert.equal(dependencies.publicationModes,modeRepository);
 assert.equal(dependencies.judge,judge);
 const publication=await require('../server/services/secureshopAssessmentPublicationScope')
  .captureAssessmentPublicationScope(dependencies.publicationModes,17,undefined,scope);
 assert.equal(publication.binding.mode,'vuln');await publication.assertCurrent();
 assert.equal(publicationReads,2);assert.equal(legacyReads,0);
 assert.throws(()=>standaloneDisclosureAssessmentDependencies({grading,judge}),
  /tenant-scoped publication modes/);
});
test('peer tenant disclosure probe enables the exact objective through its own administrator',async()=>{
 const admin={tenantId:randomUUID(),role:'admin'},objectiveId='ss_mail_cross_persona_read';
 const calls=[];
 const catalog={async list(actual){assert.equal(actual,admin);calls.push('list');
  return {objectives:[{objectiveId,enabled:false,revision:'1'}]};},
 async set(actual,input){assert.equal(actual,admin);calls.push('set');
  assert.deepEqual(input,{objectiveId,enabled:true,expectedRevision:'1'});
  return {objectiveId,enabled:true,revision:'2'};}};
 const enabled=await enableStandaloneDisclosureObjective({catalog,admin,objectiveId});
 assert.equal(enabled.enabled,true);assert.deepEqual(calls,['list','set']);
 await assert.rejects(enableStandaloneDisclosureObjective({catalog:{...catalog,
  async list(){return {objectives:[{objectiveId,enabled:true,revision:'2'}]};}},admin,objectiveId}),
 /Peer disclosure objective must begin disabled/);
 assert.deepEqual(calls,['list','set'],'Already-enabled branch must not mutate the catalog');
});
