'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createMailDisclosureEvidenceRepository,buildMailDisclosureCandidate}=require('../server/services/secureshopMailDisclosureEvidence');
function fixture(){
 const b={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},targetId:randomUUID(),persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',operationId:randomUUID()};
 const r={userId:3,messages:[{id:10,sha256:'b'.repeat(64)}]},recovered={found:true,action:'read',operationId:b.operationId,requestSha256:'a'.repeat(64),receipt:r};
 const snapshot={operationId:b.operationId,replayed:true,receipt:r,emails:[{id:10,body_markdown:'owned synthetic private message'}]};
 const state={valid:true,checks:0,stale:false,calls:[]};
 const authority={capture(x){return {binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},async assertRemoteAdmission(){if(++state.checks===2&&state.stale)throw Error('reset');},async withPersonaEffect(fn){return fn({async query(sql,args){if(args){assert.match(sql,/jsonb_build_array\('read'/);assert.deepEqual(args,[3,'a'.repeat(64)]);return {rows:[{valid:state.valid}]};}return {rows:[]};}});}};}};
 const repo=createMailDisclosureEvidenceRepository({personaAuthority:authority,mailRepository:{async recover(x){state.calls.push('recover');assert.deepEqual(x,b);return recovered;},async read(x,id){state.calls.push('read');assert.deepEqual(x,b);assert.equal(id,3);return snapshot;}}});
 return {b,r,recovered,snapshot,state,repo};
}
test('exact saved read replay and database-side request digest produce manual disclosure packet',async()=>{const f=fixture(),e=await f.repo.readDisclosure(f.b),p=buildMailDisclosureCandidate(e);assert.deepEqual(f.state.calls,['recover','read']);assert.equal(p.facts.foreign_persona_mailbox,true);assert.equal(p.evidence[0].content.messages[0].body_markdown,'owned synthetic private message');assert.equal(f.state.checks,2);});
test('missing, own, empty, duplicate, wrong action, operation or hash evidence rejected',async()=>{for(const mutate of [f=>f.recovered.found=false,f=>f.r.userId=2,f=>f.r.messages=[],f=>f.r.messages.push({...f.r.messages[0]}),f=>f.recovered.action='send',f=>f.recovered.operationId=randomUUID(),f=>f.state.valid=false,f=>f.snapshot.replayed=false,f=>f.snapshot.emails=[],f=>f.snapshot.emails.push({...f.snapshot.emails[0]})]){const f=fixture();mutate(f);await assert.rejects(f.repo.readDisclosure(f.b));}});
test('fixed mode and final reset reject',async()=>{const f=fixture();f.b.mode='fixed';await assert.rejects(f.repo.readDisclosure(f.b));assert.deepEqual(f.state.calls,[]);const g=fixture();g.state.stale=true;await assert.rejects(g.repo.readDisclosure(g.b),/reset/);});
test('qualified release still rejects oversized exact packet is not silently truncated',async()=>{const f=fixture(),e=await f.repo.readDisclosure(f.b);e.messages[0].body_markdown='x'.repeat(100000);assert.equal(buildMailDisclosureCandidate(e),null);assert.equal(require('../server/services/secureshopMailObjectiveReadiness').MAIL_OBJECTIVE_QUALIFICATION.ss_mail_cross_persona_read,true);});
test('scene-backed disclosure preserves the private target grant through normalization and readback',async()=>{
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const mailScene=require('../server/services/secureshopMailSceneBinding');
 const f=fixture(),birth={...f.b.scope,targetId:f.b.targetId},current={...f.b.scope,launchId:randomUUID(),scenarioId:randomUUID(),platformSessionId:9};
 let leases=0,grants=0;
 const scene=createSceneBinding({...birth,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:current,
   withLease:async work=>{leases++;return work();}});
 const target=mailScene.attach(birth,scene);
 const raw={...f.b,scope:current,target};
 const receipt={userId:3,messages:[{id:10,sha256:'b'.repeat(64)}]};
 const authority={capture(x){return {binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},
  async assertRemoteAdmission(){},async withPersonaEffect(work){return work({async query(sql){
   if(sql.includes('assert_mail_scene_execution_grant')){grants++;return {rows:[{allowed:true}]};}
   if(sql.includes('jsonb_build_array'))return {rows:[{valid:true}]};
   return {rows:[]};}});}};}};
 const mailRepository={async recover(binding){assert.equal(binding.target,target);return {found:true,action:'read',operationId:raw.operationId,requestSha256:'a'.repeat(64),receipt};},
  async read(binding){assert.equal(binding.target,target);return {operationId:raw.operationId,replayed:true,receipt,emails:[{id:10,body_markdown:'owned synthetic message'}]};}};
 const evidence=await createMailDisclosureEvidenceRepository({personaAuthority:authority,mailRepository}).readDisclosure(raw);
 assert.equal(mailScene.productScene(evidence.binding),scene);
 assert.equal(leases,1);
 assert.equal(grants,2);
});
