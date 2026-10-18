'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createOwnedAuditSearchApplication}=require('../server/services/secureshopOwnedAuditSearchApplication');
test('bounded application admission rejects excess callers before target or SQL work and releases capacity',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;});let targets=0,queries=0;
 const binding={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:1,platformSessionId:2};
 const application=createOwnedAuditSearchApplication({launches:{assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>{await gate;return{user:{id:3,role:'admin'}};}},client:{target:async()=>{targets++;return{target:'audit_'+'a'.repeat(32),sourceSha256:'a'.repeat(64),payloadSha256:'b'.repeat(64)};}},manualAdapter:{execute:async()=>{queries++;return{ok:true};}},journal:{claim:async()=>{},complete:async()=>{},markUncertain:async()=>{}}});
 const input={scope:binding,persona:{id:3,role:'admin'},token:'fixture',operationId:'30000000-0000-4000-8000-000000000001',username:'admin'};
 const first=application.search(input),second=application.search(input);await assert.rejects(application.search(input),{code:'AUDIT_RUNTIME_BUSY'});assert.equal(targets,0);assert.equal(queries,0);release();await Promise.all([first,second]);await application.search(input);assert.equal(queries,3);
});

test('canonical fixed manual audit denies raw query before target provisioning or transport',async()=>{
 const {randomUUID}=require('node:crypto'),scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona={id:3,role:'admin'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 let effects=0;const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',generation:0,modeStamp:'first'})},launches:{assertCurrent:async()=>{}}});
 const app=createOwnedAuditSearchApplication({modeAuthority,launches:{assertCurrent:async()=>{}},personaAuth:{authenticateBoundToken:async()=>({user:persona,...personaSession})},personaAuthority:{capture:x=>({binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>work({})})},client:{target:async()=>{effects++;}},manualAdapter:{execute:async()=>{effects++;}},journal:{claim:async()=>{},complete:async()=>{},markUncertain:async()=>{}}});
 const result=await app.search({scope,persona,token:'owned',operationId:randomUUID(),username:'admin'});assert.equal(result.blocked,true);assert.equal(result.modeCapability.effectiveMode,'fixed');assert.equal(result.modeCapability.scope.platformOwnerId,undefined);assert.equal(effects,0);
});
