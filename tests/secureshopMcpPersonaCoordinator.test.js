'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopMcpTrustCoordinator,createScenarioLaunches}=require('../server/services/secureshopMcpTrustProduction');
const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8};
const persona={id:3,role:'admin'},personaSession=Object.freeze({sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'2'});
const requestId='40000000-0000-4000-8000-000000000001';
function setup(){const calls=[],state={revoked:false};const denied=()=>Object.assign(Error('private-session-data'),{code:'SHOP_AUTH_INVALID'});
 const fence={async assertRemoteAdmission(){if(state.revoked)throw denied();}};
 const schema={serverIdentity:'owned-lab',version:1,schemaSha256:'a'.repeat(64)};
 const action=async(name,binding,passed)=>{calls.push([name,binding,passed]);assert.equal(passed,fence);await state.afterAction?.(name);return schema;};
 const features=Object.fromEntries(['rogue_registration','rug_pull'].map(name=>[name,{ready:true,application:{initialize:(...args)=>action('initialize',...args),rotate:(...args)=>action('rotate',...args)}}]));
 const application=createSecureShopMcpTrustCoordinator({launches:{assertCurrent:async()=>{}},availability:{read:async()=>{calls.push(['read']);await state.afterRead?.();return{visible:true,enabled:{rogue_registration:true}};},assertScenario:async()=>{}},features,
 conversations:{create:async()=>{calls.push(['conversation']);return{id:'owned-conversation'};}},checkCurrent:async()=>{},
 capturePersonaAuthority:async input=>{calls.push(['capture',input]);if(!input.personaSession||input.personaSession.sessionId!==personaSession.sessionId||input.personaSession.authorityVersion!==personaSession.authorityVersion)throw denied();return fence;},
 createRunner:()=>({run:async input=>{calls.push(['run',input]);await state.afterRun?.();return{text:'Owned result',stopReason:'end_turn'};}})});
 return{application,calls,state};}
const input={scope,persona,personaSession,trustScenario:'rogue_registration',requestId};
test('all coordinator actions require trusted session before target or model work',async()=>{
 for(const method of ['status','discover','rotate','run']){const f=setup();await assert.rejects(f.application[method]({...input,personaSession:undefined}),{code:'SHOP_AUTH_INVALID'});assert.deepEqual(f.calls.map(c=>c[0]),['capture']);}
});
test('verified session reaches runner and fence travels only as private application argument',async()=>{
 const f=setup();await f.application.run(input);const run=f.calls.find(c=>c[0]==='run')[1];assert.deepEqual(run.personaSession,personaSession);assert.ok(Object.isFrozen(run.personaSession));
 const binding=f.calls.find(c=>c[0]==='initialize')[1];assert.equal(binding.personaSession,undefined);assert.equal(binding.sessionId,undefined);assert.equal(JSON.stringify(run).includes('assertRemoteAdmission'),false);
});
test('session coordinates are snapshotted before asynchronous initialization',async()=>{
 const f=setup(),mutable={...personaSession};f.state.afterAction=()=>{mutable.sessionId='50000000-0000-4000-8000-000000000001';mutable.authorityVersion='9';};
 await f.application.run({...input,personaSession:mutable});assert.deepEqual(f.calls.find(c=>c[0]==='run')[1].personaSession,personaSession);
});
test('read-only status revocation fails auth, post-effect revocation remains uncertain',async()=>{
 const read=setup();read.state.afterRead=()=>{read.state.revoked=true;};await assert.rejects(read.application.status(input),{code:'SHOP_AUTH_INVALID'});
 for(const method of ['discover','rotate','run']){const f=setup();if(method==='run')f.state.afterRun=()=>{f.state.revoked=true;};else f.state.afterAction=()=>{f.state.revoked=true;};
 await assert.rejects(f.application[method](input),error=>error.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.executionBoundary===true&&error.cause.code==='SHOP_AUTH_INVALID'&&!JSON.stringify(error).includes('private-session-data'));}
});
test('scenario reservation forwards only explicitly supplied bounded options',async()=>{
 const calls=[],launches={assertCurrent:async()=>{},reserveMcpTarget:async(...args)=>{calls.push(args);return{};}},availability={assertScenario:async()=>{}};
 const bound=createScenarioLaunches(launches,availability,'rug_pull');await bound.reserveMcpTarget(scope,'rug_pull');await bound.reserveMcpTarget(scope,'rug_pull',{bounded:true});
 assert.equal(calls[0].length,2);assert.deepEqual(calls[1],[scope,'rug_pull',{bounded:true}]);
});
