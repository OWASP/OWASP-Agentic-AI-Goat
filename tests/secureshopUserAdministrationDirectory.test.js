'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createSecureShopBoundUserAdministration:create}=require('../server/services/secureshopBoundUserAdministration');
function fixture(){const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},input={scope,persona:{id:13,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'3'},operationId:randomUUID(),targetId:11,expectedVersion:'1',action:'set_role',role:'merchant'};let revoked=false;const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};const authority={capture:async v=>({binding:{...v.scope,personaId:v.personaId,role:v.role,sessionId:v.sessionId,authorityVersion:v.authorityVersion},assertRemoteAdmission:check,withPersonaEffect:async work=>work({}),withCrossStoreEffect:async work=>work()})};let mutation;const repository={readEffectivePersona:async()=>({role:'merchant',version:'4',banned_at:null}),readOperation:async()=>({operationId:input.operationId}),mutate:async v=>{mutation=v;revoked=true;return{applied:true};}};return{input,authority,repository,revoke:()=>{revoked=true;},mutation:()=>mutation};}
function lookupMode(scope,read=()=>({version:1,mode:'vuln',generation:0,modeStamp:'lookup-v1'})){return require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({launches:{assertCurrent:async()=>{}},progress:{getEvaluationScope:async()=>read()}});}
test('user administration uses actual protected directory without impersonating each template',async()=>{const f=fixture(),account={profile:async()=>{throw Error('No template impersonation');}},personas={listPersonas:async()=>[{id:11,username:'student_customer',role:'customer',email:'a@example.test'},{id:13,username:'student_admin',role:'admin',email:'admin@example.test'}]};const directory=require('../server/services/secureshopBoundAdmin').createSecureShopBoundAdmin({launches:{assertCurrent:async()=>{}},personas,account,personaAuthority:f.authority,accountRepository:{readProfile:async()=>({email:'overlay@example.test',full_name:'owned',phone:null})},administrationRepository:f.repository,catalog:{prepareTarget:async input=>{assert.equal(input.persona.id,13);await input.personaEffect.check(input.scope);return{...input.scope,targetId:randomUUID()};}}});const service=create({repository:f.repository,personaAuthority:f.authority,directory});const result=await service.users(f.input);assert.equal(result.users[0].role,'merchant');assert.equal(result.users[0].authority_version,'4');assert.equal(result.users[0].email,'overlay@example.test');assert.equal(result.users[0].identity_kind,'teaching_persona');assert.equal(result.users[0].reset_channel,'none');assert.equal(result.administration.roleBan,true);assert.equal(result.administration.passwordReset,false);});
test('operation and directory reject mismatched or revoked captured authority',async()=>{for(const mode of ['foreign','revoked','missing']){const f=fixture();if(mode==='missing')delete f.input.personaSession;if(mode==='revoked')f.revoke();if(mode==='foreign'){const original=f.authority.capture;f.authority.capture=async v=>{const result=await original(v);result.binding.personaId=99;return result;};}let calls=0;const service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>{calls++;}}});await assert.rejects(service.users(f.input),{code:'SHOP_AUTH_INVALID'});assert.equal(calls,0);}});
test('mutation snapshots original actor/target/operation before capture and permits self-transition acknowledgment',async()=>{const f=fixture(),capture=f.authority.capture;f.authority.capture=async v=>{f.input.targetId=99;f.input.role='admin';f.input.operationId=randomUUID();return capture(v);};const before=structuredClone(f.input),service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})}});assert.deepEqual(await service.mutate(f.input),{applied:true});assert.equal(f.mutation().targetId,before.targetId);assert.equal(f.mutation().role,before.role);assert.equal(f.mutation().operationId,before.operationId);assert.equal(f.mutation().actorSessionId,before.personaSession.sessionId);await assert.rejects(service.operation(before),{code:'SHOP_AUTH_INVALID'});});
test('directory post-read revocation withholds capability projection',async()=>{const f=fixture(),service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>{f.revoke();return{users:[]};}}});await assert.rejects(service.users(f.input),{code:'SHOP_AUTH_INVALID'});});
test('unconfigured candidate directory fallback remains available with exact captured authority',async()=>{const f=fixture(),service=create({repository:f.repository,personaAuthority:f.authority,personas:{listPersonas:async()=>[{id:11,role:'customer'}]},account:{profile:async input=>{assert.equal(input.persona.id,11);return{username:'owned',email:'owned@example.test',full_name:null,phone:null};}}});const result=await service.users(f.input);assert.equal(result.users[0].role,'merchant');assert.equal(result.total,1);assert.equal(result.administration.roleBan,true);});

test('optional lookup uses same-client original admin fence and snapshots username', async()=>{
 const f=fixture();let calls=0;const client={query(){}};const capture=f.authority.capture;
 f.authority.capture=async input=>{f.input.username='mutated';const a=await capture(input);a.withPersonaEffect=async work=>work(client);return a;};
 const lookupRepository={checkReadiness:async()=>{},prepare:async()=>['synthetic'],lookup:async(c,input)=>{calls++;assert.equal(c,client);assert.equal(input.username,'student_customer');assert.deepEqual(input.scope,f.input.scope);return{username:input.username,password:'synthetic-only'};}};
 const service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})},lookupRepository,modeAuthority:lookupMode(f.input.scope)});
 f.input.username='student_customer';const result=await service.lookup(f.input);assert.equal(result.synthetic,true);assert.equal(result.user.username,'student_customer');assert.equal(calls,1);
});
test('lookup withholds data on post-read revocation and never advertises failed readiness',async()=>{
 const f=fixture();const lookupRepository={checkReadiness:async()=>{},prepare:async()=>[],lookup:async()=>{f.revoke();return{password:'private synthetic'};}};
 const service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})},lookupRepository,modeAuthority:lookupMode(f.input.scope)});
 await assert.rejects(service.lookup({...f.input,username:'student_admin'}),{code:'SHOP_AUTH_INVALID'});
 const g=fixture();lookupRepository.checkReadiness=async()=>{throw Error('migration absent');};
 const notReady=create({repository:g.repository,personaAuthority:g.authority,directory:{users:async()=>({users:[]})},lookupRepository,modeAuthority:lookupMode(f.input.scope)});
 await assert.rejects(notReady.users(g.input),/migration absent/);
});
test('lookup rejects missing original credential and remains unavailable by default',async()=>{
 const f=fixture(),service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})}});
 await assert.rejects(service.lookup({...f.input,username:'student_admin'}),{code:'LOOKUP_UNAVAILABLE'});
 await assert.rejects(service.lookup({...f.input,personaSession:undefined,username:'student_admin'}),{code:'SHOP_AUTH_INVALID'});
});

test('optional reset forwards exact original credential and two version guards, never recovers through self',async()=>{
 const f=fixture();const calls=[];const passwordResetRepository={checkReadiness:async()=>{},versions:async()=>({credentialVersion:'4',authorityVersion:'3'}),reset:async(input,fence)=>{calls.push({input,fence});return{receipt:{operationId:input.operationId},secretAvailable:true};},read:async()=>null,reveal:async()=>({temporaryPassword:'SYNTHETIC_SECRET'}),acknowledge:async()=>({secretAvailable:false})};
 const service=create({repository:f.repository,personaAuthority:f.authority,personas:{listPersonas:async()=>[{id:11},{id:12},{id:13}]},directory:{users:async()=>({users:[{id:11,authority_version:'3',identity_kind:'teaching_persona'}]})},passwordResetRepository});
 const directory=await service.users(f.input);assert.equal(directory.administration.passwordReset,true);assert.equal(directory.users[0].credential_version,'4');
 await service.resetPassword({...f.input,expectedCredentialVersion:'4',expectedAuthorityVersion:'3',actorId:999});
 assert.equal(calls[0].input.actorId,f.input.persona.id);assert.equal(calls[0].input.actorSessionId,f.input.personaSession.sessionId);assert.equal(calls[0].input.expectedCredentialVersion,'4');assert.equal(calls[0].input.expectedAuthorityVersion,'3');assert.equal(calls[0].fence.binding.personaId,f.input.persona.id);
 await assert.rejects(service.resetPassword({...f.input,targetId:f.input.persona.id}),{code:'SELF_RESET_UNSUPPORTED'});
 passwordResetRepository.reveal=async()=>{f.revoke();return{temporaryPassword:'NEVER_PUBLISH'};};await assert.rejects(service.revealPasswordReset(f.input),{code:'SHOP_AUTH_INVALID'});
});
test('registered actors remain listed while template-only reset is explicitly unavailable',async()=>{
 const f=fixture(),registered=1000000001,calls=[];
 const passwordResetRepository={async checkReadiness(){},async versions({targetId}){calls.push(targetId);return{credentialVersion:'4',authorityVersion:'3'};},async reset(){throw Error('Registered reset must not touch teaching credentials');},async read(){throw Error('No reset read');},async reveal(){throw Error('No reset reveal');},async acknowledge(){throw Error('No reset acknowledge');}};
 const personas={listPersonas:async()=>[{id:11},{id:12},{id:13}]};
 const directory={users:async()=>({users:[{id:11,authority_version:'3',identity_kind:'teaching_persona'},{id:registered,authority_version:'1',identity_kind:'registered_account'},{id:13,authority_version:'1',identity_kind:'teaching_persona'}],total:3})};
 const service=create({repository:f.repository,personaAuthority:f.authority,personas,directory,passwordResetRepository});
 const result=await service.users(f.input);assert.equal(result.total,3);assert.deepEqual(calls,[11]);
 assert.equal(result.users[0].password_reset_available,true);assert.equal(result.users[0].credential_version,'4');
 assert.equal(result.users[0].reset_channel,'bound_persona');
 assert.equal(result.users[1].password_reset_available,false);assert.equal(result.users[1].credential_version,undefined);
 assert.equal(result.users[1].reset_channel,'protected_account');
 assert.equal(result.users[2].password_reset_available,false);
 assert.equal(result.users[2].reset_channel,'none');
 for(const action of ['resetPassword','readPasswordReset','revealPasswordReset','acknowledgePasswordReset'])await assert.rejects(service[action]({...f.input,targetId:registered}),{code:'REGISTERED_RESET_UNAVAILABLE'});
 assert.deepEqual(calls,[11]);
});
test('registered reset intent remains separate when teaching recovery is not configured',async()=>{
 const f=fixture();const service=create({repository:f.repository,personaAuthority:f.authority,
  directory:{users:async()=>({users:[
   {id:11,identity_kind:'teaching_persona'},
   {id:1000000001,identity_kind:'registered_account'},
   {id:f.input.persona.id,identity_kind:'registered_account'},
  ],total:3})}});
 const result=await service.users(f.input);
 assert.deepEqual(result.users.map(row=>row.reset_channel),['none','protected_account','none']);
 assert.deepEqual(result.users.map(row=>row.password_reset_available),[false,false,false]);
});

test('exact protected actor read selects beyond 100 username collisions before profile projection',async()=>{
 const f=fixture(),reads=[],states=[];const banned=new Date('2026-10-11T00:00:00.000Z');
 const actors=Array.from({length:150},(_,i)=>({id:i+100,username:'same_user',email:'owned@example.test',role:'customer',identity_kind:'registered_account'}));
 actors.unshift({id:13,username:'admin',email:'admin@example.test',role:'admin',identity_kind:'teaching_persona'});
 const directory=require('../server/services/secureshopBoundAdmin').createSecureShopBoundAdmin({
 launches:{assertCurrent:async()=>{}},personas:{listPersonas:async()=>{throw Error('Use owned actors');},listActors:async scope=>{assert.deepEqual(scope,f.input.scope);return actors;}},
 account:{profile:async()=>{throw Error('No impersonation');}},personaAuthority:f.authority,
 accountRepository:{readProfile:async(_target,id)=>{reads.push(id);return{email:'overlay@example.test',full_name:'not exposed',phone:'not exposed'};}},
 administrationRepository:{readEffectivePersona:async({shopUserId})=>{states.push(shopUserId);return{role:'merchant',version:'7',banned_at:banned};}},
 catalog:{prepareTarget:async()=>({targetId:randomUUID()})}});
 const service=create({repository:f.repository,personaAuthority:f.authority,directory});
 const value=await service.user({...f.input,targetId:249,query:{search:'no match',page:100}});
 assert.deepEqual(value.user,{id:249,username:'same_user',email:'overlay@example.test',role:'merchant',identity_kind:'registered_account',banned_at:banned.toISOString(),authority_version:'7'});
 assert.deepEqual(Object.keys(value.administration).sort(),['roleBan','scopeKey']);
 assert.deepEqual(reads,[249]);assert.deepEqual(states,[249]);assert.equal(f.mutation(),undefined);
 await assert.rejects(service.user({...f.input,targetId:999}),{code:'PERSONA_UNAVAILABLE'});
 assert.deepEqual(reads,[249]);assert.deepEqual(states,[249]);
});
test('exact actor read snapshots input and withholds revoked or substituted target projection',async()=>{
 for(const mode of ['revoked','substituted']){
 const f=fixture(),original=structuredClone(f.input);const service=create({repository:f.repository,personaAuthority:f.authority,
 directory:{users:async()=>{throw Error('No paginated lookup');},user:async input=>{assert.equal(input.targetId,original.targetId);if(mode==='revoked')f.revoke();return{id:mode==='substituted'?999:input.targetId};}}});
 const pending=service.user(f.input);f.input.targetId=1000;
 await assert.rejects(pending,{code:mode==='revoked'?'SHOP_AUTH_INVALID':'OWNER_MISMATCH'});
 assert.equal(f.mutation(),undefined);
 }
});

function resetReadinessFixture(){
 const f=fixture(),calls=[];
 const user={id:11,username:'student_customer',email:'customer@example.test',identity_kind:'teaching_persona',authority_version:'3',password:'not projected'};
 const versions={credentialVersion:'4',authorityVersion:'3',temporaryPassword:'not projected'};
 const passwordResetRepository={checkReadiness:async()=>{},versions:async(input,authority)=>{calls.push(input);assert.equal(authority.binding.sessionId,f.input.personaSession.sessionId);return versions;}};
 for(const key of ['reset','read','reveal','acknowledge'])passwordResetRepository[key]=async()=>{assert.fail('Readiness must not call '+key);};
 const directory={users:async()=>{assert.fail('No paginated lookup');},user:async input=>{assert.equal(input.targetId,11);return user;}};
 const service=create({repository:f.repository,personaAuthority:f.authority,personas:{listPersonas:async()=>[{id:11},{id:12},{id:13}]},directory,passwordResetRepository});
 return{...f,user,versions,calls,directory,passwordResetRepository,service};
}
test('teaching reset readiness is exact, original-authority bound and secret-free without any reset effect',async()=>{
 const f=resetReadinessFixture(),before=structuredClone(f.input);
 const pending=f.service.passwordResetReadiness(f.input);f.input.targetId=999;
 assert.deepEqual(await pending,{id:11,username:'student_customer',email:'customer@example.test',identityKind:'teaching_persona',channel:'bound_persona',credentialVersion:'4',authorityVersion:'3',resetAvailable:true});
 assert.deepEqual(f.calls,[{scope:before.scope,targetId:11}]);assert.equal(f.mutation(),undefined);
 f.versions.credentialVersion='9007199254740990';
 assert.equal((await f.service.passwordResetReadiness(before)).credentialVersion,'9007199254740990');
});
test('teaching readiness denies self, non-template, substituted and registered targets before version reads',async()=>{
 for(const [mode,code] of [['self','SELF_RESET_UNSUPPORTED'],['non-template','REGISTERED_RESET_UNAVAILABLE'],['substituted','OWNER_MISMATCH'],['registered','REGISTERED_RESET_UNAVAILABLE']]){
  const f=resetReadinessFixture();if(mode==='self')f.input.targetId=13;if(mode==='non-template')f.input.targetId=999;if(mode==='substituted')f.user.id=12;if(mode==='registered')f.user.identity_kind='registered_account';
  await assert.rejects(f.service.passwordResetReadiness(f.input),{code});assert.equal(f.calls.length,0);assert.equal(f.mutation(),undefined);
 }
});
test('teaching readiness withholds revoked authority, changed directory versions and invalid reset versions',async()=>{
 for(const mode of ['before','directory','versions','mismatch','zero','numeric','leading-zero','maximum','oversize']){
  const f=resetReadinessFixture();let code='SHOP_AUTH_INVALID';
  if(mode==='before')f.revoke();
  if(mode==='directory'){const read=f.directory.user;f.directory.user=async input=>{const row=await read(input);f.revoke();return row;};}
  if(mode==='versions'){const read=f.passwordResetRepository.versions;f.passwordResetRepository.versions=async(...args)=>{const row=await read(...args);f.revoke();return row;};}
  if(mode==='mismatch')f.user.authority_version='2';
  const invalid={zero:'0',numeric:4,'leading-zero':'04',maximum:'9007199254740991',oversize:'9999999999999999999'};
  if(Object.hasOwn(invalid,mode)){f.versions.credentialVersion=invalid[mode];code='RESET_RECOVERY_UNAVAILABLE';}
  await assert.rejects(f.service.passwordResetReadiness(f.input),{code});assert.equal(f.mutation(),undefined);
  if(mode==='before'||mode==='directory')assert.equal(f.calls.length,0);
 }
});

function agentLookupFixture(){
 const f=fixture(),events=[],mode={version:1,mode:'vuln',generation:0,modeStamp:'lookup-v1'};
 const target=require('../server/services/secureshopSceneBinding').createSceneBinding({...f.input.scope,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:f.input.scope,withLease:async work=>{events.push('scene-lease');return work();}});
 const requests=[],lookupRepository={async checkReadiness(){events.push('ready');},async prepare(){events.push('prepare');return[];},
  async lookup(){throw Error('Agent must not use manual lookup');},async lookupForAgent(_client,input){requests.push(input);return{version:1,status:input.modeExecution.mode==='fixed'?'redacted':'complete',user:{id:3,username:'student_admin',role:'admin'},receipt:{eventId:randomUUID()}};},
  async readAgentLookup(_client,input){requests.push(input);return{version:1,status:'complete',user:{id:3},receipt:input.reference};}};
 const service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})},lookupRepository,
  modeAuthority:lookupMode(f.input.scope,()=>({...mode}))});
 const input={...f.input,username:'student_admin',target,check:async()=>{events.push('scene-check');}};
 return{...f,events,mode,target,requests,lookupRepository,service,input};
}

test('agent lookup captures original admin, mode epoch and trusted scene before same-client effect',async()=>{
 const f=agentLookupFixture(),original=structuredClone({...f.input,target:undefined,check:undefined});
 const pending=f.service.lookupForAgent(f.input);f.input.username='mutated';f.input.target={scene:{}};
 const result=await pending;assert.equal(result.status,'complete');assert.equal(f.requests.length,1);
 const request=f.requests[0];assert.equal(request.username,original.username);assert.deepEqual(request.personaSession,original.personaSession);
 assert.deepEqual(request.scope,original.scope);assert.equal(request.modeExecution.featureId,'admin_assistant');assert.equal(request.modeExecution.generation,0);
 assert.deepEqual(request.sceneExecution,{targetId:f.target.targetId,sceneId:f.target.scene.sceneId,sceneGeneration:1,grantId:f.target.scene.grantId});
 assert.equal(f.events.filter(e=>e==='scene-lease').length,1);assert(f.events.indexOf('prepare')<f.events.indexOf('scene-lease'));
});

test('agent lookup read is source-only recovery without preparation or another lookup',async()=>{
 const f=agentLookupFixture(),reference={eventId:randomUUID()};
 const value=await f.service.readAgentLookup({...f.input,reference});assert.deepEqual(value.receipt,reference);
 assert.equal(f.events.includes('prepare'),false);assert.equal(f.requests.length,1);assert.deepEqual(f.requests[0].reference,reference);
 assert.equal(f.requests[0].prepared,undefined);assert.equal(f.requests[0].username,undefined);
});

test('missing/forged scene, stale feature mode and post-read revocation withhold agent data',async()=>{
 for(const kind of ['missing-scene','forged-scene','foreign-scene','mode-change','revoked']){
  const f=agentLookupFixture();
  if(kind==='missing-scene')delete f.input.target;
  if(kind==='forged-scene')f.input.target=structuredClone(f.target);
  if(kind==='foreign-scene')f.input.scope={...f.input.scope,generation:2};
  if(kind==='mode-change')f.lookupRepository.prepare=async()=>{f.mode.generation++;return[];};
  if(kind==='revoked'){const lookup=f.lookupRepository.lookupForAgent;f.lookupRepository.lookupForAgent=async(...args)=>{const value=await lookup(...args);f.revoke();return value;};}
  await assert.rejects(f.service.lookupForAgent(f.input));
  if(kind!=='revoked')assert.equal(f.requests.length,0);
 }
});

test('manual lookup preserves its DTO and uses trusted fixed mode rather than client supplied mode',async()=>{
 const f=fixture(),safe={id:3,username:'student_admin',role:'admin'};let calls=0;
 const lookupRepository={async checkReadiness(){},async prepare(){return[];},async lookup(_client,input){calls++;assert.equal(input.mode,'fixed');return safe;}};
 const service=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})},lookupRepository,
  modeAuthority:lookupMode(f.input.scope,()=>({version:1,mode:'fixed',generation:3,modeStamp:'fixed-3'}))});
 assert.deepEqual(await service.lookup({...f.input,username:'student_admin',mode:'vuln'}),{ok:true,user:safe,synthetic:true});assert.equal(calls,1);
 const unavailable=create({repository:f.repository,personaAuthority:f.authority,directory:{users:async()=>({users:[]})},lookupRepository});
 await assert.rejects(unavailable.lookup({...f.input,username:'student_admin'}),{code:'LOOKUP_UNAVAILABLE'});assert.equal(calls,1);
});
