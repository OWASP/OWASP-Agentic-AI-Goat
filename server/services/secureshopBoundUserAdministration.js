'use strict';
// Explicit bound composition; factory creation alone never enables routes.
function createSecureShopBoundUserAdministration({repository,personas,account,personaAuthority,directory,lookupRepository,passwordResetRepository,modeAuthority}={}){
 if(typeof repository?.mutate!=='function'||typeof repository?.readEffectivePersona!=='function'
  ||(!directory&&(typeof personas?.listPersonas!=='function'||typeof account?.profile!=='function'))||(directory!==undefined&&typeof directory?.users!=='function')||typeof personaAuthority?.capture!=='function')throw new TypeError('Candidate user administration dependencies required');
 if(lookupRepository!==undefined&&['checkReadiness','prepare','lookup'].some(name=>typeof lookupRepository?.[name]!=='function'))throw TypeError('Synthetic lookup repository required');
 if(passwordResetRepository!==undefined&&['checkReadiness','versions','reset','read','reveal','acknowledge'].some(name=>typeof passwordResetRepository?.[name]!=='function'))throw TypeError('Password reset repository required');
 if(passwordResetRepository!==undefined&&typeof personas?.listPersonas!=='function')throw TypeError('Resettable template directory required');
 function snapshot(raw){const input=structuredClone(raw);input.scope=require('./secureshopConversationBinding').createLaunchScope(input.scope);if(input?.persona?.role!=='admin'||!Number.isSafeInteger(input.persona.id)||input.persona.id<1)throw Object.assign(Error('Admin required'),{code:'ADMIN_REQUIRED'});const session=input.personaSession;if(typeof session?.sessionId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(session.sessionId)||typeof session.authorityVersion!=='string'||!/^[1-9]\d*$/.test(session.authorityVersion))throw Object.assign(Error('Authority unavailable'),{code:'SHOP_AUTH_INVALID'});input.personaSession=Object.freeze({sessionId:session.sessionId.toLowerCase(),authorityVersion:session.authorityVersion});return input;}
 async function fence(input){const value=await personaAuthority.capture({scope:input.scope,personaId:input.persona.id,sessionId:input.personaSession.sessionId,role:'admin',authorityVersion:input.personaSession.authorityVersion});const b=value?.binding;if(typeof value?.assertRemoteAdmission!=='function'||typeof value?.withPersonaEffect!=='function'||!b||Object.keys(input.scope).some(k=>b[k]!==input.scope[k])||b.personaId!==input.persona.id||b.role!=='admin'||b.sessionId!==input.personaSession.sessionId||b.authorityVersion!==input.personaSession.authorityVersion)throw Object.assign(Error('Authority unavailable'),{code:'SHOP_AUTH_INVALID'});await value.assertRemoteAdmission();return value;}
 async function lookupMode(input){
  if(typeof modeAuthority?.capture!=='function'||typeof modeAuthority?.assertToken!=='function')throw Object.assign(Error('Lookup mode unavailable'),{code:'LOOKUP_UNAVAILABLE'});
  return require('./secureshopFeatureModeAuthority').captureFeatureMode(modeAuthority,input.scope,'admin_assistant');
 }
 function username(value){if(typeof value!=='string'||!value||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>100)throw Object.assign(Error('Invalid username'),{code:'INVALID_ARGUMENT'});return value;}
 async function agentLookup(raw,recover){
  const input=snapshot({scope:raw.scope,persona:raw.persona,personaSession:raw.personaSession,
   ...(recover?{reference:raw.reference}:{username:raw.username})}),target=raw.target,check=raw.check;
  const {executionScope,withSceneLease}=require('./secureshopSceneBinding');
  const execution=executionScope(target);
  if(!target?.scene||Object.keys(input.scope).some(k=>execution[k]!==input.scope[k])||typeof check!=='function')throw Object.assign(Error('Lookup scene unavailable'),{code:'SHOP_SCENE_STALE'});
  const method=recover?'readAgentLookup':'lookupForAgent';
  if(typeof lookupRepository?.[method]!=='function')throw Object.assign(Error('Lookup unavailable'),{code:'LOOKUP_UNAVAILABLE'});
  if(!recover)username(input.username);
  await check();const mode=await lookupMode(input),authority=require('./secureshopFeatureModeAuthority').guardFeatureFence(await fence(input),mode);
  await lookupRepository.checkReadiness();const prepared=recover?undefined:await lookupRepository.prepare();
  const sceneExecution={targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration,grantId:target.scene.grantId};
  const request={scope:input.scope,persona:input.persona,personaSession:input.personaSession,
   modeExecution:mode.snapshot,sceneExecution,...(recover?{reference:input.reference}:{username:input.username,prepared})};
  return withSceneLease(target,async()=>{
   await check();await authority.assertRemoteAdmission();
   const value=await authority.withPersonaEffect(client=>lookupRepository[method](client,request));
   await authority.assertRemoteAdmission();await check();return value;
  });
 }
 function capability(input){return{roleBan:true,passwordReset:!!passwordResetRepository,...(passwordResetRepository?{resetActorId:input.persona.id}:{}),...(lookupRepository?{credentialLookup:true}:{}),scopeKey:JSON.stringify([input.scope.launchId,input.scope.generation,input.scope.platformOwnerId,input.scope.platformSessionId,input.persona.id,input.personaSession.sessionId])};}
 async function resettableIds(){
  const rows=await personas.listPersonas();
  if(!Array.isArray(rows)||rows.length!==3||rows.some(row=>!Number.isSafeInteger(row?.id)||row.id<1)
   ||new Set(rows.map(row=>row.id)).size!==3)throw Object.assign(Error('Resettable template directory unavailable'),{code:'RESET_RECOVERY_UNAVAILABLE'});
  return new Set(rows.map(row=>row.id));
 }
 async function resetDirectory(input,authority,result){
  if(passwordResetRepository)await passwordResetRepository.checkReadiness();
  const eligible=passwordResetRepository?await resettableIds():new Set();
  const users=[];
  for(const user of result.users){
   if(!['teaching_persona','registered_account'].includes(user.identity_kind))throw Object.assign(Error('Directory identity unavailable'),{code:'SHOP_PERSONA_UNAVAILABLE'});
   if(user.identity_kind==='registered_account'){
    users.push({...user,password_reset_available:false,reset_channel:user.id===input.persona.id?'none':'protected_account'});
    continue;
   }
   if(user.id===input.persona.id||!eligible.has(user.id)){
    users.push({...user,password_reset_available:false,reset_channel:'none'});continue;
   }
   const version=await passwordResetRepository.versions({scope:input.scope,targetId:user.id},authority);
   if(version.authorityVersion!==user.authority_version)throw Object.assign(Error('Directory changed'),{code:'SHOP_AUTH_INVALID'});
   users.push({...user,credential_version:version.credentialVersion,password_reset_available:true,reset_channel:'bound_persona'});
  }
  await authority.assertRemoteAdmission();return{...result,users};
 }
 async function passwordOperation(method,raw){
  const input=snapshot(raw);if(!passwordResetRepository)throw Object.assign(Error('Password reset unavailable'),{code:'RESET_RECOVERY_UNAVAILABLE'});
  if(input.targetId===input.persona.id)throw Object.assign(Error('Use self-service password change'),{code:'SELF_RESET_UNSUPPORTED'});
  const authority=await fence(input);await passwordResetRepository.checkReadiness();await authority.assertRemoteAdmission();
  if(!(await resettableIds()).has(input.targetId))throw Object.assign(Error('Registered credential reset is unavailable'),{code:'REGISTERED_RESET_UNAVAILABLE'});
  const request={scope:input.scope,actorId:input.persona.id,actorSessionId:input.personaSession.sessionId,actorAuthorityVersion:input.personaSession.authorityVersion,targetId:input.targetId,operationId:input.operationId,
   ...(method==='reset'?{expectedCredentialVersion:input.expectedCredentialVersion,expectedAuthorityVersion:input.expectedAuthorityVersion}:{})};
  const result=await passwordResetRepository[method](request,authority);
  try{await authority.assertRemoteAdmission();}catch(cause){if(method==='reset'||method==='acknowledge'){const error=Object.assign(Error('Password reset outcome uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});Object.defineProperty(error,'cause',{value:cause});throw error;}throw cause;}
  return result;
 }
 return Object.freeze({
  async checkReadiness(){if(typeof repository.checkReadiness==='function')await repository.checkReadiness();if(lookupRepository)await lookupRepository.checkReadiness();if(passwordResetRepository)await passwordResetRepository.checkReadiness();},
  async passwordResetReadiness(raw){
   const input=snapshot(raw);
   if(!Number.isSafeInteger(input.targetId)||input.targetId<1||input.targetId>2147483647)throw Object.assign(Error('Invalid target'),{code:'INVALID_ARGUMENT'});
   if(input.targetId===input.persona.id)throw Object.assign(Error('Use self-service password change'),{code:'SELF_RESET_UNSUPPORTED'});
   if(!passwordResetRepository||typeof directory?.user!=='function')throw Object.assign(Error('Password reset unavailable'),{code:'RESET_RECOVERY_UNAVAILABLE'});
   const authority=await fence(input);
   await passwordResetRepository.checkReadiness();
   if(!(await resettableIds()).has(input.targetId))throw Object.assign(Error('Registered credential reset is unavailable'),{code:'REGISTERED_RESET_UNAVAILABLE'});
   // Resolve exactly the owned target, not a match from a paginated directory.
   const user=await directory.user(input);
   if(user?.id!==input.targetId)throw Object.assign(Error('Target unavailable'),{code:'OWNER_MISMATCH'});
   if(user.identity_kind!=='teaching_persona')throw Object.assign(Error('Registered credential reset is unavailable'),{code:'REGISTERED_RESET_UNAVAILABLE'});
   if(typeof user.username!=='string'||!user.username||Buffer.byteLength(user.username)>100
    ||typeof user.email!=='string'||Buffer.byteLength(user.email)>320)throw Object.assign(Error('Target unavailable'),{code:'RESET_RECOVERY_UNAVAILABLE'});
   await authority.assertRemoteAdmission();
   const versions=await passwordResetRepository.versions({scope:input.scope,targetId:input.targetId},authority);
   const validVersion=value=>typeof value==='string'&&/^[1-9]\d{0,15}$/.test(value)&&BigInt(value)<9007199254740991n;
   if(!validVersion(versions?.credentialVersion)||!validVersion(versions?.authorityVersion))throw Object.assign(Error('Reset versions unavailable'),{code:'RESET_RECOVERY_UNAVAILABLE'});
   if(versions.authorityVersion!==user.authority_version)throw Object.assign(Error('Directory changed'),{code:'SHOP_AUTH_INVALID'});
   await authority.assertRemoteAdmission();
   return{id:user.id,username:user.username,email:user.email,identityKind:'teaching_persona',channel:'bound_persona',
    credentialVersion:versions.credentialVersion,authorityVersion:versions.authorityVersion,resetAvailable:true};
  },
  resetPassword:raw=>passwordOperation('reset',raw),
  readPasswordReset:raw=>passwordOperation('read',raw),
  revealPasswordReset:raw=>passwordOperation('reveal',raw),
  acknowledgePasswordReset:raw=>passwordOperation('acknowledge',raw),
  async lookup(raw){const input=snapshot(raw);if(!lookupRepository)throw Object.assign(Error('Lookup unavailable'),{code:'LOOKUP_UNAVAILABLE'});username(input.username);const mode=await lookupMode(input),authority=require('./secureshopFeatureModeAuthority').guardFeatureFence(await fence(input),mode);await lookupRepository.checkReadiness();const prepared=await lookupRepository.prepare();await authority.assertRemoteAdmission();const user=await authority.withPersonaEffect(client=>lookupRepository.lookup(client,{scope:input.scope,username:input.username,prepared,persona:input.persona,mode:mode.snapshot.mode}));await authority.assertRemoteAdmission();return{ok:true,user,synthetic:true};},
  lookupForAgent:raw=>agentLookup(raw,false),
  readAgentLookup:raw=>agentLookup(raw,true),
  async operation(raw){const input=snapshot(raw),a=await fence(input);await a.assertRemoteAdmission();const receipt=await repository.readOperation({scope:input.scope,actorId:input.persona.id,operationId:input.operationId});await a.assertRemoteAdmission();return receipt;},
  async user(raw){
   const input=snapshot(raw);
   if(!Number.isSafeInteger(input.targetId)||input.targetId<1||input.targetId>2147483647)throw Object.assign(Error('Invalid target'),{code:'INVALID_ARGUMENT'});
   if(typeof directory?.user!=='function')throw Object.assign(Error('Exact directory unavailable'),{code:'PERSONA_UNAVAILABLE'});
   const authority=await fence(input);
   const user=await directory.user(input);
   if(user?.id!==input.targetId)throw Object.assign(Error('Target unavailable'),{code:'OWNER_MISMATCH'});
   await authority.assertRemoteAdmission();
   return{user:{id:user.id,username:user.username,email:user.email,role:user.role,identity_kind:user.identity_kind,banned_at:user.banned_at,authority_version:user.authority_version},
    administration:{roleBan:true,scopeKey:capability(input).scopeKey}};
  },
  async users(raw){const input=snapshot(raw),authority=await fence(input);await authority.assertRemoteAdmission();
   if(lookupRepository){await lookupRepository.checkReadiness();await authority.assertRemoteAdmission();}
   const {page=1,pageSize=25,search='',role='',banned=''}=input.query||{};
   if(!Number.isInteger(page)||page<1||!Number.isInteger(pageSize)||pageSize<1||pageSize>100||typeof search!=='string'||Buffer.byteLength(search)>256||!['','customer','merchant','admin','banned'].includes(role)||!['','true','false'].includes(banned))throw Object.assign(Error('Invalid query'),{code:'INVALID_ARGUMENT'});
   if(directory){const result=await directory.users(input);await authority.assertRemoteAdmission();return{...await resetDirectory(input,authority,result),administration:capability(input)};}
   const users=[];for(const template of await personas.listPersonas()){
    const state=await repository.readEffectivePersona({scope:input.scope,shopUserId:template.id});
    // Account overlays remain tied to immutable fixture ownership, not effective role.
    const profile=await account.profile({scope:input.scope,persona:{id:template.id,role:template.role}});
    users.push({id:template.id,username:profile.username,email:profile.email,full_name:profile.full_name,phone:profile.phone,role:state.role,banned_at:state.banned_at,authority_version:state.version,identity_kind:'teaching_persona'});
   }
   await authority.assertRemoteAdmission();const q=search.toLowerCase();const filtered=users.filter(u=>(!role||(role==='banned'?!!u.banned_at:u.role===role))&&(!banned||(banned==='true')===!!u.banned_at)&&(!q||[u.username,u.email,u.full_name].some(x=>String(x||'').toLowerCase().includes(q))));
   return{administration:capability(input),...await resetDirectory(input,authority,{users:filtered.slice((page-1)*pageSize,page*pageSize),total:filtered.length,count:filtered.length,page,pageSize,pages:Math.max(1,Math.ceil(filtered.length/pageSize))})};
  },
  async mutate(raw){const input=snapshot(raw);await fence(input);return repository.mutate({scope:input.scope,actorId:input.persona.id,actorSessionId:input.personaSession.sessionId,actorAuthorityVersion:input.personaSession.authorityVersion,targetId:input.targetId,operationId:input.operationId,expectedVersion:input.expectedVersion,action:input.action,role:input.role,reason:input.reason??null});}
 });
}
module.exports={createSecureShopBoundUserAdministration};
