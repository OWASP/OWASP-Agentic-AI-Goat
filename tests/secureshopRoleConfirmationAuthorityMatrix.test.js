'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {EventEmitter}=require('node:events');
const jwt=require('jsonwebtoken');
const {createBoundRoleChatRouter}=require('../server/routes/secureshop/boundRoleChat');
const {createSecureShopBoundPersonaAuth,ISSUER,AUDIENCE}=require('../server/services/secureshopBoundPersonaAuth');
const {capture}=require('../server/database/postgres/secureshopRoleChatBindingRepository');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createSecureShopBoundRoleChat}=require('../server/services/secureshopBoundRoleChat');
const {createBoundMailActions}=require('../server/services/secureshopRoleMailActions');

const launch=Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:4,platformSessionId:5});
const merchant=Object.freeze({id:6,role:'merchant'});
const personaSession=Object.freeze({sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'2'});
const target=createSceneBinding({...launch,targetId:'40000000-0000-4000-8000-000000000001'},
 {sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
  grantId:'60000000-0000-4000-8000-000000000001',execution:launch,withLease:work=>work()});
const mode=Object.freeze({version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}});
const recipient=Object.freeze({id:8,username:'Owned recipient',email:'recipient@owned.invalid',role:'customer'});
const sender=Object.freeze({id:6,username:'Merchant',email:'merchant@owned.invalid',role:'merchant'});

function controlledRuntime(){
 let currentTarget=target,decision='merchant.mail_recipients',args={},toolIssued=false;
 let modelCalls=0,sendCalls=0,recoverCalls=0;
 const revokedPersonaSessions=new Set();
 const effects=new Map(),claims=new Map(),bindings=new Map(),sessions=new Map(),messages=[];
 const rows=stored=>({session_id:stored.sessionId,request_id:stored.requestId,role:stored.role,purpose:stored.purpose,
  launch_id:stored.launchId,scenario_id:stored.scenarioId,generation:stored.generation,owner_id:stored.ownerId,
  execution_session_id:stored.executionSessionId,persona_id:stored.personaId,persona_session_id:stored.personaSessionId,
  authority_version:stored.authorityVersion,scene_id:stored.sceneId,scene_generation:stored.sceneGeneration,
  grant_id:stored.grantId,target_id:stored.targetId,envelope_sha256:stored.envelopeSha256,request_hash:stored.requestHash});
 const conversationRepository={
  async acquireBoundSession({id,binding,purpose}){const value={id,binding,purpose,state:'pending'};sessions.set(id,value);return value;},
  async activateBoundSession(id){sessions.get(id).state='active';return true;},
  async getBoundSession(id){return sessions.get(id)||null;},
  async getMessages(){return messages;},async appendMessage(_id,_binding,message){messages.push(message);},
  async getTokens(){return 0;},async addTokens(){},async appendTraces(){},
 };
 const journal={
  async claim({sessionId,requestId,binding,message}){
   const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
   const request=createTurnRequest({sessionId,requestId,binding,message}),prior=claims.get(requestId);
   if(prior){if(prior.request_hash!==request.hash)throw Object.assign(Error('conflict'),{code:'TURN_REQUEST_CONFLICT'});return prior.status==='completed'?{status:'completed',result:prior.result_json}:prior;}
   const claim={status:'claimed',claimId:requestId,request_hash:request.hash};claims.set(requestId,claim);return claim;
  },
  async complete({requestId,result}){const old=claims.get(requestId);claims.set(requestId,{...old,status:'completed',result_json:structuredClone(result)});},
  async markUncertain({requestId}){const old=claims.get(requestId);if(old?.status!=='completed')claims.set(requestId,{...old,status:'uncertain'});},
  async readBoundRequest({requestId}){const claim=claims.get(requestId);return claim&&{status:claim.status,request_hash:claim.request_hash,request_version:1,result_json:claim.result_json};},
 };
 const bindingRepository={
  async reserve(input){const stored=capture(input);bindings.set(input.requestId,stored);return stored;},
  async read({requestId}){const stored=bindings.get(requestId);return stored&&rows(stored);},
  async readChoice({sessionId,choiceId}){
   const found=[];
   for(const [requestId,stored] of bindings){const result=claims.get(requestId)?.result_json;
    if(stored.sessionId===sessionId&&result?.taskMetadata?.roleChat?.choices?.some(choice=>choice.choiceId===choiceId))
     found.push({...rows(stored),result_json:result,turn_request_hash:claims.get(requestId).request_hash,turn_request_version:1});}
   if(found.length>1)throw Object.assign(Error('choice conflict'),{code:'ROLE_CHOICE_CONFLICT'});
   return found[0]||null;
  },
 };
 const checkPersona=sessionId=>{if(revokedPersonaSessions.has(sessionId))throw Object.assign(Error('Controlled persona session revoked'),{code:'SHOP_AUTH_INVALID'});};
 const personaAuthority={async read(_scope,_id){checkPersona(personaSession.sessionId);return{version:personaSession.authorityVersion};},async capture({scope,personaId,role,sessionId,authorityVersion}){
  const binding={...scope,personaId,role,sessionId,authorityVersion};
  return {binding,async assertRemoteAdmission(){checkPersona(sessionId);},async withPersonaEffect(work){checkPersona(sessionId);return work({});},async withCrossStoreEffect(work){checkPersona(sessionId);return work();}};
 }};
 const scenes={async readExisting(){return currentTarget;},async readRetained(){return currentTarget;},async withProvisionLease(_scope,work){return work();}};
 const mailApplication={
  async readiness(){return{ready:true,modeCapability:mode};},
  async prepareTarget(){return {targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration};},
  async readRetainedTarget(){return {targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration};},
  async send(_context,input){sendCalls++;if(!effects.has(input.requestId))effects.set(input.requestId,{emailId:91,threadId:92,send:input});return{ok:true,receipt:{email_id:91,thread_id:92}};},
  async reply(){throw Error('reply is outside this send-only authority matrix');},
  async recoverRetained(_context,input){recoverCalls++;const effect=effects.get(input.requestId);return effect
   ?{status:'saved',sent_email_id:effect.emailId,thread_id:effect.threadId,savedSend:{recipientId:recipient.id,to:recipient.email,subject:effect.send.subject,body_markdown:effect.send.body_markdown}}
   :{status:'unconfirmed'};},
 };
 const mailActions=createBoundMailActions({mailApplication,listMailActors:async()=>[sender,recipient]});
 const provider={
  async chat(){modelCalls++;if(toolIssued)return{provider:'controlled',model:'controlled',mocked:false,stop_reason:'end_turn',text:'Prepared only.',tool_uses:[]};
   toolIssued=true;return{provider:'controlled',model:'controlled',mocked:false,stop_reason:'tool_use',tool_uses:[{id:`call-${modelCalls}`,name:decision,args}]};},
  async finalResponse(){return{provider:'controlled',model:'controlled',mocked:false,stop_reason:'end_turn',text:'Model says confirmation is complete.',responseMode:'structured_final'};},
  async routeWorkflow(){return{responseMode:'decision_routing_v1',decision:{route:'management'},provider:'controlled',model:'controlled',mocked:false,usage:{inputTokens:1,outputTokens:1,totalTokens:2,attempts:1}};},
 };
 const runtime=createSecureShopBoundRoleChat({role:'merchant',launches:{async assertCurrent(){}},personaAuthority,
  conversations:conversationRepository,journal,coordinator:{async run(_owner,options,work){const admission=await options.admit();return admission.skip?admission.value:work({runId:randomUUID(),ownerKey:'controlled',durableGeneration:1,signal:options.signal,async check(){},async effect(_key,fn){return fn();},async effectWithReceipt(_key,fn){return{value:await fn(),receipt:{}}},async trace(){}});}},
  provider,catalog:{async prepareTarget(){return currentTarget;},async listMerchantProducts(){return{products:[],total:0};},async getOwnedMerchantProduct(){return{product:null};}},
  scenes,bindingRepository,commerce:{async merchantOverview(){return{kpis:{}};},async merchantTopProducts(){return{rows:[]};},async merchantOrders(){return{orders:[],nextCursor:null};},async merchantOrder(){return null;}},
  mailChat:{ready:true,async recipients(){return{version:1,kind:'recipients',recipients:[recipient],hasMore:false,mailModeCapability:mode};},async list(){throw Error('not used');},async page(){throw Error('not used');},async detail(){throw Error('not used');},async verify(input){return input.packet;}},
  mailActions,assertMailActionAllowed:async({beforeEffect})=>beforeEffect(),toolPolicyAdmission:async input=>({admissionId:randomUUID(),runId:input.runId,invocationId:input.invocationId,toolKey:`${input.agent}.${input.tool}`,policyVersion:'1',registrySha256:'a'.repeat(64),allowed:true,action:'dispatch',policyViolation:null,enforcement:true}),
 });
 return {runtime,effects,claims,personaAuthority,revokePersona(){revokedPersonaSessions.add(personaSession.sessionId);},get sends(){return sendCalls;},get recovers(){return recoverCalls;},get modelCalls(){return modelCalls;},
  decide(name,value){decision=name;args=value;toolIssued=false;},switchScene(){currentTarget=createSceneBinding({...launch,targetId:'40000000-0000-4000-8000-000000000002'}, {sceneId:'50000000-0000-4000-8000-000000000002',sceneGeneration:2,grantId:'60000000-0000-4000-8000-000000000002',execution:launch,withLease:work=>work()});},
  mutateSaved(requestId,change){const claim=claims.get(requestId);const copy=structuredClone(claim.result_json);change(copy);claim.result_json=copy;},
 };
}

async function preparedSend(f){
 const discover='70000000-0000-4000-8000-000000000002',prepare='70000000-0000-4000-8000-000000000003';
 const {id:sessionId}=await f.runtime.createSession(launch,merchant,personaSession);
 f.decide('merchant.mail_recipients',{});
 await f.runtime.run({scope:launch,persona:merchant,personaSession,sessionId,requestId:discover,message:'Find an owned recipient.'});
 const found=await f.runtime.readRequest(launch,merchant,personaSession,sessionId,discover),choiceId=found.cards[0].choiceId;
 f.decide('merchant.mail_send_prepare',{choiceId,subject:'Bound subject',body_markdown:'Bound body'});
 await f.runtime.run({scope:launch,persona:merchant,personaSession,sessionId,requestId:prepare,message:'Prepare this message.',selection:{choiceId,intent:'mail_send'}});
 const saved=await f.runtime.readRequest(launch,merchant,personaSession,sessionId,prepare);
 assert.equal(saved.mailProposal.subject,'Bound subject');
 return {sessionId,requestId:prepare,proposalId:saved.mailProposal.proposalId,discover};
}

test('Q05 controlled confirmation rejects model text, forged IDs, and changed proposal arguments before a mail effect',async()=>{
 const f=controlledRuntime(),prepared=await preparedSend(f),request={scope:launch,persona:merchant,personaSession,sessionId:prepared.sessionId,requestId:prepared.requestId,proposalId:prepared.proposalId};
 assert.equal(f.modelCalls,2);assert.equal(f.effects.size,0,'preparation and model prose have no effect');
 await assert.rejects(f.runtime.confirmMail({...request,requestId:prepared.discover,proposalId:'70000000-0000-4000-8000-000000000004'}),{code:'ROLE_PROPOSAL_UNCONFIRMED'});
 assert.equal(f.effects.size,0,'a forged confirmation ID cannot use model text as authority');
 f.mutateSaved(prepared.requestId,result=>{result.taskMetadata.roleChat.mailProposal.send.subject='Model-altered subject';});
 await assert.rejects(f.runtime.confirmMail(request),{code:'ROLE_MAIL_PROPOSAL_MISMATCH'});
 assert.equal(f.effects.size,0,'changed displayed arguments are rejected before send');
});

test('Q07 controlled confirmation rejects substituted role, tenant, platform session, persona session, scene, and generation',async()=>{
 const variants=[
  ['customer role substitution',{persona:{id:merchant.id,role:'customer'}},'OWNER_MISMATCH'],
  ['administrator role substitution',{persona:{id:merchant.id,role:'admin'}},'OWNER_MISMATCH'],
  ['another valid merchant',{persona:{id:7,role:'merchant'}},['ROLE_PROPOSAL_STALE','CONVERSATION_UNAVAILABLE']],
  ['platform launch without persona credential',{personaSession:undefined},'SHOP_AUTH_INVALID'],
  ['foreign tenant',{scope:{...launch,platformOwnerId:44}},['ROLE_PROPOSAL_STALE','CONVERSATION_UNAVAILABLE']],
  ['platform session substitution',{scope:{...launch,platformSessionId:45}},['ROLE_PROPOSAL_STALE','CONVERSATION_UNAVAILABLE']],
  ['persona session substitution',{personaSession:{sessionId:'30000000-0000-4000-8000-000000000099',authorityVersion:'2'}},['ROLE_PROPOSAL_STALE','CONVERSATION_UNAVAILABLE','SHOP_SCENE_STALE']],
  ['stale generation',{scope:{...launch,generation:2}},['ROLE_PROPOSAL_STALE','CONVERSATION_UNAVAILABLE']],
 ];
 for(const [label,override,code] of variants){
  const f=controlledRuntime(),prepared=await preparedSend(f);
  await assert.rejects(f.runtime.confirmMail({scope:launch,persona:merchant,personaSession,sessionId:prepared.sessionId,requestId:prepared.requestId,proposalId:prepared.proposalId,...override}),error=>Array.isArray(code)?code.includes(error?.code):error?.code===code,label);
  assert.equal(f.effects.size,0,`${label} leaves no send effect`);
 }
 const f=controlledRuntime(),prepared=await preparedSend(f);f.switchScene();
 await assert.rejects(f.runtime.confirmMail({scope:launch,persona:merchant,personaSession,sessionId:prepared.sessionId,requestId:prepared.requestId,proposalId:prepared.proposalId}),{code:'SHOP_SCENE_STALE'});
 assert.equal(f.effects.size,0,'stale scene leaves no send effect');
});

test('Q05/Q07 controlled valid confirmation has one effect and protected GET recovers it without replay',async()=>{
 const f=controlledRuntime(),prepared=await preparedSend(f),request={scope:launch,persona:merchant,personaSession,sessionId:prepared.sessionId,requestId:prepared.requestId,proposalId:prepared.proposalId};
 const confirmed=await f.runtime.confirmMail(request);
 assert.equal(confirmed.status,'saved');assert.equal(f.effects.size,1);assert.equal(f.sends,1);
 const recovered=await f.runtime.readMailOperation({...request,operationId:prepared.proposalId});
 assert.equal(recovered.status,'saved');assert.equal(f.effects.size,1);assert.equal(f.sends,1);assert.equal(f.recovers,2,'confirm readback plus protected GET');
 assert.equal(f.modelCalls,2,'confirmation and GET do not call the model');
});

// Exercise the actual Express handler stack without opening a socket. Only
// authority storage and dispatch dependencies are controlled; parsing, JWT
// verification, launch projection, route guards and RoleChat remain production.
function invokeRoute(router,method,path,{body={},params={},launchBearer='a'.repeat(43),token}={}){
 const route=router.stack.find(layer=>layer.route?.path===path&&layer.route.methods[method])?.route;
 assert.ok(route,`production ${method} ${path} route required`);
 const req=new EventEmitter();Object.assign(req,{body,params,query:{},headers:{'x-owasp-ai-goat-secureshop-launch':launchBearer},rawHeaders:['x-owasp-ai-goat-secureshop-launch',launchBearer],is:type=>type==='application/json'});
 if(token){req.headers.authorization=`Bearer ${token}`;req.rawHeaders.push('authorization',`Bearer ${token}`);}
 req.get=name=>req.headers[name.toLowerCase()];
 const res=new EventEmitter(),headers={};res.statusCode=200;res.writableEnded=false;res.destroyed=false;
 res.setHeader=(name,value)=>{headers[name.toLowerCase()]=value;};res.set=(name,value)=>{res.setHeader(name,value);return res;};
 res.status=value=>{res.statusCode=value;return res;};
 return new Promise((resolve,reject)=>{
  res.json=value=>{res.writableEnded=true;resolve({status:res.statusCode,body:value,headers});return res;};
  let index=0;
  const next=error=>{
   if(error)return reject(Error(`Unexpected route fallthrough: ${error}`));
   const handler=route.stack[index++]?.handle;if(!handler)return reject(Error('Production handler did not finish'));
   try{Promise.resolve(handler(req,res,next)).catch(reject);}catch(failure){reject(failure);}
  };next();
 });
}
function routedAuthority(f){
 const foreignLaunch={...launch,launchId:'10000000-0000-4000-8000-000000000044',scenarioId:'20000000-0000-4000-8000-000000000044',platformOwnerId:44,platformSessionId:45};
 const scopes=new Map([['a'.repeat(43),launch],['b'.repeat(43),foreignLaunch]]);
 const launches={async resolveCapability(bearer){return scopes.get(bearer)||null;},async assertCurrent(scope){
  assert.ok([...scopes.values()].some(value=>Object.keys(value).every(key=>value[key]===scope[key])),'controlled current launch required');
 }};
 const rows=new Map(),secret='controlled-authority-matrix-private-jwt-secret';
 const repository=Object.fromEntries(['findCredential','createSession','extendSession','revokeSession','listSessions','revokeOwnedSession','changePassword','readApiKey','rotateApiKey','authenticateApiKey','findCredentialById'].map(name=>[name,async()=>{throw Error(`Unexpected authority write/read ${name}`);} ]));
 repository.candidatePersonaAuthority=f.personaAuthority;
 repository.readSession=async({jti,scope})=>{const row=rows.get(jti);return row&&Object.keys(row.scope).every(key=>row.scope[key]===scope[key])?row.value:null;};
 const auth=createSecureShopBoundPersonaAuth({repository,launches,jwtSecret:secret,personaAuthority:f.personaAuthority});
 const issue=(user=merchant,scope=launch)=>{
  const jti=randomUUID();rows.set(jti,{scope,value:{shop_user_id:user.id,role:user.role,username:`controlled_${user.role}`,email:'owned@matrix.invalid',session_id:personaSession.sessionId,expires_at:new Date(Date.now()+60000)}});
  return jwt.sign({role:user.role,ss_authority_version:personaSession.authorityVersion,ss_launch_id:scope.launchId,ss_scenario_id:scope.scenarioId,ss_generation:scope.generation,ss_owner_id:scope.platformOwnerId,ss_platform_session_id:scope.platformSessionId},secret,{algorithm:'HS256',issuer:ISSUER,audience:AUDIENCE,subject:String(user.id),jwtid:jti,expiresIn:60});
 };
 const router=createBoundRoleChatRouter({role:'merchant',launches,authenticatePersona:auth.authenticatePersona,runtime:f.runtime});
 const platformToken=jwt.sign({role:'merchant',sub:String(merchant.id)},secret,{algorithm:'HS256',issuer:'controlled-platform',audience:'platform-session',expiresIn:60});
 return{router,issue,foreignLaunch,platformToken};
}
const confirmPath='/agents/merchant/assistant/mail/confirm';
const readPath='/agents/merchant/assistant/mail/operations/:sessionId/:requestId/:operationId';
function confirmationBody(prepared){return{sessionId:prepared.sessionId,requestId:prepared.requestId,proposalId:prepared.proposalId};}
function recoveryParams(prepared){return{sessionId:prepared.sessionId,requestId:prepared.requestId,operationId:prepared.proposalId};}

test('Q05/Q07 actual merchant handlers reject role and valid foreign-launch substitutions without effect or model work',async()=>{
 const f=controlledRuntime(),prepared=await preparedSend(f),a=routedAuthority(f);
 const variants=[
  ['customer persona',a.issue({id:8,role:'customer'}),'a'.repeat(43),403],
  ['administrator persona',a.issue({id:9,role:'admin'}),'a'.repeat(43),403],
  ['another valid merchant',a.issue({id:7,role:'merchant'}),'a'.repeat(43),401],
  ['independently valid foreign launch',a.issue(merchant,a.foreignLaunch),'b'.repeat(43),401],
 ];
 const modelBefore=f.modelCalls;
 for(const [label,token,launchBearer,status] of variants){
  const confirm=await invokeRoute(a.router,'post',confirmPath,{body:confirmationBody(prepared),token,launchBearer});
  assert.equal(confirm.status,status,label);
  const read=await invokeRoute(a.router,'get',readPath,{params:recoveryParams(prepared),token,launchBearer});
  assert.equal(read.status,status,`${label} saved GET`);
  assert.equal(f.effects.size,0,label);assert.equal(f.sends,0,label);assert.equal(f.recovers,0,label);assert.equal(f.modelCalls,modelBefore,label);
 }
 // A denied request must not poison the original proposal or its authority.
 const ownToken=a.issue();
 const valid=await invokeRoute(a.router,'post',confirmPath,{body:confirmationBody(prepared),token:ownToken});
 assert.equal(valid.status,200);assert.equal(valid.body.status,'saved');assert.equal(f.sends,1);assert.equal(f.effects.size,1);
 const saved=await invokeRoute(a.router,'get',readPath,{params:recoveryParams(prepared),token:ownToken});
 assert.equal(saved.status,200);assert.deepEqual(saved.body,valid.body);assert.equal(f.sends,1);assert.equal(f.modelCalls,modelBefore);
});

test('Q05 production confirmation handler rejects request-body authority and model-produced confirmation fields',async()=>{
 const f=controlledRuntime(),prepared=await preparedSend(f),a=routedAuthority(f),token=a.issue();
 const body=confirmationBody(prepared),modelBefore=f.modelCalls;
 for(const injected of [{confirmed:true},{persona:merchant},{scope:launch},{subject:'changed argument'},{authorityVersion:'2'}]){
  const result=await invokeRoute(a.router,'post',confirmPath,{body:{...body,...injected},token});
  assert.equal(result.status,400);assert.equal(f.effects.size,0);assert.equal(f.sends,0);assert.equal(f.recovers,0);
 }
 const valid=await invokeRoute(a.router,'post',confirmPath,{body,token});
 assert.equal(valid.status,200);assert.equal(valid.body.status,'saved');assert.equal(f.sends,1);assert.equal(f.modelCalls,modelBefore);
});

test('Q07 real JWT middleware rejects platform-only authority and revoked persona for both confirmation and saved GET',async()=>{
 const f=controlledRuntime(),prepared=await preparedSend(f),a=routedAuthority(f),token=a.issue();
 const body=confirmationBody(prepared),params=recoveryParams(prepared),modelBefore=f.modelCalls;
 for(const presented of [undefined,a.platformToken]){
  assert.equal((await invokeRoute(a.router,'post',confirmPath,{body,token:presented})).status,401);
  assert.equal((await invokeRoute(a.router,'get',readPath,{params,token:presented})).status,401);
 }
 assert.equal(f.effects.size,0);assert.equal(f.sends,0);assert.equal(f.recovers,0);
 const valid=await invokeRoute(a.router,'post',confirmPath,{body,token});assert.equal(valid.status,200);assert.equal(f.sends,1);
 const immutable=structuredClone([...f.effects]);
 f.revokePersona();
 await assert.rejects(f.runtime.confirmMail({scope:launch,persona:merchant,personaSession,...body}),{code:'SHOP_AUTH_INVALID'});
 assert.equal((await invokeRoute(a.router,'post',confirmPath,{body,token})).status,401);
 assert.equal((await invokeRoute(a.router,'get',readPath,{params,token})).status,401);
 assert.deepEqual([...f.effects],immutable);assert.equal(f.sends,1);assert.equal(f.modelCalls,modelBefore);
});
