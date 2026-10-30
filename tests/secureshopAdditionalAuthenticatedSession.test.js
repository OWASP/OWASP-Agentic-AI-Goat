'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),Module=require('node:module'),vm=require('node:vm');
const P={ROOT:path.resolve(__dirname,'..')};
const outputs=Object.fromEntries(["server/services/secureshopStandaloneAuth.js","server/database/postgres/secureshopStandaloneAuthRepository.js","server/services/secureshopBoundPersonaAuth.js","server/database/postgres/secureshopBoundPersonaRepository.js","server/routes/secureshop/boundGateway.js","server/services/secureshopBoundApplication.js","db/postgres/workshop-migrations/secureshop_agents/0119_bound_additional_authenticated_sessions.sql"].map(p=>[p,fs.readFileSync(path.join(P.ROOT,p),'utf8')]));
function load(rel){return require(path.join(P.ROOT,rel));}
// Reuse the existing actual-service fixture, not a manufactured branded principal.
const original=fs.readFileSync(path.join(P.ROOT,'tests/secureshopStandaloneAuthService.test.js'),'utf8');
let fixtureSource=original.slice(0,original.indexOf("test('standalone bootstrap"));
fixtureSource=fixtureSource.replace('return { service, calls, sessions };','return { service, calls, sessions, repository };');
const fixtureModule=new Module(path.join(P.ROOT,'tests/secureshopStandaloneAuthService.test.js'),module);
fixtureModule.filename=path.join(P.ROOT,'tests/secureshopStandaloneAuthService.test.js');fixtureModule.paths=Module._nodeModulePaths(path.join(P.ROOT,'tests'));
const nativeRequire=fixtureModule.require.bind(fixtureModule);
fixtureModule.require=r=>r==='../server/services/secureshopStandaloneAuth'?load('server/services/secureshopStandaloneAuth.js'):nativeRequire(r);
fixtureModule._compile(fixtureSource+'\nmodule.exports=fixture;',fixtureModule.filename);
async function setup(){
 const f=fixtureModule.exports();const account=await f.service.register({username:'alice',email:'alice@shop.test',password:'password123',role:'customer'});
 const execution=await f.service.establishTenantContext(account.context);let mutation=null,locked=false;
 f.repository.readExistingExecutionSession=f.repository.readOrCreateDefaultExecutionSession;
 f.repository.withCurrentCredential=async(hash,expected,action)=>{assert.equal(expected.sessionId,execution.sessionId);const row=await f.repository.readCredentialForSession(hash);if(!row)throw Object.assign(new Error(),{code:'SHOP_AUTH_INVALID'});Object.assign(row,{tenantId:execution.tenantId,membershipVersion:execution.membershipVersion},mutation);locked=true;try{return await action(row);}finally{locked=false;}};
 return {...f,account,execution,setMutation:x=>{mutation=x;},locked:()=>locked,
 reauth:(action=async p=>p,args={})=>f.service.withReauthenticatedExecution({token:account.token,username:'alice',password:'password123',...args},action)};
}
test('actual additional-session JavaScript modules compile',()=>{
 for(const [p,s]of Object.entries(outputs))if(p.endsWith('.js'))new vm.Script(Module.wrap(s),{filename:p});
 assert.equal(Object.keys(outputs).length,7);
});
test('reauthentication issues only an actual branded existing execution inside current lock',async()=>{
 const f=await setup();const result=await f.reauth(async p=>{assert.equal(f.locked(),true);assert.equal(load('server/services/secureshopStandaloneAuth.js').assertSecureShopStandalonePrincipal(p),p);return p;});
 assert.equal(result.sessionId,f.execution.sessionId);assert.equal(result.authSessionId,f.account.context.sessionId);assert.equal(f.sessions.size,1);assert.equal(f.locked(),false);
});
test('bad password and foreign username retain failed-login behavior and never issue',async()=>{
 for(const args of [{password:'wrong'},{username:'bob'}]){const f=await setup();let issued=false;await assert.rejects(f.reauth(()=>{issued=true;},args),{code:'SHOP_CREDENTIALS_INVALID'});assert.equal(issued,false);assert.equal(f.calls.filter(x=>x[0]==='failed').length,1);}
});
test('credential/authority/membership/tenant/principal/current expiry drift denies before issuance',async()=>{
 for(const change of [{passwordHash:'rotated'},{credentialVersion:'2'},{authorityVersion:'2'},{membershipVersion:'2'},{tenantId:'00000000-0000-4000-8000-000000000000'},{principalId:'foreign'},{sessionId:999},{role:'admin'},{expiresAt:new Date(0)}]){const f=await setup();f.setMutation(change);let issued=false;await assert.rejects(f.reauth(()=>{issued=true;}),{code:'SHOP_AUTH_INVALID'});assert.equal(issued,false);}
});
test('revoked auth session and absent existing execution cannot issue or allocate',async()=>{
 const f=await setup();f.sessions.clear();await assert.rejects(f.reauth(),{code:'SHOP_CREDENTIALS_INVALID'});
 const g=await setup();g.repository.readExistingExecutionSession=async()=>{throw Object.assign(new Error(),{code:'SHOP_AUTH_INVALID'});};await assert.rejects(g.reauth(),{code:'SHOP_AUTH_INVALID'});assert.equal(g.sessions.size,1);
});
test('existing-only SQL removes allocation; locked recheck fences membership and revocation',()=>{
 const s=outputs['server/database/postgres/secureshopStandaloneAuthRepository.js'];const b=s.slice(s.indexOf('async readExistingExecutionSession'),s.indexOf('async readOrCreateDefaultExecutionSession'));
 assert.doesNotMatch(b,/INSERT INTO/);assert.match(b,/practice_selections/);assert.match(b,/execution.revokedAt/);assert.match(s,/FOR SHARE OF s,p,m,t`/);
});
test('forward migration preserves existing canonical rows and unique bootstrap; additional kind immutable',()=>{
 const sql=outputs['db/postgres/workshop-migrations/secureshop_agents/0119_bound_additional_authenticated_sessions.sql'];
 assert.match(sql,/boolean NOT NULL DEFAULT false/);assert.match(sql,/revoked_at IS NULL AND NOT additional_session/);assert.match(sql,/NEW.additional_session IS DISTINCT FROM OLD.additional_session/);
 const repo=outputs['server/database/postgres/secureshopBoundPersonaRepository.js'];assert.match(repo,/bootstrap && !additionalSession/);assert.match(repo,/additional_session=false AND revoked_at IS NULL/);assert.match(repo,/bootstrap_persona_authority_version=\$14 AND credential_version=\$15 FOR UPDATE/);
});
async function boundSetup(){
 const f=await setup(),sessions=new Map();let canonical=null,reset=false;
 const scope={launchId:f.execution.tenantId,scenarioId:'20000000-0000-4000-8000-000000000082',generation:1,platformOwnerId:f.execution.ownerId,platformSessionId:f.execution.sessionId};
 const actor={id:f.execution.shopUserId,username:f.execution.username,email:f.execution.email,role:f.execution.role};
 const authority={async read(){return {role:actor.role,authority_version:'1'};}};
 const repository={candidatePersonaAuthority:authority,async findCredential(){return null;},async findCredentialById(){return actor;},async ensureStandaloneActor(){return actor;},
 async createSession(input){
   assert.equal(input.bootstrap.executionSessionId,scope.platformSessionId);
   if(input.additionalSession){assert.equal(f.locked(),true);assert(sessions.has(input.sourceJti));}
   else if(canonical&&sessions.has(canonical))return {...sessions.get(canonical),reused:true};
   const row={sessionId:input.sessionId,jti:input.jti,expiresAt:input.expiresAt};sessions.set(input.jti,row);if(!input.additionalSession)canonical=input.jti;return row;
 },async readSession({jti}){const row=sessions.get(jti);return row&&{session_id:row.sessionId,shop_user_id:actor.id,...actor,expires_at:row.expiresAt};},
 async revokeSession({jti}){return sessions.delete(jti);}};
 for(const name of ['extendSession','listSessions','revokeOwnedSession','changePassword','readApiKey','rotateApiKey','authenticateApiKey'])repository[name]=async()=>null;
 const persona=load('server/services/secureshopBoundPersonaAuth.js').createSecureShopBoundPersonaAuth({repository,personaAuthority:authority,jwtSecret:'controlled-secret-at-least-thirty-two-bytes',launches:{async assertCurrent(){if(reset)throw Object.assign(new Error(),{code:'STALE_LAUNCH'});return {expiresAt:f.execution.expiresAt};}}});
 return {...f,persona,scope,sessions,repository,setReset:()=>{reset=true;}};
}
test('actual bound service adds distinct authenticated session; canonical bootstrap stays reused and sibling survives revoke',async()=>{
 const f=await boundSetup();const first=await f.persona.establishSession({scope:f.scope,shopPrincipal:f.execution});
 const second=await f.reauth(p=>f.persona.establishAdditionalSession({scope:f.scope,shopPrincipal:p,token:first.token}));
 const a=await f.persona.authenticateBoundToken({scope:f.scope,token:first.token}),b=await f.persona.authenticateBoundToken({scope:f.scope,token:second.token});
 assert.notEqual(a.sessionId,b.sessionId);assert.equal(f.sessions.size,2);
 const again=await f.persona.establishSession({scope:f.scope,shopPrincipal:f.execution});assert.equal((await f.persona.authenticateBoundToken({scope:f.scope,token:again.token})).sessionId,a.sessionId);
 await f.repository.revokeSession({jti:b.jti});await assert.rejects(f.persona.authenticateBoundToken({scope:f.scope,token:second.token}),{code:'SHOP_AUTH_INVALID'});
 assert.equal((await f.persona.authenticateBoundToken({scope:f.scope,token:first.token})).sessionId,a.sessionId);
 assert(new Date(second.expiresAt)<=new Date(f.execution.expiresAt));
});
test('actual bound additional issuance denies forged principal, foreign launch, reset and revoked source token',async()=>{
 const f=await boundSetup();const first=await f.persona.establishSession({scope:f.scope,shopPrincipal:f.execution});
 await assert.rejects(f.persona.establishAdditionalSession({scope:f.scope,shopPrincipal:{...f.execution},token:first.token}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(f.reauth(p=>f.persona.establishAdditionalSession({scope:{...f.scope,platformOwnerId:999},shopPrincipal:p,token:first.token})),{code:'SHOP_AUTH_INVALID'});
 const a=await f.persona.authenticateBoundToken({scope:f.scope,token:first.token});await f.repository.revokeSession({jti:a.jti});
 await assert.rejects(f.reauth(p=>f.persona.establishAdditionalSession({scope:f.scope,shopPrincipal:p,token:first.token})),{code:'SHOP_AUTH_INVALID'});
 f.setReset();await assert.rejects(f.reauth(p=>f.persona.establishAdditionalSession({scope:f.scope,shopPrincipal:p,token:first.token})),{code:'STALE_LAUNCH'});
 assert.equal(f.sessions.size,0);
});
test('actual login route preserves template branch; cookie reauth failure never falls back; body scope injection denies',async()=>{
 const source=outputs['server/routes/secureshop/boundGateway.js'];const start=source.indexOf("  router.post('/v2/auth/login', handle(async (req, res) => {");
 const body=source.slice(start,source.indexOf("  router.post('/v2/auth/logout'",start));
 let handler,templateCalls=0,additionalCalls=0,reauthCalls=0;
 const standaloneAuth={async withReauthenticatedExecution(){reauthCalls++;throw Object.assign(new Error(),{code:'SHOP_AUTH_INVALID'});}};
 const personaAuth={async login(){templateCalls++;return {ok:true,template:true};},async establishAdditionalSession(){additionalCalls++;}};
 vm.runInNewContext(body,{router:{post(route,fn){handler=fn;}},handle:fn=>fn,standaloneAuth,personaAuth,
 exactQuery:req=>Object.keys(req.query).length===0,exactBody:req=>Object.keys(req.body).every(k=>['username','password'].includes(k)),
 readBearer:()=>null,require:()=>({readShopCookie:require(path.join(P.ROOT,'server/routes/secureshopStandaloneAuth')).readShopCookie})});
 const request=cookie=>({headers:{cookie},query:{},body:{username:'template',password:'password'},ssLaunch:{},get:()=>null});
 const response={statusCode:200,status(n){this.statusCode=n;return this;},json(x){return x;}};
 await handler(request(''),response);assert.equal(templateCalls,1);
 for(const token of ['a'.repeat(43),'b'.repeat(43)])await assert.rejects(handler(request('owasp_ai_goat_shop_session='+token),response),{code:'SHOP_AUTH_INVALID'});
 assert.equal(reauthCalls,2);assert.equal(templateCalls,1);assert.equal(additionalCalls,0);
 const bad=request('');bad.body.ownerId=123;await handler(bad,response);assert.equal(response.statusCode,400);assert.equal(templateCalls,1);
});

test('reauth locks only mutable runtime-authorized rows and retains immutable snapshot equality',()=>{
 const s=outputs['server/database/postgres/secureshopStandaloneAuthRepository.js'];
 const method=s.slice(s.indexOf('async withCurrentCredential('),s.indexOf('async changePassword(',s.indexOf('async withCurrentCredential(')));
 assert.deepEqual([...method.matchAll(/FOR SHARE OF ([a-z,]+)/g)].map(x=>x[1]),['s,p,m,t','e,x']);
 assert.match(method,/JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id/);
 assert.match(method,/v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version/);
 const read=n=>fs.readFileSync(path.join(P.ROOT,'db/postgres/identity-migrations',n),'utf8');
 const names=fs.readdirSync(path.join(P.ROOT,'db/postgres/identity-migrations'));
 const migration=n=>read(names.find(x=>x.startsWith(n+'_')));
 assert.match(migration('0137'),/GRANT SELECT,INSERT,UPDATE ON secureshop_auth.principals,secureshop_auth.sessions TO dvaia_identity_runtime/);
 assert.match(migration('0139').split(String.fromCharCode(10)).join(''),/GRANT SELECT,INSERT,UPDATE ON secureshop_auth.tenants,secureshop_auth.tenant_memberships, *secureshop_auth.execution_sessions TO dvaia_identity_runtime/);
 assert.match(migration('0150'),/GRANT SELECT,INSERT,UPDATE ON secureshop_auth.practice_selections,secureshop_auth.practice_preferences TO dvaia_identity_runtime/);
 const immutable=migration('0148');
 assert.match(immutable,/GRANT SELECT ON secureshop_auth.session_membership_snapshots TO dvaia_identity_runtime/);
 assert.match(immutable.split(String.fromCharCode(10)).join(''),/shop_session_memberships_immutable BEFORE UPDATE OR DELETE ON secureshop_auth.session_membership_snapshots +FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_tenant_admin_history/);
 assert.match(immutable,/RAISE EXCEPTION 'Tenant authority history is immutable' USING ERRCODE='55000'/);
});
