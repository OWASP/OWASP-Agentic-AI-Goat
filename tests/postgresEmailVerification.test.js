'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPostgresAuthRouter}=require('../server/routes/postgresAuth');
const {createIdentityRepository}=require('../server/database/postgres/identityRepository');
function repository(email='old@example.test',failure=false){
 const calls=[];const client={async query(sql,args){calls.push({sql,args});if(sql.includes('FOR UPDATE'))return {rows:[{id:7,email,email_verified:1}]};if(sql.startsWith('UPDATE identity.users')){if(failure)throw new Error('controlled');return {rows:[{id:7,email:args[0]}]};}if(sql.startsWith('INSERT INTO identity.users'))return {rows:[{id:7}]};return {rows:[{id:1}]};},release(){calls.push({sql:'release'});}};
 return {repo:createIdentityRepository({connect:async()=>client}),calls};
}
for(const endpoint of ['/verify-email','/resend-verification'])test(endpoint+' unavailable before any account read or token operation',t=>{
 const pass=(_q,_s,next)=>next();const router=createPostgresAuthRouter({adapter:{repository:new Proxy({},{get(){throw new Error('No repository access allowed');}})},loginRuntime:{close(){}},limiters:{registerRateLimiter:pass,loginRateLimiter:pass,passwordResetRateLimiter:pass}});t.after(()=>router.close());
 const handler=router.stack.find(x=>x.route?.path===endpoint).route.stack[0].handle;let status;handler({body:{token:'exposed',email:'private@example.test'}},{status(n){status=n;return this;},json(body){assert.equal(status,409);assert.equal(body.code,'EMAIL_VERIFICATION_UNAVAILABLE');assert.equal(body.emailVerificationAvailable,false);assert.equal(Object.hasOwn(body,'verificationToken'),false);}});
});
test('changed email locks user and retires only owned tokens before clearing flag',async()=>{const {repo,calls}=repository();await repo.updateProfile(7,'new@example.test','Name');assert.deepEqual(calls.map(x=>x.sql.split(' ')[0]),['BEGIN','SELECT','UPDATE','UPDATE','COMMIT','release']);assert.match(calls[1].sql,/FOR UPDATE/);assert.deepEqual(calls[2].args,[7]);assert.deepEqual(calls[3].args,['new@example.test','Name',7,true]);assert.match(calls[3].sql,/CASE WHEN \$4 THEN 0 ELSE email_verified END/);});
test('unchanged email preserves instructor attestation and pending token state',async()=>{const {repo,calls}=repository();await repo.updateProfile(7,'old@example.test','Changed name');assert.equal(calls.some(x=>x.sql.includes('email_verification_tokens')),false);assert.equal(calls.find(x=>x.sql.startsWith('UPDATE')).args[3],false);});
test('profile failure rolls back token retirement and does not commit',async()=>{const {repo,calls}=repository(undefined,true);await assert.rejects(repo.updateProfile(7,'new@example.test','Name'),/controlled/);assert.equal(calls.some(x=>x.sql==='COMMIT'),false);assert.deepEqual(calls.slice(-2).map(x=>x.sql),['ROLLBACK','release']);});
for(const supplied of [false,true])test('repository registration optional internal token compatibility '+supplied,async()=>{const {repo,calls}=repository();await repo.registerUser({username:'student',email:'student@example.test',passwordHash:'$2b$12$'+'a'.repeat(53),...(supplied?{verificationToken:'controlled-token-value'}:{})});assert.equal(calls.some(x=>x.sql.includes('INSERT INTO identity.email_verification_tokens')),supplied);assert.equal(calls.some(x=>x.sql==='COMMIT'),true);});
test('mounted registration omits token and truthfully permits local login workflow',async t=>{
 let saved;const pass=(_q,_s,next)=>next();const router=createPostgresAuthRouter({adapter:{repository:{getConfig:async()=> 'true',registerUser:async row=>{saved=row;return {id:7,username:row.username,email:row.email};}}},loginRuntime:{close(){}},limiters:{registerRateLimiter:pass,loginRateLimiter:pass,passwordResetRateLimiter:pass}});t.after(()=>router.close());
 const route=router.stack.find(x=>x.route?.path==='/register').route;const body=await new Promise((resolve,reject)=>{let i=0;const req={ip:'controlled',body:{username:'learner',email:'learner@demo.local',password:'WorkshopPass@2026'}};const res={status(n){assert.equal(n,201);return this;},json:resolve};const next=e=>{if(e)return reject(e);Promise.resolve(route.stack[i++].handle(req,res,next)).catch(reject);};next();});
 assert.equal(Object.hasOwn(saved,'verificationToken'),false);assert.equal(Object.hasOwn(body,'verificationToken'),false);assert.equal(body.emailVerificationRequired,false);assert.equal(body.emailVerificationAvailable,false);assert.equal(body.emailVerificationMode,'local-instructor-managed');assert.equal(body.user.emailVerified,false);
});

test('new unverified local account can log in through the canonical route chain',async t=>{
 const {EventEmitter}=require('node:events'),bcrypt=require('bcryptjs');
 const pass=(_q,_s,next)=>next();let user,issued=0;
 const adapter={repository:{
  getConfig:async()=> 'true',
  registerUser:async row=>{assert.equal(Object.hasOwn(row,'verificationToken'),false);user={id:7,username:row.username,email:row.email,password:row.passwordHash,role:'student',admin_level:0,is_active:true,email_verified:false};return user;},
  findCredentialByUsername:async name=>name===user.username?user:null,
  getUserById:async id=>{assert.equal(id,7);return user;},getUserPermissions:async()=>[],recordAudit:async()=>{},
 },createSession:async account=>{assert.equal(account.email_verified,false);issued++;return{token:'controlled-session',internalSessionId:71,sessionInfo:{}};},userDto:account=>({id:account.id,role:account.role,emailVerified:account.email_verified})};
 const router=createPostgresAuthRouter({adapter,loginRuntime:{close(){},run:async(signal,work)=>work({check:()=>signal.throwIfAborted(),compare:(password,hash)=>bcrypt.compare(password,hash)})},limiters:{registerRateLimiter:pass,loginRateLimiter:pass,passwordResetRateLimiter:pass}});t.after(()=>router.close());
 const invoke=(endpoint,body)=>new Promise((resolve,reject)=>{
  const route=router.stack.find(x=>x.route?.path===endpoint).route,req=Object.assign(new EventEmitter(),{ip:'controlled',method:'POST',body}),res=new EventEmitter();let i=0,status=200;
  res.status=code=>{status=code;return res;};res.json=body=>{res.writableFinished=true;resolve({status,body});};
  const next=error=>{if(error)return reject(error);const layer=route.stack[i++];if(!layer)return reject(new Error('No response'));Promise.resolve(layer.handle(req,res,next)).catch(reject);};next();
 });
 const password='WorkshopPass@2026';
 const registration=await invoke('/register',{username:'learner',email:'learner@demo.local',password});assert.equal(registration.status,201);assert.equal(registration.body.user.emailVerified,false);
 const login=await invoke('/login',{username:'learner',password});assert.equal(login.status,200);assert.equal(login.body.success,true);assert.equal(login.body.user.emailVerified,false);assert.equal(login.body.user.role,'student');assert.equal(login.body.token,'controlled-session');assert.equal(issued,1);
});
