'use strict';
// Additive R02 helper; caller owns the current full application, pages, stores and deadline.
const assert=require('node:assert/strict');
const PATHS=new Set(['/api/auth/status','/api/auth/logout','/api/auth/secureshop-launch','/api/admin/users','/api/secureshop/v2/auth/login','/api/secureshop/v2/auth/renew','/api/secureshop/v2/auth/whoami']);
function admit({origin,env,signal,owner,sibling}){
 const url=new URL(origin);assert.equal(url.origin,origin);assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');assert(url.port);
 for(const k of ['PG_TEST_DISPOSABLE','SS_ENABLE','SS_BOUND_REVIEWS_ENABLED'])assert.equal(env[k],k==='PG_TEST_DISPOSABLE'?'yes':'true');
 assert.equal(env.AI_PROVIDER,'mock');assert(signal instanceof AbortSignal);signal.throwIfAborted();
 assert(Number.isSafeInteger(owner.id)&&Number.isSafeInteger(sibling.id)&&owner.id!==sibling.id);
 for(const row of [owner,sibling]){assert.equal(typeof row.token,'string');assert(row.token);assert(row.page&&typeof row.page.reload==='function');}
}
function assertStatus(result,id){assert.equal(result.status,200);assert.equal(result.body.authenticated,true);assert.equal(Number(result.body.user.id),id);}
function assertRenewal(before,after){
 const decode=token=>{const parts=token.split('.');assert.equal(parts.length,3);return JSON.parse(Buffer.from(parts[1],'base64url'));};
 assert.equal(after.status,200);assert.equal(typeof after.body.token,'string');assert.equal(decode(after.body.token).jti,decode(before.token).jti);
 assert.equal(after.body.user.id,before.user.id);assert.equal(after.body.user.role,before.user.role);
 assert(Number.isFinite(Date.parse(after.body.expiresAt))&&Date.parse(after.body.expiresAt)>=Date.parse(before.expiresAt));
}
async function qualifyBoundSessions({origin,env,signal,owner,sibling,persona,fetch:send=global.fetch,record=()=>{}}){
 admit({origin,env,signal,owner,sibling});assert.equal(persona.username,'student_customer');assert.equal(typeof persona.password,'string');assert(persona.password);
 let requests=0;const checks={};
 async function request(path,{token,launch,cookie,method='GET',body}={}){
  assert(PATHS.has(path));signal.throwIfAborted();assert(++requests<=32);
  const response=await send(origin+path,{method,redirect:'error',signal:AbortSignal.any([signal,AbortSignal.timeout(15000)]),headers:{...(token?{authorization:'Bearer '+token}:{}),...(launch?{'x-owasp-ai-goat-secureshop-launch':launch}:{}),...(cookie?{cookie}:{}),...(body!==undefined?{'content-type':'application/json'}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
  const text=await response.text();assert(Buffer.byteLength(text)<=65536);return{status:response.status,body:JSON.parse(text)};
 }
 const save=()=>record({scope:'R02-composed-bound-sessions',checks:{...checks},requests,actualModel:false,creditAuthorized:false});
 const sessions=[];
 for(const user of [owner,sibling]){
  await user.page.reload({waitUntil:'domcontentloaded'});signal.throwIfAborted();
  const status=await user.page.evaluate(async()=>{const token=localStorage.getItem('token');const r=await fetch('/api/auth/status',{headers:token?{authorization:'Bearer '+token}:{}});return{status:r.status,body:await r.json()};});assertStatus(status,user.id);
  const issued=await request('/api/auth/secureshop-launch',{token:user.token,method:'POST',body:{}});assert.equal(issued.status,201);assert.equal(issued.body.preparationOnly,false);assert.equal(typeof issued.body.bearer,'string');
  const login=await request('/api/secureshop/v2/auth/login',{launch:issued.body.bearer,method:'POST',body:persona});assert.equal(login.status,200);assert.equal(login.body.user.role,'customer');assert.equal(typeof login.body.token,'string');
  sessions.push({user,launch:issued.body.bearer,login:login.body});
 }
 checks.reloadStatusRestored=true;save();
 const [a,b]=sessions;const renewed=await request('/api/secureshop/v2/auth/renew',{launch:a.launch,token:a.login.token,method:'PATCH',body:{}});assertRenewal(a.login,renewed);checks.boundRenewal=true;save();
 assert.equal((await request('/api/secureshop/v2/auth/whoami',{launch:b.launch,token:renewed.body.token})).status,401);checks.crossOwnerDenied=true;
 for(const cookie of [owner.cookie,'connect.sid=s%3Aforged-owner.admin-signature']){
  assert.equal(typeof cookie,'string');assert(cookie);
  assert.equal((await request('/api/admin/users',{cookie})).status,401);
  assert.equal((await request('/api/auth/secureshop-launch',{cookie})).status,401);
  assert.equal((await request('/api/secureshop/v2/auth/whoami',{cookie})).status,401);
 }
 checks.cookieOnlyDenied=true;save();
 assert.equal((await request('/api/auth/logout',{token:owner.token,cookie:owner.cookie,method:'POST',body:{}})).status,200);
 const dead=await request('/api/auth/status',{token:owner.token,cookie:owner.cookie});assert.equal(dead.status,200);assert.equal(dead.body.authenticated,false);
 assert.equal((await request('/api/auth/secureshop-launch',{token:owner.token,cookie:owner.cookie})).status,401);
 for(const path of ['/api/secureshop/v2/auth/whoami','/api/secureshop/v2/auth/renew'])assert.equal((await request(path,{launch:a.launch,token:renewed.body.token,cookie:owner.cookie,...(path.endsWith('/renew')?{method:'PATCH',body:{}}:{})})).status,401);
 checks.platformLogoutFencesBound=true;
 assertStatus(await request('/api/auth/status',{token:sibling.token,cookie:sibling.cookie}),sibling.id);
 const siblingWho=await request('/api/secureshop/v2/auth/whoami',{launch:b.launch,token:b.login.token});assert.equal(siblingWho.status,200);assert.equal(siblingWho.body.user.id,b.login.user.id);
 checks.siblingPreserved=true;save();return{scope:'R02-composed-bound-sessions',checks,requests,actualModel:false,creditAuthorized:false};
}
module.exports={admit,assertStatus,assertRenewal,qualifyBoundSessions};
