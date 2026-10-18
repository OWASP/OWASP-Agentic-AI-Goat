'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const jwt=require('jsonwebtoken');
const {EventEmitter}=require('node:events');
const {Cookie}=require('express-session');
const {readSessionLifetimeConfiguration:read}=require('../server/services/sessionLifetimeConfiguration');
const {createPostgresIdentityAdapter:create}=require('../server/services/postgresIdentityAdapter');
const {createPostgresAuthRouter}=require('../server/routes/postgresAuth');

test('lifetime configuration preserves defaults and accepts only shorter integer seconds',()=>{
 assert.deepEqual(read({}),{shopSessionTtlSeconds:14400,platformSessionTtlSeconds:86400});
 assert.deepEqual(read({SS_SESSION_TTL_SECONDS:'120',PLATFORM_SESSION_TTL_SECONDS:'300'}),{shopSessionTtlSeconds:120,platformSessionTtlSeconds:300});
 for(const [key,max] of [['SS_SESSION_TTL_SECONDS',14400],['PLATFORM_SESSION_TTL_SECONDS',86400]]){
  for(const value of ['', ' ', '119','0','-120','120.5','1.2e2','0x78','0120','120s','120 ',String(max+1),'999999999999999999999999',120,null]) {
   assert.throws(()=>read({[key]:value}),{code:'INVALID_CONFIGURATION'},`${key}: ${String(value)}`);
  }
 }
});
test('production identity construction rejects invalid lifetime configuration before opening a database pool',()=>{
 const Module=require('node:module'),filename=require.resolve('../server/services/postgresIdentityAdapter');
 const originalLoad=Module._load,originalCache=require.cache[filename];let poolCalls=0;
 const keys=['JWT_SECRET','SS_SESSION_TTL_SECONDS','PLATFORM_SESSION_TTL_SECONDS'];
 const old=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
 try{
  process.env.JWT_SECRET='private-unit-signing-key-longer-than-thirty-two-bytes';
  delete process.env.SS_SESSION_TTL_SECONDS;delete process.env.PLATFORM_SESSION_TTL_SECONDS;
  Module._load=function(request,parent,...rest){
   if(parent?.filename===filename&&request==='../database/postgres')return{createPool(){poolCalls++;throw Error('unexpected pool');}};
   return originalLoad.call(this,request,parent,...rest);
  };
  for(const key of keys.slice(1)){
   delete require.cache[filename];process.env[key]='119';
   assert.throws(()=>require(filename).getPostgresIdentityAdapter(),{code:'INVALID_CONFIGURATION'});
   delete process.env[key];
  }
  assert.equal(poolCalls,0);
 }finally{
  Module._load=originalLoad;require.cache[filename]=originalCache;
  for(const key of keys){if(old[key]===undefined)delete process.env[key];else process.env[key]=old[key];}
 }
});
function adapter(options={}){
 const saved=[];
 const user={id:7,username:'learner',password:'private-hash',is_active:true,role:'student',admin_level:0};
 const repository={
  findCredentialByUsername:async()=>user,getUserById:async()=>user,getUserPermissions:async()=>[],recordAudit:async()=>{},
  createSession:async input=>{saved.push(input);return{id:71,expires_at:input.expiresAt};},
 };
 return{saved,user,value:create({repository,jwtSecret:'owned-unit-signing-key',...options})};
}
test('platform constructor rejects invalid policy before issuing credentials',()=>{
 for(const sessionTtlSeconds of [0,60,119,86401,Infinity,NaN,120.5,'120',null]) {
  assert.throws(()=>adapter({sessionTtlSeconds}),{code:'INVALID_CONFIGURATION'});
 }
});
for(const [name,sessionTtlSeconds,loginSeconds,secureSeconds] of [
 ['default',undefined,86400,3600],['short',120,120,120],['two hours',7200,7200,3600],
])test(`real platform routes apply ${name} cap with matching JWT and database expiry`,async t=>{
 const f=adapter({sessionTtlSeconds}),pass=(_req,_res,next)=>next();
 const router=createPostgresAuthRouter({adapter:f.value,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass},
  loginRuntime:{run:async(_signal,work)=>work({check(){},compare:async()=>true}),close(){}}});
 t.after(()=>router.close());
 for(const [endpoint,seconds] of [['/login',loginSeconds],['/secure-login',secureSeconds]]){
  const req=Object.assign(new EventEmitter(),{method:'POST',body:{username:'learner',password:'credential'},ip:'127.0.0.1',get:()=>undefined});
  let savedCookie;
  req.session={regenerate(done){req.session={cookie:new Cookie({maxAge:14400000}),save(callback){savedCookie=this.cookie.expires;callback();}};done();}};
  const res=new EventEmitter();let status=200;
  const body=await new Promise((resolve,reject)=>{
   res.status=code=>{status=code;return res;};res.json=value=>{res.writableFinished=true;resolve(value);};
   const layers=router.stack.find(x=>x.route?.path===endpoint).route.stack;let at=0;
   const next=error=>{if(error)return reject(error);Promise.resolve(layers[at++].handle(req,res,next)).catch(reject);};next();
  });
  assert.equal(status,200);
  const claims=jwt.verify(body.token,'owned-unit-signing-key');
  assert.equal(claims.exp-claims.iat,seconds);
  assert.equal(f.saved.at(-1).expiresAt.getTime(),claims.exp*1000);
  assert.ok(savedCookie.getTime()<=claims.exp*1000);
  assert.ok(savedCookie.getTime()<=Date.now()+14400000,'default teaching cookie is never extended');
  if(endpoint==='/login')assert.equal(Date.parse(body.sessionInfo.expiresAt),claims.exp*1000);
 }
});
test('trusted shorter internal session duration is preserved by the configured platform cap',async()=>{
 const f=adapter({sessionTtlSeconds:120});
 const issued=await f.value.createSession(f.user,{},{durationMs:1000});
 const claims=jwt.decode(issued.token);assert.equal(claims.exp-claims.iat,1);
 assert.equal(Date.parse(issued.expiresAt),claims.exp*1000);
});
