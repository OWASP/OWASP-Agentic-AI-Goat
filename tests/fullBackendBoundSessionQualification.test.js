'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {admit,assertStatus,assertRenewal}=require('./fixtures/fullBackendBoundSessionQualification');
const token=jti=>'a.'+Buffer.from(JSON.stringify({jti})).toString('base64url')+'.b';
test('R02 helper is inert and requires explicitly owned enabled bound mock application',()=>{
 const value={origin:'http://127.0.0.1:23456',env:{PG_TEST_DISPOSABLE:'yes',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',AI_PROVIDER:'mock'},signal:new AbortController().signal,owner:{id:1,token:'one',page:{reload(){}}},sibling:{id:2,token:'two',page:{reload(){}}}};
 admit(value);for(const key of Object.keys(value.env))assert.throws(()=>admit({...value,env:{...value.env,[key]:undefined}}));
 assert.throws(()=>admit({...value,origin:'http://example.invalid'}));assert.throws(()=>admit({...value,sibling:value.owner}));assert.throws(()=>admit({...value,signal:AbortSignal.abort()}));
});
test('reload identity and renewal cannot change persona or durable JTI or shorten expiry',()=>{
 const before={token:token('one'),user:{id:12,role:'customer'},expiresAt:'2030-01-01T00:00:00Z'};const after={status:200,body:{...before,expiresAt:'2030-01-01T00:10:00Z'}};
 assertRenewal(before,after);for(const change of [{token:token('other')},{user:{id:13,role:'customer'}},{user:{id:12,role:'admin'}},{expiresAt:'2029-01-01T00:00:00Z'},{expiresAt:'bad'}])assert.throws(()=>assertRenewal(before,{...after,body:{...after.body,...change}}));
 assertStatus({status:200,body:{authenticated:true,user:{id:1}}},1);assert.throws(()=>assertStatus({status:200,body:{authenticated:true,user:{id:2}}},1));
});
test('controlled composed sequence retains logout and sibling denials, never model credit',async()=>{
 const {qualifyBoundSessions}=require('./fixtures/fullBackendBoundSessionQualification');let loggedOut=false,reloads=0;
 const login={token:token('persona'),user:{id:12,role:'customer'},expiresAt:'2030-01-01T00:00:00Z'};
 const user=id=>({id,token:'platform'+id,cookie:'connect.sid=owned'+id,page:{async reload(){reloads++;},async evaluate(){return{status:200,body:{authenticated:true,user:{id}}};}}});
 const value={origin:'http://127.0.0.1:23456',env:{PG_TEST_DISPOSABLE:'yes',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',AI_PROVIDER:'mock'},signal:new AbortController().signal,owner:user(1),sibling:user(2),persona:{username:'student_customer',password:'synthetic'}};
 const calls=[];value.fetch=async(url,o)=>{const p=new URL(url).pathname,a=o.headers.authorization,l=o.headers['x-owasp-ai-goat-secureshop-launch'];calls.push({p,method:o.method});let status=200,body={};
  if(p==='/api/auth/logout'){loggedOut=true;body={success:true};}
  else if(p==='/api/auth/status')body={authenticated:a==='Bearer platform2'||!loggedOut,user:{id:a==='Bearer platform2'?2:1}};
  else if(p==='/api/auth/secureshop-launch'&&o.method==='POST'){status=201;body={preparationOnly:false,bearer:a==='Bearer platform1'?'launch1':'launch2'};}
  else if(p.endsWith('/login'))body={...login,token:token(l==='launch1'?'persona1':'persona2')};
  else if(p.endsWith('/renew')&&!loggedOut)body={...login,token:token('persona1')};
  else if(p.endsWith('/whoami')&&l==='launch2'&&a==='Bearer '+token('persona2'))body={user:login.user};
  else status=401;
  return new Response(JSON.stringify(body),{status});
 };
 const result=await qualifyBoundSessions(value);assert.equal(reloads,2);assert.equal(result.actualModel,false);assert.equal(result.creditAuthorized,false);assert.deepEqual(Object.values(result.checks),Array(6).fill(true));assert.equal(calls.filter(x=>x.p.endsWith('/renew')).length,2);
});
