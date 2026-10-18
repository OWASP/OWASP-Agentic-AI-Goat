'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPrivateAuditServer}=require('../sidecars/audit-sql-target/http');
test('private loopback admission rejects unauthorized calls and joins admitted operations before close',async()=>{
 let release,entered;const started=new Promise(r=>{entered=r;});const done=new Promise(r=>{release=r;});let closed=false;
 const app=createPrivateAuditServer({token:'a'.repeat(48),maxActive:1,backend:{readiness:async()=>({ready:true}),provision:async()=>{},search:async()=>{entered();await done;return{ok:true};},retire:async()=>{},close:async()=>{closed=true;}}});
 const address=await app.listen();assert.equal(address.address,'127.0.0.1');const url=`http://127.0.0.1:${address.port}`;
 const call=(route,auth=true)=>fetch(url+route,{method:'POST',headers:auth?{authorization:'Bearer '+'a'.repeat(48)}:{},body:'{}'});
 try{
  assert.equal((await call('/readiness',false)).status,401);
  const running=call('/search');await started;assert.equal((await call('/readiness')).status,503);
  const closing=app.close();await new Promise(r=>setImmediate(r));assert.equal(closed,false);release();assert.equal((await running).status,200);await closing;assert.equal(closed,true);
 }finally{release();if(!closed)await app.close();}
});
test('cleanup-only daemon denies new provisioning and execution while retaining retirement',async()=>{
 let retired=0,admitted=0;const app=createPrivateAuditServer({token:'b'.repeat(48),admissions:false,backend:{readiness:async()=>({ready:true}),provision:async()=>{admitted++;},search:async()=>{admitted++;},retire:async()=>{retired++;},close:async()=>{}}});const address=await app.listen();
 try{const call=route=>fetch(`http://127.0.0.1:${address.port}${route}`,{method:'POST',headers:{authorization:'Bearer '+'b'.repeat(48)},body:'{}'});assert.equal((await call('/provision')).status,409);assert.equal((await call('/search')).status,409);assert.equal((await call('/retire')).status,200);assert.equal(admitted,0);assert.equal(retired,1);}finally{await app.close();}
});
