'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express'),{randomUUID}=require('node:crypto');
const {createBoundUserAdministrationRouter:create}=require('../server/routes/secureshop/boundUserAdministration');
test('reset routes use private original middleware identity and no-store safe receipts',async t=>{
 const operationId=randomUUID(),calls=[],receipt={operationId,targetId:2,credentialVersion:'2',authorityVersion:'3',receiptSha256:'a'.repeat(64),expiresAt:new Date().toISOString(),actorSessionId:randomUUID(),scope:{private:'not projected'}};
 const {compileBridgeOperation}=await import('../client/src/pages/secureshop/bridge/compiler.mjs');
 const app=express();app.use(express.json());app.use(create({service:{users(){},mutate(){},resetPassword:async input=>{calls.push(input);return{receipt,secretAvailable:true};},readPasswordReset:async()=>null,acknowledgePasswordReset:async()=>({receipt,secretAvailable:false}),revealPasswordReset:async()=>({receipt,temporaryPassword:'A'.repeat(40)})},authenticatePersona(req,res,next){req.ssLaunch={launchId:'trusted'};req.ssUser={id:3,role:'admin'};req.ssPersonaSession={sessionId:'original',authorityVersion:'5'};next();}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}/admin/users/2`;
 const post=(url,body)=>fetch(base+url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 const body={operationId,expectedCredentialVersion:'1',expectedAuthorityVersion:'2'};
 const response=await post('/reset-password',body);assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');assert.equal((await response.json()).receipt.actorSessionId,undefined);assert.equal(calls[0].personaSession.sessionId,'original');
 assert.equal((await post('/reset-password',{...body,actorSessionId:'forged'})).status,400);
 const reveal=await post(`/password-resets/${operationId}/reveal`,{});assert.equal(reveal.headers.get('cache-control'),'no-store');assert.equal((await reveal.json()).temporaryPassword,'A'.repeat(40));
 for(const name of ['admin.users.resetReveal','admin.users.resetAcknowledge']) {
  const compiled=compileBridgeOperation(name,{params:{id:'2',operationId},body:{}});
  const response=await fetch(`http://127.0.0.1:${server.address().port}`+compiled.path.replace('/api/secureshop',''),{
   method:compiled.method,...(compiled.body===undefined?{}:{headers:{'content-type':'application/json'},body:JSON.stringify(compiled.body)})});
  assert.equal(response.status,200,`${name} must preserve the strict JSON empty-body contract`);
 }
 assert.equal((await fetch(`${base}/password-resets/${operationId}`)).status,404);
});

test('teaching readiness route is closed, no-store and uses only original admin credentials',async t=>{
 const calls=[],scope={launchId:'trusted'},session={sessionId:'original',authorityVersion:'5'};
 const user={id:2,username:'student_customer',email:'customer@example.test',identityKind:'teaching_persona',channel:'bound_persona',credentialVersion:'4',authorityVersion:'3',resetAvailable:true};
 let failure=null,role='admin';
 const app=express();app.use(express.json());app.use(create({service:{users(){},mutate(){},passwordResetReadiness:async input=>{calls.push(input);if(failure)throw Object.assign(Error('PRIVATE_DIAGNOSTIC'),{code:failure});return{...user,temporaryPassword:'NEVER_PROJECT',actorSessionId:'private'};}},authenticatePersona(req,res,next){req.ssLaunch=scope;req.ssUser={id:3,role};req.ssPersonaSession=session;next();}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}/admin/users/`;
 const response=await fetch(base+'2/reset-readiness');assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');assert.deepEqual(await response.json(),{ok:true,user});
 assert.deepEqual(calls,[{scope,persona:{id:3,role:'admin'},personaSession:session,targetId:2}]);
 for(const suffix of ['02/reset-readiness','0/reset-readiness','2147483648/reset-readiness','2/reset-readiness?actorId=999'])assert.equal((await fetch(base+suffix)).status,400);
 assert.equal(calls.length,1);
 for(const [code,status] of [['SELF_RESET_UNSUPPORTED',403],['SHOP_AUTH_INVALID',401],['REGISTERED_RESET_UNAVAILABLE',503],['PRIVATE_ERROR',503]]){
  failure=code;const denied=await fetch(base+'2/reset-readiness');assert.equal(denied.status,status);assert.equal(denied.headers.get('cache-control'),'no-store');assert.doesNotMatch(await denied.text(),/PRIVATE_DIAGNOSTIC|PRIVATE_ERROR|NEVER_PROJECT/);
 }
 role='customer';const before=calls.length;assert.equal((await fetch(base+'2/reset-readiness')).status,403);assert.equal(calls.length,before);
});
