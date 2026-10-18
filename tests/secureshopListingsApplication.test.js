'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto'),express=require('express');
const {createListingsApplication}=require('../server/services/secureshopListingsApplication');
const {createBoundListingsRouter}=require('../server/routes/secureshop/boundListings');
function fixture(){
 const context={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 const request={version:1,action:'rewrite',operationId:randomUUID(),title:'Title',description:'Raw'};
 let stored=null,resolved=0,revoked=false,reads=0,resumes=0;
 const authority={capture(x){return{binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},async assertRemoteAdmission(){if(revoked)throw Object.assign(Error(),{code:'SHOP_AUTH_INVALID'});}};}};
 const composition={async recoverAdmission(){if(!stored)throw Object.assign(Error(),{code:'LISTING_NOT_FOUND'});return stored;},async run(x){stored=x;return{operation:{operationId:x.request.operationId,state:'completed',receipt:{html:'<img src=x onerror=owned()>',secret:'not projected'}}};},async recover(x){reads++;return{operation:{operationId:x.request.operationId,state:'unknown'},executor:{state:'completed',receiptHandle:'private'}};},async resume(x){resumes++;return{operation:{operationId:x.request.operationId,state:'declined'}};}};
 const application=createListingsApplication({composition,personaAuthority:authority,launches:{async assertCurrent(){}},async prepareTarget(){resolved++;return{targetId:randomUUID(),mode:'vuln',catalogRevision:'7'};}});
 return{context,request,application,composition,counts:()=>({resolved,reads,resumes}),revoke(){revoked=true;},stored:()=>stored};
}
test('application resolves ownership once and replays original revision; projection preserves HTML without private evidence',async()=>{
 const f=fixture(),result=await f.application.run({...f.context,request:f.request});
 assert.deepEqual(result,{ok:true,operationId:f.request.operationId,state:'completed',html:'<img src=x onerror=owned()>'});
 await f.application.run({...f.context,request:f.request});assert.equal(f.counts().resolved,1);assert.equal(f.stored().catalogRevision,'7');
 await assert.rejects(f.application.run({...f.context,request:{...f.request,title:'changed'}}),{code:'LISTING_OPERATION_CONFLICT'});
 await f.application.operation({...f.context,operationId:f.request.operationId});assert.deepEqual(f.counts(),{resolved:1,reads:1,resumes:0});
 await f.application.resume({...f.context,operationId:f.request.operationId});assert.equal(f.counts().resumes,1);
 f.revoke();await assert.rejects(f.application.operation({...f.context,operationId:f.request.operationId}),{code:'SHOP_AUTH_INVALID'});
});
test('HTTP closed bodies trust middleware only; GET is read-only and resume is explicit',async t=>{
 const f=fixture();let role='merchant',runs=0,gets=0,resumes=0,seen;
 const application={async run(x){runs++;seen=x;return{operationId:x.request.operationId,state:'running',ok:false};},async operation(x){gets++;return{operationId:x.operationId,state:'unknown',ok:false};},async resume(x){resumes++;return{operationId:x.operationId,state:'declined',ok:false};}};
 const app=express();app.use(express.json());app.use(createBoundListingsRouter({application,authenticatePersona(req,res,next){req.ssLaunch=f.context.scope;req.ssUser={...f.context.persona,role};req.ssPersonaSession=f.context.personaSession;next();}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
 const base=`http://127.0.0.1:${server.address().port}/merchant/listings`,body={operationId:f.request.operationId,title:'T',description:'D'};
 const post=(path,body)=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 assert.deepEqual(await (await fetch(base+'/readiness')).json(),{ready:false});
 assert.equal((await post('/assist-write',body)).status,202);assert.deepEqual(seen.scope,f.context.scope);
 for(const patch of[{mode:'fixed'},{binding:{}},{catalogRevision:'0'},{targetId:randomUUID()},{version:1},{action:'rewrite'},{executor:{}}])assert.equal((await post('/assist-write',{...body,...patch})).status,400);
 assert.equal(runs,1);assert.equal((await fetch(base+'/operations/'+body.operationId+'?mode=vuln')).status,400);
 assert.equal((await fetch(base+'/operations/'+body.operationId)).status,200);assert.equal(gets,1);assert.equal(resumes,0);
 assert.equal((await post('/operations/'+body.operationId+'/resume',{mode:'vuln'})).status,400);
 assert.equal((await post('/operations/'+body.operationId+'/resume',{})).status,200);assert.equal(resumes,1);
 role='customer';assert.equal((await post('/assist-write',body)).status,403);assert.equal(runs,1);
});
test('target resolver uses canonical bound catalog and exact owned database revision',async()=>{
 const {createListingsTargetResolver}=require('../server/services/secureshopListingsApplication');const f=fixture(),targetId=randomUUID();let values;
 const resolve=createListingsTargetResolver({mode:'fixed',catalog:{async prepareTarget(x){assert.deepEqual(x,f.context);return{...x.scope,targetId};}},pool:{async query(sql,args){assert.match(sql,/lifecycle='active'/);values=args;return{rows:[{revision:'42'}]};}}});
 assert.deepEqual(await resolve(f.context),{targetId,mode:'fixed',catalogRevision:'42'});
 assert.deepEqual(values,[targetId,f.context.scope.launchId,f.context.scope.scenarioId,1,1,2]);
});
test('run retains captured authority when caller input changes during admission lookup',async()=>{
 const f=fixture(),original=structuredClone(f.context);
 let release,entered;
 const waiting=new Promise(resolve=>{entered=resolve;});
 f.composition.recoverAdmission=async()=>{entered();await new Promise(resolve=>{release=resolve;});throw Object.assign(Error(),{code:'LISTING_NOT_FOUND'});};
 const running=f.application.run({...f.context,request:f.request});
 await waiting;
 f.context.scope.platformOwnerId=999;f.context.persona.id=999;f.context.personaSession.authorityVersion='99';
 release();await running;
 assert.deepEqual(f.stored().scope,original.scope);
 assert.deepEqual(f.stored().persona,original.persona);
 assert.deepEqual(f.stored().personaSession,original.personaSession);
});
test('rewrite save resolves original admission and accepts no generated HTML from caller',async()=>{
 const f=fixture();await f.application.run({...f.context,request:f.request});let seen;
 const app=createListingsApplication({composition:f.composition,prepareTarget:async()=>{throw Error('must use original');},launches:{async assertCurrent(){}},personaAuthority:{capture(x){return{binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},async assertRemoteAdmission(){}};}},rewriteSaveRepository:{async save(x){seen=x;return{saveOperationId:x.saveOperationId,rewriteOperationId:x.admission.request.operationId,productId:7,private:'omit'};}}});
 const request={rewriteOperationId:f.request.operationId,saveOperationId:randomUUID(),productId:null,item:{name:f.request.title,description:f.request.description,price:2,category:null,images:[],templateSource:null}};
 const result=await app.save({...f.context,request});assert.equal(seen.admission.binding.catalogRevision,'7');assert.equal(result.productId,7);assert.equal(result.private,undefined);
 await assert.rejects(app.save({...f.context,request:{...request,item:{...request.item,description_html:'forged'}}}),{code:'INVALID_ARGUMENT'});
 let getter=0;const malicious={...request};Object.defineProperty(malicious,'item',{get(){getter++;return request.item;},enumerable:true});
 await assert.rejects(app.save({...f.context,request:malicious}),{code:'INVALID_ARGUMENT'});assert.equal(getter,0);
});
test('save contract rejects unknown deep or cyclic values without traversal or getters',()=>{
 const {normalizeListingSaveRequest}=require('../server/services/secureshopListingsApplication');
 const root={rewriteOperationId:randomUUID(),saveOperationId:randomUUID(),productId:null,item:{name:'N',description:'D',price:1,category:null,images:[],templateSource:null}};
 let nested={},head=nested;for(let n=0;n<20000;n++){head.next={};head=head.next;}
 assert.throws(()=>normalizeListingSaveRequest({...root,unexpected:nested}),{code:'INVALID_ARGUMENT'});
 const cycle={};cycle.self=cycle;assert.throws(()=>normalizeListingSaveRequest({...root,item:{...root.item,name:cycle}}),{code:'INVALID_ARGUMENT'});
 let accessed=0;const getter={};Object.defineProperty(getter,'secret',{get(){accessed++;throw Error('read');},enumerable:true});
 assert.throws(()=>normalizeListingSaveRequest({...root,item:{...root.item,unexpected:getter}}),{code:'INVALID_ARGUMENT'});
 const images=[];Object.defineProperty(images,'0',{get(){accessed++;return'x';},enumerable:true});
 assert.throws(()=>normalizeListingSaveRequest({...root,item:{...root.item,images}}),{code:'INVALID_ARGUMENT'});assert.equal(accessed,0);
});

test('saved-browser route accepts opaque IDs only and derives all authority from middleware',async t=>{
 const f=fixture();let role='merchant',seen,calls=0,retryCalls=0;
 const app=express();app.use(express.json());app.use(createBoundListingsRouter({application:f.application,
  authenticatePersona(req,res,next){req.ssLaunch=f.context.scope;req.ssUser={...f.context.persona,role};req.ssPersonaSession=f.context.personaSession;next();},
  browserAssessment:{async runAttempt(input){seen=input;calls++;return{completed:false,status:'disabled',modelEvaluated:false};},async retryAttempt(input){seen=input;retryCalls++;throw Object.assign(Error('private packet omitted'),{code:'EVIDENCE_EXPIRED'});}}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
 const body={requestId:randomUUID(),rewriteOperationId:randomUUID(),saveOperationId:randomUUID()},url=`http://127.0.0.1:${server.address().port}/merchant/listings/browser-attempt`;
 const post=value=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)});
 assert.equal((await post(body)).status,200);assert.deepEqual(seen.scope,f.context.scope);assert.deepEqual(seen.personaSession,f.context.personaSession);
 for(const extra of [{source:'HTML'},{targetId:randomUUID()},{browser:{executed:true}},{scope:{}},{mode:'vuln'}])assert.equal((await post({...body,...extra})).status,400);
 const retryBody={...body,evaluationId:randomUUID()};
 const retryPost=value=>fetch(url.replace('browser-attempt','browser-retry'),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)});
 assert.equal((await retryPost(body)).status,400);assert.equal((await retryPost({...retryBody,evidence:{}})).status,400);
 const expired=await retryPost(retryBody);assert.equal(expired.status,409);assert.deepEqual(await expired.json(),{ok:false,error:'Listings unavailable',code:'EVIDENCE_EXPIRED'});assert.equal(retryCalls,1);assert.deepEqual(seen.scope,f.context.scope);
 role='customer';assert.equal((await post(body)).status,403);assert.equal((await retryPost(retryBody)).status,403);assert.equal(calls,1);
});

test('fresh listing target uses owner mode and opposite-mode durable target remains unchanged',async()=>{
 const f=fixture(),targetId=randomUUID();let existing=[];const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',generation:0,modeStamp:'first'})},launches:{assertCurrent:async()=>{}}});
 const resolve=require('../server/services/secureshopListingsApplication').createListingsTargetResolver({mode:'vuln',modeAuthority,catalog:{prepareTarget:async context=>({...context.scope,targetId})},pool:{query:async sql=>({rows:sql.includes('DISTINCT')?existing:[{revision:'1'}]})}});
 assert.equal((await resolve(f.context)).mode,'fixed');existing=[{mode:'vuln'}];await assert.rejects(resolve(f.context),{code:'LISTING_MODE_TARGET_CONFLICT'});assert.equal((await resolve({...f.context,action:'rewrite'})).mode,'fixed');assert.deepEqual(existing,[{mode:'vuln'}]);
});

test('canonical resolver queries retained birth revision only after private current merchant validation',async()=>{
 const f=fixture();f.context.persona.id=1000000001;const targetId=randomUUID(),birth={...f.context.scope,launchId:randomUUID(),platformSessionId:8,targetId};
 const {createSceneBinding,authorizeSceneMerchant}=require('../server/services/secureshopSceneBinding');
 const target=authorizeSceneMerchant(createSceneBinding(birth,{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:f.context.scope,withLease:async work=>work()}),f.context.persona.id);
 let args,queries=0;const make=chosen=>require('../server/services/secureshopListingsApplication').createListingsTargetResolver({mode:'vuln',catalog:{prepareTarget:async()=>chosen},pool:{query:async(_sql,values)=>{queries++;args=values;return{rows:[{revision:'3'}]};}}});
 assert.deepEqual(await make(target)(f.context),{targetId,mode:'vuln',catalogRevision:'3'});
 assert.deepEqual(args,[targetId,birth.launchId,birth.scenarioId,birth.generation,birth.platformOwnerId,birth.platformSessionId]);
 const before=queries;await assert.rejects(make(JSON.parse(JSON.stringify(target)))(f.context),{code:'SHOP_SCENE_STALE'});assert.equal(queries,before);
});
