'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createWorkshopRagComposition}=require('../server/services/workshopRagComposition');
function fixture(){
 const state={valid:true,ready:true,calls:[],journal:'pending'};
 const source={read:async scope=>({resourceGeneration:'7',documentId:null,selectionVersion:'2'}),readDocument:async()=>null,ingest:async()=>{},
 beginReset:async(binding,input)=>{state.calls.push(['begin',binding,input]);return{state:state.journal};},
 applyReset:async(binding,input)=>{state.calls.push(['apply',binding,input]);return{removed:1};},
 finishReset:async(binding,input)=>{state.calls.push(['finish',binding,input]);state.journal='completed';},
 deleteOwner:async binding=>{state.calls.push(['delete',binding]);return{removed:1};}};
 const composition=createWorkshopRagComposition({pool:{},identityAdapter:{validateSession:async()=>state.valid?{user:{id:11},session:{id:21,user_id:11}}:null},embedder:{embed:async()=>{},getRuntimeFingerprint:()=>({fingerprint:'a'.repeat(64)})},assertReady:async()=>{if(!state.ready)throw Error('private credential');},sourceFactory:()=>source,revisionFactory:()=>Object.fromEntries(['snapshot','publish','publishAndSelect','search','findIngestReplay'].map(k=>[k,async()=>{}]))});
 const req={user:{id:11},identitySession:{id:21},headers:{authorization:'Bearer canonical'}};
 const execution={ownerKey:JSON.stringify(['RAG','11']),runId:randomUUID(),durableGeneration:'5',check:async()=>{}};
 return{state,source,composition,req,execution};
}
test('explicit readiness fails closed, sanitizes failure and can retry',async()=>{const f=fixture();await assert.rejects(f.composition.resolveRequest(f.req),{code:'RAG_STORAGE_NOT_READY'});f.state.ready=false;await assert.rejects(f.composition.initialize(),e=>e.code==='RAG_STORAGE_NOT_READY'&&!e.message.includes('private'));f.state.ready=true;await f.composition.initialize();assert.equal(f.composition.isReady(),true);});
test('canonical bearer, owner and session are mandatory; cookie/body cannot substitute',async()=>{const f=fixture();await f.composition.initialize();for(const req of [{...f.req,headers:{}},{...f.req,user:{id:12}},{...f.req,identitySession:{id:22}},{...f.req,rawHeaders:['Authorization','Bearer canonical','Authorization','Bearer canonical']}])await assert.rejects(f.composition.resolveRequest(req),{code:'RAG_AUTH_REQUIRED'});});
test('fresh revalidation rejects revoked sessions after request construction',async()=>{const f=fixture();await f.composition.initialize();const request=await f.composition.resolveRequest(f.req);f.state.valid=false;await assert.rejects(request.read(),{code:'RAG_AUTH_REQUIRED'});});
test('binding uses authoritative resource generation and rejects foreign execution',async()=>{const f=fixture();await f.composition.initialize();const request=await f.composition.resolveRequest(f.req);const bound=await request.bind(f.execution);assert.equal(bound.scope.resourceGeneration,'7');assert.equal(bound.scope.graphGeneration,'5');await assert.rejects(request.bind({...f.execution,ownerKey:JSON.stringify(['RAG','12'])}),{code:'RAG_RUN_REQUIRED'});});
test('reset retains original operation, completes only after continuation, completed replay skips continuation',async()=>{const f=fixture();await f.composition.initialize();const request=await f.composition.resolveRequest(f.req),operationId=randomUUID();let continued=0;await request.reset(f.execution,{operationId,afterErase:async()=>{continued++;assert.deepEqual(f.state.calls.map(x=>x[0]),['begin','apply']);}});assert.deepEqual(f.state.calls.map(x=>x[0]),['begin','apply','finish']);assert.ok(f.state.calls.every(x=>x[2].operationId===operationId));await request.reset(f.execution,{operationId,afterErase:async()=>{continued++;}});assert.equal(continued,1);});
test('failed continuation leaves journal resumable, without finish or invented target session',async()=>{const f=fixture();await f.composition.initialize();const request=await f.composition.resolveRequest(f.req),operationId=randomUUID();await assert.rejects(request.reset({...f.execution,ownerKey:JSON.stringify(['RAG','99'])},{operationId,targetOwnerId:99,afterErase:async()=>{throw Error('flush failed');}}),/flush failed/);assert.deepEqual(f.state.calls.map(x=>x[0]),['begin','apply']);assert.deepEqual(f.state.calls[0][1],{actorOwnerId:11,actorSessionId:21,ownerId:99,family:'RAG',graphGeneration:'5'});});
test('reset HTTP envelope ignores supplied identity and returns a resumable stable operation',()=>{
 const {workshopResetRequest,childResetOperation}=require('../server/services/workshopResetRequest');const operationId=randomUUID(),headers={};
 const req={user:{id:11},identitySession:{id:21},headers:{authorization:'Bearer actual'},rawHeaders:['Authorization','Bearer actual'],body:{actorRequest:{user:{id:99}},operationId:randomUUID()},get:()=>operationId};
 const value=workshopResetRequest(req,{setHeader:(k,v)=>headers[k]=v});
 assert.equal(value.operationId,operationId);assert.equal(headers['x-reset-operation-id'],operationId);assert.equal(value.actorRequest.user.id,11);assert.equal(value.actorRequest.identitySession.id,21);assert.equal(value.actorRequest.body,undefined);
 req.user.id=999;req.rawHeaders[1]='Bearer attacker';assert.equal(value.actorRequest.user.id,11);assert.equal(value.actorRequest.rawHeaders[1],'Bearer actual');
 assert.equal(childResetOperation(operationId,'student1'),childResetOperation(operationId,'student1'));assert.notEqual(childResetOperation(operationId,'student1'),childResetOperation(operationId,'student2'));
 assert.throws(()=>workshopResetRequest({...req,get:()=> 'invalid'},{}),{statusCode:400});
});

test('fresh owner without a slot receives404 only while the authenticated initial snapshot remains empty',async()=>{
 const f=fixture();const empty={resourceGeneration:'0',selectionVersion:'0',documentId:null,document:null};f.source.read=async()=>empty;
 f.source.readDocument=async()=>{throw Object.assign(new Error('RAG resource generation stale'),{code:'55000'});};
 await f.composition.initialize();const bound=await(await f.composition.resolveRequest(f.req)).bind(f.execution);
 await assert.rejects(bound.document(randomUUID()),{code:'RAG_DOCUMENT_NOT_FOUND',statusCode:404});
});
test('initial absence mapping preserves genuine generation races, database failures, and revoked authority',async()=>{
 for(const scenario of ['advanced','existing','outage','revoked','reset']){
  const f=fixture();let reads=0;const stale=Object.assign(new Error('RAG resource generation stale'),{code:'55000'});
  f.source.read=async()=>{reads++;return{resourceGeneration:scenario==='existing'?'1':scenario==='advanced'&&reads>1?'1':'0',selectionVersion:'0',documentId:null,document:null};};
  let invalidated=false;f.execution.check=async()=>{if(invalidated)throw Object.assign(new Error('Reset raced'),{name:'AbortError'});};
  f.source.readDocument=async()=>{if(scenario==='revoked')f.state.valid=false;if(scenario==='reset')invalidated=true;if(scenario==='outage')throw Object.assign(new Error('connection failure'),{code:'08006'});throw stale;};
  await f.composition.initialize();const bound=await(await f.composition.resolveRequest(f.req)).bind(f.execution);
  await assert.rejects(bound.document(randomUUID()),scenario==='revoked'?{code:'RAG_AUTH_REQUIRED'}:scenario==='reset'?{name:'AbortError'}:scenario==='outage'?{code:'08006'}:{code:'55000',message:'RAG resource generation stale'});
 }
});
