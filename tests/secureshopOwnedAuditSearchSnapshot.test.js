'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createOwnedAuditSearchSnapshotBuilder:create,receiptFor}=require('../server/services/secureshopOwnedAuditSearchSnapshot');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:1,platformSessionId:2};
const row=()=>({id:'agents:33333333-3333-4333-8333-333333333333',store:'agents',ts:'2026-09-19T12:00:00.123456Z',actor:'admin',action:'profile_update',target:null,params_json:'{"teaching":"raw"}',outcome:'completed',source_kind:'profile',source_id:'1',privateExtra:'DO_NOT_EXPORT'});
test('projects only teaching columns and binds immutable private receipt to exact current launch',async()=>{
 const input=row();let checks=0;
 const builder=create({reader:{recent:async(s,q)=>{assert.deepEqual(s,scope);assert.deepEqual(q,{limit:200});return{events:[input],hasMore:false};}},assertCurrent:async()=>{checks++;}});
 const snapshot=await builder.capture({...scope,learnerClaim:'ignored'});const receipt=receiptFor(snapshot);
 assert.equal(checks,2);assert.deepEqual(Object.keys(snapshot.rows[0]),['id','actor','action','target','params_json','ts']);
 assert.deepEqual(receipt.binding,scope);assert.equal(receipt.selection.consistency,'bounded-owner-journal-page');
 input.params_json='changed';assert.equal(snapshot.rows[0].params_json,'{"teaching":"raw"}');
 assert.equal(receiptFor(JSON.parse(JSON.stringify(snapshot))),null);assert.equal(receiptFor({receipt}),null);
 assert.throws(()=>{snapshot.rows[0].actor='forged';},TypeError);assert.throws(()=>{receipt.binding.generation=2;},TypeError);
});
test('reset during snapshot read rejects instead of publishing stale authority',async()=>{
 let checks=0;const builder=create({reader:{recent:async()=>({events:[row()],hasMore:false})},assertCurrent:async()=>{if(++checks===2)throw Error('stale generation');}});
 await assert.rejects(builder.capture(scope),/stale generation/);
});
test('source edits change receipt and incomplete pages are explicit, never silently complete',async()=>{
 let input=row();const builder=create({reader:{recent:async()=>({events:[input],hasMore:true,nextCursor:'trusted-reader-cursor'})},assertCurrent:async()=>{}});
 const first=receiptFor(await builder.capture(scope));input={...input,params_json:'new teaching input'};
 const second=receiptFor(await builder.capture(scope));assert.notEqual(first.payloadSha256,second.payloadSha256);assert.notEqual(first.sourcesSha256,second.sourcesSha256);assert.equal(second.selection.hasMore,true);
});
test('invalid page and duplicate rows fail closed',async()=>{
 for(const page of [{events:[row(),row()],hasMore:false},{events:[row()],hasMore:true},{events:Array(201).fill(row()),hasMore:false}]){
  await assert.rejects(create({reader:{recent:async()=>page},assertCurrent:async()=>{}}).capture(scope));
 }
});
const {createOwnedAuditSearchLifecycle:lifecycle}=require('../server/services/secureshopOwnedAuditSearchLifecycle');
test('durable admission precedes service; unknown outcome cannot repeat and remains retireable',async()=>{
 const snapshot=await create({reader:{recent:async()=>({events:[row()],hasMore:false})},assertCurrent:async()=>{}}).capture(scope);
 let state=null,calls=0;const order=[];
 const journal={withLock:async(_,fn)=>fn(),get:async()=>state,begin:async(_,receipt)=>{order.push('begin');state={...receipt,state:'pending',target:'audit_'+'a'.repeat(32)};return state;},ready:async()=>{state.state='ready';},retiring:async()=>{state.state='retiring';},retired:async()=>{state.state='retired';}};
 const service={provision:async request=>{calls++;order.push('network');assert.deepEqual(Object.keys(request),['target','rows','payloadSha256']);throw Error('lost acknowledgment');},retire:async()=>{order.push('retired');}};
 const value=lifecycle({journal,service,assertCurrent:async()=>{}});
 await assert.rejects(value.provision(snapshot),/lost acknowledgment/);await assert.rejects(value.provision(snapshot),{code:'AUDIT_SEARCH_TARGET_UNCERTAIN'});
 assert.equal(calls,1);await value.retire(scope);assert.equal(state.state,'retired');assert.deepEqual(order,['begin','network','retired']);
 await assert.rejects(value.provision(JSON.parse(JSON.stringify(snapshot))),/Private audit snapshot/);
});
test('retirement failure preserves debt and never acknowledges cleanup',async()=>{
 let state={state:'ready',target:'audit_'+'a'.repeat(32)};
 const journal={withLock:async(_,fn)=>fn(),get:async()=>state,begin:async()=>{},ready:async()=>{},retiring:async()=>{state.state='retiring';},retired:async()=>{throw Error('must not acknowledge');}};
 const value=lifecycle({journal,service:{provision:async()=>{},retire:async()=>{throw Error('service unavailable');}},assertCurrent:async()=>{}});
 await assert.rejects(value.retire(scope),/service unavailable/);assert.equal(state.state,'retiring');
});
test('nested mutable params cannot enroll and cross-store UUIDs stay distinct',async()=>{
 const source=row();const builder=create({reader:{recent:async()=>({events:[source],hasMore:false})},assertCurrent:async()=>{}});
 source.params_json={nested:{instruction:'mutable'}};
 await assert.rejects(builder.capture(scope),/Invalid audit source row/);
 const a=row(),b={...row(),id:row().id.replace('agents:','review:'),store:'review'};
 const snapshot=await create({reader:{recent:async()=>({events:[a,b],hasMore:false})},assertCurrent:async()=>{}}).capture(scope);
 assert.notEqual(snapshot.rows[0].id,snapshot.rows[1].id);assert.equal(receiptFor(snapshot).rowCount,2);
});
