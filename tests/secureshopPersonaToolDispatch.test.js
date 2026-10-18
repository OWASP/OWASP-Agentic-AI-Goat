'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPersonaToolDispatch:create}=require('../server/services/secureshopPersonaToolDispatch');
const binding={launchId:'l',scenarioId:'s',generation:1,platformOwnerId:1,platformSessionId:2,shopUserId:3,role:'customer'};
function fixture(){let live=true,locked=false;const client={};const fence={binding:{...binding,personaId:3},assertRemoteAdmission:async()=>{assert.equal(locked,false);if(!live)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},withPersonaEffect:async work=>{if(!live)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});locked=true;try{return await work(client,fence.binding);}finally{locked=false;}}};return{fence,client,live:v=>{live=v;},locked:()=>locked};}
test('exact local selected arguments use shared transaction client',async()=>{const f=fixture();const d=create({binding,fence:f.fence,modes:{'x.write':'local_transaction'},localTools:{'x.write':async(args,ctx)=>{assert.equal(f.locked(),true);assert.equal(ctx.client,f.client);return args;}},pool:{}});assert.deepEqual(await d.localTools.get('x.write')({n:2}),{n:2});});
test('revoked dispatch throws execution boundary and never invokes tool',async()=>{const f=fixture();let called=false;const d=create({binding,fence:f.fence,modes:{'x.write':'local_transaction'},localTools:{'x.write':async()=>{called=true;}},pool:{}});f.live(false);await assert.rejects(d.localTools.get('x.write')({}),{code:'SHOP_AUTH_INVALID',executionBoundary:true});assert.equal(called,false);});
test('remote effect executes outside lease and stale publication rejects without rollback claim',async()=>{const f=fixture();let effect=false;const d=create({binding,fence:f.fence,modes:{},localTools:{},pool:{callTool:async()=>{assert.equal(f.locked(),false);effect=true;f.live(false);return 'already done';}}});await assert.rejects(d.pool.callTool('x','y',{}),{code:'SHOP_AUTH_INVALID'});assert.equal(effect,true);});
test('unclassified local tool and mismatched role fail closed',()=>{const f=fixture();assert.throws(()=>create({binding,fence:f.fence,modes:{},localTools:{x:async()=>{}},pool:{}}));assert.throws(()=>create({binding:{...binding,role:'admin'},fence:f.fence,modes:{},localTools:{},pool:{}}));});
test('mode is snapshotted before caller configuration mutation',async()=>{const f=fixture(),modes={'x.write':'local_transaction'};const d=create({binding,fence:f.fence,modes,localTools:{'x.write':async(_args,ctx)=>{assert.equal(f.locked(),true);assert.equal(ctx.client,f.client);}},pool:{}});modes['x.write']='remote_admission';await d.localTools.get('x.write')({});});
test('external denial projector retains private error identity through persona pool',async()=>{
 const f=fixture(),branded=new WeakSet(),denial=Object.assign(Error('private denial'),{code:'BOUND_SSRF_UNAVAILABLE'});
 branded.add(denial);const pool={async callTool(){throw denial;},projectRecoverableToolError(error){
  assert.equal(this,pool);return branded.has(error)?'INVALID_TOOL_SELECTION':null;
 }};
 const d=create({binding,fence:f.fence,modes:{},localTools:{},pool});
 pool.projectRecoverableToolError=()=>{throw Error('late projector replacement');};
 await assert.rejects(d.pool.callTool('summarizer','explain_return_policy',{}),error=>error===denial);
 assert.equal(d.pool.projectRecoverableToolError(denial),'INVALID_TOOL_SELECTION');
 assert.equal(d.pool.projectRecoverableToolError(Object.assign(Error('spoof'),{code:denial.code})),null);
 assert.equal(d.pool.projectRecoverableToolError(Object.assign(Error('authority'),{code:'SHOP_AUTH_INVALID'})),null);
 assert.equal(d.pool.projectRecoverableToolError(Object.assign(Error('stale'),{executionBoundary:true})),null);
 f.live(false);await assert.rejects(d.pool.callTool('summarizer','explain_return_policy',{}),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
});
test('persona pool does not invent a denial projector for ordinary pools',()=>{
 const f=fixture(),d=create({binding,fence:f.fence,modes:{},localTools:{},pool:{async callTool(){return{};}}});
 assert.equal(Object.hasOwn(d.pool,'projectRecoverableToolError'),false);
});
test('authority revoked while external pool denies cannot become recoverable feedback',async()=>{
 const f=fixture(),branded=new WeakSet(),denial=Error('private fixed denial');branded.add(denial);
 const pool={async callTool(){f.live(false);throw denial;},
  projectRecoverableToolError(error){return branded.has(error)?'INVALID_TOOL_SELECTION':null;}};
 const d=create({binding,fence:f.fence,modes:{},localTools:{},pool});
 let observed;await assert.rejects(d.pool.callTool('summarizer','explain_return_policy',{}),error=>{
  observed=error;return error?.code==='SHOP_AUTH_INVALID'&&error.executionBoundary===true;
 });
 assert.notEqual(observed,denial);
 assert.equal(d.pool.projectRecoverableToolError(observed),null);
});
