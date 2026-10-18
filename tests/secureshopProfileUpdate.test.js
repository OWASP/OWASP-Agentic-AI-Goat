'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const C=require('../server/services/secureshopConversationalCommerceContract');
const P=require('../server/services/secureshopProfileUpdateContract');
const {createConversationalCommerceRepository}=require('../server/database/postgres/secureshopConversationalCommerceRepository');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const defaults={fullName:'Practice Customer',email:'customer@example.invalid',phone:null};
function fixture(options={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const target=createSceneBinding({...scope,targetId:randomUUID()},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:work=>work()});
 const auth={shopUserId:9,mode:'vuln',personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 let state={profiles:[],ops:[],audit:[]},clock=0,retired=false;
 const calls=[],stamp=()=>`2026-10-11 01:02:03.${String(++clock).padStart(6,'0')}+00`;
 const client={async query(raw,p=[]){const sql=raw.replace(/\s+/g,' ').trim();calls.push({sql,p});let rows=[];
  if(sql.startsWith('SELECT pg_advisory'))return {rows:[],rowCount:1};
  if(sql.startsWith('SELECT count(*)'))return {rows:[{count:state.ops.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]).length}]};
  if(sql.startsWith('INSERT INTO secureshop_review.chat_commerce_operations')){
   if(options.failReceipt)throw Object.assign(Error('receipt failed'),{code:'TEST_RECEIPT_FAILED'});
   state.ops.push({operation_id:p[0],target_id:p[1],shop_user_id:p[2],kind:p[3],context_json:p[4],request_json:p[5],intent_sha256:p[6],proposal_json:p[7],proposal_sha256:p[8],result_json:p[9],result_sha256:p[10],state:p[11]});
  }else if(sql.startsWith('SELECT * FROM secureshop_review.chat_commerce_operations'))rows=state.ops.filter(r=>r.operation_id===p[0]&&(p.length<3||(r.target_id===p[1]&&r.shop_user_id===p[2])));
  else if(sql.startsWith('SELECT email,full_name,phone'))rows=state.profiles.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]);
  else if(sql.startsWith('INSERT INTO secureshop_review.product_target_profile_overlays')){
   let row=state.profiles.find(r=>r.target_id===p[0]&&r.shop_user_id===p[1]);
   if(!row){row={target_id:p[0],shop_user_id:p[1],created_at:stamp()};state.profiles.push(row);}
   Object.assign(row,{email:p[2],full_name:p[3],phone:p[4],updated_at:stamp()});rows=[row];
  }else throw Error('Unexpected query: '+sql);
  return {rows:structuredClone(rows),rowCount:rows.length};
 }};
 const unused=async()=>{throw Error('Unexpected unrelated worker');};
 const domain=createConversationalCommerceRepository({guarded:async(value,work)=>{
  if(retired)throw Object.assign(Error('retired'),{code:'SHOP_SCENE_STALE'});
  const old=structuredClone(state);try{const result=await work(client,value);if(options.failCommit)throw Object.assign(Error('commit failed'),{code:'TEST_COMMIT_FAILED'});if(options.failPostAuthority)throw Object.assign(Error('authority expired'),{code:'SHOP_AUTH_INVALID'});return result;}catch(e){state=old;throw e;}
 },listCartWithClient:unused,addCartWithClient:unused,updateCartWithClient:unused,removeCartWithClient:unused,checkoutWithClient:unused,
 auditStore:{async append(c,event){assert.equal(c,client);if(options.failAudit)throw Object.assign(Error('audit failed'),{code:'TEST_AUDIT_FAILED'});state.audit.push(event);}}});
 return {domain,target,auth,calls,state:()=>state,stamp,retire(){retired=true}};
}
const form=f=>f.domain.profileForm(f.target,{...f.auth,canonicalProfile:defaults});
async function request(f,fields={...defaults,fullName:'Updated Customer',phone:'555-0101'}){const before=await form(f);return {operationId:randomUUID(),expectedSnapshotSha256:before.expectedSnapshotSha256,fields};}
const save=(f,args,canonicalProfile=defaults)=>f.domain.saveProfile(f.target,{...f.auth,canonicalProfile,...args});
test('profile patch/fields are closed, canonical and preserve omitted values',()=>{
 assert.deepEqual(P.normalizeProfilePatch({phone:null}),{phone:null});
 assert.deepEqual(P.normalizeProfileFields({phone:' ',email:defaults.email,fullName:''}),{fullName:null,email:defaults.email,phone:null});
 assert.equal(P.profileFieldsDigest(Object.fromEntries(Object.entries(defaults).reverse())),C.digest(defaults));
 const input={operationId:randomUUID(),expectedSnapshotSha256:'a'.repeat(64),fields:defaults};
 assert.equal(P.profileRequestDigest(input),C.digest({operationId:input.operationId,expectedSnapshotSha256:input.expectedSnapshotSha256,fieldsSha256:C.digest(defaults)}));
 for(const patch of [{},{role:'admin'},{email:null},{email:'bad'},{phone:42},{phone:'\0'},{fullName:'\ud800'},{fullName:'é'.repeat(257)}])assert.throws(()=>P.normalizeProfilePatch(patch));
 for(const extra of ['ownerId','targetId','username','password'])assert.throws(()=>P.normalizeProfileFields({...defaults,[extra]:'x'}));
});
test('absent overlay form is no-effect and save atomically records profile, audit and hash-only receipt',async()=>{
 const f=fixture(),before=await form(f);assert.deepEqual(before.fields,defaults);assert.equal(before.version,1);assert.match(before.scopeKey,/^[a-f0-9]{64}$/);
 assert.deepEqual(f.state(),{profiles:[],ops:[],audit:[]});
 const args=await request(f),result=await save(f,args);assert.equal(result.status,'completed');assert.equal(result.kind,'profile.update');
 assert.equal(result.result.fieldsSha256,P.profileFieldsDigest(args.fields));assert.equal(f.state().profiles[0].full_name,args.fields.fullName);
 assert.equal(f.state().audit.length,1);assert.equal(f.state().audit[0].action,'profile_update');assert.equal(f.state().audit[0].sourceKind,'profile');
 assert.equal((await form(f)).expectedSnapshotSha256,result.result.profileSnapshotSha256);
 for(const text of [args.fields.fullName,args.fields.email,args.fields.phone])assert.equal(JSON.stringify(f.state().ops).includes(text),false);
 assert.equal(f.state().ops[0].proposal_json,null);assert.equal(f.state().ops[0].state,'completed');
 const firstRead=f.calls.findIndex(c=>c.sql.startsWith('SELECT email,full_name'));
 assert.ok(f.calls.slice(0,firstRead).some(c=>c.sql.startsWith('SELECT pg_advisory')));
 const row=f.state().profiles[0];row.full_name='Later change';row.updated_at=f.stamp();
 assert.deepEqual(await save(f,args),{...result,replayed:true});assert.equal(f.state().audit.length,1);assert.equal(f.state().profiles[0].full_name,'Later change');
 const {scopeKey,...receipt}=result;
 assert.deepEqual(await f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId}),{scopeKey,operationId:args.operationId,status:'completed',receipt:{...receipt,replayed:true}});
 await assert.rejects(save(f,{...args,fields:{...args.fields,phone:null}}),{code:'COMMERCE_OPERATION_CONFLICT'});
});
test('overlay presence, exact version and changed canonical fallback create durable stale results',async()=>{
 for(const kind of ['presence','version','fallback']){
  const f=fixture();if(kind==='version')await save(f,await request(f));
  const args=await request(f);let canonical=defaults;
  if(kind==='presence')f.state().profiles.push({target_id:f.target.targetId,shop_user_id:9,email:defaults.email,full_name:defaults.fullName,phone:null,updated_at:f.stamp()});
  if(kind==='version')f.state().profiles[0].updated_at=f.stamp();
  if(kind==='fallback')canonical={...defaults,fullName:'Changed canonical'};
  const before=structuredClone(f.state()),result=await save(f,args,canonical);
  assert.equal(result.status,'stale');assert.deepEqual(result.result,{fieldsSha256:P.profileFieldsDigest(args.fields)});
  assert.deepEqual(f.state().profiles,before.profiles);assert.deepEqual(f.state().audit,before.audit);assert.equal(f.state().ops.length,before.ops.length+1);
  const persisted=structuredClone(f.state());assert.deepEqual(await save(f,args,defaults),{...result,replayed:true});assert.deepEqual(f.state(),persisted);
  const {scopeKey,...receipt}=result;assert.deepEqual(await f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId}),{scopeKey,operationId:args.operationId,status:'completed',receipt:{...receipt,replayed:true}});
 }
});
test('receipt, audit, commit and authority failures do not yield saved profile success',async()=>{
 for(const flag of ['failReceipt','failAudit','failCommit','failPostAuthority']){
  const options={},f=fixture(options),args=await request(f);options[flag]=true;
  const before=structuredClone(f.state());await assert.rejects(save(f,args));assert.deepEqual(f.state(),before);
 }
});
test('foreign owner, session, mode and retired target cannot adopt or read an owned operation',async()=>{
 const f=fixture(),args=await request(f);await save(f,args);const before=structuredClone(f.state());
 const absent=await f.domain.readOperation(f.target,{...f.auth,shopUserId:10,operationId:args.operationId});assert.equal(absent.status,'not_found');assert.equal(Object.hasOwn(absent,'receipt'),false);
 for(const auth of [{...f.auth,shopUserId:10},{...f.auth,mode:'fixed'},{...f.auth,personaSession:{sessionId:randomUUID(),authorityVersion:'1'}}])await assert.rejects(f.domain.saveProfile(f.target,{...auth,canonicalProfile:defaults,...args}),{code:'COMMERCE_OPERATION_CONFLICT'});
 await assert.rejects(f.domain.readOperation(f.target,{...f.auth,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:args.operationId}),{code:'COMMERCE_OPERATION_CONFLICT'});
 assert.deepEqual(f.state(),before);f.retire();await assert.rejects(form(f),{code:'SHOP_SCENE_STALE'});await assert.rejects(save(f,args),{code:'SHOP_SCENE_STALE'});
});
test('profile GET validates hash-only intent and result bindings beyond independent stored hashes',async()=>{
 for(const change of ['kind','fields','operation','extra','request']){
  const f=fixture(),args=await request(f);await save(f,args);const row=f.state().ops[0],result=JSON.parse(row.result_json);
  if(change==='kind')result.kind='address.update';
  if(change==='fields')result.result.fieldsSha256='f'.repeat(64);
  if(change==='operation')result.operationId=randomUUID();
  if(change==='extra')result.result.email='private@example.invalid';
  if(change==='request'){const req=JSON.parse(row.request_json);req.ownerId=10;row.request_json=JSON.stringify(req);row.intent_sha256=C.digest(row.request_json);}
  row.result_json=JSON.stringify(result);row.result_sha256=C.digest(row.result_json);
  await assert.rejects(f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId}),{code:'COMMERCE_STATE_INVALID'});
 }
});

test('retained malformed email and whitespace fields remain readable and only changed email is strict',async()=>{
 const f=fixture();f.state().profiles.push({target_id:f.target.targetId,shop_user_id:9,email:'   ',full_name:' ',phone:' ',updated_at:f.stamp()});
 const current=await form(f);assert.deepEqual(current.fields,{fullName:' ',email:'   ',phone:' '});
 assert.deepEqual(P.normalizeProfileView(current.fields),current.fields);
 assert.throws(()=>P.normalizeProfilePatch({email:'   '}));
 const args={operationId:randomUUID(),expectedSnapshotSha256:current.expectedSnapshotSha256,fields:{...current.fields,fullName:'Corrected name'}};
 await save(f,args);assert.equal(f.state().profiles[0].email,'   ');assert.equal(f.state().profiles[0].phone,' ');
 const fresh=await form(f),before=structuredClone(f.state());
 await assert.rejects(save(f,{operationId:randomUUID(),expectedSnapshotSha256:fresh.expectedSnapshotSha256,fields:{...fresh.fields,email:'not-an-email'}}));
 assert.deepEqual(f.state(),before);
 // A caller cannot substitute a claimed before value: there is no public before input.
 assert.throws(()=>save(f,{operationId:randomUUID(),expectedSnapshotSha256:fresh.expectedSnapshotSha256,fields:{...fresh.fields,email:'not-an-email'},before:{...fresh.fields,email:'not-an-email'}}));
 assert.deepEqual(f.state(),before);
 await save(f,{operationId:randomUUID(),expectedSnapshotSha256:fresh.expectedSnapshotSha256,fields:{...fresh.fields,email:'corrected@example.invalid'}});
 assert.equal(f.state().profiles[0].email,'corrected@example.invalid');
});

 test('saved scope is checked before replay or writes and profile snapshots cannot cross scenes',async()=>{
 const f=fixture(),first=await form(f),args=await request(f),before=structuredClone(f.state());
 for(const expectedScopeKey of ['f'.repeat(64),'invalid',null]){
  const start=f.calls.length;
  await assert.rejects(save(f,{...args,expectedScopeKey}),{code:'COMMERCE_OPERATION_CONFLICT'});
  assert.deepEqual(f.state(),before);
  assert.equal(f.calls.slice(start).some(c=>c.sql.includes('chat_commerce_operations')||c.sql.startsWith('SELECT email')),false);
 }
 const other=fixture(),otherForm=await form(other);assert.deepEqual(otherForm.fields,first.fields);
 assert.notEqual(otherForm.scopeKey,first.scopeKey);assert.notEqual(otherForm.expectedSnapshotSha256,first.expectedSnapshotSha256);
 await assert.rejects(save(other,{...args,expectedScopeKey:first.scopeKey}),{code:'COMMERCE_OPERATION_CONFLICT'});
 assert.deepEqual(other.state(),{profiles:[],ops:[],audit:[]});
 // Trusted Account saves have no private expectedScopeKey; their captured snapshot still cannot write another scene.
 const stale=await save(other,args);assert.equal(stale.status,'stale');assert.deepEqual(other.state().profiles,[]);assert.deepEqual(other.state().audit,[]);
 const completed=await save(f,{...args,expectedScopeKey:first.scopeKey});assert.equal(completed.status,'completed');
 const saved=structuredClone(f.state());await assert.rejects(save(f,{...args,expectedScopeKey:otherForm.scopeKey}),{code:'COMMERCE_OPERATION_CONFLICT'});assert.deepEqual(f.state(),saved);
 assert.equal((await save(f,{...args,expectedScopeKey:first.scopeKey})).replayed,true);
});
