'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const C=require('../server/services/secureshopConversationalCommerceContract');
const A=require('../server/services/secureshopAddressSetupContract');
const {createConversationalCommerceRepository}=require('../server/database/postgres/secureshopConversationalCommerceRepository');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const fields={label:'Home',line1:'123 Synthetic Street',line2:null,city:'Testville',state:null,zip:null,phone:'555-0100',isDefault:true};
function fixture({failReceipt=false,failAudit=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const target=createSceneBinding({...scope,targetId:randomUUID()},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:work=>work()});
 const auth={shopUserId:9,mode:'vuln',personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 let state={addresses:[],choices:[],ops:[],audit:[]},clock=0;
 const calls=[];
 const stamp=()=>`2026-10-10 01:02:03.${String(++clock).padStart(6,'0')}+00`;
 const snapshot=row=>Object.fromEntries(['address_id','label','line1','line2','city','state','zip','phone','is_default'].map(k=>[k,row[k]]));
 const client={async query(raw,p=[]){const sql=raw.replace(/\s+/g,' ').trim();calls.push({sql,p});let rows=[];
  const owned=()=>state.addresses.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]);
  if(sql.startsWith('SELECT pg_advisory'))return {rows:[],rowCount:1};
  if(sql.startsWith('SELECT count(*)'))return {rows:[{count:sql.includes('chat_commerce_operations')?state.ops.length:sql.includes('chat_commerce_choices')?state.choices.length:owned().length}]};
  if(sql.startsWith('INSERT INTO secureshop_review.chat_commerce_choices')){state.choices.push({choice_id:p[0],target_id:p[1],shop_user_id:p[2],kind:p[3],context_json:p[4],snapshot_json:p[5],snapshot_sha256:p[6],state:'active'});}
  else if(sql.startsWith('SELECT choice_id'))rows=state.choices.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]&&r.kind===p[2]&&r.context_json===p[3]&&r.snapshot_sha256===p[4]&&r.snapshot_json===p[5]);
  else if(sql.startsWith('SELECT * FROM secureshop_review.chat_commerce_choices'))rows=state.choices.filter(r=>r.choice_id===p[0]);
  else if(sql.startsWith('INSERT INTO secureshop_review.chat_commerce_operations')){
   if(failReceipt)throw Object.assign(Error('controlled receipt failure'),{code:'TEST_RECEIPT_FAILED'});
   state.ops.push({operation_id:p[0],target_id:p[1],shop_user_id:p[2],kind:p[3],context_json:p[4],request_json:p[5],intent_sha256:p[6],proposal_json:p[7],proposal_sha256:p[8],result_json:p[9],result_sha256:p[10],state:p[11]});
  }else if(sql.startsWith('SELECT * FROM secureshop_review.chat_commerce_operations'))rows=state.ops.filter(r=>r.operation_id===p[0]&&(p.length<3||(r.target_id===p[1]&&r.shop_user_id===p[2])));
  else if(sql.startsWith('SELECT address_id,label'))rows=owned().filter(r=>p.length===2||Number(r.address_id)===p[2]).map(r=>sql.includes('updated_at::text')?{...snapshot(r),updated_at:r.updated_at}:snapshot(r));
  else if(sql.startsWith('SELECT address_id FROM'))rows=owned().filter(r=>p.length===2||Number(r.address_id)===p[2]).map(r=>({address_id:r.address_id}));
  else if(sql.includes('SET is_default=false')){for(const r of owned().filter(r=>r.is_default)){r.is_default=false;r.updated_at=stamp();}}
  else if(sql.startsWith('INSERT INTO secureshop_review.product_target_addresses')||sql.includes('SET label=$3')){
   let row=p.length===11?owned().find(r=>Number(r.address_id)===p[10]):null;
   if(!row){row={address_id:String(state.addresses.length+1),target_id:p[0],shop_user_id:p[1],created_at:stamp()};state.addresses.push(row);}
   Object.assign(row,{label:p[2],line1:p[3],line2:p[4],city:p[5],state:p[6],zip:p[7],phone:p[8],is_default:p[9],updated_at:stamp()});rows=[row];
  }else throw Error('Unexpected query: '+sql);
  return {rows:structuredClone(rows),rowCount:rows.length};
 }};
 const unused=async()=>{throw Error('Unexpected non-address worker');};
 const domain=createConversationalCommerceRepository({guarded:async(value,work)=>{const old=structuredClone(state);try{return await work(client,value);}catch(e){state=old;throw e;}},
 listCartWithClient:unused,addCartWithClient:unused,updateCartWithClient:unused,removeCartWithClient:unused,checkoutWithClient:unused,
 auditStore:{async append(c,event){assert.equal(c,client);if(failAudit)throw Object.assign(Error('controlled audit failure'),{code:'TEST_AUDIT_FAILED'});state.audit.push(event);}}});
 return {domain,target,auth,calls,state:()=>state,stamp};
}
async function request(f,values=fields,action='create',choiceId=null){const form=await f.domain.addressForm(f.target,{...f.auth,action,choiceId});return {operationId:randomUUID(),action,choiceId,expectedSnapshotSha256:form.expectedSnapshotSha256,defaultSetSha256:form.defaultSetSha256,fields:values};}
async function save(f,args){return f.domain.saveAddress(f.target,{...f.auth,...args});}
async function selected(f){return (await f.domain.addresses(f.target,f.auth)).cards[0].choiceId;}
test('address fields have canonical JSON order and closed partial suggestions without invented values',()=>{
 const reordered=Object.fromEntries(Object.entries({...fields,label:'  ',phone:''}).reverse());
 assert.deepEqual(A.normalizeAddressFields(reordered),{...fields,label:null,phone:null});
 assert.equal(A.addressFieldsDigest(reordered),C.digest({...fields,label:null,phone:null}));
 assert.deepEqual(A.normalizeAddressDraft({city:'Testville'}),{city:'Testville'});
 for(const bad of [{...fields,line1:''},{...fields,phone:'\0'},{...fields,addressId:1},{...fields,isDefault:'true'},{...fields,line1:'\ud800'}])assert.throws(()=>A.normalizeAddressFields(bad));
 assert.throws(()=>A.normalizeAddressDraft({isDefault:true}));
 assert.throws(()=>A.addressSetup({version:1,kind:'address_setup',action:'update',choiceId:'1',draft:{}}));
});
test('form is no-effect; create atomically saves default, audit and hash-only receipt, then replays before CAS',async()=>{
 const f=fixture(),args=await request(f);assert.deepEqual(f.state(),{addresses:[],choices:[],ops:[],audit:[]});
 const result=await save(f,args);assert.equal(result.kind,'address.create');assert.equal(result.result.fieldsSha256,A.addressFieldsDigest(fields));
 assert.equal(f.state().addresses.length,1);assert.equal(f.state().addresses[0].is_default,true);assert.equal(f.state().audit[0].action,'address_create');
 for(const text of [fields.line1,fields.phone])assert.equal(JSON.stringify(f.state().ops).includes(text),false);
 assert.equal(f.state().ops[0].proposal_json,null);assert.equal(f.state().ops[0].state,'completed');
 f.state().addresses[0].updated_at=f.stamp();f.state().addresses[0].line1='Later edit';
 assert.deepEqual(await save(f,args),{...result,replayed:true});assert.equal(f.state().addresses.length,1);assert.equal(f.state().audit.length,1);
 const read=await f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId});
 const {scopeKey,...receipt}=result;assert.deepEqual(read,{scopeKey,operationId:args.operationId,status:'completed',receipt:{...receipt,replayed:true}});
 await assert.rejects(save(f,{...args,fields:{...fields,line1:'Changed intent'}}),{code:'COMMERCE_OPERATION_CONFLICT'});
});
test('update uses selected owned full fields and row/default-set CAS; replay remains exact after edit invalidates choice',async()=>{
 const f=fixture();await save(f,await request(f));const choiceId=await selected(f);
 const form=await f.domain.addressForm(f.target,{...f.auth,action:'update',choiceId});assert.deepEqual(form.fields,fields);
 const args=await request(f,{...fields,line1:'456 Updated Street'},'update',choiceId),result=await save(f,args);
 assert.equal(result.kind,'address.update');assert.equal(f.state().addresses.length,1);assert.equal(f.state().addresses[0].line1,args.fields.line1);
 assert.deepEqual(await save(f,args),{...result,replayed:true});assert.equal(f.state().audit.length,2);
 await assert.rejects(f.domain.addressForm(f.target,{...f.auth,action:'update',choiceId}),{code:'COMMERCE_CHOICE_STALE'});
});
test('sub-millisecond address ABA and another address/default change deny stale saves before any effect',async()=>{
 for(const change of ['aba','other']){
  const f=fixture();await save(f,await request(f));const choiceId=await selected(f),args=await request(f,{...fields,city:'New city'},'update',choiceId);
  if(change==='aba')f.state().addresses[0].updated_at=f.stamp();
  else await save(f,await request(f,{...fields,label:'Office',line1:'789 Other Street'}));
  const before=structuredClone(f.state());
  const result=await save(f,args);assert.equal(result.status,'stale');assert.deepEqual(result.result,{fieldsSha256:A.addressFieldsDigest(args.fields)});
  assert.deepEqual(f.state().addresses,before.addresses);assert.deepEqual(f.state().audit,before.audit);assert.equal(f.state().ops.length,before.ops.length+1);
  const stored=structuredClone(f.state());assert.deepEqual(await save(f,args),{...result,replayed:true});assert.deepEqual(f.state(),stored);
  const {scopeKey,...receipt}=result;assert.deepEqual(await f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId}),{scopeKey,operationId:args.operationId,status:'completed',receipt:{...receipt,replayed:true}});
  await assert.rejects(save(f,{...args,fields:{...args.fields,line1:'Different intent'}}),{code:'COMMERCE_OPERATION_CONFLICT'});
 }
});
test('default flip, address and audit all roll back if receipt admission or audit fails',async()=>{
 for(const option of ['failReceipt','failAudit']){
  const f=fixture({[option]:true});
  f.state().addresses.push({address_id:'1',target_id:f.target.targetId,shop_user_id:f.auth.shopUserId,label:'Existing',line1:'Old Street',line2:null,city:null,state:null,zip:null,phone:null,is_default:true,updated_at:f.stamp()});
  const args=await request(f),before=structuredClone(f.state());
  await assert.rejects(save(f,args),{code:option==='failReceipt'?'TEST_RECEIPT_FAILED':'TEST_AUDIT_FAILED'});assert.deepEqual(f.state(),before);
 }
});
test('foreign or stale context cannot recover or edit owned data; invalid saved hashes fail closed',async()=>{
 const f=fixture(),args=await request(f);await save(f,args);const choiceId=await selected(f),before=structuredClone(f.state());
 const foreign=await f.domain.readOperation(f.target,{...f.auth,shopUserId:10,operationId:args.operationId});assert.equal(foreign.status,'not_found');assert.equal(Object.hasOwn(foreign,'receipt'),false);
 for(const auth of [{...f.auth,shopUserId:10},{...f.auth,personaSession:{sessionId:randomUUID(),authorityVersion:'1'}}])await assert.rejects(f.domain.addressForm(f.target,{...auth,action:'update',choiceId}),{code:'COMMERCE_CHOICE_DENIED'});
 await assert.rejects(f.domain.readOperation(f.target,{...f.auth,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:args.operationId}),{code:'COMMERCE_OPERATION_CONFLICT'});assert.deepEqual(f.state(),before);
 const update=await request(f,fields,'update',choiceId);await assert.rejects(f.domain.saveAddress(f.target,{...f.auth,...update,shopUserId:10}),{code:'COMMERCE_CHOICE_DENIED'});assert.deepEqual(f.state(),before);
 f.state().ops[0].request_json=f.state().ops[0].request_json.replace(args.operationId,randomUUID());
 await assert.rejects(f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId}),{code:'COMMERCE_STATE_INVALID'});
});
test('address capacity and operation capacity reject without any business or audit effect',async()=>{
 for(const type of ['addresses','ops']){
  const f=fixture();if(type==='addresses')for(let i=0;i<32;i++)f.state().addresses.push({address_id:String(i+1),target_id:f.target.targetId,shop_user_id:f.auth.shopUserId,...Object.fromEntries(Object.entries(fields).filter(([k])=>k!=='isDefault')),is_default:i===0,updated_at:f.stamp()});
  else f.state().ops=Array.from({length:256},()=>({operation_id:randomUUID()}));
  const args=await request(f),before=structuredClone(f.state());await assert.rejects(save(f,args),{code:type==='addresses'?'COMMERCE_ADDRESS_CAPACITY':'COMMERCE_OPERATION_CAPACITY'});assert.deepEqual(f.state(),before);
 }
});
test('trusted address choices reach all 32 owned rows while model address cards remain capped at 12',async()=>{
 const f=fixture();for(let i=0;i<32;i++)f.state().addresses.push({address_id:String(i+1),target_id:f.target.targetId,shop_user_id:f.auth.shopUserId,...Object.fromEntries(Object.entries({...fields,label:'Address '+(i+1)}).filter(([k])=>k!=='isDefault')),is_default:i===0,updated_at:f.stamp()});
 const trusted=await f.domain.addressChoices(f.target,f.auth);assert.equal(trusted.cards.length,32);
 const last=trusted.cards[31];assert.equal(last.title,'Address 32');
 assert.equal(trusted.addresses.length,32);assert.deepEqual(trusted.addresses[31],{addressId:32,choiceId:last.choiceId,fields:{...fields,label:'Address 32',isDefault:false}});
 for(let i=0;i<32;i++)assert.equal(trusted.addresses[i].choiceId,trusted.cards[i].choiceId);
 assert.equal(Object.hasOwn(await f.domain.addresses(f.target,f.auth),'addresses'),false);
 const foreign=await f.domain.addressChoices(f.target,{...f.auth,shopUserId:10});assert.deepEqual(foreign.cards,[]);assert.deepEqual(foreign.addresses,[]);
 assert.equal((await f.domain.addressForm(f.target,{...f.auth,action:'update',choiceId:last.choiceId})).fields.label,'Address 32');
 assert.equal((await f.domain.addresses(f.target,f.auth)).cards.length,12);
});
test('address GET validates receipt/request bindings even when each stored JSON hash is internally consistent',async()=>{
 for(const change of ['kind','fields','operation','extra']){
  const f=fixture(),args=await request(f);await save(f,args);const row=f.state().ops[0],result=JSON.parse(row.result_json);
  if(change==='kind')result.kind='address.update';
  if(change==='fields')result.result.fieldsSha256='f'.repeat(64);
  if(change==='operation')result.operationId=randomUUID();
  if(change==='extra')result.result.line1='Unexpected raw data';
  row.result_json=JSON.stringify(result);row.result_sha256=C.digest(row.result_json);
  await assert.rejects(f.domain.readOperation(f.target,{...f.auth,operationId:args.operationId}),{code:'COMMERCE_STATE_INVALID'});
 }
});

test('changed owned address choice and create default-set drift produce durable no-effect stale receipts',async()=>{
 for(const action of ['update','create']){
  const f=fixture();await save(f,await request(f));const choiceId=action==='update'?await selected(f):null;
  const args=await request(f,{...fields,line1:'Intended change'},action,choiceId);
  f.state().addresses[0].line1='Concurrent edit';f.state().addresses[0].updated_at=f.stamp();
  const before=structuredClone(f.state());const saved=await save(f,args);
  assert.equal(saved.status,'stale');assert.deepEqual(f.state().addresses,before.addresses);assert.deepEqual(f.state().audit,before.audit);
  assert.equal(f.state().ops.length,before.ops.length+1);assert.equal(f.state().ops.at(-1).state,'completed');
  assert.deepEqual(await save(f,args),{...saved,replayed:true});
 }
});
