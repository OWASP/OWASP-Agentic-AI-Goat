'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {createSecureShopOwnedAgencyRoleRepository,validateAgencyRoleReceipt}=require('../server/database/postgres/secureshopOwnedAgencyRoleRepository');
function input(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:101,platformSessionId:202};
 const runId=randomUUID(),callId='original-call',step=1;
 return {scope,scene:{targetId:randomUUID(),sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID()},
  persona:{id:1000000001,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},
  requestId:randomUUID(),runId,callId,step,effectKey:JSON.stringify([step,callId,'user-management.set_role']),
  args:{user_id:1000000001,role:'admin'},modeExecution:{version:1,featureId:'customer_chat',
   policyVersion:'owned-catalog-and-cart-read-v1',mode:'vuln',generation:0,modeStamp:'owned-mode-epoch',scope:{...scope}},
  policyAdmission:{admissionId:randomUUID(),runId,invocationId:`${step}:${callId}`,toolKey:'user-management.set_role',
   policyVersion:'1',registrySha256:'a'.repeat(64),enforcement:false,allowed:false,action:'dispatch',policyViolation:'denied-by-acl'}};
}
const ref=q=>Object.fromEntries(['requestId','runId','callId','effectKey'].map(k=>[k,q[k]]));
function fixture(){
 const targets=new Map(),effects=[],queries=[];let failInsert=false;
 const client={async query(sql,p=[]){
  queries.push(sql);const rows=r=>({rows:r,rowCount:r.length});
  if(sql.startsWith('INSERT INTO secureshop_agents.owned_agency_role_targets')){
   if(!targets.has(p[0]))targets.set(p[0],{target_key:p[0],platform_launch_id:p[1],platform_scenario_id:p[2],
    platform_launch_generation:p[3],original_platform_owner_id:p[4],original_platform_session_id:p[5],
    target_id:p[6],scene_id:p[7],scene_generation:p[8],grant_id:p[9],customer_id:p[10],
    teaching_role:'customer',revision:'1',lifecycle:'active'});return rows([]);
  }
  if(sql.startsWith('SELECT * FROM secureshop_agents.owned_agency_role_targets'))return rows(targets.has(p[0])?[structuredClone(targets.get(p[0]))]:[]);
  if(sql.startsWith('SELECT * FROM secureshop_agents.owned_agency_role_effects'))return rows(effects.filter(r=>r.target_key===p[0]&&
   ((r.request_id===p[1]&&r.call_id===p[3])||(r.run_id===p[2]&&r.effect_key===p[4]))).map(r=>structuredClone(r)));
  if(sql.startsWith('UPDATE secureshop_agents.owned_agency_role_targets')&&sql.includes("SET teaching_role='admin'")){
   const r=targets.get(p[0]);if(!r||r.lifecycle!=='active'||r.teaching_role!=='customer'||r.revision!=='1')return rows([]);
   r.teaching_role='admin';r.revision='2';return rows([{}]);
  }
  if(sql.startsWith('INSERT INTO secureshop_agents.owned_agency_role_effects')){
   if(failInsert)throw Error('controlled insert failure');
   effects.push({target_key:p[0],request_id:p[1],run_id:p[2],call_id:p[3],effect_key:p[4],request_json:JSON.parse(p[5]),
    request_sha256:p[6],receipt_json:JSON.parse(p[7]),receipt_sha256:p[8]});return rows([]);
  }
  if(sql.startsWith('UPDATE secureshop_agents.owned_agency_role_targets')&&sql.includes("SET lifecycle='retired'")){
   let n=0;for(const r of targets.values())if(r.lifecycle==='active'&&
    [r.platform_launch_id,r.platform_scenario_id,r.platform_launch_generation,r.original_platform_owner_id,r.original_platform_session_id].every((x,i)=>x===p[i])){r.lifecycle='retired';n++;}
   return {rows:[],rowCount:n};
  }
  throw Error(`Unexpected SQL ${sql}`);
 }};
 return {repo:createSecureShopOwnedAgencyRoleRepository(),client,targets,effects,queries,
  failInsert(){failInsert=true;},async transaction(work){const before=structuredClone([...targets]),old=structuredClone(effects);
   try{return await work(client);}catch(e){targets.clear();for(const [k,v]of before)targets.set(k,v);effects.splice(0,effects.length,...old);throw e;}}};
}
test('teaching transition uses original client and immutable effect; exact replay and JSONB key reorder preserve bytes',async()=>{
 const f=fixture(),q=input(),initial=await f.repo.ensureWithClient(f.client,q);
 assert.equal(initial.teachingRole,'customer');assert.equal(initial.revision,'1');
 const first=await f.repo.applyWithClient(f.client,q);assert.equal(first.replayed,false);
 assert.equal(first.receipt.changed,true);assert.deepEqual(first.receipt.before,{role:'customer',revision:'1'});
 assert.deepEqual(first.receipt.after,{role:'admin',revision:'2'});assert.equal(first.receipt.requestSha256,canonicalDigest(Object.fromEntries(Object.keys(first.receipt).filter(k=>!['version','before','after','changed','requestSha256','receiptSha256'].includes(k)).map(k=>[k,first.receipt[k]]))));
 const reorder=x=>x&&typeof x==='object'?Array.isArray(x)?x.map(reorder):Object.fromEntries(Object.entries(x).reverse().map(([k,v])=>[k,reorder(v)])):x;
 f.effects[0].request_json=reorder(f.effects[0].request_json);f.effects[0].receipt_json=reorder(f.effects[0].receipt_json);
 const count=f.queries.length;assert.deepEqual(await f.repo.readEffectWithClient(f.client,q,ref(q)),first.receipt);
 assert.ok(f.queries.slice(count).every(s=>s.startsWith('SELECT')));
 assert.deepEqual(await f.repo.applyWithClient(f.client,q),{receipt:first.receipt,replayed:true});assert.equal(f.effects.length,1);
 assert.equal((await f.repo.readWithClient(f.client,q)).teachingRole,'admin');
 assert.ok(f.queries.every(s=>!s.includes('shop_users')&&!s.includes('bound_persona_state')&&!s.includes('identity.')&&!/^BEGIN|COMMIT|ROLLBACK/.test(s)));
});
test('second operation records truthful no-op and cannot claim a new customer to admin transition',async()=>{
 const f=fixture(),q=input();await f.repo.ensureWithClient(f.client,q);await f.repo.applyWithClient(f.client,q);
 q.requestId=randomUUID();q.runId=randomUUID();q.policyAdmission.runId=q.runId;q.policyAdmission.admissionId=randomUUID();
 const second=await f.repo.applyWithClient(f.client,q);assert.equal(second.receipt.changed,false);
 assert.deepEqual(second.receipt.before,second.receipt.after);assert.equal(f.effects.length,2);
});
test('fixed, allowed, enforced or blocked policy never mutates teaching state',async()=>{
 for(const change of [q=>{q.modeExecution.mode='fixed';},q=>{q.policyAdmission.allowed=true;q.policyAdmission.policyViolation=null;},
  q=>{q.policyAdmission.enforcement=true;},q=>{q.policyAdmission.action='block';}]){
  const f=fixture(),q=input();await f.repo.ensureWithClient(f.client,q);change(q);const count=f.queries.length;
  await assert.rejects(f.repo.applyWithClient(f.client,q),{code:'AGENCY_ROLE_DENIED'});
  assert.equal(f.queries.length,count);assert.equal(f.effects.length,0);assert.equal([...f.targets.values()][0].teaching_role,'customer');
 }
});
test('foreign argument, invalid authority, fabricated ACL invocation and effect keys reject before SQL',async()=>{
 for(const change of [q=>{q.args.user_id++;},q=>{q.args.role='merchant';},q=>{q.args.extra=true;},q=>{q.persona.role='admin';},
  q=>{q.personaSession.authorityVersion='0';},q=>{q.scene.sceneGeneration=0;},q=>{q.modeExecution.scope.platformSessionId++;},
  q=>{q.policyAdmission.invocationId=q.callId;},q=>{q.policyAdmission.runId=randomUUID();},q=>{q.effectKey='forged';}]){
  const f=fixture(),q=input();change(q);await assert.rejects(f.repo.applyWithClient(f.client,q),{code:'AGENCY_ROLE_INVALID'});assert.equal(f.queries.length,0);
 }
});
test('conflicting request, changed epoch and renewed session cannot reuse an original effect',async()=>{
 for(const change of [q=>{q.modeExecution.modeStamp='new-mode';},q=>{q.personaSession.sessionId=randomUUID();},
  q=>{q.runId=randomUUID();q.policyAdmission.runId=q.runId;},q=>{q.requestId=randomUUID();}]){
  const f=fixture(),q=input();await f.repo.ensureWithClient(f.client,q);await f.repo.applyWithClient(f.client,q);
  const original=structuredClone(f.effects);change(q);
  await assert.rejects(f.repo.applyWithClient(f.client,q),{code:'AGENCY_ROLE_CONFLICT'});assert.deepEqual(f.effects,original);
 }
});
test('retirement fences reads/replay/ensure without deleting history or changing siblings',async()=>{
 const f=fixture(),q=input(),s=input();s.scope.platformOwnerId++;s.modeExecution.scope={...s.scope};
 await f.repo.ensureWithClient(f.client,q);await f.repo.ensureWithClient(f.client,s);await f.repo.applyWithClient(f.client,q);
 const history=structuredClone(f.effects),sibling=await f.repo.readWithClient(f.client,s);
 assert.equal(await f.repo.retireWithClient(f.client,q.scope),1);assert.equal(await f.repo.retireWithClient(f.client,q.scope),0);
 for(const work of [()=>f.repo.readWithClient(f.client,q),()=>f.repo.ensureWithClient(f.client,q),()=>f.repo.applyWithClient(f.client,q),()=>f.repo.readEffectWithClient(f.client,q,ref(q))])
  await assert.rejects(work(),{code:'AGENCY_ROLE_RETIRED'});
 assert.deepEqual(f.effects,history);assert.deepEqual(await f.repo.readWithClient(f.client,s),sibling);
 const fresh=input(),count=f.queries.length;assert.equal(await f.repo.readWithClient(f.client,fresh),null);assert.equal(f.targets.size,2);
 assert.ok(f.queries.slice(count).every(s=>s.startsWith('SELECT')));
});
test('caller transaction rolls back transition when immutable effect insertion fails',async()=>{
 const f=fixture(),q=input();await f.repo.ensureWithClient(f.client,q);f.failInsert();
 await assert.rejects(f.transaction(c=>f.repo.applyWithClient(c,q)),/controlled insert failure/);
 assert.equal((await f.repo.readWithClient(f.client,q)).teachingRole,'customer');assert.equal(f.effects.length,0);
});
test('original receipt and persisted state tampering fails closed',async()=>{
 const f=fixture(),q=input();await f.repo.ensureWithClient(f.client,q);const {receipt}=await f.repo.applyWithClient(f.client,q);
 for(const change of [r=>{r.changed=false;},r=>{r.after.role='customer';},r=>{r.scene.grantId=randomUUID();},r=>{r.receiptSha256='b'.repeat(64);}]){
  const r=structuredClone(receipt);change(r);assert.throws(()=>validateAgencyRoleReceipt(r,q),{code:'AGENCY_ROLE_INTEGRITY'});
 }
 f.effects[0].receipt_json.before.role='admin';await assert.rejects(f.repo.readEffectWithClient(f.client,q,ref(q)),{code:'AGENCY_ROLE_INTEGRITY'});
 [...f.targets.values()][0].customer_id++;await assert.rejects(f.repo.readWithClient(f.client,q),{code:'AGENCY_ROLE_INTEGRITY'});
});
test('saved effect cannot disagree with current teaching state',async()=>{
 const f=fixture(),q=input();await f.repo.ensureWithClient(f.client,q);await f.repo.applyWithClient(f.client,q);
 Object.assign([...f.targets.values()][0],{teaching_role:'customer',revision:'1'});
 await assert.rejects(f.repo.readEffectWithClient(f.client,q,ref(q)),{code:'AGENCY_ROLE_INTEGRITY'});
 await assert.rejects(f.repo.applyWithClient(f.client,q),{code:'AGENCY_ROLE_INTEGRITY'});
 assert.equal(f.effects.length,1);
});
