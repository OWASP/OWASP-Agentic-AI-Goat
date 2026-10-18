'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createXssMutationAdmission}=require('../server/services/xssMutationAdmission');
function fixture(){
 const calls=[];const journal={assertMutationAdmitted:async id=>{assert.equal(id,42);calls.push('admit');}};
 const lifecycle=async(_,owner,work)=>{assert.equal(owner,42);calls.push('lock');try{return await work(null,{check:async()=>{calls.push('guard');}});}finally{calls.push('unlock');}};
 return{calls,journal,admit:createXssMutationAdmission({pool:{connect(){}},journal,lifecycle})};
}
test('authenticated mutation guard retains lifecycle and expires after work',async()=>{
 const f=fixture();let retained;
 assert.equal(await f.admit('42',async guard=>{retained=guard;await guard.check();return 'ok';}),'ok');
 assert.equal(f.calls[0],'lock');assert.equal(f.calls.at(-1),'unlock');
 await assert.rejects(retained.check(),/ended/);
});
test('pending reset prevents handler work and releases lifecycle',async()=>{
 const f=fixture();let ran=false;f.journal.assertMutationAdmitted=async()=>{throw new Error('pending reset');};
 await assert.rejects(f.admit(42,async()=>{ran=true;}),/pending reset/);
 assert.equal(ran,false);assert.equal(f.calls.at(-1),'unlock');
});
test('anonymous or malformed owner cannot acquire platform mutation authority',async()=>{
 const f=fixture();for(const value of ['anon_session','042',0,-1,2147483648,null])await assert.rejects(f.admit(value,async()=>{}),TypeError);
 assert.deepEqual(f.calls,[]);
});
test('admission is rechecked before a subsequent mutation boundary',async()=>{
 const f=fixture();let mutated=false;
 await assert.rejects(f.admit(42,async guard=>{
  f.journal.assertMutationAdmitted=async()=>{throw new Error('owner unavailable');};
  await guard.check();mutated=true;
 }),/owner unavailable/);assert.equal(mutated,false);
});
test('configured admission is lazy and dependency failures do not allocate lifecycle pools',()=>{
 const {createLazyXssMutationAdmission}=require('../server/services/xssMutationAdmission');let allocations=0;
 const admit=createLazyXssMutationAdmission({createLifecyclePool:()=>{allocations++;return{};},createJournal:()=>{throw new Error('not ready');}});
 assert.equal(allocations,0);assert.throws(()=>admit(42,()=>{}),/not ready/);assert.equal(allocations,0);
});
test('profile reset pending check uses held lifecycle authority and fails before reset',async()=>{
 const {createXssProfileResetPendingCheck}=require('../server/services/xssMutationAdmission');
 const calls=[];let pending=null;
 const check=createXssProfileResetPendingCheck({journal:{readNonterminalForOwner:async owner=>{
  assert.equal(owner,42);calls.push('read');return pending;
 }}});
 const guard={ownerId:42,check:async()=>calls.push('guard')};
 assert.equal(await check(42,guard),true);
 pending={operationId:'pending'};
 await assert.rejects(check('42',guard),{code:'XSS_PROFILE_RESET_PENDING',statusCode:503});
 assert.deepEqual(calls,['guard','read','guard','guard','read','guard']);
});
test('profile reset pending check rejects missing, foreign, or malformed held authority',async()=>{
 const {createXssProfileResetPendingCheck}=require('../server/services/xssMutationAdmission');
 let reads=0;const check=createXssProfileResetPendingCheck({journal:{readNonterminalForOwner:async()=>{reads++;}}});
 for(const [owner,guard] of [[42,null],[42,{ownerId:41,check:async()=>{}}],['042',{ownerId:42,check:async()=>{}}]])
  await assert.rejects(()=>check(owner,guard),TypeError);
 assert.equal(reads,0);
});

test('only pre-acquisition lock timeout is actionable busy; retry can acquire normally',async()=>{
 const {OwnerWorkflowHttpError}=require('../server/agent-runtime/ownerWorkflowHttpError');
 let busy=true,entered=0,journalCalls=0;
 const admit=createXssMutationAdmission({pool:{connect(){}},journal:{assertMutationAdmitted:async()=>{journalCalls++;}},lifecycle:async(_p,_id,work)=>{if(busy)throw Object.assign(Error('private SQL lock details'),{code:'55P03'});return work(null,{check:async()=>{}});}});
 await assert.rejects(admit(42,async()=>{entered++;}),e=>e instanceof OwnerWorkflowHttpError&&e.status===503&&e.retryAfter===2&&!e.message.includes('SQL'));
 assert.equal(entered,0);assert.equal(journalCalls,0);busy=false;
 assert.equal(await admit(42,async()=>{entered++;return 'retried';}),'retried');assert.equal(entered,1);
});
test('journal, mutation and release lock timeouts never become safe busy retries',async()=>{
 for(const phase of ['journal','mutation','release','other-before']){
  const original=Object.assign(Error('original '+phase),{code:phase==='other-before'?'57014':'55P03'});
  const admit=createXssMutationAdmission({pool:{connect(){}},journal:{assertMutationAdmitted:async()=>{if(phase==='journal')throw original;}},lifecycle:async(_p,_id,work)=>{if(phase==='other-before')throw original;const result=await work(null,{check:async()=>{}});if(phase==='release')throw original;return result;}});
  await assert.rejects(admit(42,async()=>{if(phase==='mutation')throw original;}),e=>e===original);
 }
});
test('busy reset HTTP contract preserves exact session and performs no coordinator work before retry',async()=>{
 const {createXssOwnerWorkflowRoute}=require('../server/agent-runtime/xssOwnerWorkflowRoute');
 let busy=true,live=true,coordinated=0,mutations=0;const tokens=[];
 const admit=createXssMutationAdmission({pool:{connect(){}},journal:{assertMutationAdmitted:async()=>{}},lifecycle:async(_p,_id,work)=>{if(busy)throw Object.assign(Error('canceling statement due to lock timeout'),{code:'55P03'});return work(null,{check:async()=>{}});}});
 const route=createXssOwnerWorkflowRoute({coordinator:{reset:async(_o,work)=>{coordinated++;return work({check:async()=>{}});}},ownerFor:()=>42,postgres:true,admit,pendingProfileReset:async()=>{},validateSession:async token=>{tokens.push(token);return live?{user:{id:42},session:{id:7,user_id:42}}:null;}})(async(_q,res)=>{mutations++;res.json({success:true});},{reset:true});
 const req={user:{id:42},identitySession:{id:7},headers:{authorization:'Bearer original'}};
 const response=()=>({statusCode:200,headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.statusCode=n;return this;},json(body){this.body=body;this.headersSent=true;}});
 const blocked=response();await route(req,blocked);assert.equal(blocked.statusCode,503);assert.equal(blocked.headers['Retry-After'],'2');assert.match(blocked.body.error,/Wait for it to finish, then try again/);assert.equal(coordinated,0);assert.equal(mutations,0);
 busy=false;const retry=response();await route(req,retry);assert.equal(retry.statusCode,200);assert.equal(mutations,1);
 live=false;const revoked=response();await route(req,revoked);assert.equal(revoked.statusCode,401);assert.equal(mutations,1);assert.ok(tokens.every(token=>token==='original'));
});
