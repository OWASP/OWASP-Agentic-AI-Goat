'use strict';
// Controlled fault only. No uncertainty rows, provider, or production authority
// are minted here. The original authority owns BEGIN/checks/ROLLBACK/release.
const {createSecureShopBoundPersonaAuthority}=require('../../server/database/postgres/secureshopBoundPersonaAuthority');
const SQL='SELECT secureshop_agents.bound_lab_mail($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb';
function observeCommittedMailPool(pool,records){
 const assert=require('node:assert/strict');
 const bind=(o,k)=>typeof o[k]==='function'?o[k].bind(o):o[k];
 return new Proxy(pool,{get(o,k){if(k!=='connect')return bind(o,k);return async()=>{
  const client=await o.connect();let staged=[];
  return new Proxy(client,{get(c,key){if(key!=='query')return bind(c,key);return async(...args)=>{
   const [sql,v]=args;let result;
   try{result=await c.query(...args);}catch(error){staged=[];throw error;}
   if(typeof sql==='string'&&(sql===SQL+') AS result'||sql===SQL+',$15::uuid) AS result')&&['read','send'].includes(v?.[12])){
    const value=result.rows?.[0]?.result;assert.equal(value?.ok,true);assert.equal(value.operationId,v[11]);
    staged.push(structuredClone({operationId:v[11],targetId:v[0],scope:{launchId:v[1],scenarioId:v[2],generation:v[3],platformOwnerId:v[4],platformSessionId:v[5]},
     personaId:v[6],sessionId:v[7],role:v[8],authorityVersion:String(v[9]),mode:v[10],action:v[12],payload:JSON.parse(v[13]),result:value.receipt}));
   }
   if(sql==='COMMIT'){assert(records.length+staged.length<=128,'Bounded committed mail witnesses');records.push(...staged);staged=[];}
   if(sql==='ROLLBACK')staged=[];
   return result;
  };}});
 };}});
}
function assertReceiptDelta({before,after,witnesses,expected,forbidden,siblingId,siblingSession}){
 const assert=require('node:assert/strict'),baseline=new Map(before.map(r=>[r.operation_id,r])),final=new Map(after.map(r=>[r.operation_id,r]));
 assert.equal(baseline.size,before.length);assert.equal(final.size,after.length);
 for(const [id,row]of baseline)assert.deepEqual(final.get(id),row,'Existing mail receipt changed');
 for(const id of forbidden)assert.equal(final.has(id),false,'Faulted send receipt must remain absent');
 const delta=after.filter(r=>!baseline.has(r.operation_id));assert.equal(delta.length,expected.length);
 assert.equal(new Set(expected.map(e=>e.operationId)).size,expected.length);
 for(const e of expected){
  assert(!baseline.has(e.operationId));const row=final.get(e.operationId);assert(row);
  const seen=witnesses.filter(w=>w.operationId===e.operationId);assert(seen.length>0,'Missing committed operation witness');
  const w=seen[0];for(const duplicate of seen)assert.deepEqual(duplicate,w);
  assert.equal(w.targetId,e.targetId);assert.deepEqual(w.scope,e.context.scope);
  assert.equal(w.personaId,e.context.persona.id);assert.equal(w.role,e.context.persona.role);
  assert.equal(w.sessionId,e.context.personaSession.sessionId);assert.equal(w.authorityVersion,String(e.context.personaSession.authorityVersion));
  assert.equal(w.action,e.action);assert.equal(w.mode,'vuln');
  for(const [field,value]of Object.entries({target_id:w.targetId,caller_id:w.personaId,persona_session_id:w.sessionId,role:w.role,mode:w.mode,action:w.action}))assert.equal(row[field],value);
  assert.equal(String(row.authority_version),w.authorityVersion);assert.deepEqual(row.result,w.result);
  assert.deepEqual(w.payload,e.payload);assert.match(e.requestSha256,/^[0-9a-f]{64}$/);
  assert.equal(Buffer.from(row.request_sha256).toString('hex'),e.requestSha256);
  if(e.action==='read')assert.equal(w.result.userId,e.context.persona.id);
  if(e.result)assert.deepEqual(w.result,e.result);
 }
 for(const w of witnesses)if(!baseline.has(w.operationId))assert(expected.some(e=>e.operationId===w.operationId),'Unaccounted committed operation');
 const sibling=rows=>rows.filter(r=>r.caller_id===siblingId||r.persona_session_id===siblingSession);
 assert.deepEqual(sibling(after),sibling(before),'Sibling receipts changed');
}
function assertSiblingMail(before,after,siblingId){
 const assert=require('node:assert/strict');assert(before.length>0&&before.length<=1024);
 assert(before.some(row=>row.sender_id===siblingId||row.recipient_id===siblingId),'Populated sibling messages required');
 assert.deepEqual(after,before,'Populated sibling mail and complete threads must remain unchanged');
}
function selectedReplyButton({role,threadId,subject,label,disabled}){
 const matches=[];
 for(const heading of document.querySelectorAll('h2')){
  if(heading.textContent.trim()!==subject)continue;
  const metadata=heading.parentElement?.querySelector('.ss-card__meta');
  const prefix=(role==='merchant'?'THREAD #':'Thread #')+threadId+' ·';
  if(!metadata?.textContent.trim().startsWith(prefix))continue;
  const panel=role==='merchant'?heading.parentElement?.parentElement:heading.parentElement?.parentElement?.parentElement;
  for(const button of panel?.querySelectorAll('button')||[]){
   if(button.textContent.trim()===label&&button.disabled===disabled&&button.getClientRects().length&&
    getComputedStyle(button).visibility!=='hidden'&&getComputedStyle(button).display!=='none')matches.push(button);
  }
 }
 return matches.length===1?matches[0]:false;
}
async function waitSelectedReplyButton(frame,options,deadline){
 const remaining=deadline-performance.now();
 if(!(remaining>0))throw Error('Q05_SELECTED_PANEL_DEADLINE');
 return frame.waitForFunction(selectedReplyButton,{timeout:Math.max(1,Math.floor(remaining)),polling:'raf'},options);
}
async function createAdmittedRolePage({browser,boundary,admission,origin,contexts,pageErrors}){
 if(!boundary||!admission)throw Error('Q05_BROWSER_ADMISSION_REQUIRED');
 const context=await browser.createBrowserContext();contexts.push(context);
 const page=await boundary.newPage(context);
 page.on('pageerror',error=>pageErrors.push(error.name||'PageError'));
 await admission.guardPageRequests(page,origin);
 await page.setViewport({width:1280,height:900});
 boundary.assertNoUnexpectedTargets();
 return page;
}
function createMailPersistenceFault(){
 let armed=null,closed=false,hits=0;
 const bind=(target,key)=>typeof target[key]==='function'?target[key].bind(target):target[key];
 return Object.freeze({
  arm(binding,threadId){
   // One lifetime fault per role-specific instance. close is terminal, so a
   // canceled instance cannot be recycled into another attempted operation.
   if(closed||armed||hits!==0||!Number.isSafeInteger(threadId)||threadId<1)throw Error('FAULT_ARM_INVALID');
   const s=binding.scope;
   armed=Object.freeze({coordinates:[binding.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,
    binding.persona.id,binding.personaSession.sessionId,binding.persona.role,binding.personaSession.authorityVersion,binding.mode,binding.operationId],threadId});
  },
  createAuthority({pool,checkCurrent}){
   const wrapped=new Proxy(pool,{get(target,key){
    if(key!=='connect')return bind(target,key);
    return async()=>{const client=await target.connect();return new Proxy(client,{get(c,k){
     if(k!=='query')return bind(c,k);
     return (...args)=>{
      const [sql,values]=args;
      if(!closed&&armed&&typeof sql==='string'&&
       (sql===SQL+') AS result'||sql===SQL+',$15::uuid) AS result')&&Array.isArray(values)&&values[12]==='send'&&
       armed.coordinates.every((v,i)=>v===values[i])){
       const payload=JSON.parse(values[13]);
       if(payload.threadId===armed.threadId){armed=null;hits++;throw Object.assign(Error('Controlled precommit mail persistence failure'),{code:'Q05_CONTROLLED_MAIL_WRITE_FAILURE'});}
      }
      return c.query(...args);
     };
    }});};
   }});
   return createSecureShopBoundPersonaAuthority({pool:wrapped,checkCurrent});
  },
  close(){closed=true;armed=null;},
  snapshot(){return Object.freeze({hits,armed:!!armed,closed,controlledFault:true});},
 });
}
function createKeepUnresolvedFacet(){
 const assert=require('node:assert/strict');
 const faults=Object.fromEntries(['customer','merchant'].map(role=>[role,createMailPersistenceFault()]));
 const contexts=new Map(),attempts=new Map(),detaches=[],readiness=new Map(),committed=[];let selected=null;
 const requestScope=new(require('node:async_hooks').AsyncLocalStorage)();
 return Object.freeze({
  readinessMiddleware(req,res,next){
   if(req.method!=='GET'||req.originalUrl!=='/api/secureshop/email/readiness')return next();
   assert(readiness.size<32,'Bounded readiness witnesses');
   const id=require('node:crypto').randomUUID(),record={authorization:req.headers.authorization,context:null};readiness.set(id,record);
   res.setHeader('x-q05-readiness-witness',id);return requestScope.run(record,next);
  },
  observePageReadiness(page,{origin,role,username}){
   let bootstrap=null,candidate=null,failure=null,closed=false;const pending=new Set();
   const onResponse=response=>{
    const work=(async()=>{
     const url=new URL(response.url());if(url.origin!==origin)return;
     const request=response.request();
     if(url.pathname==='/api/secureshop/auth/bootstrap'&&request.method()==='POST'&&response.status()===200){
      const value=await response.json();if(closed)return;
      if(value?.persona?.user?.role===role&&value.persona.user.username===username){
       assert.equal(typeof value.persona.token,'string');bootstrap=`Bearer ${value.persona.token}`;
      }
     }
     if(url.pathname==='/api/secureshop/email/readiness'){
      assert.equal(url.search,'');assert.equal(request.method(),'GET');assert.equal(response.status(),200);
      const id=response.headers()['x-q05-readiness-witness'],record=readiness.get(id);
      assert(record?.context,'Actual wrapped readiness completion required');
      assert.equal(record.context.persona.role,role);
      assert(record.authorization===request.headers().authorization,'Q05_READINESS_AUTHORIZATION_MISMATCH');
      assert.equal(typeof record.authorization,'string');candidate=record;
     }
    })().catch(error=>{if(!closed)failure=error;}).finally(()=>pending.delete(work));pending.add(work);
   };
   page.on('response',onResponse);
   return Object.freeze({async wait(){
    const end=performance.now()+15000;
    while(performance.now()<end){if(failure)throw failure;
     if(bootstrap&&candidate&&candidate.authorization===bootstrap)return candidate.context;
     await new Promise(resolve=>setTimeout(resolve,10));
    }throw Error('Q05_CURRENT_PAGE_READINESS_UNAVAILABLE');
   },close(){closed=true;page.off('response',onResponse);}});
  },
  observeReply(page,{origin,role,threadId,context,deadline}){
   assert(Number.isFinite(deadline)&&deadline>performance.now());
   let physical=null,failure=null,closed=false;
   const onRequest=request=>{try{
    const url=new URL(request.url());if(url.origin!==origin||url.pathname!==`/api/secureshop/email/auto-reply/${threadId}`)return;
    assert.equal(url.search,'');assert.equal(request.method(),'POST');assert.equal(physical,null,'One original reply POST only');
    const body=JSON.parse(request.postData());assert.deepEqual(Object.keys(body),['requestId']);
    assert.match(body.requestId,/^[0-9a-f-]{36}$/);physical={request,requestId:body.requestId,status:null,finished:false};
   }catch(error){failure=error;}};
   const onResponse=response=>{if(physical&&response.request()===physical.request){
    physical.status=response.status();
    void response.text().then(text=>{
     if(closed)return;assert(Buffer.byteLength(text)<=2048,'Q05_REPLY_RESPONSE_BOUND');
     const body=JSON.parse(text);
     assert(body&&Object.keys(body).sort().join(',')==='error,ok'&&body.ok===false&&body.error==='Bound mail unavailable','Q05_REPLY_RESPONSE_INVALID');
     physical.bodyVerified=true;
    }).catch(()=>{if(!closed)failure=Error('Q05_REPLY_RESPONSE_INVALID');});
   }};
   const onFinished=request=>{if(physical&&request===physical.request)physical.finished=true;};
   const onFailed=request=>{if(physical&&request===physical.request)failure=Error('Q05_ORIGINAL_REPLY_REQUEST_FAILED');};
   page.on('request',onRequest);page.on('response',onResponse);page.on('requestfinished',onFinished);page.on('requestfailed',onFailed);
   return Object.freeze({async wait(){
    while(performance.now()<deadline){
     if(failure)throw failure;const attempt=attempts.get(role);
     if(attempt&&physical){
      assert.equal(attempt.input.requestId,physical.requestId);assert.equal(attempt.input.threadId,threadId);
      assert.deepEqual(attempt.context,context);
      if(attempt.settlement){
       assert.equal(attempt.settlement.rejected,true);assert.equal(attempt.settlement.code,'MAIL_SEND_UNCONFIRMED');
       assert.equal(faults[role].snapshot().hits,1,'Original precommit fault must have executed');
       if(physical.finished&&physical.bodyVerified){assert.equal(physical.status,503);return attempt;}
      }
     }
     await new Promise(resolve=>setTimeout(resolve,10));
    }throw Error('Q05_ORIGINAL_REPLY_SETTLEMENT_DEADLINE');
   },close(){closed=true;page.off('request',onRequest);page.off('response',onResponse);page.off('requestfinished',onFinished);page.off('requestfailed',onFailed);}});
  },
  createAuthority(options){
   options={...options,pool:observeCommittedMailPool(options.pool,committed)};
   const original=createSecureShopBoundPersonaAuthority(options);
   const scoped=Object.fromEntries(Object.entries(faults).map(([r,f])=>[r,f.createAuthority(options)]));
   return Object.freeze({...original,capture(input){return (scoped[input.role]||original).capture(input);}});
  },
  wrapApplication(application,mailScenes){return Object.freeze({...application,
   async readiness(context,...rest){const result=await application.readiness(context,...rest);contexts.set(context.persona.role,context);
    const record=requestScope.getStore();if(record)record.context=context;return result;},
   async keepUnresolved(context,input){const result=await application.keepUnresolved(context,input);
    detaches.push(structuredClone({context,input,result}));return result;},
   async reply(context,input,options){
    assert.equal(context.persona.role,selected,'Only selected physical role may start the faulted operation');
    assert.equal(attempts.has(selected),false,'Exactly one original reply per role');
    const target=await mailScenes.resolve(context);
    const binding={...context,target, targetId:target.targetId,mode:'vuln',operationId:require('../../server/services/secureshopBoundMailGraph').operationId(input.requestId,'reply')};
    faults[selected].arm(binding,input.threadId);
    const attempt={context,input:structuredClone(input),targetId:target.targetId,settlement:null};attempts.set(selected,attempt);
    try{const result=await application.reply(context,input,options);attempt.settlement={rejected:false,code:null};return result;}
    catch(error){attempt.settlement={rejected:true,code:error.code||null};throw error;}
   },
  });},
  select(role){assert(Object.hasOwn(faults,role));assert(!attempts.has(role));selected=role;},
  context(role){assert(contexts.has(role),'Actual mounted readiness required');return contexts.get(role);},
  attempt(role){assert(attempts.has(role));return attempts.get(role);},
  detaches(){return structuredClone(detaches);},
  committed(){return structuredClone(committed);},
  snapshot(){return Object.fromEntries(Object.entries(faults).map(([r,f])=>[r,f.snapshot()]));},
  close(){selected=null;for(const f of Object.values(faults))f.close();},
 });
}
const SCOPE='q05-mail-keep-unresolved-rendered-v1';
function assertReceipt(value){
 const a=require('node:assert/strict');
 const exact=(o,keys)=>a.deepEqual(Object.keys(o).sort(),keys.sort());
 const flags=['passed','isolatedStores','bothRoles','zeroJudge','noExtraSend','fixtureCleaned'];
 exact(value,[...flags,'scope','canonicalCredit','qualificationAccepted','actorCalls','roleTurns','judgeCalls','errors','mailKeepUnresolved']);
 for(const k of flags)a.equal(value[k],true,k);
 a.equal(value.scope,SCOPE);a.equal(value.canonicalCredit,0);a.equal(value.qualificationAccepted,false);
 a.equal(value.roleTurns,0);a.equal(value.judgeCalls,0);a.deepEqual(value.errors,[]);
 a(Number.isSafeInteger(value.actorCalls)&&value.actorCalls>=4&&value.actorCalls<=30);
 const r=value.mailKeepUnresolved;exact(r,['version','scope','passed','roles','faults']);
 a.equal(r.version,1);a.equal(r.scope,SCOPE);a.equal(r.passed,true);
 a.deepEqual(r.roles.map(x=>x.role),['merchant','customer']);exact(r.faults,['merchant','customer']);
 let calls=0;
 for(const row of r.roles){
  exact(row,['role','requestId','threadId','disclosed','retained','noExtraSend','physicalPost','protectedDetach','actorHttpCalls','providerEvidence','controlledComponent']);
  a.match(row.requestId,/^[a-f0-9-]{36}$/);a(Number.isSafeInteger(row.threadId)&&row.threadId>0);
  for(const k of ['disclosed','retained','noExtraSend'])a.equal(row[k],true);
  a(Number.isSafeInteger(row.actorHttpCalls)&&row.actorHttpCalls>=2);calls+=row.actorHttpCalls;
  a.equal(row.providerEvidence,'original mail-actions physical transport capture');a.equal(row.controlledComponent,'one precommit persistence fault only');
  exact(row.physicalPost,['method','path','body','status']);a.equal(row.physicalPost.method,'POST');a.equal(row.physicalPost.status,200);
  a.equal(row.physicalPost.path,`/api/secureshop/email/operations/autoReply/${row.requestId}/keep-unresolved`);
  a.deepEqual(row.physicalPost.body,{threadId:row.threadId});
  const d=row.protectedDetach;exact(d,['session_id','request_id','claim_id','request_hash','target_id','persona_id','persona_session_id','authority_version','thread_id','mode']);
  a.equal(d.request_id,row.requestId);a.equal(Number(d.thread_id),row.threadId);a.equal(d.mode,'vuln');
  for(const k of ['session_id','claim_id','target_id','persona_session_id'])a.match(d[k],/^[a-f0-9-]{36}$/);
  a.match(d.request_hash,/^[a-f0-9]{64}$/);a(Number.isSafeInteger(d.persona_id)&&d.persona_id>0);a.match(String(d.authority_version),/^[1-9]\d*$/);
  a.deepEqual(r.faults[row.role],{hits:1,armed:false,closed:true,controlledFault:true});
 }
 a.equal(calls,value.actorCalls);return value;
}
module.exports={createMailPersistenceFault,createKeepUnresolvedFacet,createAdmittedRolePage,selectedReplyButton,waitSelectedReplyButton,observeCommittedMailPool,assertReceiptDelta,assertSiblingMail,assertReceipt,SCOPE};
