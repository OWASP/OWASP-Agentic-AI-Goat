'use strict';
// Real shared LangGraph runner with controlled provider, authority and persistence.
// Does not establish actual model calls, PostgreSQL containment or Judge credit.
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto');
const {createSecureShopBoundAnalytics}=require('../server/services/secureshopBoundAnalytics');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
const persona={id:3,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
const sql="SELECT username FROM shop_users UNION SELECT secret FROM teaching_secrets -- intentionally raw";
const {hash:canonicalHash}=require('../sidecars/analytics-sql-target/contract');
const sha=v=>createHash('sha256').update(v).digest('hex');
function fixture(options={}){
 const sessions=new Map(),messages=new Map(),requests=new Map(),traces=[],queries=[];let calls=0,finalCalls=0;
 const repo={async getBoundSession(id){return sessions.get(id);},async acquireBoundSession({id,binding,purpose}){
   const prior=[...sessions.values()].find(s=>JSON.stringify(s.binding)===JSON.stringify(binding)&&s.purpose===purpose);if(prior)return prior;
   const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;
  },async activateBoundSession(id){sessions.get(id).state='active';return true;},async getMessages(id){return structuredClone(messages.get(id)||[]);},
  async appendMessage(id,_binding,m){messages.set(id,[...(messages.get(id)||[]),structuredClone(m)]);},async getTokens(){return 0;},async addTokens(){},async appendTraces(_id,_binding,rows){traces.push(...structuredClone(rows));}};
 const journal={async claim({requestId,requestDigest}){if(requests.has(requestId))return requests.get(requestId);const value={status:'claimed',claimId:requestId};requests.set(requestId,value);return value;},async complete({requestId,result}){requests.set(requestId,{status:'completed',claimId:requestId,result:structuredClone(result)});options.onJournalComplete?.();},async markUncertain(){}};
 const coordinator={async run(_owner,opts,work){const admitted=await opts.admit();if(admitted.skip)return admitted.value;const runId=randomUUID();return work({runId,ownerKey:'analytics-owner',generation:1,durableGeneration:'1',signal:opts.signal,check:async()=>{},effect:async(_key,fn)=>fn(),effectWithReceipt:async(key,fn)=>({value:await fn(),receipt:options.missingEffect?null:{version:1,runId,ownerKey:'analytics-owner',generation:'1',status:'completed',effectKey:`${opts.idempotencyKey}:${key}`}}),trace:async()=>{}});}};
 let revoked=false;
 const authority={capture:async({scope,personaId,role,...session})=>({binding:{...scope,personaId,role,...session,...options.fenceBinding},assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},withPersonaEffect:async fn=>fn({})})};
 const provider={async chat(args){options.inspectPrompt?.(args);calls++;return{stop_reason:'tool_use',tool_uses:[{id:'query-1',name:options.tool||'analytics.execute_query',args:options.args||{sql}}],provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,...options.decision};},async finalResponse(){finalCalls++;return{stop_reason:'end_turn',responseMode:'structured_final',text:'Observed synthetic secret',provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,...options.final};}};
 const target={targetId:randomUUID(),scope,sourceManifestSha256:'a'.repeat(64)};
 const ownedQuery={resolve:async()=>target,schema:'shop_users(username text); teaching_secrets(secret text)',async execute(input){queries.push(input);if(options.revokeAfterQuery)revoked=true;options.afterQuery?.();const result={sql:input.sql,columns:['username'],rows:[{username:'SYNTHETIC_ONLY'}],row_count:1,error:null};
  const receipt={version:1,operationId:input.operationId,targetId:target.targetId,scope:input.scope,runId:input.runId,requestId:input.requestId,sessionId:input.sessionId,callId:input.callId,sqlSha256:sha(input.sql),sourceManifestSha256:'a'.repeat(64),resultSha256:canonicalHash(result),result};
  if(input.mode){receipt.version=3;receipt.mode=input.mode;receipt.protectedEvidence={version:1,observations:[],truncated:false};}if(options.mutateReceipt)options.mutateReceipt(receipt);return receipt;}};
 const admitted=new Map();
 const requestRepository=options.admission?{async admit(input){const old=admitted.get(input.requestId);if(old){if(old.personaSession.sessionId!==input.personaSession.sessionId)throw Object.assign(Error('original'),{code:'SHOP_AUTH_INVALID'});if(old.question!==input.question)throw Object.assign(Error('conflict'),{code:'ANALYTICS_REQUEST_CONFLICT'});return {created:false};}admitted.set(input.requestId,structuredClone({...input}));return {created:!options.admissionInterrupted};},async read(input){const a=admitted.get(input.requestId);if(!a)return null;if(a.personaSession.sessionId!==input.personaSession.sessionId)throw Object.assign(Error('original'),{code:'SHOP_AUTH_INVALID'});const r=requests.get(input.requestId);return {sessionId:a.sessionId,question:a.question,modeSnapshot:a.modeSnapshot,status:r?.status||'admitted',result:r?.result};}}:undefined;
 const service=createSecureShopBoundAnalytics({launches:{assertCurrent:async()=>{}},conversationRepository:repo,journal,coordinator,provider,personaAuthority:authority,ownedQuery,promptPolicyRepository:options.promptPolicyRepository,requestRepository,modeAuthority:options.modeAuthority,assessmentFactory:options.assessmentFactory,disclosureAssessmentFactory:options.disclosureAssessmentFactory});
 const input={scope,persona,personaSession,question:'Show customer names',requestId:randomUUID(),signal:undefined};
 return{service,input,traces,queries,sessions,messages,calls:()=>calls,finalCalls:()=>finalCalls};
}
test('actual shared graph preserves raw SQL and joins model, owned receipt, effect and final output',async()=>{
 const f=fixture(),r=await f.service.query(f.input);assert.equal(r.sql,sql);assert.equal(r.rows[0].username,'SYNTHETIC_ONLY');assert.equal(f.queries.length,1);assert.equal(f.calls(),1);assert.equal(f.finalCalls(),1);
 assert.deepEqual(f.queries[0].scope,scope);assert.equal(f.queries[0].persona.id,persona.id);assert.equal(r.receipt.requestId,f.input.requestId);
 assert.equal([...f.sessions.values()][0].purpose,'secureshop_analytics');
 assert.ok(f.traces.some(t=>t.kind==='model_decision'&&JSON.parse(t.params_json||'{}').toolCalls?.[0]?.args.sql===sql));
 assert.ok(f.traces.some(t=>t.kind==='local_tool_result'));assert.ok(f.traces.some(t=>t.kind==='terminal'));
 const again=await f.service.query(f.input);assert.deepEqual(again,r);assert.equal(f.queries.length,1);assert.equal(f.calls(),1);
});
test('invalid, unavailable, mock or fallback decision cannot dispatch owned SQL',async()=>{
 for(const options of [{tool:'system.diagnostic'},{args:{sql,targetId:randomUUID()}},{args:{sql:''}},{args:{sql:'a\0b'}},{decision:{mocked:true}},{decision:{fallback:true}},{decision:{provider:'mock'}},{decision:{model:''}},{decision:{stop_reason:'end_turn',text:'invented',tool_uses:[]}}, {decision:{tool_uses:[{id:'a',name:'analytics.execute_query',args:{sql}},{id:'b',name:'analytics.execute_query',args:{sql}}]}}]){
  const f=fixture(options);await assert.rejects(f.service.query(f.input));assert.equal(f.queries.length,0);assert.equal(f.finalCalls(),0);
 }
});
test('final response requires real-provider provenance and structured nonempty text',async()=>{
 for(const final of [{mocked:true},{fallback:true},{provider:'mock'},{responseMode:'text'},{text:''},{stop_reason:'tool_use',tool_uses:[{}]}]){
  const f=fixture({final});await assert.rejects(f.service.query(f.input));assert.equal(f.queries.length,1);
 }
});
test('receipt scope, SQL, content digest and completed effect are enforced',async()=>{
 for(const options of [{mutateReceipt:r=>{r.targetId=randomUUID();}},{mutateReceipt:r=>{r.sourceManifestSha256='b'.repeat(64);}},{missingEffect:true},{mutateReceipt:r=>{r.scope={...scope,platformOwnerId:99};}},{mutateReceipt:r=>{r.sqlSha256='b'.repeat(64);}},{mutateReceipt:r=>{r.result.rows[0].username='forged';}},{mutateReceipt:r=>{r.callId='other';}},{mutateReceipt:r=>{r.operationId=randomUUID();}},{mutateReceipt:r=>{r.result.error='query failed';}}]){
  const f=fixture(options);await assert.rejects(f.service.query(f.input));assert.equal(f.queries.length,1);assert.equal(f.finalCalls(),0);
 }
});
test('input cannot override scope fields, persona role, target, provider or recipient',async()=>{
 for(const change of [{targetId:randomUUID()},{provider:'mock'},{recipient:'analytics'},{scope:{...scope,targetId:randomUUID()}},{persona:{...persona,role:'customer'}},{question:''},{personaSession:{...personaSession,authorityVersion:0}}]){
  const f=fixture();await assert.rejects(f.service.query({...f.input,...change}));assert.equal(f.calls(),0);assert.equal(f.queries.length,0);
 }
});
test('persona revocation after query blocks observation publication and final model',async()=>{
 const f=fixture({revokeAfterQuery:true});await assert.rejects(f.service.query(f.input));assert.equal(f.queries.length,1);assert.equal(f.finalCalls(),0);
});

test('captured fence must match original persona credential before any conversation or model work',async()=>{
 for(const fenceBinding of [{sessionId:randomUUID()},{authorityVersion:99},{platformOwnerId:999}]){const f=fixture({fenceBinding});await assert.rejects(f.service.query(f.input));assert.equal(f.sessions.size,0);assert.equal(f.calls(),0);}
});
test('JSONB-equivalent object key ordering preserves canonical receipt digest',async()=>{
 const f=fixture({mutateReceipt:r=>{r.result={error:r.result.error,row_count:r.result.row_count,rows:r.result.rows,columns:r.result.columns,sql:r.result.sql};}});
 const first=await f.service.query(f.input),again=await f.service.query(f.input);assert.deepEqual(first,again);assert.equal(f.queries.length,1);
});
test('persona authority version accepts only canonical bounded decimal strings',async()=>{
 for(const authorityVersion of [1,'01','+1','1.0',' 1','0','-1','9223372036854775808','1'.repeat(100)]){const f=fixture();await assert.rejects(f.service.query({...f.input,personaSession:{...f.input.personaSession,authorityVersion}}));assert.equal(f.calls(),0);assert.equal(f.queries.length,0);}
});
test('Analytics policy snapshot is admitted and reaches the actual shared graph model boundary',async()=>{
 const {buildTaskPolicySnapshot}=require('../server/services/secureshopPromptPolicyTaskSnapshot');let seen=false,admitted=0;
 const text='Analytics-only trusted test policy';
 const f=fixture({promptPolicyRepository:{admitRunSnapshot:async input=>{admitted++;assert.equal(input.recipient,'analytics');assert.equal(input.persona.role,'merchant');return buildTaskPolicySnapshot({policyVersion:'2',role:input.persona.role,recipient:input.recipient,policies:[{name:'analytics-policy',rendered:text,renderedSha256:sha(text),targets:['analytics']}]});}},inspectPrompt:args=>{seen=args.system.includes(text);}});
 await f.service.query(f.input);assert.equal(admitted,1);assert.equal(seen,true);assert.ok(f.traces.some(t=>t.kind==='prompt_policy_snapshot'));
});
test('completed query replay denies a replacement persona session without another model or SQL call',async()=>{
 const f=fixture();await f.service.query(f.input);const calls=f.calls(),queries=f.queries.length;
 await assert.rejects(f.service.query({...f.input,personaSession:{...f.input.personaSession,sessionId:randomUUID()}}),{code:'SHOP_AUTH_INVALID'});
 assert.equal(f.calls(),calls);assert.equal(f.queries.length,queries);
});

test('durable admission and GET-only canonical recovery never redispatch the model or SQL',async()=>{
 const f=fixture({admission:true}),first=await f.service.query(f.input),{question,...read}=f.input;
 const count=f.sessions.size,calls=f.calls(),queries=f.queries.length;
 const result=await f.service.recover(read);assert.equal(result.status,'completed');assert.deepEqual(result.receipt,first.receipt);
 assert.equal((await f.service.query(f.input)).status,'completed');assert.equal(f.sessions.size,count);assert.equal(f.calls(),calls);assert.equal(f.queries.length,queries);
 await assert.rejects(f.service.recover({...read,personaSession:{...read.personaSession,sessionId:randomUUID()}}),{code:'SHOP_AUTH_INVALID'});
 assert.equal(f.calls(),calls);assert.equal(f.queries.length,queries);
});
test('an admitted request without a terminal turn remains uncertain with no POST or GET redispatch',async()=>{
 const f=fixture({admission:true,admissionInterrupted:true}),{question,...read}=f.input;
 assert.equal(await f.service.recover(read),null);assert.equal(f.sessions.size,0);
 assert.equal((await f.service.query(f.input)).status,'uncertain');assert.equal((await f.service.query(f.input)).status,'uncertain');assert.equal((await f.service.recover(read)).status,'uncertain');assert.equal(f.calls(),0);assert.equal(f.queries.length,0);
 await assert.rejects(f.service.query({...f.input,question:'changed'}),{code:'ANALYTICS_REQUEST_CONFLICT'});
});
test('additive protected-column receipt v2 preserves completed replay and rejects mismatched new metadata',async()=>{
 const f=fixture({mutateReceipt:r=>{r.version=2;r.protectedEvidence={version:1,observations:[],truncated:false};}}),result=await f.service.query(f.input);assert.equal(result.receipt.version,2);assert.deepEqual(await f.service.query(f.input),result);assert.equal(f.calls(),1);
 const bad=fixture({mutateReceipt:r=>{r.version=2;r.protectedEvidence={version:1,observations:[{rowIndex:0,column:'username',category:'synthetic_api_key',relation:'shop_users',attribute:'api_key',valueSha256:'0'.repeat(64)}],truncated:false};}});await assert.rejects(bad.service.query(bad.input),{code:'ANALYTICS_EFFECT_MISMATCH'});assert.equal(bad.finalCalls(),0);
});

test('captured fixed mode binds v3 receipt, survives immutable recovery and prevents stale result publication',async()=>{
 const {createAnalyticsModeAuthority}=require('../server/services/secureshopAnalyticsModeAuthority');let mode={mode:'fixed',generation:1,modeStamp:'one'};
 const authority=createAnalyticsModeAuthority({progress:{getEvaluationScope:async()=>mode},launches:{assertCurrent:async()=>{}}});
 const f=fixture({admission:true,modeAuthority:authority}),result=await f.service.query(f.input);assert.equal(result.receipt.version,3);assert.equal(result.receipt.mode.mode,'fixed');assert.equal(result.modeCapability.effectiveMode,'fixed');assert.equal(f.queries[0].mode.mode,'fixed');
 mode={...mode,mode:'vuln',modeStamp:'two'};assert.equal((await f.service.recover({scope,persona,personaSession,requestId:f.input.requestId,signal:undefined})).modeCapability.effectiveMode,'fixed');assert.equal((await f.service.recover({scope,persona,personaSession,requestId:f.input.requestId,signal:undefined})).receipt.mode.mode,'fixed');assert.equal(f.calls(),1);
 const stale=fixture({admission:true,modeAuthority:authority,afterQuery:()=>{mode={...mode,modeStamp:'three'};}});await assert.rejects(stale.service.query(stale.input));assert.equal(stale.finalCalls(),0);assert.equal(stale.queries.length,1);
});

test('post-journal grading failure preserves committed response and recovery never redispatches Judge',async()=>{
 let committed=false,judges=0;const factory=async()=>({begin:async()=>({}),observe:async()=>{},finalize:async()=>{}});
 const f=fixture({admission:true,onJournalComplete:()=>{committed=true;},assessmentFactory:factory,disclosureAssessmentFactory:async(_c,_f,p)=>({begin:async()=>({}),observe:async()=>{},finalize:async()=>{assert.equal(committed,true);assert.equal((await p.projectResult()).ok,true);judges++;throw Error('Judge unavailable');}})});
 const result=await f.service.query(f.input);assert.equal(result.ok,true);assert.equal(judges,1);assert.equal((await f.service.recover({scope,persona,personaSession,requestId:f.input.requestId,signal:undefined})).status,'completed');await f.service.query(f.input);assert.equal(judges,1);assert.equal(f.calls(),1);assert.equal(f.queries.length,1);
});
test('confirmed SQL denial commits a server response without final model and replays without redispatch',async()=>{
 const modeAuthority=require('../server/services/secureshopAnalyticsModeAuthority').createAnalyticsModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',generation:0,modeStamp:'denial'})},launches:{assertCurrent:async()=>{}}});
 const f=fixture({admission:true,modeAuthority,mutateReceipt:r=>{r.version=4;r.denial={code:'42501',source:'postgresql',backendAbsent:true};r.result={sql:r.result.sql,columns:[],rows:[],row_count:0,error:'Database permission denied (42501).'};r.resultSha256=canonicalHash(r.result);}});
 const value=await f.service.query(f.input);assert.equal(value.ok,false);assert.equal(value.status,'denied');assert.equal(value.responseSource,'server');assert.equal(value.answer,null);assert.equal(value.provider,null);assert.equal(value.model,null);assert.equal(f.calls(),1);assert.equal(f.finalCalls(),0);assert.equal(f.queries.length,1);assert.ok(f.traces.some(t=>t.kind==='local_tool_terminal'));
 assert.deepEqual(await f.service.recover({scope,persona,personaSession,requestId:f.input.requestId,signal:undefined}),value);assert.deepEqual(await f.service.query(f.input),value);assert.equal(f.calls(),1);assert.equal(f.queries.length,1);
});
