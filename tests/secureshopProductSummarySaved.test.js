'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createSecureShopBoundProductAssist}=require('../server/services/secureshopBoundProductAssist');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {SECURESHOP_CONVERSATION_PURPOSES:P}=require('../server/services/secureshopConversationPurpose');

// Controlled in-memory stores/providers exercise the real graph and admission
// code. These tests produce no actual model, PostgreSQL, browser or credit proof.
function fixture({capture,afterCommit,readHook,observation,chatHook,toolHook,fixedFactory=false}={}) {
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:12,platformSessionId:13};
  const persona={id:1000000012,role:'customer'},personaSession={sessionId:randomUUID(),authorityVersion:'2'};
  let target=createSceneBinding({...scope,generation:1,targetId:randomUUID()},
    {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:fn=>fn()});
  const sessions=new Map(),messages=new Map(),requests=new Map(),runs=new Map(),callbackRuns=[];
  const counts={actor:0,tools:0,catalog:0,sceneReads:0,claims:0,commits:0,postCommit:0};
  let mode='vuln',revision=1,current=true;
  const check=async()=>{if(!current)throw Object.assign(Error('Authority revoked'),{code:'SHOP_AUTH_INVALID'});};
  const repository={
    async getBoundSession(id){return sessions.get(id)||null;},
    async acquireBoundSession({id,binding,purpose}){const old=[...sessions.values()].find(s=>equal(s.binding,binding)&&s.purpose===purpose);if(old)return old;
      const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},
    async activateBoundSession(id){sessions.get(id).state='active';return true;},
    async getMessages(id){return structuredClone(messages.get(id)||[]);},
    async appendMessage(id,_binding,message){messages.set(id,[...(messages.get(id)||[]),structuredClone(message)]);},
    async appendTraces(){},async getTokens(){return 0;},async addTokens(){}
  };
  const key=x=>JSON.stringify([x.sessionId,x.requestId]);
  const journal={
    async claim(input){counts.claims++;const hash=createTurnRequest(input).hash,old=requests.get(key(input));
      if(old){if(old.request_hash!==hash)throw Object.assign(Error('Request conflict'),{code:'TURN_REQUEST_CONFLICT'});
        return old.status==='completed'?{status:'completed',result:structuredClone(old.result_json)}:{status:old.status,claimId:old.claimId};}
      const claimId=randomUUID();requests.set(key(input),{session_id:input.sessionId,request_id:input.requestId,
        request_version:1,request_hash:hash,status:'started',claimId,binding:input.binding});return {status:'claimed',claimId};},
    async complete(input){counts.commits++;const row=requests.get(key(input));row.status='completed';row.result_json=structuredClone(input.result);},
    async markUncertain(input){const row=requests.get(key(input));if(row?.status==='started')row.status='uncertain';},
    async readBoundRequest(input){assert.equal(input.purpose,P.productAssist);await readHook?.();
      const row=requests.get(key(input));if(!row)return null;if(!equal(row.binding,input.binding))throw Error('Foreign row');return structuredClone(row);}
  };
  const tokens=new WeakSet();
  const modeAuthority={async capture(input){const generation=revision,selectedMode=mode;const token={snapshot:{version:1,featureId:'product_assist',
    policyVersion:'bounded-product-data-and-catalog-neighbors-v1',mode,generation,modeStamp:String(revision).repeat(64),scope:input},
    async assertCurrent(){if(revision!==generation||mode!==selectedMode)throw Object.assign(Error('Mode changed'),{code:'SECURESHOP_FEATURE_MODE_STALE'});}};tokens.add(token);return token;},
    assertToken(token){assert.ok(tokens.has(token));return token;}};
  const personaAuthority={async capture(input){await check();return {binding:{...input.scope,personaId:input.personaId,role:input.role,
    sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check,
    withCrossStoreEffect:async fn=>{await check();return fn();},withPersonaEffect:async fn=>{await check();return fn();}};}};
  const coordinator={async run(owner,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;
    const runId=randomUUID();runs.set(runId,{status:'running'});
    try { const result=await work({runId,ownerKey:JSON.stringify(['SecureShopBoundConversation',owner]),generation:0,durableGeneration:'0',signal:options.signal,
      check,async effect(_key,fn){return fn();},async trace(){}});runs.get(runId).status='completed';return result; }
    catch(error){runs.get(runId).status='failed';throw error;}}};
  const value=observation||{product_id:7,name:'Owned',price:10,category:'Home',stock_quantity:1,description:'Untrusted product source',description_html:'<b>Original</b>'};
  const provider={async chat(){counts.actor++;await chatHook?.();return {provider:'ollama',model:'controlled-test',mocked:false,stop_reason:'tool_use',
    tool_uses:[{id:'original-call',name:'summarizer.summarize_product',args:{product_id:7}}],usage:{input_tokens:0,output_tokens:0}};},
    async finalResponse(){counts.actor++;return {provider:'ollama',model:'controlled-test',mocked:false,text:'Observed original summary.',stop_reason:'end_turn',responseMode:'structured_final',usage:{input_tokens:0,output_tokens:0}};}};
  const assist=createSecureShopBoundProductAssist({launches:{assertCurrent:check},conversationRepository:repository,journal,coordinator,
    provider,personaAuthority,modeAuthority,catalog:{async getProduct(input){counts.catalog++;return input.productId===7?{product:{id:7}}:null;}},
    scenes:{async readRetained(){counts.sceneReads++;await check();return target;}},
    afterSummaryCommit:async packet=>{counts.postCommit++;callbackRuns.push(runs.get(packet.execution.runId)?.status);
      assert.equal(requests.get(key(packet)).status,'completed');assert.equal(runs.get(packet.execution.runId)?.status,'completed');await afterCommit?.(packet);},
    async createProductTools(input){
      if(fixedFactory){const {createSecureShopBoundProductTools}=require('../server/services/secureshopBoundProductTools');
        const seed={id:7,name:'Owned',price:10,stock_quantity:1,category:'Home',description:'Owned catalog'};
        return createSecureShopBoundProductTools({...input,catalog:{async getProduct(){return {product:seed};},
          async listProducts(){return {products:[seed],total:1};}},retrieval:{async similar(){throw Error('Fixed must not retrieve');}}});}
      return new Map([['summarizer.summarize_product',async()=>{counts.tools++;await toolHook?.();

      return {content:[{type:'text',text:JSON.stringify(value)}]};}]]);}
  });
  const base={scope,persona,personaSession,productId:7};
  return {assist,base,counts,requests,runs,callbackRuns,key,value,async input(){return {...base,...await assist.createSummarySession(base),requestId:randomUUID()};},
    setMode(next='fixed'){mode=next;revision++;},revoke(){current=false;},switchScene(){target=createSceneBinding({...scope,generation:1,targetId:randomUUID()},
      {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:fn=>fn()});}};
}

test('summary retains original hop; saved read and exact replay add no model, tool, commit or assessment',async()=>{
  const f=fixture(),input=await f.input();
  assert.equal(f.counts.actor,0);
  assert.equal((await f.assist.readSummary(input)).status,'not_found');
  const result=await f.assist.runSummary(input);
  assert.equal(result.summary,'Observed original summary.');assert.equal(result.sessionId,input.sessionId);
  assert.equal(f.counts.actor,2);assert.equal(f.counts.tools,1);assert.equal(f.counts.postCommit,1);
  assert.deepEqual(f.callbackRuns,['completed']);
  const before={...f.counts};
  assert.deepEqual(await f.assist.readSummary(input),{status:'completed',result});
  assert.deepEqual(await f.assist.runSummary(input),result);
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});
test('summary rejects foreign owner/session/product, changed original hash and changed hop bytes',async()=>{
  const f=fixture(),input=await f.input();await f.assist.runSummary(input);
  for(const patch of [{persona:{id:17,role:'customer'}},{productId:8},{sessionId:randomUUID()},
    {personaSession:{...input.personaSession,sessionId:randomUUID()}},
    {personaSession:{...input.personaSession,authorityVersion:'3'}}])await assert.rejects(f.assist.readSummary({...input,...patch}));
  const row=f.requests.get(f.key(input)),original=structuredClone(row);
  row.request_hash='a'.repeat(64);await assert.rejects(f.assist.readSummary(input));
  Object.assign(row,structuredClone(original));row.result_json.hops[0].result.content[0].text+=' ';
  await assert.rejects(f.assist.readSummary(input));assert.equal(f.counts.actor,2);assert.equal(f.counts.tools,1);
});
test('summary refuses mode/reset/scene changes and a revocation crossing saved read',async()=>{
  for(const change of ['setMode','switchScene','revoke']){const f=fixture(),input=await f.input();await f.assist.runSummary(input);f[change]();await assert.rejects(f.assist.readSummary(input));}
  let release,started;const ready=new Promise(resolve=>{started=resolve;});
  const f=fixture({readHook:()=>{started();return new Promise(resolve=>{release=resolve;});}}),input=await f.input();
  await f.assist.runSummary(input);const reading=f.assist.readSummary(input);await ready;f.revoke();release();await assert.rejects(reading);
});
test('summary assessment failure preserves genuine original result, without replaying assessment',async()=>{
  const f=fixture({afterCommit:()=>{throw Error('Judge unavailable');}}),input=await f.input();
  const result=await f.assist.runSummary(input);assert.equal(result.summary,'Observed original summary.');
  assert.deepEqual((await f.assist.readSummary(input)).result,result);assert.equal(f.counts.postCommit,1);
});
test('summary pending and uncertain recovery does not dispatch work',async()=>{
  const f=fixture(),input=await f.input();await f.assist.runSummary(input);const before={...f.counts};
  for(const status of ['started','uncertain']){f.requests.get(f.key(input)).status=status;assert.equal((await f.assist.readSummary(input)).status,'pending');}
  for(const name of ['actor','tools','commits','postCommit'])assert.equal(f.counts[name],before[name]);
});

test('summary recovery key is stable across admission and scopes mode revisions, persona sessions and product',async()=>{
 const f=fixture(),first=await f.assist.createSummarySession(f.base),second=await f.assist.createSummarySession(f.base);
 assert.deepEqual(second,first);assert.match(first.recoveryKey,/^[a-f0-9]{64}$/);assert.equal(f.counts.actor,0);assert.equal(f.counts.tools,0);
 f.setMode('fixed');const fixed=await f.assist.createSummarySession(f.base);
 f.setMode('vuln');const back=await f.assist.createSummarySession(f.base);
 const changed=await f.assist.createSummarySession({...f.base,personaSession:{sessionId:randomUUID(),authorityVersion:'3'}});
 assert.equal(new Set([first.recoveryKey,fixed.recoveryKey,back.recoveryKey,changed.recoveryKey]).size,4);
 assert.equal(new Set([first.sessionId,fixed.sessionId,back.sessionId,changed.sessionId]).size,1);
 assert.equal(f.counts.actor,0);assert.equal(f.counts.tools,0);
});
