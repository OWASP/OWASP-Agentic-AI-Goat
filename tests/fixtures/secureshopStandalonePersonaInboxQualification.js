'use strict';

// Test-only current-scene adapter. The caller owns the disposable stores,
// mounted standalone app, configured wire transport and physical browser.
const assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
const {createRenderedPersonaEvidence,runRenderedPersonaInbox}=require('./renderedSecureShopPersona');
const {bindInboxActual}=require('./secureshopMailRenderedQualification');
const {MODEL,DIGEST}=require('./dpiTechniqueActualTransport');
const IDS=Object.freeze(['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block']);
const sha=value=>createHash('sha256').update(value).digest('hex');
const clone=value=>require('node:v8').deserialize(require('node:v8').serialize(value));

// The default Judge must construct its own configured provider to retain its
// private production proof. Observe only its unchanged local HTTP envelope.
function observeConfiguredPersonaJudge({transport,assertPhase,isActor}){
  const previousFetch=global.fetch,keys=['JUDGE_PROVIDER','JUDGE_MODEL','OLLAMA_BASE_URL'];
  const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  const endpoint=new URL('/api/chat',transport.url).href;
  const observed=async(url,options={})=>{
    if(String(url)===endpoint&&!isActor()){
      assertPhase();assert.equal(options.method,'POST');assert.equal(typeof options.body,'string');
      const value=JSON.parse(options.body);assert.equal(value.model,MODEL);assert.equal(value.stream,true);
      assert.deepEqual(Object.keys(value).sort(),['format','messages','model','options','stream']);
      transport.expect('judge',{messages:value.messages,tools:[],options:{...value.options,format:value.format,signal:options.signal}});
    }
    return previousFetch(url,options);
  };
  process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=MODEL;process.env.OLLAMA_BASE_URL=transport.url;
  global.fetch=observed;let closed=false;
  return ()=>{if(closed)return;closed=true;assert.equal(global.fetch,observed);global.fetch=previousFetch;
    for(const key of keys)if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];};
}

function createPersonaRecorder({transport,record}){
  assert.equal(transport.model,MODEL);assert.equal(typeof record,'function');
  const retained={version:1,cases:[],transcripts:[],providerCalls:[],actorInvocations:[],snapshots:[]};
  let phase=null,actorPending=0;const save=()=>record(clone(retained));
  const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({model:MODEL,baseUrl:transport.url});
  const chat=provider.transport.chat.bind(provider.transport);
  provider.transport.chat=async(messages,tools,options)=>{
    assert(phase,'Actor inference outside physical read');
    const num_ctx=require('../../server/agent-runtime/providers/langchainProvider').ollamaContextWindow(options);
    transport.expect('actor',{messages,tools,options:{...options,num_ctx}});
    const row={role:'actor',phase,wireIndex:transport.snapshot().calls.length,messages:clone(messages),tools:clone(tools),
      options:{temperature:options.temperature,num_predict:options.num_predict,format:clone(options.format)}};
    retained.providerCalls.push(row);save();actorPending++;
    try{row.result=await chat(messages,tools,options);return row.result;}finally{actorPending--;save();}
  };
  for(const method of ['chat','finalResponse']){const original=provider[method].bind(provider);provider[method]=async input=>{
    assert(phase);const row={phase,method,input:{system:input.system,messages:clone(input.messages),...(input.tools?{tools:clone(input.tools)}:{})},wireStart:transport.snapshot().calls.length};
    retained.actorInvocations.push(row);save();try{row.result=await original(input);return row.result;}
    finally{row.wireEnd=transport.snapshot().calls.length;save();}
  };}
  const close=observeConfiguredPersonaJudge({transport,assertPhase:()=>assert(phase,'Judge inference outside physical read'),isActor:()=>actorPending>0});
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
    observeExecutionTranscript:row=>{retained.transcripts.push(row);save();}});
  return Object.freeze({provider,judge,transport,
    begin(name){assert.equal(phase,null);assert.equal(name,['advisory','enforced'][retained.cases.length]);transport.beginCase(name);phase=name;},
    complete(value){assert.equal(value.name,phase);retained.cases.push(clone(value));transport.endCase();phase=null;save();},
    scope(value){retained.scope=clone(value);save();},snapshot:()=>clone(retained),close,
    retain(label,value){retained.snapshots.push({label,value:clone(value)});save();},
  });
}

function assertRegisteredPersonaJudgment(row,subject){
  const b=subject.binding,e=row.execution_json;
  assert.equal(row.tenant_id,subject.tenantId);assert.equal(row.principal_id,subject.principalId);
  assert.equal(row.shop_user_id,b.shopUserId);assert(IDS.includes(row.objective_id));
  assert.deepEqual(e.scope,createLaunchScope(b));assert.equal(e.tenantId,subject.tenantId);
  assert.equal(e.principalId,subject.principalId);assert.equal(e.shopUserId,b.shopUserId);assert.equal(e.role,b.role);
  assert.equal(e.personaSessionId,subject.personaSessionId);assert.equal(e.personaAuthorityVersion,subject.personaAuthorityVersion);
  assert.equal(e.runId,row.run_id);assert.equal(e.ownerKey,row.owner_key);assert.equal(String(e.ownerGeneration),String(row.owner_generation));
  assert.equal(sha(row.packet),row.evidence_digest);assert.equal(sha(row.result_serialized),row.result_digest);
  assert.deepEqual(JSON.parse(row.result_serialized),row.result_json);
  if(row.judge_result_json){assert.equal(row.judge_observations?.version,1);
    assert.equal(row.judge_observations.runId,row.run_id);assert.equal(row.judge_observations.evidenceDigest,row.evidence_digest);
    assert.equal(sha(row.judge_result_json),row.judge_observations.resultSha256);
  }
  if(row.verdict==='pass'){
    assert.equal(row.credited,row.evaluation_id);assert(['awarded','already_complete'].includes(row.disposition));
    assert.equal(row.result_json.provider,'ollama');assert.equal(row.result_json.model,MODEL);
    assert(row.judge_observations.calls.some(call=>call.provider==='ollama'&&call.model===MODEL));
  }
  return row;
}

function createStandalonePersonaEvidence({identity,agents,subject,mailScenes,inboxRepository,record}){
  const scope=createLaunchScope(subject.binding);
  const readJudgments=async()=>{
    const rows=(await identity.query(`SELECT j.*,c.evaluation_id AS credited FROM secureshop_auth.assessment_judgments j
      LEFT JOIN secureshop_auth.active_assessment_contributions c USING(tenant_id,principal_id,evaluation_id)
      WHERE j.tenant_id=$1 AND j.principal_id=$2 AND j.execution_json->'scope'->>'launchId'=$3
        AND j.execution_json->'scope'->>'generation'=$4 AND j.objective_id=ANY($5::text[])
      ORDER BY j.created_at,j.evaluation_id`,[subject.tenantId,subject.principalId,scope.launchId,String(scope.generation),IDS])).rows;
    rows.forEach(row=>assertRegisteredPersonaJudgment(row,subject));return rows;
  };
  const projectedIdentity={async query(sql,args){
    if(sql.includes('FROM workshop_platform.objective_judgments j')){
      assert.deepEqual(args,[scope.platformOwnerId,'secureshop_agent_security',scope.launchId,scope.generation,IDS]);
      return {rows:await readJudgments()};
    }
    assert(!sql.includes('workshop_platform.'),'Registered qualification cannot substitute workshop credit');
    return identity.query(sql,args);
  }};
  const evidence=createRenderedPersonaEvidence({identityRuntime:projectedIdentity,agentsRuntime:agents,binding:subject.binding,
    readTarget:()=>mailScenes.readRetained(scope),async readAccessEvent(target,id){
      const source=await inboxRepository.readAccessEvent(target,id);record({source:clone(source)});return source;
    }});
  const snapshot=async()=>{
    const judgments=await readJudgments();
    const traces=(await agents.query(`SELECT t.* FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s
      ON s.id=t.session_id WHERE s.platform_launch_id=$1 AND s.original_platform_owner_id=$2 ORDER BY t.id`,[scope.launchId,scope.platformOwnerId])).rows;
    const accesses=(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1 ORDER BY event_id',[subject.targetId])).rows;
    const messages=(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_messages WHERE target_id=$1 ORDER BY message_id',[subject.targetId])).rows;
    const acls=(await agents.query('SELECT * FROM secureshop_agents.persona_inbox_acl_versions WHERE target_id=$1 ORDER BY version',[subject.targetId])).rows;
    const runIds=[...new Set(judgments.map(row=>row.run_id))];
    const effects=(await identity.query('SELECT * FROM graph_runtime.effects WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,effect_key',[runIds])).rows;
    const original={judgments,traces,accesses,messages,acls,effects};record(clone(original));
    // Field aliases adapt the old verifier only after exact registered authority
    // validation. Original rows remain separately retained, unchanged.
    return {...original,judgments:judgments.map(row=>({...row,user_id:scope.platformOwnerId})),
      packets:judgments.map(row=>({...row,user_id:scope.platformOwnerId})),
      contributions:judgments.filter(row=>row.credited).map(row=>({evaluation_id:row.evaluation_id,objective_id:row.objective_id}))};
  };
  return Object.freeze({...evidence,readJudgments,snapshotFull:snapshot});
}

async function physicalPersonaControl(frame,subject,control=subject===undefined?'enforce':'read'){
  assert(['read','enforce','refresh'].includes(control));
  await frame.waitForFunction(({subject,control})=>{
    const section=document.querySelector('section[aria-labelledby="persona-inbox-lab-title"]');if(!section)return false;
    let button;
    if(control!=='read')button=[...section.querySelectorAll('button')].find(b=>b.textContent.trim()===(control==='enforce'?'Enforce ACL':'Refresh'));
    else {const labels=[...section.querySelectorAll('strong')].filter(e=>e.textContent===subject);
      if(labels.length!==1)return false;button=labels[0].parentElement.parentElement.querySelector('button');}
    if(!button||button.disabled||!button.getClientRects().length)return false;
    button.scrollIntoView({block:'center',behavior:'instant'});const r=button.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
    if(hit!==button&&!button.contains(hit))return false;button.setAttribute('data-c31-control','active');return true;
  },{timeout:20000,polling:'mutation'},{subject,control});
  try{await frame.click('[data-c31-control="active"]');}
  finally{await frame.evaluate(()=>document.querySelector('[data-c31-control="active"]')?.removeAttribute('data-c31-control'));}
}

async function qualifyStandalonePersonaInbox({page,frame,origin,subject,message,observe,recorder,api,resetOwner,record,screenshot}){
  assert.equal(new URL(origin).hostname,'127.0.0.1');assert.equal(typeof record,'function');
  const requestFrame=page.mainFrame(),posts=[];const requests=request=>{
    if(request.frame()!==requestFrame||request.method()!=='POST')return;const url=new URL(request.url());
    if(url.origin===origin&&url.pathname.startsWith('/api/secureshop/v2/persona-inbox/'))posts.push(request);
  };page.on('request',requests);
  const baseline=await observe.snapshotFull(),siblingBefore=await api.siblingSnapshot();
  assert(siblingBefore.messages.length>0,'Sibling must have real durable messages');
  const siblingReady=await api.siblingReadiness();assert.equal(siblingReady.status,200);
  assert.equal(siblingReady.value.ready,true);assert.equal(siblingReady.value.acl.mode,'advisory');
  assert(siblingReady.value.messages.every(row=>row.messageId!==message.messageId));
  recorder.scope({ownerId:subject.binding.platformOwnerId,platformSessionId:subject.binding.platformSessionId,
    launchId:subject.binding.launchId,generation:subject.binding.generation,persona:{id:subject.binding.shopUserId,role:subject.binding.role},messageId:message.messageId});
  let phaseIndex=0;
  const evidence={...observe,async snapshot(){const name=['advisory','enforced'][phaseIndex];recorder.begin(name);return observe.snapshot();},
    async verify(input){const verified=await observe.verify(input),snapshot=await observe.snapshotFull();
      recorder.complete({name:input.mode,requestId:input.requestId,response:{status:200,body:input.response},snapshot,verified});phaseIndex++;return verified;}};
  const boundPage={waitForResponse(predicate,options){return page.waitForResponse(response=>
    response.request().frame()===requestFrame&&predicate(response),options);}};
  try{
    const readsBefore=recorder.transport.snapshot().calls.length;
    const refreshResponse=page.waitForResponse(response=>response.request().frame()===requestFrame
      &&response.request().method()==='GET'&&new URL(response.url()).origin===origin
      &&new URL(response.url()).pathname==='/api/secureshop/v2/persona-inbox/readiness',{timeout:20000});
    refreshResponse.catch(()=>{});await physicalPersonaControl(frame,undefined,'refresh');
    const refreshed=await refreshResponse;assert.equal(refreshed.status(),200);
    assert.equal((await refreshed.json()).acl.mode,'advisory');
    assert.equal(recorder.transport.snapshot().calls.length,readsBefore);
    assert.deepEqual(await observe.snapshotFull(),baseline,'Readiness must not execute a read or Judge');
    const result=await runRenderedPersonaInbox({page:boundPage,frame,origin,evidence,
      messageId:message.messageId,subject:message.subject,timeoutMs:300000,
      clickRead:selected=>physicalPersonaControl(frame,selected),
      clickEnforce:async()=>{await screenshot('advisory');await physicalPersonaControl(frame);}});
    assert.equal(posts.length,3);assert.deepEqual(posts.map(r=>new URL(r.url()).pathname.split('/').at(-1)),['read','enforce','read']);
    for(const [index,request]of posts.entries()){
      const body=JSON.parse(request.postData());if(index===1)assert.deepEqual(body,{});
      else{assert.deepEqual(Object.keys(body).sort(),['message_id','request_id']);assert.equal(body.message_id,message.messageId);
        assert.equal(body.request_id,result.results[index===0?0:1].requestId);}
    }
    assert.notEqual(result.results[0].requestId,result.results[1].requestId);
    await screenshot('enforced');const after=await observe.snapshotFull();
    const calls=recorder.transport.snapshot().calls.length;
    const replay=await api.read({request_id:result.results[1].requestId,message_id:message.messageId});
    assert.equal(replay.status,200);assert.equal(replay.value.replayed,true);
    assert.deepEqual(replay.value.accesses,recorder.snapshot().cases[1].response.body.accesses);
    const saved=await api.savedAssessments();assert.equal(saved.status,200);
    for(const row of after.judgments.filter(row=>row.credited))assert(saved.value.judgments.some(j=>j.evaluationId===row.evaluation_id));
    assert.deepEqual(await observe.snapshotFull(),after);assert.equal(recorder.transport.snapshot().calls.length,calls);
    await api.reloadEnforced();assert.deepEqual(await observe.snapshotFull(),after);
    const current=await api.readiness();assert.equal(current.status,200);assert.equal(current.value.ready,true);
    assert.equal(current.value.acl.mode,'enforced');
    assert.equal(recorder.transport.snapshot().calls.length,calls,'Reload must not replay either model read');
    const peer=await api.read({request_id:randomUUID(),message_id:message.messageId},'sibling');
    assert.equal(peer.status,400);assert.deepEqual(peer.value,{error:'Invalid persona inbox request'});
    assert.deepEqual(await api.siblingSnapshot(),siblingBefore);
    const wire=recorder.transport.snapshot();assert.equal(wire.model,MODEL);assert.equal(wire.digest,DIGEST);
    const qualified=bindInboxActual(recorder.snapshot(),wire);assert.equal(qualified.qualification,'qualified');assert.equal(qualified.genuineCredit,3);
    const reset=await resetOwner();assert.equal(reset.status,'committed');
    const stale=await api.read({request_id:result.results[1].requestId,message_id:message.messageId});
    assert.equal(stale.status,401);assert.deepEqual(stale.value,{error:'Shop authentication required'});
    assert.equal(stale.launchState,null);
    await api.assertResetPreserved(after,reset);assert.deepEqual(await api.siblingSnapshot(),siblingBefore);
    assert.equal(recorder.transport.snapshot().calls.length,calls);
    record({result,qualified,reset,baseline,after,siblingBefore,posts:posts.map(request=>({path:new URL(request.url()).pathname,body:JSON.parse(request.postData())}))});
    return {...qualified,actualQualification:false,scope:'C31 standalone rendered Persona Inbox; caller must verify physical cleanup',resetVerified:true,siblingVerified:true};
  }finally{page.off('request',requests);}
}
module.exports={IDS,MODEL,DIGEST,observeConfiguredPersonaJudge,createPersonaRecorder,assertRegisteredPersonaJudgment,createStandalonePersonaEvidence,
  physicalPersonaControl,qualifyStandalonePersonaInbox};
