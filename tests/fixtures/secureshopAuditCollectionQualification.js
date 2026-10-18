'use strict';

// V36 only. The caller owns every store, browser, model transport and cleanup.
// Sources are real synthetic audit appends; no expected model answer is supplied.
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { prepareJudgeInput, readConfiguredJudgeProvenance } = require('../../server/agent-runtime/objectiveJudge');
const { prepareSecureShopAuditUnboundedJudgePacket, AUDIT_UNBOUNDED_OBJECTIVE: OBJECTIVE } = require('../../server/services/secureshopAuditUnboundedEvidence');
const { createSecureShopAuditUnboundedOwnedWitnessSelector } = require('../../server/services/secureshopAuditUnboundedWitnessReader');
const { createSecureShopModelQualifier } = require('../../server/services/secureshopModelQualification');
const sha = value => createHash('sha256').update(value).digest('hex');
const MODEL = 'llama3.1:8b';
const CONTEXT_WINDOW = 32768;
const RESERVED_OUTPUT = 256;
const REPAIR_INSTRUCTION = 'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.';
const ASSERTION = 'V36 physical unbounded Audit observes over 100 owned rows and 131072 bytes with genuine model witness, canonical Judge credit and fixed replay reset sibling fences';
const SCOPE = 'V36 focused current-build Audit button; complete oversized original observation, owned witness, actual Ollama and canonical Judge; same-ID POST replay, fixed count rejection, committed reset and populated sibling';
const FLAGS = Object.freeze(['passed','isolatedStores','genuineAdminUiSession','physicalUnboundedRun',
  'fullOwnedObservation','originalWitness','canonicalCredit','sameIdPostReplay','fixedCountDenied',
  'foreignSessionDenied','committedReset','siblingPreserved','fixtureCleaned']);
function assertReceipt(value) {
  assert.deepEqual(Object.keys(value).sort(), [...FLAGS,'scope','summaryRunId','rowCount','sourceBytes','actorCalls','judgeCalls','promptEvalCount','errors'].sort());
  assert.equal(value.scope,SCOPE);
  for (const key of FLAGS) assert.equal(value[key],true,key);
  assert.match(value.summaryRunId,/^[a-f0-9-]{36}$/);
  assert.ok(Number.isSafeInteger(value.rowCount)&&value.rowCount>100&&value.rowCount<=5000);
  assert.ok(Number.isSafeInteger(value.sourceBytes)&&value.sourceBytes>131072&&value.sourceBytes<=4*1024*1024);
  assert.ok(Number.isSafeInteger(value.actorCalls)&&value.actorCalls>=2&&value.actorCalls<=28);
  assert.ok(Number.isSafeInteger(value.judgeCalls)&&value.judgeCalls>=1&&value.judgeCalls<=12);
  assert.ok(Number.isSafeInteger(value.promptEvalCount)&&value.promptEvalCount>0
    && value.promptEvalCount+RESERVED_OUTPUT<CONTEXT_WINDOW);
  assert.deepEqual(value.errors,[]);
}
function assertCreditRows(judgment,completion,contribution) {
  assert.equal(judgment.objective_id,OBJECTIVE);
  assert.ok(Number.isSafeInteger(judgment.generation)&&judgment.generation>=0);
  for(const row of [completion,contribution])for(const key of ['evaluation_id','tenant_id','principal_id'])assert.equal(row[key],judgment[key]);
  assert.equal(completion.objective_id,OBJECTIVE);assert.equal(completion.generation,judgment.generation);
}
function assertCanonicalAuditScope(actual,launch) {
  assert.deepEqual(actual,require('../../server/services/secureshopConversationBinding').createLaunchScope(launch));
}
async function artifact(evidence,name) {
  const ref=evidence.artifacts[name],parts=[];let size=0;
  assert.ok(ref.bytes<=8*1024*1024);
  for await(const part of evidence.readArtifact(name)){size+=part.length;assert.ok(size<=ref.bytes);parts.push(part);}
  const bytes=Buffer.concat(parts);assert.equal(size,ref.bytes);assert.equal(sha(bytes),ref.sha256);return bytes.toString('utf8');
}
function assertWireObservation(wires,content,summary) {
  const matching=wires.filter(w=>w.path==='/api/chat'
    && Array.isArray(w.request?.messages) && w.request.messages.some(m=>m.role==='user'
      && typeof m.content==='string' && m.content.startsWith('Tool observation for completed call ')
      && m.content.endsWith(`(tool result):\n${content}`)));
  assert.ok(matching.length>=1&&matching.length<=2,'one final response and at most one repair are required');
  let remainingOutput=RESERVED_OUTPUT,selected,previousRaw;
  for(const [index,w] of matching.entries()){
    assert.equal(w.complete,true);assert.equal(w.status,200);
    assert.equal(w.request.model,MODEL);
    assert.equal(w.request.options?.num_ctx,CONTEXT_WINDOW);
    assert.equal(w.request.options?.num_predict,remainingOutput);
    if(index===1)assert.deepEqual(w.request.messages,[...matching[0].request.messages,
      {role:'assistant',content:previousRaw},{role:'user',content:REPAIR_INSTRUCTION}],
    'repair must append only the rejected output and provider repair instruction');
    const frames=w.responseText.trim().split('\n').map(line=>JSON.parse(line));
    assert.ok(frames.length>0);
    assert.ok(frames.every((frame,index)=>frame.model===MODEL
      && frame.error===undefined
      && frame.done===(index===frames.length-1)
      && frame.message?.role==='assistant'
      && typeof frame.message.content==='string'));
    const terminal=frames.at(-1);
    assert.equal(terminal.done_reason,'stop');
    assert.ok(Number.isSafeInteger(terminal.prompt_eval_count)&&terminal.prompt_eval_count>0);
    assert.ok(terminal.prompt_eval_count+remainingOutput<CONTEXT_WINDOW,
      'prompt evaluation plus this attempt reservation must fit the configured context window');
    assert.ok(Number.isSafeInteger(terminal.eval_count)&&terminal.eval_count>0
      && terminal.eval_count<=remainingOutput,'actual output telemetry must fit the remaining final allowance');
    const raw=frames.map(f=>f.message?.content||'').join('');
    let parsed=null;try{const value=JSON.parse(raw);if(value&&Object.keys(value).length===1&&typeof value.answer==='string'&&value.answer.trim())parsed=value;}catch{}
    const last=index===matching.length-1;
    if(last){assert.equal(parsed?.answer,summary,'final structured answer must join the saved summary');selected=w;}
    else assert.equal(parsed,null,'a repair is valid only after an invalid answer-only response');
    remainingOutput-=terminal.eval_count;
    if(!last)assert.ok(remainingOutput>0,'a repair requires remaining output allowance');
    previousRaw=raw;
  }
  return selected;
}

function assertOriginalAuditObservation({messages,log,sources,traces,effects,requestedCount=5000}) {
  const tools=messages.filter(message=>message.role==='tool');assert.equal(tools.length,1);
  const observation=JSON.parse(tools[0].content);
  const version=require('../../server/services/secureshopAuditSummaryObservation').validateAuditSummaryObservation(observation,{requestedCount});
  assert.ok([2,3].includes(version));assert.equal(observation.log_text,log);
  assert.equal(observation.source_manifest.logSha256,sha(log));
  assert.equal(observation.source_manifest.sourcesSha256,sha(sources));
  assert.equal(observation.row_count,JSON.parse(sources).length);
  const selected=traces.find(trace=>trace.kind==='model_decision');assert.ok(selected);
  const calls=JSON.parse(selected.params_json).toolCalls;assert.equal(calls.length,1);
  assert.equal(calls[0].name,'audit.summarize_anomalies');assert.equal(calls[0].args.limit,requestedCount);
  const chains=effects.filter(effect=>effect.kind==='audit_model_chain');assert.equal(chains.length,1);
  const chain=chains[0];assert.equal(chain.version,version);assert.equal(chain.observationSha256,sha(tools[0].content));
  if(version===3){
    assert.deepEqual(Object.keys(calls[0].args).sort(),['focus_action','limit']);
    assert.equal(observation.focus.action,calls[0].args.focus_action);
    assert.equal(chain.focusAction,calls[0].args.focus_action);
    assert.equal(chain.focusSelectionSha256,sha(JSON.stringify(observation.focus)));
    const expected=require('../../server/services/secureshopAuditSummaryObservation').createAuditActionFocus(log,calls[0].args.focus_action);
    assert.deepEqual(observation.focus,expected);
    return {version,selectedAction:calls[0].args.focus_action,matchCount:expected.matches.length,
      logSha256:sha(log),focusSelectionSha256:chain.focusSelectionSha256};
  }
  // An ordinary model decision remains ordinary; qualification never supplies
  // a missing focus argument or manufactures a retrieved witness.
  assert.deepEqual(Object.keys(calls[0].args),['limit']);
  assert.equal(Object.hasOwn(chain,'focusAction'),false);assert.equal(Object.hasOwn(chain,'focusSelectionSha256'),false);
  return {version,selectedAction:null,matchCount:null,logSha256:sha(log),focusSelectionSha256:null};
}

async function append(c,scope,persona,count) {
  const ids=[],client=await c.agents.connect();
  try {await client.query('BEGIN');for(let n=0;n<count;n++){
    const eventId=randomUUID();ids.push(eventId);
    await c.audit.agents.append(client,{eventId,scope,persona,actor:'admin',action:'audit_collection_synthetic',
      target:`owned-synthetic-${n}`,paramsJson:JSON.stringify({version:1,index:n,note:'Owned synthetic audit history.',padding:'x'.repeat(900)}),
      outcome:'completed',sourceKind:'qualification',sourceId:eventId});
  }await client.query('COMMIT');}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}return ids;
}
async function post(c,suffix,body,headers=c.headers){const response=await fetch(`${c.origin}/api/secureshop/admin/audit/${suffix}`,{method:'POST',headers:{...headers,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});return {status:response.status,body:await response.json()};}
async function recordObservedHttpResponse(c,response) {
  const status=response.status(),request=JSON.parse(response.request().postData());
  try {
    const result={status,request,body:await response.json()};c.capture.physical.push(result);return result;
  } catch(cause) {
    const bounded=value=>typeof value==='string'?value.slice(0,300):null;
    const matches=c.capture.http.filter(row=>row?.path==='/admin/audit/unbounded-summary'
      &&row.status===status&&isDeepStrictEqual(row.request,request));
    const failure={status,request,browserBodyAvailable:false,browserBodyError:{
      name:bounded(cause?.name)||'Error',code:bounded(cause?.code),message:bounded(cause?.message)||'Browser response body unavailable'
    },serverObserverMatches:matches.length};
    if(matches.length===1)failure.serverObservedBody=structuredClone(matches[0].body);
    c.capture.physical.push(failure);
    const error=new Error(failure.browserBodyError.message,{cause});error.name=failure.browserBodyError.name;
    if(failure.browserBodyError.code!==null)error.code=failure.browserBodyError.code;
    throw error;
  }
}
async function physical(c,frame) {
  const waiting=c.page.waitForResponse(r=>r.url()===`${c.origin}/api/secureshop/admin/audit/unbounded-summary`&&r.request().method()==='POST',{timeout:240000}).then(response=>({response}),error=>({error}));
  const button=await frame.waitForSelector('button[aria-label="Observe unbounded audit summary"]',{visible:true,timeout:30000});
  await frame.waitForFunction(()=>!document.querySelector('button[aria-label="Observe unbounded audit summary"]').disabled,{timeout:30000});
  await button.scrollIntoView();assert.equal(await button.evaluate(node=>{const r=node.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return node.contains(hit);}),true);
  await button.click();const observed=await waiting;if(observed.error)throw observed.error;
  return recordObservedHttpResponse(c,observed.response);
}
async function qualifyAuditCollection(c) {
  const {scope,principal,identity,agents,composition,scenes,modeRepository,reset,capture}=c;
  assert.notEqual(c.peer.scope.platformOwnerId,scope.platformOwnerId);
  await composition.catalog.prepareTarget({scope,persona:principal.user});
  const binding=await scenes.readRetained(scope);assert.ok(binding.scene);
  const peerPrincipal=await composition.personaAuth.authenticateBoundToken({scope:c.peer.scope,token:c.peer.headers.authorization.slice(7)});
  await composition.catalog.prepareTarget({scope:c.peer.scope,persona:peerPrincipal.user});
  const peerBinding=await scenes.readRetained(c.peer.scope);assert.notEqual(peerBinding.targetId,binding.targetId);
  capture.seedIds=await append(c,scope,principal.user,128);
  capture.peerIds=await append(c,c.peer.scope,peerPrincipal.user,1);
  const peerRows=async()=>(await agents.query('SELECT * FROM secureshop_agents.bound_audit_events WHERE event_id=$1',[capture.peerIds[0]])).rows;
  const siblingBefore=await peerRows();assert.equal(siblingBefore.length,1);
  const count=async()=>({actors:c.actorCalls(),judges:c.judgeCalls(),runs:Number((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_audit_runs')).rows[0].n)});
  await c.frame.click('a[href="/secureshop/admin/audit"]');
  const actual=await physical(c,c.frame);assert.equal(actual.status,200);
  assert.deepEqual(Object.keys(actual.request).sort(),['limit','request_id','session_id']);assert.equal(actual.request.limit,5000);
  const originalHttp=capture.http.filter(h=>h.path==='/admin/audit/unbounded-summary'&&h.request.request_id===actual.request.request_id);assert.equal(originalHttp.length,1);assert.deepEqual(originalHttp[0],{path:'/admin/audit/unbounded-summary',request:actual.request,status:actual.status,body:actual.body});
  const result=actual.body;assert.equal(result.replayed,false);assert.equal(result.provider,'ollama');assert.equal(result.model,MODEL);
  await c.frame.waitForFunction(text=>document.querySelector('section[aria-label="Unbounded audit observation"] pre')?.textContent===text,{timeout:30000},result.summary.slice(0,8000));
  const evidence=await c.openEvidence(result.runId);
  assert.equal(evidence.summary,result.summary);assert.equal(evidence.rowCount,result.rowCount);
  const log=await artifact(evidence,'log'),sources=await artifact(evidence,'sources'),messages=JSON.parse(await artifact(evidence,'messages'));
  capture.artifacts={log,sources,messages,traces:JSON.parse(await artifact(evidence,'traces')),effects:JSON.parse(await artifact(evidence,'effects'))};
  capture.originalObservation=assertOriginalAuditObservation({messages,log,sources,
    traces:capture.artifacts.traces,effects:capture.artifacts.effects});
  const sourceRows=JSON.parse(sources);
  for(const id of capture.seedIds)assert.equal(sourceRows.filter(r=>r.id===`agents:${id}`).length,1);
  assert.equal(sourceRows.some(r=>r.id===`agents:${capture.peerIds[0]}`),false);
  const witnessRows=(await agents.query(`SELECT event_id,actor,action,target,params_json FROM secureshop_agents.bound_audit_events
    WHERE launch_id=$1 AND generation=$2 AND action='audit_unbounded_requested' AND target=$3`,[scope.launchId,scope.generation,result.runId])).rows;
  assert.equal(witnessRows.length,1);const row=witnessRows[0];
  assert.equal(JSON.parse(row.params_json).requestId,actual.request.request_id);
  const boundedWitness=await createSecureShopAuditUnboundedOwnedWitnessSelector({sourceEventId:`agents:${row.event_id}`,actor:row.actor,action:row.action,target:row.target,paramsJson:row.params_json})({logText:log,sourcesText:sources});
  const preparedResult=await prepareSecureShopAuditUnboundedJudgePacket(evidence,{mode:'vuln',boundedWitness,qualifyModel:createSecureShopModelQualifier(c.provider),check:c.check});
  const prepared=prepareJudgeInput(preparedResult.packet);assert.equal(prepared.evidenceError,undefined);
  const observation=messages.filter(m=>m.role==='tool');assert.equal(observation.length,1);
  assert.ok(Buffer.byteLength(observation[0].content,'utf8')>131072);
  capture.wire=assertWireObservation(c.wires,observation[0].content,result.summary);
  const promptEvalCount=JSON.parse(capture.wire.responseText.trim().split('\n').at(-1)).prompt_eval_count;
  capture.witness={row,boundedWitness};capture.prepared=prepared;
  const judgments=(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE run_id=$1 AND objective_id=$2',[result.runId,OBJECTIVE])).rows;
  capture.judgments=judgments;assert.equal(judgments.length,1);const judgment=judgments[0];
  assertCanonicalAuditScope(judgment.execution_json.scope,scope);assert.equal(Number(judgment.shop_user_id),principal.user.id);assert.equal(judgment.mode,'vuln');
  assert.equal(judgment.packet,prepared.packet);assert.equal(judgment.evidence_digest,prepared.evidenceDigest);
  assert.equal(judgment.verdict,'pass');assert.equal(judgment.disposition,'awarded');assert.equal(result.objectiveCredit,true);assert.equal(result.assessment.completed,true);
  const original=c.judgeResults.find(j=>j.result.runId===result.runId),transcript=c.judgeTranscripts.find(j=>j.header?.runId===result.runId);
  assert.ok(original&&transcript);assert.deepEqual(JSON.parse(judgment.judge_result_json),original.result);
  assert.deepEqual(judgment.judge_observations,readConfiguredJudgeProvenance(original.result));
  assert.equal(transcript.complete,true);assert.equal(transcript.header.packet,prepared.packet);assert.deepEqual(transcript.outcome.value,original.result);
  const credit=async()=>({judgments:(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1',[judgment.evaluation_id])).rows,
    completions:(await identity.query('SELECT * FROM secureshop_auth.assessment_completions WHERE evaluation_id=$1',[judgment.evaluation_id])).rows,
    contributions:(await identity.query('SELECT * FROM secureshop_auth.assessment_contributions WHERE evaluation_id=$1',[judgment.evaluation_id])).rows});
  const originalCredit=await credit();capture.credit=originalCredit;
  assert.equal(originalCredit.completions.length,1);assert.equal(originalCredit.contributions.length,1);assertCreditRows(judgment,originalCredit.completions[0],originalCredit.contributions[0]);
  const stable=await count();capture.replay=await post(c,'unbounded-summary',actual.request);
  assert.deepEqual(capture.replay,{status:200,body:{...result,replayed:true}});assert.deepEqual(await count(),stable);
  const foreignErrors=capture.errors.length;capture.foreign=await post(c,'unbounded-summary',actual.request,c.peer.headers);assert.equal(capture.foreign.status,503);assert.deepEqual(capture.errors.slice(foreignErrors),[{requestId:actual.request.request_id,code:'CONVERSATION_UNAVAILABLE'}]);assert.deepEqual(await count(),stable);
  const subjects=(await identity.query(`SELECT e.tenant_id AS "tenantId",e.principal_id AS "principalId",p.shop_user_id AS "shopUserId",e.session_id AS "sessionId"
    FROM secureshop_auth.execution_authority_state e JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id WHERE e.session_id=$1 AND e.is_active=1`,[scope.platformSessionId])).rows;
  assert.equal(subjects.length,1);const mode=await modeRepository.getPrincipalMode(subjects[0]);assert.equal(mode.mode,'vuln');
  await modeRepository.setPrincipalMode(subjects[0],{mode:'fixed',expectedRevision:mode.revision});
  await c.page.reload({waitUntil:'domcontentloaded'});const fixedFrame=await c.frameFor(c.page);await fixedFrame.click('a[href="/secureshop/admin/audit"]');
  capture.fixed=await physical(c,fixedFrame);assert.equal(capture.fixed.status,400);assert.deepEqual(capture.fixed.body,{error:'Fixed audit summaries accept at most 100 events'});
  assert.deepEqual(await count(),stable);assert.deepEqual(await credit(),originalCredit);
  capture.reset=await reset.launchResetCoordinator.reset({...scope,expectedGeneration:scope.generation,idempotencyKey:randomUUID()},{expectedSceneId:binding.scene.sceneId});assert.equal(capture.reset.status,'committed');
  capture.old=await post(c,'unbounded-summary',actual.request);assert.equal(capture.old.status,401);
  assert.equal(c.actorCalls(),stable.actors);assert.equal(c.judgeCalls(),stable.judges);assert.deepEqual(await credit(),originalCredit);
  assert.deepEqual(await peerRows(),siblingBefore);
  const peerMe=await fetch(`${c.origin}/api/secureshop/v2/auth/users/me`,{headers:c.peer.headers,signal:AbortSignal.timeout(15000)});assert.equal(peerMe.status,200);
  const active=(await identity.query('SELECT evaluation_id FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1',[judgment.evaluation_id])).rows;assert.deepEqual(active,[]);
  return {...Object.fromEntries(FLAGS.filter(k=>k!=='fixtureCleaned').map(k=>[k,true])),scope:SCOPE,summaryRunId:result.runId,rowCount:evidence.rowCount,sourceBytes:preparedResult.observed.sourceBytes,actorCalls:c.actorCalls(),judgeCalls:c.judgeCalls(),promptEvalCount,errors:[]};
}
module.exports={ASSERTION,SCOPE,FLAGS,assertReceipt,assertCreditRows,assertWireObservation,qualifyAuditCollection,appendCollectionFixtureEvents:append,assertCanonicalAuditScope,recordObservedHttpResponse,assertOriginalAuditObservation};
