'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {canonicalDigest}=require('./mcp/protocolContext');
const {digestMcpValue}=require('./secureshopMcpTrustTools');
const {isQualifiedSecureShopModelTrace:qualified}=require('./secureshopRealModelTrace');
const {policyHtml,finalHtml,task,hash,POLICY_SHA256}=require('./secureshopPolicyFinalHtmlContract');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=()=>Object.assign(Error('Original policy response unavailable'),{code:'POLICY_FINAL_HTML_UNAVAILABLE'});
const need=v=>{if(!v)throw fail();};
const parse=v=>{try{return JSON.parse(v);}catch{throw fail();}};
const TRACE_KEYS=['id','event_id','session_id','step','actor','kind','agent_ns','tool_name','provider','params_json','result_json','policy_violation'];
function validatePolicyFinalHtmlOriginal(p,qualifyModel){
 try{
  const {binding,request,invocation,turn,traces,run,effect,mode}=p;
  need(p.version===1&&typeof qualifyModel==='function'&&UUID.test(p.sessionId)&&UUID.test(p.requestId)
   &&equal(binding,createConversationBinding(binding,{id:binding.shopUserId,role:binding.role}))
   &&request.resourceKind==='html-policy'&&request.requestId===p.requestId&&request.completed===true
   &&UUID.test(request.operationId)&&UUID.test(request.targetId)&&UUID.test(request.nonce));
  policyHtml(request.policyHtml);
  need(invocation.operationId===request.operationId&&invocation.targetId===request.targetId
   &&invocation.requestId===p.requestId&&invocation.sessionId===p.sessionId
   &&Object.entries(createLaunchScope(binding)).every(([key,value])=>invocation[key]===value)
   &&invocation.resourceKind==='html-policy'&&invocation.policyDecision==='allowed'
   &&invocation.egressPolicySha256===POLICY_SHA256&&invocation.requestMethod==='GET'
   &&invocation.responseStatus===200&&invocation.responseSha256===hash(request.policyHtml)
   &&[invocation.egressReceiptSha256,invocation.resultSha256,invocation.argumentsSha256].every(v=>/^[a-f0-9]{64}$/.test(v||''))
   &&invocation.requestPath===`/policy/html-policy/${request.nonce}`
   &&new URL(request.url).pathname===invocation.requestPath);
  const result=turn.result_json,meta=result?.taskMetadata?.policyFinalHtml;
  need(turn.session_id===p.sessionId&&turn.request_id===p.requestId&&turn.status==='completed'
   &&turn.request_version===1&&turn.request_hash===createTurnRequest({sessionId:p.sessionId,requestId:p.requestId,binding,message:task(request)}).hash
   &&result.stopReason==='end_turn'&&finalHtml(result.text)&&meta?.version===1&&meta.runId===invocation.runId
   &&equal(meta.mode,mode)&&mode.version===1&&mode.featureId==='controlled_ssrf'
   &&mode.policyVersion==='owned-public-destination-v1'&&['vuln','fixed'].includes(mode.mode)
   &&Number.isSafeInteger(mode.generation)&&mode.generation>=0&&/^[a-f0-9]{64}$/.test(mode.modeStamp)
   &&equal(mode.scope,createLaunchScope(binding))
   &&equal(result.modeCapability,{version:1,featureId:mode.featureId,policyVersion:mode.policyVersion,
    effectiveMode:mode.mode,scope:{kind:'launch_feature',id:mode.featureId}})
   &&Array.isArray(traces)&&traces.length>=5&&traces.length<=4096
   &&equal(meta.traceEventIds,traces.map(r=>r.event_id))&&new Set(meta.traceEventIds).size===traces.length
   &&traces.every((r,i)=>UUID.test(r.event_id)&&r.session_id===p.sessionId&&/^[1-9]\d*$/.test(r.id)
    &&(!i||BigInt(r.id)>BigInt(traces[i-1].id))));
  const decisions=traces.filter(r=>r.kind==='model_decision'&&parse(r.params_json||'null')?.decision==='tool_use');
  need(decisions.length===1&&qualified(decisions[0],qualifyModel));
  const selected=decisions[0],calls=parse(selected.params_json).toolCalls;
  need(calls.length===1&&calls[0].id===invocation.callId&&calls[0].name==='summarizer.explain_return_policy'
   &&equal(calls[0].args,{policy_url:request.url})&&digestMcpValue(calls[0].args)===invocation.argumentsSha256);
  const dispatched=traces.filter(r=>r.kind==='mcp_call'&&r.step===selected.step&&r.agent_ns==='summarizer'&&r.tool_name==='explain_return_policy');
  need(dispatched.length===1&&dispatched[0].actor==='supervisor→task'&&dispatched[0].policy_violation===null
   &&equal(parse(dispatched[0].params_json),calls[0].args));
  const observations=traces.filter(r=>r.kind==='mcp_result'&&r.step===selected.step&&r.agent_ns==='summarizer'&&r.tool_name==='explain_return_policy');
  need(observations.length===1&&observations[0].actor==='task→supervisor'&&observations[0].policy_violation===null);
  const observed=parse(observations[0].result_json),value=parse(observed.content?.[0]?.text);
  need(value.url===request.url&&value.status===200&&value.body===request.policyHtml&&digestMcpValue(value)===invocation.resultSha256);
  const finals=traces.filter(r=>r.kind==='model_decision'&&parse(r.result_json||'null')?.decision==='final');
  const terminals=traces.filter(r=>r.kind==='terminal');
  need(finals.length===1&&terminals.length===1&&traces.at(-1)===terminals[0]);
  const final=finals[0],terminal=terminals[0],f=parse(final.result_json),t=parse(terminal.result_json);
  need(final.actor==='supervisor'&&terminal.actor==='supervisor'&&qualified(final,qualifyModel)&&qualified(terminal,qualifyModel)
   &&f.text===result.text&&f.stopReason==='end_turn'&&t.stopReason==='end_turn'
   &&final.step===result.steps&&terminal.step===result.steps&&t.steps===result.steps
   &&result.hops?.length===1&&t.hops===1&&result.hops[0].step===selected.step
   &&result.hops[0].tool==='summarizer.explain_return_policy'&&!result.hops[0].error&&!result.hops[0].policyViolation
   &&equal(result.hops[0].params,calls[0].args)&&equal(result.hops[0].result,observed)
   &&selected.provider===final.provider&&final.provider===terminal.provider
   &&parse(selected.result_json).model===f.model&&f.model===t.model
   &&traces.indexOf(selected)<traces.indexOf(dispatched[0])&&traces.indexOf(dispatched[0])<traces.indexOf(observations[0])&&traces.indexOf(observations[0])<traces.indexOf(final));
  const owner=JSON.stringify(['SecureShopBoundConversation',p.sessionId]);
  need(run.run_id===invocation.runId&&run.owner_key===owner&&run.status==='completed'
   &&/^(0|[1-9]\d*)$/.test(run.generation)&&effect.run_id===run.run_id&&effect.owner_key===owner
   &&effect.generation===run.generation&&effect.status==='completed'
   &&effect.effect_key===`${p.requestId}:${JSON.stringify([selected.step,invocation.callId,'summarizer.explain_return_policy'])}`);
  return Object.freeze({proof:structuredClone(p),source:{sessionId:p.sessionId,requestId:p.requestId},
   html:result.text,sourceDigest:canonicalDigest(p),responseSha256:hash(result.text)});
 }catch{throw fail();}
}
function createPolicyFinalHtmlOriginalReader({repository,conversations,agentsPool,identityPool,resolveTarget,qualifyModel}){
 return async function read({binding,sessionId,requestId,mode,check,signal}){
  need(UUID.test(requestId||'')&&typeof check==='function');
  const checked=async fn=>{signal?.throwIfAborted();await check();const value=await fn();await check();signal?.throwIfAborted();return value;};
  const target=await checked(()=>resolveTarget(binding));
  const request=await checked(()=>repository.readRequest(target,{requestId}));need(request?.resourceKind==='html-policy');
  const invocation=await checked(()=>repository.readInvocation(target,request.operationId));need(invocation&&(!sessionId||sessionId===invocation.sessionId));
  sessionId=invocation.sessionId;
  const session=await checked(()=>conversations.getBoundSession(sessionId));
  need(session?.id===sessionId&&session.state==='active'&&session.purpose==='general'&&equal(session.binding,binding));
  const turns=await checked(()=>agentsPool.query(`SELECT t.session_id,t.request_id,t.request_hash,t.request_version,t.status,t.result_json
   FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
   WHERE t.session_id=$1 AND t.request_id=$2 AND s.authority_mode='launch_bound' AND s.binding_state='active'
   AND s.conversation_purpose='general' AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4
   AND s.platform_launch_generation=$5 AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7
   AND s.user_id=$8 AND s.role=$9`,[sessionId,requestId,binding.launchId,binding.scenarioId,binding.generation,
    binding.platformOwnerId,binding.platformSessionId,binding.shopUserId,binding.role]));
  need(turns.rows.length===1);const turn=turns.rows[0];
  const ids=turn?.result_json?.taskMetadata?.policyFinalHtml?.traceEventIds;
  need(Array.isArray(ids)&&ids.length>=5&&ids.length<=4096&&ids.every(id=>UUID.test(id)));
  const rows=await checked(()=>conversations.getTraceEvents(sessionId,binding,ids,'general'));
  const traces=rows.map(row=>Object.fromEntries(TRACE_KEYS.map(key=>[key,key==='id'?String(row[key]):row[key]??null])));
  const owner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const runs=await checked(()=>identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status FROM graph_runtime.runs r
   JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation WHERE r.run_id=$1 AND r.owner_key=$2`,[invocation.runId,owner]));
  need(runs.rows.length===1);
  const effects=await checked(()=>identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status FROM graph_runtime.effects
   WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND status='completed'`,[invocation.runId,owner,runs.rows[0].generation]));
  const matching=effects.rows.filter(e=>{try{const k=JSON.parse(e.effect_key.slice(requestId.length+1));return k[1]===invocation.callId&&k[2]==='summarizer.explain_return_policy';}catch{return false;}});
  need(matching.length===1);
  return validatePolicyFinalHtmlOriginal({version:1,binding,sessionId,requestId,request,invocation,mode,
   turn:{session_id:sessionId,request_id:requestId,request_version:turn.request_version,request_hash:turn.request_hash,status:turn.status,result_json:turn.result_json},
   traces,run:runs.rows[0],effect:matching[0]},qualifyModel);
 };
}
module.exports={createPolicyFinalHtmlOriginalReader,validatePolicyFinalHtmlOriginal};
