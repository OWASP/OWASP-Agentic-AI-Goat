'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {digestMcpValue}=require('../../server/services/secureshopMcpTrustTools');
const {buildSecureShopSsrfEvidence}=require('../../server/services/secureshopSsrfEvidence');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const WORKSHOP='secureshop_agent_security';
const OBJECTIVE='ss_controlled_ssrf';
const FAILURE_REQUEST_LIMIT=4,FAILURE_TRACE_LIMIT=50,FAILURE_RUN_LIMIT=8,FAILURE_EFFECT_LIMIT=16;
const FAILURE_PROVIDERS=new Set(['ollama','openai','anthropic','bedrock','mock']);
const TOOL_ERROR_CATEGORIES=new Map([
 ['Selected SSRF tool request is unavailable','selected_request_invalid'],
 ['SSRF response receipt mismatch','response_receipt_mismatch'],
 ['SSRF tool result unavailable','tool_result_unavailable'],
 ['Owned SSRF target unavailable','target_receipt_unavailable'],
 ['Bound SSRF observation unavailable','bound_observation_unavailable'],
 ['QUALIFICATION_ENDPOINT_BLOCKED','endpoint_blocked'],
 ['timeout','upstream_timeout'],
]);
const RECOVERABLE_RESULTS=Object.freeze({
 INVALID_TOOL_ARGUMENTS:'Selected tool arguments were rejected before execution.',
 INVALID_TOOL_SELECTION:'Selected tool was rejected before execution.',
});
const replayAuthorities=new WeakMap();
const replayComparable=value=>digestMcpValue({...value,replayed:false});
const parseJson=value=>{try{return JSON.parse(value);}catch{return null;}};
function recoveryResult(row){
 const result=parseJson(row?.result_json),content=Array.isArray(result?.content)?result.content:[];
 if(result?.isError!==true||content.length!==1||content[0]?.type!=='text'||typeof content[0].text!=='string')return null;
 const projected=parseJson(content[0].text),keys=projected&&typeof projected==='object'&&!Array.isArray(projected)
  ?Object.keys(projected).sort():[];
 if(keys.join(',')!=='code,error,ok'||projected.ok!==false
  ||!Object.hasOwn(RECOVERABLE_RESULTS,projected.code)||projected.error!==RECOVERABLE_RESULTS[projected.code])return null;
 return projected.code;
}
function noEffectClassification(events){
 const failed=events.filter(event=>Object.hasOwn(RECOVERABLE_RESULTS,event.recoverableCode)).length;
 const terminalWithoutTool=events.some(event=>event.kind==='model_decision'&&event.provider==='ollama'
  &&event.expectedModel===true&&event.mocked===false&&event.decision==='final'&&event.callCount===0
  &&event.stopReason==='end_turn');
 return Object.freeze({outcome:'no_effect',failedAttempts:failed,
  successfulAttempts:0,actualModelDecision:events.some(event=>event.provider==='ollama'
   &&event.expectedModel===true&&event.mocked===false),terminalWithoutTool,refusalProven:false});
}
function successfulRecoveryClassification({traces,successIndex,successCall,issuedUrl,requestId,effects}){
 assert.ok(Number.isInteger(successIndex)&&successIndex>=0);assert.equal(typeof issuedUrl,'string');assert.match(requestId,UUID);
 const priorRows=traces.slice(0,successIndex);
 const earlier=priorRows.map((row,index)=>({row,index}))
  .filter(value=>value.row.kind==='model_decision');
 const unproven=()=>Object.freeze({outcome:'recovery_not_proven',failedAttempts:null,
  successfulAttempts:1,actualModelDecision:true,failureCodes:Object.freeze([])});
 if(earlier.length===0)return priorRows.some(row=>['mcp_call','mcp_result','tool_blocked','denied'].includes(row.kind))
  ?unproven():Object.freeze({outcome:'first_call_success',failedAttempts:0,
   successfulAttempts:1,actualModelDecision:true,failureCodes:Object.freeze([])});
 const failureCodes=[];
 for(let offset=0;offset<earlier.length;offset++){
  const {row,index}=earlier[offset],params=parseJson(row.params_json),identity=parseJson(row.result_json);
  const calls=Array.isArray(params?.toolCalls)?params.toolCalls:[];
  if(row.provider!=='ollama'||identity?.model!=='llama3.1:8b'||identity?.mocked!==false
   ||params?.decision!=='tool_use'||calls.length!==1)return unproven();
  const call=calls[0];
  if(typeof call?.id!=='string'||!call.id||call.id===successCall.id
   ||typeof call?.name!=='string'||!/^[^.]+\.[^.]+$/.test(call.name))return unproven();
  const nextDecision=earlier[offset+1]?.index??successIndex;
  const [agent,tool]=call.name.split('.');
  const results=traces.slice(index+1,nextDecision).filter(candidate=>candidate.kind==='mcp_result'
   &&candidate.step===row.step&&candidate.agent_ns===agent&&candidate.tool_name===tool);
  if(results.length!==1)return unproven();
  const code=recoveryResult(results[0]);if(!code)return unproven();
  const args=call.args,argumentMatches=args&&typeof args==='object'&&!Array.isArray(args)
   &&Object.keys(args).length===1&&Object.keys(args)[0]==='policy_url'&&args.policy_url===issuedUrl;
  if(code==='INVALID_TOOL_SELECTION'&&call.name==='summarizer.explain_return_policy')return unproven();
  if(code==='INVALID_TOOL_ARGUMENTS'
   &&(call.name!=='summarizer.explain_return_policy'||argumentMatches!==false))return unproven();
  const effectKey=`${requestId}:${JSON.stringify([row.step,call.id,call.name])}`;
  const matching=effects.filter(effect=>effect.effect_key===effectKey);
  if(matching.length!==1||matching[0].status!=='uncertain')return unproven();
  failureCodes.push(code);
 }
 return Object.freeze({outcome:'recovered',failedAttempts:failureCodes.length,
  successfulAttempts:1,actualModelDecision:true,failureCodes:Object.freeze(failureCodes)});
}
// These functions are intentionally self-contained: Puppeteer serializes them
// into the opaque shop frame, where module bindings are unavailable.
function clickWithBridgeResponseTap({label,origin,token,maxBytes,deadlineMs}){
  const key='__dvaiaRenderedSsrfResponseTap';
  if(typeof token!=='string'||!/^[a-f0-9-]{36}$/.test(token)||typeof origin!=='string'
    ||!Number.isSafeInteger(maxBytes)||maxBytes<1||!Number.isSafeInteger(deadlineMs)||deadlineMs<1)throw Error('Invalid response tap');
  if(Object.prototype.hasOwnProperty.call(globalThis,key)||typeof globalThis.fetch!=='function')throw Error('Response tap unavailable');
  const button=[...document.querySelectorAll('section[aria-labelledby="controlled-ssrf-title"] button')]
    .find(value=>value.textContent===label&&!value.disabled);
  if(!button)throw Error('Policy action unavailable');
  const original=globalThis.fetch;
  const state={token,original,wrapper:null,matched:false,capture:null};
  const captureFailure=code=>Object.freeze({ok:false,code});
  const wrapper=function(input,init){
    let url,method;
    try{
      const raw=input instanceof Request?input.url:input;
      url=new URL(raw,origin);method=String(init?.method||(input instanceof Request?input.method:'GET')).toUpperCase();
    }catch{return Reflect.apply(original,this,arguments);}
    if(url.origin!==origin||url.pathname!=='/api/secureshop/v2/controlled-ssrf/run'||url.search||url.hash||method!=='POST'){
      return Reflect.apply(original,this,arguments);
    }
    if(state.matched){state.capture=Promise.resolve(captureFailure('DUPLICATE_FRAME_REQUEST'));return Reflect.apply(original,this,arguments);}
    state.matched=true;
    // Home checks a WeakMap branded bridge fetch on every render. Restore that
    // exact function before invoking it or yielding to React.
    if(globalThis.fetch===wrapper)globalThis.fetch=original;
    let requestBody=null;
    if(typeof init?.body==='string')requestBody=init.body;
    else if(input instanceof Request&&init?.body===undefined){
      try{requestBody=input.clone().text();}catch{requestBody=Promise.reject(Error('request clone failed'));}
    }
    let returned;
    try{returned=Reflect.apply(original,this,arguments);}
    catch(error){state.capture=Promise.resolve(captureFailure('FETCH_THROW'));throw error;}
    state.capture=Promise.resolve(returned).then(async response=>{
      try{
        if(!(response instanceof Response))return captureFailure('INVALID_RESPONSE');
        const clone=response.clone(),reader=clone.body?.getReader();
        const chunks=[];let bytes=0,timer;
        const expired=Object.freeze({expired:true});
        const deadline=new Promise(resolve=>{timer=setTimeout(()=>resolve(expired),deadlineMs);});
        try{
          if(reader)while(true){
            const value=await Promise.race([reader.read(),deadline]);
            if(value===expired)throw Error('capture deadline');
            if(value.done)break;
            bytes+=value.value.byteLength;if(bytes>maxBytes)throw Error('capture too large');
            chunks.push(value.value);
          }
        }finally{clearTimeout(timer);if(reader){try{reader.cancel().catch(()=>{});}catch{}try{reader.releaseLock();}catch{}}}
        const joined=new Uint8Array(bytes);let offset=0;
        for(const chunk of chunks){joined.set(chunk,offset);offset+=chunk.byteLength;}
        const bodyText=new TextDecoder('utf-8',{fatal:true}).decode(joined);
        const resolvedBody=await requestBody;
        if(typeof resolvedBody!=='string')return captureFailure('INVALID_REQUEST_BODY');
        return Object.freeze({ok:true,url:url.href,method,requestBody:resolvedBody,status:response.status,
          contentType:response.headers.get('content-type')||'',bytes,bodyText});
      }catch{return captureFailure('CAPTURE_FAILED');}
    },()=>captureFailure('FETCH_REJECTED'));
    // Preserve the exact promise/Response semantics seen by the application.
    return returned;
  };
  state.wrapper=wrapper;
  Object.defineProperty(globalThis,key,{value:state,configurable:true});
  globalThis.fetch=wrapper;
  try{button.click();}
  catch(error){if(globalThis.fetch===wrapper)globalThis.fetch=original;delete globalThis[key];throw error;}
  if(!state.matched||globalThis.fetch!==original){
    if(globalThis.fetch===wrapper)globalThis.fetch=original;
    delete globalThis[key];throw Error('Policy request was not captured');
  }
  return true;
}
async function readBridgeResponseTap({token}){
  const state=globalThis.__dvaiaRenderedSsrfResponseTap;
  if(!state||state.token!==token||!state.matched||!state.capture)throw Error('Response tap unavailable');
  return state.capture;
}
function closeBridgeResponseTap({token}){
  const key='__dvaiaRenderedSsrfResponseTap',state=globalThis[key];
  if(!state||state.token!==token)return Object.freeze({closed:false,replaced:false});
  let replaced=false;
  if(globalThis.fetch===state.wrapper)globalThis.fetch=state.original;
  else if(globalThis.fetch!==state.original)replaced=true;
  delete globalThis[key];
  return Object.freeze({closed:true,replaced,restored:globalThis.fetch===state.original});
}
// Supplied pools must already be admitted disposable runtime pools. This helper
// constructs no composition, provider, transport, session, or replacement effect.
function createRenderedSsrfEvidence({identityRuntime,agentsRuntime,ownerId,launchId,generation}) {
  assert.equal(typeof identityRuntime?.query,'function');assert.equal(typeof agentsRuntime?.query,'function');
  assert.ok(Number.isSafeInteger(ownerId)&&ownerId>0);assert.ok(Number.isSafeInteger(generation)&&generation>0);
  assert.match(launchId,UUID);
  let failureAttempt=null;
  function clearFailureAttempt(){failureAttempt=null;}
  function retainFailureAttempt({before,requestId,resource}={}){
    assert.ok(before&&typeof before==='object'&&!Array.isArray(before));assert.match(requestId,UUID);
    assert.ok(['public-policy','private-policy'].includes(resource));
    const traceHead=String(before.traceHead??'');assert.match(traceHead,/^(?:0|[1-9][0-9]*)$/);
    failureAttempt=Object.freeze({requestId,resource,traceHead});
  }
  async function snapshot(){
    const invocations=(await agentsRuntime.query(`SELECT i.*,t.launch_id,t.scenario_id,t.generation,t.original_platform_owner_id,t.original_platform_session_id
      FROM secureshop_agents.bound_ssrf_invocations i JOIN secureshop_agents.bound_ssrf_targets t USING(target_id)
      WHERE t.original_platform_owner_id=$1 AND t.launch_id=$2 AND t.generation=$3 ORDER BY i.completed_at,i.operation_id`,[ownerId,launchId,generation])).rows;
    const judgments=(await identityRuntime.query(`SELECT * FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND objective_id=$2 AND workshop_key=$3 ORDER BY created_at,evaluation_id`,[ownerId,OBJECTIVE,WORKSHOP])).rows;
    const contributions=(await identityRuntime.query(`SELECT * FROM workshop_platform.objective_contributions
      WHERE user_id=$1 AND objective_id=$2 AND platform_launch_id=$3 AND platform_launch_generation=$4 AND workshop_key=$5 ORDER BY evaluation_id`,[ownerId,OBJECTIVE,launchId,generation,WORKSHOP])).rows;
    const traceHead=(await agentsRuntime.query(`SELECT COALESCE(MAX(t.id),0)::text AS id FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE s.original_platform_owner_id=$1 AND s.platform_launch_id=$2 AND s.platform_launch_generation=$3`,[ownerId,launchId,generation])).rows[0].id;
    return {invocations,judgments,contributions,traceHead};
  }
  async function verifyTurn({before,requestId,resource,response}){
    assert.match(requestId,UUID);
    assert.equal(response.stopReason,'end_turn');assert.equal(response.resourceKind,resource);assert.equal(response.replayed,false);
    assert.ok(typeof response.response==='string'&&response.response.trim());
    const after=await snapshot();
    const added=after.invocations.filter(row=>!before.invocations.some(old=>old.operation_id===row.operation_id));
    if(added.length!==1){
      // Preserve a bounded diagnostic before disposable stores are removed.
      // This is an owner/launch trace window, not a replacement effect receipt.
      let traceWindow={available:false};
      try{
        const rows=(await agentsRuntime.query(`SELECT t.kind,t.provider,t.params_json,t.result_json
          FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
          WHERE s.original_platform_owner_id=$1 AND s.platform_launch_id=$2
          AND s.platform_launch_generation=$3 AND t.id>$4 ORDER BY t.id LIMIT 51`,
          [ownerId,launchId,generation,before.traceHead])).rows;
        traceWindow={available:true,truncated:rows.length>50,events:rows.slice(0,50).map(row=>{
          const params=parseJson(row.params_json),result=parseJson(row.result_json);
          const calls=Array.isArray(params?.toolCalls)?params.toolCalls:[];
          const recoverableCode=recoveryResult(row);
          return {kind:['model_decision','mcp_result','terminal','error','denied'].includes(row.kind)?row.kind:'other',
            provider:['ollama','openai','anthropic','bedrock','mock'].includes(row.provider)?row.provider:'unknown',
            decision:['tool_use','final'].includes(params?.decision||result?.decision)?params?.decision||result?.decision:'unknown',
            callCount:calls.length,selectedExpectedTool:calls.some(call=>call?.name==='summarizer.explain_return_policy'),
            expectedModel:result?.model==='llama3.1:8b',mocked:typeof result?.mocked==='boolean'?result.mocked:null,
            stopReason:['end_turn','max_steps','error','cancelled','budget_exhausted'].includes(result?.stopReason)
              ?result.stopReason:'unknown',recoverableCode:recoverableCode||null};
        })};
        traceWindow.classification=noEffectClassification(traceWindow.events);
      }catch{/* Diagnostic failure must not turn missing effect evidence into success. */}
      assert.fail(`SSRF invocation count mismatch: ${JSON.stringify({resource,invocations:added.length,
        responseSha256:crypto.createHash('sha256').update(response.response).digest('hex'),traceWindow})}`);
    }
    const effect=added[0];
    assert.equal(effect.request_id,requestId);assert.equal(effect.resource_kind,resource);assert.equal(effect.response_status,200);assert.equal(effect.request_method,'GET');
    assert.equal(effect.policy_decision,resource==='private-policy'?'denied':'allowed');
    assert.equal(effect.original_platform_owner_id,ownerId);assert.equal(effect.launch_id,launchId);assert.equal(Number(effect.generation),generation);
    for(const key of ['arguments_sha256','result_sha256','response_sha256','egress_receipt_sha256','egress_policy_sha256'])assert.ok(Buffer.isBuffer(effect[key])&&effect[key].length===32);
    const turn=(await agentsRuntime.query(`SELECT status,result_json FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,[effect.session_id,requestId])).rows;
    assert.equal(turn.length,1);assert.equal(turn[0].status,'completed');
    const journal=turn[0].result_json;assert.equal(journal.stopReason,response.stopReason);
    assert.equal(journal.text ?? journal.response ?? journal.message ?? null,response.response);
    const sessions=(await agentsRuntime.query(`SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1`,[effect.session_id])).rows;
    assert.equal(sessions.length,1);const session=sessions[0];assert.equal(session.authority_mode,'launch_bound');assert.equal(session.binding_state,'active');
    assert.equal(Number(session.original_platform_owner_id),ownerId);assert.equal(session.platform_launch_id,launchId);
    assert.equal(session.platform_scenario_id,effect.scenario_id);assert.equal(Number(session.platform_launch_generation),generation);
    assert.equal(Number(session.original_platform_session_id),Number(effect.original_platform_session_id));
    const traces=(await agentsRuntime.query(`SELECT * FROM secureshop_agents.agent_trace WHERE session_id=$1 AND id>$2 ORDER BY id`,[effect.session_id,before.traceHead])).rows;
    const parse=value=>JSON.parse(value);
    const decision=traces.find(row=>row.kind==='model_decision'&&parse(row.params_json)?.toolCalls?.some(call=>call.id===effect.call_id));
    assert.ok(decision);assert.equal(decision.provider,'ollama');assert.equal(parse(decision.result_json).model,'llama3.1:8b');assert.equal(parse(decision.result_json).mocked,false);
    const call=parse(decision.params_json).toolCalls.find(call=>call.id===effect.call_id);
    assert.equal(call.name,'summarizer.explain_return_policy');assert.ok(call.args&&typeof call.args==='object'&&!Array.isArray(call.args));
    assert.deepEqual(Object.keys(call.args),['policy_url']);assert.equal(typeof call.args.policy_url,'string');
    assert.equal(digestMcpValue(call.args),effect.arguments_sha256.toString('hex'));
    const resultIndex=traces.findIndex(row=>row.kind==='mcp_result'&&row.step===decision.step&&`${row.agent_ns}.${row.tool_name}`===call.name);
    assert.ok(resultIndex>traces.indexOf(decision));const output=parse(traces[resultIndex].result_json),observed=parse(output.content[0].text);
    assert.equal(digestMcpValue(observed),effect.result_sha256.toString('hex'));assert.equal(crypto.createHash('sha256').update(observed.body).digest('hex'),effect.response_sha256.toString('hex'));
    assert.equal(observed.status,200);assert.equal(observed.url,call.args.policy_url);
    const requests=(await agentsRuntime.query(`SELECT * FROM secureshop_agents.bound_ssrf_requests WHERE target_id=$1 AND request_id=$2`,[effect.target_id,requestId])).rows;assert.equal(requests.length,1);const issued=requests[0];
    assert.equal(issued.operation_id,effect.operation_id);assert.equal(issued.resource_kind,resource);assert.equal(issued.issued_url,observed.url);assert.match(issued.nonce,UUID);assert.equal(new URL(issued.issued_url).pathname,effect.request_path);
    const egress={version:1,targetId:effect.target_id,nonce:issued.nonce,operationId:effect.operation_id,requestId,method:'GET',path:effect.request_path,resourceKind:resource,status:200,responseSha256:effect.response_sha256.toString('hex')};
    assert.equal(crypto.createHash('sha256').update(JSON.stringify(egress)).digest('hex'),effect.egress_receipt_sha256.toString('hex'));
    const terminal=traces.at(-1);assert.equal(terminal.kind,'terminal');assert.equal(terminal.provider,'ollama');assert.equal(parse(terminal.result_json).model,'llama3.1:8b');assert.equal(parse(terminal.result_json).mocked,false);assert.equal(parse(terminal.result_json).stopReason,'end_turn');assert.ok(traces.indexOf(terminal)>resultIndex);
    const runs=(await identityRuntime.query(`SELECT * FROM graph_runtime.runs WHERE run_id=$1`,[effect.run_id])).rows;assert.equal(runs.length,1);const run=runs[0];assert.equal(run.status,'completed');assert.equal(run.owner_key,JSON.stringify(['SecureShopBoundConversation',String(effect.session_id)]));
    const effectKey=`${requestId}:${JSON.stringify([decision.step,effect.call_id,call.name])}`;
    const receipts=(await identityRuntime.query(`SELECT * FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4`,[effect.run_id,run.owner_key,run.generation,effectKey])).rows;assert.equal(receipts.length,1);assert.equal(receipts[0].status,'completed');
    const requestEffects=(await identityRuntime.query(`SELECT effect_key,status FROM graph_runtime.effects
      WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key LIKE $4 ORDER BY effect_key`,
    [effect.run_id,run.owner_key,run.generation,`${requestId}:%`])).rows;
    const recovery=successfulRecoveryClassification({traces,successIndex:traces.indexOf(decision),successCall:call,
      issuedUrl:issued.issued_url,requestId,effects:requestEffects});
    const receipt={version:1,status:'completed',runId:effect.run_id,ownerKey:run.owner_key,generation:String(run.generation),effectKey};
    if(resource==='private-policy'){
      const binding={targetId:effect.target_id,launchId,scenarioId:effect.scenario_id,generation,platformOwnerId:ownerId,platformSessionId:effect.original_platform_session_id};
      const invocation={...binding,operationId:effect.operation_id,runId:effect.run_id,requestId,sessionId:effect.session_id,callId:effect.call_id,resourceKind:resource,requestMethod:effect.request_method,requestPath:effect.request_path,responseStatus:effect.response_status,policyDecision:effect.policy_decision};
      for(const [camel,snake] of [['argumentsSha256','arguments_sha256'],['resultSha256','result_sha256'],['responseSha256','response_sha256'],['egressReceiptSha256','egress_receipt_sha256'],['egressPolicySha256','egress_policy_sha256']])invocation[camel]=effect[snake].toString('hex');
      const packets=buildSecureShopSsrfEvidence({binding,execution:{runId:effect.run_id,ownerKey:run.owner_key,durableGeneration:run.generation},sessionId:effect.session_id,requestId,traces,observation:{step:decision.step,callId:effect.call_id,tool:call.name,args:call.args,result:output,effectReceipt:receipt},externalRecord:{invocation,effectReceipt:receipt},result:response,qualifyModel:value=>value.provider==='ollama'&&value.model==='llama3.1:8b'&&value.mocked===false});
      assert.equal(packets.length,1,'Production extractor must accept exact persisted actor/tool/effect chain');
    }
    const fresh=after.judgments.filter(row=>!before.judgments.some(old=>old.evaluation_id===row.evaluation_id));
    if(resource==='public-policy'){
      assert.deepEqual(after.contributions,before.contributions);assert.ok(fresh.every(row=>row.verdict!=='pass'));
    }else{
      const accepted=fresh.filter(row=>row.verdict==='pass'&&row.run_id===effect.run_id);assert.equal(accepted.length,1);
      assert.equal(accepted[0].platform_launch_id,launchId);assert.equal(Number(accepted[0].platform_launch_generation),generation);
      const result=accepted[0].result_json;assert.equal(result.provider,'ollama');assert.equal(result.model,'llama3.1:8b');
      assert.equal(result.verdict,'pass');assert.ok(Array.isArray(result.criteria)&&result.criteria.length>0&&result.criteria.every(row=>row.satisfied===true));
      // Criteria schemas remain the production Judge's authority; require its
      // durable pass and exact contribution rather than inventing criterion keys.
      const credit=after.contributions.filter(row=>!before.contributions.some(old=>old.evaluation_id===row.evaluation_id));
      assert.equal(credit.length,1);assert.equal(credit[0].evaluation_id,accepted[0].evaluation_id);
    }
    const effectCount=Number((await identityRuntime.query(
      'SELECT count(*)::int AS n FROM graph_runtime.effects WHERE owner_key=$1',[run.owner_key])).rows[0]?.n);
    assert.ok(Number.isSafeInteger(effectCount)&&effectCount>0);
    return Object.freeze({after,runId:effect.run_id,requestId,resource,
      effectReceipt:Object.freeze(receipt),effectCount,
      responseFingerprintSha256:replayComparable(response),recovery});
  }
  async function verifyHistoryPreserved(receipt){
    assert.ok(receipt?.after&&receipt?.effectReceipt);const after=await snapshot();
    assert.deepEqual(after.invocations,receipt.after.invocations);assert.deepEqual(after.judgments,receipt.after.judgments);
    assert.deepEqual(after.contributions,receipt.after.contributions);assert.equal(after.traceHead,receipt.after.traceHead);
    const effect=receipt.effectReceipt;
    const exact=(await identityRuntime.query(`SELECT status FROM graph_runtime.effects
      WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4`,
    [effect.runId,effect.ownerKey,effect.generation,effect.effectKey])).rows;
    assert.deepEqual(exact,[{status:'completed'}]);
    const count=Number((await identityRuntime.query(
      'SELECT count(*)::int AS n FROM graph_runtime.effects WHERE owner_key=$1',[effect.ownerKey])).rows[0]?.n);
    assert.equal(count,receipt.effectCount);
    return Object.freeze({historyPreserved:true,traceHead:after.traceHead,effectCount:count});
  }
  async function captureFailure(){
    const parse=value=>{if(value&&typeof value==='object')return value;try{return JSON.parse(value);}catch{return null;}};
    if(!failureAttempt)return Object.freeze({scope:'rendered_secureshop_ssrf_failure_evidence',ownerScopeVerified:true,
      attemptPresent:false,requestCount:0,requestTruncated:false,requestBound:false,requestMissing:true,
      requestAmbiguous:false,latestResource:'unknown',latestRequestAttached:false,latestInvocationPresent:false,
      requestTurnBound:false,requestTurnMissing:true,requestTurnAmbiguous:false,traceCount:0,traceTruncated:false,
      decisionPresent:false,provider:'unknown',decisionKind:'unknown',callCount:0,callTruncated:false,
      selectedExpectedTool:false,argumentShapeValid:false,argumentMatchesIssued:null,resultPresent:false,
      resultIsError:null,errorCategory:'attempt_unavailable',runCount:0,runTruncated:false,runStatuses:Object.freeze([]),
      effectCount:0,effectTruncated:false,effectStatuses:Object.freeze([])});
    const requests=(await agentsRuntime.query(`SELECT r.resource_kind,r.issued_url,
      i.operation_id IS NOT NULL AS invoked,i.session_id AS invocation_session_id,i.run_id AS invocation_run_id,
      (SELECT count(*)::int FROM secureshop_agents.bound_ssrf_requests counted
        WHERE counted.target_id=r.target_id) AS owner_request_count,
      (SELECT count(*)::int FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
        WHERE tr.request_id=r.request_id AND s.original_platform_owner_id=$1 AND s.platform_launch_id=$2
        AND s.platform_launch_generation=$3 AND (i.session_id IS NULL OR tr.session_id=i.session_id)) AS turn_count,
      (SELECT min(tr.session_id) FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
        WHERE tr.request_id=r.request_id AND s.original_platform_owner_id=$1 AND s.platform_launch_id=$2
        AND s.platform_launch_generation=$3 AND (i.session_id IS NULL OR tr.session_id=i.session_id)) AS session_id
      FROM secureshop_agents.bound_ssrf_requests r JOIN secureshop_agents.bound_ssrf_targets t USING(target_id)
      LEFT JOIN secureshop_agents.bound_ssrf_invocations i
        ON i.operation_id=r.operation_id AND i.target_id=r.target_id AND i.request_id=r.request_id
      WHERE t.original_platform_owner_id=$1 AND t.launch_id=$2 AND t.generation=$3
      AND r.request_id=$4 AND r.resource_kind=$5
      ORDER BY r.created_at DESC,r.operation_id DESC LIMIT 2`,
      [ownerId,launchId,generation,failureAttempt.requestId,failureAttempt.resource])).rows;
    const requestMatchCount=requests.length,latestRequest=requestMatchCount===1?requests[0]:null;
    const turnCount=Number(latestRequest?.turn_count),boundSessionId=turnCount===1
      &&typeof latestRequest?.session_id==='string'?latestRequest.session_id:null;
    const traceRows=boundSessionId?(await agentsRuntime.query(`SELECT t.session_id,t.step,t.kind,t.provider,t.agent_ns,t.tool_name,t.params_json,t.result_json
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.turn_requests tr
        ON tr.session_id=t.session_id AND tr.request_id=$5
      JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.original_platform_owner_id=$1 AND s.platform_launch_id=$2 AND s.platform_launch_generation=$3
      AND t.session_id=$4 AND t.id>$6 ORDER BY t.id DESC LIMIT $7`,
      [ownerId,launchId,generation,boundSessionId,failureAttempt.requestId,failureAttempt.traceHead,
        FAILURE_TRACE_LIMIT+1])).rows:[];
    const ownerKey=boundSessionId?JSON.stringify(['SecureShopBoundConversation',boundSessionId]):null;
    const invocationRunId=UUID.test(latestRequest?.invocation_run_id||'')?latestRequest.invocation_run_id:null;
    const runs=!ownerKey?[]:invocationRunId?(await identityRuntime.query(`SELECT run_id,owner_key,status,provider,model
      FROM graph_runtime.runs WHERE owner_key=$1 AND run_id=$2 ORDER BY started_at DESC LIMIT $3`,
      [ownerKey,invocationRunId,FAILURE_RUN_LIMIT+1])).rows:(await identityRuntime.query(`SELECT DISTINCT r.run_id,r.owner_key,r.status,r.provider,r.model,r.started_at
      FROM graph_runtime.runs r JOIN graph_runtime.effects e ON e.run_id=r.run_id AND e.owner_key=r.owner_key
      WHERE r.owner_key=$1 AND e.effect_key LIKE $2 ORDER BY r.started_at DESC LIMIT $3`,
      [ownerKey,`${failureAttempt.requestId}:%`,FAILURE_RUN_LIMIT+1])).rows;
    const runIds=runs.slice(0,FAILURE_RUN_LIMIT).map(row=>row.run_id);
    const effects=runIds.length?(await identityRuntime.query(`SELECT run_id,status FROM graph_runtime.effects
      WHERE run_id=ANY($1::uuid[]) AND owner_key=$2 AND effect_key LIKE $3
      ORDER BY updated_at DESC LIMIT $4`,[runIds,ownerKey,`${failureAttempt.requestId}:%`,FAILURE_EFFECT_LIMIT+1])).rows:[];
    const traces=traceRows.slice(0,FAILURE_TRACE_LIMIT).reverse(),decisionIndex=traces.findLastIndex(row=>row.kind==='model_decision');
    const decision=decisionIndex>=0?traces[decisionIndex]:null,params=parse(decision?.params_json);
    const allCalls=Array.isArray(params?.toolCalls)?params.toolCalls:[],calls=allCalls.slice(0,9);
    const expectedCalls=calls.filter(call=>call?.name==='summarizer.explain_return_policy');
    const selected=expectedCalls.length===1?expectedCalls[0]:null;
    const args=selected?.args,argumentShapeValid=!!args&&!Array.isArray(args)&&Object.getPrototypeOf(args)===Object.prototype
      &&Object.keys(args).length===1&&Object.keys(args)[0]==='policy_url'&&typeof args.policy_url==='string';
    const result=decision?traces.slice(decisionIndex+1).find(row=>row.kind==='mcp_result'
      &&row.session_id===decision.session_id&&row.step===decision.step
      &&row.agent_ns==='summarizer'&&row.tool_name==='explain_return_policy'):null;
    const resultValue=parse(result?.result_json),isError=resultValue?resultValue.isError===true:null;
    const errorText=isError&&typeof resultValue?.content?.[0]?.text==='string'
      &&resultValue.content[0].text.startsWith('ERROR: ')?resultValue.content[0].text.slice(7):null;
    const errorCategory=errorText?(TOOL_ERROR_CATEGORIES.get(errorText)||'unclassified_tool_error')
      :(result&&!resultValue?'malformed_tool_result':result?'none':'trace_unavailable');
    const runStatuses=runs.slice(0,FAILURE_RUN_LIMIT).map(row=>['running','completed','failed','cancelled','interrupted']
      .includes(row.status)?row.status:'unknown');
    const effectStatuses=effects.slice(0,FAILURE_EFFECT_LIMIT).map(row=>['started','completed','uncertain']
      .includes(row.status)?row.status:'unknown');
    const ownerRequestCount=Number(latestRequest?.owner_request_count),boundedRequestCount=Number.isSafeInteger(ownerRequestCount)
      &&ownerRequestCount>=0?ownerRequestCount:requestMatchCount;
    return Object.freeze({scope:'rendered_secureshop_ssrf_failure_evidence',ownerScopeVerified:true,
      attemptPresent:true,requestCount:Math.min(boundedRequestCount,FAILURE_REQUEST_LIMIT),
      requestTruncated:boundedRequestCount>FAILURE_REQUEST_LIMIT,requestBound:requestMatchCount===1,
      requestMissing:requestMatchCount===0,requestAmbiguous:requestMatchCount>1,
      latestResource:['public-policy','private-policy'].includes(latestRequest?.resource_kind)?latestRequest.resource_kind:'unknown',
      latestRequestAttached:typeof latestRequest?.issued_url==='string',latestInvocationPresent:latestRequest?.invoked===true,
      requestTurnBound:!!boundSessionId,requestTurnMissing:turnCount===0,requestTurnAmbiguous:turnCount>1,
      traceCount:Math.min(traceRows.length,FAILURE_TRACE_LIMIT),traceTruncated:traceRows.length>FAILURE_TRACE_LIMIT,
      decisionPresent:!!decision,provider:FAILURE_PROVIDERS.has(decision?.provider)?decision.provider:'unknown',
      decisionKind:['tool_use','final'].includes(params?.decision)?params.decision:'unknown',
      callCount:Math.min(allCalls.length,8),callTruncated:allCalls.length>8,
      selectedExpectedTool:expectedCalls.length===1,argumentShapeValid,
      argumentMatchesIssued:boundSessionId&&argumentShapeValid&&typeof latestRequest?.issued_url==='string'
        ?args.policy_url===latestRequest.issued_url:null,
      resultPresent:!!result,resultIsError:isError,errorCategory,
      runCount:Math.min(runs.length,FAILURE_RUN_LIMIT),runTruncated:runs.length>FAILURE_RUN_LIMIT,runStatuses:Object.freeze(runStatuses),
      effectCount:Math.min(effects.length,FAILURE_EFFECT_LIMIT),effectTruncated:effects.length>FAILURE_EFFECT_LIMIT,
      effectStatuses:Object.freeze(effectStatuses)});
  }
  return Object.freeze({snapshot,verifyTurn,verifyHistoryPreserved,clearFailureAttempt,retainFailureAttempt,captureFailure});
}
async function runRenderedControlledSsrf({page,frame,origin,evidence,timeoutMs=420000}){
  assert.ok(Number.isSafeInteger(timeoutMs)&&timeoutMs>=1000&&timeoutMs<=420000);
  const results=[];
  for(const [resource,label] of [['public-policy','Fetch public policy'],['private-policy','Try internal policy']]){
    evidence.clearFailureAttempt();
    const before=await evidence.snapshot();
    await frame.waitForFunction(text=>[...document.querySelectorAll('section[aria-labelledby="controlled-ssrf-title"] button')].some(b=>b.textContent===text&&!b.disabled),{timeout:timeoutMs,polling:'mutation'},label);
    const token=crypto.randomUUID(),requests=[];
    const matches=request=>{const url=new URL(request.url());return url.origin===origin
      &&url.pathname==='/api/secureshop/v2/controlled-ssrf/run'&&!url.search&&!url.hash&&request.method()==='POST';};
    const observe=request=>{if(matches(request))requests.push(request);};
    page.on('request',observe);
    const waitAbort=new AbortController();
    const pending=page.waitForResponse(r=>{const u=new URL(r.url());return u.origin===origin&&u.pathname==='/api/secureshop/v2/controlled-ssrf/run'&&r.request().method()==='POST';},{timeout:timeoutMs,signal:waitAbort.signal});void pending.catch(()=>{});
    let closeResult=null;
    try{
      await frame.evaluate(clickWithBridgeResponseTap,{label,origin,token,maxBytes:8*1024*1024,deadlineMs:30000});
      const response=await pending;
      assert.equal(response.frame(),page.mainFrame(),'Rendered SSRF request must originate from the parent transport frame');
      const captured=await frame.evaluate(readBridgeResponseTap,{token});
      const postData=response.request().postData();
      assert.ok(captured?.ok===true,'Rendered SSRF response capture failed');
      assert.ok(captured.url===response.url()&&captured.method==='POST'&&captured.requestBody===postData
        &&captured.status===response.status(),
        'Rendered SSRF request capture mismatch');
      const headers=response.headers(),mime=String(headers['content-type']||'').split(';')[0].trim().toLowerCase();
      assert.ok(mime==='application/json'&&captured.contentType.split(';')[0].trim().toLowerCase()===mime,
        'Rendered SSRF response MIME mismatch');
      const declared=Number(headers['content-length']);
      assert.ok(Number.isSafeInteger(declared)&&declared>=0&&declared===captured.bytes
        &&Buffer.byteLength(captured.bodyText,'utf8')===captured.bytes,
      'Rendered SSRF response length mismatch');
      let body;try{body=JSON.parse(captured.bodyText);}catch{assert.fail('Rendered SSRF response was not valid JSON');}
      const request=JSON.parse(postData);assert.equal(request.resource,resource);assert.match(request.request_id,UUID);
      evidence.retainFailureAttempt({before,requestId:request.request_id,resource});
      assert.equal(response.status(),200);
      const result=await evidence.verifyTurn({before,requestId:request.request_id,resource,response:body});
      await frame.waitForFunction(text=>document.querySelector('[aria-label="Policy agent observation"] pre')?.textContent===text,{timeout:timeoutMs,polling:'mutation'},body.response);
      assert.equal(requests.length,1,'Expected exactly one rendered SSRF network request');
      assert.equal(response.request(),requests[0],'Rendered SSRF response did not match its sole request');
      results.push(result);
      if(resource==='private-policy'){
        const requestHeaders=response.request().headers();const authorization=requestHeaders.authorization;
        const launchBearer=requestHeaders['x-dvaia-secureshop-launch'];
        assert.match(authorization||'',/^Bearer [^\s]+$/);assert.match(launchBearer||'',/^[A-Za-z0-9_-]{43}$/);
        replayAuthorities.set(result,Object.freeze({authorization,launchBearer}));
      }
    }finally{
      page.off('request',observe);
      waitAbort.abort();await pending.catch(()=>{});
      try{closeResult=await frame.evaluate(closeBridgeResponseTap,{token});}catch{}
    }
    assert.ok(closeResult?.closed===true&&closeResult.restored===true&&closeResult.replaced===false,
      'Rendered SSRF response tap cleanup failed');
  }
  return Object.freeze({objectiveId:OBJECTIVE,scope:'rendered_controlled_ssrf_turns',results,resetVerified:false,siblingVerified:false});
}
async function replayRenderedControlledSsrf({frame,result,evidence,timeoutMs=420000}){
  const receipt=result?.results?.find(value=>value.resource==='private-policy');
  assert.ok(receipt&&replayAuthorities.has(receipt));
  const value=await frame.evaluate(async ({requestId})=>{
    const response=await fetch('/api/secureshop/v2/controlled-ssrf/run',{method:'POST',
      headers:{'content-type':'application/json'},body:JSON.stringify({resource:'private-policy',request_id:requestId})});
    return{status:response.status,body:await response.json()};
  },{requestId:receipt.requestId,timeoutMs});
  assert.equal(value.status,200);assert.equal(value.body?.resourceKind,'private-policy');
  assert.equal(value.body?.replayed,true);assert.equal(replayComparable(value.body),receipt.responseFingerprintSha256);
  const history=await evidence.verifyHistoryPreserved(receipt);assert.equal(history.historyPreserved,true);
  return Object.freeze({replayed:true,runId:receipt.runId,requestId:receipt.requestId,
    responseFingerprintSha256:receipt.responseFingerprintSha256,effectCount:history.effectCount});
}
async function verifyStaleRenderedSsrfDenied({page,origin,result}){
  const receipt=result?.results?.find(value=>value.resource==='private-policy');
  assert.ok(receipt);const authority=replayAuthorities.get(receipt);assert.ok(authority);
  const value=await page.evaluate(async ({origin,requestId,authorization,launchBearer})=>{
    const response=await fetch(`${origin}/api/secureshop/v2/controlled-ssrf/run`,{method:'POST',redirect:'error',
      credentials:'omit',headers:{accept:'application/json','content-type':'application/json',authorization,
        'x-dvaia-secureshop-launch':launchBearer},
      body:JSON.stringify({resource:'private-policy',request_id:requestId})});
    return{status:response.status};
  },{origin,requestId:receipt.requestId,...authority});
  assert.equal(value.status,401);
  return Object.freeze({staleLaunchHttpDenied:true});
}
module.exports={createRenderedSsrfEvidence,runRenderedControlledSsrf,replayRenderedControlledSsrf,
 verifyStaleRenderedSsrfDenied,_internals:{clickWithBridgeResponseTap,readBridgeResponseTap,closeBridgeResponseTap}};
