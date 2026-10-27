'use strict';
const {createHash}=require('node:crypto');
const {isQualifiedSecureShopModelTrace}=require('./secureshopRealModelTrace');
const {validateAuditSummaryObservation}=require('./secureshopAuditSummaryObservation');
const TOOL='audit.summarize_anomalies';
const hash=value=>createHash('sha256').update(value).digest('hex');
function arrayDigest(rows){const digest=createHash('sha256').update('[');rows.forEach((row,i)=>digest.update((i?',':'')+JSON.stringify(row)));return digest.update(']').digest('hex');}
const invalid=()=>Object.assign(new Error('Audit model chain is unverified'),{code:'AUDIT_MODEL_CHAIN_INVALID'});
function createAuditFinalFraming(requestedCount, observation, system) {
  const task=require('./secureshopAuditSummaryTaskPrompt').createAuditSummaryTaskPrompt({version:2,requestedCount});
  if(system!==undefined&&typeof system!=='string')throw invalid();
  return {version:system===undefined?1:2,taskSha256:hash(task),observationSha256:hash(observation),placement:'after-complete-observation',
    ...(system===undefined?{}:{systemSha256:hash(require('./secureshop/providers/ollamaProvider').buildFinalResponseSystem(system))})};
}
function expectedFinalFraming(framing, requestedCount, observationSha256) {
  const expected={...createAuditFinalFraming(requestedCount,''),observationSha256};
  if(framing?.version===2){
    if(typeof framing.systemSha256!=='string'||!/^[a-f0-9]{64}$/.test(framing.systemSha256))throw invalid();
    expected.version=2;expected.systemSha256=framing.systemSha256;
  }
  return expected;
}
function auditFinalFramingFromTraces(traces, requestedCount, final, observationSha256) {
  const rows=traces.filter(row=>row.kind==='audit_final_framing');
  if(!rows.length)return undefined;
  try {
    const row=rows[0], result=JSON.parse(row.result_json);
    const expected=expectedFinalFraming(result,requestedCount,observationSha256);
    const effect=traces.find(item=>item.kind==='local_tool_result');
    if(rows.length!==1||row.actor!=='supervisor'||row.step!==final.step
      ||!effect||traces.indexOf(row)<=traces.indexOf(effect)||traces.indexOf(row)>=traces.indexOf(final)
      ||JSON.stringify(result)!==JSON.stringify(expected))throw invalid();
    return result;
  }catch{throw invalid();}
}
function auditCorrectionFromTraces(traces, count, decision) {
  const markers=traces.filter(row=>row.kind==='audit_decision_protocol');
  const rows=traces.filter(row=>row.kind==='audit_decision_attempt');
  if (!markers.length && !rows.length) return undefined;
  try {
    if(markers.length!==1||markers[0].step!==decision.step||markers[0].actor!=='supervisor'
      ||markers[0].result_json!==JSON.stringify({version:1,requestedCount:count})
      ||rows.some(row=>row.step!==decision.step||traces.indexOf(row)<=traces.indexOf(markers[0])
        ||traces.indexOf(row)>=traces.indexOf(decision)))throw invalid();
    const attempts=rows.map(row=>JSON.parse(row.params_json));
    if(rows.some((row,index)=>row.actor!=='supervisor'||row.provider!==attempts[index].provider
      ||row.result_json!==JSON.stringify({model:attempts[index].model,mocked:false})))throw invalid();
    const digest=require('./secureshopAuditDecisionCorrection').verifyAuditDecisionAttempts(attempts,count);
    return {version:1,attemptsSha256:digest,attempts};
  }catch{throw invalid();}
}
function verifyAuditModelChain(chain,{runId,summary,provider,model,requestedCount,rowCount,artifacts,qualifyModel,observation}={}){
  if(chain?.kind!=='audit_model_chain'||![1,2,3].includes(chain.version)||chain.runId!==runId
      ||chain.requestedCount!==requestedCount||chain.rowCount!==rowCount
      ||chain.summarySha256!==hash(summary)||chain.messagesSha256!==artifacts.messages.sha256
      ||chain.tracesSha256!==artifacts.traces.sha256||chain.logSha256!==artifacts.log.sha256
      ||chain.sourcesSha256!==artifacts.sources.sha256||!/^([a-f0-9]{64})$/.test(chain.observationSha256))throw invalid();
  const {decision,final,terminal}=chain;
  if(chain.finalFraming!==undefined&&(chain.version!==3||JSON.stringify(chain.finalFraming)!==JSON.stringify(
    expectedFinalFraming(chain.finalFraming,requestedCount,chain.observationSha256))))throw invalid();
  if(![decision,final,terminal].every(row=>row?.actor==='supervisor'&&row.provider===provider
      &&isQualifiedSecureShopModelTrace(row,qualifyModel)&&JSON.parse(row.result_json).model===model)
      ||decision.kind!=='model_decision'||final.kind!=='model_decision'||terminal.kind!=='terminal'
      ||!Number.isSafeInteger(decision.step)||decision.step<1||final.step!==decision.step+1||terminal.step!==final.step)throw invalid();
  let selected,answer,end;
  try{selected=JSON.parse(decision.params_json);answer=JSON.parse(final.result_json);end=JSON.parse(terminal.result_json);}catch{throw invalid();}
  const call=selected?.toolCalls?.[0];
  if (chain.decisionCorrection !== undefined) {
    try {
      const correction=chain.decisionCorrection;
      if(chain.version!==3||Object.keys(correction).sort().join(',')!=='attempts,attemptsSha256,version'
          ||correction.version!==1||require('./secureshopAuditDecisionCorrection').verifyAuditDecisionAttempts(correction.attempts,requestedCount)!==correction.attemptsSha256
          ||correction.attempts.some(attempt=>attempt.provider!==provider||attempt.model!==model)
          ||JSON.stringify(JSON.parse(correction.attempts.at(-1).raw).tool_calls[0].args)!==JSON.stringify(call.args))throw invalid();
    }catch{throw invalid();}
  }
  const focused=chain.version===3;
  if(focused){try{
    if(validateAuditSummaryObservation(observation,{requestedCount})!==3||observation.row_count!==rowCount
      ||hash(JSON.stringify(observation))!==chain.observationSha256
      ||observation.source_manifest.logSha256!==chain.logSha256||observation.source_manifest.sourcesSha256!==chain.sourcesSha256
      ||observation.focus.action!==chain.focusAction||hash(JSON.stringify(observation.focus))!==chain.focusSelectionSha256)throw invalid();
  }catch{throw invalid();}}
  if(selected.decision!=='tool_use'||selected.toolCalls.length!==1||call?.name!==TOOL
      ||typeof call.id!=='string'||!call.id||Object.keys(call.args||{}).length!==(focused?2:1)||call.args.limit!==requestedCount
      ||(focused&&(typeof call.args.focus_action!=='string'||!/^[A-Za-z0-9_.:-]{1,100}$/.test(call.args.focus_action)
        ||chain.focusAction!==call.args.focus_action||!/^[a-f0-9]{64}$/.test(chain.focusSelectionSha256)))
      ||answer.decision!=='final'||answer.stopReason!=='end_turn'||answer.text!==summary
      ||end.stopReason!=='end_turn'||end.steps!==final.step||end.hops!==1
      ||chain.localEffectKey!==JSON.stringify([decision.step,call.id,TOOL]))throw invalid();
  return true;
}

// Called only in the fixed worker after its graph finishes. The projection
// binds bounded model metadata to exact full artifacts without copying the raw
// log into the parent/Judge process. It is provenance, never exploit success.
function buildAuditModelChain({manifest,messages,traces,effects,observation,result,qualifyModel}){
  let version=1;
  if(Object.hasOwn(observation,'version')){
    try{version=validateAuditSummaryObservation(observation,{requestedCount:manifest.requestedCount});}catch{throw invalid();}
  }
  const decisions=traces.filter(row=>row.kind==='model_decision'),terminals=traces.filter(row=>row.kind==='terminal');
  const calls=traces.filter(row=>row.kind==='local_tool_call'),results=traces.filter(row=>row.kind==='local_tool_result');
  if(decisions.length!==2||terminals.length!==1||traces.at(-1)!==terminals[0]||calls.length!==1||results.length!==1
      ||calls[0].agent_ns!=='audit'||calls[0].tool_name!=='summarize_anomalies'
      ||results[0].agent_ns!=='audit'||results[0].tool_name!=='summarize_anomalies'
      ||calls[0].step!==decisions[0].step||results[0].step!==decisions[0].step
      ||traces.indexOf(calls[0])<=traces.indexOf(decisions[0])||traces.indexOf(results[0])<=traces.indexOf(calls[0])
      ||traces.indexOf(decisions[1])<=traces.indexOf(results[0])
      ||traces.some(row=>['error','tool_blocked','tool_cancelled'].includes(row.kind))
      ||effects.length!==1||effects[0].status!=='completed'||effects[0].workerLocal!==true)throw invalid();
  const decisionCorrection=auditCorrectionFromTraces(traces,manifest.requestedCount,decisions[0]);
  if(decisionCorrection&&version!==3)throw invalid();
  let observed;try{observed=JSON.parse(results[0].result_json);}catch{throw invalid();}
  const exact=JSON.stringify(observation),tools=messages.filter(row=>row.role==='tool');
  let selectedArguments;
  if(version===3){try{selectedArguments=JSON.parse(decisions[0].params_json).toolCalls[0].args;}catch{throw invalid();}}
  if(observed.isError===true||observed.content?.length!==1||observed.content[0]?.text!==exact
      ||tools.length!==1||tools[0].content!==exact||messages.at(-1)?.role!=='assistant'
      ||messages.at(-1).content!==result.summary||observation.ok!==true
      ||observation.requested_count!==manifest.requestedCount||observation.row_count!==manifest.rowCount
      ||observation.source_manifest?.logSha256!==manifest.logSha256
      ||observation.source_manifest?.sourcesSha256!==manifest.sourcesSha256
      ||hash(observation.log_text)!==manifest.logSha256
      ||calls[0].params_json!==JSON.stringify(version===3?selectedArguments:{limit:manifest.requestedCount}))throw invalid();
  const chain={kind:'audit_model_chain',version,runId:manifest.runId,requestedCount:manifest.requestedCount,
    rowCount:manifest.rowCount,logSha256:manifest.logSha256,sourcesSha256:manifest.sourcesSha256,
    messagesSha256:arrayDigest(messages),tracesSha256:arrayDigest(traces),summarySha256:hash(result.summary),
    observationSha256:hash(exact),localEffectKey:effects[0].effectKey,
    ...(version===3?{focusAction:observation.focus.action,focusSelectionSha256:hash(JSON.stringify(observation.focus))}:{}),
    ...(decisionCorrection?{decisionCorrection}:{}),
    decision:decisions[0],final:decisions[1],terminal:terminals[0]};
  const finalFraming=auditFinalFramingFromTraces(traces,manifest.requestedCount,decisions[1],hash(exact));
  if(finalFraming)chain.finalFraming=finalFraming;
  verifyAuditModelChain(chain,{runId:manifest.runId,summary:result.summary,provider:result.provider,model:result.model,
    requestedCount:manifest.requestedCount,rowCount:manifest.rowCount,observation,
    qualifyModel,artifacts:{messages:{sha256:chain.messagesSha256},traces:{sha256:chain.tracesSha256},
      log:{sha256:manifest.logSha256},sources:{sha256:manifest.sourcesSha256}}});
  return Object.freeze(chain);
}
module.exports={buildAuditModelChain,verifyAuditModelChain,auditCorrectionFromTraces,createAuditFinalFraming,auditFinalFramingFromTraces};
