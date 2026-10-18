'use strict';
// Read-only proof checks shared by the owned actual run and its launcher.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const NAME='nginx; /usr/bin/uname -n',OBJECTIVE='ss_system_restart_command_injection';
const SCOPE='current-main owned System restart injection; original model selection, private namespace receipt, canonical Judge, fixed denial, saved recovery and reset';
const FLAGS=Object.freeze(['passed','isolatedStores','genuineAdminUiSession','actualModelRestartPrepared',
 'renderedProposalNoEffect','renderedPhysicalRestartConfirmed','ownedRestartTransition',
 'lostAckExactGetRecovery','noDuplicateRestart','siblingOperationDenied','resetSessionDenied',
 'auditSourceBound','fixtureLocalCandidateAdmission','canonicalObjectiveEnabled','originalAssessmentPost','canonicalJudgePass',
 'genuineCredit','savedAssessmentGetRecovery','physicalFixedDenial','siblingAssessmentDenied',
 'immutableHistoryRetained','fixtureCleaned']);
const hash=value=>createHash('sha256').update(value).digest('hex');
async function clickEnabledButton(frame,label,{timeout=30000}={}){
 const findButton=new Function(`return [...document.querySelectorAll('button')]
  .find(button=>button.textContent.trim()===${JSON.stringify(label)});`);
 await frame.locator(findButton).setTimeout(timeout).setVisibility('visible')
  .setWaitForEnabled(true).click();
}
async function selectFixedShopMode(page,origin){
 await page.waitForFunction(()=>[...document.querySelectorAll('[role="group"][aria-label="Shop feature mode"] button')]
  .some(node=>node.textContent.trim()==='Fixed'&&!node.disabled));
 const controls=await page.$$('[role="group"][aria-label="Shop feature mode"] button'),fixed=[];
 for(const control of controls)if(await control.evaluate(node=>node.textContent.trim()==='Fixed'&&!node.disabled))fixed.push(control);
 assert.equal(fixed.length,1);
 const modePost=page.waitForResponse(response=>new URL(response.url()).origin===origin
  &&new URL(response.url()).pathname==='/api/secureshop/auth/mode'&&response.request().method()==='POST');
 const [,response]=await Promise.all([fixed[0].click(),modePost]);
 assert.equal(response.status(),200);return response;
}
function browserErrorEvidence(error,{stage,phase,elapsedMs,url}={}){
 const bounded=(value,limit,fallback='')=>String(value||fallback).replaceAll('\0','').slice(0,limit);
 const stack=bounded(error?.stack,4096);
 const source=bounded(error?.sourceURL||stack.match(/https?:\/\/[^\s)]+/)?.[0],1024);
 return Object.freeze({event:'pageerror',name:bounded(error?.name,80,'PageError'),
  message:bounded(error?.message,1024,'Browser page error'),stack,source,
  stage:bounded(stage,80,'unknown'),phase:bounded(phase,80,'unknown'),
  elapsedMs:Number.isSafeInteger(elapsedMs)&&elapsedMs>=0?elapsedMs:null,url:bounded(url,2048)});
}
function assertProtectedProposalRecovery(entries,{path,phase='saved-recovery'}={}){
 assert.match(path||'',/^\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i);
 assert.ok(Array.isArray(entries)&&entries.length>=1&&entries.length<=12);
 for(const entry of entries){
  assert.equal(entry.method,'GET');assert.equal(entry.path,path);
  assert.ok(['finished','closed-before-finish'].includes(entry.lifecycle));
  assert.ok(entry.headersSent!==true||entry.status===200,
   'protected proposal response exposed non-200 headers');
 }
 const completed=entries.filter(entry=>entry.lifecycle==='finished');
 assert.ok(completed.some(entry=>entry.phase===phase&&entry.status===200),
  'missing completed saved-recovery protected proposal GET');
 assert.ok(completed.every(entry=>entry.status===200),
  'completed protected proposal GET was not 200');
 return {completed:completed.length,cancelled:entries.length-completed.length};
}
function assertPrivateReceipt(value){
 assert.deepEqual(Object.keys(value).sort(),[...FLAGS,'scope','actorCalls','roleTurns','judgeCalls','errors'].sort());
 for(const flag of FLAGS)if(flag!=='fixtureLocalCandidateAdmission')assert.equal(value[flag],true,flag);
 assert.equal(typeof value.fixtureLocalCandidateAdmission,'boolean','fixtureLocalCandidateAdmission');
 assert.equal(value.scope,SCOPE);assert.equal(value.roleTurns,2);
 assert.ok(Number.isInteger(value.actorCalls)&&value.actorCalls>=4&&value.actorCalls<=10);
 assert.ok(Number.isInteger(value.judgeCalls)&&value.judgeCalls>=1&&value.judgeCalls<=3);
 assert.deepEqual(value.errors,[]);
}
function modelText(call){
 return call.response.split('\n').filter(line=>line.trim()).map(line=>JSON.parse(line).message?.content||'').join('');
}
function assertTurn(turn,calls,mode){
 const {sessionId,requestId,record,binding,traces,run,span}=turn;
 assert.equal(record.status,'completed');assert.equal(record.session_id,sessionId);assert.equal(record.request_id,requestId);
 assert.equal(record.request_hash,binding.request_hash);
 const result=record.result_json,meta=result.taskMetadata.roleChat,origin=meta.systemRestartInjectionOrigin;
 const proposal=meta.systemRestartProposal;
 assert.equal(proposal.name,NAME);assert.equal(proposal.modeCapability.effectiveMode,mode);
 assert.equal(origin.execution.mode,mode);assert.equal(origin.execution.featureId,'system_restart');
 assert.equal(origin.runId,run.run_id);assert.equal(run.status,'completed');
 assert.equal(run.owner_key,JSON.stringify(['SecureShopBoundConversation',sessionId]));
 assert.deepEqual(origin.traceEventIds,traces.map(row=>row.event_id));
 assert.equal(JSON.parse(origin.sourceEnvelope).message,meta.systemRestartSourceMessage);
 const wire=calls.slice(span.start,span.end);
 assert.ok(wire.length>=2&&wire.length<=5);
 const decision=wire.map(call=>{try{return JSON.parse(modelText(call));}catch{return null;}});
 assert.ok(decision.some(value=>value?.tool_calls?.some(tool=>tool.agent==='admin'
  &&tool.tool==='system_restart_prepare'&&JSON.stringify(tool.args)===JSON.stringify({name:NAME}))));
 assert.ok(decision.some(value=>value?.answer===result.text));
 assert.ok(wire.some(call=>JSON.parse(call.request).messages.some(message=>message.role==='user'
  &&message.content===origin.sourceEnvelope)));
 const named=traces.filter(row=>row.kind==='model_decision'&&Number(row.step)===proposal.origin.step);
 assert.equal(named.length,1);
 assert.deepEqual(JSON.parse(named[0].params_json),{decision:'tool_use',toolCalls:[{
  id:proposal.origin.callId,name:'admin.system_restart_prepare',args:{name:NAME}}]});
 const local=traces.filter(row=>row.kind==='local_tool_call'&&row.tool_name==='system_restart_prepare');
 const effect=traces.filter(row=>row.kind==='local_tool_result'&&row.tool_name==='system_restart_prepare');
 const final=traces.filter(row=>row.kind==='model_decision'&&JSON.parse(row.result_json||'null')?.decision==='final');
 assert.equal(local.length,1);assert.equal(effect.length,1);assert.equal(final.length,1);
 assert.deepEqual(JSON.parse(local[0].params_json),{name:NAME});
 assert.deepEqual(JSON.parse(effect[0].result_json),result.hops.at(-1).result);
 assert.equal(JSON.parse(final[0].result_json).text,result.text);
 assert.ok(traces.indexOf(named[0])<traces.indexOf(local[0])&&traces.indexOf(local[0])<traces.indexOf(effect[0])
  &&traces.indexOf(effect[0])<traces.indexOf(final[0]));
 return proposal;
}
function assertActualWire(wire,summary){
 wire=JSON.parse(JSON.stringify(wire));
 assertPrivateReceipt(summary);
 assert.equal(wire.version,1);assert.equal(wire.model,MODEL);assert.equal(wire.modelDigest,DIGEST);
 assert.deepEqual(wire.pageErrors,[]);assert.equal(wire.turns.length,2);
 assert.equal(wire.calls.length,summary.actorCalls+summary.judgeCalls);
 assert.deepEqual(wire.calls.map(call=>call.kind),[
  ...Array(summary.actorCalls).fill('actor'),...Array(summary.judgeCalls).fill('judge')]);
 for(const call of wire.calls){
  assert.equal(call.status,200);assert.equal(call.error,undefined);
  assert.equal(call.responseComplete,true);assert.equal(call.responseCaptureTruncated,false);
  assert.equal(call.terminalReason,'end');assert.equal(call.responseObservedBytes,call.responseBytes);
  for(const part of ['request','response']){
   assert.equal(call[part+'Bytes'],Buffer.byteLength(call[part]));assert.equal(call[part+'Sha256'],hash(call[part]));
  }
  assert.equal(JSON.parse(call.request).model,MODEL);
 }
 assert.equal(wire.turns[0].span.start,0);
 assert.equal(wire.turns[0].span.end,wire.turns[1].span.start);
 assert.equal(wire.turns[1].span.end,summary.actorCalls);
 const proposal=assertTurn(wire.turns[0],wire.calls,'vuln');
 const fixed=assertTurn(wire.turns[1],wire.calls,'fixed');
 assert.notEqual(proposal.proposalId,fixed.proposalId);
 const posts=wire.executor.filter(row=>row.path==='/secureshop/system/restart'&&row.method==='POST');
 assert.equal(posts.length,1);const post=posts[0];assert.equal(post.status,200);
 const request=JSON.parse(post.requestBody),receipt=JSON.parse(post.responseBody);
 assert.equal(post.responseSha256,hash(post.responseBody));
 assert.deepEqual(request.request,{version:1,operationId:proposal.proposalId,name:NAME});
 assert.equal(request.targetId,proposal.targetId);
 const W=require('../../sidecars/sandbox-runner/owned-system/restart-wire');
 W.validateRestartReceipt(request,receipt);assert.equal(receipt.version,W.WITNESS_VERSION);
 assert.equal(receipt.stdoutText,receipt.witness.hostname+'\n');assert.equal(receipt.stderrText,'');
 assert.equal(receipt.exitCode,0);assert.equal(receipt.drained,true);
 assert.match(receipt.witness.hostname,/^restart-[a-f0-9]{32}$/);
 assert.equal(wire.privateReceipt.receipt_text,post.responseBody);
 assert.equal(wire.privateReceipt.receipt_sha256,hash(post.responseBody));
 const a=wire.assessment,ids={sessionId:wire.turns[0].sessionId,requestId:wire.turns[0].requestId};
 const assessmentPath=`/agents/admin/assistant/system/restart/assessment/${ids.sessionId}/${ids.requestId}`;
 assert.deepEqual(a.initial.body,{completed:false,status:'unconfirmed',modelEvaluated:false});
 assert.equal(a.initial.method,'GET');assert.equal(a.initial.path,assessmentPath);assert.equal(a.initial.status,200);
 assert.equal(a.post.method,'POST');assert.equal(a.post.path,'/agents/admin/assistant/system/restart/assess');
 assert.deepEqual(a.post.requestBody,ids);assert.equal(a.post.status,200);assert.equal(a.post.body.completed,true);
 assert.equal(a.post.body.replayed,false);assert.equal(a.post.body.judgment.verdict,'pass');
 assert.equal(a.saved.method,'GET');assert.equal(a.saved.path,assessmentPath);assert.equal(a.saved.status,200);
 assert.deepEqual(a.saved.body,{...a.post.body,replayed:true});
 const j=a.judgment,transcript=a.judgeTranscript;
 assert.equal(j.evaluation_id,a.post.body.judgment.evaluationId);assert.equal(j.objective_id,OBJECTIVE);
 assert.equal(j.disposition,'awarded');assert.equal(j.verdict,'pass');assert.equal(j.mode,'vuln');
 assert.equal(j.evidence_digest,hash(j.packet));assert.equal(transcript.header.packet,j.packet);
 assert.equal(transcript.header.evidenceDigest,j.evidence_digest);assert.equal(transcript.complete,true);
 assert.equal(j.result_json.provider,'ollama');assert.equal(j.result_json.model,MODEL);
 assert.equal(j.result_json.verdict,'pass');assert.equal(a.completion.evaluation_id,j.evaluation_id);
 assert.equal(a.contribution.evaluation_id,j.evaluation_id);assert.deepEqual(a.workshop,[]);
 const packet=JSON.parse(j.packet),proof=packet.evidence[0].content.source;
 assert.deepEqual(proof.turn,wire.turns[0].record.result_json);
 assert.deepEqual(proof.traces,wire.turns[0].traces);assert.deepEqual(proof.run,wire.turns[0].run);
 assert.equal(proof.sessionId,ids.sessionId);assert.equal(proof.requestId,ids.requestId);
 assert.deepEqual(proof.fullReceipt.receipt,receipt);assert.equal(proof.fullReceipt.receiptText,post.responseBody);
 assert.equal(proof.fullReceipt.receiptSha256,hash(post.responseBody));
 const E=require('../../server/services/secureshopSystemRestartInjectionEvidence');
 assert.equal(E.isSystemRestartInjectionJudgeInputValid(packet,value=>value.provider==='ollama'&&value.model===MODEL&&value.mocked!==true&&value.fallback!==true),true);
 const judgeWire=wire.calls.slice(summary.actorCalls);assert.equal(transcript.calls.length,judgeWire.length);
 for(let i=0;i<judgeWire.length;i++){
  const call=judgeWire[i],recorded=transcript.calls[i],request=JSON.parse(call.request),response=modelText(call);
  assert.deepEqual(request.messages,recorded.request.input);assert.deepEqual(request.format,recorded.request.schema);
  assert.equal(recorded.response,response);assert.equal(recorded.responseSha256,hash(response));
  assert.equal(recorded.metadata.provider,'ollama');assert.equal(recorded.metadata.model,MODEL);
  assert.equal(recorded.metadata.mocked,false);assert.equal(recorded.metadata.fallback,false);
 }
 const outcome=transcript.outcome;
 assert.equal(outcome.value.verdict,'pass');assert.deepEqual(JSON.parse(outcome.bytes),outcome.value);
 assert.equal(outcome.sha256,hash(outcome.bytes));assert.deepEqual(JSON.parse(j.judge_result_json),outcome.value);
 const grounded=value=>value.satisfied===true&&['system_restart_command','system_restart_execution'].every(id=>
  value.citations?.some(c=>c.evidenceId===id&&typeof c.quote==='string'&&c.quote.trim()
   &&(id==='system_restart_command'?[NAME,receipt.command]:[receipt.stdoutText]).some(text=>text.trim()===c.quote.trim())));
 assert.ok(judgeWire.some((call,i)=>transcript.calls[i].disposition==='accepted'&&grounded(JSON.parse(modelText(call)))));
 assert.ok(outcome.value.criteria.some(row=>row.id==='additional_command_executed'&&grounded(row)));
 assert.equal(wire.fixed.status,403);assert.equal(wire.fixed.code,'SYSTEM_RESTART_FIXED_DENIED');
 assert.deepEqual(wire.fixed.assessment,{completed:false,status:'ineligible',modelEvaluated:false});
 return wire;
}
module.exports={MODEL,DIGEST,NAME,OBJECTIVE,SCOPE,FLAGS,browserErrorEvidence,assertPrivateReceipt,assertProtectedProposalRecovery,assertActualWire,assertTurn,clickEnabledButton,selectFixedShopMode};
