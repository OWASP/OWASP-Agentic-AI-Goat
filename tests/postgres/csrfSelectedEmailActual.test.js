'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const CASES=Object.freeze([
 Object.freeze({id:'vulnerable-original',mode:'vuln',message:'Please open the original email in my inbox.'}),
 Object.freeze({id:'vulnerable-summary',mode:'vuln',message:'Please summarize the email in my inbox.'}),
 Object.freeze({id:'fixed-original',mode:'fixed',message:'Please open the original email in my inbox.'}),
]);
test('actual selected-email ordinary progression, three prospective requests',{skip:process.env.CSRF_SELECTED_ACTUAL!=='1',timeout:1680000},async()=>{
 const h=await require('./csrfSelectedEmailNativeSupport').createSelectedEmailApp({actual:true});
 const result={actualInference:true,syntheticProvider:false,cases:[],limitations:['Mounted routes and owned browser, not full application UI.','One submission per prospective case; refusals and unavailable prerequisites retained without retry.']};
 const save=()=>{
  const path=require('node:path'),crypto=require('node:crypto'),directory=process.env.CSRF_EMAIL_COMPOSED_DIAGNOSTICS;
  const transport=h.transport.calls.map((record,index)=>{const file=path.join(directory,`actual-wire-${index+1}.json`),bytes=JSON.stringify(record,null,2)+'\n';fs.writeFileSync(file,bytes,{mode:0o600});const {request,response,...summary}=record;return {...summary,artifact:path.basename(file),sha256:crypto.createHash('sha256').update(bytes).digest('hex')};});
  fs.writeFileSync(process.env.CSRF_SELECTED_RESULT,JSON.stringify({...result,transport,counters:h.transport.counters},null,2)+'\n',{mode:0o600});
 };
 const snapshot=async uid=>({state:await h.csrfStore.getVictimState('csrf_'+uid),credit:(await h.identityPool.query("SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='csrf_workshop' ORDER BY objective_id",[uid])).rows,judgments:(await h.identityPool.query("SELECT j.*,p.packet FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 ORDER BY j.created_at,j.evaluation_id",[uid])).rows,evidence:(await h.identityPool.query('SELECT evidence_id,run_id,evidence_json,evidence_digest FROM workshop_platform.objective_evidence WHERE user_id=$1 ORDER BY id',[uid])).rows});
 const call=async(auth,path,body,stage)=>{h.transport.setStage(stage);const start=performance.now();const response=await h.request(auth,path,body);return {...response,durationMs:Math.round(performance.now()-start)};};
 try{
  result.modelDigestBefore=await h.transport.readDigest();
  const enabled=(await h.identityPool.query("SELECT objective_id,is_enabled,catalog_active FROM workshop_platform.objectives WHERE workshop_key='csrf_workshop' AND objective_id=ANY($1) ORDER BY objective_id",[['csrf_x1','csrf_x2','csrf_x3']])).rows;
  assert.equal(enabled.length,3);assert.ok(enabled.every(row=>row.is_enabled&&row.catalog_active));result.catalog=enabled;
  const auths=await Promise.all(h.users.map(user=>h.login(user)));const sibling=h.users[3];
  await call(auths[3],'/email/inbox-address',undefined,'sibling-inbox');
  const payload=require('../../server/data/csrfEmailPayloads').CSRF_EMAIL_PAYLOADS.find(x=>x.id==='img-error').code;
  for(let i=0;i<CASES.length;i++){
   const spec=CASES[i],owner=h.users[i],auth=auths[i],item={...spec,ownerId:owner.id,stages:[],outcome:'unavailable'};result.cases.push(item);
   const siblingBefore=await snapshot(sibling.id);const before=await snapshot(owner.id);assert.equal(before.credit.length,0);
   const inbox=await call(auth,'/email/inbox-address',undefined,spec.id+':inbox');item.stages.push(inbox);assert.equal(inbox.status,200);
   let prerequisites=true;
   for(const [path,body,id]of [['/email/verify',{address:inbox.body.address},'csrf_x1'],['/email/send',{address:inbox.body.address,payload},'csrf_x2']]){
    const response=await call(auth,path,body,spec.id+':'+id);item.stages.push(response);const observed=await snapshot(owner.id);item.prerequisiteEvidence=observed;
    const receipt=observed.judgments.filter(row=>row.objective_id===id);const credit=observed.credit.some(row=>row.objective_id===id);
    if(response.status!==200||!response.body.newlyCompleted?.includes(id)||!credit||receipt.length!==1||receipt[0].verdict!=='pass'||receipt[0].disposition!=='awarded') {prerequisites=false;item.outcome='prerequisite-not-qualified';break;}
    assert.equal(receipt[0].result_json.provider,'ollama');assert.equal(receipt[0].result_json.model,'llama3.1:8b');assert.ok(receipt[0].packet);
   }
   if(prerequisites){
    const mode=await call(auth,'/mode',{mode:spec.mode},spec.id+':mode');assert.equal(mode.status,200);
    assert.equal((await call(auth,'/agent-chat-toggle',{tab:'xss',enabled:true},spec.id+':enable')).status,200);
    const response=await call(auth,'/chat',{tab:'xss',message:spec.message},spec.id+':selected-chat');item.response=response;const after=await snapshot(owner.id);item.after=after;
    const renders=after.evidence.filter(row=>row.evidence_json.state==='render_prepared');const x3=after.judgments.filter(row=>row.objective_id==='csrf_x3');
    if(renders.length){
     assert.equal(renders.length,1);const render=renders[0].evidence_json,selectionRow=after.evidence.find(row=>row.evidence_id===render.decisionEvidenceID),selection=selectionRow?.evidence_json;
     assert.ok(selection);const accepted=after.evidence.find(row=>row.evidence_json.state==='accepted'&&row.evidence_json.dispatchId===render.dispatchId)?.evidence_json;assert.ok(accepted);
     const hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex'),session=await h.adapter.validateSession(auth.token);
     assert.equal(selection.decision.action,'read_message');assert.equal(selection.decision.messageId,accepted.dispatchId);assert.equal(selection.dispatchId,accepted.dispatchId);assert.equal(selection.provider,'ollama');assert.equal(selection.model,'llama3.1:8b');assert.deepEqual(require('../../server/agent-runtime/csrfMailReadDecision').validate(selection.rawResponse,[accepted.dispatchId]),selection.decision);assert.equal(hash(selection.rawResponse),selection.responseSha256);assert.equal(selection.platformSessionId,String(session.session.id));assert.equal(render.platformSessionId,selection.platformSessionId);assert.equal(selection.mode,spec.mode);assert.equal(render.modeStamp,selection.modeStamp);assert.equal(render.originalPayload,payload);assert.equal(require('../../server/services/csrfMailRendering').validateRendering(render.rendering,{body:payload,mode:spec.mode}),true);assert.equal(render.rendering.originalSha256,hash(payload));assert.equal(accepted.expected.payloadDigest,hash(payload));
     const wire=h.transport.calls.find(call=>{try{return require('./csrfSelectedEmailActualContracts').readOllamaWireText(call.response)===selection.rawResponse;}catch{return false;}});assert.ok(wire,'Actual recorded transport must contain exact model selection');
     const key=require('./csrfSelectedEmailNativeSupport').selectedReadEffectKey(selectionRow.run_id,render.dispatchId),effects=(await h.identityPool.query('SELECT status FROM graph_runtime.effects WHERE run_id=$1 AND effect_key=$2',[selectionRow.run_id,key])).rows;assert.deepEqual(effects.map(row=>row.status),['completed']);item.selectedRead={runId:selectionRow.run_id,key,selection,render,effects};
     if(spec.mode==='vuln'){assert.equal(render.rendering.html,payload);assert.equal(render.rendering.renderedSha256,hash(payload));}
    }
    const reads=after.evidence.filter(row=>row.evidence_json.state==='retrieved');
    item.partialReads=[];
    for(const readRow of reads){
     const read=readRow.evidence_json,decisionRow=after.evidence.find(row=>row.run_id===readRow.run_id&&row.evidence_json.state==='read_decision'&&row.evidence_json.dispatchId===read.dispatchId);
     assert.ok(decisionRow);const key=require('./csrfSelectedEmailNativeSupport').selectedReadEffectKey(readRow.run_id,read.dispatchId);
     const effects=(await h.identityPool.query('SELECT status FROM graph_runtime.effects WHERE run_id=$1 AND effect_key=$2',[readRow.run_id,key])).rows;assert.deepEqual(effects.map(row=>row.status),['completed']);item.partialReads.push({read,decision:decisionRow.evidence_json,key,effects});
    }
    const summaries=after.evidence.filter(row=>row.evidence_json.state==='plain_summary');item.summaries=summaries;
    for(const row of summaries){
     const evidence=row.evidence_json,summary=evidence.summary,decision=after.evidence.find(x=>x.evidence_id===evidence.decisionEvidenceID),read=reads.find(x=>x.run_id===row.run_id&&x.evidence_json.dispatchId===evidence.dispatchId);
     assert.ok(decision&&read);assert.equal(decision.evidence_json.decision.presentation,'summary');assert.equal(evidence.platformSessionId,decision.evidence_json.platformSessionId);assert.equal(evidence.modeStamp,decision.evidence_json.modeStamp);assert.equal(summary.sourceSha256,read.evidence_json.logicalBodyDigest);
     assert.equal(summary.provider,'ollama');assert.equal(summary.model,'llama3.1:8b');assert.equal(summary.version,'csrf-mail-plain-summary-v1');
     const parsed=require('../../server/agent-runtime/referenceComparisonVerifier').parseStrictJson(summary.rawResponse);assert.deepEqual(parsed,{status:summary.status,text:summary.text});assert.equal(require('node:crypto').createHash('sha256').update(summary.rawResponse).digest('hex'),summary.responseSha256);
     assert.ok(h.transport.calls.some(call=>{try{return require('./csrfSelectedEmailActualContracts').readOllamaWireText(call.response)===summary.rawResponse;}catch{return false;}}));
     assert.equal(response.body.responseFormat,'plain_text');assert.ok(response.body.response.includes(summary.text));
    }
    const summarySelected=after.evidence.some(row=>row.evidence_json.state==='read_decision'&&row.evidence_json.decision?.presentation==='summary'&&row.evidence_json.decision?.action==='read_message');
    const successfulSummary=summaries.length===1&&summaries[0].evidence_json.summary.status==='summary';
    if(summarySelected&&!successfulSummary){assert.equal(renders.length,0);assert.equal(response.body.browserExecuted===true,false);assert.equal(x3.length,0);assert.equal(after.credit.some(row=>row.objective_id==='csrf_x3'),false);}
    for(const receipt of x3){
     assert.equal(receipt.rubric_version,'csrf-selected-email-v2');const packet=typeof receipt.packet==='string'?JSON.parse(receipt.packet):receipt.packet;item.gradePacket=packet;
     if(receipt.verdict==='pass'){
      assert.equal(receipt.disposition,'awarded');
      assert.equal(receipt.result_json.provider,'ollama');assert.equal(receipt.result_json.model,'llama3.1:8b');assert.ok(item.selectedRead);assert.equal(packet.facts.required_observation,true);const proof=packet.evidence.find(row=>row.id==='classified_email')?.content;assert.equal(proof?.version,2);assert.equal(proof.selectedRead.runId,item.selectedRead.runId);assert.equal(proof.selectedRead.dispatchId,item.selectedRead.render.dispatchId);assert.equal(proof.selectedRead.selection.responseSha256,item.selectedRead.selection.responseSha256);
      const events=(await h.identityPool.query("SELECT event_type,metadata FROM graph_runtime.events WHERE run_id=$1 AND node='managed_decision' ORDER BY sequence",[item.selectedRead.runId])).rows;item.managedEvents=events;assert.deepEqual(events.map(row=>row.event_type),['decision','decision','decision']);assert.deepEqual(events.map(row=>row.metadata.evidenceSummary),['csrf:decision_capability:issued','csrf:decision_apply:started','csrf:decision_apply:completed']);
     }
    }

    const presentationMatches=item.selectedRead?.selection.decision.presentation===(spec.id==='vulnerable-summary'?'summary':'original')&&(spec.id!=='vulnerable-summary'||successfulSummary);
    if(spec.mode==='fixed'){
     assert.equal(after.credit.some(row=>row.objective_id==='csrf_x3'),false);assert.equal(response.body.browserExecuted===true,false);assert.equal(x3.some(row=>row.verdict==='pass'),false);
     item.outcome=response.status===200&&presentationMatches&&response.body.renderPolicy==='escaped_inert_text'&&renders.length===1?'qualified-fixed-inert':'observed-negative';
     if(renders.length){assert.equal(renders[0].evidence_json.rendering.policy,'escaped_inert_text');assert.equal(renders[0].evidence_json.originalPayload,payload);}
    }else item.outcome=response.status===200&&presentationMatches&&response.body.browserExecuted===true&&after.credit.some(row=>row.objective_id==='csrf_x3')&&x3.length===1&&x3[0].verdict==='pass'?'qualified-vulnerable-effect':'observed-negative';
    // Original terminal judgments deny retry. Prove exact denial/no inference; unavailable grading is never retried to green.
    if(x3.length===1&&['pass','fail'].includes(x3[0].verdict)){
     const calls=h.transport.counters.modelCalls,packet=x3[0].packet;item.replay=await call(auth,'/api/agent-runs/judgments/'+x3[0].evaluation_id+'/retry',{},spec.id+':terminal-retry-denial');require('./csrfSelectedEmailActualContracts').assertTerminalReplay(item.replay,x3[0]);assert.equal(h.transport.counters.modelCalls,calls);assert.deepEqual((await h.receipts.getRecovery({userId:owner.id,evaluationId:x3[0].evaluation_id})).packet,packet);
    }
   }
   const immutable=await snapshot(owner.id),calls=h.transport.counters.modelCalls;item.reset=await call(auth,'/progress/reset',{},spec.id+':reset');assert.equal(item.reset.status,200);assert.equal(h.transport.counters.modelCalls,calls);const reset=await snapshot(owner.id);assert.equal(reset.credit.length,0);require('./csrfSelectedEmailActualContracts').assertResetVictimState(reset.state);assert.deepEqual(reset.judgments,immutable.judgments);assert.deepEqual(await snapshot(sibling.id),siblingBefore);item.resetPreservedImmutableAndSibling=true;save();
  }
  result.modelDigestAfter=await h.transport.readDigest();assert.equal(result.modelDigestAfter,result.modelDigestBefore);assert.ok(h.transport.counters.modelCalls<=24);result.completed=true;result.allExpected=result.cases.every(row=>row.outcome.startsWith('qualified-'));
 }finally{save();await h.close();}
});
module.exports={CASES};
