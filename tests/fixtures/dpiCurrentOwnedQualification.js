'use strict';
const assert=require('node:assert/strict'),path=require('node:path'),{randomUUID}=require('node:crypto'),C=require('./dpiCurrentOwnedContractV2');
const WORKSHOP='direct_prompt_injection';
function bindFixedDecoder(decoder,{request,response,runId,ownerId,generation,effects}){
 assert(decoder?.receipt,'Fixed decoder receipt required');
 const ownerKey=JSON.stringify(['DPI',String(ownerId)]),decodeEffects=effects.filter(effect=>effect.effect_key.includes(':dpi-decode:'));
 assert.equal(decodeEffects.length,1,'Exactly one owned decode effect required');
 assert.equal(decoder.runId,runId);assert.equal(decoder.ownerKey,ownerKey);assert.equal(decoder.generation,String(generation));
 assert.equal(decoder.receipt.runId,runId);assert.equal(decoder.receipt.ownerKey,ownerKey);assert.equal(decoder.receipt.generation,String(generation));
 assert.equal(decoder.receipt.effectKey,decodeEffects[0].effect_key);
 assert.equal(decodeEffects[0].run_id,runId);assert.equal(decodeEffects[0].owner_key,ownerKey);assert.equal(String(decodeEffects[0].generation),String(generation));assert.equal(decodeEffects[0].status,'completed');
 assert.equal(require('../../server/agent-runtime/dpiDecoderEvidence').validateDecoderEvidence(decoder,request,response,'fixed'),false);
 return true;
}
async function qualify({pools,transport,ports,evidence,persist}){
 const [pool,migration,lease]=pools,api=require('../../server/database/postgres/identityRepository');
 await api.initializeIdentityRepository(pool,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
 const identity=api.createIdentityRepository(pool),adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(pool),config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(pool);
 const users={},sessions={};for(const who of ['owner','sibling']){users[who]=await identity.createUser({username:'dpi-owned-'+who,email:'dpi-owned-'+who+'@fixture.invalid',passwordHash:await require('bcryptjs').hash(require('node:crypto').randomUUID(),4)});sessions[who]=await adapter.createSession(await identity.findCredentialById(users[who].id),{get:()=>null,ip:'127.0.0.1'});}
 await config.setExerciseVisibility(WORKSHOP,true,users.owner.id);for(const id of C.IDS)await config.setObjectiveVisibility(WORKSHOP,id,true,users.owner.id);
 const transcripts=[],captures=[],actors=[];const save=()=>require('./boundedJsonArtifact').saveBounded(path.join(evidence,'canonical-dpi-evidence.json'),{captures,transcripts,actors});
 const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:C.MODEL,baseURL:transport.judgeUrl}),observeExecutionTranscript:t=>{transcripts.push(t);save();}});
 const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool),completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress,judge});
 const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(pool,{leasePool:lease});
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'DPI',ledger,defaultTimeoutMs:C.TOTAL.turnMs});
 const progressService=require('../../server/services/promptInjectionProgressService').createPostgresPromptInjectionProgressService({pool,progress,config});
 const ai=require('../../server/services/multiProviderAIService'),original=ai.chatWithMessages;
 // Observation wrapper preserves receiver, arguments, result, exception and real proof creation.
 ai.chatWithMessages=async function(messages,options){const row={messages:structuredClone(messages),result:null};actors.push(row);try{const result=await Reflect.apply(original,this,[messages,options]);row.result=structuredClone(result);save();return result;}catch(error){row.failure=true;save();throw error;}};
 const express=require('express'),app=express();app.use(express.json({limit:'128kb'}));app.use(require('../../server/middleware/adminAuth').authenticateToken);
 app.use(require('../../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({progressService,completionService:completion,runCoordinator:coordinator}));
 const records=async()=>(await pool.query('SELECT to_jsonb(j) judgment,to_jsonb(p) packet_record FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 ORDER BY j.evaluation_id',[users.owner.id])).rows;
 const completed=async who=>(await pool.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id',[users[who].id,WORKSHOP])).rows;
    const modeRevision=async userId=>BigInt((await pool.query("SELECT revision::text AS revision FROM workshop_platform.revisions WHERE scope_type='user' AND scope_key=$1 AND category='workshop_mode'",[String(userId)])).rows[0]?.revision||'0');
    const sibling=async()=>({generation:String(await progress.getGeneration(users.sibling.id,WORKSHOP)),modeScope:await progress.getEvaluationScope(users.sibling.id,WORKSHOP),modeRevision:String(await modeRevision(users.sibling.id)),completed:await completed('sibling'),receipts:(await pool.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[users.sibling.id])).rows});
 const ux=process.env.DPI_CURRENT_SELECTOR===C.UX_MODE;
 const retained=[C.RETAINED_FOUR,C.RETAINED_FIXED,C.RETAINED_RETRY,C.UX_MODE].includes(process.env.DPI_CURRENT_SELECTOR);
 let server;const result={technicalPassed:false,semanticQualified:false,allObjectivesCreditQualified:false,installedWrites:false,turns:[],siblingScope:'Empty sibling isolation only; populated sibling preservation remains unqualified',scope:'Actual route/actor/Judge evidence; current grading containment retained; no rendered proof',...(retained?{selector:process.env.DPI_CURRENT_SELECTOR,actorAchievement:'unreviewed'}:{}),...(ux?{modeTransitions:[]}: {})};
 try{
  server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);const base='http://127.0.0.1:'+server.address().port;
  async function request(route,body){const response=await fetch(base+route,{method:'POST',headers:{authorization:'Bearer '+sessions.owner.token,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(route==='/chat'?C.TOTAL.turnMs+5000:15000)});return {status:response.status,body:await response.json()};}
  const siblingBefore=await sibling();let prior=null,selectedMode='vuln';
  for(const item of C.cases()){
   if(prior&&!ux&&(item.objective!==prior.objective||item.kind==='negative')){const old=await records(),generation=BigInt(await progress.getGeneration(users.owner.id,WORKSHOP));const reset=await request('/progress/reset',{});assert.equal(reset.status,200);assert.equal(BigInt(await progress.getGeneration(users.owner.id,WORKSHOP)),generation+1n);assert.deepEqual(await completed('owner'),[]);assert.deepEqual(await records(),old);assert.deepEqual(await sibling(),siblingBefore);}
   if(retained){const targetMode=item.mode||'vuln';if(targetMode!==selectedMode){
      const old=ux?await records():null,done=ux?await completed('owner'):null,beforeScope=ux?await progress.getEvaluationScope(users.owner.id,WORKSHOP):null,beforeRevision=ux?await modeRevision(users.owner.id):null;
      const switched=await request('/mode',{mode:targetMode});assert.equal(switched.status,200);assert.equal(switched.body.mode,targetMode);
      if(ux){
       const afterScope=await progress.getEvaluationScope(users.owner.id,WORKSHOP),afterRevision=await modeRevision(users.owner.id);
       assert.equal(beforeScope.mode,selectedMode);assert.equal(afterScope.mode,targetMode);assert.equal(afterScope.generation,beforeScope.generation);
       assert.notEqual(afterScope.modeStamp,beforeScope.modeStamp);assert(afterRevision>beforeRevision);
       await assert.rejects(receipts.beginEvaluation({userId:users.owner.id,evaluationId:randomUUID(),workshopKey:WORKSHOP,objectiveId:'interact',family:'DPI',scenario:'aws_assistant',rubricVersion:'dpi-mode-stale-probe-v1',evidenceDigest:C.sha(JSON.stringify([beforeScope.mode,beforeScope.modeStamp])),runId:null,mode:beforeScope.mode,expectedGeneration:beforeScope.generation,expectedMode:beforeScope.mode,expectedModeStamp:beforeScope.modeStamp}),error=>error?.code==='MODE_CHANGED');
       assert.deepEqual(await records(),old);assert.deepEqual(await completed('owner'),done);assert.deepEqual(await sibling(),siblingBefore);
       result.modeTransitions.push({from:selectedMode,to:targetMode,generationBefore:String(beforeScope.generation),generationAfter:String(afterScope.generation),modeStampBefore:beforeScope.modeStamp,modeStampAfter:afterScope.modeStamp,revisionBefore:String(beforeRevision),revisionAfter:String(afterRevision),staleGradeDenied:true,completedObjectiveIds:done.map(row=>row.objective_id)});await persist(result);
      }
     selectedMode=targetMode;
    }const mode=await fetch(base+'/mode',{headers:{authorization:'Bearer '+sessions.owner.token}});assert.equal(mode.status,200);assert.equal((await mode.json()).mode,targetMode);}
   const before=await records(),beforeCompleted=ux?await completed('owner'):null,beforeRuns=retained?await ledger.listRuns(JSON.stringify(['DPI',String(users.owner.id)])):[],actorStart=actors.length,transcriptStart=transcripts.length,generation=String(await progress.getGeneration(users.owner.id,WORKSHOP));
   transport.beginCase(item.id);let response;try{response=await request('/chat',{userMessage:item.message,activeObjectiveId:item.objective});}finally{await transport.endCase();}
   const after=await records(),fresh=after.filter(r=>!before.some(b=>b.judgment.evaluation_id===r.judgment.evaluation_id));
   const newRuns=retained?(await ledger.listRuns(JSON.stringify(['DPI',String(users.owner.id)]))).filter(r=>!beforeRuns.some(b=>b.runId===r.runId)):[];
   const capture={...item,ownerId:String(users.owner.id),generation,status:response.status,body:response.body,actor:actors.slice(actorStart),transcripts:transcripts.slice(transcriptStart),records:fresh,runId:response.body.judgment?.runId??fresh[0]?.judgment.run_id??newRuns[0]?.runId??null};captures.push(capture);save();
   assert([200,500,503].includes(capture.status));assert.deepEqual(after.filter(r=>before.some(b=>b.judgment.evaluation_id===r.judgment.evaluation_id)),before);
   const rows=transport.snapshot().calls.filter(r=>r.caseId===item.id);
   const summary={id:item.id,objective:item.objective,status:capture.status,verdict:capture.body.judgment?.verdict??'unavailable',disposition:fresh[0]?.judgment.disposition??null,actualActorCalls:rows.filter(r=>r.kind==='actor').length,actualJudgeCalls:rows.filter(r=>r.kind==='judge').length,...(retained?{actualReviewCalls:rows.filter(r=>r.kind==='review').length}:{}),outputLimited:rows.some(r=>r.kind!=='tags'&&r.doneReason==='length'),qualified:false};
   let actorCalls=[],reviewCalls=[],wireReviews=[];
   if(retained){
    assert.equal(newRuns.length,1,'One owner-scoped run per retained case');assert(capture.runId);capture.run=await ledger.getRun(capture.runId,JSON.stringify(['DPI',capture.ownerId]));
    capture.effects=(await pool.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 ORDER BY effect_key',[capture.runId,JSON.stringify(['DPI',capture.ownerId])])).rows;save();
    assert.equal(String(capture.run.generation),generation);assert.equal(capture.run.provider,'ollama');assert.equal(capture.run.model,C.MODEL);assert.equal(capture.run.decisionSource,'model');
    const policy=require('../../server/agent-runtime/dpiPublicationDefense').POLICY;
    actorCalls=capture.actor.filter(call=>call.messages[0]?.content!==policy);reviewCalls=capture.actor.filter(call=>call.messages[0]?.content===policy);
    const wireActors=rows.filter(r=>r.kind==='actor');wireReviews=rows.filter(r=>r.kind==='review');assert(wireActors.length>0);assert.equal(wireActors.length,actorCalls.length);assert.equal(wireReviews.length,reviewCalls.length);
    const binder=require('./dpiCurrentOwnedWireBinding');for(const [index,actor]of actorCalls.entries()){const row=wireActors[index],raw=C.responseText(row);assert.deepEqual(JSON.parse(row.request).messages,binder.wireMessages(actor.messages));assert.equal(raw.text,actor.result?.response);assert.equal(actor.result?.provider,'ollama');assert.equal(actor.result?.model,C.MODEL);assert.notEqual(actor.result?.mocked,true);assert.notEqual(actor.result?.fallback,true);}
    assert.equal(actorCalls[0].messages.at(-1).content,item.message);summary.actorProvenance=true;
    const ownerKey=JSON.stringify(['DPI',capture.ownerId]);const ownedEffect=e=>e.status==='completed'&&e.owner_key===ownerKey&&e.run_id===capture.runId&&String(e.generation)===generation;
    summary.effectProvenance=item.objective==='obfuscation'
     ?capture.effects.length===(item.mode==='fixed'?2:1)&&capture.effects.every(ownedEffect)&&capture.effects.filter(e=>e.effect_key.includes(':dpi-decode:')).length===1&&capture.effects.filter(e=>e.effect_key.includes(':dpi-publication:')).length===(item.mode==='fixed'?1:0)
     :capture.effects.length===0;
    summary.actorComplete=wireActors.every(row=>row.doneReason==='stop');
    summary.actorOutcome={assessment:'unreviewed',response:actorCalls.at(-1).result.response,effects:capture.effects.length,mode:item.mode||'vuln'};save();
   }
   result.turns.push(summary);await persist(result);
   if(capture.status===200){
    assert.equal(fresh.length,1);const {judgment:j,packet_record:p}=fresh[0];assert.equal(j.evaluation_id,capture.body.judgment.evaluationId);assert.equal(j.run_id,capture.runId);assert.equal(String(j.user_id),capture.ownerId);assert.equal(j.family,'DPI');assert.equal(j.scenario,'aws_assistant');assert.equal(j.objective_id,item.objective);assert.equal(j.verdict,capture.body.judgment.verdict);
    if(!retained){capture.run=await ledger.getRun(capture.runId,JSON.stringify(['DPI',capture.ownerId]));capture.effects=(await pool.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 ORDER BY effect_key',[capture.runId,JSON.stringify(['DPI',capture.ownerId])])).rows;save();}
    assert.equal(String(capture.run.generation),generation);assert.equal(capture.run.provider,'ollama');assert.equal(capture.run.model,C.MODEL);assert.equal(capture.run.decisionSource,'model');
    const packet=typeof p.packet==='string'?JSON.parse(p.packet):p.packet;const binder=require('./dpiCurrentOwnedWireBinding');
    if(item.mode==='fixed'&&item.objective==='obfuscation'){
     const proof=require('../../server/agent-runtime/dpiPolicyBinding').admitPolicyBinding(packet).proof;
     assert.deepEqual(proof.policy,require('../../server/agent-runtime/dpiPolicyContract').selectPolicy({objectiveId:item.objective,mode:'fixed'}));
     const decoder=packet.evidence.find(x=>x.id==='owned_decoder')?.content;
     bindFixedDecoder(decoder,{request:item.message,response:actorCalls.at(-1).result.response,runId:capture.runId,ownerId:capture.ownerId,generation,effects:capture.effects});
     const audit=packet.evidence.find(x=>x.id==='fixed_publication_audit')?.content;assert(audit?.receipt);assert.equal(audit.status,capture.body.publication?.status);assert.equal(audit.runId,capture.runId);assert.equal(audit.ownerKey,JSON.stringify(['DPI',capture.ownerId]));assert.equal(audit.generation,generation);
     assert.equal(audit.receipt.effectKey,capture.effects.find(e=>e.effect_key.includes(':dpi-publication:'))?.effect_key);
     assert.equal(audit.attempts.length,wireReviews.length);for(const [index,row]of wireReviews.entries()){const output=C.responseText(row),attempt=audit.attempts[index];assert.equal(output.text,attempt.raw);assert.equal(attempt.responseSha256,C.sha(output.text));assert.equal(attempt.provider,'ollama');assert.equal(attempt.model,C.MODEL);assert.deepEqual(JSON.parse(row.request).messages,binder.wireMessages(reviewCalls[index].messages));}
     summary.reviewProvenance=wireReviews.length>0&&wireReviews.every(row=>row.doneReason==='stop');summary.publicationStatus=audit.status;
     summary.actorBinding={actorCalls:actorCalls.length,effects:capture.effects.length};
    }else summary.actorBinding=binder.bindActor(capture,rows,packet,capture.effects,{requirePolicyBinding:true});
    if(item.mode==='fixed'){
     const policy=require('../../server/agent-runtime/dpiPolicyContract');
     assert.deepEqual(capture.body.selectedLesson,policy.selectedLesson(policy.selectPolicy({objectiveId:item.objective,mode:'fixed'})));
    }
    assert.equal(capture.transcripts.length,1);summary.judgeBinding=binder.bindTranscript(capture.transcripts[0],rows,p);assert.equal(capture.transcripts[0].outcome.value.verdict,j.verdict);
    const actual=await completed('owner'),awarded=['awarded','already_complete'].includes(j.disposition);assert.equal(actual.some(x=>x.objective_id===item.objective),awarded||Boolean(beforeCompleted?.some(x=>x.objective_id===item.objective)));
    if(j.disposition==='grading_unqualified')assert(!actual.some(x=>x.objective_id===item.objective));
    summary.qualified=ux?!summary.outputLimited&&j.verdict==='pass'&&(item.id==='interact:fixed1'?j.disposition==='threshold_pending':awarded)
      :!retained&&!summary.outputLimited&&(item.kind==='negative'?j.verdict==='fail'&&!awarded:j.verdict==='pass');
    if(ux)summary.completedAfter=(await completed('owner')).map(row=>row.objective_id);
   }else{assert.equal(fresh.filter(r=>['awarded','already_complete'].includes(r.judgment.disposition)).length,0);assert.deepEqual(await completed('owner'),ux?beforeCompleted:[]);}
   if(retained&&!ux)assert.deepEqual(await completed('owner'),[],'Deferred DPI grading must not award credit');
   assert.deepEqual(await sibling(),siblingBefore);prior=item;save();await persist(result);
  }
  const finalHistory=await records(),finalGeneration=BigInt(await progress.getGeneration(users.owner.id,WORKSHOP));assert.equal((await request('/progress/reset',{})).status,200);assert.equal(BigInt(await progress.getGeneration(users.owner.id,WORKSHOP)),finalGeneration+1n);assert.deepEqual(await completed('owner'),[]);assert.deepEqual(await records(),finalHistory);assert.deepEqual(await sibling(),siblingBefore);
  if(retained){assert.equal((await request('/mode',{mode:'vuln'})).status,200);const mode=await fetch(base+'/mode',{headers:{authorization:'Bearer '+sessions.owner.token}});assert.equal((await mode.json()).mode,'vuln');}
  result.resetHistorySiblingPreserved=true;result.technicalPassed=!retained||result.turns.every(x=>x.actorProvenance&&x.effectProvenance&&x.actorComplete&&(x.id!=='obfuscation:fixed'||x.reviewProvenance)
    &&(!ux||(x.status===200&&x.actualActorCalls>0&&x.actualJudgeCalls>0&&x.actorBinding?.actorCalls===x.actualActorCalls&&x.judgeBinding?.judgeCalls===x.actualJudgeCalls)));
  result.semanticQualified=(!retained||ux)&&result.turns.every(x=>x.qualified);result.allObjectivesCreditQualified=false;await persist(result);return result;
 }finally{ai.chatWithMessages=original;if(server)await new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();});}
}
module.exports={qualify,WORKSHOP,bindFixedDecoder};
