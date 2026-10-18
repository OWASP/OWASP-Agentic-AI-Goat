'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const sha=x=>createHash('sha256').update(x).digest('hex');
const WORKSHOP='sensitive_info_disclosure';
async function verifyCapturedHistory(captures,records){for(const c of captures)assert.deepEqual(await records(c.ownerId,c.runId),c.records,'Cohort immutable history changed');}
async function qualifyNative({cohort,pools,transport,ports,evidenceRoot,persist}){
 const [i,im,f,fm]=pools;
 const api=require('../../server/database/postgres/identityRepository');await api.initializeIdentityRepository(i,im);
 await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
 await require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(f).initialize(fm);
 const identity=api.createIdentityRepository(i),progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(i);
 const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
 const users={},sessions={};for(const who of ['owner','sibling']){users[who]=await identity.createUser({username:'policy-'+who,email:'policy-'+who+'@fixture.invalid',passwordHash:await require('bcryptjs').hash(require('node:crypto').randomUUID(),4)});sessions[who]=await adapter.createSession(await identity.findCredentialById(users[who].id),{get:()=>null,ip:'127.0.0.1'});}
 const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(i);await config.setExerciseVisibility(WORKSHOP,true,users.owner.id);for(const id of ['admin_read_logs','admin_llm_logs'])await config.setObjectiveVisibility(WORKSHOP,id,true,users.owner.id);
 const express=require('express'),app=express();app.use(express.json({limit:'128kb'}));const auth=require('../../server/routes/auth');app.use('/api/auth',auth);app.use('/api/workshop/sensitive-info',require('../../server/routes/sensitiveInfoWorkshop'));
 let server;const captures=[];
 const records=async(ownerId,runId)=>(await i.query(`SELECT to_jsonb(j) judgment,to_jsonb(p) packet_record FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.run_id=$2 ORDER BY j.evaluation_id`,[ownerId,runId])).rows;
 const completions=async who=>(await i.query('SELECT objective_id FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id',[users[who].id,WORKSHOP])).rows;
 const snapshotSibling=async()=>({generation:String(await progress.getGeneration(users.sibling.id,WORKSHOP)),completions:await completions('sibling')});
 try{
  server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);const base='http://127.0.0.1:'+server.address().port+'/api/workshop/sensitive-info';
  async function request(who,route,body){const r=await fetch(base+route,{method:'POST',headers:{authorization:'Bearer '+sessions[who].token,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(route==='/chat'?125000:15000)});assert.equal(r.status,200);return r.json();}
  return await require('./finflowPolicyQualification').qualify({cohort,persist,snapshotSibling,
   setMode:mode=>request('owner','/mode',{mode}),verifyNoCredit:async who=>assert.deepEqual(await completions(who),[]),
   chat:async({actor,message,phase,item})=>{const caseId=item.id+':'+phase;transport.beginCase(caseId);let body;try{body=await request(actor,'/chat',{userMessage:message,objectiveId:item.id});}finally{transport.endCase();}
    const runId=body.run?.runId;assert.match(runId||'',/^[a-f0-9-]{36}$/);const capture={body,ownerId:String(users[actor].id),runId,caseId,generation:String(await progress.getGeneration(users[actor].id,WORKSHOP)),records:await records(users[actor].id,runId)};captures.push(capture);require('./boundedJsonArtifact').saveBounded(path.join(evidenceRoot,'canonical-policy-evidence.json'),captures);return capture;},
   verifyCapture:async({capture:c,actor,message,item})=>{
    const run=(await i.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2',[c.runId,JSON.stringify(['FinFlow',c.ownerId])])).rows[0];
    const effects=(await i.query('SELECT owner_key,generation,run_id,effect_key,status FROM graph_runtime.effects WHERE owner_key=$1 AND generation=$2 AND run_id=$3 ORDER BY effect_key',[JSON.stringify(['FinFlow',c.ownerId]),c.generation,c.runId])).rows;
    c.run=run||null;c.effects=effects;require('./boundedJsonArtifact').saveBounded(path.join(evidenceRoot,'canonical-policy-evidence.json'),captures);
    assert(run);assert.equal(run.provider,'ollama');assert.equal(run.model,'llama3.1:8b');assert.equal(run.decision_source,'model');assert.equal(String(run.generation),c.generation);
    const rows=transport.snapshot().calls.filter(x=>x.caseId===c.caseId);const decisions=rows.filter(x=>x.kind==='generate'&&JSON.parse(x.request).format==='json');assert(decisions.length>0);for(const x of decisions)assert(JSON.parse(x.request).prompt.includes('\nRequest: '+JSON.stringify(message)));
    const awarded=(c.body.newlyCompletedObjectives||[]).includes(item.id);assert.deepEqual(c.body.newlyCompletedObjectives||[],awarded?[item.id]:[]);assert.deepEqual(await completions(actor),awarded?[{objective_id:item.id}]:[]);
    c.wireBinding=await require('./finflowPolicyWireBinding').bindAll({body:c.body,records:c.records,run,effects,rows,prompt:message,objectiveId:item.id,ownerId:c.ownerId,generation:c.generation});
    require('./boundedJsonArtifact').saveBounded(path.join(evidenceRoot,'canonical-policy-evidence.json'),captures);
    const selected=require('./finflowPolicyWireBinding').selectPublished({body:c.body,records:c.records,ownerId:c.ownerId,runId:c.runId,objectiveId:item.id});
    const relevantLog=call=>call.name==='admin_read_logs'&&call.success===true&&(item.id==='admin_llm_logs'?call.params?.log_type==='llm_requests':['access','error','audit'].includes(call.params?.log_type));
    if((c.body.toolCalls||[]).some(relevantLog))assert(selected.length>0,'Administrative effect needs canonical packet');
    let matchingAwardPair=false;
    for(const {judgment,packet} of selected){
     if(awarded){assert.equal(judgment.disposition,'awarded');assert.equal(judgment.verdict,'pass');for(const fact of packet.rubric.requiredFacts)assert.equal(packet.facts[fact],true);}
     for(const pair of packet.evidence.filter(x=>x.id.startsWith('customer_policy_log_pair_'))){
      assert.equal(pair.source,'server_observation');const {controlledLog:log,policyAction:policy,callIndex,toolEvidenceId}=pair.content;const call=c.body.toolCalls[callIndex];assert.equal(call.name,'admin_read_logs');assert.equal(call.params.log_type,log.logType);assert.equal(call.success,true);assert.equal(toolEvidenceId,'tool_'+callIndex);const persistedKey=require('./finflowPolicyWireBinding').persistedEffectKey(c.runId,callIndex,call);assert.equal(effects.filter(x=>x.effect_key===persistedKey&&x.status==='completed').length,1);
      for(const receipt of [log,policy]){assert.equal(String(receipt.ownerId),c.ownerId);assert.equal(receipt.runId,c.runId);assert.equal(String(receipt.generation),c.generation);}assert.equal(policy.requestSha256,sha(message));assert.equal(policy.policyViolation,true);assert.equal(policy.sessionRole,'customer');const expectedPolicy=require('../../server/services/finflowCustomerPolicy').customerPolicySnapshot();assert.equal(policy.policySha256,expectedPolicy.sha256);assert.equal(policy.policyVersion,expectedPolicy.version);assert.equal(policy.paramsSha256,sha(JSON.stringify(call.params)));
      const names={access:'access.log',error:'error.log',audit:'audit.log',llm_requests:'llm_requests.log'};assert(Object.hasOwn(names,log.logType));const bytes=fs.readFileSync(path.join(__dirname,'../../server/sensitive_files/logs',names[log.logType]));assert.equal(log.contentSha256,sha(bytes));assert.equal(log.byteLength,bytes.length);assert.equal(log.returnedSha256,sha(call.result));if(log.logType===item.logType)matchingAwardPair=true;
     }
     for(const [index,call]of (c.body.toolCalls||[]).entries())if(relevantLog(call))assert(packet.evidence.some(x=>x.id==='customer_policy_log_pair_'+index),'Successful administrative effect requires paired receipt even without award');
    }
    if(awarded)assert(matchingAwardPair,'Award requires exact requested log type');

   },
   resetAndVerify:async({captures:prior,sibling})=>{const before=BigInt(await progress.getGeneration(users.owner.id,WORKSHOP));await request('owner','/progress/reset',{});assert.equal(BigInt(await progress.getGeneration(users.owner.id,WORKSHOP)),before+1n);assert.deepEqual(await completions('owner'),[]);assert.deepEqual(await snapshotSibling(),sibling);await verifyCapturedHistory(captures,records);}
  });
 }finally{const outcomes=await require('./secureshopAnalyticsBrowserOwner').settleOwnership([['http',()=>server&&new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['auth',()=>auth.close()]],10000);assert(outcomes.every(x=>x.status==='fulfilled'),'Policy route cleanup unsettled');}
}
module.exports={qualifyNative,verifyCapturedHistory};
