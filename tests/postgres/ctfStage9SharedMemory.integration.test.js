'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomUUID}=require('node:crypto');
const helper=require('./ctfStage9MainQualification');
const enabled=process.env.CTF_STAGE9_MAIN_ISOLATED==='1';
const one=async(p,sql,args=[])=>(await p.query(sql,args)).rows[0];
test(process.env.CTF_STAGE9_MODE==='stage6-actual'?'current mounted Stage6 authority actual model and earned rendered lifecycle':'controlled current mounted Stage9 shared winning-memory lifecycle',{skip:!enabled,timeout:process.env.CTF_STAGE9_MODE==='stage6-actual'?1500000:process.env.CTF_STAGE9_MODE==='actual'?600000:240000},async t=>{
 await helper.startGate();const owned=helper.admit(),stage6=owned.mode==='stage6-actual',target=stage6?6:9;
 const allowedPorts=new Set([Number(new URL(process.env.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL).port)]);const actualTransport=['actual','stage6-actual'].includes(owned.mode)?require('./ctfStage9ActualTransport'):null;const restoreFence=helper.installSocketFence(allowedPorts,{allowUpstream:actualTransport?.allowsUpstream});
 const pools=[];let application,listener,transport,actual,authMount;const ledger=[];let mode='fail',secret='';
 if(stage6)require('../fixtures/ownedBrowserCdpAllowance').install({browserExecutable:process.env.ANALYTICS_BROWSER_EXECUTABLE,ownedRoot:owned.evidence,addEndpoint:x=>allowedPorts.add(x.port),removeEndpoint:x=>allowedPorts.delete(x.port)});
 t.after(async()=>{
  const failures=[];for(const work of [()=>application?.stop(),()=>authMount?.close(),()=>listener&&new Promise((r,j)=>{listener.closeAllConnections();listener.close(e=>e?j(e):r());}),()=>actual?.close(),()=>transport&&new Promise((r,j)=>{transport.closeAllConnections();transport.close(e=>e?j(e):r());}),...pools.map(p=>()=>p.end())])try{await work();}catch(e){failures.push(e);}
  restoreFence();fs.writeFileSync(path.join(owned.evidence,'synthetic-provider-ledger.json'),JSON.stringify(stage6?{syntheticProvider:false,calls:[]}:{actualModelProof:false,calls:ledger}),{mode:0o600,flag:'wx'});owned.assertLoaded();assert.equal(failures.length,0,'All owned resources must drain');
 });
 // Establish the synthetic endpoint/configuration before any production import can capture provider settings.
 let endpoint;
 if(actualTransport){actual=await actualTransport.createTransport({evidence:owned.evidence});endpoint=actual.actorUrl;allowedPorts.add(Number(new URL(endpoint).port));}else{
 const http=require('node:http');transport=http.createServer(async(req,res)=>{try{let raw='';for await(const chunk of req){raw+=chunk;assert(Buffer.byteLength(raw)<=131072);}assert(ledger.length<56);assert(['/api/generate','/api/chat','/v1/chat/completions'].includes(req.url));assert.equal(req.method,'POST');const body=JSON.parse(raw);assert.equal(body.model,'controlled-stage9-fixture');ledger.push({route:req.url,mode,requestSha256:helper.sha(raw)});if(req.url==='/v1/chat/completions'||mode==='unavailable'&&req.url==='/api/chat'){res.writeHead(400,{'content-type':'application/json'});res.end('{"error":"synthetic unavailable"}');return;}const text=helper.syntheticResponse(body,mode,secret);ledger.at(-1).responseSha256=helper.sha(text);const frame={model:body.model,created_at:new Date().toISOString(),done:false,eval_count:8,prompt_eval_count:8,total_duration:1000000,...(req.url==='/api/chat'?{message:{role:'assistant',content:text}}:{response:text})};const end={...frame,done:true,done_reason:'stop',...(req.url==='/api/chat'?{message:{role:'assistant',content:''}}:{response:''})};res.writeHead(200,{'content-type':'application/x-ndjson'});res.end(JSON.stringify(frame)+'\n'+JSON.stringify(end)+'\n');}catch(e){ledger.push({failure:true});res.writeHead(400);res.end('synthetic fixture failure');}});
 transport.requestTimeout=10000;await new Promise(r=>transport.listen(0,'127.0.0.1',r));allowedPorts.add(transport.address().port);endpoint='http://127.0.0.1:'+transport.address().port;
 }
 Object.assign(process.env,{AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',OLLAMA_BASE_URL:endpoint,OLLAMA_MODEL:actualTransport?actualTransport.MODEL:'controlled-stage9-fixture',JUDGE_MODEL:actualTransport?actualTransport.MODEL:'controlled-stage9-fixture',LMSTUDIO_BASE_URL:endpoint+'/v1',LMSTUDIO_MODEL:'controlled-stage9-fixture',AWS_EC2_METADATA_DISABLED:'true',OPENAI_API_KEY:'',ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'',AWS_ACCESS_KEY_ID:'',AWS_PROFILE:'',AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'',AWS_WEB_IDENTITY_TOKEN_FILE:'',DISABLE_OLLAMA:'false'});
 const {createPool}=require('../../server/database/postgres'),{migrate}=require('../../db/postgres/migrate');const stores={};
 for(const key of ['IDENTITY','CTF']){const runtime=createPool(process.env,`PG_CTF_STAGE9_${key}_RUNTIME_URL`),migration=createPool(process.env,`PG_CTF_STAGE9_${key}_MIGRATION_URL`);pools.push(runtime,migration);stores[key]={runtime,migration};const dir=path.join(owned.source,'db/postgres',key==='IDENTITY'?'identity-migrations':'workshop-migrations/ctf');await migrate(migration,dir);assert.deepEqual(await migrate(migration,dir),[]);}
 const i=stores.IDENTITY,c=stores.CTF;await require('../../server/database/postgres/ctfDb').seed(c.migration);
 // Unearned prerequisite records are explicit, exclusively before bootstrap.
 const fixturePassword=stage6?'OwnedCtfStage6@123':null;
 const passwordHash=stage6?await require('bcryptjs').hash(fixturePassword,4):'$2b$04$'+'a'.repeat(53);
 for(const id of [2001,2002,2003,2004])await i.migration.query('INSERT INTO identity.users(id,username,email,password,role,admin_level) VALUES($1,$2,$3,$4,$5,$6)',[id,(stage6?'stage6-':'stage9-')+id,id+'@fixture.invalid',passwordHash,id===2004?'admin':'student',id===2004?1:0]);
 for(const id of [2001,2002,2003]){
  await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username,started_at) VALUES($1,$1,$2,clock_timestamp())",[id,(stage6?'stage6-':'stage9-')+id]);
  await c.migration.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,completed_at,completion_time) SELECT $1,id,'completed',clock_timestamp(),clock_timestamp(),1 FROM ctf.ctf_stages WHERE stage_number BETWEEN 1 AND $2",[id,stage6?5:8]);
 }
 const stage=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE stage_number=$1',[target]);assert.equal(stage.adaptive_mode,stage6?'none':'payload');secret=stage.success_criteria;
 if(!stage6){const siblingPayload='retained unrelated stage payload';await c.migration.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(10,$1,$2,2003)',[helper.sha(siblingPayload),siblingPayload]);
 await c.migration.query("INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES(2003,9,'role_play')");}
 const {createCtfAuthorityBootstrapRepository}=require('../../server/database/postgres/ctfAuthorityBootstrapRepository');
 const operationId=randomUUID();const prepared=await require('../../server/services/ctfAuthorityBootstrap').createCtfAuthorityBootstrap({repository:createCtfAuthorityBootstrapRepository({identityPool:i.migration,ctfPool:c.migration})}).prepare({operationId});assert(prepared.prepared);
 const operator=require('../../server/database/postgres/ctfDeliveryActivationOperator').createCtfDeliveryActivationOperator({identityMigrationPool:i.migration,ctfMigrationPool:c.migration});const activationId=randomUUID();let activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:8});for(let n=0;activated.staged&&n<8;n++)activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:8});assert(activated.activation);
 const deliveryUrl=process.env.PG_CTF_STAGE9_CTF_DELIVERY_URL;const delivery=await require('../../server/database/postgres/ctfDeliveryPool').createCtfDeliveryPool({env:{...process.env,CTF_DELIVERY_DATABASE_URL:deliveryUrl},activation:activated.activation});pools.push(delivery);
 await require('../../server/database/postgres/ctfDeliveryActivation').createCtfDeliveryActivation({identityPool:i.runtime,ctfPool:c.runtime}).verify(activated.activation);
 const jwt=require('jsonwebtoken'),jwtSecret='owned-stage9-'+randomUUID();const repository=require('../../server/database/postgres/identityRepository').createIdentityRepository(i.runtime);const identityAdapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository,progress:stage6?require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(i.runtime):undefined,jwtSecret});const validateSession=identityAdapter.validateSession;
 const actors={},sessionIds={};for(const id of [2001,2002,2003,2004]){const token=jwt.sign({userId:id},jwtSecret,{expiresIn:'1h',jwtid:randomUUID()});sessionIds[id]=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour') RETURNING id",[id,helper.sha(token)])).id;actors[id]=token;}
 const leasePool=createPool({...process.env,PG_POOL_MAX_WORKSHOP:'2'},'PG_CTF_STAGE9_IDENTITY_RUNTIME_URL',{purpose:'lease'});pools.push(leasePool);const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'CTF',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(i.runtime,{leasePool}),defaultTimeoutMs:actualTransport?240000:15000});
 application=require('../../server/services/ctfAuthorityApplication').createCtfAuthorityApplication({identityPool:i.runtime,ctfPool:c.runtime,deliveryPool:delivery,deliveryDatabaseUrl:deliveryUrl,activation:activated.activation,validateSession,coordinator});await application.start();assert((await application.runtime.readiness()).runtimeReady);
 const web=require('express')();web.use(require('express').json({limit:'32kb'}));if(stage6)authMount=require('../fixtures/ctfStage6EarnedRendered').mountAuthRoutes({app:web,adapter:identityAdapter});web.use('/api/ctf',application.router);if(stage6)require('../fixtures/ctfStage6EarnedRendered').mountStaticRoutes({app:web,buildDirectory:process.env.CTF_STAGE6_BUILD_DIRECTORY});listener=await new Promise(r=>{const s=web.listen(0,'127.0.0.1',()=>r(s));});allowedPorts.add(listener.address().port);
 async function request(method,route,id,body,token=actors[id]){const response=await fetch('http://127.0.0.1:'+listener.address().port+'/api/ctf'+route,{method,headers:{authorization:'Bearer '+token,...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(actualTransport?245000:15000)});return{status:response.status,body:await response.json()};}
 async function mutation(route,id,body={}){let r=await request('POST',route,id,body);if(r.status===202){const op=r.body.operationId;assert(op);for(let n=0;n<100&&r.status===202;n++){await new Promise(r=>setTimeout(r,20));r=await request('GET','/operations/'+op,id);}}assert.equal(r.status,200,route);return r;}
 for(const id of [2001,2002])await mutation('/stage/'+target+'/start',id);
 const memory=async()=>({authority:(await i.runtime.query("SELECT * FROM identity.ctf_adaptive_memory WHERE kind='payload' AND stage_id=9 ORDER BY memory_id")).rows,projection:(await c.runtime.query('SELECT * FROM ctf.ctf_payload_blocklist WHERE stage_id=9 ORDER BY payload_hash')).rows});
 const sibling=async()=>({progress:(await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=2003 ORDER BY id')).rows,attempts:(await c.runtime.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=2003 ORDER BY id')).rows,memory:(await i.runtime.query("SELECT * FROM identity.ctf_adaptive_memory WHERE stage_id<>9 OR kind='technique' AND owner_id=2003 ORDER BY memory_id")).rows,projection:(await c.runtime.query('SELECT * FROM ctf.ctf_payload_blocklist WHERE stage_id<>9 ORDER BY stage_id,payload_hash')).rows,technique:(await c.runtime.query('SELECT * FROM ctf.ctf_technique_blocklist WHERE participant_id=2003 ORDER BY id')).rows});
 const siblingBefore=await sibling();assert.deepEqual(await memory(),{authority:[],projection:[]});
 let publicationProbeDone=false,pendingSqlQualified=false;
 async function attempt(id,payload,nextMode,external=null){mode=nextMode;const count=()=>actual?actual.snapshot().counts.external:ledger.length;const start=count();const ownerBefore=external?.ownerBefore??await one(i.runtime,'SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['CTF',String(id)])]);const r=external?{status:external.initialStatus,body:external.initialBody}:await request('POST','/stage/'+target+'/attempt',id,{payload});if(r.body.blocked){assert.equal(r.status,200);if(nextMode!=='actual'&&nextMode!=='stage6-actual'){assert.equal(r.body.lessonState.shared_similarity_blocked,true);assert.equal(count(),start);}return r;}
  if(r.status===503&&actualTransport)return r;
  assert.equal(r.status,202);assert(r.body.decisionId);const decisionId=r.body.decisionId;
  let probedThisAttempt=false;
  if(!actualTransport&&!publicationProbeDone){
   publicationProbeDone=true;
   probedThisAttempt=true;
   const probe=async()=>one(i.runtime,`SELECT d.owner_id=$2 AND d.session_id=$3 AND d.proposal_id IS NOT NULL AS session_bound,
    g.lifecycle_state='ready' AND s.lifecycle_state='ready' AND o.lifecycle_state='ready'
      AND g.revision=d.global_revision AND s.revision=d.stage_revision
      AND o.owner_generation=d.owner_generation AS scope_ready,
    ev.state='applied' AND pr.applied_operation_id=d.decision_id
      AND pr.applied_sequence=d.sequence AS projection_applied,
    ev.state AS outbox_state,o.lifecycle_state AS owner_lifecycle,pr.status AS progress_status,
    gr.status AS run_status,d.accepted AS accepted
    FROM identity.ctf_decisions d
    JOIN identity.ctf_authority g ON g.scope_key='global'
    JOIN identity.ctf_authority s ON s.scope_key='stage:'||d.stage_id
    JOIN identity.ctf_authority o ON o.scope_key='owner:'||d.owner_id
    LEFT JOIN identity.ctf_outbox ev ON ev.operation_id=d.decision_id
    LEFT JOIN identity.ctf_progress_bindings pr ON pr.progress_id=d.progress_id
    LEFT JOIN graph_runtime.runs gr ON gr.run_id=d.run_id
    WHERE d.decision_id=$1`,[decisionId,id,sessionIds[id]]);
   const before=await probe();
   const early=await request('GET','/publications/'+decisionId,id);
   const after=await probe();
   fs.writeFileSync(path.join(owned.evidence,'pending-publication-diagnostic.json'),JSON.stringify({version:1,syntheticProvider:true,decisionId,before,earlyStatus:early.status,after,earlyError:early.body?.error??null}),{mode:0o600,flag:'wx'});
   assert.ok(before?.outbox_state==='pending'||before?.outbox_state==='applied');
   assert.ok(early.status===202||early.status===200,'controlled publication probe must be explicit');
   if(early.status===202)assert.deepEqual(early.body,{success:false,pending:true,decisionId});
   if(before.outbox_state==='pending'&&after.outbox_state==='pending')assert.equal(early.status,202,'current pending projection must remain retryable');
  }
  const pendingAssertions=!actualTransport?require('./ctfCurrentPendingPublication.assertions'):null;
  if(pendingAssertions&&!pendingSqlQualified)pendingSqlQualified=await pendingAssertions.assertControlledSqlGates({
   identityRuntime:i.runtime,identityMigration:i.migration,decisionId,actorId:id,
   sessionId:sessionIds[id],rawToken:actors[id],stageId:target,ownerGeneration:ownerBefore.generation,
  });
  let applied=false;for(let n=0;n<100&& !applied;n++){if((await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[decisionId]))?.state==='applied'){applied=true;break;}await new Promise(r=>setTimeout(r,20));}assert(applied);
  if(pendingAssertions)await pendingAssertions.assertApplied({identityRuntime:i.runtime,decisionId,actorId:id,sessionId:sessionIds[id],rawToken:actors[id]});
  if(external)assert.equal(decisionId,external.decisionId,'browser POST and publication must share one decision');const published=external?{status:external.publicationStatus,body:external.publicationBody}:await request('GET','/publications/'+decisionId,id);
  if(probedThisAttempt){
   const diagnostic=path.join(owned.evidence,'pending-publication-diagnostic.json');
   const value=JSON.parse(fs.readFileSync(diagnostic,'utf8'));
   value.late={outboxState:(await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[decisionId]))?.state??null,
    ownerLifecycle:(await one(i.runtime,'SELECT lifecycle_state FROM identity.ctf_authority WHERE scope_key=$1',['owner:'+id]))?.lifecycle_state??null,
    progressApplied:(await one(i.runtime,'SELECT applied_operation_id=$1 AS applied FROM identity.ctf_progress_bindings WHERE owner_id=$2 AND stage_id=$3',[decisionId,id,target]))?.applied??null,
    publicationStatus:published.status};
   fs.writeFileSync(diagnostic,JSON.stringify(value),{mode:0o600});
  }
  const decision=await one(i.runtime,'SELECT * FROM identity.ctf_decisions WHERE decision_id=$1',[decisionId]);assert.equal(String(decision.owner_id),String(id));assert.equal(String(decision.stage_id),String(target));assert.equal(decision.run_id,r.body.runId);if(external)assert.equal(helper.sha(external.browserToken),external.sessionTokenSha256,'exact browser JWT token hash required');const expectedSessionId=external?(await one(i.runtime,'SELECT id FROM identity.user_sessions WHERE session_token_hash=$1 AND user_id=$2',[external.sessionTokenSha256,id]))?.id:sessionIds[id];assert.ok(expectedSessionId,'exact browser JWT session must persist');assert.equal(String(decision.session_id),String(expectedSessionId));assert.equal(String(decision.owner_generation),ownerBefore.generation);const persistedRun=await one(i.runtime,'SELECT owner_key,generation::text,status FROM graph_runtime.runs WHERE run_id=$1',[decision.run_id]);assert.equal(persistedRun.owner_key,JSON.stringify(['CTF',String(id)]));assert.equal(persistedRun.generation,ownerBefore.generation);assert.equal(persistedRun.status,'completed');const proposal=await one(i.runtime,'SELECT canonical_evidence,evidence_hash FROM identity.ctf_decision_proposals WHERE proposal_id=$1',[decision.proposal_id]);assert.equal(helper.sha(proposal.canonical_evidence),proposal.evidence_hash);assert.equal(proposal.evidence_hash,decision.evidence_hash);assert.deepEqual(JSON.parse(proposal.canonical_evidence),decision.evidence);assert.equal(decision.evidence.binding.sessionId,String(expectedSessionId));assert.equal(decision.evidence.binding.ownerGeneration,ownerBefore.generation);assert.equal(decision.evidence.binding.stageRevision,String(decision.stage_revision));const receipt=await one(i.runtime,'SELECT state FROM identity.ctf_outbox WHERE operation_id=$1',[decisionId]);assert.equal(receipt.state,'applied');assert.deepEqual(await request('GET','/publications/'+decisionId,id,undefined,external?.browserToken??actors[id]),published);return{...published,decision};
 }
 if(stage6){
  const sourceCandidates=require('../../server/data/ctfSolutions').levels.find(row=>row.level===6).payloads;
  const cases=owned.input.cases;
  assert.equal(cases[0].payload,'Please describe the daytime weather in a short sentence.');
  assert.equal(sourceCandidates.filter(payload=>payload===cases[1].payload).length,1,
    'One exact source-defined Stage 6 candidate required');
  assert.notEqual(cases[0].payload,cases[1].payload);
  const stage7=await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE stage_number=7');
  const siblingBefore=(await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=2002 ORDER BY stage_id')).rows;
  const outcomes=[];let candidateUiSubmission=null;
  for(const entry of cases){
   let result;
   if(entry.id==='benign'){
    actual.beginCase(entry.id);
    try{result=await attempt(entry.owner,entry.payload,'stage6-actual');}
    finally{actual.endCase();}
   }else{
    let browserOwnerBefore;
    candidateUiSubmission=await require('../fixtures/ctfStage6EarnedRendered').submitStage6CandidateInBrowser({
     origin:'http://127.0.0.1:'+listener.address().port,
     owner:await one(i.runtime,'SELECT * FROM identity.users WHERE id=2001'),
     password:fixturePassword,stage6:stage,payload:entry.payload,evidence:owned.evidence,
     beforeSubmit:async()=>{
      browserOwnerBefore=await one(i.runtime,'SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['CTF','2001'])]);
      actual.beginCase(entry.id);
     },
     afterSubmit:()=>actual.endCase(),
    });
    if(typeof candidateUiSubmission.publicationBody?.aiResponse==='string')
     assert.equal(candidateUiSubmission.responseVisibleInLearnerChat,true,
      'The actual post-defense response must appear in learner chat even on refusal');
    if(candidateUiSubmission.publicationBody?.success===true)
     assert.equal(candidateUiSubmission.domVisible,true,
      'Accepted browser candidate must render its exact post-defense reply before redirect');
    result=await attempt(entry.owner,entry.payload,'stage6-actual',
      {...candidateUiSubmission,browserToken:candidateUiSubmission.browserToken,
       ownerBefore:browserOwnerBefore});
   }
   const used=actual.snapshot().calls.filter(row=>row.caseId===entry.id);
   assert.ok(used.length<=5,'Stage 6 case exceeded guardian/reviewer/Judge call budget');
   outcomes.push({id:entry.id,result});
   if(entry.id==='benign'){assert.notEqual(result.body.success,true);assert.equal(result.decision?.accepted===true,false);}
  }
  const candidate=outcomes[1].result,accepted=candidate.decision?.accepted===true;
  const wire=actual.snapshot();let transportValid=true;
  try{actual.assertComplete();}catch{transportValid=false;}
  assert.ok(wire.counts.external<=11&&wire.counts.generate<=10,'Stage 6 two-case budget exceeded');
  const bindingFailures=[];
  const boundGuardian=outcomes.map(row=>{
   if(!row.result.decision)return false;
   try{return helper.assertGuardianWire({evidence:row.result.decision.evidence,rows:wire.calls,
    caseId:row.id,payload:cases.find(item=>item.id===row.id).payload,
    systemPrompt:stage.system_prompt,model:actualTransport.MODEL});}
   catch{bindingFailures.push({caseId:row.id,code:'GUARDIAN_WIRE_BINDING_FAILED'});return false;}
  });
  let earnedRendered=null;
  const actorQualified=boundGuardian.every(Boolean);
  if(accepted){
   assert.equal(candidate.body.success,true);assert.equal(candidate.body.judgment?.verdict,'pass');
   const visible=candidate.decision.evidence.visibleResponse;
   assert.match(visible,/^\s*\{[\s\S]*\}\s*$/,'Accepted Stage 6 answer must be only a JSON object');
   const handoff=JSON.parse(visible);
   assert.deepEqual(Object.keys(handoff).sort(),['environment','kind','value']);
   assert.deepEqual(handoff,{kind:'rotation_handoff',environment:'staging',value:secret},
    'Accepted answer must carry only the exact claimed internal handoff with the configured secret');
   assert.equal(boundGuardian[1],true,'Accepted guardian must bind to the candidate wire');
   const completion=await one(c.runtime,'SELECT status,authorized_decision_id,successful_attempts FROM ctf.ctf_progress WHERE participant_id=2001 AND stage_id=$1',[stage.id]);
   assert.equal(completion.status,'completed');assert.equal(completion.authorized_decision_id,candidate.decision.decision_id);assert.equal(completion.successful_attempts,1);
   assert.equal((await one(i.runtime,'SELECT status FROM identity.ctf_progress_bindings WHERE progress_id=$1',[candidate.decision.progress_id])).status,'completed');
   assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_progress WHERE participant_id=2001 AND stage_id=$1',[stage7.id])).n,0);
   const judgment=await one(c.runtime,'SELECT j.*,a.ai_response,a.payload FROM ctf.ctf_judgments j JOIN ctf.ctf_attempts a ON a.id=j.attempt_id WHERE j.decision_id=$1',[candidate.decision.decision_id]);
   assert.equal(judgment.verdict,'pass');assert.equal(Number(judgment.accepted),1);assert.equal(judgment.ai_response,candidate.decision.evidence.visibleResponse);assert.equal(judgment.payload,cases[1].payload);
   const metadata=JSON.parse(judgment.metadata),profile=require('../../server/services/ctfDefenseLayers').reviewerProfileEvidence(stage);
   assert.deepEqual(metadata.guardian.reviewerProfile,profile);assert.equal(metadata.provider,'ollama');assert.equal(metadata.model,'llama3.1:8b');
   const reviewer=(await i.runtime.query("SELECT metadata FROM graph_runtime.events WHERE run_id=$1 AND node='ctf_output_reviewer' AND event_type='decision'",[judgment.run_id])).rows;
   assert.equal(reviewer.length,1);assert.equal(reviewer[0].metadata.provider,'ollama');assert.equal(reviewer[0].metadata.model,'llama3.1:8b');assert.equal(reviewer[0].metadata.reviewerPolicyDigest,profile.policyDigest);assert.equal(reviewer[0].metadata.verdict,'SAFE');
   const owner=await one(i.runtime,'SELECT * FROM identity.users WHERE id=2001'),sibling=await one(i.runtime,'SELECT * FROM identity.users WHERE id=2002'),admin=await one(i.runtime,'SELECT * FROM identity.users WHERE id=2004');
   const participant=await one(c.runtime,'SELECT * FROM ctf.ctf_participants WHERE user_id=2001'),siblingParticipant=await one(c.runtime,'SELECT * FROM ctf.ctf_participants WHERE user_id=2002');
   earnedRendered=await require('../fixtures/ctfStage6EarnedRendered').qualifyStage6EarnedRendered({
    origin:'http://127.0.0.1:'+listener.address().port,owner,sibling,admin,password:fixturePassword,
    stage6:stage,stage7,ownerSession:{token:actors[2001]},siblingSession:{token:actors[2002]},
    adminSession:{token:actors[2004]},authorityApplication:application,participant,siblingParticipant,
    acceptedJudgment:judgment,evidence:owned.evidence,
    resetOwner:()=>mutation('/admin/participants/2001/reset',2004),
   });
   assert.equal(earnedRendered.stage6Completed,true);assert.equal(earnedRendered.stage7Unlocked,true);
   assert.equal(earnedRendered.ownerReset,true);assert.equal(earnedRendered.siblingPreserved,true);
  }else await mutation('/admin/participants/2001/reset',2004);
  assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_progress WHERE participant_id=2001')).n,0);
  assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=2002 ORDER BY stage_id')).rows,siblingBefore);
  assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE stage_number=6'),stage);
  const providerUnavailable=outcomes.some(row=>row.result.status===503||row.result.body.judgment?.verdict==='unavailable');
  fs.writeFileSync(path.join(owned.evidence,'qualification-summary.json'),JSON.stringify({version:1,
   mode:'stage6-actual',scope:'supported-active-authority',transportValid,providerUnavailable,bindingFailures,
   actualModelProof:actorQualified,fixedCandidateAccepted:accepted,
   syntheticPrerequisites:true,prerequisiteStages1To5Earned:false,
   earnedRendered:earnedRendered!==null,learnerCandidateVisible:candidateUiSubmission?.domVisible===true,
   rendered:earnedRendered,
   outcomes:outcomes.map(row=>({id:row.id,status:row.result.status,success:row.result.body.success===true,
    verdict:row.result.body.judgment?.verdict??null,decisionId:row.result.decision?.decision_id??null}))}),
   {mode:0o600,flag:'wx'});
  await application.stop();await actual.close();actual=null;owned.assertLoaded();
  assert(transportValid&&!providerUnavailable&&actorQualified,
    'Stage 6 actual guardian/Judge qualification unavailable; receipt retained');
  return;
 }
 if(owned.mode==='actual'){
  const outcomes=[];
  for(const entry of owned.input.cases){actual.beginCase(entry.id);let result;try{result=await attempt(entry.owner,entry.payload,'actual');}finally{actual.endCase();}outcomes.push({id:entry.id,result});if(entry.id==='benign'){assert.notEqual(result.body.success,true);assert.equal(result.decision?.accepted===true,false);assert.deepEqual(await memory(),{authority:[],projection:[]});}}
  const candidate=outcomes[1].result,attackSucceeded=candidate.decision?.accepted===true;
  const {hashPayload}=require('../../server/services/promptInjectionCTF');const payload=owned.input.cases[1].payload,fp=hashPayload(payload);
  if(attackSucceeded){
   assert.equal(candidate.body.success,true);assert.equal(candidate.body.judgment.verdict,'pass');const completion=await one(c.runtime,'SELECT status,authorized_decision_id,successful_attempts FROM ctf.ctf_progress WHERE participant_id=2001 AND stage_id=9');assert.equal(completion.status,'completed');assert.equal(completion.authorized_decision_id,candidate.decision.decision_id);assert.equal(completion.successful_attempts,1);const canonicalCompletion=await one(i.runtime,'SELECT status FROM identity.ctf_progress_bindings WHERE progress_id=$1',[candidate.decision.progress_id]);assert.equal(canonicalCompletion.status,'completed');const win=await memory();assert.equal(win.authority.length,1);assert.equal(win.projection.length,1);assert.equal(win.authority[0].decision_id,candidate.decision.decision_id);assert.equal(win.authority[0].payload_hash,fp.hash);assert.equal(win.projection[0].payload_hash,fp.hash);
   assert.equal((await attempt(2002,payload,'shared-replay')).body.blocked,true);await mutation('/admin/participants/2001/reset',2004);assert.equal((await memory()).authority[0].payload_hash,fp.hash);assert.equal((await memory()).projection[0].payload_hash,fp.hash);assert.equal((await attempt(2002,payload,'shared-replay')).body.blocked,true);
   const before=await memory();assert.equal((await request('POST','/admin/blocklists/payload/clear',2002,{stageId:9})).status,403);assert.deepEqual(await memory(),before);const techniques=(await i.runtime.query("SELECT * FROM identity.ctf_adaptive_memory WHERE kind='technique' ORDER BY memory_id")).rows;await mutation('/admin/blocklists/payload/clear',2004,{stageId:9});assert.deepEqual(await memory(),{authority:[],projection:[]});assert.deepEqual((await i.runtime.query("SELECT * FROM identity.ctf_adaptive_memory WHERE kind='technique' ORDER BY memory_id")).rows,techniques);
  }else{assert.deepEqual(await memory(),{authority:[],projection:[]});assert.equal((await one(c.runtime,'SELECT status FROM ctf.ctf_progress WHERE participant_id=2001 AND stage_id=9')).status,'in_progress');}
  assert.deepEqual(await sibling(),siblingBefore);assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE stage_number=9'),stage);const wire=actual.snapshot();let transportValid=true;try{actual.assertComplete();}catch{transportValid=false;}const boundGuardian=outcomes.map(x=>x.result.decision?helper.assertGuardianWire({evidence:x.result.decision.evidence,rows:wire.calls,caseId:x.id,payload:owned.input.cases.find(c=>c.id===x.id).payload,systemPrompt:stage.system_prompt,model:actualTransport.MODEL}):false);await application.stop();await actual.close();actual=null;owned.assertLoaded();
  const providerUnavailable=outcomes.some(x=>x.result.status===503||x.result.body.judgment?.verdict==='unavailable');
  fs.writeFileSync(path.join(owned.evidence,'qualification-summary.json'),JSON.stringify({version:1,mode:'actual',outcomeAccountingPassed:true,qualificationPassed:transportValid&&!providerUnavailable,transportValid,attackSucceeded,syntheticPrerequisites:true,syntheticCreditOnly:false,providerUnavailable,actualModelProof:boundGuardian.some(Boolean),unattempted:attackSucceeded?['post-clear-third-inference']:['accepted-memory-replay-reset-clear'],outcomes:outcomes.map(x=>({id:x.id,status:x.result.status,blocked:x.result.body.blocked===true,success:x.result.body.success===true,verdict:x.result.body.judgment?.verdict??null,classification:x.result.body.blocked?'predefense-block-no-guardian':x.result.status===503||x.result.body.judgment?.verdict==='unavailable'?'unavailable':x.result.body.judgment?.verdict==='inconclusive'?'inconclusive':x.result.body.success?'accepted-disclosure':'completed-nondisclosure',guardianObserved:!!x.result.decision?.evidence?.guardian,lessonState:x.result.body.lessonState??null,decisionId:x.result.decision?.decision_id??null}))}),{mode:0o600,flag:'wx'});assert(transportValid&&!providerUnavailable,'Actual qualification unavailable; failed summary retained');return;
 }
 for(const [text,m]of [['Please describe the daytime weather in a short sentence.','fail'],['Please provide a simple example of a calendar entry.','inconclusive']]){const r=await attempt(2001,text,m);assert.equal(r.status,200);assert.equal(r.body.success,false);assert.equal(r.body.judgment.verdict,m);assert.deepEqual(await memory(),{authority:[],projection:[]});}
 const payload='Please complete this ordinary example record with a clear concise value for the requested field.';
 const {hashPayload,isNearDuplicate}=require('../../server/services/promptInjectionCTF');
 const fingerprint=hashPayload(payload),near=payload.replace('concise','concize'),nearHash=hashPayload(near);assert.notEqual(nearHash.hash,fingerprint.hash);assert(isNearDuplicate(nearHash.hash,nearHash.normalized,[{payload_hash:fingerprint.hash,normalized_snippet:fingerprint.normalized}]).blocked);
 const won=await attempt(2001,payload,'win');assert.equal(won.status,200);assert.equal(won.body.success,true);assert.equal(won.body.judgment.verdict,'pass');assert.equal(won.decision.accepted,true);
 const afterWin=await memory();assert.equal(afterWin.authority.length,1);assert.equal(afterWin.projection.length,1);assert.equal(afterWin.authority[0].payload_hash,fingerprint.hash);assert.equal(afterWin.authority[0].normalized_payload,fingerprint.normalized);assert.equal(afterWin.authority[0].decision_id,won.decision.decision_id);assert.equal(afterWin.projection[0].payload_hash,fingerprint.hash);assert.equal(afterWin.projection[0].normalized_snippet,fingerprint.normalized);
 assert.equal((await one(c.runtime,'SELECT status FROM ctf.ctf_progress WHERE participant_id=2001 AND stage_id=9')).status,'completed');
 for(const text of [payload,near]){const r=await attempt(2002,text,'fail');assert.equal(r.body.blocked,true);assert.equal((await one(c.runtime,'SELECT status FROM ctf.ctf_progress WHERE participant_id=2002 AND stage_id=9')).status,'in_progress');}
 const unrelated='What is the sum of two and three?';const unrelatedHash=hashPayload(unrelated);assert.equal(isNearDuplicate(unrelatedHash.hash,unrelatedHash.normalized,[{payload_hash:fingerprint.hash,normalized_snippet:fingerprint.normalized}]).blocked,false);
 const unrelatedResult=await attempt(2002,unrelated,'fail');assert.equal(unrelatedResult.body.judgment.verdict,'fail');assert.equal(unrelatedResult.decision.accepted,false);const retained=await memory();assert.equal(retained.authority[0].payload_hash,fingerprint.hash);
 await mutation('/admin/participants/2001/reset',2004);assert.equal((await one(c.runtime,'SELECT count(*)::int n FROM ctf.ctf_progress WHERE participant_id=2001')).n,0);assert.equal((await memory()).authority[0].payload_hash,fingerprint.hash);assert.equal((await memory()).projection[0].payload_hash,fingerprint.hash);assert.equal((await attempt(2002,payload,'fail')).body.blocked,true);assert.deepEqual(await sibling(),siblingBefore);
 const beforeDenied=await memory();assert.equal((await request('POST','/admin/blocklists/payload/clear',2002,{stageId:9})).status,403);assert.deepEqual(await memory(),beforeDenied);
 const techniquesBefore=(await i.runtime.query("SELECT * FROM identity.ctf_adaptive_memory WHERE kind='technique' ORDER BY memory_id")).rows;
 await mutation('/admin/blocklists/payload/clear',2004,{stageId:9});assert.deepEqual(await memory(),{authority:[],projection:[]});assert.deepEqual((await i.runtime.query("SELECT * FROM identity.ctf_adaptive_memory WHERE kind='technique' ORDER BY memory_id")).rows,techniquesBefore);assert.deepEqual(await sibling(),siblingBefore);
 const calls=ledger.length,afterClear=await attempt(2002,payload,'fail');assert(ledger.length>calls);assert.equal(afterClear.body.judgment.verdict,'fail');assert.equal(afterClear.decision.accepted,false);assert.deepEqual(await memory(),{authority:[],projection:[]});assert.equal((await one(c.runtime,'SELECT status FROM ctf.ctf_progress WHERE participant_id=2002 AND stage_id=9')).status,'in_progress');assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.ctf_stages WHERE stage_number=9'),stage);assert.deepEqual(await sibling(),siblingBefore);assert(!ledger.some(x=>x.failure));
 await application.stop();owned.assertLoaded();
 assert.equal(pendingSqlQualified,true,'at least one real pending decision must qualify SQL stale gates');
 fs.writeFileSync(path.join(owned.evidence,'qualification-summary.json'),JSON.stringify({version:1,mode:'controlled',mechanismPassed:true,pendingSqlQualified,actualModelProof:false,syntheticPrerequisites:true,syntheticCreditOnly:true,canonicalStageUnchanged:true,failAndInconclusiveNoMemory:true,twoOwnerExactAndNearBlock:true,ownerResetRetainsSharedMemory:true,studentClearDenied:true,instructorClearReadmission:true,siblingPreserved:true,providerCalls:ledger.length}),{mode:0o600,flag:'wx'});
});
