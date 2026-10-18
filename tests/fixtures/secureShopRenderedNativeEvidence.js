'use strict';
const assert=require('node:assert/strict');
const {QUALIFIED_OBJECTIVE_IDS,WORKSHOP_KEY}=require('../../server/config/secureshopCurriculum');
const {validateReviewExpectation}=require('./renderedSecureShopReviewWorkflow');
const {createRenderedSecureShopReviewEvidence}=require('./renderedSecureShopReviewWorkflow');
const {createRenderedBrowserEvidence}=require('./renderedSecureShopBrowser');
const {createRenderedPersonaEvidence}=require('./renderedSecureShopPersona');
const {createRenderedMcpTrustEvidence}=require('./renderedSecureShopMcpTrust');
const {createRenderedSsrfEvidence}=require('./renderedSecureShopSsrf');
const {attestSyntheticPersonaFixtures}=require('./secureShopPrivateQualificationFailure');
function readOnly(pool){
 assert.equal(typeof pool?.query,'function');
 return Object.freeze({query(sql,args){assert.ok(typeof sql==='string'&&/^\s*SELECT\b/i.test(sql),'Only explicit read-only qualification queries');return pool.query(sql,args);},async connect(){throw Error('Qualification factory does not open mutable transactions');}});
}
function createSecureShopRenderedNativeEvidence({identityRuntime,agentsRuntime,reviewRuntime,commerceRuntime,ownerId,siblingId,renderer,scenarioInputs,privateFailureWriter}){
 for(const value of [ownerId,siblingId])assert.ok(Number.isSafeInteger(value)&&value>0);assert.notEqual(ownerId,siblingId);
 const identity=readOnly(identityRuntime),agents=readOnly(agentsRuntime),review=readOnly(reviewRuntime);if(commerceRuntime)readOnly(commerceRuntime);
 const verifiedLifecycle=new WeakSet(), verifiedResets=new Map(), replayBaselines=new Map(), knownLaunches=new Map();
 let personaFixtureAttestation=null;
 if(privateFailureWriter!==undefined)assert.equal(typeof privateFailureWriter?.write,'function');
 const owners=new Set([ownerId,siblingId]);
 function admitted(id){assert.ok(owners.has(id),'Only the two owned learners are admitted');}
 async function launch(id){admitted(id);const rows=(await identity.query(`SELECT l.launch_id,l.scenario_id,l.generation,l.platform_session_id,l.original_platform_owner_id,l.credential_version,l.expires_at
  FROM identity.secureshop_launches l JOIN identity.user_sessions s ON s.id=l.platform_session_id
  WHERE l.original_platform_owner_id=$1 AND l.status='active' AND l.expires_at>clock_timestamp()
    AND s.user_id=$1 AND s.is_active=1 AND s.expires_at>clock_timestamp()`,[id])).rows;
  assert.equal(rows.length,1,'One actual active login/launch required; ambiguous sessions are not guessed');knownLaunches.set(id,rows[0]);return rows[0];}
 async function forPersona({ownerId:id,role}){
  assert.ok(['customer','merchant','admin'].includes(role));const row=await launch(id);
  const sessions=(await agents.query(`SELECT session_id,shop_user_id,role,platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id
    FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
    AND original_platform_owner_id=$4 AND original_platform_session_id=$5 AND role=$6 AND revoked_at IS NULL AND expires_at>clock_timestamp()`,[row.launch_id,row.scenario_id,row.generation,id,row.platform_session_id,role])).rows;
  assert.equal(sessions.length,1,'Real UI persona login required; duplicate active persona sessions fail closed');const session=sessions[0];
  assert.equal(session.role,role);assert.equal(session.platform_launch_id,row.launch_id);assert.equal(session.platform_scenario_id,row.scenario_id);
  assert.equal(Number(session.platform_launch_generation),Number(row.generation));assert.equal(Number(session.original_platform_owner_id),id);assert.equal(Number(session.original_platform_session_id),Number(row.platform_session_id));
  const binding=Object.freeze({launchId:row.launch_id,scenarioId:row.scenario_id,generation:Number(row.generation),platformOwnerId:id,platformSessionId:Number(row.platform_session_id),shopUserId:Number(session.shop_user_id),role});
  const common={identityRuntime:identity,agentsRuntime:agents,reviewRuntime:review,binding};
  return Object.freeze({binding,evidence:Object.freeze({
   ...(role==='merchant'?{review:createRenderedSecureShopReviewEvidence(common)}:{}),
   ...(role==='customer'?{browser:createRenderedBrowserEvidence({...common,renderer})}:{}),
   persona:createRenderedPersonaEvidence({...common,...(privateFailureWriter?{privateFailure:{
    write:value=>privateFailureWriter.write(value),attestation:()=>personaFixtureAttestation}}:{})}),mcpTrust:createRenderedMcpTrustEvidence(common),
   ssrf:createRenderedSsrfEvidence({identityRuntime:identity,agentsRuntime:agents,ownerId:id,launchId:binding.launchId,generation:binding.generation})})});
 }
 async function prepareScenario(){
  for(const key of ['reviewInstructionBody','storedBrowserBody'])assert.ok(typeof scenarioInputs?.[key]==='string'&&scenarioInputs[key].length>0&&Buffer.byteLength(scenarioInputs[key])<=65536,'Explicit reviewed scenario bodies required');
  const reviewExpectation=validateReviewExpectation(scenarioInputs.reviewExpectation);
  const row=await launch(ownerId),scope=[row.launch_id,row.scenario_id,row.generation,ownerId,row.platform_session_id];
  const products=(await review.query(`SELECT p.product_id FROM secureshop_review.product_target_products p JOIN secureshop_review.product_targets t USING(target_id) WHERE t.launch_id=$1 AND t.scenario_id=$2 AND t.generation=$3 AND t.original_platform_owner_id=$4 AND t.original_platform_session_id=$5 AND t.lifecycle='active' ORDER BY p.product_id LIMIT 1`,scope)).rows;assert.equal(products.length,1,'Real Products UI must provision the owned catalog first');
  let messages;
  if(privateFailureWriter){const fixtureRows=(await agents.query(`SELECT m.message_id,m.fixture_key,m.owner_shop_role,m.subject,m.body,m.body_sha256 FROM secureshop_agents.persona_inbox_messages m JOIN secureshop_agents.persona_inbox_targets t USING(target_id) WHERE t.launch_id=$1 AND t.scenario_id=$2 AND t.generation=$3 AND t.original_platform_owner_id=$4 AND t.original_platform_session_id=$5 AND t.lifecycle='active' ORDER BY m.message_id`,scope)).rows;
   personaFixtureAttestation=attestSyntheticPersonaFixtures(fixtureRows);
   messages=fixtureRows.filter(message=>message.owner_shop_role!=='merchant').slice(0,1);
  }else messages=(await agents.query(`SELECT m.message_id,m.subject FROM secureshop_agents.persona_inbox_messages m JOIN secureshop_agents.persona_inbox_targets t USING(target_id) WHERE t.launch_id=$1 AND t.scenario_id=$2 AND t.generation=$3 AND t.original_platform_owner_id=$4 AND t.original_platform_session_id=$5 AND t.lifecycle='active' AND m.owner_shop_role<>'merchant' ORDER BY m.message_id LIMIT 1`,scope)).rows;
  assert.equal(messages.length,1,'Real Inbox UI must provision owned messages first');
  assert.ok(Number.isSafeInteger(Number(products[0].product_id))&&Number(products[0].product_id)>0);assert.ok(Number.isSafeInteger(Number(messages[0].message_id))&&Number(messages[0].message_id)>0);assert.ok(typeof messages[0].subject==='string'&&messages[0].subject.length>0);
  const admittedReviewExpectation=reviewExpectation.mode==='observed_outcome'
   ?Object.freeze({mode:'observed_outcome'})
   :Object.freeze({mode:reviewExpectation.mode,decision:reviewExpectation.decision});
  return Object.freeze({productId:Number(products[0].product_id),personaMessageId:Number(messages[0].message_id),personaSubject:messages[0].subject,reviewInstructionBody:scenarioInputs.reviewInstructionBody,storedBrowserBody:scenarioInputs.storedBrowserBody,reviewExpectation:admittedReviewExpectation});
 }
 async function expectedProgress(id){admitted(id);const rows=(await identity.query(`SELECT o.objective_id,(c.objective_id IS NOT NULL) AS completed FROM workshop_platform.objectives o LEFT JOIN workshop_platform.completions c ON c.workshop_key=o.workshop_key AND c.objective_id=o.objective_id AND c.user_id=$1 WHERE o.workshop_key=$2 AND o.catalog_active AND o.is_enabled ORDER BY o.ordinal,o.objective_id`,[id,WORKSHOP_KEY])).rows;
  assert.deepEqual(rows.map(row=>row.objective_id).sort(),[...QUALIFIED_OBJECTIVE_IDS].sort());return Object.freeze({objectiveIds:rows.map(row=>row.objective_id),completedObjectiveIds:rows.filter(row=>row.completed===true).map(row=>row.objective_id),totalObjectives:rows.length,completedObjectives:rows.filter(row=>row.completed===true).length});}
 async function expectedStudentView(id){admitted(id);const rows=(await identity.query(`SELECT e.workshop_key,e.challenge_name,count(o.objective_id)::int objective_count,count(c.objective_id)::int completed_objective_count FROM workshop_platform.exercises e LEFT JOIN workshop_platform.objectives o ON o.workshop_key=e.workshop_key AND o.catalog_active=true AND o.is_enabled=true LEFT JOIN workshop_platform.completions c ON c.user_id=$1 AND c.workshop_key=o.workshop_key AND c.objective_id=o.objective_id WHERE e.catalog_active=true AND e.is_visible=true GROUP BY e.workshop_key,e.challenge_name ORDER BY e.workshop_key`,[id])).rows;const shop=rows.find(r=>r.workshop_key===WORKSHOP_KEY);assert.ok(shop);assert.equal(Number(shop.objective_count),QUALIFIED_OBJECTIVE_IDS.length);return Object.freeze({completedChallenges:rows.filter(r=>Number(r.objective_count)>0&&Number(r.objective_count)===Number(r.completed_objective_count)).length,completedObjectives:rows.reduce((sum,r)=>sum+Number(r.completed_objective_count),0),totalObjectives:rows.reduce((sum,r)=>sum+Number(r.objective_count),0),secureShopCompletedObjectives:Number(shop.completed_objective_count),secureShopTotalObjectives:Number(shop.objective_count),secureShopChallengeName:shop.challenge_name});}
 async function verifyRunDetail({ownerId:id,runId,body,projection}){
  admitted(id);assert.match(runId,/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);assert.ok(['student','admin'].includes(projection));
  const rows=(await identity.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1',[runId])).rows;assert.equal(rows.length,1);const run=rows[0],owner=JSON.parse(run.owner_key);assert.equal(owner[0],'SecureShopBoundConversation');assert.equal(owner.length,2);assert.equal(run.owner_key,JSON.stringify(['SecureShopBoundConversation',String(owner[1])]));
  const sessions=(await agents.query('SELECT id,original_platform_owner_id FROM secureshop_agents.agent_sessions WHERE id=$1',[owner[1]])).rows;assert.equal(sessions.length,1);assert.equal(Number(sessions[0].original_platform_owner_id),id);
  assert.equal(body?.run?.runId,runId);if(projection==='admin')assert.equal(String(body.run.ownerId),String(id));else assert.equal(body.run.ownerId,undefined);
  for(const [key,column] of [['status','status'],['provider','provider'],['model','model'],['decisionSource','decision_source']])assert.equal(body.run[key],run[column]);assert.equal(String(body.run.generation),String(run.generation));
  const judgments=(await identity.query('SELECT evaluation_id,objective_id,rubric_version,verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 AND run_id=$2 AND workshop_key=$3 ORDER BY evaluation_id',[id,runId,WORKSHOP_KEY])).rows;assert.equal(body.judgments.length,judgments.length);
  for(const row of judgments){const projected=body.judgments.find(j=>j.evaluationId===row.evaluation_id);assert.ok(projected);for(const [key,column] of [['objectiveId','objective_id'],['rubricVersion','rubric_version'],['verdict','verdict'],['disposition','disposition']])assert.equal(projected[key],row[column]);}
  const events=(await identity.query('SELECT sequence,node,event_type FROM graph_runtime.events WHERE run_id=$1 ORDER BY sequence',[runId])).rows;assert.deepEqual(body.events.map(e=>[e.seq,e.node,e.type]),events.slice(0,100).map(e=>[e.sequence,e.node,e.event_type]));assert.equal(body.nextCursor??null,events.length>100?events[99].sequence:null);return Object.freeze({ownerId:id,runId,verified:true});
 }
 async function histories(id){admitted(id);return{
  judgments:(await identity.query(`SELECT j.* FROM workshop_platform.objective_judgments j WHERE j.user_id=$1 AND j.workshop_key=$2 ORDER BY j.evaluation_id`,[id,WORKSHOP_KEY])).rows,
  contributions:(await identity.query(`SELECT c.* FROM workshop_platform.objective_contributions c WHERE c.user_id=$1 AND c.workshop_key=$2 ORDER BY c.evaluation_id`,[id,WORKSHOP_KEY])).rows,
  sessions:(await agents.query(`SELECT id,platform_launch_id,platform_launch_generation,binding_state,messages_json FROM secureshop_agents.agent_sessions WHERE original_platform_owner_id=$1 ORDER BY id`,[id])).rows};}
 async function reservations(id){const row=await launch(id);return(await identity.query('SELECT target_id,target_kind,generation FROM identity.secureshop_target_reservations WHERE launch_id=$1 AND generation=$2 ORDER BY target_kind',[row.launch_id,row.generation])).rows;}
 async function snapshotLifecycle(){return{ownerTargets:await reservations(ownerId),siblingTargets:await reservations(siblingId),ownerLaunch:await launch(ownerId),owner:await histories(ownerId),siblingLaunch:await launch(siblingId),sibling:await histories(siblingId),siblingProgress:await expectedProgress(siblingId)};}
 async function verifyReset({before,response,resetBody}){
  response=response||resetBody;
  assert.deepEqual(Object.keys(response||{}).sort(),['cleanupComplete','launch','resetId']);
  assert.deepEqual(Object.keys(response.launch||{}).sort(),['credentialVersion','expiresAt','generation','launchId']);
  assert.equal(response.cleanupComplete,true);const current=await launch(ownerId);assert.equal(current.launch_id,before.ownerLaunch.launch_id);assert.equal(Number(current.generation),Number(before.ownerLaunch.generation)+1);
  assert.equal(response.launch.launchId,current.launch_id);assert.equal(response.launch.generation,Number(current.generation));
  assert.equal(response.launch.expiresAt,new Date(current.expires_at).toISOString());
  assert.ok(Number.isSafeInteger(response.launch.credentialVersion)&&response.launch.credentialVersion>0);
  assert.ok([response.launch.credentialVersion,response.launch.credentialVersion+1]
    .includes(Number(current.credential_version)),'Reset response credential must be current or have one matched recovery rotation');
  const resets=(await identity.query(`SELECT status,reconciliation_required,conversation_reconciliation_required,progress_reconciliation_required,from_generation,to_generation FROM identity.secureshop_launch_resets WHERE reset_id=$1 AND launch_id=$2`,[response.resetId,current.launch_id])).rows;assert.equal(resets.length,1);assert.equal(resets[0].status,'committed');assert.equal(resets[0].reconciliation_required,false);assert.equal(resets[0].conversation_reconciliation_required,false);assert.equal(resets[0].progress_reconciliation_required,false);assert.equal(Number(resets[0].from_generation),Number(before.ownerLaunch.generation));assert.equal(Number(resets[0].to_generation),Number(current.generation));
  const owner=await histories(ownerId);assert.deepEqual(owner.judgments,before.owner.judgments);assert.deepEqual(owner.contributions,before.owner.contributions);
  assert.deepEqual(await histories(siblingId),before.sibling);assert.deepEqual(await launch(siblingId),before.siblingLaunch);assert.deepEqual(await expectedProgress(siblingId),before.siblingProgress);
  assert.equal((await expectedProgress(ownerId)).completedObjectives,0);
  assert.deepEqual(await reservations(siblingId),before.siblingTargets);
  const mapping={reviews:[review,'secureshop_review.review_targets','secureshop_review.review_cleanup_receipts',['secureshop_review.reviews']],products:[review,'secureshop_review.product_targets','secureshop_review.product_cleanup_receipts',['secureshop_review.product_target_products']],persona_inbox:[agents,'secureshop_agents.persona_inbox_targets','secureshop_agents.persona_inbox_cleanup_receipts',['secureshop_agents.persona_inbox_messages','secureshop_agents.persona_inbox_access_events','secureshop_agents.persona_inbox_acl_versions']],mcp_rogue:[agents,'secureshop_agents.bound_mcp_targets','secureshop_agents.bound_mcp_cleanup_receipts',['secureshop_agents.bound_mcp_tool_payloads']],mcp_rug_pull:[agents,'secureshop_agents.bound_mcp_targets','secureshop_agents.bound_mcp_cleanup_receipts',['secureshop_agents.bound_mcp_tool_payloads']],controlled_ssrf:[agents,'secureshop_agents.bound_ssrf_targets','secureshop_agents.bound_ssrf_cleanup_receipts',[]]};
  assert.deepEqual(before.ownerTargets.map(row=>row.target_kind).sort(),Object.keys(mapping).sort(),'All six actual semantic targets must exist before reset');
  const oldReservations=(await identity.query('SELECT target_id FROM identity.secureshop_target_reservations WHERE launch_id=$1 AND generation=$2',[current.launch_id,before.ownerLaunch.generation])).rows;assert.deepEqual(oldReservations,[]);
  for(const target of before.ownerTargets){
   const [pool,table,receiptTable,deletedTables]=mapping[target.target_kind];
   const histories=(await identity.query('SELECT * FROM identity.secureshop_target_cleanup_history WHERE target_id=$1 AND operation_id=$2',[target.target_id,response.resetId])).rows;assert.equal(histories.length,1);const history=histories[0];
   assert.equal(history.target_kind,target.target_kind);assert.equal(history.launch_id,current.launch_id);assert.equal(Number(history.from_generation),Number(before.ownerLaunch.generation));assert.equal(history.original_platform_owner_id,ownerId);assert.equal(Number(history.original_platform_session_id),Number(before.ownerLaunch.platform_session_id));
   const targets=(await pool.query(`SELECT lifecycle FROM ${table} WHERE target_id=$1`,[target.target_id])).rows;assert.deepEqual(targets,[{lifecycle:'retired'}]);
   const receipts=(await pool.query(`SELECT * FROM ${receiptTable} WHERE target_id=$1 AND operation_id=$2`,[target.target_id,response.resetId])).rows;assert.equal(receipts.length,1);const receipt=receipts[0];
   assert.equal(receipt.launch_id,current.launch_id);assert.equal(receipt.scenario_id,before.ownerLaunch.scenario_id);assert.equal(Number(receipt.generation),Number(before.ownerLaunch.generation));assert.equal(Number(receipt.original_platform_owner_id),ownerId);assert.equal(Number(receipt.original_platform_session_id),Number(before.ownerLaunch.platform_session_id));assert.ok(Buffer.isBuffer(receipt.receipt_sha256)&&receipt.receipt_sha256.length===32);assert.deepEqual(receipt.receipt_sha256,history.target_receipt_sha256);
   for(const table of deletedTables)assert.deepEqual((await pool.query(`SELECT target_id FROM ${table} WHERE target_id=$1`,[target.target_id])).rows,[]);
  }
  assert.ok(owner.sessions.filter(s=>Number(s.platform_launch_generation)===Number(before.ownerLaunch.generation)).every(s=>s.binding_state==='abandoned'));
  const activePersonas=(await agents.query(`SELECT session_id FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 AND platform_launch_generation=$2 AND revoked_at IS NULL`,[current.launch_id,before.ownerLaunch.generation])).rows;assert.deepEqual(activePersonas,[]);
  assert.ok(!verifiedResets.has(response.resetId),'Verified reset receipt may be recorded only once');
  const result=Object.freeze({authorityHistoryProgressVerified:true,resourceCleanupVerified:true,credentialRevocationVerified:true,scope:'durable_reset_resources_and_persona_retirement',httpDenialVerified:false,processPortCleanupVerified:false});verifiedLifecycle.add(result);verifiedResets.set(response.resetId,JSON.parse(JSON.stringify(response)));return result;
 }
 async function verifyForeignRunIsolation({ownerId:id,siblingId:other,runIds}){
  admitted(id);admitted(other);assert.notEqual(id,other);assert.ok(Array.isArray(runIds)&&runIds.length>0);
  assert.equal(new Set(runIds).size,runIds.length);
  for(const runId of runIds){
   const runs=(await identity.query('SELECT owner_key FROM graph_runtime.runs WHERE run_id=$1',[runId])).rows;assert.equal(runs.length,1);
   const key=JSON.parse(runs[0].owner_key);assert.deepEqual(key,['SecureShopBoundConversation',String(key[1])]);
   const sessions=(await agents.query('SELECT original_platform_owner_id FROM secureshop_agents.agent_sessions WHERE id=$1',[key[1]])).rows;assert.equal(sessions.length,1);assert.equal(Number(sessions[0].original_platform_owner_id),id);assert.notEqual(Number(sessions[0].original_platform_owner_id),other);
  }
  return Object.freeze({persistedOwnerVerified:true,httpDenialVerified:false});
 }
 async function captureResetReplayBaseline({firstResponse,recoveryResponse}){
  assert.ok(!replayBaselines.has(firstResponse.resetId),'Recovered launch baseline may be captured only once');
  assert.deepEqual(firstResponse,verifiedResets.get(firstResponse.resetId),'First reset must match the privately verified cleanup receipt');
  assert.equal(firstResponse.cleanupComplete,true);assert.equal(recoveryResponse?.preparationOnly,false);
  assert.deepEqual(Object.keys(firstResponse).sort(),['cleanupComplete','launch','resetId']);
  assert.deepEqual(Object.keys(recoveryResponse).sort(),['bearer','launch','preparationOnly']);
  for(const value of [firstResponse.launch,recoveryResponse.launch])assert.deepEqual(Object.keys(value||{}).sort(),['credentialVersion','expiresAt','generation','launchId']);
  for(const key of ['launchId','generation','expiresAt'])assert.equal(recoveryResponse.launch[key],firstResponse.launch[key],`Recovery changed ${key}`);
  assert.equal(recoveryResponse.launch.credentialVersion,firstResponse.launch.credentialVersion+1);
  assert.equal(typeof recoveryResponse.bearer,'string');assert.match(recoveryResponse.bearer,/^[A-Za-z0-9_-]{43}$/);
  const before=await snapshotLifecycle(),persisted=before.ownerLaunch;
  assert.equal(recoveryResponse.launch.launchId,persisted.launch_id);assert.equal(recoveryResponse.launch.generation,Number(persisted.generation));
  assert.equal(recoveryResponse.launch.credentialVersion,Number(persisted.credential_version));
  assert.equal(recoveryResponse.launch.expiresAt,new Date(persisted.expires_at).toISOString());
  replayBaselines.set(firstResponse.resetId,before);return Object.freeze({recoveryVerified:true});
 }
 async function verifyResetReplay({firstResponse,replayResponse}){
  assert.ok(replayBaselines.has(firstResponse.resetId),'Bound recovered launch baseline required before replay');
  assert.equal(replayResponse.resetId,firstResponse.resetId);assert.equal(replayResponse.cleanupComplete,true);
  const before=replayBaselines.get(firstResponse.resetId),persisted=before.ownerLaunch;
  for(const value of [firstResponse.launch,replayResponse.launch])assert.deepEqual(Object.keys(value||{}).sort(),['credentialVersion','expiresAt','generation','launchId']);
  for(const key of ['launchId','generation','expiresAt'])assert.equal(replayResponse.launch[key],firstResponse.launch[key],`Reset replay changed ${key}`);
  assert.equal(replayResponse.launch.launchId,persisted.launch_id);assert.equal(replayResponse.launch.generation,Number(persisted.generation));
  assert.equal(replayResponse.launch.credentialVersion,Number(persisted.credential_version));
  assert.equal(replayResponse.launch.expiresAt,new Date(persisted.expires_at).toISOString());
  assert.deepEqual(await snapshotLifecycle(),before,'Reset replay must not change generation, credential, history, targets or sibling');
  return Object.freeze({replayVerified:true});
 }
 async function verifyReentry({ownerId:id,beforeBinding,afterBinding}){
  admitted(id);assert.equal(beforeBinding.platformOwnerId,id);assert.equal(afterBinding.platformOwnerId,id);
  assert.equal(afterBinding.launchId,beforeBinding.launchId);assert.equal(afterBinding.scenarioId,beforeBinding.scenarioId);
  assert.equal(afterBinding.generation,beforeBinding.generation+1);assert.equal(afterBinding.platformSessionId,beforeBinding.platformSessionId);
  const actual=await forPersona({ownerId:id,role:afterBinding.role});assert.deepEqual(actual.binding,afterBinding);
  assert.equal((await expectedProgress(id)).completedObjectives,0);return Object.freeze({reentryVerified:true});
 }
 async function verifyLogout({ownerId:id,siblingId:other}){
  admitted(id);admitted(other);assert.notEqual(id,other);const prior=knownLaunches.get(id);assert.ok(prior,'Actual owned launch must have been observed before logout');
  const rows=(await identity.query('SELECT id,user_id,is_active FROM identity.user_sessions WHERE id=$1',[prior.platform_session_id])).rows;
  assert.equal(rows.length,1);assert.equal(Number(rows[0].user_id),id);assert.equal(Number(rows[0].is_active),0);
  await launch(other);return Object.freeze({persistedPlatformSessionRevoked:true,httpDenialVerified:false});
 }
 function assertLifecycleComplete(value){assert.ok(verifiedLifecycle.has(value),'Only this factory verified lifecycle receipt is accepted');return true;}
 return Object.freeze({version:'secureshop-rendered-native-evidence-v1',capabilities:Object.freeze({persistedBindings:true,semanticVerifiers:true,authorityHistoryProgress:true,completeLifecycle:true,runInspector:true,foreignRunIsolation:true,resetReplay:true,reentry:true,logoutRevocation:true}),forPersona,prepareScenario,expectedProgress,expectedStudentView,verifyRunDetail,verifyForeignRunIsolation,captureResetReplayBaseline,verifyResetReplay,verifyReentry,verifyLogout,snapshotLifecycle,snapshotBeforeReset:snapshotLifecycle,verifyReset,assertLifecycleComplete});
}
module.exports={createSecureShopRenderedNativeEvidence};
