'use strict';
// Inert internal composition. Caller owns a bounded transaction; no pool, model,
// identity call, bootstrap or route activation occurs here.
const {resolveAttemptRegistrationLocator}=require('./ctfAttemptRegistrationLocator');
const {createCtfMutationAdapter}=require('./ctfDb');
const {validateCtfLifecycleCommand}=require('../../services/ctfLifecycleCommands');
const {buildCtfProjectionResult,validateCtfProjectionResult}=require('../../services/ctfProjectionResults');
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const one=async(c,sql,args=[])=>(await c.query(sql,args)).rows[0];
const id=v=>String(v);
// Receipt clocks bypass pg Date parsing; retain microseconds from the owned row.
const stamp=v=>v==null?v:v.replace(/(\.\d{3})000Z$/,'$1Z');
const drift=()=>{throw new Error('CTF_PROJECTION_STATE_DRIFT');};
async function dispatch(client,command,event){
 const m=createCtfMutationAdapter(client,{occurredAt:command.occurredAt}),s=command.scope,b=command.body;
 const owner=s.ownerId,p=s.participantId,stage=s.stageId;
 const progress=()=>one(client,`SELECT *,to_char(started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS receipt_started_at,to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS receipt_completed_at FROM ctf.ctf_progress WHERE participant_id=$1 AND stage_id=$2`,[p,stage]);
 let data,outcome='applied';
 switch(command.kind){
 case 'register':{
  const prior=await one(client,'SELECT id,is_active FROM ctf.ctf_participants WHERE user_id=$1',[owner]);
  if(event.registrationDisposition==='new'&&prior)drift();
  if(event.registrationDisposition==='active_recovery'&&(!prior||prior.is_active!==1||id(prior.id)!==event.registrationParticipantBefore))drift();
  if(event.registrationDisposition==='reactivate'&&prior&&(prior.is_active===1||id(prior.id)!==event.registrationParticipantBefore))drift();
  const a=await m.admitParticipant(owner,b.username,b.email,b.teamName);
  if(!a.admitted){outcome=a.reason;data={admitted:false,reason:a.reason,participantId:null,recovered:false,active:false,banned:false,registeredAt:null};break;}
  const row=await one(client,`SELECT *,to_char(started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS receipt_registered_at FROM ctf.ctf_participants WHERE id=$1 AND user_id=$2`,[a.participantId,owner]);if(!row)drift();
  await m.createSession(a.participantId,b.teachingSessionToken,b.clientIp,b.userAgent);
  await m.recordRegistration(a.participantId,JSON.stringify({username:b.username}));
  const ban=await one(client,'SELECT id FROM ctf.ctf_bans WHERE user_id=$1',[owner]);
  data={admitted:true,reason:null,participantId:id(row.id),recovered:a.recovered,active:row.is_active===1,banned:!!ban,registeredAt:stamp(row.receipt_registered_at)};break;
 }
 case 'start':{
  const prior=await progress();
  if(!prior||prior.status==='not_started'){
   const currentStage=await one(client,'SELECT stage_name FROM ctf.ctf_stages WHERE id=$1',[stage]);if(!currentStage)drift();
   await m.startStage(p,stage);await m.updateParticipantActivity(p);
   await m.recordStageStart(p,stage,JSON.stringify({stage_name:currentStage.stage_name}));
  }
  const row=await progress();if(!row)drift();
  data={progressId:id(row.id),status:row.status,startedAt:stamp(row.receipt_started_at),completedAt:stamp(row.receipt_completed_at),completionTime:row.completion_time==null?null:id(row.completion_time),attemptsCount:row.attempts_count,failedAttempts:row.failed_attempts,successfulAttempts:row.successful_attempts,hintsUsed:row.hints_used,hintPenaltyTotal:row.hint_penalty_total};break;
 }
 case 'hint':{
  await m.purchaseHint(s.progressId,b.expectedHints,b.cost);const row=await progress();if(!row||id(row.id)!==s.progressId)drift();
  data={progressId:id(row.id),hintsUsed:row.hints_used,hintPenaltyTotal:row.hint_penalty_total};break;
 }
 case 'admit_attempt':{
  const attemptNumber=await m.incrementAttempts(p,stage,b.failed,s.progressId);const row=await progress();if(!row||id(row.id)!==s.progressId)drift();
  data={progressId:id(row.id),attemptNumber,failedAttempts:row.failed_attempts};break;
 }
 case 'record_blocked_attempt':{
  const row=await progress();if(!row||id(row.id)!==s.progressId||row.attempts_count<b.attemptNumber)drift();
  let payloadHitIncremented=false;
  if(b.matchedPayloadHash!==null){payloadHitIncremented=await m.incrementPayloadHitCount(stage,b.matchedPayloadHash);if(!payloadHitIncremented)drift();}
  const locator=await resolveAttemptRegistrationLocator(client,s,b.teachingSessionToken);
  const attemptId=await m.logAttempt(p,stage,b.attemptNumber,b.payload,b.response,false,b.responseTime,locator,b.techniqueTag,b.techniqueConfidence,true,b.reason,b.payloadHash);
  data={attemptId:id(attemptId),admissionOperationId:b.admissionOperationId,payloadHitIncremented};break;
 }
 case 'owner_reset':case 'owner_remove':{
  const row=await one(client,'SELECT id FROM ctf.ctf_participants WHERE id=$1 AND user_id=$2',[p,owner]);if(!row)drift();
  const removed=command.kind==='owner_remove';await m.reset({participantId:p,userId:owner,remove:removed});data={participantId:p,removed};break;
 }
 case 'global_reset':{
  const row=await one(client,'SELECT count(*)::integer AS count FROM ctf.ctf_participants');await m.reset({all:true});data={removedParticipants:row.count};break;
 }
 case 'ban':case 'unban':{
  const banned=command.kind==='ban';if(banned)await m.banUser(owner,b.reason,command.actorId);else await m.unbanUser(owner);data={ownerId:owner,banned};break;
 }
 case 'blocklist_clear':{
  const removedCount=await (b.memory==='technique'?m.clearTechniqueBlocklist:m.clearPayloadBlocklist)(stage);data={memory:b.memory,stageId:stage,removedCount};break;
 }
 case 'config_mutation':{
  if(!await m.updateConfig(b.key,b.value))drift();data={key:b.key,value:b.value};break;
 }
 case 'catalog_mutation':{
  if(b.action==='delete'){const deleted=await m.deleteStage(stage);if(!deleted)drift();data={stageId:stage,deleted};break;}
  const stageId=b.action==='create'?await m.createStage(b.fields):stage;
  if(b.action==='update'&&!await m.updateStage(stage,b.fields))drift();
  const row=await one(client,'SELECT * FROM ctf.ctf_stages WHERE id=$1',[stageId]);if(!row)drift();
  let hints;try{hints=JSON.parse(row.hints||'[]');}catch{drift();}if(!Array.isArray(hints)||hints.length>3)drift();
  data={stageId:id(row.id),stageNumber:row.stage_number,stageOrder:row.stage_order,active:row.is_active===1,stageDigest:stageDigest(row),adaptiveMode:row.adaptive_mode,feedbackMode:row.feedback_mode,hintCount:hints.length,levelScore:row.level_score,maxAttempts:row.max_attempts};break;
 }
 default:throw new Error('CTF_DECISION_DELIVERY_NOT_ENABLED');
 }
 return {data,outcome};
}
async function applyCtfProjection(client,event){
 const command=validateCtfLifecycleCommand(event.command),sequence=event.sequence;
 if(typeof sequence!=='string'||!(/^[1-9][0-9]*$/).test(sequence)||BigInt(sequence)>9223372036854775807n)throw new TypeError('CTF sequence required');
 const owner=command.scope.ownerId,register=command.kind==='register';
 if(register?!['new','active_recovery','reactivate'].includes(event.registrationDisposition):event.registrationDisposition!==null)drift();
 if(register&&event.registrationDisposition!=='new'){
  if(typeof event.registrationParticipantBefore!=='string'||!(/^[1-9][0-9]*$/).test(event.registrationParticipantBefore)||BigInt(event.registrationParticipantBefore)>2147483647n)drift();
 }else if(event.registrationParticipantBefore!==null)drift();
 if(owner){
  const advances=['owner_reset','owner_remove'].includes(command.kind)||(register&&event.registrationDisposition!=='active_recovery');
  if(event.ownerGenerationAfter!==String(BigInt(command.scope.ownerGeneration)+(advances?1n:0n)))drift();
 }else if(event.ownerGenerationAfter!==null)drift();
 await client.query('SELECT pg_advisory_xact_lock(1886610804,44)');
 const cursor=await one(client,'SELECT * FROM ctf.projection_cursor WHERE singleton FOR UPDATE');
 if(!cursor?.initialized)throw new Error('CTF_PROJECTION_UNINITIALIZED');
 const prior=await one(client,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1 OR sequence=$2',[command.operationId,sequence]);
 if(prior){
  if(prior.operation_id!==command.operationId||id(prior.sequence)!==sequence||prior.command_hash!==command.commandHash)throw new Error('CTF_PROJECTION_REPLAY_CONFLICT');
  return validateCtfProjectionResult(command,sequence,prior.canonical_result,prior.result_hash);
 }
 if(BigInt(sequence)!==BigInt(cursor.applied_sequence)+1n)throw new Error('CTF_PROJECTION_OUT_OF_ORDER');
 const s=command.scope,k=command.kind,b=command.body;
 const scopes=(await client.query('SELECT * FROM ctf.projection_scopes WHERE scope_key=ANY($1::text[])',[['global',...(s.stageId?['stage:'+s.stageId]:[]),...(s.ownerId?['owner:'+s.ownerId]:[])]] )).rows;
 const byKey=new Map(scopes.map(row=>[row.scope_key,row]));
 if(id(byKey.get('global')?.revision)!==s.globalRevision)drift();
 if(s.stageId&&id(byKey.get('stage:'+s.stageId)?.revision)!==s.stageRevision)drift();
 const ownerScope=s.ownerId?byKey.get('owner:'+s.ownerId):null;
 if(s.ownerId&&ownerScope&&id(ownerScope.owner_generation)!==s.ownerGeneration)drift();
 if(s.ownerId&&!ownerScope&&await one(client,'SELECT id FROM ctf.ctf_participants WHERE user_id=$1',[s.ownerId]))drift();
 const {data,outcome}=await dispatch(client,command,event),receipt=buildCtfProjectionResult(command,sequence,data,outcome);
 await client.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind,command_hash,canonical_result,result_hash) VALUES($1,$2,$3,$4,$5,$6)',[sequence,command.operationId,command.kind,command.commandHash,receipt.canonicalResult,receipt.resultHash]);
 // A denied registration receipt is durable but does not advance delivery.
 // Identity acknowledgment will block authority with its reservation still held.
 if(outcome==='applied'){
  const put=async(key,revision,generation=null)=>client.query('INSERT INTO ctf.projection_scopes(scope_key,revision,owner_generation,applied_operation_id) VALUES($1,$2,$3,$4) ON CONFLICT(scope_key) DO UPDATE SET revision=EXCLUDED.revision,owner_generation=EXCLUDED.owner_generation,applied_operation_id=EXCLUDED.applied_operation_id',[key,revision,generation,command.operationId]);
  if(s.ownerId){const advance=event.ownerGenerationAfter!==s.ownerGeneration||['ban','unban'].includes(k);await put('owner:'+s.ownerId,String(BigInt(ownerScope?.revision||'0')+(advance?1n:0n)),event.ownerGenerationAfter);}
  else {
   const stageOnly=['catalog_mutation','blocklist_clear'].includes(k)&&s.stageId&&!(k==='catalog_mutation'&&(b.action==='delete'||Object.hasOwn(b.fields,'stage_order')||Object.hasOwn(b.fields,'is_active')));
   await put(stageOnly?'stage:'+s.stageId:'global',String(BigInt(stageOnly?s.stageRevision:s.globalRevision)+1n));
   if(k==='catalog_mutation'&&b.action==='create')await put('stage:'+data.stageId,'0');
  }
  await client.query('UPDATE ctf.projection_cursor SET applied_sequence=$1,last_operation_id=$2 WHERE singleton',[sequence,command.operationId]);
 }
 return receipt;
}
module.exports={applyCtfProjection};
