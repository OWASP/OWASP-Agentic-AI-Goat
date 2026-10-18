'use strict';
const fail=()=>{throw Object.assign(Error('CTF response unavailable'),{code:'CTF_RESPONSE_STALE',statusCode:409});};
const publicStage=['id','stage_number','stage_name','stage_description','difficulty_level','difficulty','ai_guardian_name','ai_guardian_personality','adaptive_mode','level_score','teaching_objective'];
function createCtfAuthorityResponseProjection({repository}){
 if(typeof repository?.read!=='function'||typeof repository?.readStage!=='function')throw TypeError('Canonical response repository required');
 return Object.freeze({async project({command,session},{signal}={}){
  const args={operationId:command.operationId,session},options={signal};let s=await repository.read(args,options);if(s.command.commandHash!==command.commandHash)fail();
  if(s.receipt.outcome!=='applied')fail();const kind=s.command.kind;let stage=null,hints=[];
  if(['start','hint'].includes(kind)){
   stage=await repository.readStage({stageId:s.command.scope.stageId,digest:s.stage.stage_digest},options);
   try{hints=JSON.parse(stage.hints||'[]');}catch{fail();}if(!Array.isArray(hints)||hints.length>3||hints.some(x=>typeof x!=='string'))fail();
   const previous=JSON.stringify(s);s=await repository.read(args,options);if(JSON.stringify(s)!==previous)fail();
  }
  if(signal?.aborted)fail();const r=s.receipt.data;let body;
  switch(kind){
   case'register':body={message:'Successfully registered for CTF',participantId:Number(r.participantId),sessionToken:s.command.body.teachingSessionToken};break;
   case'start':if(s.progress.status==='completed'){body={message:'Stage already completed',alreadyCompleted:true};break;}body={message:'Stage started successfully',stage:Object.fromEntries(publicStage.map(k=>[k,stage[k]])),attemptsSoFar:s.progress.attempts_count,hintsAvailable:s.progress.attempts_count>=s.config.hint_gating_attempts,hintsUsed:s.progress.hints_used,hintPenaltyTotal:s.progress.hint_penalty_total,purchasedHints:hints.slice(0,s.progress.hints_used)};break;
   case'hint':{const i=r.hintsUsed-1;if(i<0||i>=hints.length)fail();body={hint:hints[i],hintIndex:i,cost:s.command.body.cost,hintsUsed:r.hintsUsed,totalPenalty:r.hintPenaltyTotal,remainingHints:hints.length-r.hintsUsed,effectiveStageScore:Math.max(0,(stage.level_score??100)-r.hintPenaltyTotal)};break;}
   case'config_mutation':body={message:'Configuration updated successfully'};break;
   case'catalog_mutation':body=s.command.body.action==='create'?{message:'Stage created',id:Number(r.stageId)}:{message:s.command.body.action==='delete'?'Stage deleted':'Stage updated'};break;
   case'owner_reset':body={message:'Participant reset successfully'};break;
   case'owner_remove':body={message:`${s.owner.username} removed from CTF. They can re-register.`};break;
   case'global_reset':body={message:'CTF reset successfully'};break;
   case'ban':body={message:'User banned from CTF'};break;
   case'unban':body={message:'User unbanned'};break;
   case'blocklist_clear':body={message:`${s.command.body.memory==='technique'?'Technique':'Payload'} blocklist cleared (${r.removedCount} entries removed)`};break;
   default:fail();
  }
  return Object.freeze({status:200,body:Object.freeze(body)});
 }});
}
module.exports={createCtfAuthorityResponseProjection};
