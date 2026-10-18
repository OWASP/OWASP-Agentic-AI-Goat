'use strict';
// Internal closed receipt transport. A receipt is not a model judgment.
const {createHash}=require('node:crypto');
const {canonicalCtfJson,validateCtfLifecycleCommand}=require('./ctfLifecycleCommands');
const schemas={"register":{"type":"object","properties":{"admitted":{"type":"boolean"},"reason":{"type":"string","enum":["registration_closed","capacity_reached"],"nullable":true},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true},"recovered":{"type":"boolean"},"active":{"type":"boolean"},"banned":{"type":"boolean"},"registeredAt":{"type":"string","bytes":27,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}([0-9]{3})?Z$","nullable":true}},"optional":false},"start":{"type":"object","properties":{"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"status":{"type":"string","enum":["in_progress","completed"]},"startedAt":{"type":"string","bytes":27,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}([0-9]{3})?Z$"},"completedAt":{"type":"string","bytes":27,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}([0-9]{3})?Z$","nullable":true},"completionTime":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807","nullable":true},"attemptsCount":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"failedAttempts":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"successfulAttempts":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"hintsUsed":{"type":"number","minimum":0,"maximum":3,"integer":true},"hintPenaltyTotal":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false},"hint":{"type":"object","properties":{"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"hintsUsed":{"type":"number","minimum":1,"maximum":3,"integer":true},"hintPenaltyTotal":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false},"admit_attempt":{"type":"object","properties":{"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"attemptNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"failedAttempts":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false},"record_blocked_attempt":{"type":"object","properties":{"attemptId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"admissionOperationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"payloadHitIncremented":{"type":"boolean"}},"optional":false},"catalog_mutation":{"type":"object","properties":{"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stageOrder":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"active":{"type":"boolean"},"stageDigest":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"adaptiveMode":{"type":"string","enum":["none","technique","payload","hybrid"]},"feedbackMode":{"type":"string","enum":["full","reason","silent"]},"hintCount":{"type":"number","minimum":0,"maximum":3,"integer":true},"levelScore":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"maxAttempts":{"type":"number","minimum":-1,"maximum":1000000,"integer":true,"nullable":true}},"optional":false},"config_mutation":{"type":"object","properties":{"key":{"type":"string","enum":["ctf_enabled","ctf_visible_to_students","student_leaderboard_visible","public_leaderboard_visible","ctf_registration_open","ctf_max_participants","ctf_time_limit","leaderboard_update_interval","ctf_nav_visible","ctf_show_technique_feedback","ctf_show_attempt_counter","ctf_hint_gating_attempts","ctf_hint_cost_1","ctf_hint_cost_2","ctf_hint_cost_3"]},"value":{"type":"string","bytes":8192}},"optional":false},"owner_reset":{"type":"object","properties":{"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"removed":{"type":"boolean","enum":[false]}},"optional":false},"owner_remove":{"type":"object","properties":{"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"removed":{"type":"boolean"}},"optional":false},"global_reset":{"type":"object","properties":{"removedParticipants":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false},"ban":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"banned":{"type":"boolean"}},"optional":false},"unban":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"banned":{"type":"boolean"}},"optional":false},"blocklist_clear":{"type":"object","properties":{"memory":{"type":"string","enum":["technique","payload"]},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true},"removedCount":{"type":"number","minimum":0,"maximum":2147483647,"integer":true}},"optional":false},"catalog_delete":{"type":"object","properties":{"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"deleted":{"type":"boolean"}},"optional":false}};
function matches(v,r){
 if(v===null)return r.nullable===true;
 if(r.type==='object'){
  if(!v||Array.isArray(v)||![Object.prototype,null].includes(Object.getPrototypeOf(v)))return false;
  if(Reflect.ownKeys(v).some(k=>typeof k!=='string'||!Object.hasOwn(r.properties,k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value')))return false;
  return Object.keys(r.properties).every(k=>Object.hasOwn(v,k)&&matches(v[k],r.properties[k]));
 }
 if(typeof v!==r.type)return false;
 if(r.enum&&!r.enum.includes(v))return false;
 if(r.type==='string'&&(!v.isWellFormed()||v.includes('\0')||(r.bytes!==undefined&&Buffer.byteLength(v)>r.bytes)||(r.pattern&&!new RegExp(r.pattern).test(v))))return false;
 if(r.type==='number'&&(!Number.isFinite(v)||(r.integer&&!Number.isSafeInteger(v))))return false;
 if(r.minimum!==undefined||r.maximum!==undefined){
  if(r.type==='string'){const n=BigInt(v);if(n<BigInt(String(r.minimum))||n>BigInt(String(r.maximum)))return false;}
  else if(v<r.minimum||v>r.maximum)return false;
 }
 return true;
}
const fail=()=>{throw new TypeError('Invalid CTF projection result');};
function buildCtfProjectionResult(command,sequence,data,outcome='applied'){
 command=validateCtfLifecycleCommand(command);
 if(typeof sequence!=='string'||!(/^[1-9][0-9]*$/).test(sequence)||BigInt(sequence)>9223372036854775807n)fail();
 const schema=command.kind==='catalog_mutation'&&command.body.action==='delete'?schemas.catalog_delete:schemas[command.kind];
 if(!schema||!matches(data,schema))fail();
 if(command.kind==='register'){
  if(outcome==='applied'){if(!data.admitted||!data.active||data.reason!==null||data.participantId===null||data.registeredAt===null)fail();}
  else if(!['registration_closed','capacity_reached'].includes(outcome)||data.admitted||data.reason!==outcome||data.participantId!==null||data.registeredAt!==null)fail();
 }else if(outcome!=='applied')fail();
 if(command.kind==='start'&&((data.status==='completed')!==(data.completedAt!==null&&data.completionTime!==null)||(data.status!=='completed'&&(data.completedAt!==null||data.completionTime!==null))))fail();
 for(const k of ['registeredAt','startedAt','completedAt'])if(data[k]!=null&&(!Number.isFinite(Date.parse(data[k]))||new Date(data[k]).toISOString()!==data[k].replace(/(\.\d{3})\d{3}Z$/,'$1Z')))fail();
 const value={version:1,kind:command.kind,operationId:command.operationId,sequence,commandHash:command.commandHash,outcome,data};
 const canonicalResult=canonicalCtfJson(value);if(Buffer.byteLength(canonicalResult)>16384)fail();
 return Object.freeze({canonicalResult,resultHash:createHash('sha256').update(canonicalResult).digest('hex'),value:JSON.parse(canonicalResult)});
}
function validateCtfProjectionResult(command,sequence,canonicalResult,resultHash){
 if(typeof canonicalResult!=='string'||Buffer.byteLength(canonicalResult)>16384)fail();
 const value=JSON.parse(canonicalResult);
 if(!value||typeof value!=='object'||Array.isArray(value))fail();
 const result=buildCtfProjectionResult(command,sequence,value.data,value.outcome);
 if(result.canonicalResult!==canonicalResult||result.resultHash!==resultHash)fail();
 return result;
}
module.exports={buildCtfProjectionResult,validateCtfProjectionResult};
