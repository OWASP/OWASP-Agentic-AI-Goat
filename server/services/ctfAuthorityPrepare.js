'use strict';
const {randomBytes}=require('node:crypto');
const {buildCtfLifecycleCommand}=require('./ctfLifecycleCommands');
const adminKinds=new Set(['catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear']);
const shapes={register:['teamName','displayName'],start:['stageId'],hint:['stageId','hintIndex'],catalog_mutation:['action','stageId','fields'],config_mutation:['key','value'],owner_reset:['ownerId'],owner_remove:['ownerId'],global_reset:[],ban:['ownerId','reason'],unban:['ownerId'],blocklist_clear:['memory','stageId']};
const fail=()=>{throw new TypeError('Invalid CTF request intent');};
const id=x=>{if(typeof x!=='string'||!/^[1-9][0-9]*$/.test(x)||BigInt(x)>2147483647n)fail();return x;};
function createCtfAuthorityPrepare({repository,token=()=>randomBytes(32).toString('hex')}){if(typeof repository?.read!=='function')fail();return async({kind,input,session},options)=>{
 if(!Object.hasOwn(shapes,kind)||!input||![Object.prototype,null].includes(Object.getPrototypeOf(input))||Reflect.ownKeys(input).some(k=>typeof k!=='string'||!shapes[kind].includes(k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(input,k),'value')))fail();
 const v=structuredClone(input),admin=adminKinds.has(kind),ownerKinds=['register','start','hint','owner_reset','owner_remove','ban','unban'];
 if(kind==='register'&&v.displayName!=null&&(typeof v.displayName!=='string'||!v.displayName.isWellFormed()||v.displayName.includes('\0')||Buffer.byteLength(v.displayName)>256))fail();
 const ownerId=ownerKinds.includes(kind)?id(admin?v.ownerId:session.actorId):null;
 const stageId=v.stageId==null?null:id(v.stageId);if(['start','hint'].includes(kind)&&!stageId)fail();
 const s=await repository.read({session,ownerId,stageId,admin},options);
 const scope={ownerId,participantId:null,stageId,progressId:null,ownerGeneration:ownerId?String(s.owner.generation):null,globalRevision:String(s.global.revision),stageRevision:stageId?String(s.stage.authority_revision):null};
 if(['start','hint','owner_reset','owner_remove'].includes(kind)){if(!s.participant)fail();scope.participantId=String(s.participant.participant_id);}
 let body={};
 // The display name is teaching-profile content; actor/session authority and
 // contact details still come exclusively from the canonical identity snapshot.
 if(kind==='register')body={username:v.displayName?.trim()||s.actor.username,email:s.actor.email??null,teamName:v.teamName??null,teachingSessionToken:token(),clientIp:null,userAgent:null};
 if(kind==='hint'){if(!s.progress||String(s.progress.participant_id)!==scope.participantId||s.progress.hints_used>=3)fail();if(Object.hasOwn(v,'hintIndex')){if(!Number.isInteger(v.hintIndex)||v.hintIndex<0||v.hintIndex>2)fail();if(v.hintIndex!==Number(s.progress.hints_used))throw Object.assign(Error('CTF hint state changed; recover the operation'),{statusCode:409,code:'CTF_HINT_STALE'});}scope.progressId=String(s.progress.progress_id);body={expectedHints:s.progress.hints_used,cost:s.config['hint_cost_'+(s.progress.hints_used+1)]};}
 if(kind==='catalog_mutation')body={action:v.action,fields:v.fields};
 if(kind==='config_mutation')body={key:v.key,value:v.value};
 if(kind==='ban')body={reason:v.reason};
 if(kind==='blocklist_clear')body={memory:v.memory};
 const checked=buildCtfLifecycleCommand(kind,body,{operationId:'00000000-0000-0000-0000-000000000001',actorId:session.actorId,occurredAt:'2000-01-01T00:00:00.000Z',scope});
 return Object.freeze({body:checked.body,scope:checked.scope});
 };}
module.exports={createCtfAuthorityPrepare};
