'use strict';
// Pure transport validation, NOT caller authentication or enqueue authority.
// Build only from server-captured identity, persisted stage/progress IDs and DB
// timestamps. HTTP bodies must never be spread into the authority argument.
const { createHash } = require('node:crypto');
const MAX_COMMAND_BYTES = 65536;
const defaults = require('../data/ctfDefaults');
const { MAX_HINT_COST } = require('../middleware/ctfHintConfigInput');
const fail = () => { throw new TypeError('Invalid CTF lifecycle command'); };
const id = x => typeof x === 'string' && /^[1-9][0-9]*$/.test(x) && BigInt(x) <= 2147483647n;
const generation = x => typeof x === 'string' && /^(0|[1-9][0-9]*)$/.test(x) && BigInt(x) <= 9223372036854775807n;
const uuid = x => typeof x === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
const timestamp = x => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x) && Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;
const text = max => x => typeof x === 'string' && x.isWellFormed() && !x.includes('\u0000') && Buffer.byteLength(x, 'utf8') <= max;
const integer = (min,max) => x => Number.isSafeInteger(x) && x >= min && x <= max;
const choice = values => x => values.includes(x);
const nullable = validator => x => x === null || validator(x);
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype,null].includes(Object.getPrototypeOf(value))) fail();
  for (const key of Reflect.ownKeys(value)) if (typeof key !== 'string' || ['__proto__','prototype','constructor'].includes(key)
    || !Object.getOwnPropertyDescriptor(value,key).enumerable
    || !Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value')) fail();
  return value;
}
function shape(value, fields, optional = []) {
  object(value);
  if (Object.keys(value).some(key => !Object.hasOwn(fields,key))
    || Object.keys(fields).some(key => !optional.includes(key) && !Object.hasOwn(value,key))) fail();
  for (const [key, val] of Object.entries(value)) if (!fields[key](val)) fail();
  return true;
}
const stageFields = {
  stage_number: integer(1,2147483647), stage_name:text(1024),stage_description:nullable(text(8192)),difficulty_level:nullable(text(128)),
  ai_guardian_name:nullable(text(1024)),ai_guardian_personality:nullable(text(8192)),system_prompt:nullable(text(16384)),success_criteria:text(4096),
  hints:nullable(text(8192)),teaching_objective:text(8192),solution_content:text(16384),stage_order:integer(0,2147483647),difficulty:choice([...new Set(defaults.stages.map(row=>row.difficulty))]),
  defense_style:text(4096),adaptive_mode:choice(['none','technique','payload','hybrid']),level_score:integer(0,1000000),time_bonus_seconds:integer(0,2147483647),
  feedback_mode:choice([...new Set(defaults.stages.map(row=>row.feedback_mode))]),is_active:integer(0,1),max_attempts:integer(-1,1000000),
};
const stagePatch = x => { shape(x,stageFields,Object.keys(stageFields)); return true; };
const configKeys = defaults.configs.map(row=>row.key);
const schemas = {
  catalog_mutation: { action:choice(['create','update','delete']), fields:stagePatch },
  config_mutation: { key:choice(configKeys),value:text(8192) },
  owner_reset: {}, owner_remove: {}, global_reset: {},
  ban:{reason:text(4096)},unban:{},blocklist_clear:{memory:choice(['technique','payload'])},
  register:{username:text(256),email:nullable(text(320)),teamName:nullable(text(256)),teachingSessionToken:text(256),clientIp:nullable(text(128)),userAgent:nullable(text(1024))},
  start:{},hint:{expectedHints:integer(0,1000000),cost:integer(0,MAX_HINT_COST)},
  admit_attempt:{failed:x=>typeof x==='boolean'},
  record_blocked_attempt:{admissionOperationId:uuid,matchedPayloadHash:nullable(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x)),attemptNumber:integer(1,1000000),payload:text(16384),response:nullable(text(16384)),responseTime:integer(0,300000),
    teachingSessionToken:nullable(text(256)),techniqueTag:nullable(text(128)),techniqueConfidence:nullable(x=>typeof x==='number'&&Number.isFinite(x)&&x>=0&&x<=1),
    reason:text(4096),payloadHash:nullable(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x))},
};
const scopeFields = {ownerId:nullable(id),participantId:nullable(id),stageId:nullable(id),progressId:nullable(id),
  ownerGeneration:nullable(generation),globalRevision:generation,stageRevision:nullable(generation)};
function validateScope(kind, value, body) {
  shape(value,scopeFields);
  if ((value.ownerId === null) !== (value.ownerGeneration === null)) fail();
  if ((value.stageId === null) !== (value.stageRevision === null)) fail();
  const ownerKinds=['owner_reset','owner_remove','ban','unban','register','start','hint','admit_attempt','record_blocked_attempt'];
  if (ownerKinds.includes(kind) && value.ownerId === null) fail();
  if (['start','hint','admit_attempt','record_blocked_attempt'].includes(kind) && (value.participantId === null || value.stageId === null)) fail();
  if (['hint','admit_attempt','record_blocked_attempt'].includes(kind) && value.progressId === null) fail();
  if (['global_reset','config_mutation','catalog_mutation','blocklist_clear'].includes(kind)
    && [value.ownerId,value.ownerGeneration,value.participantId,value.progressId].some(x=>x!==null)) fail();
  if(['global_reset','config_mutation'].includes(kind) && value.stageId!==null) fail();
  if(['owner_reset','owner_remove','ban','unban','register'].includes(kind) && (value.stageId!==null||value.progressId!==null)) fail();
  if(['owner_reset','owner_remove'].includes(kind) && value.participantId===null) fail();
  if(['ban','unban','register'].includes(kind) && value.participantId!==null) fail();
  if(kind==='start' && value.progressId!==null) fail();
  if (kind==='catalog_mutation' && (body.action==='create' ? value.stageId!==null : value.stageId===null)) fail();
}
function canonical(value) {
  if (value && typeof value === 'object') return Array.isArray(value) ? value.map(canonical)
    : Object.fromEntries(Object.keys(value).sort().map(key => [key,canonical(value[key])]));
  return value;
}
function deepFreeze(value) { if(value && typeof value==='object'){Object.values(value).forEach(deepFreeze);Object.freeze(value);}return value; }
function buildCtfLifecycleCommand(kind, body, authority) {
  if (!Object.hasOwn(schemas,kind)) { if(kind==='decision') throw new Error('CTF_DECISION_DELIVERY_NOT_ENABLED'); fail(); }
  shape(body,schemas[kind]);
  shape(authority,{operationId:uuid,actorId:id,occurredAt:timestamp,scope:x=>{validateScope(kind,x,body);return true;}});
  if(kind==='config_mutation') {
    const numeric={ctf_max_participants:[-1n,9223372036854775807n],ctf_time_limit:[-1n,9223372036854775807n],leaderboard_update_interval:[0n,2147483647n],ctf_hint_gating_attempts:[0n,2147483647n],ctf_hint_cost_1:[0n,BigInt(MAX_HINT_COST)],ctf_hint_cost_2:[0n,BigInt(MAX_HINT_COST)],ctf_hint_cost_3:[0n,BigInt(MAX_HINT_COST)]};
    if(Object.hasOwn(numeric,body.key)) {
      if(!/^(?:-1|0|[1-9][0-9]*)$/.test(body.value))fail();
      const value=BigInt(body.value),[min,max]=numeric[body.key];if(value<min||value>max)fail();
    }else if(!['true','false'].includes(body.value))fail();
  }
  if(kind==='catalog_mutation') {
    if((body.action==='delete') !== (Object.keys(body.fields).length===0)) fail();
    if(body.action==='create' && (!Object.hasOwn(body.fields,'stage_number')||!Object.hasOwn(body.fields,'stage_name')||!Object.hasOwn(body.fields,'stage_order'))) fail();
    if(body.action==='update' && Object.hasOwn(body.fields,'stage_number')) fail();
  }
  const content=canonical({version:1,kind,operationId:authority.operationId,actorId:authority.actorId,occurredAt:authority.occurredAt,scope:authority.scope,body});
  const encoded=JSON.stringify(content);
  const commandHash=createHash('sha256').update(encoded).digest('hex');
  const command={...content,commandHash};
  if(Buffer.byteLength(JSON.stringify(command),'utf8')>MAX_COMMAND_BYTES) fail();
  return deepFreeze(command);
}
function validateCtfLifecycleCommand(command) {
  shape(command,{version:x=>x===1,kind:text(64),operationId:uuid,actorId:id,occurredAt:timestamp,scope:()=>true,body:()=>true,commandHash:x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x)});
  const built=buildCtfLifecycleCommand(command.kind,command.body,{operationId:command.operationId,actorId:command.actorId,occurredAt:command.occurredAt,scope:command.scope});
  if(built.commandHash!==command.commandHash) fail();
  return built;
}
module.exports={buildCtfLifecycleCommand,validateCtfLifecycleCommand,MAX_COMMAND_BYTES,canonicalCtfJson:value=>JSON.stringify(canonical(value))};
