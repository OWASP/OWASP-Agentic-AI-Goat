'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {buildCtfLifecycleCommand:build,validateCtfLifecycleCommand:validate}=require('../server/services/ctfLifecycleCommands');
const empty={ownerId:null,participantId:null,stageId:null,progressId:null,ownerGeneration:null,globalRevision:'0',stageRevision:null};
const owner={...empty,ownerId:'1',ownerGeneration:'9007199254740993'};
const stage={...empty,stageId:'3',stageRevision:'0'};
const progress={...owner,participantId:'2',stageId:'3',stageRevision:'0',progressId:'4'};
const authority=scope=>({operationId:'00000000-0000-0000-0000-000000000001',actorId:'1',occurredAt:'2026-09-26T00:00:00.000Z',scope});
const blocked={admissionOperationId:'00000000-0000-0000-0000-000000000002',matchedPayloadHash:null,attemptNumber:1,payload:'teach',response:'blocked',responseTime:0,teachingSessionToken:null,techniqueTag:'other',techniqueConfidence:0,reason:'policy',payloadHash:null};
test('closed lifecycle kinds roundtrip with exact zero/null values and canonical hashes',()=>{
 const cases=[['global_reset',{},empty],['owner_reset',{}, {...owner,participantId:'2'}],['owner_remove',{}, {...owner,participantId:'2'}],['ban',{reason:'teaching'},owner],['unban',{},owner],['blocklist_clear',{memory:'payload'},empty],['blocklist_clear',{memory:'technique'},stage],['start',{}, {...progress,progressId:null}],['hint',{expectedHints:0,cost:0},progress],['admit_attempt',{failed:false},progress],['record_blocked_attempt',blocked,progress],['register',{username:'learner',email:null,teamName:null,teachingSessionToken:'owned',clientIp:null,userAgent:null},owner],['catalog_mutation',{action:'delete',fields:{}},stage],['catalog_mutation',{action:'update',fields:{difficulty:'legendary',feedback_mode:'full',time_bonus_seconds:0}},stage],['catalog_mutation',{action:'create',fields:{stage_number:1,stage_name:'A',stage_order:0}},empty]];
 for(const [kind,body,scope] of cases){const c=build(kind,body,authority(scope));assert.deepEqual(validate(JSON.parse(JSON.stringify(c))),c);assert(Object.isFrozen(c.body));}
 for(const row of require('../server/data/ctfDefaults').configs)assert.equal(build('config_mutation',{key:row.key,value:row.value},authority(empty)).body.key,row.key);
 const one=build('hint',{expectedHints:0,cost:0},authority(progress));const two=build('hint',{cost:0,expectedHints:0},authority(progress));assert.equal(one.commandHash,two.commandHash);
});
test('decision, unknown SQL fields, malformed Unicode, invalid authority and tampering fail closed',()=>{
 assert.throws(()=>build('decision',{},authority(empty)),/NOT_ENABLED/);
 assert.throws(()=>build('execute_sql',{sql:'DELETE'},authority(empty)));
 assert.throws(()=>build('hint',{expectedHints:0,cost:0,table:'ctf_progress'},authority(progress)));
 assert.throws(()=>build('ban',{reason:'\ud800'},authority(owner)));
 assert.throws(()=>build('ban',{reason:'a\u0000b'},authority(owner)));
 assert.throws(()=>build('ban',{reason:'x'.repeat(4097)},authority(owner)));
 assert.throws(()=>build('global_reset',{},authority(owner)));
 assert.throws(()=>build('hint',{expectedHints:0,cost:0},authority({...progress,ownerGeneration:'9223372036854775808'})));
 const c=JSON.parse(JSON.stringify(build('hint',{expectedHints:0,cost:0},authority(progress))));c.body.cost=1;assert.throws(()=>validate(c));
 assert.throws(()=>build('catalog_mutation',{action:'delete',fields:{stage_name:'x'}},authority(stage)));
 assert.throws(()=>build('catalog_mutation',{action:'update',fields:{stage_number:2}},authority(stage)));
});
test('accessors are never evaluated and canonical copies do not alias caller input',()=>{
 let invoked=0;const body={get reason(){invoked++;return'x';}};
 assert.throws(()=>build('ban',body,authority(owner)));assert.equal(invoked,0);
 const data={reason:'old'};const c=build('ban',data,authority(owner));data.reason='new';assert.equal(c.body.reason,'old');
});

test('every authoritative default stage and config is accepted without logging protected content',()=>{
 const defaults=require('../server/data/ctfDefaults');
 for(const stage of defaults.stages){
  try{build('catalog_mutation',{action:'create',fields:stage},authority(empty));}
  catch{assert.fail(`Default stage ${stage.stage_number} schema rejected`);}
 }
 for(const config of defaults.configs)build('config_mutation',{key:config.key,value:config.value},authority(empty));
});

test('hint cost uses the instructor configuration ceiling exactly',()=>{
 const {MAX_HINT_COST}=require('../server/middleware/ctfHintConfigInput');
 for(const cost of [0,1000001,MAX_HINT_COST])assert.equal(build('hint',{expectedHints:0,cost},authority(progress)).body.cost,cost);
 assert.throws(()=>build('hint',{expectedHints:0,cost:MAX_HINT_COST+1},authority(progress)));
});

test('nullable managed stage patches preserve route semantics; defense null remains rejected',()=>{
 for(const key of ['stage_description','ai_guardian_personality','system_prompt','hints'])assert.equal(build('catalog_mutation',{action:'update',fields:{[key]:null}},authority(stage)).body.fields[key],null);
 assert.throws(()=>build('catalog_mutation',{action:'update',fields:{defense_style:null}},authority(stage)));
});

test('teaching content travels only as a bounded catalog patch',()=>{
 const command=build('catalog_mutation',{action:'update',fields:{stage_name:'Learner title',stage_description:'Learner description',hints:'["one"]',teaching_objective:'Learner objective',solution_content:'Instructor-only solution'}},authority(stage));
 assert.equal(command.body.fields.teaching_objective,'Learner objective');
 assert.equal(command.body.fields.solution_content,'Instructor-only solution');
 for(const fields of [{teaching_objective:null},{solution_content:null},{teaching_objective:'x'.repeat(8193)},{solution_content:'x'.repeat(16385)},{solution_content:'ok',guardian_policy:'forged'}])assert.throws(()=>build('catalog_mutation',{action:'update',fields},authority(stage)));
});

test('blocked admission graph null response is representable',()=>{
 assert.equal(build('record_blocked_attempt',{...blocked,response:null},authority(progress)).body.response,null);
});

test('ordered config rejects unprojectable boolean and numeric values before admission',()=>{
 const authority={operationId:'11111111-1111-1111-1111-111111111111',actorId:'1',occurredAt:'2026-09-26T00:00:00.000Z',scope:{ownerId:null,participantId:null,stageId:null,progressId:null,ownerGeneration:null,globalRevision:'0',stageRevision:null}};
 for(const [key,value] of [['ctf_enabled','garbage'],['ctf_enabled','1'],['ctf_max_participants','-2'],['ctf_hint_cost_1','715827883'],['ctf_time_limit','9223372036854775808'],['leaderboard_update_interval','01']])assert.throws(()=>build('config_mutation',{key,value},authority));
 for(const [key,value] of [['ctf_enabled','false'],['ctf_max_participants','-1'],['ctf_hint_cost_1','715827882'],['ctf_time_limit','9223372036854775807']])assert.equal(build('config_mutation',{key,value},authority).body.value,value);
});
