'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createObjectiveJudgmentRepository}=require('../server/database/postgres/objectiveJudgmentRepository');

const evaluationId='123e4567-e89b-42d3-a456-426614174001';
const runId='123e4567-e89b-42d3-a456-426614174000';
const xssScope=Object.freeze({runId,ownerId:7,ownerKey:'["XSS","7"]',scopeKey:'stored_user',
 parentGeneration:'3',childGeneration:'4'});
const input={userId:7,evaluationId,workshopKey:'xss_workshop',objectiveId:'xss_s2',family:'XSS',scenario:'stored',
 rubricVersion:'xss-v1',evidenceDigest:'a'.repeat(64),runId,mode:null,expectedGeneration:9,
 expectedMode:null,expectedModeStamp:'default',xssScope};
function row(){return{user_id:7,evaluation_id:evaluationId,workshop_key:'xss_workshop',objective_id:'xss_s2',
 family:'XSS',scenario:'stored',rubric_version:'xss-v1',evidence_digest:'a'.repeat(64),run_id:runId,
 generation:9,mode:null,canonical_mode:null,mode_stamp:'default',verdict:null,disposition:null};}
function fixture({existing=false,childFailure=false,scopedRun=false}={}){
 const events=[];
 const client={release(){},async query(sql){
  events.push(sql.trim().split(/\s+/).slice(0,5).join(' '));
  if(sql==='BEGIN'||sql==='COMMIT'||sql==='ROLLBACK')return{rows:[],rowCount:0};
  if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:'xss_workshop',is_visible:true,
    exercise_active:true,catalog_active:true,is_enabled:true}],rowCount:1};
  if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation:9}],rowCount:1};
  if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[],rowCount:0};
  if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:existing?[row()]:[],rowCount:existing?1:0};
  if(sql.includes('INSERT INTO workshop_platform.objective_judgments'))return{rows:[row()],rowCount:1};
  return{rows:[],rowCount:1};
 }};
 const xssBindings={
  async assertRunIsUnscoped(){events.push('xss:unscoped');if(scopedRun)throw Object.assign(new Error('scoped run'),{code:'STALE_GENERATION'});},
  async lockEvaluationPrefix(){events.push('xss:prefix');return existing?xssScope:null;},
  async lockRunPrefix(){events.push('xss:run');return xssScope;},
  async bindEvaluationAfterWorkshopLock(){events.push('xss:bind');return xssScope;},
  async assertChildAfterWorkshopLock(){events.push('xss:child');if(childFailure){const e=new Error('stale');e.code='STALE_GENERATION';throw e;}return xssScope;},
 };
 return{repo:createObjectiveJudgmentRepository({connect:async()=>client},{xssBindings}),events};
}

test('new XSS evaluation locks run prefix before workshop state and binds after judgment insertion',async()=>{
 const f=fixture();await f.repo.beginEvaluation(input);
 const run=f.events.indexOf('xss:run'), workshop=f.events.findIndex(value=>value.includes('workshop_platform.user_state'));
 const inserted=f.events.findIndex(value=>value.includes('INSERT INTO workshop_platform.objective_judgments'));
 assert.ok(run>=0&&run<workshop);assert.ok(inserted>=0&&inserted<f.events.indexOf('xss:bind'));
});

test('existing scoped evaluation checks child after workshop lock and rolls back when stale',async()=>{
 const f=fixture({existing:true,childFailure:true});
 await assert.rejects(f.repo.beginEvaluation(input),{code:'STALE_GENERATION'});
 assert.ok(f.events.indexOf('xss:prefix')<f.events.findIndex(value=>value.includes('workshop_platform.user_state')));
 assert.equal(f.events.includes('xss:run'),false,'persisted replay does not require the original run to remain running');
 assert.ok(f.events.includes('xss:child'));assert.ok(f.events.includes('ROLLBACK'));
 assert.equal(f.events.some(value=>value.includes('INSERT INTO workshop_platform.objective_judgments')),false);
});

test('omitted scope on a scoped run rolls back before judgment insertion',async()=>{
 const f=fixture({scopedRun:true});
 const {xssScope:ignored,...unbound}=input;
 await assert.rejects(f.repo.beginEvaluation(unbound),{code:'STALE_GENERATION'});
 assert.ok(f.events.includes('xss:unscoped'));assert.ok(f.events.includes('ROLLBACK'));
 assert.equal(f.events.some(value=>value.includes('INSERT INTO workshop_platform.objective_judgments')),false);
});
test('persisted scoped receipt cannot be replayed as unbound legacy evidence',async()=>{
 const f=fixture({existing:true});
 const {xssScope:ignored,...unbound}=input;
 await assert.rejects(f.repo.beginEvaluation(unbound),{code:'IDEMPOTENCY_CONFLICT'});
 assert.ok(f.events.includes('ROLLBACK'));
});
