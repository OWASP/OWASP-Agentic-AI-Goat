'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {captureXssJudgmentScope,XSS_OBJECTIVE_SCOPES}=require('../server/services/xssJudgmentScope');

const runId='123e4567-e89b-42d3-a456-426614174000';
const base=()=>Object.freeze({runId,ownerId:7,ownerKey:'["XSS","7"]',scopeKey:'stored_user',
  parentGeneration:'9007199254740993',childGeneration:'4'});

test('captures exact protected scope before objective selection and binds closed objective mapping',()=>{
 const captured=captureXssJudgmentScope(base(),{userId:7,runId});
 assert.ok(Object.isFrozen(captured));assert.equal(captured.parentGeneration,'9007199254740993');
 assert.equal(captureXssJudgmentScope(base(),{userId:7,runId,objectiveId:'xss_s2'}).scopeKey,'stored_user');
 assert.equal(XSS_OBJECTIVE_SCOPES.xss_g3,'stored_llm');
});

test('rejects mutable, foreign, extra, ambiguous, and objective-mismatched bindings',()=>{
 const cases=[
  {...base()},
  Object.freeze({...base(),extra:true}),
  Object.freeze({...base(),ownerId:8}),
  Object.freeze({...base(),ownerKey:'["XSS","8"]'}),
  Object.freeze({...base(),runId:'223e4567-e89b-42d3-a456-426614174000'}),
  Object.freeze({...base(),parentGeneration:9007199254740993}),
 ];
 for(const value of cases) assert.throws(()=>captureXssJudgmentScope(value,{userId:7,runId}),TypeError);
 assert.throws(()=>captureXssJudgmentScope(base(),{userId:7,runId,objectiveId:'xss_g2'}),TypeError);
 assert.throws(()=>captureXssJudgmentScope(base(),{userId:7,runId,objectiveId:'unknown'}),TypeError);
});
