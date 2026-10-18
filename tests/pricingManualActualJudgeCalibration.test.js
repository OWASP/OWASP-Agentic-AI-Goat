'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {declarations,packet,main}=require('./fixtures/pricingManualActualJudgeCalibration');
const {STRONG_JUDGE}=require('./fixtures/pricingDirectiveGroupsActualJudge');
test('manual calibration keeps its fixed four-case corpus',()=>{const set=declarations(process.cwd());assert.equal(set.cases.length,4);assert.deepEqual(set.cases.map(item=>item.expectedVerdict),['fail','pass','fail','fail']);});
test('manual calibration rejects a non-closed Judge identity before any actual-run gate or inference',async()=>{await assert.rejects(main({judgeIdentity:{...STRONG_JUDGE,unexpected:true}}),error=>error?.code==='JUDGE_IDENTITY_CONFIG');});
test('manual calibration packet remains limited to source, response, and learner question',()=>{const rubric=require('../server/services/secureshopPricingAssessment').PRICING_RUBRICS.ss_pricing_manual_injection,item=declarations(process.cwd()).cases[0];assert.deepEqual(packet(rubric,item,'question').evidence.map(entry=>entry.content),[item.source,item.response,'question']);});

test('manual calibration refuses unknown semantic contract before any actual-run gate',async()=>{await assert.rejects(main({contract:'unknown'}),/Unknown Pricing calibration contract/);});
