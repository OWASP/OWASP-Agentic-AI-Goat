'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const V5 = require('./fixtures/secureshopUserLookupResponseFormatV5');
const E = require('../server/services/secureshopUserLookupEvidence');
const {prepareJudgeInput} = require('../server/agent-runtime/objectiveJudge');
test('fresh genuine pair retains original four-criterion packets without host verdict hints', () => {
  const pair = V5.prepareGenuinePair();
  assert.equal(pair.executionAuthorized, false);
  assert.equal(pair.creditAuthorized, false);
  assert.equal(pair.calibrationCompleted, false);
  assert.equal(pair.negative.provenance.assessmentAttempted, false);
  assert.equal(pair.negative.provenance.cohortPassed, false);
  for (const entry of [pair.positive,pair.negative]) {
    const packet = V5.modelInput(pair,entry);
    assert(E.isUserLookupJudgeInputValid(packet));
    assert.deepEqual(packet.rubric.criteria, prepareJudgeInput({...packet,rubric:{...E.RUBRIC,mode:'vuln'}}).rubric.criteria);
    assert.equal(packet.evidence[1].source,'server_observation');
    assert.equal(packet.evidence[2].source,'assistant_response');
    for (const key of ['provenance','expectedVerdict','positive','negative','cohortPassed','calibrationCompleted']) assert.equal(Object.hasOwn(packet,key),false);
    assert(Object.isFrozen(packet.evidence[1].content));
  }
  const positive = V5.modelInput(pair,pair.positive), negative = V5.modelInput(pair,pair.negative);
  assert(E.FIELDS.every(k=>positive.evidence[2].content.includes(positive.evidence[1].content[k])));
  assert(E.FIELDS.every(k=>!negative.evidence[2].content.includes(negative.evidence[1].content[k])));
});
test('copies, relabels, cross-pair and reconstructed admission are rejected', () => {
  const pair=V5.prepareGenuinePair(), other=V5.prepareGenuinePair();
  for (const altered of [structuredClone(pair),{...pair},JSON.parse(JSON.stringify(pair)),{...pair,positive:pair.negative}])
    assert.throws(()=>V5.modelInput(altered,pair.negative),/fresh genuine pair/);
  assert.throws(()=>V5.modelInput(pair,other.negative),/fresh genuine pair/);
  assert.throws(()=>V5.modelInput(pair,structuredClone(pair.negative)),/fresh genuine pair/);
  assert.throws(()=>{V5.modelInput(pair,pair.negative).evidence[2].content='fabricated';},TypeError);
});
