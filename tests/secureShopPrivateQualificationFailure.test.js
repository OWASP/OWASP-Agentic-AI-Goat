'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createSecureShopPersonaInboxRubric } = require('../server/services/secureshopPersonaInboxAssessment');
const { JUDGE_VERSION } = require('../server/agent-runtime/objectiveJudge');
const { resultValue } = require('../server/database/postgres/objectiveJudgmentRepository');
const { FIXTURES, FILE_NAME, MAX_PACKET_BYTES, MAX_RESULT_BYTES,
  attestSyntheticPersonaFixtures, privatePersonaJudgmentFailureArtifact,
  createOwnedPrivateQualificationWriter } = require('./fixtures/secureShopPrivateQualificationFailure');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const ids = ['ss_cross_persona_effect','ss_acl_advisory_effect'];
const facts = {
  model_selected_cross_persona:true,completed_cross_persona_effect:true,same_launch_resource:true,
  server_acl_denied:true,advisory_not_enforced:true,disclosed_after_denial:true,
  real_model_terminal:true,authoritative_advisory_chain_consistent:true,
  authoritative_cross_persona_disclosure_consistent:true,
};
function rows(overrides={}) {
  return FIXTURES.map((fixture,index)=>({message_id:index+1,fixture_key:fixture.fixtureKey,
    owner_shop_role:fixture.ownerRole,subject:fixture.subject,body:fixture.body,
    body_sha256:crypto.createHash('sha256').update(fixture.body).digest(),...overrides}));
}
function stored(objectiveId,index,{packetExtra=''}={}) {
  const kind=index===0?'cross':'advisory',body=FIXTURES[2].body;
  const evidence=[{id:'disclosed_private_message',source:'tool_result',content:body},
    {id:'persona_inbox_chain',source:'server_observation',content:{version:1,messageId:3,
      resourceOwner:{id:3,role:'admin'}}},
    ...(!index?[{id:'cross_persona_disclosure_outcome',source:'server_observation',content:{version:1,
      messageId:3,bodySha256:sha(body),privateMessageReturned:true,effectStatus:'completed'}}]:[]),
    ...(index?[{id:'advisory_acl_outcome',source:'server_observation',content:{version:1,
      crossPersona:true,policyDecision:'deny',enforcementMode:'advisory',policyEnforced:false,
      privateMessageReturned:true,effectStatus:'completed'}}]:[])];
  const required=createSecureShopPersonaInboxRubric(kind,'vuln').requiredFacts;
  const packet=JSON.stringify({rubric:createSecureShopPersonaInboxRubric(kind,'vuln'),
    facts:Object.fromEntries(required.map(key=>[key,facts[key]===true])),evidence,
    ...(packetExtra?{padding:packetExtra}:{})});
  const result={family:'SecureShop',scenario:'persona_inbox',objectiveId,
    rubricVersion:createSecureShopPersonaInboxRubric(kind,'vuln').version,evidenceDigest:sha(packet),
    runId:'70000000-0000-4000-8000-000000000001',mode:'vuln',verdict:index?'fail':'pass',
    explanation:index?'A scoped semantic criterion was not satisfied; no completion was awarded.':'All required server facts and scoped semantic criteria were satisfied.',
    criteria:[{id:index?'advisory_acl_disclosure':'cross_persona_resource_effect',satisfied:!index,
      evidenceRefs:index?[]:['disclosed_private_message'],citations:index?[]:[{
        evidenceId:'disclosed_private_message',quote:body}]}],provider:'ollama',model:'llama3.1:8b',
    usage:{outputTokens:12},durationMs:12,contextTokens:32768,attempts:1,errorCode:null,
    judgeVersion:JUDGE_VERSION,judgePolicyDigest:'a'.repeat(64),
    ...(index?{scopedCriteria:[{criterionId:'advisory_acl_disclosure',
      scopeEvidenceIds:evidence.map(item=>item.id),scopeEvidenceDigest:'b'.repeat(64),attempts:1,
      attemptDurationsMs:[12],provider:'ollama',model:'llama3.1:8b',responseSha256:'c'.repeat(64),
      errorCode:null,verdict:'fail'}]}:{})};
  const evaluationId=`90000000-0000-4000-8000-00000000000${index+1}`;
  const row={evaluation_id:evaluationId,family:'SecureShop',scenario:'persona_inbox',
    objective_id:objectiveId,rubric_version:result.rubricVersion,
    run_id:result.runId,mode:'vuln',
    verdict:result.verdict,disposition:index?'not_pass':'awarded',credited:index?null:evaluationId,
    packet,evidence_digest:sha(packet),rebuilt:{facts:JSON.parse(packet).facts,evidence}};
  row.result_json=resultValue(result,{family:'SecureShop',scenario:'persona_inbox',
    objective_id:objectiveId,rubric_version:result.rubricVersion,evidence_digest:row.evidence_digest,
    run_id:result.runId,mode:row.mode});
  return row;
}
function input(options={}) {
  const first=stored(ids[0],0,options),second=stored(ids[1],1,options);
  return {mode:'advisory',fresh:[first,second],expected:ids,
    packets:{cross:[first.rebuilt],advisory:[second.rebuilt]},attestation:attestSyntheticPersonaFixtures(rows())};
}

test('private artifact retains both exact expected receipts and their bounded provenance',()=>{
  const artifact=privatePersonaJudgmentFailureArtifact(input());
  assert.equal(artifact.objectives.length,2);assert.deepEqual(artifact.objectives.map(row=>row.verdict),['pass','fail']);
  for(const row of artifact.objectives){assert.equal(sha(row.packetJson),row.packetSha256);
    assert.equal(sha(row.resultJson),row.resultSha256);const result=JSON.parse(row.resultJson);
    assert.equal(result.provider,'ollama');assert.equal(result.model,'llama3.1:8b');
    if(row.objectiveId==='ss_acl_advisory_effect')assert.equal(result.scopedCriteria[0].responseSha256,'c'.repeat(64));
    else assert.equal(result.scopedCriteria,undefined);}
});

test('private artifact rejects non-fixture, tampered and oversized evidence without truncation',()=>{
  const altered=rows();altered[2]={...altered[2],body:'not reviewed',body_sha256:crypto.createHash('sha256').update('not reviewed').digest()};
  assert.throws(()=>attestSyntheticPersonaFixtures(altered),/Expected values to be strictly equal/);
  const tampered=input(),changed=JSON.parse(tampered.fresh[1].packet);
  changed.evidence[0].content='changed';tampered.fresh[1].packet=JSON.stringify(changed);
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(tampered),/digest mismatch/);
  const widened=input(),widenedPacket=JSON.parse(widened.fresh[1].packet);widenedPacket.extra=true;
  widened.fresh[1].packet=JSON.stringify(widenedPacket);widened.fresh[1].evidence_digest=sha(widened.fresh[1].packet);
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(widened));
  const wrongOwner=input(),ownerPacket=JSON.parse(wrongOwner.fresh[1].packet);
  ownerPacket.evidence.find(row=>row.id==='persona_inbox_chain').content.resourceOwner.role='customer';
  wrongOwner.fresh[1].packet=JSON.stringify(ownerPacket);wrongOwner.fresh[1].evidence_digest=sha(wrongOwner.fresh[1].packet);
  wrongOwner.packets.advisory[0].evidence=ownerPacket.evidence;
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(wrongOwner),/fixture owner/);
  const duplicate=input();duplicate.fresh.push({...duplicate.fresh[1]});
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(duplicate),/Exactly one expected/);
  const duplicateExpected=input();duplicateExpected.expected=[ids[0],ids[0]];
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(duplicateExpected),/must be unique/);
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(input({packetExtra:'x'.repeat(MAX_PACKET_BYTES)})),/packet exceeds bound/);
});

test('private artifact requires exact canonical result provenance and grounded citations',()=>{
  const extra=input();extra.fresh[0].result_json.unreviewed='x';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(extra),/exact canonical receipt/);
  const oldJudge=input();oldJudge.fresh[0].result_json.judgeVersion='objective-judge-v24';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(oldJudge),/foreign Judge version/);
  const ungrounded=input();ungrounded.fresh[0].result_json.criteria[0].citations[0].quote=
    'This plausible sentence does not occur in the reviewed private body.';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(ungrounded),/not grounded/);
  const partialProvider=input();partialProvider.fresh[0].result_json.model=null;
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(partialProvider),/jointly present or absent/);
  const foreignRun=input();foreignRun.fresh[0].run_id='70000000-0000-4000-8000-000000000099';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(foreignRun),/runId does not match/);
  const foreignVerdict=input();foreignVerdict.fresh[0].verdict='fail';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(foreignVerdict));
  const foreignFamily=input();foreignFamily.fresh[0].family='Other';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(foreignFamily));
  const foreignScenario=input();foreignScenario.fresh[0].scenario='other';
  assert.throws(()=>privatePersonaJudgmentFailureArtifact(foreignScenario));
});

test('private artifact preserves an exact unavailable transport receipt with null provider identity',()=>{
  const value=input(),row=value.fresh[1];
  const raw={...row.result_json,verdict:'unavailable',criteria:[],
    explanation:'Objective evaluation is temporarily unavailable; no completion was awarded.',
    provider:null,model:null,usage:null,durationMs:4,attempts:0,errorCode:'JUDGE_TRANSPORT'};
  delete raw.scopedCriteria;
  row.result_json=resultValue(raw,{family:'SecureShop',scenario:'persona_inbox',
    objective_id:row.objective_id,rubric_version:row.rubric_version,
    evidence_digest:row.evidence_digest,run_id:raw.runId,mode:row.mode});
  row.verdict='unavailable';row.disposition='not_pass';row.credited=null;
  const artifact=privatePersonaJudgmentFailureArtifact(value);
  const retained=JSON.parse(artifact.objectives[1].resultJson);
  assert.equal(retained.verdict,'unavailable');assert.equal(retained.errorCode,'JUDGE_TRANSPORT');
  assert.equal(retained.provider,null);assert.equal(retained.model,null);
});

test('owned writer creates one mode-0600 artifact and rejects a collision',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-private-qualification-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.chmodSync(root,0o700);const writer=createOwnedPrivateQualificationWriter(fs.realpathSync(root));
  assert.throws(()=>writer.write({scope:'forged'}),/helper-built/);
  const artifact=privatePersonaJudgmentFailureArtifact(input());assert.equal(writer.write(artifact),writer.output);
  assert.equal(fs.statSync(writer.output).mode&0o777,0o600);assert.deepEqual(JSON.parse(fs.readFileSync(writer.output)),artifact);
  assert.throws(()=>writer.write(artifact),error=>error?.code==='EEXIST');
  assert.deepEqual(JSON.parse(fs.readFileSync(writer.output)),artifact,'collision must not replace prior evidence');
});
