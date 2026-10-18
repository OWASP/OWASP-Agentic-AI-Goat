'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {stageDigest,stageSnapshot,judgeCtfStage}=require('../server/agent-runtime/ctfStageJudge');
const {createCtfLessonReceipt}=require('../server/agent-runtime/ctfLessonState');
const {reviewerProfileEvidence}=require('../server/services/ctfDefenseLayers');
const hash=value=>createHash('sha256').update(value).digest('hex');
const stage6={id:6,stage_number:6,success_criteria:'SYNTHETIC_TOKEN',defense_style:'["meta_rotation_handoff_reviewer_v1"]'};

test('Stage 6 snapshot binds closed reviewer identity while all other stage bytes remain historical',()=>{
 const profile=reviewerProfileEvidence(stage6),snapshot=stageSnapshot(stage6),pairs=JSON.parse(snapshot);
 assert.deepEqual(profile&&Object.keys(profile).sort(),['id','policyDigest','version']);
 assert.deepEqual(Object.fromEntries(pairs).__ctf_reviewer_profile,profile);
 assert.equal(hash(snapshot),stageDigest(stage6));
 const replay=Object.fromEntries(pairs);
 assert.equal(stageSnapshot(replay),snapshot);
 replay.__ctf_reviewer_profile.policyDigest='0'.repeat(64);
 assert.throws(()=>stageDigest(replay),/profile snapshot mismatch/);
 for(const stage of [{id:5,stage_number:5,defense_style:'["meta_structured_artifact_reviewer_v1"]'},
   {id:6,stage_number:6,defense_style:'["meta_llm_judge"]'},
   {id:7,stage_number:7,defense_style:'["meta_llm_judge"]'}]){
   const old=JSON.stringify(Object.keys(stage).sort().map(key=>[key,stage[key]]));
   assert.equal(stageSnapshot(stage),old);
   assert.equal(stageDigest(stage),hash(old));
 }
});

test('Stage 6 Judge packet carries profile but retains exact post-defense visible-secret criterion',async()=>{
 const profile=reviewerProfileEvidence(stage6),visible='No protected value here';
 const result=await judgeCtfStage({stage:stage6,processedResponse:visible,realModel:true,observedSecret:false,reviewerProfile:profile},async packet=>{
   assert.equal(packet.rubric.version,'ctf-visible-secret-v2');
   assert.deepEqual(packet.rubric.requiredFacts,['real_model','post_defense_secret']);
   assert.equal(packet.rubric.criteria[0].quoteRequired,true);
   assert.deepEqual(packet.rubric.criteria[0].allowedSources,['assistant_response']);
   assert.equal(packet.facts.post_defense_secret,false);
   assert.equal(packet.evidence[0].content,visible);
   assert.deepEqual(packet.evidence[1],{id:'reviewer_profile',source:'server_observation',content:profile});
   return {verdict:'fail',rubricVersion:'ctf-visible-secret-v2'};
 });
 assert.equal(result.verdict,'fail');
 assert.deepEqual(result.reviewerProfile,profile);
 await assert.rejects(judgeCtfStage({stage:stage6,processedResponse:visible,realModel:true,observedSecret:false,reviewerProfile:{...profile,version:'forged'}},async()=>({verdict:'pass'})),/profile binding mismatch/);
});

test('private lesson receipt binds Stage 6 profile without changing five public observation flags',()=>{
 const profile=reviewerProfileEvidence(stage6),digest=stageDigest(stage6);
 const receipt=createCtfLessonReceipt({ownerId:7,participantId:9,stageId:6,stageNumber:6,stageDigest:digest,reviewerProfile:profile});
 receipt.bindAttempt(1);receipt.observeReviewer();
 assert.deepEqual(receipt.profileEvidence(),{stageDigest:digest,reviewerProfile:profile});
 assert.deepEqual(receipt.project({ownerId:7,participantId:9,stageId:6,attemptNumber:1}),{input_guard_observed:false,reviewer_observed:true,category_consumed:false,category_reuse_blocked:false,shared_similarity_blocked:false});
 assert.throws(()=>createCtfLessonReceipt({ownerId:7,participantId:9,stageId:5,stageNumber:5,stageDigest:digest,reviewerProfile:profile}),/Invalid CTF reviewer profile/);
});
