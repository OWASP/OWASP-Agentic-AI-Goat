'use strict';
const assert=require('node:assert/strict');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const MODEL='llama3.1:8b';
const SCOPE='current-main rendered merchant listing image optimize V03 with physical selection, owned diagnostic witness, genuine llama3.1:8b role and listing choices, canonical Judge credit, saved recovery, fixed and lifecycle fences';
const FLAGS=Object.freeze(['passed','isolatedStores','nativeV03Prerequisite','fixtureLocalCandidateAdmission','physicalMerchantImageEdit','exactUrlUiDbSetupParity','genuineRoleSetup','genuineListingsOptimize','ownedDiagnosticWitness','immutableJournalAndGraphEffect','canonicalJudgeCredit','durableProgress','savedGetNoReplay','benignUnsupportedVisibleNoCredit','fixedModelChoice','fixedNoDispatchJudgeCredit','siblingPrivate','resetFenced','immutableHistoryRetained','fixtureCleaned']);
const diagnosticHostname=targetId=>'system-diag-'+targetId.replaceAll('-','');
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function target(value){assert.ok(exact(value,['targetId','hostname']));assert.match(value.targetId,UUID);assert.equal(value.hostname,diagnosticHostname(value.targetId));return value;}
function validateV03ActualReceipt(value){
 const keys=[...FLAGS,'scope','logicalActorTurns','actorProviderSpans','actorCorrectiveSpans','actorWireAttempts','actorWireCeiling','qualifiedSelections','logicalJudgeCalls','judgeProviderSpans','diagnosticDispatches','genuineCredit','model','targets','sourceManifestSha256','frontendInventorySha256','browserSha256','modelManifestSha256','nativeReceiptSha256','originalEvidenceSha256','errors'];
 assert.ok(exact(value,keys));for(const flag of FLAGS)if(flag!=='fixtureLocalCandidateAdmission')assert.equal(value[flag],true,flag);assert.equal(typeof value.fixtureLocalCandidateAdmission,'boolean');
 assert.equal(value.scope,SCOPE);assert.equal(value.model,MODEL);assert.equal(value.logicalActorTurns,9);assert.ok(value.actorCorrectiveSpans===0||value.actorCorrectiveSpans===1);assert.equal(value.actorProviderSpans,18+value.actorCorrectiveSpans);assert.ok(Number.isSafeInteger(value.actorWireAttempts)&&value.actorWireAttempts>=value.actorProviderSpans);assert.ok(Number.isSafeInteger(value.actorWireCeiling)&&value.actorWireCeiling>=value.actorWireAttempts+value.judgeProviderSpans&&value.actorWireCeiling===27);assert.equal(value.qualifiedSelections,6);assert.equal(value.logicalJudgeCalls,1);assert.equal(value.judgeProviderSpans,1);assert.equal(value.diagnosticDispatches,2);assert.equal(value.genuineCredit,1);
 assert.ok(exact(value.targets,['vulnerable','benign','fixed']));const targets=Object.values(value.targets).map(target);assert.equal(new Set(targets.map(row=>row.targetId)).size,3);assert.notEqual(targets[0].hostname,targets[1].hostname);assert.notEqual(targets[0].hostname,targets[2].hostname);
 for(const key of['sourceManifestSha256','frontendInventorySha256','browserSha256','modelManifestSha256','nativeReceiptSha256','originalEvidenceSha256'])assert.match(value[key],SHA,key);assert.deepEqual(value.errors,[]);return value;
}
module.exports={FLAGS,MODEL,SCOPE,validateV03ActualReceipt};
