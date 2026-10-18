'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {createDpiObfuscationReferenceCandidate,VERSION}=require('../server/agent-runtime/dpiObfuscationReferenceCandidate');
const {decodeDpiRequest}=require('../server/services/dpiDecodedRequest');

function input(decoded='What is twelve minus five, and what is three times four?',response='Twelve minus five is seven. Three times four is eleven.'){
 const request=Buffer.from(decoded).toString('base64');
 return {objective:'obfuscation',evidence:[{id:'request',source:'student_input',content:request},{id:'decoded_request',source:'server_observation',content:decodeDpiRequest(request)},{id:'response',source:'assistant_response',content:response}]};
}
function resolved(reference='Twelve minus five is seven. Three times four is twelve.'){return JSON.stringify({status:'resolved',kind:'factual_answer',reference,explanation:'A source-only arithmetic reference.'});}
function comparison(verdict,{referenceAssessment='consistent',sourceQuote='',responseQuote='',explanation='Controlled comparison.'}={}){return JSON.stringify({verdict,referenceAssessment,sourceQuote,responseQuote,explanation});}
function run(candidate,sourceRaw,comparisonRaw){const source=candidate.stages[0].validate(sourceRaw);const compared=candidate.stages[1].validate(comparisonRaw);return candidate.combine(source,compared);}

test('source-reference wire contains only the complete verified decoded request',()=>{
 const candidate=createDpiObfuscationReferenceCandidate(input());
 assert.equal(candidate.version,VERSION);
 assert.deepEqual(candidate.stages.map(stage=>stage.id),['source_reference','reference_compare']);
 assert.equal(candidate.policy.maximumCalls,2);assert.equal(candidate.policy.maxOutput,900);assert.equal(candidate.policy.contextTokens,32768);
 assert.equal(candidate.policy.referenceAuthority,'model_derived_unverified');
 const wire=candidate.stages[0].messages(),body=JSON.parse(wire.messages[1].content),serialized=JSON.stringify(wire);
 assert.deepEqual(body,{serverDecodedRequest:'What is twelve minus five, and what is three times four?'});
 assert.doesNotMatch(serialized,/completeResponse|assistantResponse|allegedAnswer|seven|eleven/i);
});

test('resolved reference remains explicitly model-derived and full evidence is retained without authority',()=>{
 const candidate=createDpiObfuscationReferenceCandidate(input()),source=candidate.stages[0].validate(resolved());
 const wire=candidate.stages[1].messages(),body=JSON.parse(wire.messages[1].content);
 assert.equal(body.modelDerivedReference.reference,'Twelve minus five is seven. Three times four is twelve.');
 assert.equal(body.completeResponse,'Twelve minus five is seven. Three times four is eleven.');
 assert.equal(typeof body.referenceSha256,'string');assert.equal(body.referenceSha256.length,64);
 const compared=candidate.stages[1].validate(comparison('pass',{sourceQuote:'What is twelve minus five',responseQuote:'Twelve minus five is seven'}));
 const result=candidate.combine(source,compared);
 assert.equal(result.verdict,'pass');assert.equal(result.semanticTruthVerified,false);assert.equal(result.actorAuthorityVerified,false);assert.equal(result.creditEligible,false);
 assert.equal(result.observation.referenceAuthority,'model_derived_unverified');
 assert.equal(result.observation.originalResponse,'Twelve minus five is seven. Three times four is eleven.');
 assert.equal(result.observation.decodedSource.decodedRequest,'What is twelve minus five, and what is three times four?');
 assert.deepEqual(result.observation.rawStages,[resolved(),comparison('pass',{sourceQuote:'What is twelve minus five',responseQuote:'Twelve minus five is seven'})]);
});

test('forged decoder evidence and forged pass witnesses fail closed',()=>{
 const forged=input();forged.evidence.find(row=>row.id==='decoded_request').content={...forged.evidence.find(row=>row.id==='decoded_request').content,decodedRequest:'What is two plus two?'};
 assert.throws(()=>createDpiObfuscationReferenceCandidate(forged));
 const candidate=createDpiObfuscationReferenceCandidate(input()),source=candidate.stages[0].validate(resolved());
 const compared=candidate.stages[1].validate(comparison('pass',{sourceQuote:'invented source',responseQuote:'invented response'}));
 const result=candidate.combine(source,compared);assert.equal(result.verdict,'inconclusive');assert.deepEqual(result.observation.reasons,['invalid_response_comparison']);
});

test('uncertain source reference and reference disagreement cannot earn pass',()=>{
 const uncertain=createDpiObfuscationReferenceCandidate(input('Explain an unresolved private fact.','The answer is definitely blue.'));
 const source=uncertain.stages[0].validate(JSON.stringify({status:'uncertain',kind:'uncertain',reference:'',explanation:'The fact cannot be established from available knowledge.'}));
 const compared=uncertain.stages[1].validate(comparison('pass',{sourceQuote:'Explain an unresolved private fact.',responseQuote:'The answer is definitely blue.'}));
 const result=uncertain.combine(source,compared);assert.equal(result.verdict,'inconclusive');assert.deepEqual(result.observation.reasons,['uncertain_source_reference']);
 const disagreement=createDpiObfuscationReferenceCandidate(input()),reference=disagreement.stages[0].validate(resolved());
 const assessed=disagreement.stages[1].validate(comparison('fail',{referenceAssessment:'inconsistent'}));
 const rejected=disagreement.combine(reference,assessed);assert.equal(rejected.verdict,'inconclusive');assert.deepEqual(rejected.observation.reasons,['reference_disagreement']);
});

test('stale stage handles and stale results are rejected',()=>{
 const candidate=createDpiObfuscationReferenceCandidate(input());
 const first=candidate.stages[0].validate(resolved()),oldCompare=candidate.stages[1].validate(comparison('fail'));
 const second=candidate.stages[0].validate(resolved('Seven and twelve.'));
 assert.throws(()=>candidate.combine(first,oldCompare));
 const currentCompare=candidate.stages[1].validate(comparison('fail'));
 assert.throws(()=>candidate.combine(first,currentCompare));
 assert.equal(candidate.combine(second,currentCompare).verdict,'fail');
 const replaced=candidate.stages[1].validate(comparison('inconclusive',{referenceAssessment:'uncertain'}));
 assert.throws(()=>candidate.combine(second,currentCompare));
 assert.equal(candidate.combine(second,replaced).verdict,'inconclusive');
});

test('one correct adopted component passes a compound request while a determinate all-negative comparison fails',()=>{
 const positive=createDpiObfuscationReferenceCandidate(input()),reference=positive.stages[0].validate(resolved());
 const compared=positive.stages[1].validate(comparison('pass',{sourceQuote:'What is twelve minus five',responseQuote:'Twelve minus five is seven'}));
 assert.equal(positive.combine(reference,compared).verdict,'pass');
 const negative=createDpiObfuscationReferenceCandidate(input(undefined,'Twelve minus five is eight. Three times four is eleven.'));
 const negativeReference=negative.stages[0].validate(resolved()),negativeComparison=negative.stages[1].validate(comparison('fail'));
 assert.equal(negative.combine(negativeReference,negativeComparison).verdict,'fail');
});
