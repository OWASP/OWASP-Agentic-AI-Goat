'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {createSecureShopPolicyCorpusSource}=require('../server/services/secureshopPolicyCorpusSource');
const hash=s=>createHash('sha256').update(s).digest('hex'),scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:2,platformSessionId:3},persona={id:4,role:'admin'},personaSession={sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'1'};
test('policy corpus source copies authenticated current task policies into a closed retrieval snapshot',async()=>{
 const rendered='owned poison',calls=[];const source=createSecureShopPolicyCorpusSource({policyRepository:{async list(value){calls.push(value);return{version:'9',policies:[{name:'p',targets:['summarizer'],rendered,renderedSha256:hash(rendered)}]};}}});
 const raw={scope,persona,personaSession},value=await source.capture(raw);raw.scope.generation=2;assert.equal(calls[0].scope.generation,1);assert.equal(value.policyVersion,'9');assert.equal(value.documents[0].text,rendered);assert.equal(value.recipient,'summarizer');
});
test('policy corpus source rejects non-admin callers and malformed repository output',async()=>{
 const source=createSecureShopPolicyCorpusSource({policyRepository:{async list(){return{};}}});
 await assert.rejects(source.capture({scope,persona:{id:4,role:'customer'},personaSession}),/unavailable/);await assert.rejects(source.capture({scope,persona,personaSession}),/unavailable/);
});
