'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createOwnedMcpRegistryLifecycle}=require('../server/services/secureshopOwnedMcpRegistryLifecycle');
const id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',binding={launchId:id,scenarioId:id,generation:1,platformOwnerId:1,platformSessionId:1};
// Use the canonical binding constructor contract, including registered scenario.
function fixture(verified){let queries=0;const lifecycle=createOwnedMcpRegistryLifecycle({pool:{async query(sql,args){queries++;assert.ok(sql.includes('receipt_sha256=sha256'));assert.ok(sql.includes('NOT EXISTS'));return{rows:verified===null?[]:[{verified}]};}},cleanupAuthority:{async getOperation(){return{resetId:id,status:'committed',binding};}}});return{lifecycle,queries:()=>queries};}
test('disabled-history deletion verification is mandatory and preserves canonical lease checks',async()=>{
 let checks=0;const x=fixture(true);await x.lifecycle.verifyDeletion({jobId:id,subjectId:1,check:async()=>checks++});assert.equal(checks,2);assert.equal(x.queries(),1);
 for(const value of [false,null])await assert.rejects(fixture(value).lifecycle.verifyDeletion({jobId:id,subjectId:1,check:async()=>{}}),{code:'MCP_REGISTRY_CLEANUP_UNVERIFIED'});
});
test('conversation verification preserves original receipt and checks both retirement and replay',async()=>{
 const x=fixture(true),receipt=Object.freeze({privateReceipt:true}),base={async retireGeneration(){return receipt;},async readReceipt(){return receipt;}};
 const decorated=x.lifecycle.decorateConversation(base);assert.equal(await decorated.retireGeneration(id),receipt);assert.equal(await decorated.readReceipt(id),receipt);assert.equal(x.queries(),2);
 await assert.rejects(fixture(false).lifecycle.decorateConversation(base).retireGeneration(id),{code:'MCP_REGISTRY_CLEANUP_UNVERIFIED'});
});
test('real canonical lifecycle completion and checkpoint replay cannot bypass registry verification',async()=>{
 const {createSecureShopConversationLifecycle}=require('../server/services/secureshopConversationLifecycle');
 const {buildReceipt,digestSessionIds}=require('../server/database/postgres/secureshopConversationLifecycleRepository');
 const receipt=buildReceipt({resetId:id,...binding},{completedAt:'2026-09-26T12:00:00.000Z',sessionCount:0,uncertainTurnCount:0,sessionSetSha256:digestSessionIds([])});
 let state='pending',verified=false,reads=0;
 const authority={async getOperation(){return{resetId:id,status:'fenced',binding};}};
 const base=createSecureShopConversationLifecycle({cleanupAuthority:authority,turns:{async retire(){}},repository:{async beginRetirement(){return{resetId:id,status:state};},async listRetirableSessions(){return[];},async retireSession(){},async completeRetirement(){state='completed';},async readRetirementReceipt(){reads++;return receipt;}}});
 const wrapped=createOwnedMcpRegistryLifecycle({pool:{async query(){return{rows:[{verified}]};}},cleanupAuthority:authority}).decorateConversation(base);
 await assert.rejects(wrapped.retireGeneration(id),{code:'MCP_REGISTRY_CLEANUP_UNVERIFIED'});assert.equal(state,'completed','Canonical retirement is not rolled back by later verification denial');
 verified=true;assert.deepEqual(await wrapped.retireGeneration(id),receipt);assert.deepEqual(await wrapped.readReceipt(id),receipt);assert.equal(reads,3);
});
