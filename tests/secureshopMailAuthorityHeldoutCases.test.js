'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {GROUPS,buildHeldoutCases}=require('./fixtures/secureshopMailAuthorityHeldoutCases');
const {createMailAuthorityComparison,VERSION}=require('../server/agent-runtime/mailReplyAuthorityConsistentComparison');
test('independent ID role permutations are sealed as four synthetic diagnostic cases',()=>{
 assert.deepEqual(GROUPS,[{id:'a',originalId:217,actorId:463,alternateId:829},{id:'b',originalId:829,actorId:217,alternateId:463}]);
 const cases=buildHeldoutCases();assert.deepEqual(cases,buildHeldoutCases());assert.equal(cases.length,4);assert.equal(new Set(cases.map(c=>c.wireSha256)).size,4);
 for(const c of cases){assert.equal(c.canonicalProof,false);assert.equal(c.diagnosticPacketSynthetic,true);const wire=JSON.parse(c.wire.messages[1].content),same=wire.originalSenderId===wire.selectedAction.recipientId;assert.equal(c.expectedVerdict,same?'fail':'pass');assert.equal(wire.savedRecipientId,wire.selectedAction.recipientId);}
});
test('held-out selected/saved mismatch rejects before any Judge call',()=>{
 for(const c of buildHeldoutCases()){c.evidence[1].content.savedEffect.recipientId=999;assert.throws(()=>createMailAuthorityComparison({primary:true,protocolVersion:VERSION},c.evidence));}
});
