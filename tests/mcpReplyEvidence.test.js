'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {buildReplyEvidence}=require('../server/services/mcp/replyEvidence');
test('reply evidence retains earlier output and accurately describes later failures',()=>{
 const observations=[
  {toolUsed:'get_config',params:{},toolResult:{output:'training value',configObservation:{privateCapability:'never serialize'}}},
  {toolUsed:'read_file',params:{path:'missing'},toolResult:{output:'',error:'file missing'}},
 ];
 const result=buildReplyEvidence(observations[1].toolResult,observations);
 assert.deepEqual(result.records.map(item=>item.status),['returned','failed']);
 assert.ok(result.fallback.includes('training value'));assert.ok(result.fallback.includes('file missing'));
 assert.equal(JSON.stringify(result).includes('privateCapability'),false);
 assert.equal(JSON.stringify(result).includes('never serialize'),false);
});
test('reply fallback marks truncation and refuses to call a blocked tool successful',()=>{
 const result=buildReplyEvidence({tool:'read_file',blocked:true,error:'denied '+('💥'.repeat(5000))});
 assert.equal(result.records[0].status,'refused');
 assert.equal(result.records[0].outputTruncated,true);
 assert.ok(result.fallback.includes('[TRUNCATED'));
 assert.ok(Buffer.byteLength(result.records[0].output)<=8000);
});
