'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {verifyActualReplyJudgment}=require('./fixtures/secureshopMailActualJudgmentContract');
const {createHash}=require('node:crypto');
const sha=v=>createHash('sha256').update(v).digest('hex');
function seal(f,raw){const packet=JSON.parse(f.packetRow.packet);packet.evidence[0].content={raw,sha256:sha(JSON.stringify(raw))};f.packetRow.packet=JSON.stringify(packet);f.judgmentRow.evidence_digest=sha(f.packetRow.packet);}
function fixture(){
 const audit={version:'mail-recipient-authority-comparison-v12',observation:{relation:'verified_unauthorized_reply',savedRecipientId:941}},judgment={evaluationId:'controlled-id',verdict:'pass',mailReplyComparison:audit};
 const binding={operationId:'controlled-operation',targetId:'controlled-target',scope:{platformOwnerId:1,platformSessionId:2,generation:1}},threadId=12;
 const raw={binding,operationId:binding.operationId,threadId,sourceSha256:'controlled-source',source:[{id:1}],sent:{recipientId:941,email_id:21,thread_id:12,contentSha256:'controlled-content'}};
 const f={packetRow:{evaluation_id:'controlled-id',packet:JSON.stringify({rubric:{version:'secureshop-mail-reply-v15',mailReplyComparison:{protocolVersion:audit.version}},evidence:[{id:'mail_reply_audit'}]})},judgmentRow:{evaluation_id:'controlled-id',rubric_version:'secureshop-mail-reply-v15',verdict:'pass',disposition:'awarded',result_json:{provider:'ollama',model:'controlled-wire-model',mailReplyComparison:audit}},judgment,completed:true,recipientId:941,model:'controlled-wire-model',binding:structuredClone(binding),threadId,observed:{binding:structuredClone(binding),threadId,send:structuredClone(raw.sent),source:structuredClone(raw.source),turn:{metadata:{sourceSha256:raw.sourceSha256}}}};seal(f,raw);return f;
}
test('actual cohort readback contract checks v15 packet and persisted audit/provider/disposition (synthetic control)',()=>{verifyActualReplyJudgment(fixture());for(const change of [f=>f.judgmentRow.result_json.provider='mock',f=>f.judgmentRow.result_json.model='other',f=>f.judgmentRow.rubric_version='secureshop-mail-reply-v13',f=>f.judgmentRow.disposition='rejected',f=>f.judgmentRow.result_json.mailReplyComparison=structuredClone({...f.judgment.mailReplyComparison,version:'other'}),f=>f.recipientId=157]){const f=fixture();change(f);assert.throws(()=>verifyActualReplyJudgment(f));}});

test('actual unavailability remains a retained negative even without completed provider audit',()=>{const f=fixture();f.completed=false;f.judgment={evaluationId:'controlled-id',verdict:'unavailable'};Object.assign(f.judgmentRow,{verdict:'unavailable',disposition:'pending',result_json:{provider:null,model:null,criteria:[]}});verifyActualReplyJudgment(f);f.completed=true;assert.throws(()=>verifyActualReplyJudgment(f));});

test('same-recipient unrelated packet cannot satisfy exact operation/thread/effect or canonical digest (synthetic)',()=>{
 for(const change of [r=>r.binding.operationId='other',r=>r.binding.targetId='other',r=>r.binding.scope.platformSessionId=99,r=>r.threadId=99,r=>r.sent.email_id=99,r=>r.sent.thread_id=99,r=>r.sent.contentSha256='other']){const f=fixture(),raw=JSON.parse(f.packetRow.packet).evidence[0].content.raw;change(raw);seal(f,raw);assert.throws(()=>verifyActualReplyJudgment(f));}
 const f=fixture();f.judgmentRow.evidence_digest='wrong';assert.throws(()=>verifyActualReplyJudgment(f));
});
