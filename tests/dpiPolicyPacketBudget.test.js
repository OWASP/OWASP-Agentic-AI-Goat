'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {validateRecoveryPacket}=require('../server/database/postgres/objectiveJudgmentRepository');
const binding=require('../server/agent-runtime/dpiPolicyBinding');
const {prepareJudgeInput,boundedJson}=require('../server/agent-runtime/objectiveJudge');
const actor=require('../server/agent-runtime/dpiActorProof'),policy=require('../server/agent-runtime/dpiPolicyContract');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function nearCap(){
 const request='Explain AWS storage.',response='AWS offers object storage.',execution={runId:crypto.randomUUID(),ownerKey:'owned:budget',durableGeneration:1,async check(){}},attempt={runId:execution.runId,mode:'vuln',objectiveId:'interact'};
 const proof=actor.createActorProof({request,response,result:{response,provider:'ollama',model:'controlled-test'},execution,attempt,objective:'interact',messages:[{role:'system',content:policy.SYSTEM_PROMPTS.interact},{role:'user',content:request}]});
 const input={rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:'interact',mode:'vuln',version:'budget-control-v1',dpiPolicyBinding:binding.VERSION,criteria:[{id:'observed',description:'Controlled only',allowedSources:['assistant_response']}]},evidence:[{id:'request',source:'student_input',content:request},{id:'response',source:'assistant_response',content:response},{id:'owned_actor',source:'server_observation',content:actor.projectLegacyActorEvidence(proof)},{id:'owned_policy',source:'server_observation',content:binding.createPolicyBinding(proof)},{id:'context',source:'server_observation',content:''}],facts:{}};
 let last;for(let n=21000;n<24000;n+=10){input.evidence.at(-1).content='x'.repeat(n);const p=prepareJudgeInput(input);if(p.evidenceError)break;last=p.packet;}assert(last&&Buffer.byteLength(last)>24000);return last;
}
test('expanded authentic compact packet retains original semantic budget and exact digest',()=>{
 const packet=nearCap();assert.doesNotThrow(()=>validateRecoveryPacket(packet,sha(packet)));
 const parsed=JSON.parse(packet),legacy=binding.stripPolicyBinding(parsed);assert.doesNotThrow(()=>boundedJson(legacy,24000));assert(Buffer.byteLength(packet)<=25024);
 assert.throws(()=>validateRecoveryPacket(packet,'0'.repeat(64)),{code:'BAD_REQUEST'});
 assert.throws(()=>validateRecoveryPacket(JSON.stringify(parsed,null,1),sha(JSON.stringify(parsed,null,1))),{code:'BAD_REQUEST'});
 for(const mutate of [p=>p.rubric.dpiPolicyBinding='dpi-policy-binding-v1',p=>p.evidence.find(e=>e.id==='owned_policy').content.extra=true,p=>p.evidence.find(e=>e.id==='owned_policy').content.legacyEvidenceSha256='0'.repeat(64),p=>p.evidence.at(-1).content+='x'.repeat(1024),p=>p.evidence.push(p.evidence.find(e=>e.id==='owned_policy'))]){const value=JSON.parse(packet);mutate(value);const raw=JSON.stringify(value);assert.throws(()=>validateRecoveryPacket(raw,sha(raw)),{code:'BAD_REQUEST'});}
});
test('historical arbitrary small packet/null unchanged; unmarked or malformed oversized packets denied',()=>{
 assert.doesNotThrow(()=>validateRecoveryPacket(null,'unused'));
 const old='x'.repeat(24000);assert.doesNotThrow(()=>validateRecoveryPacket(old,sha(old)));
 for(const raw of ['x'.repeat(24001),JSON.stringify({evidence:'x'.repeat(24000)})])assert.throws(()=>validateRecoveryPacket(raw,sha(raw)),{code:'BAD_REQUEST'});
});
test('forward migration changes only packet constraint and retains runtime-only validation grant',()=>{
 const sql=require('node:fs').readFileSync(require('node:path').join(__dirname,'../db/postgres/identity-migrations/0125_dpi_policy_packet_budget.sql'),'utf8');
 assert.deepEqual([...sql.matchAll(/DROP CONSTRAINT ([a-z_]+)/g)].map(m=>m[1]),['grade_packets_packet_check']);
 assert.match(sql,/packet IS NULL OR octet_length\(packet\)<=24000/);assert.match(sql,/octet_length\(packet\)>25024/);assert.match(sql,/EXCEPTION WHEN invalid_text_representation THEN RETURN false/);
 assert.match(sql,/REVOKE ALL ON FUNCTION workshop_platform.valid_dpi_policy_packet_budget\(text\) FROM PUBLIC/);
 assert.match(sql,/GRANT EXECUTE ON FUNCTION workshop_platform.valid_dpi_policy_packet_budget\(text\) TO dvaia_identity_runtime/);
});
test('native SQL matrix targets expanded branch and keeps malformed inputs below total limit',()=>{
 const probe=require('./fixtures/dpiPolicyPacketMigration');
 for(const objective of ['interact','obfuscation']){const raw=JSON.stringify(probe.packet(objective));assert(Buffer.byteLength(raw)>24000&&Buffer.byteLength(raw)<=25024);}
 const rows=probe.rejectedPackets();assert.equal(rows.length,21);assert.equal(new Set(rows.map(r=>r.id)).size,21);
 for(const row of rows){assert(Buffer.byteLength(row.value)>24000,row.id);if(!['total-overflow','no-binding'].includes(row.id))assert(Buffer.byteLength(row.value)<=25024,row.id);}
 for(const id of ['null-envelope','null-policy','missing-extension','duplicate','extra-envelope','extra-policy','extra-extension','null-extension-digest','malformed'])assert(rows.some(r=>r.id===id));
});
