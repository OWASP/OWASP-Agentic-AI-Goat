'use strict';
// Used only inside the existing disposable identity migration qualification.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const NAME='0125_dpi_policy_packet_budget.sql';
function packet(objective='interact'){
 const policy=require('../../server/agent-runtime/dpiPolicyContract').selectPolicy({objectiveId:objective,mode:'vuln'});
 return {rubric:{family:'DPI',scenario:'aws_assistant',objectiveId:objective,mode:'vuln',dpiPolicyBinding:'dpi-policy-binding-v2'},evidence:[{id:'owned_policy',source:'server_observation',content:{version:'dpi-policy-binding-v2',objective,mode:'vuln',policy,extension:{[objective==='obfuscation'?'decisionMessagesSha256':'messagesSha256']:'a'.repeat(64)},legacyEvidenceSha256:'b'.repeat(64)}},{id:'padding',source:'server_observation',content:'x'.repeat(23300)}],facts:{}};
}
function rejectedPackets(){
 const changes=[['marker',p=>p.rubric.dpiPolicyBinding='dpi-policy-binding-v1'],['family',p=>p.rubric.family='OTHER'],['scenario',p=>p.rubric.scenario='other'],['identity',p=>p.rubric.objectiveId='jailbreak'],['mode',p=>p.rubric.mode='fixed'],['duplicate',p=>p.evidence.push(p.evidence[0])],['source',p=>p.evidence[0].source='student_input'],['null-envelope',p=>p.evidence[0].content=null],['extra-envelope',p=>p.evidence[0].content.proof={}],['missing-extension',p=>delete p.evidence[0].content.extension],['null-policy',p=>p.evidence[0].content.policy=null],['extra-policy',p=>p.evidence[0].content.policy.extra='x'],['wrong-lesson',p=>p.evidence[0].content.policy.lessonKind='other'],['null-digest',p=>p.evidence[0].content.legacyEvidenceSha256=null],['bad-digest',p=>p.evidence[0].content.legacyEvidenceSha256='bad'],['wrong-extension',p=>p.evidence[0].content.extension={decisionMessagesSha256:'a'.repeat(64)}],['extra-extension',p=>p.evidence[0].content.extension.extra='x'],['null-extension-digest',p=>p.evidence[0].content.extension.messagesSha256=null]];
 return [...changes.map(([id,change])=>{const p=structuredClone(packet());p.evidence[1].content='x'.repeat(22000);change(p);return {id,value:JSON.stringify(p).padEnd(24500,' ')};}),{id:'malformed',value:'x'.repeat(24001)},{id:'total-overflow',value:JSON.stringify(packet()).padEnd(25025,' ')},{id:'no-binding',value:JSON.stringify({rubric:{},evidence:['x'.repeat(24000)],facts:{}})}];
}
async function beforeUpgrade({runtime,migration}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const suffix=crypto.randomBytes(8).toString('hex'),key='packet_probe_'+suffix;
 const user=(await runtime.query('INSERT INTO identity.users(username,email,password,is_active) VALUES($1,$2,$3,0) RETURNING id',[key,key+'@fixture.invalid','$2b$12$'+'a'.repeat(53)])).rows[0].id;
 await migration.query('INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,is_visible,catalog_active,ordinal) VALUES($1,$1,$1,false,false,9999)',[key]);
 await migration.query('INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,ordinal,is_enabled,catalog_active) VALUES($1,$2,$2,0,false,false)',[key,'probe']);
 const evaluation=crypto.randomUUID();
 await runtime.query('INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,mode) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,$9)',[user,evaluation,key,'probe','DPI','aws_assistant','controlled-migration','a'.repeat(64),'vuln']);
 await runtime.query('INSERT INTO workshop_platform.grade_packets(user_id,evaluation_id,packet,judge_version,mode_stamp) VALUES($1,$2,$3,$4,$5)',[user,evaluation,'legacy sentinel','controlled-migration','fixture']);
 const read=async()=>(await runtime.query('SELECT to_jsonb(p) row FROM workshop_platform.grade_packets p WHERE user_id=$1 AND evaluation_id=$2',[user,evaluation])).rows;
 const sentinel=await read();
 // Predecessor must actually deny the same expanded packet accepted afterward.
 await assert.rejects(runtime.query('UPDATE workshop_platform.grade_packets SET packet=$3 WHERE user_id=$1 AND evaluation_id=$2',[user,evaluation,JSON.stringify(packet())]),{code:'23514',constraint:'grade_packets_packet_check'});
 return {user,evaluation,read,sentinel};
}
async function afterUpgrade({runtime,state}){
 assert.deepEqual(await state.read(),state.sentinel);
 const sql='UPDATE workshop_platform.grade_packets SET packet=$3 WHERE user_id=$1 AND evaluation_id=$2';
 let accepted=0,rejected=0;
 for(const value of [null,'x'.repeat(24000),JSON.stringify(packet()),JSON.stringify(packet('obfuscation'))]){
  await runtime.query(sql,[state.user,state.evaluation,value]);accepted++;
 }
 for(const row of rejectedPackets()){
  assert(Buffer.byteLength(row.value)>24000,row.id+' must exercise expanded branch');
  assert.equal((await runtime.query('SELECT workshop_platform.valid_dpi_policy_packet_budget($1) valid',[row.value])).rows[0].valid,false,row.id);
  await assert.rejects(runtime.query(sql,[state.user,state.evaluation,row.value]),{code:'23514',constraint:'grade_packets_packet_budget_check'});rejected++;
 }
 const grants=(await runtime.query("SELECT has_function_privilege(current_user,'workshop_platform.valid_dpi_policy_packet_budget(text)','EXECUTE') runtime_allowed,NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='workshop_platform.valid_dpi_policy_packet_budget(text)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') public_denied")).rows[0];assert.deepEqual(grants,{runtime_allowed:true,public_denied:true});
 await runtime.query(sql,[state.user,state.evaluation,'legacy sentinel']);assert.deepEqual(await state.read(),state.sentinel);
 return {migration:NAME,populatedUpgrade:true,priorPacketPreserved:true,predecessorExpandedDenied:true,legacy24000Preserved:true,compactActorAccepted:true,compactDecoderAccepted:true,sqlNullAccepted:true,runtimeGrants:true,publicExecuteDenied:true,accepted,rejected,freshInitialization:false};
}
module.exports={NAME,packet,rejectedPackets,beforeUpgrade,afterUpgrade};
