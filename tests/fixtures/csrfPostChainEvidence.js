'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
function createPostChainEvidence({identity,progress,student,root,model,state,judgments}){
 let protectedVictim,immutable,count=0;const hash=s=>createHash('sha256').update(s).digest('hex');
 return async(stage,d)=>{
  if(stage==='post-defense-enabled'){const s=(await state(student)).post;assert.equal(s.defenses.csrfToken,true);protectedVictim=structuredClone(s.victim);return;}
  if(stage==='reset'){assert.equal((await progress.getWorkshopProgress(student.id,'csrf_workshop')).completedObjectiveCount,0);assert.deepEqual(await judgments(),immutable);assert.notEqual((await state(student)).post.victim.profile.email,'post-fetch@fixture.invalid');return;}
  if(stage!=='post-effect')return;
  const owned=JSON.parse(fs.readFileSync(path.join(root,'csrf-post-owned-receipt-'+(++count)+'.json'))),receipt=owned.receipt,action=owned.activity;
  assert.equal(receipt.ownerKey,JSON.stringify(['CSRF',String(student.id)]));assert.equal(receipt.objectiveId,d.id);assert.equal(receipt.payloadDigest,hash(d.html));assert.equal(receipt.method,'POST');assert.equal(receipt.resourceType,d.resource);assert.equal(receipt.responseStatus,d.status);assert.equal(receipt.responseObserved,true);assert.equal(receipt.cookiePresent,true);assert.equal(action.result.vector,d.kind==='form'?'direct_post':'fetch');assert.equal(receipt.runId,owned.binding.runId);
  const all=await judgments();assert.equal(all.length,d.total);
  if(!d.replay){const j=all.find(x=>x.objective_id===d.id);assert.equal(j.verdict,'pass');assert.equal(j.disposition,'awarded');assert.equal(j.run_id,receipt.runId);assert.equal(j.result_json.provider,'ollama');assert.equal(j.result_json.model,model);const raw=(await identity.query('SELECT packet FROM workshop_platform.grade_packets WHERE user_id=$1 AND evaluation_id=$2',[student.id,j.evaluation_id])).rows[0].packet;assert.equal(hash(raw),j.evidence_digest);const packet=JSON.parse(raw);assert.equal(packet.facts.required_observation,true);assert.deepEqual(packet.evidence.find(e=>e.id==='receipt').content,receipt);if(d.id==='csrf_p3'){assert.equal(packet.rubric.version,'csrf-defense-mode-v10');assert.equal(packet.rubric.mode,'vuln');}fs.writeFileSync(path.join(root,'csrf-post-packet-'+d.id+'.json'),raw,{mode:0o600});}
  if(d.status===200){assert.equal(action.result.stateChanged,true);assert.equal((await state(student)).post.victim.profile.email,d.kind==='form'?'post-form@fixture.invalid':'post-fetch@fixture.invalid');const events=(await identity.query('SELECT node,event_type,metadata FROM graph_runtime.events WHERE run_id=$1 ORDER BY sequence',[receipt.runId])).rows;assert(events.some(e=>e.node==='classify'&&e.metadata?.decisionSource==='model'&&e.metadata?.tool==='change_email'&&e.metadata?.provider==='ollama'&&e.metadata?.model===model));fs.writeFileSync(path.join(root,'csrf-post-traces-'+d.id+'.json'),JSON.stringify(events,null,2),{mode:0o600});}
  else{assert.equal(action.result.blocked,true);assert.equal(action.result.defenses.csrfToken,true);assert.equal(action.result.stateChanged===true,false);assert.deepEqual((await state(student)).post.victim,protectedVictim);if(d.replay)assert.deepEqual(all,immutable);else immutable=all;}
  assert.equal((await progress.getWorkshopProgress(student.id,'csrf_workshop')).completedObjectiveCount,d.total);
 };
}
module.exports={createPostChainEvidence};
