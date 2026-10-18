'use strict';
const assert=require('node:assert/strict');
const {document}=require('../../server/database/postgres/catalogDefaultProvenance');
const fields=new Set(['ss_mail_reply_redirect:hint_content','ss_mail_reply_redirect:solution_content','ss_mail_header_construction:hint_content']);
function assertCustomObservationRefresh(before,after){
 assert.deepEqual(after.objectives,before.objectives,'All instructor content, gates and sibling objective rows preserved');
 assert.deepEqual(after.exercises,before.exercises);assert.deepEqual(after.revision,before.revision);
 assert.equal(after.defaults.length,before.defaults.length);let refreshed=0;
 for(let i=0;i<before.defaults.length;i++){
  const old=before.defaults[i],next=after.defaults[i];
  if(old.entity_kind==='objective'&&old.workshop_key==='secureshop_agent_security'&&fields.has(old.objective_id+':'+old.field_name)){
   assert.equal(old.provenance_state,'custom');assert.equal(next.provenance_state,'custom');
   const row=before.objectives.find(x=>x.workshop_key===old.workshop_key&&x.objective_id===old.objective_id);assert(row);
   assert.deepEqual(next.observed_document,document(row[old.field_name]));
   assert.notDeepEqual(old.observed_document,next.observed_document,'Expected first observation refresh');
   assert(new Date(next.updated_at).getTime()>=new Date(old.updated_at).getTime());
   assert.deepEqual({...next,observed_document:old.observed_document,updated_at:old.updated_at},old,'Only observed document and timestamp may change');refreshed++;
  }else assert.deepEqual(next,old,'Every unrelated provenance row preserved');
 }
 assert.equal(refreshed,3);
}
module.exports={assertCustomObservationRefresh};
