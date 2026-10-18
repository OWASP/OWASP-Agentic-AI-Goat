'use strict';
const assert=require('node:assert/strict');
const OBJECTIVE='ss_inventory_cross_merchant_stock';
function inventoryGradeVerifier({identity,user,review}){
 let parent,terminal;
 return async(stage,requestId)=>{
  const rows=(await identity.query('SELECT j.evaluation_id,j.verdict,j.evidence_digest,j.result_digest,p.packet,p.child_evaluation_id FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.objective_id=$2 ORDER BY j.created_at',[user.id,OBJECTIVE])).rows;
  const count=(await identity.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND objective_id=$2',[user.id,OBJECTIVE])).rows[0].n;
  if(stage==='unavailable'){assert.equal(count,0);assert.equal(rows.length,1);assert.equal(rows[0].verdict,'unavailable');parent={...rows[0]};const packet=JSON.parse(parent.packet),raw=packet.evidence.find(e=>e.id==='inventory_stock').content.raw;assert.equal(raw.context.requestId,requestId);assert.equal(raw.entry.receipt.binding.execution.requestId,requestId);assert.notEqual(raw.entry.receipt.result.retailerId,raw.entry.receipt.binding.persona.id);assert.equal(raw.entry.receipt.result.after,4);assert.notEqual(raw.entry.receipt.result.before,4);}
  else{assert.equal(rows.length,2);const original=rows.find(r=>r.evaluation_id===parent.evaluation_id),child=rows.find(r=>r.evaluation_id!==parent.evaluation_id);assert.equal(original.verdict,'unavailable');assert.equal(child.verdict,'pass');assert.equal(child.evidence_digest,parent.evidence_digest);assert.equal(original.child_evaluation_id,child.evaluation_id);assert.equal(count,stage==='reset'?0:1);if(stage!=='reset'){assert.equal(original.packet,parent.packet);terminal=rows.map(({evaluation_id,verdict,result_digest})=>({evaluation_id,verdict,result_digest}));}else assert.deepEqual(rows.map(({evaluation_id,verdict,result_digest})=>({evaluation_id,verdict,result_digest})),terminal);}
  if(stage!=='reset'){const stock=(await review.query("SELECT result_json FROM secureshop_review.owned_inventory_operations WHERE state='completed' AND action='set_stock'")).rows;assert.equal(stock.length,1);assert.equal(JSON.parse(stock[0].result_json).result.after,4);}
  return{count,judgments:rows.length};
 };
}
module.exports={inventoryGradeVerifier};
