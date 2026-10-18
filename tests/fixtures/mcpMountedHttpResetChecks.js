'use strict';
const assert=require('node:assert/strict');
function verifyReset({before,after,siblingBefore,siblingAfter}){
 assert.equal(BigInt(after.graphGeneration),BigInt(before.graphGeneration)+1n);
 assert.equal(BigInt(after.progressGeneration),BigInt(before.progressGeneration)+1n);
 assert.deepEqual(after.completions,[]);
 for(const key of ['workshopProgress','toolLog']){
  assert(Array.isArray(before[key])&&Array.isArray(siblingBefore[key])&&Array.isArray(siblingAfter[key]),`Missing mutable ${key} snapshot`);
  assert.deepEqual(after[key],[],`Owner ${key} was not cleared`);
 }
 for(const key of ['operations','records'])assert.deepEqual(after[key],before[key],`Immutable ${key} changed`);
 assert.deepEqual(siblingAfter,siblingBefore,'Sibling state changed');
 assert(before.targets.length>0,'Retirement needs previously owned targets');
 assert.deepEqual(after.targets.map(x=>x.target_id),before.targets.map(x=>x.target_id));
 for(const target of after.targets){
  const old=before.targets.find(x=>x.target_id===target.target_id);
  for(const key of ['user_key','platform_session_id','generation','created_at'])assert.deepEqual(target[key],old[key]);
  assert.equal(target.state,'retired');assert(target.retired_at);
  const child=after.http.filter(x=>x.target_id===target.target_id),cleanup=after.cleanups.filter(x=>x.target_id===target.target_id);
  assert.equal(child.length,1);assert.equal(cleanup.length,1);assert.equal(child[0].state,'retired');assert.equal(cleanup[0].status,'completed');
  for(const row of [child[0],cleanup[0]])for(const key of ['user_key','platform_session_id','generation'])assert.equal(String(row[key]),String(target[key]));
  const scope={targetId:target.target_id,platformOwnerId:Number(target.user_key),platformSessionId:Number(target.platform_session_id),generation:Number(target.generation)};
  require('../../server/database/postgres/mcpHttpLeaseRepository').verifyHttpCleanupReceipt(child[0].cleanup_receipt,{...scope,operationId:child[0].cleanup_operation_id});
  require('../../server/database/postgres/mcpResourceRepository')._internals.completedRunnerReceipt(cleanup[0].receipt_json,{...scope,operationId:cleanup[0].operation_id});
  assert.equal(cleanup[0].receipt_sha256,cleanup[0].receipt_json.receiptSha256);
 }
 assert.equal(after.http.length,after.targets.length);assert.equal(after.cleanups.length,after.targets.length);
 return true;
}
module.exports={verifyReset};
