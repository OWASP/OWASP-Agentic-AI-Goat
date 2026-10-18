'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {createSensitiveInfoCleanupRepository}=require('../server/database/postgres/sensitiveInfoCleanupRepository');
const input={operationId:'11111111-1111-4111-8111-111111111111',stepKey:'legacy_store',ownerId:41,fromGeneration:3,toGeneration:4};
test('destination cleanup and private reread preserve every immutable scope field',async()=>{
 const calls=[];const pool={query:async(sql,params)=>{calls.push({sql,params});return{rows:[{operation_id:input.operationId,step_key:input.stepKey,owner_id:41,from_generation:3,to_generation:4}]};}};
 const repository=createSensitiveInfoCleanupRepository(pool);
 assert.deepEqual(await repository.apply(input),input);assert.deepEqual(await repository.readReceipt(input),input);
 assert.match(calls[0].sql,/apply_sensitive_info_cleanup/);assert.deepEqual(calls[0].params,[input.operationId,41,3,4,'legacy_store']);
 assert.match(calls[1].sql,/read_sensitive_info_cleanup_receipt/);
});
test('destination cleanup rejects owner, operation, step and generation spoofing before SQL',async()=>{
 const repository=createSensitiveInfoCleanupRepository({query:async()=>{throw Error('must not query')}});
 for(const patch of [{ownerId:42.5},{operationId:'bad'},{stepKey:'other'},{toGeneration:8}])
  await assert.rejects(repository.apply({...input,...patch}),TypeError);
});
test('FinFlow draft uses an owner-serialized immutable receipt before destructive cleanup',()=>{
 const sql=fs.readFileSync(path.resolve(__dirname,'../docs/modernization/drafts/sensitive-info-aggregate-reset-finflow.sql'),'utf8');
 assert.match(sql,/pg_advisory_xact_lock/);assert.match(sql,/Stale Sensitive Information cleanup generation/);
 assert.ok(sql.indexOf('IF EXISTS(SELECT 1 FROM finflow.sensitive_info_cleanup_receipts')<sql.indexOf('DELETE FROM legacy_sensitive.access_logs'));
 assert.ok(sql.indexOf('DELETE FROM legacy_sensitive.access_logs')<sql.indexOf('INSERT INTO finflow.sensitive_info_cleanup_receipts'));
 assert.match(sql,/SET generation=legacy_sensitive\.owner_state\.generation\+1/);
 assert.doesNotMatch(sql,/legacy_generation>p_from_generation/);
  assert.match(sql,/REVOKE ALL ON FUNCTION finflow\.apply_sensitive_info_cleanup/);
  assert.match(sql,/sensitive_info_cleanup_operation_binding_guard/);
  assert.match(sql,/sensitive_info_cleanup_receipt_binding_guard/);
 assert.doesNotMatch(sql,/GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)\s+ON finflow\.sensitive_info_cleanup_/i);
});
test('cleanup readiness uses valid lateral ACL syntax and rejects public execution',async()=>{
 let inspected;const repository=createSensitiveInfoCleanupRepository({query:async sql=>{inspected=sql;return{rows:[{
  operations:true,receipts:true,apply:true,read:true,operation_guard:true,receipt_guard:true,
  runtime_apply:true,runtime_read:true,no_public_execute:true}]};}});
 assert.equal(await repository.assertReady(),true);
 assert.match(inspected,/FROM pg_proc p CROSS JOIN LATERAL aclexplode/);
 assert.doesNotMatch(inspected,/p,CROSS JOIN/);
});
