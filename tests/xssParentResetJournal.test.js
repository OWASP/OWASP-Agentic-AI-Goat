'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createXssParentResetJournalRepository}=require('../server/database/postgres/xssParentResetJournalRepository');
const OP='11111111-1111-4111-8111-111111111111';
const LEASE='22222222-2222-4222-8222-222222222222';
function row(overrides={}){return {operationId:OP,ownerId:42,ownerKey:'["XSS","42"]',workshopGenerationFrom:'3',workshopGenerationTo:null,
 childOperationId:'33333333-3333-4333-8333-333333333333',childOutcomeDigest:null,clearReceiptDigest:null,graphGeneration:null,status:'pending',leaseToken:null,
 leaseExpiresAt:null,failureCode:null,createdAt:new Date(),updatedAt:new Date(),completedAt:null,...overrides};}
function harness(answer=row()){
 const calls=[];const pool={query:async(sql,args)=>{calls.push({sql,args});return {rowCount:1,rows:[answer]};}};
 return {calls,repo:createXssParentResetJournalRepository(pool)};
}
test('claim accepts the closed object API and binds the authenticated owner',async()=>{
 const h=harness(row({status:'running',leaseToken:LEASE,leaseExpiresAt:new Date()}));
 const result=await h.repo.claim({operationId:OP,ownerId:42});
 assert.equal(result.ownerId,42);assert.equal(result.lease.token,LEASE);
 assert.equal(h.calls[0].args[0],OP);assert.equal(h.calls[0].args[1],42);assert.equal(h.calls[0].args[3],30000);
 assert.throws(()=>h.repo.claim({operationId:OP,ownerId:42,foreign:true}),TypeError);
});
test('clear acknowledgement forwards exact bounded receipt including transport replay marker',async()=>{
 const h=harness({receiptSha256:'a'.repeat(64),replayed:false});
 const receipt={operationId:OP,ownerId:42,profileRevisions:{name:'1',bio:'2',website:'3'},progressRemoved:4,originsRemoved:2,
  appliedAt:'2026-09-19T12:00:00.000Z',replayed:false};
 await h.repo.acknowledgeClear({operationId:OP,leaseToken:LEASE,receipt});
 assert.deepEqual(JSON.parse(h.calls[0].args[2]),receipt);
 await assert.rejects(()=>h.repo.acknowledgeClear({operationId:OP,leaseToken:LEASE,receipt:{...receipt,secret:'x'}}),TypeError);
});
test('child acknowledgement preserves the full retirement tuple for SQL authority',async()=>{
 const h=harness({receiptSha256:'b'.repeat(64),replayed:false});
 const outcome={kind:'retired_no_effect',operationId:'33333333-3333-4333-8333-333333333333',ownerId:42,
  graphParentGeneration:'2',workshopGeneration:'3',children:{stored_user:{from:'1',to:'2'},stored_llm:{from:'5',to:'6'}}};
 await h.repo.acknowledgeChild({operationId:OP,leaseToken:LEASE,outcome});
 assert.deepEqual(JSON.parse(h.calls[0].args[2]),outcome);
});
test('completed DTO retains exact terminal graph and workshop coordinates',async()=>{
 const h=harness(row({status:'completed',workshopGenerationTo:'4',graphGeneration:'7',completedAt:new Date()}));
 const result=await h.repo.read(OP);assert.equal(result.status,'completed');assert.equal(result.graphGeneration,'7');
 assert.equal(result.workshopGenerationFrom,'3');assert.equal(result.workshopGenerationTo,'4');
});
test('mutation admission uses only the bounded owner capability',async()=>{
 const h=harness({admitted:true});assert.equal(await h.repo.assertMutationAdmitted(42),true);
 assert.match(h.calls[0].sql,/assert_xss_mutation_admitted/);assert.deepEqual(h.calls[0].args,[42]);
 await assert.rejects(()=>h.repo.assertMutationAdmitted(true),TypeError);
});
test('0077 owns atomic canonical finalization and closed runtime authority',()=>{
 const sql=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0077_xss_parent_reset_journal.sql'),'utf8');
 assert.match(sql,/DELETE FROM workshop_platform\.completions/);
 assert.match(sql,/DELETE FROM workshop_platform\.activity_counters/);
 assert.match(sql,/DELETE FROM workshop_platform\.time_tracking/);
 assert.match(sql,/reconcile_xss_profile_reset_after_parent/);
 assert.match(sql,/requested_receipt-'replayed'/);
 assert.match(sql,/REVOKE ALL ON identity\.xss_parent_reset_operations,identity\.xss_parent_reset_steps FROM PUBLIC,dvaia_identity_runtime/);
 assert.match(sql,/xss_parent_reset_run_guard/);assert.match(sql,/xss_parent_reset_judgment_guard/);
});
test('0078 serializes both admission orders on the owner before parent authority',()=>{
 const sql=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0078_xss_parent_reset_admission_fence.sql'),'utf8');
 assert.match(sql,/identity\.users[\s\S]*FOR UPDATE OF u[\s\S]*xss_parent_reset_operations[\s\S]*FOR UPDATE OF p/);
 assert.match(sql,/CREATE FUNCTION identity\.assert_xss_mutation_admitted[\s\S]*FOR SHARE OF u[\s\S]*p\.status<>'completed'/);
  assert.ok((sql.match(/assert_xss_mutation_admitted\(/g)||[]).length>=6);
 assert.match(sql,/OLD\.workshop_key='xss_workshop'[\s\S]*NEW\.workshop_key='xss_workshop'[\s\S]*ORDER BY v\.owner_id/);
 assert.match(sql,/CREATE TRIGGER xss_parent_reset_scope_binding_guard[\s\S]*BEFORE INSERT ON identity\.xss_run_bindings/);
 assert.match(sql,/p\.status<>'completed'/);
 assert.match(sql,/REVOKE ALL ON FUNCTION[\s\S]*guard_xss_parent_reset_scope_binding\(\) FROM PUBLIC/);
});
test('0079 filters deleted recovery and permits only finalizer-bound exact redaction',()=>{
 const sql=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0079_xss_deletion_redaction_recovery_filter.sql'),'utf8');
 assert.equal((sql.match(/JOIN identity\.users u ON u\.id=[rp]\.owner_id AND u\.is_active=1/g)||[]).length,2);
 assert.equal((sql.match(/NOT EXISTS\(SELECT 1 FROM identity\.student_deletion_jobs/g)||[]).length,2);
 assert.match(sql,/backend_pid=pg_backend_pid\(\)[\s\S]*transaction_id=txid_current\(\)[\s\S]*subject_user_id=OLD\.user_id/);
 assert.match(sql,/to_jsonb\(NEW\)-ARRAY\['result_json','result_digest'\][\s\S]*to_jsonb\(OLD\)-ARRAY\['result_json','result_digest'\]/);
 assert.match(sql,/NEW\.result_digest IS NULL[\s\S]*jsonb_build_object\('deleted',true\)/);
 assert.match(sql,/IS NOT DISTINCT FROM\s*\(CASE WHEN OLD\.verdict IS NULL[\s\S]*END\) THEN/);
 assert.match(sql,/d\.state='running'[\s\S]*d\.lease_token=a\.lease_token[\s\S]*d\.lease_expires_at>clock_timestamp\(\)/);
 assert.match(sql,/REVOKE ALL ON identity\.xss_deletion_redaction_authority FROM PUBLIC,dvaia_identity_runtime/);
 assert.doesNotMatch(sql,/status\s*=\s*'deleted'|status IN \([^)]*'deleted'/);
});
