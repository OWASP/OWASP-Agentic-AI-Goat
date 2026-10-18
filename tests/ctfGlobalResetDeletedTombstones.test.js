'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const base=fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0114_ctf_blocked_predefense_command.sql'),'utf8');
const next=fs.readFileSync(require.resolve('../db/postgres/identity-migrations/0121_ctf_global_reset_deleted_tombstones.sql'),'utf8');
const original=base.slice(base.indexOf('CREATE OR REPLACE FUNCTION'),base.indexOf('\n',base.indexOf('GRANT EXECUTE ON FUNCTION identity.enqueue_ctf_user_command'))+1);
const start=next.indexOf('EXISTS(SELECT 1 FROM identity.ctf_authority tomb'),end=next.indexOf(' OR EXISTS(SELECT 1 FROM identity.ctf_registration_reservations',start);
test('forward enqueue changes only settled deletion scope predicate, retaining all other body and grants',()=>{
 assert(start>0&&end>start);const restored=next.slice(next.indexOf('CREATE OR REPLACE FUNCTION')).replace(next.slice(start,end),"EXISTS(SELECT 1 FROM identity.ctf_authority WHERE lifecycle_state IN ('pending','blocked'))");assert.equal(restored,original);
});
test('settled exception binds retained deletion evidence and denies nullable or mismatched proof',()=>{
 const predicate=next.slice(start,end);for(const value of ['student_deletion_jobs','student_deletion_run_blocks','ctf_deletion_command_matches','ctf_deletion_receipt_matches','generationAfter','participantId','policyVersion','result_hash','command_hash','octet_length(deleted.canonical_result)<=16384','IS TRUE','IS JSON OBJECT WITH UNIQUE KEYS','retained.generation=tomb.owner_generation'])assert(predicate.includes(value),value);
 assert(!predicate.includes('FOR UPDATE'));assert(!predicate.includes("job.state='completed'"));
});
