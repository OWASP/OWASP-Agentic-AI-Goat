'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{createHash}=require('node:crypto');
const sql=fs.readFileSync('db/postgres/maintenance-migrations/0004_executable_recovery_admission.sql','utf8');
const control=require('../server/database/postgres/applicationMaintenanceControl');
const uuid=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const ledger=[['0001_maintenance_fence.sql',control.MAINTENANCE_BOOTSTRAP_SHA256],['0002_local_recovery.sql',control.MAINTENANCE_RECOVERY_SHA256],['0003_canonical_inprocess_recovery.sql',control.MAINTENANCE_REPLAY_SHA256],['0004_executable_recovery_admission.sql',control.MAINTENANCE_EXECUTION_SHA256]].map(([name,checksum])=>({name,checksum}));
function fixture(rows=ledger,{dirty=false,extended=false}={}){
 let state=dirty?'dirty':'clean',operation=uuid(1);const calls=[];
 const query=async(s,args)=>{calls.push(s);if(s.includes('FROM pg_locks'))return{rows:[{held:true}]};if(s.includes('to_regnamespace'))return{rows:[{present:true}]};if(s.startsWith('SELECT name,checksum'))return{rows};if(s.startsWith('SELECT *,database_oid'))return{rows:[{version:1,target_matches:true,installation_id:uuid(2),operation_id:operation,epoch:'5',state}]};if(s.startsWith('UPDATE dvaia_maintenance.control SET epoch')){state='dirty';operation=args[0];return{};}if(s.startsWith('SELECT epoch FROM dvaia_maintenance.epoch_replay_profiles'))return{rows:extended?[{epoch:'5'}]:[]};if(s.startsWith("UPDATE dvaia_maintenance.control SET state='clean'")){state='clean';return{rows:[{finished_at:'2026-09-27 12:00:00.123456+00'}]};}if(s.startsWith('UPDATE dvaia_maintenance.epochs')){assert.equal(args[2],'2026-09-27 12:00:00.123456+00');return{rowCount:1};}return{};};
 return{calls,state:()=>state,c:control.createApplicationMaintenanceControl({query,assertHeld(){},mode:'maintenance'})};
}
test('exact prefixes1–4 preserve ordinary clean/read/begin/finish with unavailable binding and no schema auto-upgrade',async()=>{
 for(let n=1;n<=4;n++){const f=fixture(ledger.slice(0,n));await f.c.assertClean();const token=await f.c.begin();assert.equal(f.state(),'dirty');await f.c.finish(token);assert.equal(f.state(),'clean');assert.equal(f.calls.some(s=>s.includes("'UNMANAGED_BEGIN'")),n>=2);assert(!f.calls.some(s=>s.includes('CREATE TABLE')||s.includes('INSERT INTO dvaia_maintenance.epoch_execution_admissions')));}
});
test('missing/reordered/extra/checksum-corrupt fourth ledger entries deny without mutation',async()=>{
 for(const rows of [[],[...ledger.slice(0,2),ledger[3]],[...ledger].reverse(),[...ledger,ledger[3]],ledger.map((r,i)=>i===3?{...r,checksum:'0'.repeat(64)}:r)]){const f=fixture(rows);await assert.rejects(f.c.assertClean(),{code:'APPLICATION_MAINTENANCE_VERSION_MISMATCH'});assert(f.calls.every(s=>s.startsWith('SELECT')));}
});
test('0004 generic finish denies extended epoch; dirty begin never installs or repairs schema',async()=>{
 const f=fixture(ledger,{extended:true}),t=await f.c.begin();await assert.rejects(f.c.finish(t),{code:'APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE'});assert.equal(f.state(),'dirty');
 const d=fixture(ledger,{dirty:true});await assert.rejects(d.c.begin(),{code:'APPLICATION_MAINTENANCE_DIRTY'});assert(!d.calls.some(s=>s.includes('CREATE TABLE')||s.startsWith('UPDATE')));
});
test('new SQL checksum bound and schema-only structures are private immutable prospective extensions',()=>{
 assert.equal(createHash('sha256').update(sql).digest('hex'),control.MAINTENANCE_EXECUTION_SHA256);
 for(const table of ['epoch_execution_admissions','recovery_abandonment_observations','recovery_finish_claims','recovery_finish_claim_results']){assert(sql.includes('CREATE TABLE dvaia_maintenance.'+table));assert(sql.includes('BEFORE UPDATE OR DELETE ON dvaia_maintenance.'+table));}
 assert(sql.includes('FROM PUBLIC,dvaia_identity_runtime'));assert(!/GRANT |SECURITY DEFINER|CREATE EXTENSION|DELETE FROM/.test(sql));
 assert(sql.includes("state='clean'"));assert(sql.includes("mode='ExclusiveLock'"));assert(sql.includes('mod(pg_current_xact_id()::text::numeric,4294967296)'));
});
test('source contract binds abandonment in both directions, claimed insertion and original prior-state transition',()=>{
 for(const clause of ["NEW.state<>'claimed'","prior_state=OLD.state","o.attempt_id IS NULL","ELSIF o.attempt_id IS NOT NULL","o.finished_at<>a.finished_at","a.recovery_owner_record::text","complete_execution_admission","complete_execution_attempt","complete_execution_abandonment"])assert(sql.includes(clause),clause);
 assert(sql.includes("state IN ('claimed','reconciled','published'))>1"));
});
test('finish-only SQL source binds exact latest claim, publication/manifest, phase and microsecond timestamp',()=>{
 for(const clause of ["a.state<>'published'","NEW.ordinal IS NOT NULL OR NEW.previous_claim_id IS NOT NULL","ORDER BY ordinal DESC LIMIT 1","NEW.ordinal:=COALESCE(prior.ordinal,0)+1","claim.previous_claim_id IS DISTINCT FROM previous","claim.publication_sha256<>b.publication_sha256","claim.artifact_manifest_sha256<>p.artifact_manifest_sha256","result.claim_id<>previous","receipt.recovery_attempt_id<>a.attempt_id","created_at=result.finished_at","Premature finish claim result"])assert(sql.includes(clause),clause);
});

test('repeatable-read serialization uses an unconditional immediate common-row write, never a recursive deferred write',()=>{
 const barrier=sql.split('CREATE FUNCTION dvaia_maintenance.serialize_execution_write()')[1].split('END $$;')[0];
 assert.match(barrier,/UPDATE dvaia_maintenance\.control SET epoch=epoch WHERE singleton;/);
 assert(!barrier.includes('epoch_execution_admissions'));
 assert.equal((sql.match(/UPDATE dvaia_maintenance\./g)||[]).length,1);
 for(const [name,event] of [['attempt','INSERT OR UPDATE'],['abandonment','INSERT'],['claim','INSERT'],['result','INSERT']]){
  assert(sql.includes(`CREATE TRIGGER aaa_execution_${name}_barrier BEFORE ${event} ON`));
 }
 const checker=sql.split('CREATE FUNCTION dvaia_maintenance.check_execution_epoch()')[1].split('END $$;')[0];
 assert(!/UPDATE dvaia_maintenance/.test(checker));
 assert(sql.includes('serialize_execution_write(),dvaia_maintenance.guard_execution_admission()'));
 // Original live publisher remains permitted without a takeover finish claim.
 assert(sql.includes("IF previous IS NOT NULL AND a.state='finished' THEN"));
});
