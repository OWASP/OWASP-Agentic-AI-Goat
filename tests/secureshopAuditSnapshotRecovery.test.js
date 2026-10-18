'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const snapshots=require('../server/services/secureshopOwnedAuditSearchSnapshot');
const {createAuditTargetAdmissionRepository}=require('../server/database/postgres/secureshopAuditTargetAdmissionRepository');
const binding={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:1,platformSessionId:2};
async function snapshot(){return snapshots.createOwnedAuditSearchSnapshotBuilder({assertCurrent:async()=>{},reader:{recent:async()=>({hasMore:false,events:[{id:'agents:33333333-3333-4333-8333-333333333333',store:'agents',ts:'2026-09-20T00:00:00.000000Z',actor:'admin',action:'synthetic',target:null,params_json:'{}',outcome:'completed',source_kind:'profile',source_id:'1'}]})}}).capture(binding);}
test('durable JSONB key ordering restores exact canonical bytes; corruption and extra fields reject',async()=>{
 const value=await snapshot(),receipt=snapshots.receiptFor(value),stored=snapshots.durableSnapshotFor(value);
 stored.sources=stored.sources.map(row=>Object.fromEntries(Object.entries(row).reverse()));
 const restore=()=>snapshots.restoreAdmittedSnapshot({binding,snapshot:stored,sourceSha256:receipt.sourcesSha256,payloadSha256:receipt.payloadSha256});
 assert.deepEqual(snapshots.privateRequestFor(restore()),snapshots.privateRequestFor(value));
 stored.sources[0].action='changed';assert.throws(restore,/digest mismatch/);stored.sources[0].action='synthetic';stored.sources[0].extra='not admitted';assert.throws(restore,/source fields/);
});
test('concurrent same-digest hash-only winner cannot bypass unavailable recovery; transaction rolls back',async()=>{
 const value=await snapshot(),receipt=snapshots.receiptFor(value),queries=[];
 const future=new Date(Date.now()+60000);const row={scenario_id:binding.scenarioId,platform_session_id:2,original_platform_owner_id:1,source_sha256:receipt.sourcesSha256,payload_sha256:receipt.payloadSha256,snapshot_json:null};
 const client={release(){queries.push('RELEASE');},async query(sql){queries.push(sql);let rows=[];
 if(sql.startsWith('SELECT is_active'))rows=[{is_active:true}];else if(sql.startsWith('SELECT user_id'))rows=[{user_id:1,is_active:true,expires_at:future}];else if(sql.includes('SELECT * FROM identity.secureshop_launches'))rows=[{...row,status:'active',expires_at:future,generation:1}];else if(sql.startsWith('SELECT clock'))rows=[{now:new Date()}];else if(sql.startsWith('SELECT * FROM identity.secureshop_audit_target_admissions'))rows=[row];return{rows};}};
 const repo=createAuditTargetAdmissionRepository({pool:{connect:async()=>client}});
 await assert.rejects(repo.admit({binding,snapshot:value,sourceSha256:receipt.sourcesSha256,payloadSha256:receipt.payloadSha256}),{code:'AUDIT_TARGET_SNAPSHOT_UNAVAILABLE'});
 assert.equal(queries.at(-2),'ROLLBACK');assert.equal(queries.at(-1),'RELEASE');assert.ok(!queries.includes('COMMIT'));
});
for(const flag of ['triggers_ready','functions_private'])test(`readiness rejects missing ${flag}`,async()=>{
 const repo=createAuditTargetAdmissionRepository({pool:{query:async sql=>({rows:[sql.includes('snapshot_ready')?{snapshot_ready:true,permitted:true,mutable:false,columns:false}:{triggers_ready:true,functions_private:true,[flag]:false}]})}});
 await assert.rejects(repo.checkReadiness(),/lifecycle unavailable/);
});

for(const change of ['missing','unvalidated','unenforced','weaker'])test(`snapshot CHECK readiness rejects ${change}`,async()=>{
 const {SNAPSHOT_CHECK}=require('../server/database/postgres/secureshopAuditTargetAdmissionRepository');
 const pool={query:async sql=>({rows:sql.includes('snapshot_ready')?[{snapshot_ready:true,permitted:true,mutable:false,columns:false}]:sql.includes('pg_constraint')?(change==='missing'?[]:[{convalidated:change!=='unvalidated',conenforced:change!=='unenforced',definition:change==='weaker'?SNAPSHOT_CHECK.replace('16777216','33554432'):SNAPSHOT_CHECK}]):[{triggers_ready:true,functions_private:true}]})};
 await assert.rejects(createAuditTargetAdmissionRepository({pool}).checkReadiness(),/constraint unavailable/);
});
test('snapshot CHECK exact validated/enforced tree passes readiness',async()=>{
 const {SNAPSHOT_CHECK}=require('../server/database/postgres/secureshopAuditTargetAdmissionRepository');
 const pool={query:async sql=>({rows:sql.includes('snapshot_ready')?[{snapshot_ready:true,permitted:true,mutable:false,columns:false}]:sql.includes('pg_constraint')?[{convalidated:true,conenforced:true,definition:SNAPSHOT_CHECK}]:[{triggers_ready:true,functions_private:true}]})};
 await createAuditTargetAdmissionRepository({pool}).checkReadiness();
});
