'use strict';const test=require('node:test'),assert=require('node:assert/strict');
const{createPostgresWorkshopResetAdapters}=require('../server/services/postgresWorkshopResetService');
test('staged legacy bulk adapter is lazy before runtime enablement',()=>{const adapters=createPostgresWorkshopResetAdapters(()=>assert.fail('eager dependency load'));assert.equal(typeof adapters.legacy_sensitive_file_ssi.preflight,'function');});
test('enabled adapter preserves exact bulk child operation and rejects unavailable composition',async()=>{
 const calls=[];const load=name=>name==='./legacySensitiveRunCoordinator'?{legacySensitiveRuns:{}}:{getLegacySensitiveCandidateComposition:async()=>({reset:{reset:async(...args)=>calls.push(args)}})};
 const adapter=createPostgresWorkshopResetAdapters(load,{env:{LEGACY_SENSITIVE_CANONICAL_AGENT_ENABLED:'true'}}).legacy_sensitive_file_ssi;
 assert.equal(await adapter.bulkResetReplaySafe(),true);await adapter.resetOwner(42,{operationId:'exact-child'});assert.deepEqual(calls,[[42,{operationId:'exact-child'}]]);
 const unavailable=createPostgresWorkshopResetAdapters(name=>name==='./legacySensitiveRunCoordinator'?{legacySensitiveRuns:{}}:{getLegacySensitiveCandidateComposition:async()=>null},{env:{LEGACY_SENSITIVE_CANONICAL_AGENT_ENABLED:'true'}}).legacy_sensitive_file_ssi;
 await assert.rejects(unavailable.preflight(),{code:'RESET_STORAGE_NOT_READY'});
});
