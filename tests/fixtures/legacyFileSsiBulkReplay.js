'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto');
async function qualifyLegacyFileSsiBulkReplay({pool,migration,finflow,identity,owner,owners,progress,resetComposition,runs,request}){
 // Qualify the registered migration directly without writing to the source checkout.
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 await require('../../db/postgres/migrate').migrate(migration,path.resolve('db/postgres/identity-migrations'));
 assert.deepEqual(await require('../../db/postgres/migrate').migrate(migration,path.resolve('db/postgres/identity-migrations')),[]);
 const admin=await owner();await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.user.id]);await identity.grantPermission({userId:admin.user.id,permission:'manage_progress',grantedBy:admin.user.id});
 const leases=new (require('pg').Pool)({connectionString:process.env.WORKSHOP_RAG_RUNTIME_URL,max:2});
 try{
  const journal=require('../../server/database/postgres/adminBulkResetRepository').createAdminBulkResetRepository(pool,{leasePool:leases});
  await require('../../server/services/adminBulkResetComposition').assertAdminBulkResetReadiness(pool);
  let fail=true;const invoked=[];const real=resetComposition.reset;
  const lostResponse={reset:async(id,options)=>{invoked.push({id:Number(id),operationId:options.operationId});const result=await real.reset(id,options);if(Number(id)===owners[1].user.id&&fail){fail=false;throw Error('owned lost response after completed legacy child');}return result;}};
  const factory=require('../../server/services/postgresWorkshopResetService');
  const adapters=factory.createPostgresWorkshopResetAdapters(name=>{
   if(name==='./legacySensitiveCandidateComposition')return{getLegacySensitiveCandidateComposition:async()=>({reset:lostResponse})};
   if(name==='./legacySensitiveRunCoordinator')return{legacySensitiveRuns:runs};throw Error('Unexpected dependency '+name);
  },{env:{LEGACY_SENSITIVE_CANONICAL_AGENT_ENABLED:'true'}});
  const authority={actorId:admin.user.id,sessionId:String(admin.session.internalSessionId)};
  const service=factory.createPostgresWorkshopResetService({adapters,bulkJournal:journal,resolveBulkActor:async()=>authority});
  const operationId=randomUUID();await assert.rejects(service.resetWorkshop({workshopKey:'legacy_sensitive_file_ssi',operationId}),/owned lost response/);
  const parent=(await journal.listPending(authority)).find(row=>row.operationId===operationId);
  assert.equal(parent.children.find(c=>c.ownerId===owners[0].user.id).state,'completed');
  const uncertain=parent.children.find(c=>c.ownerId===owners[1].user.id);assert.equal(uncertain.state,'uncertain');
  const receipt=(await finflow.query('SELECT * FROM finflow.read_legacy_file_ssi_cleanup_receipt($1,$2)',[uncertain.childOperationId,'legacy_store'])).rows;
  assert.equal(receipt.length,1);
  for(const o of owners)assert.equal((await request(o)).body.completed,true);
  const newer=await Promise.all(owners.map(o=>progress.getWorkshopProgress(o.user.id,'legacy_sensitive_file_ssi')));
  const late=await owner();assert.equal((await request(late)).body.completed,true);
  const lateBefore=await progress.getWorkshopProgress(late.user.id,'legacy_sensitive_file_ssi');
  await service.resetWorkshop({workshopKey:'legacy_sensitive_file_ssi',operationId});
  assert.deepEqual(await Promise.all(owners.map(o=>progress.getWorkshopProgress(o.user.id,'legacy_sensitive_file_ssi'))),newer);
  assert.deepEqual(await progress.getWorkshopProgress(late.user.id,'legacy_sensitive_file_ssi'),lateBefore);
  assert.deepEqual((await finflow.query('SELECT * FROM finflow.read_legacy_file_ssi_cleanup_receipt($1,$2)',[uncertain.childOperationId,'legacy_store'])).rows,receipt);
  assert.equal(invoked.filter(i=>i.id===owners[0].user.id).length,1);assert.equal(new Set(invoked.filter(i=>i.id===owners[1].user.id).map(i=>i.operationId)).size,1);
  return{realCompletedChildLostResponseReconciled:true,newerOwnerProgressPreserved:true,lateEnrollmentExcluded:true,exactChildReceiptPreserved:true,candidateOnly:true};
 }finally{await leases.end();}
}
module.exports={qualifyLegacyFileSsiBulkReplay};
