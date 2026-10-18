'use strict';
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');

// Qualifies owned SecureShop reset/audit cleanup and native identity finalization.
// Other application stores are absent from this isolated fixture manifest.
async function qualifyAuditDeletion({identity,migration,agents,review,ledger,subjectId,launchResetCoordinator}){
  const identities=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  const passwordHash=await require('bcryptjs').hash('owned-audit-deletion',4);
  const admin=await identities.createUser({username:`audit-delete-${randomUUID()}`,email:`${randomUUID()}@audit.invalid`,passwordHash});
  await migration.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[admin.id]);
  const jobs=require('../../server/database/postgres/studentDeletionRepository').createStudentDeletionRepository(identity,
    {steps:['revoke_runs','secureshop','identity']});
  const admitted=await jobs.admit({requesterId:admin.id,subjectId});
  const lease=await jobs.claim(admitted.jobId);assert.ok(lease);
  const jobScope={jobId:admitted.jobId,leaseToken:lease.leaseToken};
  const scope={...jobScope,subjectId,check:()=>jobs.renew(jobScope)};
  assert.equal((await jobs.nextStep(jobScope)).stepKey,'revoke_runs');
  await require('../../server/services/studentDeletionRunDrain').createStudentDeletionRunDrain({pool:identity,ledger})(scope);
  await jobs.acknowledge({...jobScope,stepKey:'revoke_runs'});
  assert.equal((await jobs.nextStep(jobScope)).stepKey,'secureshop');
  const siblings=async()=>(await agents.query('SELECT row_to_json(r) AS row FROM secureshop_agents.bound_audit_runs r WHERE original_platform_owner_id<>$1 ORDER BY run_id',[subjectId])).rows;
  const before=await siblings();
  const cleanup=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true}).cleanup;
  const cleanSecureShop=require('../../server/services/secureshopStudentDeletionCleanup').createSecureShopStudentDeletionCleanup({
    repository:jobs,launchResetCoordinator,auditCleanup:cleanup});
  const aggregate=await cleanSecureShop(scope);assert.equal(aggregate.completed,true);assert.ok(aggregate.resetCount>=1);
  assert.deepEqual(await cleanSecureShop(scope),aggregate);
  const result=await cleanup(scope);assert.equal(result.completed,true);
  assert.equal(result.artifacts.deletedRunCount,'1');assert.equal(result.artifacts.deletedArtifactCount,'5');
  assert.ok(BigInt(result.artifacts.deletedBytes)>0n);
  assert.deepEqual(await cleanup(scope),result);
  assert.equal((await agents.query('SELECT count(*)::integer AS n FROM secureshop_agents.bound_audit_runs WHERE original_platform_owner_id=$1',[subjectId])).rows[0].n,0);
  assert.deepEqual(await siblings(),before);
  await jobs.acknowledge({...jobScope,stepKey:'secureshop'});
  assert.equal((await jobs.nextStep(jobScope)).stepKey,'identity');
  await assert.rejects(jobs.complete(jobScope));
  await scope.check();
  const finalized=(await identity.query('SELECT identity.finalize_student_deletion($1::uuid,$2::uuid,$3::integer) AS finalized',
    [scope.jobId,scope.leaseToken,subjectId])).rows[0].finalized;
  assert.equal(finalized,true);
  await jobs.acknowledge({...jobScope,stepKey:'identity'});
  const completed=await jobs.complete(jobScope);assert.equal(completed.state,'completed');
  const tombstone=(await identity.query('SELECT username,is_active FROM identity.users WHERE id=$1',[subjectId])).rows[0];
  assert.equal(tombstone.is_active,0);assert.equal(tombstone.username,`deleted-${scope.jobId}`);
  return {auditStepCompleted:true,identityFinalized:true};
}
module.exports={qualifyAuditDeletion};
