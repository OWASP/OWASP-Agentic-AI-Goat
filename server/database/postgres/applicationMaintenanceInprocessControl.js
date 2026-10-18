'use strict';
const {createHash}=require('node:crypto');
const caps=require('../../services/applicationMaintenanceInprocessAdmission');
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=()=>Object.assign(Error('Prepared maintenance unavailable'),{code:'APPLICATION_MAINTENANCE_PREPARED_UNCERTAIN'});
function createInprocessControl({query,held,lock,read,transaction,mode,identity,reserve,upgrade,assertExecutionReady}){
 let busy=false;
 async function operation(work){if(mode!=='maintenance'||!identity||busy)throw fail();busy=true;try{return await transaction(async()=>{await lock();return work();});}catch{throw fail();}finally{busy=false;}}
 return Object.freeze({
  async beginPrepared(capability){const a=caps.consumePrepared(capability,identity),execution=caps.executionBinding?.(a);reserve();let epoch;
   await operation(async()=>{if(execution)await assertExecutionReady();else await upgrade();const c=await read();if(c.installation_id!==a.clean.installationId||String(c.epoch)!==a.clean.epoch||c.state!=='clean')throw fail();
    await query("UPDATE dvaia_maintenance.control SET epoch=epoch+1,state='dirty',operation_id=$1,owner_host_sha256=$2,begun_at=clock_timestamp(),finished_at=NULL WHERE singleton AND state='clean'",[a.operationId,a.owner.hostSha256]);const current=await read();epoch=String(current.epoch);
    await query('INSERT INTO dvaia_maintenance.epochs(epoch,operation_id,owner_host_sha256,begun_at) SELECT epoch,operation_id,owner_host_sha256,begun_at FROM dvaia_maintenance.control');
    await query("INSERT INTO dvaia_maintenance.epoch_bindings(epoch,operation_id,profile,workspace_sha256,store_manifest_sha256,publication_id,publication_sha256,source_manifest_sha256,owner_record,owner_record_sha256) VALUES($1,$2,'upgrade-canonical16-v1',$3,$4,$5,$6,$7,$8::jsonb,$9)",[epoch,a.operationId,a.owner.workspaceSha256,hash(a.stores),a.publicationId,a.publicationSha256,a.sourceManifestSha256,JSON.stringify(a.owner),hash(a.owner)]);
    for(const [i,s]of a.stores.entries())await query('INSERT INTO dvaia_maintenance.epoch_stores(epoch,ordinal,store_key,cluster_identifier,database_oid,database_name,runtime_role,migration_role,delivery_role,endpoint_policy_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[epoch,i+1,s.storeKey,s.clusterIdentifier,s.databaseOid,s.databaseName,s.runtimeRole,s.migrationRole,s.deliveryRole,s.endpointPolicySha256]);
    await query("INSERT INTO dvaia_maintenance.epoch_replay_profiles(epoch,operation_id,profile,source_manifest_sha256,artifact_manifest_sha256,identity_store_id,ctf_store_id,bootstrap_id,activation_id,writer_policy) VALUES($1,$2,'canonical16-ctf-inprocess-v1',$3,$4,$5,$6,$7,$8,'inprocess-only')",[epoch,a.operationId,a.sourceManifestSha256,a.artifactManifestSha256,a.binding.identityStoreId,a.binding.ctfStoreId,a.bootstrapId,a.activationId]);
    for(const r of a.artifacts)await query('INSERT INTO dvaia_maintenance.epoch_replay_artifacts(epoch,kind,relative_path,schema_version,binding_sha256,content_sha256,artifact_id) VALUES($1,$2,$3,$4,$5,$6,$7)',[epoch,r.kind,r.relativePath,r.schemaVersion,r.bindingSha256,r.contentSha256,r.artifactId]);
    await query("INSERT INTO dvaia_maintenance.ctf_journal_lock_intents(epoch,writer_id,writer_kind,original_operation_id,nonce,binding_sha256,owner_record_sha256) VALUES($1,$2,'original',$2,$3,$4,$5)",[epoch,a.operationId,a.nonce,a.artifacts.find(r=>r.kind==='ctf-authority').bindingSha256,hash(a.owner)]);
    if(execution)await query("INSERT INTO dvaia_maintenance.epoch_execution_admissions(epoch,operation_id,profile,launch_policy,source_manifest_sha256,owner_record_sha256,launcher_policy_sha256) VALUES($1,$2,'canonical16-ctf-recovery-v1','exclusive-inprocess-no-helpers-v1',$3,$4,$5)",[epoch,a.operationId,a.sourceManifestSha256,hash(a.owner),execution.policySha256]);
   });held();return caps.bindAdmitted(a,epoch);
  },
  async finishPrepared(token,completion){const a=caps.admittedState(token,identity);require('../../services/applicationMaintenanceInprocessWorkflow').consumeCompletion(completion,token,identity);caps.invalidateAdmitted(token);
   await operation(async()=>{const c=await read();if(c.state!=='dirty'||String(c.epoch)!==a.epoch||c.operation_id!==a.operationId||c.installation_id!==a.clean.installationId)throw fail();
    if((await query('SELECT 1 FROM dvaia_maintenance.recovery_attempts WHERE epoch=$1',[a.epoch])).rows.length)throw fail();
    const r=await query("UPDATE dvaia_maintenance.control SET state='clean',finished_at=clock_timestamp() WHERE singleton AND state='dirty' AND epoch=$1 AND operation_id=$2 RETURNING finished_at::text AS finished_at",[a.epoch,a.operationId]);if(r.rows.length!==1)throw fail();
    const time=r.rows[0].finished_at;await query('INSERT INTO dvaia_maintenance.epoch_finish_receipts(epoch,operation_id,recovery_attempt_id,profile_binding_sha256,publication_id,publication_sha256,finished_at) VALUES($1,$2,NULL,$3,$4,$5,$6)',[a.epoch,a.operationId,a.artifactManifestSha256,a.publicationId,a.publicationSha256,time]);const updated=await query('UPDATE dvaia_maintenance.epochs SET finished_at=$3 WHERE epoch=$1 AND operation_id=$2 AND finished_at IS NULL',[a.epoch,a.operationId,time]);if(updated.rowCount!==1)throw fail();
   });
  }
 });
}
module.exports={createInprocessControl};
