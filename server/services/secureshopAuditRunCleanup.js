'use strict';
const {createHash,timingSafeEqual}=require('node:crypto');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const COUNTS=['deleted_run_count','deleted_artifact_count','deleted_chunk_count','deleted_bytes'];
function verify(row,owner,job){
  if(!row||row.deletion_job_id!==job||Number(row.original_platform_owner_id)!==owner)
    throw new Error('Audit artifact deletion receipt scope mismatch');
  const counts=COUNTS.map(key=>{
    const value=row[key];
    if(!((typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value))
      ||(typeof value==='number'&&Number.isSafeInteger(value)&&value>=0)))
      throw new Error('Audit artifact deletion receipt count invalid');
    return BigInt(value).toString();
  });
  const expected=createHash('sha256').update(['secureshop-audit-run-deletion-v1',job,String(owner),...counts].join('\x1f')).digest();
  if(!Buffer.isBuffer(row.receipt_sha256)||row.receipt_sha256.length!==32||!timingSafeEqual(row.receipt_sha256,expected))
    throw new Error('Audit artifact deletion receipt digest mismatch');
  return Object.freeze({deletionJobId:job,originalPlatformOwnerId:owner,
    deletedRunCount:counts[0],deletedArtifactCount:counts[1],deletedChunkCount:counts[2],deletedBytes:counts[3],
    receiptSha256:expected.toString('hex')});
}

// Compose only after audit-run schema readiness. Existing journal receipts
// retain their exact format; artifacts have a separate crash-recoverable step.
function createSecureShopAuditRunCleanup({pool,cleanJournals}={}){
  if(typeof pool?.query!=='function'||typeof cleanJournals!=='function')throw new TypeError('Audit deletion dependencies required');
  return async function cleanup(scope={}){
    if(!Number.isInteger(scope.subjectId)||scope.subjectId<1||scope.subjectId>2147483647
      ||typeof scope.jobId!=='string'||!UUID.test(scope.jobId)||typeof scope.check!=='function')
      throw new TypeError('Audit owner deletion scope required');
    const owner=scope.subjectId,job=scope.jobId.toLowerCase();
    const check=async()=>{scope.signal?.throwIfAborted();await scope.check();scope.signal?.throwIfAborted();};
    await check();
    const journals=await cleanJournals({...scope,jobId:job});
    await check();
    if(journals?.completed!==true||['agents','review'].some(store=>
      journals[store]?.deletionJobId!==job||journals[store]?.originalPlatformOwnerId!==owner))
      throw new Error('Audit journal deletion is unverified');
    const returned=await pool.query('SELECT * FROM secureshop_agents.destroy_bound_audit_runs($1,$2::uuid)',[owner,job]);
    await check();
    if(returned.rows?.length!==1)throw new Error('Audit artifact deletion receipt missing');
    const receipt=verify(returned.rows[0],owner,job);
    const reread=await pool.query(`SELECT * FROM secureshop_agents.bound_audit_run_deletion_receipts
      WHERE deletion_job_id=$1::uuid AND original_platform_owner_id=$2`,[job,owner]);
    await check();
    if(reread.rows?.length!==1||JSON.stringify(verify(reread.rows[0],owner,job))!==JSON.stringify(receipt))
      throw new Error('Audit artifact deletion receipt changed');
    return Object.freeze({...journals,artifacts:receipt});
  };
}
module.exports={createSecureShopAuditRunCleanup};
