'use strict';
// Wrap both direct cleanup and reconciliation: neither may acknowledge a
// provisioned mailbox until its atomic SQL cleanup receipt verifies.
function withMailCleanup(repository,mail){
 if(typeof repository?.cleanup!=='function'||typeof repository?.readCleanupReceipt!=='function'
  ||typeof mail?.verifyCleanup!=='function')throw TypeError('Canonical inbox and mail cleanup required');
 const finish=method=>async(scope,options)=>{
  const receipt=await repository[method](scope,options);
  await mail.verifyCleanup(scope,options?.operationId);
  return receipt; // Preserve original three-note receipt semantics and digest.
 };
 return Object.freeze({...repository,cleanup:finish('cleanup'),readCleanupReceipt:finish('readCleanupReceipt')});
}
module.exports={withMailCleanup};

// Always installed in the canonical target lifecycle, independently of serving
// readiness. A restart with mail disabled still must verify previously created
// mail resources before acknowledging retirement.
function createDurableMailCleanupVerifier(pool,additionalVerifier){
 if(typeof pool?.connect!=='function'||(additionalVerifier!==undefined&&typeof additionalVerifier?.verifyCleanup!=='function'))throw TypeError('Mail lifecycle pool required');
 return Object.freeze({async verifyCleanup(scope,operationId){
  const client=await pool.connect();
  try{
   await client.query('BEGIN READ ONLY');
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   const schema=(await client.query("SELECT to_regclass('secureshop_agents.lab_mail_targets')::text AS table_name")).rows[0];
   if(!schema||!Object.hasOwn(schema,'table_name'))throw Error('Mail lifecycle schema check unavailable');
   if(schema.table_name!==null){
    const provision=(await client.query('SELECT EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_targets WHERE target_id=$1) AS provisioned',[scope.targetId])).rows[0];
    if(typeof provision?.provisioned!=='boolean')throw Error('Mail lifecycle provisioning check unavailable');
    if(provision.provisioned){
     const r=(await client.query('SELECT secureshop_agents.verify_bound_lab_mail_cleanup($1,$2) AS result',[scope.targetId,operationId])).rows[0]?.result;
     if(r?.provisioned!==true||r.operationId!==operationId||r.targetId!==scope.targetId)throw Error('Mail lifecycle receipt mismatch');
    }
   }
   await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  if(additionalVerifier)await additionalVerifier.verifyCleanup(scope,operationId);
 }});
}
module.exports.createDurableMailCleanupVerifier=createDurableMailCleanupVerifier;
