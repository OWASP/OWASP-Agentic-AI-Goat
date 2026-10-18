'use strict';
const {createSecureShopProgressCleanupCheckpointRepository}=require('./secureshopProgressCleanupCheckpointRepository');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const unavailable=()=>Object.assign(new Error('SecureShop progress cleanup authority unavailable'),{code:'PROGRESS_CHECKPOINT_MISMATCH'});
function createSecureShopRealmProgressCleanupCheckpointRepository(pool){
  const platform=createSecureShopProgressCleanupCheckpointRepository(pool);
  return Object.freeze({async finalize(resetId){
    if(typeof resetId!=='string'||!UUID.test(resetId))throw unavailable();
    resetId=resetId.toLowerCase();
    const row=(await pool.query(`SELECT o.realm FROM identity.secureshop_launch_resets r
      JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id
      JOIN identity.secureshop_authority_owners o ON o.id=l.original_platform_owner_id
      WHERE r.reset_id=$1`,[resetId])).rows[0];
    if(row?.realm==='platform')return platform.finalize(resetId);
    if(row?.realm!=='shop')throw unavailable();
    const checkpoint=(await pool.query('SELECT * FROM secureshop_auth.finalize_assessment_cleanup($1)',[resetId])).rows[0];
    if(checkpoint?.reset_id!==resetId)throw unavailable();
    return Object.freeze({resetId,realm:'shop',checkpoint:Object.freeze(checkpoint)});
  }});
}
module.exports={createSecureShopRealmProgressCleanupCheckpointRepository};
