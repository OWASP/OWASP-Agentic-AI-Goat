'use strict';
const {exact,fail}=require('./contract');
function createClusterVerifier(controlPool, identity) {
 exact(identity,['systemIdentifier','controlDatabase','clusterName']);
 if(!/^[0-9]{10,24}$/.test(identity.systemIdentifier)||!/^owasp_ai_goat_analytics_control_[a-f0-9]{12}$/.test(identity.controlDatabase)
  ||identity.clusterName!==`owasp-ai-goat-owned-analytics-${identity.controlDatabase.slice(-12)}`)throw TypeError('Bootstrap-pinned dedicated cluster identity required');
 const expected=Object.freeze({...identity});
 return Object.freeze({identity:expected,async verify(){
  const row=(await controlPool.query("SELECT current_database() AS database,current_setting('cluster_name') AS cluster,(SELECT system_identifier::text FROM pg_control_system()) AS system_identifier")).rows[0];
  if(row?.database!==expected.controlDatabase||row.cluster!==expected.clusterName||row.system_identifier!==expected.systemIdentifier)throw fail('ANALYTICS_CLUSTER_MISMATCH');
  const databases=(await controlPool.query("SELECT datname,datallowconn,EXISTS(SELECT 1 FROM aclexplode(COALESCE(datacl,acldefault('d',datdba))) a WHERE a.grantee=0 AND a.privilege_type='CONNECT') AS public_connect FROM pg_database")).rows;
  if(!databases.length||databases.some(d=>!['postgres','template0','template1',expected.controlDatabase].includes(d.datname)&&!/^analytics_[a-f0-9]{32}$/.test(d.datname))
    ||databases.some(d=>d.datallowconn&&d.public_connect))throw fail('ANALYTICS_CLUSTER_GRANTS');
  return true;
 },async verifyTarget(client,database,user){
  const row=(await client.query("SELECT current_database() AS database,current_user AS username,current_setting('cluster_name') AS cluster")).rows[0];
  if(row?.database!==database||row.username!==user||row.cluster!==expected.clusterName)throw fail('ANALYTICS_CLUSTER_MISMATCH');
 }});
}
module.exports={createClusterVerifier};
