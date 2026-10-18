'use strict';
const {createPool}=require('./index');
const {validateCtfDeliveryTuple}=require('./ctfDeliveryActivation');
async function createCtfDeliveryPool({env=process.env,activation,create=createPool}={}){
 const expected=validateCtfDeliveryTuple(activation);
 const url=new URL(env.CTF_DELIVERY_DATABASE_URL);
 if(decodeURIComponent(url.username)!=='dvaia_ctf_delivery')throw Error('CTF_DELIVERY_ROLE_REQUIRED');
 // Dedicated pool stays in the existing global budget; overrides cannot enlarge it.
 const pool=create({...env,PG_POOL_MAX_WORKSHOP:'1'},'CTF_DELIVERY_DATABASE_URL',{purpose:'workshop'});
 try{
  const client=await pool.connect();try{
   const role=(await client.query(`SELECT session_user AS login,current_user AS effective,current_database() AS database,
    r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls,
    EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid) AS membership
    FROM pg_roles r WHERE r.rolname=session_user`)).rows[0];
   if(role?.login!=='dvaia_ctf_delivery'||role.effective!==role.login||role.database!==decodeURIComponent(url.pathname.slice(1))||!role.rolcanlogin||['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls','membership'].some(k=>role[k]))throw Error('CTF_DELIVERY_ROLE_INVALID');
   const row=(await client.query(`SELECT a.activation_id::text,a.authority_sha256,a.identity_store_id::text,a.ctf_store_id::text,a.bootstrap_operation_id::text,a.source_revision::text,a.manifest_sha256,a.protocol_version
    FROM ctf.delivery_control c JOIN ctf.delivery_activations a USING(activation_id) WHERE c.singleton AND ctf.delivery_checkpoint_ready()`)).rows[0];
   if(!row||Object.keys(expected).some(k=>row[k]!==expected[k]))throw Error('CTF_DELIVERY_CHECKPOINT_INVALID');
  }finally{client.release();}
  return pool;
 }catch(error){await pool.end();throw error;}
}
module.exports={createCtfDeliveryPool};
