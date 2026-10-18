'use strict';
const {randomBytes}=require('node:crypto');
const {databaseName,fail}=require('./contract');
const {withTargetPool}=require('./admission');
const roleName=id=>databaseName(id)+'_metrics';
// Caller holds the exact target journal lease and global admission until drain.
function createFixedCapability({controlPool,createPool,connection,verifyTarget}){
 if(typeof controlPool?.query!=='function'||typeof createPool!=='function'||typeof verifyTarget!=='function')throw TypeError('Private capability dependencies required');
 async function read(client,id){return(await client.query('SELECT state,password FROM owned_analytics_fixed_capabilities WHERE target_id=$1',[id])).rows[0]||null;}
 return Object.freeze({
  async prepare(client,target){
   const prior=await read(client,target.targetId);if(prior?.state==='ready')return;if(prior)throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');
   const name=roleName(target.targetId),database=databaseName(target.targetId),password=randomBytes(32).toString('hex');
   await client.query("INSERT INTO owned_analytics_fixed_capabilities(target_id,state,password) VALUES($1,'pending',$2)",[target.targetId,password]);
   await controlPool.query(`CREATE ROLE ${name} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1`);
   await controlPool.query(`GRANT CONNECT ON DATABASE ${database} TO ${name}`);
   await withTargetPool(createPool,{...connection,database},async pool=>{const c=await pool.connect();try{
    await verifyTarget(c,database,connection.user);await c.query('BEGIN');
    await c.query(`GRANT USAGE ON SCHEMA public TO ${name}`);
    await c.query(`GRANT SELECT ON public.products,public.orders,public.order_items TO ${name}`);
    await c.query('COMMIT');
   }finally{c.release(true);}});
   const changed=await client.query("UPDATE owned_analytics_fixed_capabilities SET state='ready' WHERE target_id=$1 AND state='pending'",[target.targetId]);if(changed.rowCount!==1)throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');
  },
  async credential(client,target){const row=await read(client,target.targetId);if(row?.state!=='ready'||!/^[a-f0-9]{64}$/.test(row.password||''))throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');return Object.freeze({user:roleName(target.targetId),password:row.password});},
  async disable(client,target){const row=await read(client,target.targetId);if(!row||row.state==='retired')return;const name=roleName(target.targetId);if((await controlPool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[name])).rows.length)await controlPool.query(`ALTER ROLE ${name} NOLOGIN`);},
  async retire(client,target){const row=await read(client,target.targetId);if(!row||row.state==='retired')return;const name=roleName(target.targetId);if((await controlPool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[name])).rows.length)await controlPool.query(`DROP ROLE ${name}`);await client.query("UPDATE owned_analytics_fixed_capabilities SET state='retired',password=NULL WHERE target_id=$1 AND state IN ('pending','ready')",[target.targetId]);}
 });
}
module.exports={createFixedCapability,roleName};
