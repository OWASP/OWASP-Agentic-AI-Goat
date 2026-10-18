'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
const {hash,scope,fail}=require('./contract');
function createOwnedAnalyticsJournal(pool){
 if(typeof pool?.connect!=='function')throw TypeError('Dedicated control pool required');
 const leases=new AsyncLocalStorage();
 const connection=()=>{const value=leases.getStore();if(!value)throw fail('ANALYTICS_TARGET_LEASE_REQUIRED');value.assert();return value.client;};
 const key=value=>hash(scope(value));
 return Object.freeze({
  async withClient(work){const client=connection();const result=await work(client);connection();return result;},
  signal(){const lease=leases.getStore();if(!lease)throw fail('ANALYTICS_TARGET_LEASE_REQUIRED');lease.assert();return lease.signal;},
  async withLock(binding,work){const id=key(binding),client=await pool.connect();let held=false,lost=false;
   const controller=new AbortController();
   const onError=error=>{lost=true;controller.abort(Object.assign(fail('ANALYTICS_LEASE_LOST'),{cause:error}));};
   const assert=()=>{if(lost)throw controller.signal.reason;};client.on('error',onError);
   try{held=(await client.query("SELECT pg_try_advisory_lock(('x'||$1)::bit(64)::bigint) AS held",[id.slice(0,16)])).rows[0]?.held===true;if(!held)throw fail('ANALYTICS_TARGET_BUSY');
    assert();const result=await leases.run({client,signal:controller.signal,assert},work);assert();return result;
   }finally{let broken=!held||lost;if(held&&!lost)try{if((await client.query("SELECT pg_advisory_unlock(('x'||$1)::bit(64)::bigint) AS released",[id.slice(0,16)])).rows[0]?.released!==true)broken=true;}catch{broken=true;}if(!broken)client.off('error',onError);client.release(broken);}
  },
  async get(binding){const r=(await connection().query('SELECT target_id,scope,source_manifest_sha256,state FROM owned_analytics_targets WHERE binding_sha256=$1',[key(binding)])).rows[0];return r?{targetId:r.target_id,scope:r.scope,sourceManifestSha256:r.source_manifest_sha256,state:r.state}:null;},
  async begin(binding,target){await connection().query("INSERT INTO owned_analytics_targets(binding_sha256,target_id,scope,source_manifest_sha256,state) VALUES($1,$2,$3,$4,'pending')",[key(binding),target.targetId,target.scope,target.sourceManifestSha256]);},
  async transition(binding,from,to){const r=await connection().query('UPDATE owned_analytics_targets SET state=$2 WHERE binding_sha256=$1 AND state=$3',[key(binding),to,from]);if(r.rowCount!==1)throw fail('ANALYTICS_TARGET_CONFLICT');},
  async saveCredential(id,password){await connection().query('INSERT INTO owned_analytics_credentials(target_id,password) VALUES($1,$2)',[id,password]);},
  async credential(id){return(await connection().query('SELECT password FROM owned_analytics_credentials WHERE target_id=$1',[id])).rows[0]?.password;},
  async eraseCredential(id){await connection().query('DELETE FROM owned_analytics_credentials WHERE target_id=$1',[id]);},
  async readQuery(id,operation){return(await connection().query('SELECT request_sha256,state,receipt,result_sha256 FROM owned_analytics_queries WHERE target_id=$1 AND operation_id=$2',[id,operation])).rows[0]||null;},
  async admitQuery(id,operation,requestDigest){await connection().query("INSERT INTO owned_analytics_queries(target_id,operation_id,request_sha256,state) VALUES($1,$2,$3,'pending')",[id,operation,requestDigest]);},
  async completeQuery(id,operation,receipt){const r=await connection().query("UPDATE owned_analytics_queries SET state='completed',receipt=$3,result_sha256=$4 WHERE target_id=$1 AND operation_id=$2 AND state='pending'",[id,operation,receipt,receipt.resultSha256]);if(r.rowCount!==1)throw fail('ANALYTICS_QUERY_CONFLICT');},
  async redact(id){await connection().query("UPDATE owned_analytics_queries SET state='redacted',receipt=NULL WHERE target_id=$1 AND state='completed'",[id]);},
 });
}
module.exports={createOwnedAnalyticsJournal};
