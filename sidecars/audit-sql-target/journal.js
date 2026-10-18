'use strict';
const {createHash,randomBytes}=require('node:crypto');
const {AsyncLocalStorage}=require('node:async_hooks');
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function createJournal({pool}) {
 const transactions=new AsyncLocalStorage();
 const connection=()=>{const c=transactions.getStore();if(!c)throw Error('Target lease required');return c;};
 const key=binding=>hash([binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId]);
 const update=async(binding,state)=>{
  const result=await connection().query('UPDATE owned_audit_targets SET state=$2 WHERE binding_sha256=$1',[key(binding),state]);
  if(result.rowCount!==1)throw Error('Target admission missing');
 };
 return Object.freeze({
  async withLock(binding,fn){
   const c=await pool.connect();const lock=key(binding).slice(0,16);let held=false;
   try {await c.query("SELECT pg_advisory_lock(('x'||$1)::bit(64)::bigint)",[lock]);held=true;return await transactions.run(c,fn);}
   finally {let broken=!held;if(held){try{await c.query("SELECT pg_advisory_unlock(('x'||$1)::bit(64)::bigint)",[lock]);}catch{broken=true;}}c.release(broken);}
  },
  async get(binding){const row=(await connection().query('SELECT target,state,receipt FROM owned_audit_targets WHERE binding_sha256=$1',[key(binding)])).rows[0];return row?{...row.receipt,target:row.target,state:row.state}:null;},
  async begin(binding,receipt){const target='audit_'+randomBytes(16).toString('hex');await connection().query('INSERT INTO owned_audit_targets(binding_sha256,target,receipt,state) VALUES($1,$2,$3,\'pending\')',[key(binding),target,receipt]);return {target};},
  async ready(binding,target){const result=await connection().query("UPDATE owned_audit_targets SET state='ready' WHERE binding_sha256=$1 AND target=$2 AND state='pending'",[key(binding),target]);if(result.rowCount!==1)throw Error('Target admission mismatch');},
  async redactQueries(target){return(await connection().query("UPDATE owned_audit_queries SET retired_result_sha256=receipt->>'resultSha256',receipt=NULL,state='redacted' WHERE target=$1 AND state IN ('pending','completed') RETURNING operation_id,request_sha256,retired_result_sha256",[target])).rows;},
  async getQuery(target,operationId){return(await connection().query('SELECT request_sha256,state,receipt FROM owned_audit_queries WHERE target=$1 AND operation_id=$2',[target,operationId])).rows[0]||null;},
  async beginQuery(target,operationId,requestSha256){await connection().query("INSERT INTO owned_audit_queries(target,operation_id,request_sha256,state) VALUES($1,$2,$3,'pending')",[target,operationId,requestSha256]);},
  async completeQuery(target,operationId,receipt){const result=await connection().query("UPDATE owned_audit_queries SET state='completed',receipt=$3 WHERE target=$1 AND operation_id=$2 AND state='pending'",[target,operationId,receipt]);if(result.rowCount!==1)throw Error('Query completion conflict');},
  retiring:binding=>update(binding,'retiring'),retired:binding=>update(binding,'retired'),
 });
}
module.exports={createJournal};
