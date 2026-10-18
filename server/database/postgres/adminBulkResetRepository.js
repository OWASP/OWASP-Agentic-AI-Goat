'use strict';
const {randomUUID}=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function createAdminBulkResetRepository(pool,{leasePool}={}){
 if(typeof pool?.query!=='function')throw new TypeError('Identity pool required');
 function actor(value){if(!Number.isSafeInteger(value?.actorId)||value.actorId<1||!/^\d+$/.test(String(value.sessionId)))throw new TypeError('Current canonical administrator required');return[value.actorId,String(value.sessionId)];}
 function operation(value){if(!UUID.test(value||''))throw new TypeError('Reset operation UUID required');return value;}
 async function query(sql,args){try{return(await pool.query(sql,args)).rows[0]?.result;}catch(error){if(error.code==='42501')throw Object.assign(new Error('Current reset permission required'),{code:'BULK_RESET_AUTHORITY_REJECTED',statusCode:403});if(error.code==='22023')throw Object.assign(new Error('Reset operation request conflicts with retained request'),{code:'BULK_RESET_CONFLICT',statusCode:409});if(error.code==='55000')throw Object.assign(new Error('Prior reset child requires outcome reconciliation'),{code:'BULK_RESET_RECONCILIATION_REQUIRED',statusCode:409});throw error;}}
 return Object.freeze({
 async withOperation(operationId,work){
   operation(operationId);
   if(!leasePool || leasePool===pool || typeof leasePool.connect!=='function')throw new TypeError('Dedicated bulk reset lease pool required');
   const client=await leasePool.connect();let locked=false,discard;
   try{
     locked=(await client.query('SELECT pg_try_advisory_lock(842184,hashtext($1)) AS locked',[operationId])).rows[0].locked;
     if(!locked)throw Object.assign(new Error('Reset operation is already running'),{code:'BULK_RESET_BUSY',statusCode:409});
     return await work(createAdminBulkResetRepository(client));
   }finally{
     try{if(locked){const unlocked=(await client.query('SELECT pg_advisory_unlock(842184,hashtext($1)) AS unlocked',[operationId])).rows[0]?.unlocked;if(!unlocked)throw new Error('Reset lease unlock failed');}}
     catch(error){discard=error;throw error;}
     finally{client.release(discard);}
   }
 },
 begin({operationId,requestKind,workshopKeys,...authority}){return query('SELECT identity.begin_bulk_reset($1,$2,$3,$4,$5) AS result',[operation(operationId),...actor(authority),requestKind,workshopKeys]);},
 claim({operationId,ordinal,replaySafe=false,...authority}){return query('SELECT identity.claim_bulk_reset_child($1,$2,$3,$4,$5,$6) AS result',[operation(operationId),...actor(authority),ordinal,randomUUID(),replaySafe===true]);},
 finish({operationId,ordinal,leaseToken,completed,...authority}){return query('SELECT identity.finish_bulk_reset_child($1,$2,$3,$4,$5,$6,$7) AS result',[operation(operationId),...actor(authority),ordinal,operation(leaseToken),completed,null]);},
 listPending(authority,scope){if(scope)return query('SELECT identity.list_bulk_resets_for_scope($1,$2,$3,$4) AS result',[...actor(authority),scope.requestKind,scope.workshopKey??null]);return query('SELECT identity.list_bulk_resets($1,$2) AS result',actor(authority));}
 });
}
module.exports={createAdminBulkResetRepository};
