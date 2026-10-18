'use strict';
function stale(message='Graph generation is no longer current'){const error=new Error(message);error.name='AbortError';return error;}
// node-postgres clients permit only one active query. Keep business callbacks
// parallel while serializing the short ledger statements that share a run's
// connection-scoped advisory-lock client. Closing first stops new admission,
// then drains every already accepted statement before unlock/release.
function createLeaseQueryLane(raw,releasePermit=()=>{}){
 let accepting=true,tail=Promise.resolve(),closing;
 const releaseRaw=destroy=>{raw.release(destroy);releasePermit();};
 const lane={graphLeaseError:null,graphLeaseErrorHandler:null,
  query(sql,args){
   if(!accepting)return Promise.reject(stale('Graph lease is closing'));
   const result=tail.then(()=>{
    if(lane.graphLeaseError)throw lane.graphLeaseError;
    return raw.query(sql,args);
   });
   tail=result.then(()=>undefined,()=>undefined);
   return result;
  },
  close(ownerKey,{unlock=true,destroy=false}={}){
   if(closing)return closing;
   accepting=false;
   closing=(async()=>{
    await tail;
    let failure;
    if(lane.graphLeaseError)destroy=true;
    else if(unlock){try{await raw.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[ownerKey]);}catch(error){failure=error;destroy=true;}}
    try{raw.removeListener('error',lane.graphLeaseErrorHandler);}catch(error){failure=failure?new AggregateError([failure,error],'Graph lease cleanup failed'):error;destroy=true;}
    // A throwing release has unknown physical disposition. Never retry it or
    // return its permit; retain capacity conservatively and surface failure.
    releaseRaw(destroy||undefined);
    if(failure)throw failure;
   })();
   return closing;
  },
 };
 const errorHandler=error=>{lane.graphLeaseError=error;};
 lane.graphLeaseErrorHandler=errorHandler;
 raw.on('error',errorHandler);
 return lane;
}
/** A connection-scoped advisory lock spans each run/reset. Crashed connections
 * release the lock; the next holder marks unfinished runs interrupted. No
 * mutating node is replayed, even when its effect outcome is uncertain. */
function createPostgresRunLedger(pool,{leasePool=pool,scopeAuthority}={}){
 if(scopeAuthority!==undefined && (typeof scopeAuthority?.bindRun!=='function'||typeof scopeAuthority?.assertRunCurrent!=='function'))throw new TypeError('Invalid graph scope authority');
 const clients=new Map();
 const admission=require('./graphLeaseAdmission').admissionFor(leasePool);
 const lock=async(ownerKey,signal=AbortSignal.timeout(300000),kind='run')=>{
  const releasePermit=await admission.acquire(ownerKey,signal,kind);
  let raw;
  try{raw=await leasePool.connect();}catch(error){releasePermit();throw error;}
  if(signal.aborted){raw.release();releasePermit();throw signal.reason;}
  let client;
  try{client=createLeaseQueryLane(raw,releasePermit);}catch(error){
   // A setup failure still owns the checked-out session. Dispose once; an
   // exception from disposition deliberately retains its admission permit.
   try{raw.release(true);}catch(cleanup){throw new AggregateError([error,cleanup],'Graph lease setup cleanup failed');}
   releasePermit();throw error;
  }
  try{
   while(true){
    if(signal.aborted)throw signal.reason;
    if(client.graphLeaseError)throw client.graphLeaseError;
    const result=await client.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS acquired',[ownerKey]);
    if(result.rows[0].acquired)return client;
    await new Promise(resolve=>setTimeout(resolve,25));
   }
  }catch(error){await client.close(ownerKey,{unlock:false,destroy:true});throw error;}
 };
 const unlock=(client,ownerKey)=>client.close(ownerKey);
 const current=async(context,client=clients.get(context.runId))=>{
  if(!client)throw stale('Graph run has no active lease');
  if(client.graphLeaseError)throw stale('Graph lease connection was lost');
  const row=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[context.ownerKey])).rows[0];
  if(client.graphLeaseError)throw stale('Graph lease connection was lost');
  if(!row||String(row.generation)!==String(context.durableGeneration))throw stale();
  if(context.scope!==undefined){
   if(!scopeAuthority||!context.scopeBinding)throw stale('Graph scope authority is unavailable');
   await scopeAuthority.assertRunCurrent(client,context);
   if(client.graphLeaseError)throw stale('Graph lease connection was lost');
  }
 };
 const settleOrphans=async(client,ownerKey)=>{
  // Only the exclusive owner lease proves an old process can no longer be
  // executing. Preserve completed effects and terminal run history.
  await client.query("UPDATE graph_runtime.runs SET status='interrupted',finished_at=clock_timestamp() WHERE owner_key=$1 AND status='running'",[ownerKey]);
  await client.query("UPDATE graph_runtime.effects SET status='uncertain',updated_at=clock_timestamp() WHERE owner_key=$1 AND status='started'",[ownerKey]);
 };
 return {
  supportsPreRunAdmission:true,
  supportsScopedAdmission:scopeAuthority!==undefined,
  async begin(context,{signal,admit}={}){
   if(context.scope!==undefined&&!scopeAuthority)throw new Error('Graph ledger does not support scoped admission');
   signal?.throwIfAborted();
   const queuedGeneration=(await pool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[context.ownerKey])).rows[0]?.generation??0;
   signal?.throwIfAborted();
   const client=await lock(context.ownerKey,signal);
   let transaction=false;
   try{
    await client.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING',[context.ownerKey]);
    const initial=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[context.ownerKey])).rows[0];
    if(String(initial.generation)!==String(queuedGeneration))throw stale('Graph generation changed during lease admission');
    await settleOrphans(client,context.ownerKey);
    const admission=admit?await admit():undefined;
    // invalidate() deliberately bumps this row before waiting for the lease.
    // Reject a change across journal admission rather than adopting the new
    // generation: this invocation was queued under the old launch authority.
    const current=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[context.ownerKey])).rows[0];
    signal?.throwIfAborted();
    if(!initial||!current||String(initial.generation)!==String(current.generation))throw stale();
    if(admission?.skip){await unlock(client,context.ownerKey);return {skipped:true,value:admission.value};}
    let scopeBinding;
    if(context.scope!==undefined){
     await client.query('BEGIN');transaction=true;
     const locked=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR SHARE',[context.ownerKey])).rows[0];
     if(!locked||String(locked.generation)!==String(initial.generation))throw stale();
    }
    await client.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,$3,'running')",[context.runId,context.ownerKey,initial.generation]);
    if(context.scope!==undefined){
     scopeBinding=await scopeAuthority.bindRun(client,{...context,durableGeneration:String(initial.generation)});
     if(!scopeBinding||typeof scopeBinding!=='object')throw new TypeError('Graph scope binding is unavailable');
     signal?.throwIfAborted();
     await client.query('COMMIT');transaction=false;
    }
    clients.set(context.runId,client);
    return {durableGeneration:String(initial.generation),...(scopeBinding?{scopeBinding:Object.freeze({...scopeBinding})}:{})};
   }catch(error){
    if(transaction){try{await client.query('ROLLBACK');}catch(rollbackError){error.rollbackError=rollbackError;}}
    clients.delete(context.runId);
    if(error.rollbackError)await client.close(context.ownerKey,{destroy:true});else await unlock(client,context.ownerKey);
    throw error;
   }
  },
  assertCurrent:current,
  async recordEvent(context,event){
   const client=clients.get(context.runId);await current(context,client);
   const data=require('./runTraceStore').traceData(event.data);
   await client.query('UPDATE graph_runtime.runs SET provider=COALESCE($2,provider),model=COALESCE($3,model),decision_source=COALESCE($4,decision_source),tokens=CASE WHEN $5::bigint IS NULL THEN tokens ELSE COALESCE(tokens,0)+$5 END WHERE run_id=$1',[context.runId,data.provider||null,data.model||null,data.decisionSource||null,data.tokens>0?data.tokens:null]);
   await client.query(`INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) SELECT $1,$2,COALESCE(MAX(sequence),0)+1,$3,$4,$5::jsonb FROM graph_runtime.events WHERE run_id=$1 HAVING COALESCE(MAX(sequence),0)<200`,[context.runId,context.ownerKey,event.node,event.type,JSON.stringify(data)]);
  },
  async listRuns(ownerKey,limit=25){return (await pool.query('SELECT run_id AS "runId",owner_key AS "ownerKey",generation,status,provider,model,decision_source AS "decisionSource",tokens,last_node AS "lastNode",started_at AS "startedAt",finished_at AS "finishedAt" FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY started_at DESC LIMIT $2',[ownerKey,Math.min(100,Math.max(1,limit))])).rows;},
  async getRun(runId,ownerKey){const run=(await pool.query('SELECT run_id AS "runId",owner_key AS "ownerKey",generation,status,provider,model,decision_source AS "decisionSource",tokens,last_node AS "lastNode",started_at AS "startedAt",finished_at AS "finishedAt" FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2',[runId,ownerKey])).rows[0];if(!run)return null;run.events=(await pool.query('SELECT sequence AS seq,node,event_type AS type,metadata AS data,created_at AS "createdAt" FROM graph_runtime.events WHERE run_id=$1 AND owner_key=$2 ORDER BY sequence',[runId,ownerKey])).rows;return run;},
  async checkpoint(context,{node}){const client=clients.get(context.runId);await current(context,client);await client.query('UPDATE graph_runtime.runs SET last_node=$2 WHERE run_id=$1',[context.runId,node]);},
  async finish(context,{status}){
   const client=clients.get(context.runId);if(!client)return;
   try{await client.query('UPDATE graph_runtime.runs SET status=$2,finished_at=clock_timestamp() WHERE run_id=$1',[context.runId,status]);}
   finally{clients.delete(context.runId);await unlock(client,context.ownerKey);}
  },
  // Scoped maintenance shares the run lease without advancing the parent.
  // The caller owns child-generation changes and store receipt recovery.
  async withOwnerLease({ownerKey,signal}={},work){
   if(typeof ownerKey!=='string'||!ownerKey.length||ownerKey.length>512||typeof work!=='function')throw new TypeError('Owner lease coordinates and callback required');
   const client=await lock(ownerKey,signal,'lifecycle');
   let active=true;
   try{
    const row=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0];
    if(!row)throw stale('Graph owner is unavailable');
    const durableGeneration=require('./durableGeneration').canonicalDurableGeneration(row.generation);
    const check=async()=>{
     if(!active)throw stale('Graph maintenance lease expired');
     signal?.throwIfAborted();
     await current({ownerKey,durableGeneration},client);
     signal?.throwIfAborted();
     if(!active)throw stale('Graph maintenance lease expired');
    };
    await check();
    const result=await work(Object.freeze({ownerKey,durableGeneration,check}));
    await check();
    return result;
   }finally{active=false;await unlock(client,ownerKey);}
  },
  async invalidate({ownerKey,signal}){
    // Bump first so a remote model cannot begin its next mutation. Wait for the
    // active holder to drain before the reset clears workshop state.
    signal?.throwIfAborted();
   const invalidated=(await pool.query(`INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,1)
     ON CONFLICT(owner_key) DO UPDATE SET generation=graph_runtime.owners.generation+1,updated_at=clock_timestamp()
     RETURNING generation`,[ownerKey])).rows[0];
   if(!invalidated||invalidated.generation==null)throw stale('Graph reset generation is unavailable');
   const durableGeneration=String(invalidated.generation);
    signal?.throwIfAborted();
   let client,acquireStarted=false;
   const assertClientCurrent=async candidate=>{
    if(!candidate||candidate.graphLeaseError)throw stale('Graph reset lease connection was lost');
    try{
     const result=await candidate.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey]);
     if(candidate.graphLeaseError)throw stale('Graph reset lease connection was lost');
     const row=result.rows[0];
     if(!row||String(row.generation)!==durableGeneration)throw stale('Graph reset authority was superseded');
    }catch(error){
     if(error?.name==='AbortError')throw error;
     const failure=stale('Graph reset lease current check failed');failure.cause=error;throw failure;
    }
   };
   return Object.freeze({durableGeneration,
    acquire:async()=>{
     if(acquireStarted)throw stale('Graph reset lease was already acquired');
     acquireStarted=true;
     const candidate=await lock(ownerKey,signal,'lifecycle');
     try{await assertClientCurrent(candidate);await settleOrphans(candidate,ownerKey);await assertClientCurrent(candidate);client=candidate;}
     catch(error){await unlock(candidate,ownerKey);throw error;}
    },
    assertCurrent:async()=>assertClientCurrent(client),
    release:async()=>{if(client){const acquired=client;client=null;await unlock(acquired,ownerKey);}},
   });
  },
  async effect(context,key,execute){
   const client=clients.get(context.runId);await current(context,client);
   const claimed=await client.query("INSERT INTO graph_runtime.effects(owner_key,generation,effect_key,run_id,status) VALUES($1,$2,$3,$4,'started') ON CONFLICT DO NOTHING RETURNING effect_key",[context.ownerKey,context.durableGeneration,key,context.runId]);
   if(!claimed.rowCount){const error=new Error('Effect already attempted; automatic replay is forbidden');error.code='GRAPH_EFFECT_REPLAY_BLOCKED';throw error;}
   try{await current(context,client);const result=await require('./effectAdmissionContext').withEffectAdmission(context,key,execute);await client.query("UPDATE graph_runtime.effects SET status='completed',updated_at=clock_timestamp() WHERE owner_key=$1 AND generation=$2 AND effect_key=$3",[context.ownerKey,context.durableGeneration,key]);return result;}
   catch(error){await client.query("UPDATE graph_runtime.effects SET status='uncertain',updated_at=clock_timestamp() WHERE owner_key=$1 AND generation=$2 AND effect_key=$3",[context.ownerKey,context.durableGeneration,key]);throw error;}
  },
  async readCompletedEffect(context,key){
   const client=clients.get(context.runId);await current(context,client);
   const row=(await client.query(`SELECT owner_key AS "ownerKey",generation::text AS generation,
     effect_key AS "effectKey",run_id AS "runId",status
     FROM graph_runtime.effects
     WHERE owner_key=$1 AND generation=$2 AND effect_key=$3 AND run_id=$4 AND status='completed'`,
   [context.ownerKey,context.durableGeneration,key,context.runId])).rows[0];
   return row?Object.freeze(row):null;
  },
 };
}
let sharedLeasePool;
function configuredRunLedger({family}={}){
 if(process.env.PLATFORM_DATABASE_ENGINE!=='postgres')return undefined;
 if(!sharedLeasePool)sharedLeasePool=require('../database/postgres').createPool(process.env,'IDENTITY_DATABASE_URL',{purpose:'lease'});
 const scopeAuthority=family==='XSS'
  ?require('../database/postgres/xssScopeAuthorityRepository').createXssScopeAuthorityRepository():undefined;
 return createPostgresRunLedger(require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().pool,
  {leasePool:sharedLeasePool,scopeAuthority});
}
module.exports={createPostgresRunLedger,configuredRunLedger};
