'use strict';
const {poolConfig}=require('../../server/database/postgres');
const fail=code=>Object.assign(new Error(code),{code});
const IDENTITY_SQL=`SELECT pid,backend_start::text AS backend_start,datid::text AS database_oid,usesysid::text AS role_oid FROM pg_stat_activity WHERE pid=pg_backend_pid()`;
const BLOCKED_SQL=`SELECT a.pid,a.backend_start::text AS backend_start,a.datid::text AS database_oid,a.usesysid::text AS role_oid
FROM pg_stat_activity a WHERE a.pid<>$1 AND a.datid=$3::oid AND a.usesysid=$4::oid
AND a.state='active' AND a.wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(a.pid))
AND EXISTS(SELECT 1 FROM pg_stat_activity h WHERE h.pid=$1 AND h.backend_start::text=$2 AND h.datid=$3::oid AND h.usesysid=$4::oid)
AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory' AND l.granted AND l.objsubid=1
AND l.classid::bigint=((hashtextextended($5,0)>>32)&4294967295) AND l.objid::bigint=(hashtextextended($5,0)&4294967295))`;
async function acquireLifecycleBarrier({environment,runId,ownerKey,observeQuery,signal,Client=require('pg').Client,setTimer=setTimeout,clearTimer=clearTimeout}={}){
 if(typeof runId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(runId)||typeof ownerKey!=='string'||ownerKey.length>512||typeof observeQuery!=='function')throw fail('LIFECYCLE_BARRIER_ARGUMENTS');
 let parsed;try{parsed=JSON.parse(ownerKey);}catch{}if(!Array.isArray(parsed)||parsed.length!==2||parsed[0]!=='ARIA'||typeof parsed[1]!=='string'||! /^[1-9][0-9]*$/.test(parsed[1])||JSON.stringify(parsed)!==ownerKey)throw fail('LIFECYCLE_BARRIER_ARGUMENTS');
 signal?.throwIfAborted();
 const client=new Client({...poolConfig(environment,'IDENTITY_DATABASE_URL'),application_name:'owasp-ai-goat-capacity-lifecycle-barrier',connectionTimeoutMillis:2000,query_timeout:2000});
 let transaction=false,released=false,releasePromise,timer,invalid=null,identity;
 const onError=()=>{invalid??=fail('LIFECYCLE_BARRIER_CONNECTION_LOST');};client.on('error',onError);
 async function bounded(work){let t;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{t=setTimeout(()=>reject(fail('LIFECYCLE_BARRIER_CLEANUP_UNKNOWN')),2500);})]);}finally{clearTimeout(t);}}
 function assertValid(){signal?.throwIfAborted();if(invalid)throw invalid;if(released)throw fail('LIFECYCLE_BARRIER_RELEASED');}
 function release(){if(releasePromise)return releasePromise;released=true;clearTimer(timer);releasePromise=(async()=>{const errors=[];if(transaction)try{await bounded(()=>client.query('ROLLBACK'));}catch(e){errors.push(e);}try{await bounded(()=>client.end());}catch(e){errors.push(e);}if(errors.length){invalid??=fail('LIFECYCLE_BARRIER_CLEANUP_UNKNOWN');throw new AggregateError(errors,'Lifecycle barrier cleanup unknown');}})();return releasePromise;}
 try{
  await client.connect();signal?.throwIfAborted();
  const rows=(await client.query(IDENTITY_SQL)).rows;if(rows.length!==1||!Number.isInteger(rows[0].pid)||rows[0].pid<=0||!rows[0].backend_start||!/^\d+$/.test(rows[0].database_oid)||!/^\d+$/.test(rows[0].role_oid))throw fail('LIFECYCLE_BARRIER_IDENTITY');identity=Object.freeze({...rows[0]});
  await client.query('BEGIN');transaction=true;
  await client.query("SET LOCAL lock_timeout='500ms'; SET LOCAL idle_in_transaction_session_timeout='4000ms'");
  const locked=(await client.query('SELECT run_id,owner_key,status FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2 FOR UPDATE',[runId,ownerKey])).rows;
  if(locked.length!==1||locked[0].run_id!==runId||locked[0].owner_key!==ownerKey||locked[0].status!=='running')throw fail('LIFECYCLE_BARRIER_RUN');
  timer=setTimer(()=>{invalid=fail('LIFECYCLE_BARRIER_WATCHDOG');void release().catch(()=>{});},3000);
  assertValid();
  return Object.freeze({identity,assertValid,async assertBlocked(){assertValid();const rows=(await observeQuery(BLOCKED_SQL,[identity.pid,identity.backend_start,identity.database_oid,identity.role_oid,ownerKey])).rows;assertValid();if(rows.length!==1||!Number.isInteger(rows[0].pid)||rows[0].pid===identity.pid||!rows[0].backend_start||rows[0].database_oid!==identity.database_oid||rows[0].role_oid!==identity.role_oid)throw fail('LIFECYCLE_BARRIER_NOT_BLOCKED');return Object.freeze({...rows[0]});},release,async releaseThenJoin(join){if(typeof join!=='function')throw fail('LIFECYCLE_BARRIER_ARGUMENTS');let cleanup;try{await release();}catch(e){cleanup=e;}try{await bounded(join);}catch(e){if(cleanup)throw new AggregateError([cleanup,e],'Lifecycle barrier settlement failed');throw e;}if(cleanup)throw cleanup;if(invalid)throw invalid;}});
 }catch(error){try{await release();}catch(cleanup){throw new AggregateError([error,cleanup],'Lifecycle barrier acquisition failed');}throw error;}
}
function remainingLifecycleTimeout(deadline,now=performance.now()){
 const remaining=Math.floor(deadline-now);
 if(!Number.isFinite(deadline)||!Number.isFinite(now)||!Number.isSafeInteger(remaining)||remaining<1||remaining>2500)throw fail('LIFECYCLE_OBSERVATION_DEADLINE');
 return remaining;
}
module.exports={acquireLifecycleBarrier,remainingLifecycleTimeout,IDENTITY_SQL,BLOCKED_SQL};
