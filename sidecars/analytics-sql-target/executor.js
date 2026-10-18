'use strict';
const {collectQuery}=require('./bounded-query');
const {withTargetPool}=require('./admission');
const {databaseName,fail}=require('./contract');
const {DatabaseError}=require('pg');
// Caller holds the durable target lease and global admission throughout this
// operation, including server-side termination and proof of backend absence.
function createExecutor({controlPool,createPool,verifyTarget,connection}){
 if(typeof controlPool?.query!=='function'||typeof createPool!=='function'||typeof verifyTarget!=='function'||!connection)throw TypeError('Private Analytics executor dependencies required');
 return async function execute(target,password,sql,{signal,captureProtected=false,captureQueryError=false,loginRole,values=[]}={}){
  if(typeof captureQueryError!=='boolean'||captureQueryError&&(captureProtected||loginRole))throw fail('ANALYTICS_QUERY_PARAMETERS');
  const database=databaseName(target.targetId),user=loginRole||database;
  if(user!==database&&user!==database+'_metrics')throw fail('ANALYTICS_TARGET_INVALID');
  let querySignal;
  const output=await withTargetPool(createPool,{...connection,database,user,password},async pool=>{
   const client=await pool.connect();let identity,finished=false,timer,queryStarted=false,denied=false,capturedError=false;
   const abort=new AbortController();const clientError=error=>abort.abort(error);client.on('error',clientError);const onAbort=()=>abort.abort(signal.reason||fail('ANALYTICS_QUERY_ABORTED'));
   querySignal=abort.signal;
   signal?.addEventListener('abort',onAbort,{once:true});
   try{
    signal?.throwIfAborted();await verifyTarget(client,database,user);
    if(loginRole){const grant=(await client.query("SELECT has_any_column_privilege(current_user,'public.shop_users','SELECT') AS protected_read,has_table_privilege(current_user,'public.products','SELECT') AND has_table_privilege(current_user,'public.orders','SELECT') AND has_table_privilege(current_user,'public.order_items','SELECT') AS metrics_read,has_schema_privilege(current_user,'public','CREATE') AS schema_write,EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)) AS memberships,(SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user) AS powerful")).rows[0];if(!grant||grant.protected_read||!grant.metrics_read||grant.schema_write||grant.memberships||grant.powerful)throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');}
    identity=(await client.query("SELECT pg_backend_pid() AS pid,backend_start::text FROM pg_stat_activity WHERE pid=pg_backend_pid()")).rows[0];
    if(!Number.isInteger(identity?.pid)||typeof identity.backend_start!=='string')throw fail('ANALYTICS_BACKEND_UNVERIFIED');
    await client.query('BEGIN READ ONLY');
    await client.query("SET LOCAL statement_timeout='1500ms'");
    await client.query("SET LOCAL lock_timeout='500ms'");
    timer=setTimeout(()=>abort.abort(fail('ANALYTICS_QUERY_DEADLINE')),2000);
    let protectedEvidence,origin;
    if(captureProtected){const row=(await client.query("SELECT a.attrelid::oid AS table_id,a.attnum::integer AS column_id FROM pg_attribute a WHERE a.attrelid='public.shop_users'::regclass AND a.attname='api_key' AND a.attnum>0 AND NOT a.attisdropped")).rows[0];origin={tableId:row?.table_id,columnId:row?.column_id};}
    let result;
    try{
     queryStarted=true;result=await collectQuery(client,sql,{signal:abort.signal,values,...(captureProtected?{onFields:(fields,rows)=>{protectedEvidence=require('./protected-columns').protectedColumns({fields,rows,origin});}}:{})});
    }catch(error){
     // Only this admitted statement can supply a teaching error. Preflight,
     // transport, cancellation, rollback and cleanup failures stay unavailable.
     if(!captureQueryError||abort.signal.aborted||!(error instanceof DatabaseError)||error.code!=='22P02'
      ||typeof error.message!=='string'||!error.message||!error.message.isWellFormed()
      ||error.message.includes('\0')||Buffer.byteLength(error.message)>8192)throw error;
     result={queryError:{sqlstate:'22P02',message:error.message}};capturedError=true;
    }
    if(captureQueryError)abort.signal.throwIfAborted();
    await client.query('ROLLBACK');finished=true;return captureProtected?{result,protectedEvidence}:result;
   }catch(error){
    if(queryStarted&&loginRole&&error.code==='42501'){await client.query('ROLLBACK');finished=true;denied=true;return {result:{sql,columns:[],rows:[],row_count:0,error:'Database permission denied (42501).'},protectedEvidence:{version:1,observations:[],truncated:false},denial:{code:'42501',source:'postgresql',backendAbsent:true}};}
    throw error;
   }finally{
    clearTimeout(timer);signal?.removeEventListener('abort',onAbort);
    try{if(!finished&&identity){
     // PID reuse is fenced by backend_start plus exact target DB and login.
     await controlPool.query({text:'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2::timestamptz AND datname=$3 AND usename=$4',values:[identity.pid,identity.backend_start,database,user],query_timeout:1000});
    }
    }catch(error){throw Object.assign(fail('ANALYTICS_QUERY_DRAIN_UNCERTAIN'),{cause:error});}finally{client.release(true);}
    if((!finished||denied||capturedError)&&identity){
     try{let remaining=true;const deadline=Date.now()+1500;
     do{
      remaining=(await controlPool.query({text:'SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2::timestamptz AND datname=$3 AND usename=$4',values:[identity.pid,identity.backend_start,database,user],query_timeout:1000})).rows.length>0;
      if(remaining)await new Promise(resolve=>setTimeout(resolve,25));
     }while(remaining&&Date.now()<deadline);
     if(remaining)throw fail('ANALYTICS_QUERY_DRAIN_UNCERTAIN');
     }catch(error){throw Object.assign(fail('ANALYTICS_QUERY_DRAIN_UNCERTAIN'),{cause:error});}
    }
   }
  });
  // A captured database error is not publishable until both backend and pool
  // cleanup have completed and no cancellation/connection error won the race.
  if(captureQueryError){signal?.throwIfAborted();querySignal?.throwIfAborted();}
  return output;
 };
}
module.exports={createExecutor};
