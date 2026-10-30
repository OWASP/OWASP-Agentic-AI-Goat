'use strict';
const fail=code=>Object.assign(Error(code),{code});
// Entire cluster remains counted. Only transaction analysis is scoped to owned databases.
const ACTIVITY_SQL=`WITH activity AS MATERIALIZED (SELECT * FROM pg_stat_activity), stamp AS MATERIALIZED (SELECT clock_timestamp() now FROM activity LIMIT 1)
SELECT (SELECT count(*)::int FROM activity) total,(SELECT count(*)::int FROM activity WHERE backend_type='client backend') client_count,pg_backend_pid() self_pid,
(SELECT (extract(epoch FROM backend_start)*1000000)::bigint::text FROM activity WHERE pid=pg_backend_pid()) self_start,
(extract(epoch FROM stamp.now)*1000000)::bigint::text observed_us,
coalesce((SELECT json_agg(row_to_json(r)) FROM (SELECT pid,datname database,usename role,state,
(extract(epoch FROM backend_start)*1000000)::bigint::text backend_start,
(extract(epoch FROM xact_start)*1000000)::bigint::text xact_start,
(extract(epoch FROM state_change)*1000000)::bigint::text state_change,
(extract(epoch FROM (stamp.now-xact_start))*1000)::text transaction_age_ms,
(extract(epoch FROM (stamp.now-state_change))*1000)::text state_age_ms
FROM activity WHERE backend_type='client backend' ORDER BY pid LIMIT 97) r),'[]'::json) clients FROM stamp`;
function createTransactionObserver(pairs){
 const allowed=new Set(pairs.map(x=>JSON.stringify(x))),databases=new Set(pairs.map(x=>x[0]));let previous=new Map(),samples=0,peak=0;
 const micros=x=>{if(typeof x!=='string'||!/^\d{1,20}$/.test(x))throw metadataFailure('MICROSECOND_FORMAT');return BigInt(x);};
 function inspect(s){
  if(++samples>1000)throw fail('SAMPLE_LIMIT');
  if(!s||!Number.isInteger(s.total)||s.total<1)throw metadataFailure('TOTAL_SHAPE');
  if(s.total>=96)throw fail('PG_TOTAL_LIMIT');peak=Math.max(peak,s.total);
  if(!Array.isArray(s.clients)||!Number.isInteger(s.client_count)||s.clients.length!==s.client_count||s.clients.length>s.total||s.clients.length>95)throw metadataFailure('CLIENT_COUNTS');
  const now=micros(s.observed_us),selfStart=micros(s.self_start);if(!Number.isInteger(s.self_pid)||selfStart>now)throw metadataFailure('OBSERVER_IDENTITY');
  const next=new Map(),seen=new Set(),rows=[];let selfSeen=false;
  for(const r of s.clients){
   if(!Number.isInteger(r.pid)||r.pid<=0||seen.has(r.pid))throw metadataFailure('CLIENT_PID');seen.add(r.pid);
   if(r.pid===s.self_pid){if(r.backend_start!==s.self_start)throw metadataFailure('OBSERVER_START');selfSeen=true;continue;}
   if(!databases.has(r.database))continue;
   if(!allowed.has(JSON.stringify([r.database,r.role]))||!['active','idle','idle in transaction','idle in transaction (aborted)','fastpath function call','disabled'].includes(r.state)||r.state==='disabled')throw metadataFailure('ROLE_OR_STATE');
   const birth=micros(r.backend_start),changed=micros(r.state_change);if(birth>changed||changed>now)throw metadataFailure('CLIENT_TIMELINE');
   if(r.state_age_ms===null||!Number.isFinite(Number(r.state_age_ms))||Number(r.state_age_ms)<0)throw metadataFailure('STATE_AGE');
   const idle=r.state.startsWith('idle in transaction');
   if(r.xact_start===null){if(idle||r.transaction_age_ms!==null)throw metadataFailure('TRANSACTION_NULLABILITY');continue;}
   const start=micros(r.xact_start);if(start<birth||start>now)throw metadataFailure('TRANSACTION_TIMELINE');
   const age=Number(r.transaction_age_ms),stateAge=Number(r.state_age_ms);if(r.transaction_age_ms===null||r.state_age_ms===null||!Number.isFinite(age)||!Number.isFinite(stateAge)||age<0||stateAge<0)throw metadataFailure('TRANSACTION_AGE');
   if(idle&&stateAge>=30000)throw Object.assign(fail('PG_IDLE_AGE_LIMIT'),{observation:{total:s.total,pid:r.pid,backendStart:r.backend_start,transactionStart:r.xact_start,stateChange:r.state_change,idleAgeMs:stateAge}});
   const key=JSON.stringify([r.pid,r.backend_start,r.xact_start]),prior=previous.get(key),episode=idle?r.state_change:null;
   const row={pid:r.pid,backendStart:r.backend_start,transactionStart:r.xact_start,stateChange:r.state_change,state:r.state,transactionAgeMs:age,idleAgeMs:idle?stateAge:null,observations:(prior?.observations||0)+1,idleObservations:idle?(prior?.episode===episode?prior.idleObservations+1:1):0,episode};next.set(key,row);rows.push(row);
  }
  if(!selfSeen)throw metadataFailure('OBSERVER_MISSING');previous=next;return{version:2,samples,peak,total:s.total,openTransactions:rows.length,transactions:rows};
 }
 return{inspect};
}
function validateObserverUrl(value,identityUrl){
 let u,identity;try{u=new URL(value);identity=new URL(identityUrl);}catch{throw fail('PG_OBSERVER_TARGET_INVALID');}
 if(u.protocol!=='postgresql:'||u.hostname!=='127.0.0.1'||!u.port||u.host!==identity.host||u.username!=='ownership_test_admin'||u.pathname!=='/postgres'||u.search||u.hash||u.password)throw fail('PG_OBSERVER_TARGET_INVALID');return value;
}
async function drainTransactions({release,join,sample,queues,now=()=>performance.now(),wallNow=()=>Date.now(),sleep=ms=>new Promise(r=>setTimeout(r,ms)),timeoutMs=30000}){
 const end=now()+timeoutMs;let first=null;
 const check=()=>{if(now()>=end)throw fail('PG_DRAIN_DEADLINE');};
 async function bounded(work){check();let timer;try{const value=await Promise.race([work(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('PG_DRAIN_DEADLINE')),Math.max(1,end-now()));})]);check();return value;}finally{clearTimeout(timer);}}
 function metric(){const x=queues();if(!x||!Number.isInteger(x.pid)||!Number.isInteger(x.sequence)||!Number.isFinite(x.sampledAt)||typeof x.empty!=='boolean')throw metadataFailure('QUEUE_METRIC');return x;}
 await bounded(release);await bounded(join);
 while(true){check();const before=metric();const row=await bounded(sample),queryFinished=wallNow();let after;
  do{await bounded(()=>sleep(20));after=metric();}while(after.pid===before.pid&&(after.sequence<=before.sequence||after.sampledAt<=queryFinished));
  if(after.pid!==before.pid)throw metadataFailure('QUEUE_PROCESS_CHANGED');
  if(before.empty&&after.empty&&row.openTransactions===0){if(first!==null&&now()-first.at>=1000&&after.sequence>first.sequence&&after.pid===first.pid)return{snapshots:2,finalSequence:after.sequence};first??={at:now(),sequence:after.sequence,pid:after.pid};}else first=null;
  await bounded(()=>sleep(Math.min(1000,end-now())));
 }
}
module.exports={ACTIVITY_SQL,createTransactionObserver,drainTransactions,validateObserverUrl};
async function qualifyIdleTimeout({client,observe,inspect,timeoutMs=35000,now=()=>performance.now()}){
 const end=now()+timeoutMs;async function within(work){if(now()>=end)throw fail('PG_LEAK_PROBE_TIMEOUT');let t;try{const value=await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{t=setTimeout(()=>reject(fail('PG_LEAK_PROBE_TIMEOUT')),Math.max(1,end-now()));})]);if(now()>=end)throw fail('PG_LEAK_PROBE_TIMEOUT');return value;}finally{clearTimeout(t);}}
 let timer,settle;const ended=new Promise(resolve=>settle=resolve);const onError=e=>settle(e);client.on('error',onError);
 try{await within(()=>client.connect());const identity=(await within(()=>client.query("SELECT pg_backend_pid() pid,(extract(epoch FROM backend_start)*1000000)::bigint::text backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()"))).rows[0];
  if(!identity||!Number.isInteger(identity.pid)||typeof identity.backend_start!=='string')throw metadataFailure('PROBE_IDENTITY');
  await within(()=>client.query('BEGIN'));const raw=await within(observe);await within(()=>inspect(raw));const row=raw.clients.find(r=>r.pid===identity.pid&&r.backend_start===identity.backend_start);if(!row||row.state!=='idle in transaction'||row.xact_start===null)throw fail('PG_LEAK_PROBE_NOT_OBSERVED');
  const error=await within(()=>ended);if(error?.code!=='25P03')throw fail('PG_LEAK_PROBE_TERMINATION_UNPROVEN');
  return{pid:identity.pid,backendStart:identity.backend_start,observedOpenTransaction:true,terminationCode:'25P03',configuredIdleTimeoutMs:30000};
 }finally{clearTimeout(timer);let closeTimer;try{await Promise.race([client.end(),new Promise((_,reject)=>{closeTimer=setTimeout(()=>reject(fail('PG_LEAK_PROBE_CLOSE_TIMEOUT')),2000);})]);}finally{clearTimeout(closeTimer);client.off('error',onError);}}
}
module.exports.qualifyIdleTimeout=qualifyIdleTimeout;

const METADATA_PREDICATES=Object.freeze(['MICROSECOND_FORMAT', 'TOTAL_SHAPE', 'CLIENT_COUNTS', 'OBSERVER_IDENTITY', 'CLIENT_PID', 'OBSERVER_START', 'ROLE_OR_STATE', 'CLIENT_TIMELINE', 'STATE_AGE', 'TRANSACTION_NULLABILITY', 'TRANSACTION_TIMELINE', 'TRANSACTION_AGE', 'OBSERVER_MISSING', 'QUEUE_METRIC', 'QUEUE_PROCESS_CHANGED', 'PROBE_IDENTITY']);
function metadataFailure(predicate){return Object.assign(fail('PG_METADATA_INVALID'),{predicate});}
function metadataDiagnostic(error){return error?.code==='PG_METADATA_INVALID'&&METADATA_PREDICATES.includes(error?.predicate)?{code:'PG_METADATA_INVALID',predicate:error.predicate}:null;}
function authorizedCapacityPairs(manifest,environment){
 const pairs=manifest.flatMap(row=>[row.runtimeVariable,row.migrationVariable].map(key=>{const u=new URL(environment[key]);return[decodeURIComponent(u.pathname.slice(1)),decodeURIComponent(u.username)];}));
 if(environment.CTF_DELIVERY_DATABASE_URL!==undefined){
  let delivery,ctf,identity;try{delivery=new URL(environment.CTF_DELIVERY_DATABASE_URL);ctf=new URL(environment.CTF_DATABASE_URL);identity=new URL(environment.IDENTITY_DATABASE_URL);}catch{throw fail('PG_DELIVERY_TARGET_INVALID');}
  if(ctf.protocol!=='postgresql:'||identity.protocol!=='postgresql:'||decodeURIComponent(ctf.username)!=='dvaia_ctf_runtime'||decodeURIComponent(identity.username)!=='dvaia_identity_runtime'||identity.pathname!=='/owasp_ai_goat_identity'||ctf.search||ctf.hash||identity.search||identity.hash||delivery.protocol!=='postgresql:'||delivery.hostname!=='127.0.0.1'||!delivery.port||delivery.host!==identity.host||delivery.host!==ctf.host||delivery.pathname!==ctf.pathname||delivery.pathname!=='/owasp_ai_goat_ctf'||decodeURIComponent(delivery.username)!=='dvaia_ctf_delivery'||!delivery.password||delivery.search||delivery.hash)throw fail('PG_DELIVERY_TARGET_INVALID');
  pairs.push(['owasp_ai_goat_ctf','dvaia_ctf_delivery']);
 }
 return pairs;
}
module.exports.authorizedCapacityPairs=authorizedCapacityPairs;
module.exports.metadataDiagnostic=metadataDiagnostic;
