'use strict';
const {performance}=require('node:perf_hooks');
const {APPLICATION_MAINTENANCE_KEY}=require('../../server/services/applicationMaintenanceLease');
const SQL=`SELECT pid FROM pg_locks WHERE locktype='advisory'
 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND classid=$1::oid AND objid=$2::oid AND objsubid=2 AND granted ORDER BY pid`;
// Process exit is not acknowledgement that PostgreSQL has processed socket EOF.
// Observe release only: never terminate a backend, unlock, or retry admission.
async function waitForOwnedLeaseRelease({client,assertExited,onObservation=()=>{},timeoutMs=5000,now=()=>performance.now(),sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}){
 if(!client||typeof assertExited!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>5000)throw TypeError('Invalid lease observation options');
 const started=now();let probes=0;
 for(;;){
  assertExited();
  const remaining=timeoutMs-(now()-started);
  if(remaining<=0)throw Object.assign(Error('Owned PostgreSQL lease release deadline'),{code:'OWNED_LEASE_RELEASE_TIMEOUT'});
  const result=await client.query({text:SQL,values:[...APPLICATION_MAINTENANCE_KEY],query_timeout:Math.max(1,Math.min(1000,Math.ceil(remaining)))});
  const pids=result.rows.map(row=>row.pid);
  if(pids.length>16||pids.some(pid=>!Number.isInteger(pid)||pid<=0))throw Error('Invalid lease observation');
  const observation={probes:++probes,elapsedMs:Math.ceil(now()-started),backendPids:pids,released:pids.length===0};onObservation(observation);
  if(!pids.length)return observation;
  await sleep(Math.min(25,Math.max(0,timeoutMs-(now()-started))));
 }
}
module.exports={waitForOwnedLeaseRelease};
