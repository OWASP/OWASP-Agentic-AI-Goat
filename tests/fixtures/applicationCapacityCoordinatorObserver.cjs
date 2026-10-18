'use strict';
// Fixture-only transform: no production expressions are replaced or reordered.
const {createHash}=require('node:crypto');
const SYMBOL='dvaia.capacity.coordinator.observer';
// Exact source reviewed against the retained capacity cohort before admitting a run.
const REVIEWED_COORDINATOR_SHA256='acf235a04e3d538cd7ea6bf289fa7863b00096c01d06ee81e0861f15808e8c50';
function reviewedCoordinatorSha256(source){
 instrument(source,REVIEWED_COORDINATOR_SHA256);
 return REVIEWED_COORDINATOR_SHA256;
}
const anchors=[
 ['retained[lane]++; owner[field]++;',"retained[lane]++; owner[field]++;\n    try { globalThis[Symbol.for('"+SYMBOL+"')]?.({lane,ownerKey:owner.key,global:retained[lane],owner:owner[field],event:'reserve'}); } catch {}"],
 ['retained[lane]--; owner[field]--;',"retained[lane]--; owner[field]--;\n      try { globalThis[Symbol.for('"+SYMBOL+"')]?.({lane,ownerKey:owner.key,global:retained[lane],owner:owner[field],event:'release'}); } catch {}"],
];
function instrument(source,expectedSha256){
 if(typeof expectedSha256!=='string'||!/^[a-f0-9]{64}$/.test(expectedSha256)||createHash('sha256').update(source).digest('hex')!==expectedSha256)throw Error('Coordinator source identity mismatch');
 for(const [anchor]of anchors)if(source.split(anchor).length!==2)throw Error('Coordinator observation anchor mismatch');
 for(const [anchor,replacement]of anchors)source=source.replace(anchor,replacement);
 return source;
}
function createRecorder(syntheticOwnerIds,{maxSamples=4096}={}){
 if(!Array.isArray(syntheticOwnerIds)||syntheticOwnerIds.length!==200||new Set(syntheticOwnerIds).size!==200||syntheticOwnerIds.some(x=>typeof x!=='string'||!/^[1-9][0-9]{0,9}$/.test(x)||Number(x)>2147483647)||maxSamples!==4096)throw Error('Exact synthetic owner set required');
 const allowed=new Set(syntheticOwnerIds),samples=[],owners=new Map();let invalid=false,total=0;const peak={runs:0,lifecycle:0,ownerRuns:0,ownerLifecycle:0},current={runs:0,lifecycle:0};
 function record(row){try{
  const tuple=JSON.parse(row.ownerKey);if(!Array.isArray(tuple)||tuple.length!==2||!allowed.has(tuple[1])||!['runs','lifecycle'].includes(row.lane)||!['reserve','release'].includes(row.event)||!Number.isSafeInteger(row.global)||row.global<0||!Number.isSafeInteger(row.owner)||row.owner<0)throw Error();
  if(!['ARIA','NOVA','capacity'].includes(tuple[0]))throw Error();const ownerState=owners.get(row.ownerKey)||{runs:0,lifecycle:0};ownerState[row.lane]=row.owner;if(ownerState.runs||ownerState.lifecycle)owners.set(row.ownerKey,ownerState);else owners.delete(row.ownerKey);if(owners.size>400)throw Error();
  total++;current[row.lane]=row.global;peak[row.lane]=Math.max(peak[row.lane],row.global);const key=row.lane==='runs'?'ownerRuns':'ownerLifecycle';peak[key]=Math.max(peak[key],row.owner);
  if(samples.length<maxSamples)samples.push({lane:row.lane,event:row.event,global:row.global,owner:row.owner});else invalid=true;
 }catch{invalid=true;}}
 return{record,snapshot:()=>({valid:!invalid,total,peak:{...peak},current:{...current},owners:[...owners].map(([ownerKey,value])=>({ownerKey,...value})),samples:samples.map(x=>({...x}))}),invalidate:()=>{invalid=true;}};
}
module.exports={instrument,createRecorder,SYMBOL,reviewedCoordinatorSha256};

function observeLeaseAdmission(value,ownerIds){let sequence=0,valid=true;const entries=new Map();
 const wrapped={acquire(owner,signal,kind='run'){let admitted;try{admitted=JSON.parse(owner);}catch{}let tracked=Array.isArray(admitted)&&['ARIA','NOVA'].includes(admitted[0])&&ownerIds.has(String(admitted[1]));const id=++sequence;if(tracked&&entries.size>=1280){valid=false;tracked=false;}if(tracked)entries.set(id,{ownerKey:owner,kind,state:'queued'});let pending;try{pending=value.acquire(owner,signal,kind);}catch(error){entries.delete(id);throw error;}return pending.then(release=>{if(tracked)entries.get(id).state='active';return()=>{release();entries.delete(id);};},error=>{entries.delete(id);throw error;});},snapshot:()=>({...value.snapshot(),valid,owners:[...entries.values()].map(e=>({...e}))})};return wrapped;}
module.exports.observeLeaseAdmission=observeLeaseAdmission;

// Select only from a complete held snapshot; arrival order is not admission order.
function selectInvalidationCohorts(users,observations){
 if(!Array.isArray(users)||users.length!==200||!Array.isArray(observations)||observations.length!==200)throw Error('Complete held owner snapshot required');
 const byKey=new Map(users.map(u=>[JSON.stringify([u.index<100?'ARIA':'NOVA',String(u.id)]),u]));
 if(byKey.size!==200)throw Error('Unique workload owners required');
 const seen=new Set(),active=[],queued=[];
 for(const row of observations){if(row.kind!=='run'||!byKey.has(row.ownerKey)||seen.has(row.ownerKey)||!['active','queued'].includes(row.state))throw Error('Invalid held owner snapshot');seen.add(row.ownerKey);(row.state==='active'?active:queued).push(byKey.get(row.ownerKey));}
 if(active.length!==4||queued.length!==196)throw Error('Exact held admission required');
 active.sort((a,b)=>a.index-b.index);queued.sort((a,b)=>a.index-b.index);
 // All three invalidation kinds include actual active AND queued work.
 const cancel=[active[0],active[3],...queued.slice(0,38)],revoke=[active[1],...queued.slice(38,57)],reset=[active[2],...queued.slice(57,76)],siblings=queued.slice(76);
 return {cancel,revoke,reset,siblings,ordered:[...cancel,...revoke,...reset,...siblings]};
}
module.exports.selectInvalidationCohorts=selectInvalidationCohorts;

function physicalSampleFailure(error,rows,sample,phase,elapsedMs){
 const safeCode=typeof error?.code==='string'&&/^[A-Z0-9_]{1,40}$/.test(error.code)?error.code:null;
 return {sample,phase,elapsedMs,reason:['SAMPLE_LIMIT','PG_TOTAL_LIMIT','PG_IDLE_TRANSACTION','PG_IDLE_AGE_LIMIT','PG_METADATA_INVALID','PG_DRAIN_DEADLINE'].includes(safeCode)?safeCode:'PG_QUERY_FAILURE',code:safeCode,name:['Error','AbortError','TimeoutError'].includes(error?.name)?error.name:'Error',snapshot:Array.isArray(rows)?{total:rows.reduce((n,r)=>n+r.total,0),idleTransactions:rows.reduce((n,r)=>n+r.transactions,0)}:null};
}
function assertResetOutcomes(rows){
 if(!Array.isArray(rows)||rows.length!==4||rows.some(r=>r?.error||![200,409].includes(r?.status)))throw Error('Lifecycle reset outcome was not successful or superseded');
}
module.exports.physicalSampleFailure=physicalSampleFailure;
module.exports.assertResetOutcomes=assertResetOutcomes;

async function settlePhysicalSampler(timer,pending,save){
 clearInterval(timer);
 try{await pending;}finally{save();}
}
module.exports.settlePhysicalSampler=settlePhysicalSampler;
