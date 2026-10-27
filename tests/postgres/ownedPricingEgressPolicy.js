'use strict';
// Closed Pricing allocation, not a caller-selectable relay limit. The retained
// 9f7509ca census was 35 build + 1 runtime Debian objects (50,198,128 bytes).
// 68 is an imposed ceiling: existing 32 overhead admissions + at most 36
// authenticated artifact requests. It is not a prediction of Docker retries.
const closure=require('./ownedMcpDependencyClosure');
const VERSION='pricing-original-deb-36-v1';
const RELAY_SHA='2f1ac0b8bace7bbd97001d3c5bea836c0b3906d05f6156d458aee465431bf102';
const LIMITS=Object.freeze({connections:68,overheadConnections:32,artifacts:36});
const fail=code=>Object.assign(new Error(code),{code});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
const count=n=>Number.isSafeInteger(n)&&n>=0;
function once(source,before,after){if(typeof source!=='string'||source.split(before).length!==2)throw fail('PRICING_EGRESS_ANCHOR');return source.replace(before,after);}
function deriveChild(source){
 // Called only by the exact-source Pricing bounded derivation. Keep all other
 // byte/concurrency/host/TLS/DNS/deadline policies byte-for-byte unchanged.
 let result=once(source,"if self.connections>=32: raise Denied('connections')","if self.connections>=68: raise Denied('connections')");
 result=once(result,'self.connections+=1',"self.connections+=1; globals()['PRICING_ADMITTED_CONNECTIONS']=self.connections");
 return once(result,'activeWorkers=threading.active_count()-1,',
  `activeWorkers=threading.active_count()-1,pricingBudget=dict(version=1,policy='${VERSION}',sourceSha256='${RELAY_SHA}',limit=68,connections=globals().get('PRICING_ADMITTED_CONNECTIONS',0)),`);
}
function validateOverheadCheckpoint(packet,{runId}={}){
 const bad=()=>{throw fail('PRICING_EGRESS_OVERHEAD');};
 if(!/^[a-f0-9]{32}$/.test(runId||'')||!exact(packet,'version,runId,variant,rows')||packet.version!==1||packet.runId!==runId||packet.variant!=='metadata-idle-barrier-v4'||!exact(packet.rows,'adapter,connector'))bad();
 const counts={};
 for(const mode of ['adapter','connector']){
  const row=packet.rows[mode],b=row?.pricingBudget;
  if(!exact(row,'kind,variant,runId,mode,sequence,trigger,counts,activeWorkers,deniedAuthorities,admission,pricingBudget')||row.kind!=='transport-audit'||row.variant!==packet.variant||row.runId!==runId||row.mode!==mode||row.trigger!=='checkpoint'||!count(row.sequence)||row.sequence<1||row.activeWorkers!==0
   ||!exact(b,'version,policy,sourceSha256,limit,connections')||b.version!==1||b.policy!==VERSION||b.sourceSha256!==RELAY_SHA||b.limit!==LIMITS.connections||!count(b.connections)||b.connections>LIMITS.overheadConnections)bad();
  if(!exact(row.counts,'dnsSubprocesses,externalConnectAttempts,unixConnectAttempts,peerChecks,peerDenied')||!Object.values(row.counts).every(count)||row.counts.peerDenied!==0
   ||!exact(row.admission,'workerLimitRejected,connectionLimitRejected,saturated')||!count(row.admission.workerLimitRejected)||row.admission.connectionLimitRejected!==0||row.admission.saturated!==false
   ||!exact(row.deniedAuthorities,'hosts,unclassified,overflow')||!row.deniedAuthorities.hosts||typeof row.deniedAuthorities.hosts!=='object'||Array.isArray(row.deniedAuthorities.hosts)||!Object.values(row.deniedAuthorities.hosts).every(count)||!count(row.deniedAuthorities.unclassified)||!count(row.deniedAuthorities.overflow))bad();
  if(row.counts.peerChecks>b.connections||row.counts.externalConnectAttempts>b.connections||row.counts.unixConnectAttempts>b.connections||row.counts.dnsSubprocesses>b.connections)bad();
  counts[mode]=b.connections;
 }
 return Object.freeze({version:1,policy:VERSION,runId,connections:Object.freeze(counts),artifactCeiling:LIMITS.artifacts});
}
function validatePricingArtifactCensus(artifacts){
 closure._internals.validateArtifacts(artifacts);
 if(artifacts.length>LIMITS.artifacts||artifacts.some(row=>row.kind!=='deb'||row.urls.length!==1||!Array.isArray(row.stages)||!row.stages.length||row.stages.some(s=>!['build','runtime'].includes(s))))throw fail('PRICING_EGRESS_CENSUS');
 return Object.freeze({version:1,policy:VERSION,artifacts:artifacts.length,bytes:artifacts.reduce((n,row)=>n+row.bytes,0),maximumConnections:LIMITS.connections});
}
module.exports={VERSION,RELAY_SHA,LIMITS,validateOverheadCheckpoint,validatePricingArtifactCensus,_internals:{deriveChild}};
