'use strict';
const VERSION = 'secureshop-owned-system-metrics.v1';
const KEYS = Object.freeze(['version','ok','hostname','platform','node','uptime_s','loadavg','freemem_mb','totalmem_mb','ts','metricsSource','memorySource','uptimeSource','loadSource']);
const fail = () => { throw Object.assign(new Error('Invalid owned System health metrics'), { code:'SYSTEM_HEALTH_INVALID' }); };
const text = value => { if(typeof value!=='string'||!value||value.length>255||/[\u0000-\u001f\u007f]/.test(value))fail();return value; };
const integer = value => { if(!Number.isSafeInteger(value)||value<0)fail();return value; };
function validateOwnedSystemMetrics(raw){
  if(!raw||typeof raw!=='object'||Array.isArray(raw))fail();
  const sorted=KEYS.slice().sort(), keys=Object.keys(raw).sort(); if(keys.length!==sorted.length||keys.some((x,i)=>x!==sorted[i]))fail();
  if(raw.version!==VERSION||raw.ok!==true||raw.loadavg!==null)fail();
  if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(raw.ts))fail();
  try{if(new Date(raw.ts).toISOString()!==raw.ts)fail();}catch{fail();}
  const result=Object.freeze({version:raw.version,ok:true,hostname:text(raw.hostname),platform:text(raw.platform),node:text(raw.node),uptime_s:integer(raw.uptime_s),loadavg:null,
    freemem_mb:raw.freemem_mb===null?null:integer(raw.freemem_mb),totalmem_mb:raw.totalmem_mb===null?null:integer(raw.totalmem_mb),ts:raw.ts,
    metricsSource:text(raw.metricsSource),memorySource:text(raw.memorySource),uptimeSource:text(raw.uptimeSource),loadSource:text(raw.loadSource)});
  if(result.metricsSource!=='owned-system-listener'||!['cgroup-v2','unavailable'].includes(result.memorySource)||result.uptimeSource!=='listener-process'||result.loadSource!=='unavailable')fail();
  if((result.freemem_mb===null)!==(result.totalmem_mb===null)||(result.freemem_mb!==null&&result.freemem_mb>result.totalmem_mb))fail();
  if(result.memorySource==='cgroup-v2'&&result.totalmem_mb===null)fail(); if(result.memorySource==='unavailable'&&result.totalmem_mb!==null)fail();
  return result;
}
module.exports={HEALTH_METRICS_VERSION:VERSION,validateOwnedSystemMetrics};
