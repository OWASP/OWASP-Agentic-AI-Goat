'use strict';
const{timestamp}=require('../../server/database/postgres/identityValidation');
const COLUMNS=Object.freeze({csrf_workshop_wallets:'user_key balance updated_at',csrf_workshop_progress:'user_key objective_id completed completed_at created_at',csrf_workshop_tool_log:'id user_key exercise_id tool_name args result_summary flag success created_at',csrf_victim_state:'session_key state_json updated_at'});
const TARGETS={csrf_workshop_wallets:'wallets',csrf_workshop_progress:'progress',csrf_workshop_tool_log:'tool_log',csrf_victim_state:'victim_state'};
function reject(code){throw Object.assign(new Error(code),{code});}
function ownerApi(){return require('./archive-owner-binding');}
function ownerContext(raw){
 if(raw.ownerBinding===undefined){
  if(raw.opaqueOwnerResolutions!==undefined)reject('OWNER_RESOLUTIONS_WITHOUT_BINDING');
  return null;
 }
 const binding=ownerApi().normalizeArchiveOwnerBinding(raw.ownerBinding);
 const resolutions=raw.opaqueOwnerResolutions===undefined?[]:raw.opaqueOwnerResolutions;
 let resolutionMap;
 try{resolutionMap=ownerApi().normalizeOpaqueResolutions(resolutions);}catch(error){reject(error.code||'INVALID_OWNER_RESOLUTIONS');}
 return{binding,resolutions,resolutionMap,usedResolutions:new Set()};
}
function mapCsrfArchive(raw){
 if(!raw||Object.keys(raw).some(key=>!['sources','archiveDigest','naiveTimestamps','review','ownerBinding','opaqueOwnerResolutions'].includes(key)))reject('INVALID_CSRF_ARCHIVE');
 const{sources,archiveDigest,naiveTimestamps='reject',review}=raw;
 if(typeof archiveDigest!=='string'||!/^[a-f0-9]{64}$/.test(archiveDigest))reject('ARCHIVE_DIGEST_REQUIRED');
 if(!sources||typeof sources!=='object'||Array.isArray(sources)||Object.keys(sources).some(key=>!['csrf_workshop.db','users_auth.db'].includes(key)))reject('INVALID_CSRF_SOURCES');
 if(!['UTC','reject'].includes(naiveTimestamps))reject('INVALID_TIMESTAMP_POLICY');
 if(!review||Object.keys(review).sort().join(',')!=='archiveDigest,missingVictimState,retainedTables'||review.archiveDigest!==archiveDigest)reject('ARCHIVE_BOUND_CSRF_REVIEW_REQUIRED');
 const owners=ownerContext(raw);
 if(owners&&owners.binding.archiveDigest!==archiveDigest)reject('OWNER_ARCHIVE_MISMATCH');
 const markResolution=value=>{
  if(!owners||typeof value!=='string')return;
  if(owners.resolutionMap.has(value))owners.usedResolutions.add(value);
  if(value.startsWith('csrf_')&&owners.resolutionMap.has(value.slice(5)))owners.usedResolutions.add(value.slice(5));
 };
 const mapKey=value=>{markResolution(value);return owners?ownerApi().mapOwnerKey(value,owners.binding,{allowAnonymous:false,opaqueOwnerResolutions:owners.resolutions}):value;};
 const mapSession=value=>{markResolution(value);return owners?ownerApi().mapDerivedOwnerKey(value,owners.binding,{prefix:'csrf_',opaqueOwnerResolutions:owners.resolutions}):value;};
 const snapshot={wallets:[],progress:[],tool_log:[],victim_state:[]},provenance=[],retained=[];
 for(const[source,envelope]of Object.entries(sources)){
  if(!envelope||!envelope.tables||typeof envelope.tables!=='object'||Array.isArray(envelope.tables))reject('INVALID_CSRF_SOURCE');
  for(const[table,rows]of Object.entries(envelope.tables)){
   if(!Array.isArray(rows))reject('INVALID_CSRF_TABLE');
   if(!Object.hasOwn(COLUMNS,table)||(table==='csrf_victim_state')!==(source==='users_auth.db'))retained.push({source,table,policy:'retain_archive_only'});
  }
 }
 for(const[table,columns]of Object.entries(COLUMNS)){
  const source=table==='csrf_victim_state'?'users_auth.db':'csrf_workshop.db',rows=sources[source]?.tables[table];
  if(rows===undefined){if(table==='csrf_victim_state'&&review.missingVictimState==='absent_source_no_victims_synthesized')continue;reject('MISSING_CSRF_SOURCE_TABLE');}
  if(table==='csrf_victim_state'&&review.missingVictimState!==null)reject('UNEXPECTED_VICTIM_STATE_ACKNOWLEDGMENT');
  const seen=new Set();
  for(const original of rows){
   if(!original||typeof original!=='object'||Array.isArray(original)||Object.keys(original).sort().join(' ')!==columns.split(' ').sort().join(' '))reject('UNMAPPED_CSRF_COLUMNS');
   const row={};
   for(const[column,rawValue]of Object.entries(original)){
    let value=rawValue;
    if(['id','balance','completed','success'].includes(column)&&value!==null){
     if(value&&typeof value==='object'&&Object.keys(value).sort().join(',')==='type,value'&&value.type==='integer'&&typeof value.value==='string'&&/^-?(0|[1-9][0-9]*)$/.test(value.value))value=value.value;
     else if(Number.isSafeInteger(value))value=String(value);else reject('INVALID_CSRF_INTEGER');
     const n=BigInt(value);
     if(column==='balance'){if(n<-(2n**63n)||n>2n**63n-1n)reject('INVALID_CSRF_BALANCE');}
     else{if(n<0n||n>=BigInt(Number.MAX_SAFE_INTEGER))reject('INVALID_CSRF_INTEGER');value=Number(value);if(column==='id'&&value===0)reject('INVALID_CSRF_ID');if(column!=='id'&&![0,1].includes(value))reject('INVALID_CSRF_FLAG');}
    }else if(value!==null&&(typeof value!=='string'||value.includes('\0')))reject('INVALID_CSRF_TEXT');
    if(value===null&&['user_key','session_key','tool_name','objective_id','id','balance','state_json'].includes(column))reject('NULL_CSRF_REQUIRED_VALUE');
    if(['user_key','session_key'].includes(column)&&(!value.length||value.length>200))reject('INVALID_CSRF_OWNER');
    if(column.endsWith('_at')&&value!==null){if(!/(Z|[+-]\d{2}:\d{2})$/.test(value)&&naiveTimestamps!=='UTC')reject('AMBIGUOUS_TIMESTAMP');value=timestamp(value,false);}
    if(column==='state_json'){try{JSON.parse(value);}catch{reject('INVALID_CSRF_VICTIM_JSON');}}
    if(table!=='csrf_victim_state'&&column==='user_key')value=mapKey(value);
    if(table==='csrf_victim_state'&&column==='session_key')value=mapSession(value);
    row[column]=value;
   }
   if(row.objective_id&&!/^csrf_[gpxi][123]$/.test(row.objective_id))reject('UNKNOWN_CSRF_OBJECTIVE');
   const key=table==='csrf_workshop_progress'?JSON.stringify([row.user_key,row.objective_id]):String(row.id??row.user_key??row.session_key);
   if(seen.has(key))reject('DUPLICATE_CSRF_TARGET_KEY');seen.add(key);
   const sourceKey=table==='csrf_workshop_progress'?JSON.stringify([original.user_key,original.objective_id]):String(original.id??original.user_key??original.session_key);
   snapshot[TARGETS[table]].push(row);provenance.push({source,table,key:sourceKey,row:structuredClone(original)});
  }
 }
 const normalized=rows=>Array.isArray(rows)?rows.map(row=>JSON.stringify(row,Object.keys(row).sort())).sort():null;
 if(JSON.stringify(normalized(review.retainedTables))!==JSON.stringify(normalized(retained)))reject('INCOMPLETE_CSRF_SOURCE_REVIEW');
 if(owners&&[...owners.resolutionMap.keys()].some(key=>!owners.usedResolutions.has(key)))reject('UNUSED_OPAQUE_OWNER_RESOLUTION');
 return{snapshot,provenance,report:{archiveDigest,identityMapSha256:owners?.binding.identityMapSha256||null,counts:Object.fromEntries(Object.entries(snapshot).map(([key,rows])=>[key,rows.length])),retainedTables:retained,canonicalProgressImported:false}};
}
module.exports={COLUMNS,mapCsrfArchive};
