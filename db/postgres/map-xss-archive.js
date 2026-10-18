'use strict';
const {timestamp}=require('../../server/database/postgres/identityValidation');
const {WORKSHOP_OBJECTIVES}=require('../../server/config/workshopCatalog');
const TABLES=Object.freeze({
 xss_workshop_profiles:{target:'profiles',columns:'id user_key name bio website updated_at',omit:['id']},
 xss_workshop_progress:{target:'progress',columns:'id user_key objective_id completed completed_at created_at',omit:['id']},
 xss_workshop_emails:{target:'emails',columns:'id subject sender body user_key received_at'},
 email_profiles:{target:'email_profiles',columns:'id user_id full_name email_address company_name job_title phone_number signature_html signature_plain profile_image_url created_at updated_at'},
 email_templates:{target:'email_templates',columns:'id user_id profile_id template_name template_subject template_type html_content plain_content ai_prompt ai_model is_favorite view_count last_viewed created_at',rename:{template_subject:'subject'}},
 template_previews:{target:'template_previews',columns:'id template_id user_id preview_type xss_detected xss_payload viewed_at'},
 xss_challenge_progress:{target:'xss_challenge_progress',columns:'id user_id challenge_level challenge_name completed payload_used completed_at hints_used attempts created_at'},
 xss_email_judge_receipts:{target:'xss_email_judge_receipts',columns:'id user_id challenge_level template_id verdict judge_version rubric_version evidence_digest run_id error_code browser_executed browser_reason created_at'},
 admin_config:{target:'legacy_challenge_config',columns:'id config_key config_value updated_at',omit:['id']},
});
const INTEGER=new Set('id user_id profile_id template_id challenge_level completed is_favorite view_count xss_detected hints_used attempts browser_executed'.split(' '));
const FLAGS=new Set('completed is_favorite xss_detected browser_executed'.split(' '));
const DATES=new Set('updated_at created_at completed_at received_at last_viewed viewed_at'.split(' '));
const REQUIRED={xss_workshop_profiles:['user_key'],xss_workshop_progress:['user_key','objective_id'],xss_workshop_emails:['subject','sender','body'],email_profiles:['user_id','full_name','email_address'],email_templates:['user_id','profile_id','template_name','html_content'],template_previews:['template_id','user_id'],xss_challenge_progress:['user_id','challenge_level','challenge_name'],xss_email_judge_receipts:['user_id','challenge_level','template_id','verdict','rubric_version','browser_executed'],admin_config:['config_key']};
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
function mapXssArchive(raw){
 if(!raw||typeof raw!=='object'||Array.isArray(raw)||Object.keys(raw).some(key=>!['sources','archiveDigest','naiveTimestamps','review','ownerBinding','opaqueOwnerResolutions'].includes(key)))reject('INVALID_XSS_ARCHIVE');
 const{sources,archiveDigest,naiveTimestamps='reject',review}=raw;
 if(typeof archiveDigest!=='string'||!/^[a-f0-9]{64}$/.test(archiveDigest))reject('ARCHIVE_DIGEST_REQUIRED');
 if(!['UTC','reject'].includes(naiveTimestamps))reject('INVALID_TIMESTAMP_POLICY');
 if(!sources||typeof sources!=='object'||Array.isArray(sources))reject('INVALID_XSS_SOURCES');
 if(!review||Object.keys(review).sort().join(',')!=='archiveDigest,missingTables,retainedTables,workshopSource'||review.archiveDigest!==archiveDigest||!['xss_email_challenge.db','xss_challenge.db'].includes(review.workshopSource))reject('ARCHIVE_BOUND_XSS_REVIEW_REQUIRED');
 const owners=ownerContext(raw);
 if(owners&&owners.binding.archiveDigest!==archiveDigest)reject('OWNER_ARCHIVE_MISMATCH');
 const markResolution=value=>{if(owners&&typeof value==='string'&&owners.resolutionMap.has(value))owners.usedResolutions.add(value);};
 const mapKey=(value,allowAnonymous=false)=>{markResolution(value);return owners?ownerApi().mapOwnerKey(value,owners.binding,{allowAnonymous,opaqueOwnerResolutions:owners.resolutions}):value;};
 const mapId=value=>owners?ownerApi().mapAuthenticatedOwner(value,owners.binding,{as:'number'}):value;
 if(Object.keys(sources).some(source=>!['xss_email_challenge.db','xss_challenge.db','challenge.db'].includes(source)))reject('UNKNOWN_XSS_SOURCE');
 for(const envelope of Object.values(sources))if(!envelope||!envelope.tables||typeof envelope.tables!=='object'||Array.isArray(envelope.tables))reject('INVALID_XSS_SOURCE');
 const snapshot={},provenance=[],mapped=new Set(),missing=[];
 for(const[table,config]of Object.entries(TABLES)){
  const source=table.startsWith('xss_workshop_')?review.workshopSource:table==='admin_config'?'challenge.db':'xss_email_challenge.db';
  const rows=sources[source]?.tables[table];snapshot[config.target]=[];
  if(rows===undefined){
   if(!['xss_email_judge_receipts','admin_config'].includes(table))reject('MISSING_XSS_TABLE');
   missing.push({source,table,policy:table==='admin_config'?'absent_config_remains_disabled':'prejudge_no_receipts_created'});continue;
  }
  if(!Array.isArray(rows))reject('INVALID_XSS_TABLE');mapped.add(source+':'+table);
  const seenIds=new Set(),seenKeys=new Set();
  for(const sourceRow of rows){
   if(!sourceRow||typeof sourceRow!=='object'||Array.isArray(sourceRow)||Object.keys(sourceRow).sort().join(' ')!==config.columns.split(' ').sort().join(' '))reject('UNMAPPED_XSS_COLUMNS');
   const row={};
   for(const[column,original]of Object.entries(sourceRow)){
    let value=original;
    if(value!==null&&INTEGER.has(column)){
     if(value&&typeof value==='object'&&Object.keys(value).sort().join(',')==='type,value'&&value.type==='integer'&&typeof value.value==='string'&&/^-?(0|[1-9][0-9]*)$/.test(value.value))value=Number(value.value);
     if(!Number.isSafeInteger(value)||value<0||value>2147483647)reject('INVALID_XSS_INTEGER');
     if(FLAGS.has(column)&&![0,1].includes(value))reject('INVALID_XSS_FLAG');
     if(['id','user_id','profile_id','template_id'].includes(column)&&value<1)reject('INVALID_XSS_ID');
    }else if(value!==null&&(typeof value!=='string'||value.includes('\0')))reject('INVALID_XSS_TEXT');
    if(value===null&&(column==='id'||REQUIRED[table].includes(column)))reject('MISSING_REQUIRED_XSS_VALUE');
    if(DATES.has(column)&&value!==null){if(!/(Z|[+-]\d{2}:\d{2})$/.test(value)&&naiveTimestamps!=='UTC')reject('AMBIGUOUS_TIMESTAMP');value=timestamp(value,false);}
    if(!config.omit?.includes(column))row[config.rename?.[column]||column]=value;
   }
   const id=typeof sourceRow.id==='object'?Number(sourceRow.id.value):sourceRow.id;
   if(seenIds.has(id)||id>=2147483647)reject('DUPLICATE_OR_EXHAUSTED_XSS_ID');seenIds.add(id);
    if(row.user_key!==undefined&&row.user_key!==null&&(!row.user_key.length||row.user_key.length>200))reject('INVALID_XSS_OWNER');
   if(table==='xss_workshop_progress'&&!WORKSHOP_OBJECTIVES.xss_workshop.some(o=>o.id===row.objective_id))reject('UNKNOWN_XSS_OBJECTIVE');
   if(row.challenge_level!==undefined&&![1,2,3,4].includes(row.challenge_level))reject('INVALID_XSS_LEVEL');
   if(row.verdict!==undefined&&!['pass','fail','inconclusive','unavailable'].includes(row.verdict))reject('INVALID_XSS_VERDICT');
   if(owners){
    if(['xss_workshop_profiles','xss_workshop_progress'].includes(table))row.user_key=mapKey(row.user_key);
     if(table==='xss_workshop_emails'&&row.user_key!==null)row.user_key=mapKey(row.user_key,true);
     if(['email_profiles','email_templates','template_previews','xss_challenge_progress','xss_email_judge_receipts'].includes(table))row.user_id=mapId(row.user_id);
    }
   const key=table==='xss_workshop_profiles'?row.user_key:table==='xss_workshop_progress'?JSON.stringify([row.user_key,row.objective_id]):table==='email_profiles'?row.user_id:table==='xss_challenge_progress'?JSON.stringify([row.user_id,row.challenge_level]):table==='admin_config'?row.config_key:id;
   if(seenKeys.has(key))reject('DUPLICATE_XSS_TARGET_KEY');seenKeys.add(key);
    snapshot[config.target].push(row);provenance.push({source,table,id:String(id),row:structuredClone(sourceRow)});
  }
 }
 const retained=[];
 for(const[source,envelope]of Object.entries(sources))for(const[table,rows]of Object.entries(envelope.tables)){
  if(!Array.isArray(rows))reject('INVALID_XSS_TABLE');
  if(!mapped.has(source+':'+table))retained.push({source,table,policy:'retain_archive_only'});
 }
 const equal=(a,b)=>Array.isArray(a)&&JSON.stringify(a.map(row=>JSON.stringify(row,Object.keys(row).sort())).sort())===JSON.stringify(b.map(row=>JSON.stringify(row,Object.keys(row).sort())).sort());
 if(!equal(review.missingTables,missing)||!equal(review.retainedTables,retained))reject('INCOMPLETE_XSS_SOURCE_REVIEW');
 if(owners&&[...owners.resolutionMap.keys()].some(key=>!owners.usedResolutions.has(key)))reject('UNUSED_OPAQUE_OWNER_RESOLUTION');
 return{snapshot,provenance,report:{archiveDigest,identityMapSha256:owners?.binding.identityMapSha256||null,counts:Object.fromEntries(Object.entries(snapshot).map(([table,rows])=>[table,rows.length])),retainedTables:retained,missingTables:missing,canonicalProgressImported:false}};
}
module.exports={TABLES,mapXssArchive};
