'use strict';
const {createAuditSourceManifest}=require('./secureshopAuditSourceManifest');
const FIXED_AUDIT_MAX_ROWS=100,FIXED_AUDIT_MAX_BYTES=131072;
function assertFixedAuditCount(count){
 if(!Number.isSafeInteger(count)||count<1||count>FIXED_AUDIT_MAX_ROWS)throw Object.assign(new Error('Fixed audit summaries accept at most 100 events'),{code:'AUDIT_FIXED_COUNT_LIMIT'});
}
// Preserve identity, chronology and validated outcome. No arbitrary event string
// becomes a model instruction; the digest identifies the original source bytes.
async function* fixedAuditRows(rows,check){
 let count=0;
 for await(const row of rows){
  await check();assertFixedAuditCount(++count);
  const original=createAuditSourceManifest([row]).sources[0];
  yield Object.freeze({id:original.id,store:original.store,ts:original.ts,
   actor:'recorded_actor',action:'recorded_event',target:'sha256:'+original.sha256,
   params_json:JSON.stringify({outcome:row.outcome,store:original.store}),outcome:row.outcome,
   source_kind:'audit_metadata_projection',source_id:original.sha256,
   ...(original.version===2?{fixedSource:original}:{})});
  await check();
 }
}
module.exports={FIXED_AUDIT_MAX_ROWS,FIXED_AUDIT_MAX_BYTES,assertFixedAuditCount,fixedAuditRows};
