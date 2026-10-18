'use strict';
const {createHash}=require('node:crypto');
const {preparePlatformArchive}=require('./prepare-platform-archive');
const {COLUMNS}=require('./map-platform-snapshot');
const {prepareCombinedImport}=require('./import-platform-identity');
const {canonical}=require('./import-batch');
function reject(code){throw Object.assign(new Error(code),{code});}
const FIELDS=['version','archiveDigest','identityMap','naiveTimestamps','resolutions','identityNormalizations','platformDefaults','retainedPlatformTables'];
async function preparePlatformApply({archive,review}){
 const captured=structuredClone(review);
 if(!captured||typeof captured!=='object'||Array.isArray(captured)||Object.keys(captured).sort().join(',')!==[...FIELDS].sort().join(',')||captured.version!==1)reject('INVALID_PLATFORM_APPLY_REVIEW');
 if(!['UTC','reject'].includes(captured.naiveTimestamps)||!Array.isArray(captured.identityNormalizations)||!Array.isArray(captured.retainedPlatformTables))reject('INVALID_PLATFORM_APPLY_REVIEW');
 const identityReview={archiveDigest:captured.archiveDigest,normalizations:captured.identityNormalizations};
 const prepared=await preparePlatformArchive({archive,identityMap:captured.identityMap,naiveTimestamps:captured.naiveTimestamps,resolutions:captured.resolutions,identityReview});
 if(prepared.report.archiveDigest!==captured.archiveDigest)reject('STALE_PLATFORM_APPLY_REVIEW');
 if(!prepared.inputs.identityAuxiliary)reject('MISSING_AUXILIARY_ARCHIVE_SCOPE');
 const retained=prepared.report.coverage.filter(row=>row.source==='users_auth.db'&&row.disposition==='unmapped').map(row=>row.table).sort();
 const approved=captured.retainedPlatformTables.map(row=>{
  if(!row||Object.keys(row).sort().join(',')!=='policy,table'||row.policy!=='retain_archive_only'||typeof row.table!=='string')reject('INVALID_PLATFORM_RETENTION_DECISION');
  return row.table;
 }).sort();
 if(JSON.stringify(retained)!==JSON.stringify(approved))reject('INCOMPLETE_PLATFORM_RETENTION_REVIEW');
 const {identitySource,...inputs}=prepared.inputs;
 // Remove already imported scopes from the seven-table platform mapper. Retired
 // source tables remain in its archive-only coverage, never in canonical solutions.
 inputs.platform.tables=Object.fromEntries(Object.entries(inputs.platform.tables).filter(([table])=>Object.hasOwn(COLUMNS,table)||retained.includes(table)));
 inputs.platform.review={archiveDigest:captured.archiveDigest,missingDefaults:captured.platformDefaults,retainedTables:retained};
 for(const table of ['csrf_workshop_solutions','csrf_workshop_solution_visibility'])delete inputs.additionalSolutions.sources['users_auth.db'].tables[table];
 const payload={identitySource,identityReview,retainedPlatformTables:captured.retainedPlatformTables};
 inputs.archiveReview={...payload,reviewSha256:createHash('sha256').update(JSON.stringify(canonical(payload))).digest('hex')};
 const combined=prepareCombinedImport(inputs);
 return{inputs,report:{archiveDigest:captured.archiveDigest,reviewSha256:inputs.archiveReview.reviewSha256,planSha256:combined.batch.planSha256,
  counts:combined.batch.counts,scope:'platform_identity_and_canonical_workshop_state',
  retainedPlatformTableCount:retained.length,
  otherChallengeTableCount:prepared.report.coverage.filter(row=>row.source!=='users_auth.db'&&row.disposition==='unmapped').length,
  wholeArchiveImported:false,readyForNativeValidation:true}};
}
module.exports={preparePlatformApply};
