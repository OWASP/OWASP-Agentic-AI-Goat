'use strict';
const {withTransaction}=require('../../server/database/postgres');
const {normalizeArchiveOwnerBinding,normalizeOpaqueResolutions,mapOwnerKey,assertVerifiedArchiveOwnerBinding}=require('./archive-owner-binding');
const catalogs={
 aria:{products:'id product_id name category price description stock available',orders:'id order_number user_id product_name quantity unit_price total_amount shipping_address status payment_method created_at',receipts:'id order_number receipt_number amount payment_method issued_at',cart:'id user_id product_name quantity unit_price added_at',chat_history:'id user_id message_type message timestamp'},
 nova:{papers:'id paper_id title abstract authors topics year journal citations cited_by url access_level',authors:'id author_id name institution expertise paper_count email bio',reading_lists:'id user_id paper_id added_at notes',chat_history:'id user_id message_type message timestamp',nosql_injection_solution_visibility:'objective_id solutions_enabled updated_at',nosql_injection_solutions:'objective_id title difficulty hints examples approach tips'},
};
const numeric=new Set('id price stock available quantity unit_price total_amount amount year citations paper_count solutions_enabled'.split(' '));
function validateSnapshot(snapshot){
 if(!snapshot||snapshot.version!==1||!Object.hasOwn(catalogs,snapshot.family)||!snapshot.tables||Array.isArray(snapshot.tables))throw new Error('Invalid workshop snapshot envelope');
 if(Object.keys(snapshot).some(key=>!['version','family','tables'].includes(key)))throw new Error('Unknown snapshot field');
 const catalog=catalogs[snapshot.family],expected=Object.keys(catalog);
 if(Object.keys(snapshot.tables).length!==expected.length||Object.keys(snapshot.tables).some(table=>!Object.hasOwn(catalog,table)))throw new Error('Snapshot must contain exactly the supported workshop tables');
 const tables={};
 for(const table of expected){
  const columns=catalog[table].split(' '),rows=snapshot.tables[table];if(!Array.isArray(rows))throw new Error(`Invalid rows: ${table}`);
  tables[table]=rows.map((row,index)=>{
   if(!row||Array.isArray(row)||typeof row!=='object'||Object.keys(row).length!==columns.length||columns.some(column=>!Object.hasOwn(row,column)))throw new Error(`Snapshot columns mismatch: ${table} row ${index}`);
   const result={};for(const column of columns){const value=row[column];
    if(value!==null&&(numeric.has(column)?typeof value!=='number'||!Number.isFinite(value):typeof value!=='string'||value.includes('\0')))throw new Error(`Unsupported value: ${table}.${column} row ${index}`);
    if(column==='id'&&(!Number.isSafeInteger(value)||value<1||value>2147483647))throw new Error(`Invalid preserved ID: ${table} row ${index}`);
    result[column]=value;
   }return result;
  });
 }
 return{family:snapshot.family,tables};
}
const OWNER_COLUMNS=Object.freeze({
 aria:new Set(['orders.user_id','cart.user_id','chat_history.user_id']),
 nova:new Set(['reading_lists.user_id','chat_history.user_id']),
});
const OWNER_UNIQUE_KEYS=Object.freeze({
 aria:Object.freeze({cart:['user_id','product_name']}),
 nova:Object.freeze({reading_lists:['user_id','paper_id']}),
});
const IMPORT_METADATA_MAX_BYTES=64*1024;
function reject(code){throw Object.assign(new Error(code),{code});}
function metadataError(code){reject(code);}
function resolutionFingerprint(value){return value.map(row=>JSON.stringify(row)).sort().join('|');}
function normalizeImportMetadata(raw,{binding,archiveDigest,opaqueOwnerResolutions=[]}={}){
 const direct=raw===undefined;
 const metadata=direct?{source:'direct_snapshot',naiveTimestamps:'UTC',archiveDigest:binding?.archiveDigest||archiveDigest||null,reviewSha256:null,normalizations:{integerOwnerKeys:0,novaPublicAccess:0},retainedOtherSources:[],opaqueOwnerResolutions:structuredClone(opaqueOwnerResolutions)}:raw;
 if(!metadata||typeof metadata!=='object'||Array.isArray(metadata))metadataError('INVALID_IMPORT_METADATA');
 const expected=['source','naiveTimestamps','archiveDigest','reviewSha256','normalizations','retainedOtherSources','opaqueOwnerResolutions'];
 if(Object.keys(metadata).sort().join(',')!==expected.sort().join(','))metadataError('INVALID_IMPORT_METADATA');
 if(!['direct_snapshot','archive_review'].includes(metadata.source)||!['UTC','reject'].includes(metadata.naiveTimestamps))metadataError('INVALID_IMPORT_METADATA');
 if(metadata.source==='direct_snapshot'&&(metadata.reviewSha256!==null||metadata.retainedOtherSources.length!==0))metadataError('INVALID_IMPORT_METADATA');
 if(metadata.source==='archive_review'&&(!/^[a-f0-9]{64}$/.test(metadata.archiveDigest||'')||!/^[a-f0-9]{64}$/.test(metadata.reviewSha256||'')))metadataError('INVALID_IMPORT_METADATA');
 if(metadata.archiveDigest!==null&&!/^[a-f0-9]{64}$/.test(metadata.archiveDigest))metadataError('INVALID_IMPORT_METADATA');
 if(metadata.reviewSha256!==null&&!/^[a-f0-9]{64}$/.test(metadata.reviewSha256))metadataError('INVALID_IMPORT_METADATA');
 const normalizationKeys=['integerOwnerKeys','novaPublicAccess'];
 if(!metadata.normalizations||typeof metadata.normalizations!=='object'||Array.isArray(metadata.normalizations)||Object.keys(metadata.normalizations).sort().join(',')!==normalizationKeys.join(',')||normalizationKeys.some(key=>!Number.isSafeInteger(metadata.normalizations[key])||metadata.normalizations[key]<0))metadataError('INVALID_IMPORT_METADATA');
 if(!Array.isArray(metadata.retainedOtherSources)||metadata.retainedOtherSources.some(value=>typeof value!=='string'||!value||value.length>200))metadataError('INVALID_IMPORT_METADATA');
 normalizeOpaqueResolutions(metadata.opaqueOwnerResolutions);
 normalizeOpaqueResolutions(opaqueOwnerResolutions);
 if(resolutionFingerprint(metadata.opaqueOwnerResolutions)!==resolutionFingerprint(opaqueOwnerResolutions))metadataError('IMPORT_METADATA_OWNER_RESOLUTION_MISMATCH');
 const normalized=structuredClone(metadata),serialized=JSON.stringify(normalized);
 if(Buffer.byteLength(serialized)>IMPORT_METADATA_MAX_BYTES)metadataError('IMPORT_METADATA_TOO_LARGE');
 if(binding&&normalized.archiveDigest!==binding.archiveDigest)metadataError('IMPORT_METADATA_OWNER_MISMATCH');
 if(archiveDigest&&normalized.archiveDigest!==archiveDigest)metadataError('IMPORT_METADATA_ARCHIVE_MISMATCH');
 return normalized;
}
function mapSnapshotOwners(snapshot,{ownerBinding,ownerProof,opaqueOwnerResolutions=[],archiveDigest}={}){
 const normalized=validateSnapshot(snapshot),family=normalized.family,ownerColumns=OWNER_COLUMNS[family];
 const hasOwnerState=Object.entries(normalized.tables).some(([table,rows])=>rows.some(row=>ownerColumns.has(`${table}.user_id`)&&row.user_id!==null));
 if(!ownerBinding&&ownerProof) reject('OWNER_BINDING_REQUIRED');
 if(!ownerBinding&&opaqueOwnerResolutions.length) reject('OWNER_RESOLUTIONS_WITHOUT_BINDING');
 if(hasOwnerState&&!ownerBinding) reject('OWNER_BINDING_REQUIRED');
 let binding=null;
 if(ownerBinding){
  binding=normalizeArchiveOwnerBinding(ownerBinding);
  if(archiveDigest&&binding.archiveDigest!==archiveDigest) reject('OWNER_ARCHIVE_MISMATCH');
  assertVerifiedArchiveOwnerBinding(ownerProof,binding);
 }
 const resolutions=binding?normalizeOpaqueResolutions(opaqueOwnerResolutions):new Map();
 const usedResolutions=new Set(),sourceRows=[],seenOwnerKeys=new Set();
 const tables={};
 for(const [table,rows] of Object.entries(normalized.tables)){
  tables[table]=rows.map((row,index)=>{
   const original=structuredClone(row),mapped={...row};
   if(ownerColumns.has(`${table}.user_id`)&&mapped.user_id!==null){
    const sourceKey=String(mapped.user_id);
    if(resolutions.has(sourceKey))usedResolutions.add(sourceKey);
    mapped.user_id=mapOwnerKey(sourceKey,binding,{allowAnonymous:true,opaqueOwnerResolutions});
   }
   const uniqueColumns=OWNER_UNIQUE_KEYS[family][table];
   if(uniqueColumns){
    const uniqueKey=JSON.stringify(uniqueColumns.map(column=>mapped[column]));
    if(seenOwnerKeys.has(`${table}:${uniqueKey}`)) reject('DUPLICATE_MAPPED_OWNER_STATE');
    seenOwnerKeys.add(`${table}:${uniqueKey}`);
   }
   const sourceKeyColumn=Object.hasOwn(original,'id')?'id':['objective_id','paper_id','author_id','product_id','order_number','receipt_number'].find(column=>Object.hasOwn(original,column)&&original[column]!==null);
   const sourceId=sourceKeyColumn?String(original[sourceKeyColumn]):null;
   if(!sourceId) reject('MISSING_WORKSHOP_PROVENANCE_KEY');
   sourceRows.push({sourceTable:table,sourceId:String(sourceId),sourceRow:original,rowIndex:index});
   return mapped;
  });
 }
 if([...resolutions.keys()].some(key=>!usedResolutions.has(key))) reject('UNUSED_OPAQUE_OWNER_RESOLUTION');
 return {snapshot:{version:1,family,tables},binding,sourceRows,hasOwnerState};
}
async function importWorkshopSnapshot(pool,snapshot,{apply=false,ownerBinding,ownerProof,opaqueOwnerResolutions=[],archiveDigest,reviewMetadata}={}){
 const prepared=mapSnapshotOwners(snapshot,{ownerBinding,ownerProof,opaqueOwnerResolutions,archiveDigest});
 const normalized=prepared.snapshot,family=normalized.family,catalog=catalogs[family],tableNames=Object.keys(catalog),binding=prepared.binding,metadata=normalizeImportMetadata(reviewMetadata,{binding,archiveDigest,opaqueOwnerResolutions});
 return withTransaction(pool,async client=>{
  await client.query("SET LOCAL timezone='UTC'");
  // Locks also exclude normal seeding, which writes these tables and seed_state.
  const historyTables=['import_provenance','import_batches'];
  await client.query(`LOCK TABLE ${[...tableNames,'seed_state',...historyTables].map(table=>`${family}.${table}`).join(',')} IN ACCESS EXCLUSIVE MODE`);
  for(const table of [...tableNames,'seed_state',...historyTables])if((await client.query(`SELECT EXISTS(SELECT 1 FROM ${family}.${table}) AS populated`)).rows[0].populated)throw new Error('Import requires a schema-only empty workshop destination');
  // Insert even during dry-run: native constraints validate every row/link; savepoint rollback leaves destination empty.
  await client.query('SAVEPOINT workshop_import_validation');
  for(const table of tableNames){const columns=catalog[table].split(' ');
   for(const row of normalized.tables[table])await client.query(`INSERT INTO ${family}.${table}(${columns.join(',')}) ${columns.includes('id')?'OVERRIDING SYSTEM VALUE ':''}VALUES(${columns.map((_,index)=>'$'+(index+1)).join(',')})`,columns.map(column=>row[column]));
  }
  if(binding){
   for(const row of prepared.sourceRows)await client.query(`INSERT INTO ${family}.import_provenance(archive_sha256,source_table,source_id,source_row) VALUES($1,$2,$3,$4::jsonb)`,[binding.archiveDigest,row.sourceTable,row.sourceId,JSON.stringify(row.sourceRow)]);
   await client.query(`INSERT INTO ${family}.import_batches(archive_sha256,importer_version,counts,identity_map_sha256,review_metadata) VALUES($1,$2,$3::jsonb,$4,$5::jsonb)`,[binding.archiveDigest,'workshop-snapshot-v2',JSON.stringify(Object.fromEntries(tableNames.map(table=>[table,normalized.tables[table].length]))),binding.identityMapSha256,JSON.stringify(metadata)]);
  }
  const counts=Object.fromEntries(tableNames.map(table=>[table,normalized.tables[table].length]));
  if(!apply){await client.query('ROLLBACK TO SAVEPOINT workshop_import_validation');return{status:'validated',applied:false,family,counts,archiveDigest:binding?.archiveDigest||archiveDigest||null,identityMapSha256:binding?.identityMapSha256||null,provenanceRows:binding?prepared.sourceRows.length:0,reviewMetadata:metadata};}
  // Explicit-ID inserts did not consume sequences. Restart is transactional, unlike setval.
  for(const table of tableNames)if(catalog[table].split(' ').includes('id')){
   const next=normalized.tables[table].reduce((max,row)=>Math.max(max,row.id),0)+1;
   await client.query(`ALTER TABLE ${family}.${table} ALTER COLUMN id RESTART WITH ${next}`);
  }
  await client.query(`INSERT INTO ${family}.seed_state(version) VALUES(1)`);
  return{status:'imported',applied:true,family,counts,archiveDigest:binding?.archiveDigest||archiveDigest||null,identityMapSha256:binding?.identityMapSha256||null,provenanceRows:binding?prepared.sourceRows.length:0,reviewMetadata:metadata};
 });
}
module.exports={catalogs,validateSnapshot,mapSnapshotOwners,importWorkshopSnapshot,OWNER_COLUMNS,normalizeImportMetadata};
