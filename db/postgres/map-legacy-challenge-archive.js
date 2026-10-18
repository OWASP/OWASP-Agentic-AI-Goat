'use strict';
const {createHash}=require('node:crypto');
const {timestamp}=require('../../server/database/postgres/identityValidation');
// This is an explicit mapping of the ten mounted legacy demo tables, not SQL translation.
const COLUMNS=Object.freeze({
 users:'id username email password role full_name created_at is_active',
 products:'id name description price category image_url',
 comments:'id user_id content created_at',
 reviews:'id product_id user_id rating comment created_at',
 cart:'id user_id product_id quantity created_at',
 orders:'id user_id total_amount payment_method shipping_address status created_at',
 order_items:'id order_id product_id quantity price',
 files:'id filename original_name file_path file_size mime_type uploaded_by uploaded_at',
 ai_conversations:'id user_id prompt response model_used created_at',
 vulnerability_settings:'vulnerability_key enabled',
});
const NULLABLE=new Set('role full_name created_at is_active description category image_url comments.user_id cart.quantity payment_method shipping_address status file_size mime_type uploaded_by uploaded_at ai_conversations.user_id response model_used'.split(' '));
const INTEGERS=new Set('id user_id product_id order_id quantity rating file_size uploaded_by is_active enabled'.split(' '));
const REALS=new Set(['price','total_amount']);
function reject(code){throw Object.assign(new Error(code),{code});}
function digest(value){return createHash('sha256').update(value).digest('hex');}
function mapLegacyChallengeArchive(raw){
 if(!raw||Array.isArray(raw)||Object.keys(raw).some(k=>!['tables','archiveDigest','naiveTimestamps','review'].includes(k)))reject('INVALID_LEGACY_CHALLENGE_ARCHIVE');
 const {tables,archiveDigest,review,naiveTimestamps='reject'}=raw;
 if(!/^[a-f0-9]{64}$/.test(archiveDigest||''))reject('ARCHIVE_DIGEST_REQUIRED');
 if(!tables||Array.isArray(tables)||typeof tables!=='object')reject('INVALID_ARCHIVE_TABLES');
 if(!['reject','UTC'].includes(naiveTimestamps))reject('INVALID_TIMESTAMP_POLICY');
 const snapshot={},provenance=[],references=[],retainedTables=Object.keys(tables).filter(t=>!Object.hasOwn(COLUMNS,t)).sort();
 for(const rows of Object.values(tables))if(!Array.isArray(rows))reject('INVALID_ARCHIVE_TABLE');
 for(const [table,columns]of Object.entries(COLUMNS)){
  // Some historical installations never created settings. Its absence is explicitly reviewed.
  if(!Object.hasOwn(tables,table)&&table!=='vulnerability_settings')reject('MISSING_LEGACY_CHALLENGE_TABLE');
  const seen=new Set();snapshot[table]=[];
  for(const row of tables[table]||[]){
   if(!row||Array.isArray(row)||Object.keys(row).sort().join(' ')!==columns.split(' ').sort().join(' '))reject('UNMAPPED_LEGACY_CHALLENGE_COLUMNS');
   const mapped={};
   for(const key of columns.split(' ')){
    let value=row[key];
    const nullable=NULLABLE.has(key)||NULLABLE.has(`${table}.${key}`)||(table==='products'&&key==='price');
    if(value===null){if(!nullable)reject('INVALID_LEGACY_NULL');mapped[key]=null;continue;}
    if(INTEGERS.has(key)){
     if(value&&typeof value==='object'&&Object.keys(value).sort().join(',')==='type,value'&&value.type==='integer'&&typeof value.value==='string'&&/^-?(0|[1-9][0-9]*)$/.test(value.value))value=Number(value.value);
     if(!Number.isInteger(value)||value < -2147483648||value>2147483647)reject('INVALID_LEGACY_INTEGER');
     if(key==='id'&&value===2147483647)reject('LEGACY_SEQUENCE_EXHAUSTED');
    }else if(REALS.has(key)){
     if(value&&typeof value==='object'&&Object.keys(value).sort().join(',')==='type,value'){
      if(value.type==='integer'){if(typeof value.value!=='string'||! /^-?(0|[1-9][0-9]*)$/.test(value.value)||!Number.isSafeInteger(Number(value.value)))reject('INVALID_LEGACY_REAL');value=Number(value.value);}
      else if(value.type==='real'&&(typeof value.value==='number'||value.value==='-0'))value=Number(value.value);
     }
     if(typeof value!=='number'||!Number.isFinite(value))reject('INVALID_LEGACY_REAL');
    }else{
     if(typeof value!=='string'||value.includes('\0'))reject('INVALID_LEGACY_TEXT');
     if(key.endsWith('_at')){if(!/(Z|[+-]\d{2}:\d{2})$/.test(value)&&naiveTimestamps!=='UTC')reject('AMBIGUOUS_TIMESTAMP');value=timestamp(value,false);}
    }
    mapped[key]=value;
   }
   const id=String(mapped.id??mapped.vulnerability_key);if(seen.has(id))reject('DUPLICATE_LEGACY_SOURCE_KEY');seen.add(id);
   snapshot[table].push(mapped);provenance.push({table,id,row:structuredClone(row)});
   // Review every path-bearing value, including remote URLs: no untrusted classification guesses.
   for(const field of table==='files'?['file_path']:table==='products'?['image_url']:[]){
    if(mapped[field]!==null&&mapped[field]!=='')references.push({table,id,field,valueSha256:digest(mapped[field]),disposition:'metadata_only_assets_not_verified'});
   }
  }
 }
 const relations={comments:{user_id:'users'},reviews:{user_id:'users',product_id:'products'},cart:{user_id:'users',product_id:'products'},orders:{user_id:'users'},order_items:{order_id:'orders',product_id:'products'},files:{uploaded_by:'users'},ai_conversations:{user_id:'users'}};
 for(const [table,fields]of Object.entries(relations))for(const row of snapshot[table])for(const [field,target]of Object.entries(fields))if(row[field]!==null&&!snapshot[target].some(r=>r.id===row[field]))reject('DANGLING_LEGACY_REFERENCE');
 const missingTables=Object.keys(COLUMNS).filter(t=>!Object.hasOwn(tables,t));
 const expected={archiveDigest,retainedTables,missingTables,fileReferences:references};
 if(!review||Object.keys(review).sort().join(',')!==Object.keys(expected).sort().join(',')||review.archiveDigest!==archiveDigest||JSON.stringify(review.retainedTables)!==JSON.stringify(retainedTables)||JSON.stringify(review.missingTables)!==JSON.stringify(missingTables)||JSON.stringify(review.fileReferences)!==JSON.stringify(references))reject('ARCHIVE_BOUND_LEGACY_REVIEW_REQUIRED');
 return {snapshot,provenance,report:{archiveDigest,counts:Object.fromEntries(Object.entries(snapshot).map(([k,v])=>[k,v.length])),retainedTables,missingTables,fileReferences:references,canonicalProgressImported:false,assetsVerified:false}};
}
module.exports={COLUMNS,mapLegacyChallengeArchive};
