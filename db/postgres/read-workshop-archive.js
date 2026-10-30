'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {constants}=require('node:fs');
const {readBounded}=require('./asset-bundle');
const {catalogs,validateSnapshot}=require('./import-workshop-snapshot');
const MAX_ARCHIVE_MANIFEST_BYTES=4*1024*1024;
const MAX_ARCHIVE_SCHEMA_BYTES=8*1024*1024;
const MAX_ARCHIVE_TABLE_BYTES=128*1024*1024;
const MAX_ARCHIVE_TOTAL_BYTES=512*1024*1024;
const budgets=new WeakMap();
const numbers=new Set('id price stock available quantity unit_price total_amount amount year citations paper_count solutions_enabled'.split(' '));
const integers=new Set('id stock available quantity year citations paper_count solutions_enabled'.split(' '));
const timestampColumns=new Set('created_at issued_at added_at timestamp updated_at'.split(' '));
const explicitTimezone=/\d(?:Z|[+-]\d{2}:?\d{2})$/i;
function fail(code){const e=new Error(code);e.code=code;throw e;}
function sameStat(before,after){return ['dev','ino','size','mtimeMs','ctimeMs'].every(key=>before[key]===after[key]);}
function createArchiveReadBudget(maximumBytes=MAX_ARCHIVE_TOTAL_BYTES){
 if(!Number.isSafeInteger(maximumBytes)||maximumBytes<1||maximumBytes>MAX_ARCHIVE_TOTAL_BYTES)fail('INVALID_ARCHIVE_READ_BUDGET');
 const budget=Object.freeze({maximumBytes});budgets.set(budget,{maximumBytes,consumedBytes:0});return budget;
}
function reserve(budget,bytes){
 if(budget===undefined)return;
 if(!budget||!budgets.has(budget))fail('INVALID_ARCHIVE_READ_BUDGET');
 const state=budgets.get(budget);
 if(state.consumedBytes+bytes>state.maximumBytes)fail('ARCHIVE_TOTAL_BYTES_LIMIT');
 state.consumedBytes+=bytes;
}
async function file(root,name,{maximumBytes=MAX_ARCHIVE_MANIFEST_BYTES,tooLargeCode='ARCHIVE_MANIFEST_TOO_LARGE',expectedBytes,budget}={}){
 if(typeof name!=='string'||!name||path.basename(name)!==name||name==='.'||name==='..'||name.includes('\\'))fail('UNSAFE_ARCHIVE_PATH');
 if(!Number.isSafeInteger(maximumBytes)||maximumBytes<0||maximumBytes>MAX_ARCHIVE_TOTAL_BYTES)fail('INVALID_ARCHIVE_FILE_LIMIT');
 const handle=await fs.open(path.join(root,name),constants.O_RDONLY|constants.O_NOFOLLOW);
 try{
  const before=await handle.stat();
  if(!before.isFile())fail('ARCHIVE_FILE_NOT_REGULAR');
  if(!Number.isSafeInteger(before.size)||before.size>maximumBytes)fail(tooLargeCode);
  if(expectedBytes!==undefined&&before.size!==expectedBytes)fail('ARCHIVE_HASH_MISMATCH');
  reserve(budget,before.size);
  const buffer=await readBounded(handle,before.size),after=await handle.stat();
  if(buffer.length!==before.size||!sameStat(before,after))fail('ARCHIVE_FILE_CHANGED');
  return buffer;
 }finally{await handle.close();}
}
async function verified(root,name,metadata,budget,kind=Object.hasOwn(metadata||{},'rows')?'table':'schema'){
 if(!metadata||!Number.isSafeInteger(metadata.bytes)||metadata.bytes<0||!/^[a-f0-9]{64}$/.test(metadata.sha256))fail('INVALID_ARCHIVE_HASH_METADATA');
 if(!['schema','table'].includes(kind))fail('INVALID_ARCHIVE_FILE_KIND');
 const table=kind==='table',maximumBytes=table?MAX_ARCHIVE_TABLE_BYTES:MAX_ARCHIVE_SCHEMA_BYTES;
 if(metadata.bytes>maximumBytes)fail(table?'ARCHIVE_TABLE_TOO_LARGE':'ARCHIVE_SCHEMA_TOO_LARGE');
 const buffer=await file(root,name,{maximumBytes,tooLargeCode:table?'ARCHIVE_TABLE_TOO_LARGE':'ARCHIVE_SCHEMA_TOO_LARGE',expectedBytes:metadata.bytes,budget});
 if(crypto.createHash('sha256').update(buffer).digest('hex')!==metadata.sha256)fail('ARCHIVE_HASH_MISMATCH');return buffer.toString('utf8');
}
function decode(cell,column,normalizations){
 if(!cell||typeof cell!=='object'||Array.isArray(cell))fail('INVALID_TAGGED_VALUE');
 const keys=Object.keys(cell).sort().join(',');
 if(cell.type==='null'&&keys==='type')return null;
 if(cell.type==='text'&&keys==='type,value'&&typeof cell.value==='string')return cell.value;
 if(cell.type==='integer'&&keys==='type,value'&&typeof cell.value==='string'&&/^-?(0|[1-9][0-9]*)$/.test(cell.value)){
  if(column==='user_id'){normalizations.integerOwnerKeys++;return cell.value;}
  if(!numbers.has(column))fail('INTEGER_IN_TEXT_COLUMN');
  const value=Number(cell.value);if(!Number.isSafeInteger(value)||BigInt(value)!==BigInt(cell.value))fail('UNSAFE_INTEGER');return value;
 }
 if(cell.type==='real'&&keys==='type,value'&&numbers.has(column)){
  const value=cell.value==='-0'?-0:cell.value;if(typeof value!=='number'||!Number.isFinite(value)||(integers.has(column)&&!Number.isSafeInteger(value)))fail('UNSUPPORTED_REAL');return value;
 }
 fail('UNSUPPORTED_TAGGED_VALUE');
}
async function readWorkshopArchive({archive,family,naiveTimestamps='UTC'}){
 if(!Object.hasOwn(catalogs,family))fail('UNKNOWN_WORKSHOP_FAMILY');
 if(!['reject','UTC'].includes(naiveTimestamps))fail('INVALID_TIMESTAMP_POLICY');
 const budget=createArchiveReadBudget();
 const root=await fs.realpath(archive);const incomplete=await fs.lstat(path.join(root,'INCOMPLETE')).then(()=>true,error=>{if(error.code==='ENOENT')return false;throw error;});if(incomplete)fail('INCOMPLETE_ARCHIVE');
 const manifestBytes=await file(root,'manifest.json',{budget});
 const manifest=JSON.parse(manifestBytes.toString('utf8'));
 if(manifest.version!==1||manifest.format!=='owasp-ai-goat-sqlite-archive-v1'||manifest.complete!==true||!Array.isArray(manifest.files))fail('INVALID_ARCHIVE_MANIFEST');
 const source=family==='aria'?'sql_workshop.db':'nosql_workshop.db',seen=new Set(),data=new Map();
 for(const entry of manifest.files){
  if(!entry||typeof entry.name!=='string'||seen.has(entry.name)||!Array.isArray(entry.tables))fail('INVALID_ARCHIVE_SOURCE');seen.add(entry.name);
  const schema=JSON.parse(await verified(root,entry.schemaFile,entry.schema,budget,'schema'));if(!Array.isArray(schema))fail('INVALID_ARCHIVE_SCHEMA');
  const tableNames=new Set();
  for(const table of entry.tables){
   if(typeof table.name!=='string'||tableNames.has(table.name)||!Array.isArray(table.columns)||table.columns.some(c=>typeof c!=='string')||new Set(table.columns).size!==table.columns.length||!Number.isSafeInteger(table.rows)||table.rows<0)fail('INVALID_ARCHIVE_TABLE');tableNames.add(table.name);
   const text=await verified(root,table.file,table,budget,'table'),lines=text?text.split('\n'):[];if(lines.at(-1)==='')lines.pop();if(lines.length!==table.rows)fail('ARCHIVE_ROW_COUNT_MISMATCH');
   const rows=lines.map(line=>JSON.parse(line));if(rows.some(row=>!Array.isArray(row)||row.length!==table.columns.length))fail('ARCHIVE_COLUMN_COUNT_MISMATCH');
   if(entry.name===source)data.set(table.name,{columns:table.columns,rows});
  }
  const declared=schema.filter(item=>item.type==='table').map(item=>item.name);if(declared.length!==tableNames.size||declared.some(name=>!tableNames.has(name)))fail('ARCHIVE_SCHEMA_TABLE_MISMATCH');
 }
 if(!seen.has(source))fail('WORKSHOP_SOURCE_MISSING');
 const expected=Object.keys(catalogs[family]),unmapped=[...data.keys()].filter(name=>!expected.includes(name));
 if(unmapped.length){const e=new Error('UNMAPPED_ARCHIVE_TABLES');e.code=e.message;e.unmappedTables=unmapped;throw e;}
 const normalizations={integerOwnerKeys:0,novaPublicAccess:0},tables={};
 for(const table of expected){
  const entry=data.get(table);if(!entry)fail('WORKSHOP_TABLE_MISSING');const columns=catalogs[family][table].split(' '),legacyAccess=family==='nova'&&table==='papers'&&!entry.columns.includes('access_level');
  const wanted=legacyAccess?columns.filter(c=>c!=='access_level'):columns;
  if(entry.columns.length!==wanted.length||entry.columns.some(c=>!wanted.includes(c)))fail('UNMAPPED_ARCHIVE_COLUMNS');
  tables[table]=entry.rows.map(values=>{const row={};entry.columns.forEach((column,index)=>{row[column]=decode(values[index],column,normalizations);if(naiveTimestamps==='reject'&&timestampColumns.has(column)&&row[column]!==null&&(!explicitTimezone.test(row[column])||Number.isNaN(Date.parse(row[column]))))fail('NAIVE_TIMESTAMP_REJECTED');});if(legacyAccess){row.access_level='public';normalizations.novaPublicAccess++;}return row;});
 }
 const snapshot={version:1,family,tables};validateSnapshot(snapshot);
 const archiveDigest=crypto.createHash('sha256').update(manifestBytes).digest('hex');
 return{snapshot,archiveDigest,report:{family,source,archiveDigest,naiveTimestamps,counts:Object.fromEntries(expected.map(name=>[name,tables[name].length])),normalizations,retainedOtherSources:[...seen].filter(name=>name!==source)}};
}
module.exports={readWorkshopArchive,readArchiveFile:file,readVerifiedArchiveFile:verified,createArchiveReadBudget,
 MAX_ARCHIVE_MANIFEST_BYTES,MAX_ARCHIVE_SCHEMA_BYTES,MAX_ARCHIVE_TABLE_BYTES,MAX_ARCHIVE_TOTAL_BYTES};
