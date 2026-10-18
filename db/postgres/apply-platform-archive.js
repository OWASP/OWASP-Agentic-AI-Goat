#!/usr/bin/env node
'use strict';
const fs=require('node:fs/promises');
const {preparePlatformApply}=require('./prepare-platform-apply');
const {createPool}=require('../../server/database/postgres');
const {importPlatformIdentity}=require('./import-platform-identity');
function argumentsFor(argv){
 const options={apply:false,databaseEnv:'IDENTITY_MIGRATION_DATABASE_URL'},seen=new Set();
 const keys={'--archive':'archive','--review':'reviewFile','--database-env':'databaseEnv'};
 for(let i=0;i<argv.length;i++){
  const flag=argv[i];if(seen.has(flag))throw new Error('INVALID_APPLY_ARGUMENTS');seen.add(flag);
  if(flag==='--apply'){options.apply=true;continue;}
  const key=Object.hasOwn(keys,flag)?keys[flag]:null;if(!key||!argv[i+1]||argv[i+1].startsWith('--'))throw new Error('INVALID_APPLY_ARGUMENTS');options[key]=argv[++i];
 }
 if(!options.archive||!options.reviewFile||! /^[A-Z][A-Z0-9_]*MIGRATION_DATABASE_URL$/.test(options.databaseEnv))throw new Error('INVALID_APPLY_ARGUMENTS');
 return options;
}
async function applyPlatformArchive(options,deps={}){
 if(typeof options.apply!=='boolean')throw new Error('INVALID_APPLY_ARGUMENTS');
 const file=await fs.open(options.reviewFile,require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW);
 let review;
 try{const stat=await file.stat();if(!stat.isFile()||stat.size>1048576)throw new Error('INVALID_REVIEW_FILE');review=JSON.parse(await file.readFile('utf8'));}finally{await file.close();}
 const prepared=await(deps.prepare||preparePlatformApply)({archive:options.archive,review});
 const pool=(deps.createPool||createPool)(process.env,options.databaseEnv);
 try{
  const result=await(deps.importer||importPlatformIdentity)(pool,prepared.inputs,{dryRun:!options.apply});
  return{...prepared.report,applied:result.applied,dryRun:result.dryRun,nativeConstraintsChecked:result.nativeConstraintsChecked};
 }finally{await pool.end();}
}
if(require.main===module){
 Promise.resolve().then(()=>applyPlatformArchive(argumentsFor(process.argv.slice(2)))).then(result=>console.log(JSON.stringify(result))).catch(error=>{
  const code=[error.code,error.message].find(value=>typeof value==='string'&&/^[A-Z][A-Z0-9_]{0,100}$/.test(value));
  console.error(JSON.stringify({error:code||'PLATFORM_ARCHIVE_APPLY_FAILED'}));process.exitCode=1;
 });
}
module.exports={argumentsFor,applyPlatformArchive};
