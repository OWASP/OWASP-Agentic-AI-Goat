'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');

function createLegacyChallengeOwnerCleanup({store,uploadRoot=path.resolve(__dirname,'../uploads'),fileSystem=fs,lifecycle}={}){
 if(typeof store?.destroyOwner!=='function'||typeof uploadRoot!=='string'||!path.isAbsolute(uploadRoot)
   ||typeof fileSystem?.lstat!=='function'||typeof fileSystem?.unlink!=='function')throw new TypeError('Legacy challenge store, upload root and filesystem required');
 const root=path.resolve(uploadRoot);
 async function removeFile(value,owner){
  if(typeof value!=='string'||!value.length)throw new Error('Invalid owned upload path');
  const target=path.resolve(value);
  const relative=path.relative(root,target),parts=relative.split(path.sep);
  const historical=parts.length===1&&parts[0]&&!parts[0].startsWith('..');
  const managed=parts.length===4&&parts[0]==='managed'&&parts[1]===String(owner)&&parts.every(part=>part&&part!=='.'&&part!=='..');
  if(!historical&&!managed)throw new Error('Owned upload escaped the managed root');
  let stat;
  try{stat=await fileSystem.lstat(target);}catch(error){if(error?.code==='ENOENT')return false;throw error;}
  if(!stat.isFile()||stat.isSymbolicLink())throw new Error('Owned upload is not a regular managed file');
  await fileSystem.unlink(target);return true;
 }
 return Object.freeze({async destroyOwner(owner){return lifecycle
  ? lifecycle.destroyOwner(owner,(exactOwner,orphanPaths,intentIds)=>store.destroyOwner(exactOwner,{removeFile:value=>removeFile(value,exactOwner),orphanPaths,intentIds}))
  : store.destroyOwner(owner,{removeFile:value=>removeFile(value,owner)});}});
}

function getLegacyChallengeOwnerCleanup(){
 const store=require('../database/postgres/legacyChallengeDb');
 return createLegacyChallengeOwnerCleanup({store,uploadRoot:path.resolve(__dirname,'../uploads'),
  lifecycle:require('./legacyUploadLifecycle').getLegacyUploadLifecycle()});
}
module.exports={createLegacyChallengeOwnerCleanup,getLegacyChallengeOwnerCleanup};
