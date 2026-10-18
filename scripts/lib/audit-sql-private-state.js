'use strict';
// Native private bytes only; service prerequisites and activation remain with
// their callers. Denied reads never authorize creation or credential rotation.
const fs=require('node:fs'),path=require('node:path');
const privateDefaults=require('./windows-private-state'),journalDefaults=require('./windows-provisioning-journal');
const denied=()=>Object.assign(Error('Private owned audit configuration unavailable'),{code:'AUDIT_SQL_PRIVATE_CONFIGURATION_REQUIRED'});
function createAuditSqlPrivateState({filesystemPlatform=process.platform,fileSystem=fs,privateState=privateDefaults,journal=journalDefaults}={}){
 return Object.freeze({
  read(file,{allowMissing=false,workspace=false}={}){
   try{if(filesystemPlatform!=='win32')throw denied();const target=privateDefaults.normalizePrivatePath(file);
    try{fileSystem.lstatSync(target);}catch(error){if(allowMissing&&error.code==='ENOENT')return null;throw denied();}
    const bytes=workspace?privateState.readPrivateWorkspaceFile(target):privateState.readPrivateFile(target);
    if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>(workspace?1048576:16384))throw denied();return Buffer.from(bytes);
   }catch{throw denied();}
  },
  write(file,bytes,originalBytes){
   try{if(filesystemPlatform!=='win32'||!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>16384||originalBytes!==null&&(!Buffer.isBuffer(originalBytes)||originalBytes.length>16384))throw denied();
    const target=privateDefaults.normalizePrivatePath(file);privateState.inspectPrivateDirectory(path.win32.dirname(target));
    if(originalBytes===null)journal.createJournal({filePath:target,bytes});else journal.updateJournal({filePath:target,originalBytes,resultBytes:bytes});
    const observed=privateState.readPrivateFile(target);if(!Buffer.isBuffer(observed)||!observed.equals(bytes))throw denied();
   }catch{throw denied();}
  },
 });
}
module.exports={...createAuditSqlPrivateState(),createAuditSqlPrivateState};
