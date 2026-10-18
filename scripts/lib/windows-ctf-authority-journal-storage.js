'use strict';
// Filesystem storage only; no database lease, intent, schema or replay authority.
// Callers hold their exclusive maintenance lease and validate retained DB lock
// intents before reclaim/publication. Strict CREATE_NEW plus file-buffer flush
// provides live lock exclusion. Namespace durability is not POSIX directory
// fsync: reboot may lose a lock name, but the dirty DB epoch must still refuse
// unmanaged recovery. Failed/ambiguous creates and publications remain retained;
// identical lock bytes never authorize reacquisition of an existing name.
// Same-SID arbitrary mutation and privileged identities remain trusted.
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const privateStateDefault=require('./windows-private-state');
const publicationDefault=require('./windows-private-publication');
const MAX_JOURNAL_BYTES=8192,MAX_LOCK_BYTES=4096;
const fail=()=>Object.assign(Error('Windows CTF journal storage unavailable.'),{code:'WINDOWS_CTF_AUTHORITY_JOURNAL_DENIED'});
const exact=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const validIdentity=value=>exact(value,['volumeSerial','fileId'])&&Number.isInteger(value.volumeSerial)&&value.volumeSerial>=0&&value.volumeSerial<=0xffffffff&&typeof value.fileId==='string'&&/^[a-f0-9]{16}$/.test(value.fileId);
const sameIdentity=(a,b)=>a.volumeSerial===b.volumeSerial&&a.fileId===b.fileId;
function createWindowsCtfAuthorityJournalStorage({directory,filesystemPlatform=process.platform,privateState=privateStateDefault,publication=publicationDefault,fileSystem=fs}={}){
 try{
  if(filesystemPlatform!=='win32')throw fail();
  const normalize=privateStateDefault.normalizePrivatePath;
  directory=normalize(directory);
  if(Buffer.from(directory).toString()!==directory)throw fail();
  const journalPath=normalize(path.win32.join(directory,'ctf-authority.json')),lockPath=normalize(journalPath+'.lock');
  // Reserve every native transition name before acquiring any lock.
  const reserveId='00000000-0000-4000-8000-000000000000';
  normalize(journalPath+`.dvaia-${reserveId}.stage`);
  normalize(path.win32.join(directory,`ctf-journal-${reserveId}.intent.original`));
  const receipts=new WeakMap();let initialDirectory;
  function verifyDirectory(){
   try{
    const observed=privateState.inspectPrivateDirectory(directory);
    if(!exact(observed,['path','size','identity'])||observed.path!==directory||observed.size!==null||!validIdentity(observed.identity))throw fail();
    if(initialDirectory&&!sameIdentity(observed.identity,initialDirectory))throw fail();
    if(!initialDirectory)initialDirectory={...observed.identity};
    return observed;
   }catch{throw fail();}
  }
  function bounded(bytes,limit){if(!Buffer.isBuffer(bytes)||bytes.length>limit)throw fail();return Buffer.from(bytes);}
  function present(file){try{fileSystem.lstatSync(file);return true;}catch(error){if(error.code==='ENOENT')return false;throw fail();}}
  function snapshot(file,limit){
   const value=privateState.readAndFlushPrivateFileSnapshot(file),bytes=bounded(value?.bytes,limit);
   if(value.path!==file||value.size!==bytes.length||!validIdentity(value.identity))throw fail();
   return{path:file,bytes,identity:{...value.identity}};
  }
  function lockState(receipt){const state=receipts.get(receipt);if(!state||!state.active)throw fail();return state;}
  function assertLock(receipt){
   try{verifyDirectory();const expected=lockState(receipt),actual=snapshot(lockPath,MAX_LOCK_BYTES);if(!sameIdentity(actual.identity,expected.identity)||!actual.bytes.equals(expected.bytes))throw fail();}
   catch{throw fail();}
  }
  function deleteSnapshot(observed){
   verifyDirectory();
   const deleted=privateState.deleteMatchingPrivateFile(lockPath,observed.bytes,observed.identity);
   if(deleted?.deleted!==true||deleted.path!==lockPath||deleted.size!==observed.bytes.length||!validIdentity(deleted.identity)||!sameIdentity(deleted.identity,observed.identity))throw fail();
   verifyDirectory();
   if(present(lockPath))throw fail();
  }
  function transition(original,result){
   const digest=createHash('sha256').update('dvaia:windows-ctf-authority-journal:1\0');
   const frame=bytes=>{const n=Buffer.alloc(4);n.writeUInt32BE(bytes.length);digest.update(n).update(bytes);};
   frame(Buffer.from(journalPath));digest.update(original===null?'create\0':'replace\0');if(original!==null)frame(original);frame(result);
   const hash=digest.digest('hex'),operationId=hash.slice(0,8)+'-'+hash.slice(8,12)+'-4'+hash.slice(13,16)+'-'+((parseInt(hash[16],16)&3)|8).toString(16)+hash.slice(17,20)+'-'+hash.slice(20,32);
   return{targetPath:journalPath,intentPath:normalize(path.win32.join(directory,`ctf-journal-${operationId}.intent`)),operationId};
  }
  return Object.freeze({
   verifyDirectory,
   ensureDirectory(){
    try{
     if(initialDirectory)return verifyDirectory();
     const admitted=privateState.ensurePrivateDirectory(directory),observed=verifyDirectory();
     if(admitted?.path!==directory||admitted.size!==null||!validIdentity(admitted.identity)||!sameIdentity(admitted.identity,observed.identity))throw fail();
     return observed;
    }catch{throw fail();}
   },
   readJournal(){try{verifyDirectory();if(!present(journalPath))return null;const value=snapshot(journalPath,MAX_JOURNAL_BYTES);verifyDirectory();return Buffer.from(value.bytes);}catch{throw fail();}},
   createLock(bytes){
    try{
     bytes=bounded(bytes,MAX_LOCK_BYTES);verifyDirectory();
     // Never use the retryable publication primitive for lock acquisition.
     const created=privateState.createPrivateFile(lockPath,bytes);
     if(created?.path!==lockPath||created.size!==bytes.length||!validIdentity(created.identity))throw fail();
     const observed=snapshot(lockPath,MAX_LOCK_BYTES);
     if(!observed.bytes.equals(bytes)||!sameIdentity(observed.identity,created.identity))throw fail();
     verifyDirectory();const receipt=Object.freeze({});receipts.set(receipt,{...observed,active:true});return receipt;
    }catch{throw fail();}
   },
   assertLock,
   releaseLock(receipt){
    try{assertLock(receipt);const state=lockState(receipt);state.active=false;deleteSnapshot(state);}
    catch{throw fail();} // A failed/ambiguous release cannot be retried using this capability.
   },
   async reclaimLock(expectedPredecessorBuffers,verifyCurrentCallback){
    try{
     if(!Array.isArray(expectedPredecessorBuffers)||expectedPredecessorBuffers.length<1||expectedPredecessorBuffers.length>64||typeof verifyCurrentCallback!=='function')throw fail();
     const expected=expectedPredecessorBuffers.map(bytes=>bounded(bytes,MAX_LOCK_BYTES));
     verifyDirectory();if(!present(lockPath))return false;
     const observed=snapshot(lockPath,MAX_LOCK_BYTES);if(!expected.some(bytes=>bytes.equals(observed.bytes)))throw fail();
     await verifyCurrentCallback();deleteSnapshot(observed);return true;
    }catch{throw fail();}
   },
   async publishJournal(options,verifyOwnerCallback){
    try{
     if(!exact(options,['originalBytes','resultBytes'])||typeof verifyOwnerCallback!=='function')throw fail();
     const original=options.originalBytes===null?null:bounded(options.originalBytes,MAX_JOURNAL_BYTES),result=bounded(options.resultBytes,MAX_JOURNAL_BYTES);
     verifyDirectory();await verifyOwnerCallback();verifyDirectory();
     const binding=transition(original,result);
     const prepared=publication.preparePrivatePublication({...binding,originalBytes:original,resultBytes:result});
     verifyDirectory();await verifyOwnerCallback();verifyDirectory();
     const committed=publication.publishPrivatePublication(binding);
     if(committed.state!=='committed'||prepared.size!==result.length||committed.size!==result.length||committed.intentSha256!==prepared.intentSha256||!validIdentity(prepared.identity)||!validIdentity(committed.identity)||!sameIdentity(committed.identity,prepared.identity))throw fail();
     const observed=snapshot(journalPath,MAX_JOURNAL_BYTES);
     if(!observed.bytes.equals(result)||!sameIdentity(observed.identity,committed.identity))throw fail();
     verifyDirectory();await verifyOwnerCallback();verifyDirectory();return committed;
    }catch{throw fail();}
   },
  });
 }catch{throw fail();}
}
module.exports={createWindowsCtfAuthorityJournalStorage,MAX_JOURNAL_BYTES,MAX_LOCK_BYTES};
