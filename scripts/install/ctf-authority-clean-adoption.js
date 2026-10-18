'use strict';
// Clean-state compatibility transition, before a prospective dirty epoch.
// Database activation remains authority. Never invent an activation, advance a
// checkpoint, erase the predecessor, or adopt an incomplete legacy journal.
const fs=require('node:fs'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
const {validateCtfAuthorityJournal}=require('./ctf-authority-journal');
const {validateCtfDeliveryTuple}=require('../../server/database/postgres/ctfDeliveryActivation');
const failure=()=>Object.assign(Error('Completed legacy CTF journal adoption unavailable'),{code:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const encode=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
function transition(originalBytes,binding,activation){
 if(!Buffer.isBuffer(originalBytes)||originalBytes.length>8192)throw failure();
 let journal;try{journal=validateCtfAuthorityJournal(JSON.parse(originalBytes));}catch{throw failure();}
 if(journal.version!==1||journal.phase!=='complete'||!encode(journal).equals(originalBytes)
   ||JSON.stringify(journal.binding)!==JSON.stringify(binding))throw failure();
 let current;try{current=validateCtfDeliveryTuple(activation);}catch{throw failure();}
 if(current.activation_id!==journal.activationId||current.bootstrap_operation_id!==journal.bootstrapId
   ||current.identity_store_id!==binding.identityStoreId||current.ctf_store_id!==binding.ctfStoreId
   ||current.source_revision!==journal.checkpoint.sourceRevision
   ||current.manifest_sha256!==journal.checkpoint.manifestSha256
   ||current.authority_sha256!==journal.checkpoint.authoritySha256)throw failure();
 return encode({...journal,version:2});
}
async function adoptLegacyCtfAuthorityJournal({directory,originalBytes,binding,activation,launch,lease}){
 const issuer=require('../../server/services/applicationMaintenanceExecutionAdmission');
 issuer.assertOwnedLaunch(launch,lease);
 if(directory!==launch.installation.directory)throw failure();
 const clean=await lease.assertClean();
 const checkAuthority=()=>{issuer.assertOwnedLaunch(launch,lease);launch.installation.assertCurrent();};
 checkAuthority();const resultBytes=transition(originalBytes,binding,activation);
 const names=process.platform==='win32'?path.win32:path;
 const target=names.join(directory,'ctf-authority.json');
 const predecessor=names.join(directory,`ctf-authority-v1-${hash(originalBytes)}.json`);
 const caps=require('../../server/services/applicationMaintenanceInprocessAdmission');
 const read=file=>caps.privateRead(file);
 const present=file=>{try{fs.lstatSync(file);return true;}catch(error){if(error.code==='ENOENT')return false;throw failure();}};
 const lock=target+'.lock',lockBytes=Buffer.from(JSON.stringify({pid:process.pid})+'\n');
 const windows=process.platform==='win32';let owner,lockStat,primary;
 const nativeStorage=windows?require('../lib/windows-ctf-authority-journal-storage')
   .createWindowsCtfAuthorityJournalStorage({directory,filesystemPlatform:process.platform}):null;
 const syncDirectory=()=>{const fd=fs.openSync(directory,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}};
 const assertLock=()=>{
   if(windows){nativeStorage.assertLock(owner);return;}
   const held=fs.fstatSync(owner),named=fs.lstatSync(lock);
   if(!held.isFile()||!named.isFile()||named.isSymbolicLink()||held.uid!==process.getuid()
     ||held.nlink!==1||(held.mode&0o777)!==0o600||named.dev!==lockStat.dev||named.ino!==lockStat.ino
     ||held.dev!==lockStat.dev||held.ino!==lockStat.ino||!read(lock).equals(lockBytes))throw failure();
 };
 const check=()=>{checkAuthority();assertLock();};
 // Use the same exclusive lock name and legacy PID bytes as the journal
 // writer. An absence observation cannot serialize a later publication.
 try{
   if(windows){nativeStorage.verifyDirectory();owner=nativeStorage.createLock(lockBytes);}
   else{owner=fs.openSync(lock,fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
     lockStat=fs.fstatSync(owner);fs.writeFileSync(owner,lockBytes);fs.fsyncSync(owner);syncDirectory();}
 }catch(error){
   // Ambiguous native creates retain their own lock. POSIX creation has an
   // exact held inode, so release only that inode if initialization failed.
   if(!windows&&owner!==undefined){try{const named=fs.lstatSync(lock);
     if(named.dev!==lockStat?.dev||named.ino!==lockStat?.ino||named.isSymbolicLink())throw failure();
     fs.unlinkSync(lock);syncDirectory();}finally{fs.closeSync(owner);}}
   throw failure();
 }
 try{
 const assertFiles=()=>{check();
   const bytes=read(target);if(!bytes.equals(originalBytes)&&!bytes.equals(resultBytes))throw failure();return bytes;};
 const before=assertFiles();
 if(before.equals(resultBytes)&&!present(predecessor))throw failure();
 if(process.platform==='win32'){
   // Native publication retains original/result intent bytes and performs the
   // exact private-path CAS. No POSIX permission approximation on Windows.
   const native=require('../lib/windows-private-publication');
   const digest=hash(Buffer.concat([Buffer.from(directory),originalBytes,resultBytes]));
   const operationId=`${digest.slice(0,8)}-${digest.slice(8,12)}-4${digest.slice(13,16)}-8${digest.slice(17,20)}-${digest.slice(20,32)}`;
   const archiveBinding={targetPath:predecessor,intentPath:predecessor+'.adoption',operationId};
   if(present(predecessor)){if(!read(predecessor).equals(originalBytes))throw failure();}
   else{native.preparePrivatePublication({...archiveBinding,originalBytes:null,resultBytes:originalBytes});check();native.publishPrivatePublication(archiveBinding);}
   if(!read(predecessor).equals(originalBytes))throw failure();assertFiles();
   if(!before.equals(resultBytes)){
     const journalBinding={targetPath:target,intentPath:predecessor+'.publication',operationId};
     native.preparePrivatePublication({...journalBinding,originalBytes,resultBytes});check();native.publishPrivatePublication(journalBinding);
   }
 }else{
   // Link a fully flushed private temporary file for archive creation. A crash
   // can leave an unused temporary file, never a partially published archive.
   const publish=(targetPath,bytes,replace)=>{
     const temporary=names.join(directory,`.ctf-adoption-${randomUUID()}.tmp`);let fd;
     try{check();fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
       fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;assertFiles();
       if(replace){if(!read(predecessor).equals(originalBytes)||!read(target).equals(originalBytes))throw failure();fs.renameSync(temporary,targetPath);}
       else fs.linkSync(temporary,targetPath);
       if(!replace)fs.unlinkSync(temporary);syncDirectory();
     }finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temporary);}catch(error){if(error.code!=='ENOENT')throw error;}}
   };
   if(present(predecessor)){if(!read(predecessor).equals(originalBytes))throw failure();syncDirectory();}
   else publish(predecessor,originalBytes,false);
   if(!read(predecessor).equals(originalBytes))throw failure();
   if(!before.equals(resultBytes))publish(target,resultBytes,true);
 }
 check();if(!read(predecessor).equals(originalBytes)||!read(target).equals(resultBytes))throw failure();
 const after=await lease.assertClean();check();
 if(after.epoch!==clean.epoch||after.installationId!==clean.installationId)throw failure();
 return Object.freeze({adopted:true,originalSha256:hash(originalBytes),resultBytes:Buffer.from(resultBytes)});
 }catch(error){primary=error;throw error;}finally{
   const errors=[];
   try{assertLock();if(windows)nativeStorage.releaseLock(owner);else{fs.unlinkSync(lock);syncDirectory();}}
   catch(error){errors.push(error);}
   if(!windows)try{fs.closeSync(owner);}catch(error){errors.push(error);}
   if(errors.length)throw new AggregateError([...(primary?[primary]:[]),...errors],'CTF journal adoption/cleanup failed');
 }
}
module.exports={adoptLegacyCtfAuthorityJournal};
