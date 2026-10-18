'use strict';
// Native private bytes only. The provisioning owner decides whether DDL may
// run; a retained filesystem transition never authorizes replay of DDL.
// Same-user arbitrary mutation and privileged identities retain the existing
// native helpers' trust boundary. No transition artifact is deleted here.
const path=require('node:path'),{createHash}=require('node:crypto');
const windowsPrivateState=require('./windows-private-state');
const windowsPrivatePublication=require('./windows-private-publication');
const {MAX_FILE_BYTES,normalizePrivatePath}=windowsPrivateState;
const denied=()=>Object.assign(Error('Windows provisioning journal unavailable'),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});
const keys=(value,expected)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===expected.slice().sort().join(',');
function createWindowsProvisioningJournal({platform=process.platform,privateState=windowsPrivateState,publication=windowsPrivatePublication}={}){
 function admitted(filePath){
  if(platform!=='win32')throw denied();
  const targetPath=normalizePrivatePath(filePath),parent=normalizePrivatePath(path.win32.dirname(targetPath));
  if(Buffer.from(targetPath).toString()!==targetPath)throw denied();
  // Admission reserves the fixed-length native names before a caller connects
  // to PostgreSQL. No payload-dependent transition name can exceed these.
  const reservedId='00000000-0000-4000-8000-000000000000';
  normalizePrivatePath(targetPath+`.dvaia-${reservedId}.stage`);
  normalizePrivatePath(path.win32.join(parent,`provisioning-${reservedId}.intent.result`));
  return {targetPath,parent};
 }
 function bytes(value){if(!Buffer.isBuffer(value)||value.length>MAX_FILE_BYTES)throw denied();return Buffer.from(value);}
 function transition(filePath,original,result){
  const {targetPath,parent}=admitted(filePath);
  // Length frames keep path/payload boundaries unambiguous. CREATE and UPDATE
  // have separate domains; identical retries retain exactly the same intent.
  const digest=createHash('sha256').update('dvaia:windows-provisioning-journal:1\0');
  const frame=value=>{const length=Buffer.alloc(4);length.writeUInt32BE(value.length);digest.update(length).update(value);};
  frame(Buffer.from(targetPath));digest.update(original===null?'create\0':'update\0');if(original!==null)frame(original);frame(result);
  const hash=digest.digest('hex'),operationId=hash.slice(0,8)+'-'+hash.slice(8,12)+'-4'+hash.slice(13,16)+'-'+((parseInt(hash[16],16)&3)|8).toString(16)+hash.slice(17,20)+'-'+hash.slice(20,32);
  const intentPath=normalizePrivatePath(path.win32.join(parent,`provisioning-${operationId}.intent`));
  const artifacts=[targetPath,intentPath,targetPath+`.dvaia-${operationId}.stage`,intentPath+'.original',intentPath+'.result'];
  for(const artifact of artifacts)normalizePrivatePath(artifact);
  if(new Set(artifacts.map(p=>p.toUpperCase())).size!==artifacts.length)throw denied();
  privateState.inspectPrivateDirectory(parent);
  const binding={targetPath,intentPath,operationId};
  const prepared=publication.preparePrivatePublication({...binding,originalBytes:original,resultBytes:result});
  const committed=publication.publishPrivatePublication(binding);
  if(committed.state!=='committed'||committed.intentSha256!==prepared.intentSha256||prepared.size!==result.length||committed.size!==result.length||committed.identity.volumeSerial!==prepared.identity.volumeSerial||committed.identity.fileId!==prepared.identity.fileId)throw denied();
  const observed=privateState.readPrivateFile(targetPath);
  if(!Buffer.isBuffer(observed)||observed.length>MAX_FILE_BYTES||!observed.equals(result))throw denied();
  return committed;
 }
 return Object.freeze({
  inspectDestination(options){try{if(!keys(options,['filePath']))throw denied();const {parent}=admitted(options.filePath);return privateState.inspectPrivateDirectory(parent);}catch{throw denied();}},
  createJournal(options){try{if(!keys(options,['filePath','bytes']))throw denied();return transition(options.filePath,null,bytes(options.bytes));}catch{throw denied();}},
  readJournal(options){try{if(!keys(options,['filePath']))throw denied();const {targetPath}=admitted(options.filePath),observed=privateState.readPrivateFile(targetPath);if(!Buffer.isBuffer(observed)||observed.length>MAX_FILE_BYTES)throw denied();return Buffer.from(observed);}catch{throw denied();}},
  updateJournal(options){try{if(!keys(options,['filePath','originalBytes','resultBytes']))throw denied();return transition(options.filePath,bytes(options.originalBytes),bytes(options.resultBytes));}catch{throw denied();}},
 });
}
module.exports={...createWindowsProvisioningJournal(),createWindowsProvisioningJournal,MAX_FILE_BYTES};
