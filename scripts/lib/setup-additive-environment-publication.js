'use strict';
// Private additive publication prerequisite. Caller must hold the same-epoch
// exclusive maintenance lease; filesystem checks are not an arbitrary-writer CAS.
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const invalid=()=>Object.assign(Error('Private additive publication unavailable'),{code:'SETUP_ADDITIVE_PUBLICATION_INVALID'});
function dir(p,privateOnly){const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&(privateOnly?0o077:0o022)))throw invalid();return s;}
function syncDir(p){const fd=fs.openSync(p,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function exists(p){try{fs.lstatSync(p);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
function read(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const a=fs.fstatSync(fd);if(!a.isFile()||a.uid!==process.getuid()||(a.mode&0o777)!==0o600||a.nlink!==1||!Number.isSafeInteger(a.size)||a.size<0||a.size>3*1024*1024)throw invalid();const bytes=Buffer.alloc(a.size);let offset=0;while(offset<bytes.length){const count=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!count)throw invalid();offset+=count;}fs.fsyncSync(fd);const b=fs.fstatSync(fd),n=fs.lstatSync(p);if(bytes.length!==a.size||a.dev!==n.dev||a.ino!==n.ino||n.isSymbolicLink()||a.mode!==b.mode||a.uid!==b.uid||b.nlink!==1||a.size!==b.size||a.mtimeMs!==b.mtimeMs||a.ctimeMs!==b.ctimeMs||n.mode!==b.mode||n.uid!==b.uid||n.nlink!==1)throw invalid();return bytes;}finally{fs.closeSync(fd);}}
function create(p,bytes){const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDir(path.dirname(p));}
function windowsBindings({root,directory,id,operationId},dependencies){
 const {normalizePrivatePath}=require('./windows-private-state'),canonical=dependencies.realpath||fs.realpathSync;
 if(normalizePrivatePath(root)!==root||normalizePrivatePath(directory)!==directory||canonical(root)!==root||canonical(directory)!==directory||id!==createHash('sha256').update(root).digest('hex').slice(0,12)||typeof operationId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(operationId))throw invalid();
 const envPath=path.win32.join(root,'.env'),journal=path.win32.join(directory,`additive-environment-${operationId}.json`);
 const journalBinding={targetPath:journal,intentPath:journal+'.native-journal',operationId},environmentBinding={targetPath:envPath,intentPath:journal+'.native-environment',operationId};
 const names=[];
 for(const binding of [journalBinding,environmentBinding])for(const p of [binding.targetPath,binding.intentPath,binding.targetPath+`.owasp-ai-goat-${operationId}.stage`,binding.intentPath+'.original',binding.intentPath+'.result']){
  normalizePrivatePath(p);if(Buffer.from(p).toString()!==p)throw invalid();names.push(p.toUpperCase());
 }
 if(new Set(names).size!==names.length)throw invalid();
 return {envPath,journal,journalBinding,environmentBinding};
}
function prepareWindowsAdditive(options,retainedBytes,dependencies){
 const {root,directory,id,operationId,originalBytes,encodedAdditions}=options;
 const {MAX_FILE_BYTES}=require('./windows-private-state');
 if(!Buffer.isBuffer(originalBytes)||originalBytes.length>MAX_FILE_BYTES||typeof encodedAdditions!=='string'||encodedAdditions.includes('\0'))throw invalid();
 const original=Buffer.from(originalBytes),result=Buffer.concat([original,Buffer.from((encodedAdditions&&original.length&&original.at(-1)!==10?'\n':'')+encodedAdditions)]);
 if(result.length>MAX_FILE_BYTES)throw invalid();
 const {envPath,journal,journalBinding,environmentBinding}=windowsBindings(options,dependencies);
 const bytes=Buffer.from(JSON.stringify({version:1,kind:'additive',root,directory,id,operationId,envPath,original:original.toString('base64'),result:result.toString('base64')})+'\n');
 // Preserve the exact existing journal wire format. Windows admits its packed
 // JSON only up to the native 1MiB bound, before creating any artifact.
 if(bytes.length>MAX_FILE_BYTES||retainedBytes&&(!Buffer.isBuffer(retainedBytes)||!bytes.equals(retainedBytes)))throw invalid();
 const native=dependencies.privateState||require('./windows-private-state'),publication=dependencies.publication||require('./windows-private-publication'),present=dependencies.exists||exists;
 native.inspectPrivateDirectory(directory);
 const journalExists=present(journal);
 if(journalExists){if(!native.readPrivateFile(journal).equals(bytes))throw invalid();}
 else if(retainedBytes||!native.readPrivateWorkspaceFile(envPath).equals(original)||present(path.win32.join(root,'.env.upgrade')))throw invalid();
 // Publishing the journal through a separate retained intent also reflushes
 // a complete journal left by an interrupted/failed flush. A legacy named
 // journal without this native authority is never silently adopted.
 const preparedJournal=publication.preparePrivatePublication({...journalBinding,originalBytes:null,resultBytes:bytes});
 const matches=(actual,expected,size)=>actual.intentSha256===expected.intentSha256&&actual.size===size&&actual.identity.volumeSerial===expected.identity.volumeSerial&&actual.identity.fileId===expected.identity.fileId;
 const durableJournal=publication.publishPrivatePublication(journalBinding);
 if(durableJournal.state!=='committed'||!matches(durableJournal,preparedJournal,bytes.length)||!native.readPrivateFile(journal).equals(bytes))throw invalid();
 const prepared=publication.preparePrivatePublication({...environmentBinding,originalBytes:original,resultBytes:result});
 if(prepared.size!==result.length)throw invalid();
 return Object.freeze({get resultBytes(){return Buffer.from(result);},publish(){try{
  native.inspectPrivateDirectory(directory);
  if(!native.readPrivateFile(journal).equals(bytes)||!matches(publication.inspectPrivatePublication(journalBinding),preparedJournal,bytes.length)||!matches(publication.inspectPrivatePublication(environmentBinding),prepared,result.length))throw invalid();
  const committed=publication.publishPrivatePublication(environmentBinding);
  if(committed.state!=='committed'||!matches(committed,prepared,result.length)||!native.readPrivateFile(journal).equals(bytes))throw invalid();
 }catch{throw invalid();}}});
}
function prepareAdditiveEnvironmentPublication({root,directory,id,operationId,originalBytes,encodedAdditions}={},retainedBytes,dependencies={}){
 try{
  if((dependencies.platform||process.platform)==='win32')return prepareWindowsAdditive({root,directory,id,operationId,originalBytes,encodedAdditions},retainedBytes,dependencies);
  if(typeof root!=='string'||typeof directory!=='string'||!path.isAbsolute(root)||!path.isAbsolute(directory)||fs.realpathSync(root)!==root||fs.realpathSync(directory)!==directory||id!==createHash('sha256').update(root).digest('hex').slice(0,12)||typeof operationId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(operationId)||!Buffer.isBuffer(originalBytes)||originalBytes.length>1024*1024||typeof encodedAdditions!=='string'||encodedAdditions.includes('\0'))throw invalid();
  const original=Buffer.from(originalBytes),result=Buffer.concat([original,Buffer.from((encodedAdditions&&original.length&&original.at(-1)!==10?'\n':'')+encodedAdditions)]);if(result.length>1024*1024)throw invalid();
  const roots=[dir(root,false),dir(directory,true)],envPath=path.join(root,'.env'),stage=path.join(root,'.env.upgrade'),journal=path.join(directory,`additive-environment-${operationId}.json`);
  const verify=()=>{for(const [i,p]of [root,directory].entries()){const s=dir(p,i===1);if(s.dev!==roots[i].dev||s.ino!==roots[i].ino)throw invalid();}};
  const bytes=Buffer.from(JSON.stringify({version:1,kind:'additive',root,directory,id,operationId,envPath,original:original.toString('base64'),result:result.toString('base64')})+'\n');
  verify();if(!exists(journal)){if(retainedBytes)throw invalid();if(!read(envPath).equals(original)||exists(stage))throw invalid();create(journal,bytes);}
  if(retainedBytes&&!bytes.equals(retainedBytes))throw invalid();if(!read(journal).equals(bytes))throw invalid();syncDir(directory);
  const current=read(envPath);if(!current.equals(original)&&!current.equals(result))throw invalid();verify();
  return Object.freeze({get resultBytes(){return Buffer.from(result);},publish(){try{
   verify();if(!read(journal).equals(bytes))throw invalid();const now=read(envPath);
   if(now.equals(result)){
    if(exists(stage)){if(!read(stage).equals(result))throw invalid();fs.unlinkSync(stage);}syncDir(root);return;
   }
   if(!now.equals(original))throw invalid();
   if(exists(stage)){if(!read(stage).equals(result))throw invalid();}else create(stage,result);
   if(!read(stage).equals(result))throw invalid();verify();if(!read(journal).equals(bytes)||!read(envPath).equals(original))throw invalid();
   fs.renameSync(stage,envPath);syncDir(root);if(!read(envPath).equals(result))throw invalid();
  }catch{throw invalid();}}});
 }catch{throw invalid();}
}
module.exports={prepareAdditiveEnvironmentPublication};

// Read only an existing exact journal. The digest must come from the retained
// epoch binding, never from the journal being inspected. Returned bytes remain
// private; this helper does not acquire a lease or authorize recovery.
function readAdditiveEnvironmentPublication({root,directory,id,operationId,journalSha256}={},dependencies={}){
 try{
  if((dependencies.platform||process.platform)==='win32')return readWindowsAdditive({root,directory,id,operationId,journalSha256},dependencies);
  if(typeof journalSha256!=='string'||!/^[a-f0-9]{64}$/.test(journalSha256)||typeof directory!=='string'||!path.isAbsolute(directory)||fs.realpathSync(directory)!==directory||typeof operationId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(operationId))throw invalid();
  dir(directory,true);
  const journal=path.join(directory,`additive-environment-${operationId}.json`),bytes=read(journal);
  if(createHash('sha256').update(bytes).digest('hex')!==journalSha256)throw invalid();
  const doc=JSON.parse(bytes.toString('utf8'));
  if(!doc||Array.isArray(doc)||Object.keys(doc).sort().join(',')!=='directory,envPath,id,kind,operationId,original,result,root,version'||doc.version!==1||doc.kind!=='additive'||doc.root!==root||doc.directory!==directory||doc.id!==id||doc.operationId!==operationId||doc.envPath!==path.join(root,'.env'))throw invalid();
  const decode=value=>{if(typeof value!=='string')throw invalid();const decoded=Buffer.from(value,'base64');if(decoded.length>1024*1024||decoded.toString('base64')!==value)throw invalid();return decoded;};
  const original=decode(doc.original),result=decode(doc.result);
  if(result.length<original.length||!result.subarray(0,original.length).equals(original))throw invalid();
  const suffix=result.subarray(original.length),text=suffix.toString('utf8');
  if(!Buffer.from(text).equals(suffix))throw invalid();
  // The existing writer inserts one separator only when needed. Strip that
  // separator to recover the exact additions argument, then require byte parity.
  let additions=text;
  if(suffix.length&&original.length&&original.at(-1)!==10){if(!text.startsWith('\n'))throw invalid();additions=text.slice(1);if(!additions)throw invalid();}
  const publication=prepareAdditiveEnvironmentPublication({root,directory,id,operationId,originalBytes:original,encodedAdditions:additions},bytes);
  if(!publication.resultBytes.equals(result)||!read(journal).equals(bytes))throw invalid();
  return Object.freeze({journalSha256,publicationId:operationId,get originalBytes(){return Buffer.from(original);},get resultBytes(){return publication.resultBytes;},publish:publication.publish});
 }catch{throw invalid();}
}
module.exports.readAdditiveEnvironmentPublication=readAdditiveEnvironmentPublication;

function readWindowsAdditive({root,directory,id,operationId,journalSha256},dependencies){
 if(typeof journalSha256!=='string'||!/^[a-f0-9]{64}$/.test(journalSha256))throw invalid();
 const {envPath,journal}=windowsBindings({root,directory,id,operationId},dependencies),native=dependencies.privateState||require('./windows-private-state'),{MAX_FILE_BYTES}=require('./windows-private-state');
 native.inspectPrivateDirectory(directory);
 const bytes=native.readPrivateFile(journal);
 // The externally retained epoch digest must pass before any native intent is
 // prepared or any journal/environment publication is attempted.
 if(!Buffer.isBuffer(bytes)||bytes.length>MAX_FILE_BYTES||createHash('sha256').update(bytes).digest('hex')!==journalSha256)throw invalid();
 const doc=JSON.parse(bytes.toString('utf8'));
 if(!doc||Array.isArray(doc)||Object.keys(doc).sort().join(',')!=='directory,envPath,id,kind,operationId,original,result,root,version'||doc.version!==1||doc.kind!=='additive'||doc.root!==root||doc.directory!==directory||doc.id!==id||doc.operationId!==operationId||doc.envPath!==envPath)throw invalid();
 const decode=value=>{if(typeof value!=='string'||value.length>Math.ceil(MAX_FILE_BYTES/3)*4)throw invalid();const decoded=Buffer.from(value,'base64');if(decoded.length>MAX_FILE_BYTES||decoded.toString('base64')!==value)throw invalid();return decoded;};
 const original=decode(doc.original),result=decode(doc.result);
 if(result.length<original.length||!result.subarray(0,original.length).equals(original))throw invalid();
 const suffix=result.subarray(original.length),text=suffix.toString('utf8');if(!Buffer.from(text).equals(suffix))throw invalid();
 let additions=text;if(suffix.length&&original.length&&original.at(-1)!==10){if(!text.startsWith('\n'))throw invalid();additions=text.slice(1);if(!additions)throw invalid();}
 const publication=prepareAdditiveEnvironmentPublication({root,directory,id,operationId,originalBytes:original,encodedAdditions:additions},bytes,dependencies);
 if(!publication.resultBytes.equals(result)||!native.readPrivateFile(journal).equals(bytes))throw invalid();
 return Object.freeze({journalSha256,publicationId:operationId,get originalBytes(){return Buffer.from(original);},get resultBytes(){return publication.resultBytes;},publish:publication.publish});
}
