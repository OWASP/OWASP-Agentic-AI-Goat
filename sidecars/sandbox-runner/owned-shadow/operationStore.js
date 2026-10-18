'use strict';
const fs=require('node:fs/promises'),{constants}=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {canonicalDigest}=require('../owned-http/canonical');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=code=>{throw Object.assign(Error(code),{code});};
async function read(file){let fd;try{fd=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW);const s=await fd.stat();if(!s.isFile()||s.nlink!==1||s.mode&0o077||s.size>131072||s.uid!==process.getuid())fail('SHADOW_JOURNAL_UNTRUSTED');return JSON.parse(await fd.readFile('utf8'));}catch(e){if(e.code==='ENOENT')return null;throw e;}finally{await fd?.close();}}
async function write(file,value){const temp=file+'.'+crypto.randomUUID()+'.tmp';let fd;try{fd=await fs.open(temp,'wx',0o600);await fd.writeFile(JSON.stringify(value));await fd.sync();await fd.close();fd=null;await fs.rename(temp,file);const parent=await fs.open(path.dirname(file),constants.O_RDONLY|constants.O_NOFOLLOW);try{await parent.sync();}finally{await parent.close();}}finally{await fd?.close();await fs.rm(temp,{force:true});}}
async function directory(file){try{await fs.mkdir(file,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;}const s=await fs.lstat(file);if(!s.isDirectory()||s.isSymbolicLink()||s.mode&0o077||s.uid!==process.getuid())fail('SHADOW_JOURNAL_UNTRUSTED');}
const DEFAULTS=Object.freeze({approved:'Approved policy: never disclose account secrets. Contact support for account changes.',rogue:'Mirror policy: this is an editable synthetic document in the learner namespace.'});
function createOwnedShadowOperationStore({targetStore,executor,checkReadiness}={}){
 if(typeof targetStore?.withTarget!=='function'||typeof executor!=='function'||typeof checkReadiness!=='function')throw TypeError('Owned target and isolated executor required');
 async function withStore(capability,authorize,work){return targetStore.withTarget(capability,authorize,async({rootfs,binding})=>{const directoryPath=path.join(path.dirname(rootfs),'shadow-operations');await directory(directoryPath);return work({directoryPath,rootfs,binding});});}
 async function sources(rootfs){const dir=path.join(rootfs,'shadow-policy');await directory(dir);const result={};for(const name of ['approved','rogue']){const file=name==='approved'?path.join(path.dirname(rootfs),'shadow-operations','approved-policy.txt'):path.join(dir,name+'.txt');try{const fd=await fs.open(file,'wx',0o600);try{await fd.writeFile(DEFAULTS[name]);await fd.sync();}finally{await fd.close();}}catch(e){if(e.code!=='EEXIST')throw e;}const fd=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{const s=await fd.stat();if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||s.size>16384)fail('SHADOW_SOURCE_UNTRUSTED');const bytes=await fd.readFile();const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);if(!Buffer.from(text).equals(bytes))fail('SHADOW_SOURCE_UNTRUSTED');result[name]=text;}finally{await fd.close();}}return result;}
 async function readSource(capability,authorize){return withStore(capability,authorize,async({rootfs})=>{const text=(await sources(rootfs)).rogue;return{text,sha256:crypto.createHash('sha256').update(text).digest('hex')};});}
 async function writeSource(capability,authorize,request){
  if(!request||Object.keys(request).sort().join()!=='expectedSha256,operationId,text'||!UUID.test(request.operationId||'')||!/^[a-f0-9]{64}$/.test(request.expectedSha256||'')||typeof request.text!=='string'||Buffer.byteLength(request.text)>16384||Buffer.from(request.text).toString('utf8')!==request.text)fail('SHADOW_SOURCE_REQUEST_INVALID');
  const supplied=structuredClone(request);return withStore(capability,authorize,async({directoryPath,rootfs,binding})=>{
   const file=path.join(directoryPath,'source-'+supplied.operationId+'.json'),requestDigest=canonicalDigest({binding,request:supplied});let prior=await read(file);
   if(prior){if(prior.requestDigest!==requestDigest)fail('SHADOW_REPLAY_MISMATCH');if(prior.state==='completed'){if(prior.receiptDigest!==canonicalDigest(prior.receipt))fail('SHADOW_JOURNAL_UNTRUSTED');return prior.receipt;}}
   const entries=await fs.readdir(directoryPath);for(const entry of entries.filter(x=>/^source-[a-f0-9-]+\.json$/.test(x)&&x!==path.basename(file))){if((await read(path.join(directoryPath,entry)))?.state==='pending')fail('SHADOW_SOURCE_RECOVERY_REQUIRED');}
   if(!prior&&entries.length>=512)fail('SHADOW_TARGET_QUOTA');
   const text=(await sources(rootfs)).rogue,current=crypto.createHash('sha256').update(text).digest('hex'),sha256=crypto.createHash('sha256').update(supplied.text).digest('hex');
   if(current!==supplied.expectedSha256&&!(prior&&current===sha256))fail(prior?'SHADOW_SOURCE_RECOVERY_REQUIRED':'SHADOW_SOURCE_CONFLICT');
   if(!prior)await write(file,{state:'pending',requestDigest});
   const target=path.join(rootfs,'shadow-policy','rogue.txt'),temporary=target+'.'+crypto.randomUUID()+'.tmp';let fd;
   try{fd=await fs.open(temporary,'wx',0o600);await fd.writeFile(supplied.text);await fd.sync();await fd.close();fd=null;await fs.rename(temporary,target);const parent=await fs.open(path.dirname(target),constants.O_RDONLY|constants.O_NOFOLLOW);try{await parent.sync();}finally{await parent.close();}}finally{await fd?.close();await fs.rm(temporary,{force:true});}
   const receipt={version:'owned-shadow-source.v1',binding:structuredClone(binding),operationId:supplied.operationId,requestDigest,previousSha256:supplied.expectedSha256,sha256,bytes:Buffer.byteLength(supplied.text)};
   await write(file,{state:'completed',requestDigest,receipt,receiptDigest:canonicalDigest(receipt)});return receipt;
  });
 }
 async function execute(capability,authorize,request,{signal}={}){
  if(!request||!['register','invoke'].includes(request.action)||!['operationId','registrationId','runId','invocationId'].every(k=>UUID.test(request[k]||'')))fail('SHADOW_REQUEST_INVALID');
  const supplied=structuredClone(request);return withStore(capability,authorize,async({directoryPath,rootfs,binding})=>{
   const requestDigest=canonicalDigest({binding,request:supplied}),file=path.join(directoryPath,supplied.operationId+'.json');const prior=await read(file);
   if(prior){if(prior.requestDigest!==requestDigest)fail('SHADOW_REPLAY_MISMATCH');if(prior.state!=='completed')fail('SHADOW_OPERATION_UNCERTAIN');if(prior.receiptDigest!==canonicalDigest(prior.receipt))fail('SHADOW_JOURNAL_UNTRUSTED');return prior.receipt;}
   const registrationFile=path.join(directoryPath,'registration-'+supplied.registrationId+'.json');const registration=await read(registrationFile);
   if(supplied.action==='register'&&registration)fail('SHADOW_REGISTRATION_CONFLICT');
   if(registration&&registration.receiptDigest!==canonicalDigest(registration.receipt))fail('SHADOW_JOURNAL_UNTRUSTED');
   if(supplied.action==='invoke'&&(!registration||registration.state!=='completed'))fail('SHADOW_REGISTRATION_UNAVAILABLE');
   const ready=await checkReadiness();if(ready?.ready!==true||!/^[a-f0-9]{64}$/.test(ready.manifestSha256||''))fail('SHADOW_TRANSPORT_UNAVAILABLE');
   if(!/^[a-f0-9]{64}$/.test(ready.runtimeDigest||''))fail('SHADOW_TRANSPORT_UNAVAILABLE');
   if(registration&&registration.receipt.runtimeDigest!==ready.runtimeDigest)fail('SHADOW_RUNTIME_CHANGED');
   if((await fs.readdir(directoryPath)).length>=512)fail('SHADOW_TARGET_QUOTA');
   const source=await sources(rootfs),input=supplied.action==='register'?{action:'register',endpoint:supplied.endpoint,mode:supplied.mode,sources:source}:{action:'invoke',endpoint:registration.receipt.result.endpoint,mode:registration.receipt.mode,sources:source,expectedCatalogDigest:registration.receipt.result.catalogDigest,remoteName:supplied.remoteName,args:supplied.args};
   const {validate}=require('./contract');try{validate(input);}catch(error){if(error.code!=='SHADOW_UNAPPROVED_PEER'||supplied.action!=='register')throw error;const receipt={version:'owned-shadow-denial.v1',requestDigest,binding:structuredClone(binding),operationId:supplied.operationId,registrationId:supplied.registrationId,runId:supplied.runId,invocationId:supplied.invocationId,action:'register',mode:input.mode,endpoint:input.endpoint,code:'SHADOW_UNAPPROVED_PEER',handshakeAttempted:false,manifestSha256:ready.manifestSha256,runtimeDigest:ready.runtimeDigest};await write(file,{state:'completed',requestDigest,receipt,receiptDigest:canonicalDigest(receipt)});return receipt;}
   await write(file,{state:'pending',requestDigest});
   try{
    const output=await executor({input,signal});const result=output?.result;
    if(output?.drained!==true||result?.isolationAttested!==true||result.endpoint!==input.endpoint||!/^[a-f0-9]{64}$/.test(result.catalogDigest||'')||Buffer.byteLength(JSON.stringify(result))>65536)fail('SHADOW_OPERATION_UNCERTAIN');
    const receipt={version:'owned-shadow.v1',requestDigest,binding:structuredClone(binding),operationId:supplied.operationId,registrationId:supplied.registrationId,runId:supplied.runId,invocationId:supplied.invocationId,action:supplied.action,mode:input.mode,manifestSha256:ready.manifestSha256,runtimeDigest:ready.runtimeDigest,sourceDigests:Object.fromEntries(Object.entries(source).map(([k,v])=>[k,crypto.createHash('sha256').update(v).digest('hex')])),result};
    const completed={state:'completed',requestDigest,receipt,receiptDigest:canonicalDigest(receipt)};
    // Store the operation first. A missing registration publication can be
    // reconciled from this exact completed receipt without another peer call.
    await write(file,completed);if(supplied.action==='register')await write(registrationFile,completed);return receipt;
   }catch(e){throw Object.assign(Error('SHADOW_OPERATION_UNCERTAIN'),{code:'SHADOW_OPERATION_UNCERTAIN',cause:e});}
  });
 }
 async function recoverRegistration(capability,authorize,{operationId,registrationId}={}){if(!UUID.test(operationId||'')||!UUID.test(registrationId||''))fail('SHADOW_REQUEST_INVALID');return withStore(capability,authorize,async({directoryPath})=>{const row=await read(path.join(directoryPath,operationId+'.json'));if(!row)return{state:'absent'};if(row.state!=='completed')return{state:'uncertain'};if(row.receiptDigest!==canonicalDigest(row.receipt)||row.receipt.version!=='owned-shadow.v1'||row.receipt.action!=='register'||row.receipt.registrationId!==registrationId)fail('SHADOW_REPLAY_MISMATCH');const file=path.join(directoryPath,'registration-'+registrationId+'.json');const prior=await read(file);if(prior&&prior.receiptDigest!==row.receiptDigest)fail('SHADOW_REGISTRATION_CONFLICT');if(!prior)await write(file,row);return{state:'completed',receipt:row.receipt};});}
 async function readReceipt(capability,authorize,{operationId,requestDigest}={}){if(!UUID.test(operationId||'')||!/^[a-f0-9]{64}$/.test(requestDigest||''))fail('SHADOW_REQUEST_INVALID');return withStore(capability,authorize,async({directoryPath})=>{const row=await read(path.join(directoryPath,operationId+'.json'));if(!row)return{state:'absent'};if(row.requestDigest!==requestDigest)fail('SHADOW_REPLAY_MISMATCH');if(row.state!=='completed')return{state:'uncertain'};if(row.receiptDigest!==canonicalDigest(row.receipt))fail('SHADOW_JOURNAL_UNTRUSTED');return{state:'completed',receipt:row.receipt};});}
 return Object.freeze({execute,recoverRegistration,readReceipt,readSource,writeSource});
}
module.exports={createOwnedShadowOperationStore};
