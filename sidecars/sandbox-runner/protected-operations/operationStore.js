'use strict';
// Optional connected journal capability. The caller supplies trusted withTarget and executor;
// this module does not grant graph provenance, objective credit, or retries.
const fs = require('node:fs/promises');
const {constants} = require('node:fs');
const path = require('node:path');
const {createHash}=require('node:crypto');
const {canonical, canonicalDigest} = require('../owned-http/canonical');
const VERSION = 'mcp-owned-protected-operation-journal.v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const MAX_BYTES = 1048576;
const fail = code => { throw Object.assign(new Error(code), {code}); };
function exact(value, fields) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}
function requestSnapshot(value) {
  if (!exact(value,['operationId','runId','operation','arguments'])
      || !UUID.test(value.operationId) || !UUID.test(value.runId)) fail('PROTECTED_JOURNAL_REQUEST_INVALID');
  const args = value.arguments;
  const valid = value.operation === 'read_configuration' && exact(args,[])
    || value.operation === 'rotate_keys' && exact(args,['labRole','enforceAuthorization'])
      && ['privileged','unprivileged'].includes(args.labRole) && typeof args.enforceAuthorization === 'boolean'
    || value.operation === 'set_audit_logging' && exact(args,['action']) && ['enable','disable','clear'].includes(args.action);
  if (!valid) fail('PROTECTED_JOURNAL_REQUEST_INVALID');
  return Object.freeze({...value,arguments:Object.freeze({...args})});
}
function identityFor(request,binding) {
  if (!UUID.test(binding?.targetId || '') || !Number.isSafeInteger(binding.ownerId) || binding.ownerId<1
      || !Number.isSafeInteger(binding.platformSessionId) || binding.platformSessionId<1
      || !Number.isSafeInteger(binding.generation) || binding.generation<0) fail('PROTECTED_JOURNAL_SCOPE_INVALID');
  return Object.freeze({...request,binding:Object.freeze({targetId:binding.targetId,platformOwnerId:binding.ownerId,
    platformSessionId:binding.platformSessionId,generation:binding.generation})});
}
function verifiedResult(result,identity) {
  const extras = {read_configuration:['configSha256','byteCount','audited','output'],
    rotate_keys:['labRole','policy','changed','keyVersionBefore','keyVersionAfter','audited'],
    set_audit_logging:['action','auditEnabledBefore','auditEnabled','entriesBefore','entriesAfter','audited']}[identity.operation];
  const fields=['version','operation','targetId','platformOwnerId','platformSessionId','generation','runId','receiptSha256',...extras];
  if (!exact(result,fields) || result.version!=='mcp-owned-protected-state.v1'
      || result.operation!==identity.operation || result.runId!==identity.runId
      || Object.entries(identity.binding).some(([key,value])=>result[key]!==value)) fail('PROTECTED_JOURNAL_RESULT_INVALID');
  const {receiptSha256,...body}=result;
  if (receiptSha256!==canonicalDigest(body) || extras.some(key=>!['string','number','boolean'].includes(typeof result[key]))
      || typeof result.audited!=='boolean' || Buffer.byteLength(canonical(result))>MAX_BYTES/2) fail('PROTECTED_JOURNAL_RESULT_INVALID');
  const natural=value=>Number.isSafeInteger(value)&&value>=0;
  if(identity.operation==='read_configuration' && (typeof result.output!=='string'
      || !natural(result.byteCount)||result.byteCount!==Buffer.byteLength(result.output)||result.byteCount>65536
      || result.configSha256!==createHash('sha256').update(result.output).digest('hex')))fail('PROTECTED_JOURNAL_RESULT_INVALID');
  if(identity.operation==='rotate_keys' && (result.labRole!==identity.arguments.labRole
      ||result.policy!==(identity.arguments.enforceAuthorization?'enforced':'vulnerable')
      ||typeof result.changed!=='boolean'||!natural(result.keyVersionBefore)||!natural(result.keyVersionAfter)
      ||result.keyVersionAfter!==result.keyVersionBefore+(result.changed?1:0)))fail('PROTECTED_JOURNAL_RESULT_INVALID');
  if(identity.operation==='set_audit_logging' && (result.action!==identity.arguments.action
      ||typeof result.auditEnabledBefore!=='boolean'||typeof result.auditEnabled!=='boolean'
      ||!natural(result.entriesBefore)||!natural(result.entriesAfter)))fail('PROTECTED_JOURNAL_RESULT_INVALID');
  return Object.freeze({...result});
}
async function privateDirectory(file) {
  const stat=await fs.lstat(file);
  if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o077)||stat.uid!==process.getuid())fail('PROTECTED_JOURNAL_UNSAFE');
}
async function read(file) {
  let handle;
  try {
    handle=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const stat=await handle.stat();
    if(!stat.isFile()||stat.nlink!==1||(stat.mode&0o077)||stat.uid!==process.getuid()||stat.size>MAX_BYTES)fail('PROTECTED_JOURNAL_UNSAFE');
    const bytes=await handle.readFile();let value;
    try{value=JSON.parse(bytes);}catch{fail('PROTECTED_JOURNAL_INVALID');}
    if(bytes.toString()!==canonical(value)+'\n')fail('PROTECTED_JOURNAL_INVALID');
    return value;
  } catch(error){if(error.code==='ENOENT')return null;throw error;}finally{await handle?.close();}
}
async function syncDirectory(directory){const fd=await fs.open(directory,constants.O_RDONLY|constants.O_NOFOLLOW);try{await fd.sync();}finally{await fd.close();}}
async function publish(file,value) {
  const bytes=Buffer.from(canonical(value)+'\n');if(bytes.length>MAX_BYTES)fail('PROTECTED_JOURNAL_INVALID');
  const temp=file+'.tmp';const handle=await fs.open(temp,'wx',0o600);
  try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}
  // No overwrite: an existing immutable identity is never replaced.
  await fs.link(temp,file);await syncDirectory(path.dirname(file));
  await fs.unlink(temp);await syncDirectory(path.dirname(file));
}
async function noStaging(file){try{await fs.lstat(file+'.tmp');fail('PROTECTED_JOURNAL_UNCERTAIN');}catch(error){if(error.code!=='ENOENT')throw error;}}
function createProtectedOperationStore({targetStore,executor}={}) {
  if(typeof targetStore?.withTarget!=='function'||typeof executor!=='function')throw TypeError('Trusted protected journal dependencies required');
  async function access(capability,authority,request,execute) {
    const supplied=requestSnapshot(request); // Freeze before any asynchronous work.
    return targetStore.withTarget(capability,authority,async({rootfs,binding})=>{
      const target=path.dirname(rootfs);await privateDirectory(target);
      const directory=path.join(target,'protected-operations');
      try{await fs.mkdir(directory,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}await privateDirectory(directory);await syncDirectory(target);
      const identity=identityFor(supplied,binding),requestDigest=canonicalDigest(identity);
      const pendingFile=path.join(directory,supplied.operationId+'.pending.json'),completedFile=path.join(directory,supplied.operationId+'.completed.json');
      await noStaging(pendingFile);await noStaging(completedFile);
      const pending=await read(pendingFile),completed=await read(completedFile);
      if(pending && (!exact(pending,['version','identity','requestDigest'])||pending.version!==VERSION
          || pending.requestDigest!==requestDigest || canonical(pending.identity)!==canonical(identity)))fail('PROTECTED_JOURNAL_CONFLICT');
      if(completed){
        if(!pending || !exact(completed,['version','requestDigest','result','resultDigest'])||completed.version!==VERSION
            ||completed.requestDigest!==requestDigest||completed.resultDigest!==canonicalDigest(completed.result))fail('PROTECTED_JOURNAL_INVALID');
        return Object.freeze({state:'completed',requestDigest,result:verifiedResult(completed.result,identity)});
      }
      if(pending)return Object.freeze({state:'uncertain',requestDigest});
      if(!execute)return Object.freeze({state:'absent',requestDigest});
      await publish(pendingFile,{version:VERSION,identity,requestDigest});
      try{
        const result=verifiedResult(await executor({rootfs,binding:Object.freeze({...binding}),request:supplied}),identity);
        await publish(completedFile,{version:VERSION,requestDigest,result,resultDigest:canonicalDigest(result)});
        return Object.freeze({state:'completed',requestDigest,result});
      }catch(error){throw Object.assign(new Error('PROTECTED_JOURNAL_UNCERTAIN'),{code:'PROTECTED_JOURNAL_UNCERTAIN',cause:error});}
    });
  }
  return Object.freeze({execute:(capability,authority,request)=>access(capability,authority,request,true),
    readReceipt:(capability,authority,request)=>access(capability,authority,request,false)});
}
module.exports={VERSION,createProtectedOperationStore};
