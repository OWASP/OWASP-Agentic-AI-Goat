'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, createHash } = require('node:crypto');
const { assertPrivateDirectory } = require('./secureshopPasswordResetKeys');
const { workspaceId } = require('../../scripts/application-data-root');
const FILE = 'secureshop-owned-listings.json';
const LIMIT = 8192;
const fail = code => Object.assign(new Error('Owned Listings managed configuration unavailable'), { code });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const image = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
function managedPath({ root, home } = {}) {
  if (!path.isAbsolute(root || '') || !path.isAbsolute(home || '')) throw fail('LISTINGS_MANAGED_PATH_INVALID');
  return path.join(home, '.dvaia', workspaceId(root), FILE);
}
function validate(value) {
  if (!exact(value, ['version','workspaceId','enabled','architecture','dockerAuthoritySha256','imageId',
    'sourceManifestSha256','runtimeDigest','profile','manager']) || value.version !== 1
      || !/^[a-f0-9]{12}$/.test(value.workspaceId || '') || typeof value.enabled !== 'boolean'
      || value.architecture !== 'arm64' || !hex(value.dockerAuthoritySha256) || !image(value.imageId)
      || !hex(value.sourceManifestSha256) || !hex(value.runtimeDigest) || !exact(value.profile, ['name','sha256'])
      || value.profile.name !== 'dvaia-owned-listings-'+value.workspaceId || !hex(value.profile.sha256)) throw fail('LISTINGS_MANAGED_INVALID');
  const row=value.manager;
  if (!exact(row,['container','url','token']) || row.container !== `dvaia-owned-listings-${value.workspaceId}`
      || typeof row.token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(row.token)
      || typeof row.url !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/.test(row.url)) throw fail('LISTINGS_MANAGED_INVALID');
  const port=Number(new URL(row.url).port);
  if (port<1024 || port>65535 || new URL(row.url).origin!==row.url) throw fail('LISTINGS_MANAGED_INVALID');
  return Object.freeze({...value,profile:Object.freeze({...value.profile}),manager:Object.freeze({...row})});
}
function readManaged({ filePath } = {}, captureIdentity = false) {
  let fd;
  try {
    if (!path.isAbsolute(filePath || '')) throw fail('LISTINGS_MANAGED_PATH_INVALID');
    const parent=assertPrivateDirectory(path.dirname(filePath));
    try { fd=fs.openSync(filePath,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK); }
    catch(error) { if(error.code==='ENOENT') return null;throw error; }
    const before=fs.fstatSync(fd);
    if(!before.isFile() || before.uid!==process.getuid() || before.nlink!==1 || (before.mode&0o777)!==0o600
        || before.size<2 || before.size>LIMIT) throw fail('LISTINGS_MANAGED_UNTRUSTED');
    const buffer=Buffer.alloc(LIMIT+1),count=fs.readSync(fd,buffer,0,buffer.length,0),after=fs.fstatSync(fd);
    const named=fs.lstatSync(filePath),parentAfter=assertPrivateDirectory(path.dirname(filePath));
    if(count!==before.size || after.size!==before.size || after.mtimeMs!==before.mtimeMs || after.ctimeMs!==before.ctimeMs
       || named.isSymbolicLink() || named.dev!==before.dev || named.ino!==before.ino || named.mode!==after.mode
       || named.nlink!==1 || parentAfter.dev!==parent.dev || parentAfter.ino!==parent.ino) throw fail('LISTINGS_MANAGED_UNTRUSTED');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,count));
    const value=validate(JSON.parse(text));
    // Managed files have one canonical encoding. Reject duplicate keys and
    // ambiguous parser inputs rather than treating them as a valid record.
    if(text!==encode(value)) throw fail('LISTINGS_MANAGED_INVALID');
    return captureIdentity ? Object.freeze({value,dev:before.dev,ino:before.ino,sha256:createHash('sha256').update(buffer.subarray(0,count)).digest('hex')}) : value;
  } catch(error) { throw fail(error.code?.startsWith('LISTINGS_MANAGED_')?error.code:'LISTINGS_MANAGED_UNTRUSTED'); }
  finally { if(fd!==undefined)fs.closeSync(fd); }
}
function load(options) { return readManaged(options); }
function capture(options) { return readManaged(options, true); }
function encode(raw) {
  const v=validate(raw);
  return JSON.stringify({version:v.version,workspaceId:v.workspaceId,enabled:v.enabled,architecture:v.architecture,
    dockerAuthoritySha256:v.dockerAuthoritySha256,imageId:v.imageId,sourceManifestSha256:v.sourceManifestSha256,
    runtimeDigest:v.runtimeDigest,profile:{name:v.profile.name,sha256:v.profile.sha256},
    manager:{container:v.manager.container,url:v.manager.url,token:v.manager.token}})+'\n';
}
function readPublished(filePath) {
  for(let attempt=0;attempt<25;attempt++) {
    try{return load({filePath});}catch(error){
      let stat;try{stat=fs.lstatSync(filePath);}catch{throw error;}
      if(stat.nlink===1)return load({filePath});
      if(stat.nlink!==2 || attempt===24)throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10);
    }
  }
}
// Explicit installer staging only: never activation, replacement or token rotation.
function stage({ filePath, value } = {}) {
  const expected=validate(value),bytes=encode(expected);
  if(expected.enabled!==false || !path.isAbsolute(filePath||''))throw fail('LISTINGS_MANAGED_STAGE_INVALID');
  const directory=path.dirname(filePath);assertPrivateDirectory(directory);
  const existing=readPublished(filePath);
  if(existing){if(encode(existing)!==bytes)throw fail('LISTINGS_MANAGED_CONFLICT');return Object.freeze({filePath,created:false,staged:true});}
  const temporary=path.join(directory,'.listings-'+randomBytes(12).toString('hex')+'.pending');let fd,created=false,temporaryCreated=false;
  try {
    fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    temporaryCreated=true;
    fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    try{fs.linkSync(temporary,filePath);created=true;}catch(error){if(error.code!=='EEXIST')throw error;}
  } finally {if(fd!==undefined)fs.closeSync(fd);try{if(temporaryCreated)fs.unlinkSync(temporary);}catch(error){if(error.code!=='ENOENT')throw error;}}
  const parent=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
  if(encode(readPublished(filePath))!==bytes)throw fail('LISTINGS_MANAGED_CONFLICT');
  return Object.freeze({filePath,created,staged:true});
}
// Explicit installation transition only. The caller rechecks the retained
// daemon, exact resources and schema inside verify before the enabled record
// can become visible to application startup.
async function activate({filePath,expected,verify}={}) {
  if (!path.isAbsolute(filePath||'') || !expected || typeof verify!=='function') throw fail('LISTINGS_MANAGED_ACTIVATION_INVALID');
  const directory=path.dirname(filePath),lock=filePath+'.activation.lock';
  assertPrivateDirectory(directory);
  let lockFd,tempFd,temp;
  const sameCapture=before=>{
    const now=capture({filePath});
    if(!now||now.dev!==before.dev||now.ino!==before.ino||now.sha256!==before.sha256
        ||encode(now.value)!==encode(before.value))throw fail('LISTINGS_MANAGED_CHANGED');
    return now;
  };
  try {
    lockFd=fs.openSync(lock,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    const stat=fs.fstatSync(lockFd);
    if(!stat.isFile()||stat.uid!==process.getuid()||stat.nlink!==1||(stat.mode&0o777)!==0o600)throw fail('LISTINGS_MANAGED_ACTIVATION_INVALID');
    const before=sameCapture(expected);
    if(before.value.enabled!==false)throw fail('LISTINGS_MANAGED_ACTIVATION_INVALID');
    if(await verify(before.value)!==true)throw fail('LISTINGS_MANAGED_ACTIVATION_UNREADY');
    sameCapture(before);
    const next=validate({...before.value,enabled:true});
    temp=path.join(directory,'.listings-activation-'+randomBytes(12).toString('hex'));
    tempFd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(tempFd,encode(next));fs.fsyncSync(tempFd);fs.closeSync(tempFd);tempFd=undefined;
    sameCapture(before);
    fs.renameSync(temp,filePath);temp=undefined;
    const parent=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
    return capture({filePath}).value;
  } catch(error) {
    if(error?.code==='EEXIST')throw fail('LISTINGS_MANAGED_ACTIVATION_BUSY');
    throw error;
  } finally {
    if(tempFd!==undefined)fs.closeSync(tempFd);
    if(temp)try{fs.unlinkSync(temp);}catch(error){if(error.code!=='ENOENT')throw error;}
    if(lockFd!==undefined){fs.closeSync(lockFd);fs.unlinkSync(lock);}
  }
}
// Explicit installer repair of a disabled, never-used manager. The caller
// verifies the retained resources and replacement before publication.
function clearRetargetLock({filePath,recoveryId}={}) {
  if(!path.isAbsolute(filePath||'')||!hex(recoveryId))throw fail('LISTINGS_MANAGED_RETARGET_INVALID');
  const lock=filePath+'.activation.lock';assertPrivateDirectory(path.dirname(filePath));
  let fd;
  try{
    try{fd=fs.openSync(lock,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}
    catch(error){if(error.code==='ENOENT')return false;throw error;}
    const before=fs.fstatSync(fd),named=fs.lstatSync(lock),bytes=Buffer.alloc(66);
    if(!before.isFile()||before.uid!==process.getuid()||![1,2].includes(before.nlink)||(before.mode&0o777)!==0o600
      ||before.size!==65||named.dev!==before.dev||named.ino!==before.ino
      ||fs.readSync(fd,bytes,0,bytes.length,0)!==65||bytes.subarray(0,65).toString()!==recoveryId+'\n')throw fail('LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT');
    const after=fs.fstatSync(fd);
    if(after.dev!==before.dev||after.ino!==before.ino||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw fail('LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT');
    if(before.nlink===2){
      const directory=path.dirname(lock),prefix=path.basename(lock)+'.';
      const companions=fs.readdirSync(directory).filter(name=>name.startsWith(prefix)&&/^[a-f0-9]{24}\.pending$/.test(name.slice(prefix.length)));
      if(companions.length!==1)throw fail('LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT');
      const companion=path.join(directory,companions[0]);
      const linked=fs.lstatSync(companion);
      if(!linked.isFile()||linked.uid!==before.uid||(linked.mode&0o777)!==0o600
        ||linked.dev!==before.dev||linked.ino!==before.ino||linked.nlink!==2)throw fail('LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT');
      const current=fs.lstatSync(companion);
      if(current.dev!==linked.dev||current.ino!==linked.ino||current.ctimeMs!==linked.ctimeMs)throw fail('LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT');
      fs.unlinkSync(companion);
    }
    const finalFd=fs.fstatSync(fd),finalName=fs.lstatSync(lock);
    if(finalFd.nlink!==1||finalFd.dev!==before.dev||finalFd.ino!==before.ino
      ||finalName.dev!==before.dev||finalName.ino!==before.ino)throw fail('LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT');
    fs.unlinkSync(lock);
    const parent=fs.openSync(path.dirname(lock),fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
    return true;
  }finally{if(fd!==undefined)fs.closeSync(fd);}
}
async function retargetDisabled({filePath,expected,next,verify,recoveryId}={}) {
  if(!path.isAbsolute(filePath||'')||!expected||typeof verify!=='function'||!hex(recoveryId))throw fail('LISTINGS_MANAGED_RETARGET_INVALID');
  const intended=validate(next);
  if(intended.enabled!==false)throw fail('LISTINGS_MANAGED_RETARGET_INVALID');
  const directory=path.dirname(filePath),lock=filePath+'.activation.lock';assertPrivateDirectory(directory);
  let lockFd,lockTemp,lockCreated=false,tempFd,temp;
  const sameCapture=before=>{
    const now=capture({filePath});
    if(!now||now.dev!==before.dev||now.ino!==before.ino||now.sha256!==before.sha256||encode(now.value)!==encode(before.value))throw fail('LISTINGS_MANAGED_CHANGED');
    return now;
  };
  try{
    lockTemp=lock+'.'+randomBytes(12).toString('hex')+'.pending';
    lockFd=fs.openSync(lockTemp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    const st=fs.fstatSync(lockFd);
    if(!st.isFile()||st.uid!==process.getuid()||st.nlink!==1||(st.mode&0o777)!==0o600)throw fail('LISTINGS_MANAGED_RETARGET_INVALID');
    fs.writeFileSync(lockFd,recoveryId+'\n');fs.fsyncSync(lockFd);fs.closeSync(lockFd);lockFd=undefined;
    fs.linkSync(lockTemp,lock);lockCreated=true;fs.unlinkSync(lockTemp);lockTemp=undefined;
    const lockParent=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(lockParent);}finally{fs.closeSync(lockParent);}
    const before=sameCapture(expected);
    if(before.value.enabled||before.value.manager.url===intended.manager.url
      ||Object.keys(before.value).filter(key=>key!=='manager').some(key=>JSON.stringify(before.value[key])!==JSON.stringify(intended[key]))
      ||before.value.manager.container!==intended.manager.container||before.value.manager.token!==intended.manager.token)throw fail('LISTINGS_MANAGED_RETARGET_INVALID');
    if(await verify(before.value,intended)!==true)throw fail('LISTINGS_MANAGED_RETARGET_UNREADY');
    sameCapture(before);
    temp=path.join(directory,'.listings-retarget-'+randomBytes(12).toString('hex'));
    tempFd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(tempFd,encode(intended));fs.fsyncSync(tempFd);fs.closeSync(tempFd);tempFd=undefined;
    sameCapture(before);
    fs.renameSync(temp,filePath);temp=undefined;
    const parent=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
    return capture({filePath}).value;
  }catch(error){if(error?.code==='EEXIST')throw fail('LISTINGS_MANAGED_ACTIVATION_BUSY');throw error;}
  finally{if(tempFd!==undefined)fs.closeSync(tempFd);if(temp)try{fs.unlinkSync(temp);}catch(error){if(error.code!=='ENOENT')throw error;}
    if(lockFd!==undefined)fs.closeSync(lockFd);if(lockTemp)try{fs.unlinkSync(lockTemp);}catch(error){if(error.code!=='ENOENT')throw error;}
    if(lockCreated)clearRetargetLock({filePath,recoveryId});}
}
module.exports={managedPath,validate,load,capture,stage,activate,retargetDisabled,clearRetargetLock,encode,FILE,LIMIT};
