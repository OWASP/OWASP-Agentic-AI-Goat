'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, createHash } = require('node:crypto');
const { assertPrivateDirectory } = require('./secureshopPasswordResetKeys');
const { workspaceId } = require('../../scripts/application-data-root');
const FILE = 'secureshop-owned-system.json';
const LIMIT = 8192;
const fail = code => Object.assign(new Error('Owned System managed configuration unavailable'), { code });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const image = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
function managedPath({ root, home } = {}) {
  if (!path.isAbsolute(root || '') || !path.isAbsolute(home || '')) throw fail('SYSTEM_MANAGED_PATH_INVALID');
  return path.join(home, '.owasp-ai-goat', workspaceId(root), FILE);
}
function modesFor(value) { return ['config','diagnostic','restart',...(Object.prototype.hasOwnProperty.call(value || {},'uploadPreview') ? ['uploadPreview'] : [])]; }
function validate(value) {
  if (!exact(value, ['version','workspaceId','enabled','architecture','dockerAuthoritySha256','imageId',
    'sourceManifestSha256','profile','config','diagnostic','restart',
    ...(Object.prototype.hasOwnProperty.call(value || {}, 'uploadPreview') ? ['uploadPreview'] : []),
    ...(Object.prototype.hasOwnProperty.call(value || {}, 'resourceSourceManifestSha256') ? ['resourceSourceManifestSha256'] : [])]) || value.version !== 1
      || !/^[a-f0-9]{12}$/.test(value.workspaceId || '') || typeof value.enabled !== 'boolean'
      || value.architecture !== 'arm64' || !hex(value.dockerAuthoritySha256) || !image(value.imageId)
      || !hex(value.sourceManifestSha256) || (Object.prototype.hasOwnProperty.call(value, 'resourceSourceManifestSha256') && !hex(value.resourceSourceManifestSha256)) || !exact(value.profile, ['name','sha256'])
      || value.profile.name !== 'owasp-ai-goat-mcp-sandbox' || !hex(value.profile.sha256)) throw fail('SYSTEM_MANAGED_INVALID');
  const modes = {};
  for (const mode of modesFor(value)) {
    const row=value[mode];
    if (!exact(row,['container','url','token']) || row.container !== `owasp-ai-goat-owned-system-${value.workspaceId}-${mode === 'uploadPreview' ? 'upload-preview' : mode}`
        || typeof row.token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(row.token)
        || typeof row.url !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/.test(row.url)) throw fail('SYSTEM_MANAGED_INVALID');
    const port=Number(new URL(row.url).port);
    if (port<1024 || port>65535 || new URL(row.url).origin!==row.url) throw fail('SYSTEM_MANAGED_INVALID');
    modes[mode]=Object.freeze({...row});
  }
  if (new Set(Object.values(modes).map(row=>row.url)).size!==Object.keys(modes).length || new Set(Object.values(modes).map(row=>row.token)).size!==Object.keys(modes).length) throw fail('SYSTEM_MANAGED_INVALID');
  return Object.freeze({...value,profile:Object.freeze({...value.profile}),...modes});
}
function readManaged({ filePath } = {}, captureIdentity = false) {
  let fd;
  try {
    if (!path.isAbsolute(filePath || '')) throw fail('SYSTEM_MANAGED_PATH_INVALID');
    const parent=assertPrivateDirectory(path.dirname(filePath));
    try { fd=fs.openSync(filePath,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW); }
    catch(error) { if(error.code==='ENOENT') return null;throw error; }
    const before=fs.fstatSync(fd);
    if(!before.isFile() || before.uid!==process.getuid() || before.nlink!==1 || (before.mode&0o777)!==0o600
        || before.size<2 || before.size>LIMIT) throw fail('SYSTEM_MANAGED_UNTRUSTED');
    const buffer=Buffer.alloc(LIMIT+1),count=fs.readSync(fd,buffer,0,buffer.length,0),after=fs.fstatSync(fd);
    const named=fs.lstatSync(filePath),parentAfter=assertPrivateDirectory(path.dirname(filePath));
    if(count!==before.size || after.size!==before.size || after.mtimeMs!==before.mtimeMs || after.ctimeMs!==before.ctimeMs
       || named.isSymbolicLink() || named.dev!==before.dev || named.ino!==before.ino || named.mode!==after.mode
       || named.nlink!==1 || parentAfter.dev!==parent.dev || parentAfter.ino!==parent.ino) throw fail('SYSTEM_MANAGED_UNTRUSTED');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,count));
    const value=validate(JSON.parse(text));
    // Managed files have one canonical encoding. Reject duplicate keys and
    // ambiguous parser inputs rather than treating them as a valid record.
    if(text!==encode(value)) throw fail('SYSTEM_MANAGED_INVALID');
    return captureIdentity ? Object.freeze({value,dev:before.dev,ino:before.ino,sha256:createHash('sha256').update(buffer.subarray(0,count)).digest('hex')}) : value;
  } catch(error) { throw fail(error.code?.startsWith('SYSTEM_MANAGED_')?error.code:'SYSTEM_MANAGED_UNTRUSTED'); }
  finally { if(fd!==undefined)fs.closeSync(fd); }
}
function load(options) { return readManaged(options); }
function capture(options) { return readManaged(options, true); }
function encode(raw) {
  const v=validate(raw);
  return JSON.stringify({version:v.version,workspaceId:v.workspaceId,enabled:v.enabled,architecture:v.architecture,
    dockerAuthoritySha256:v.dockerAuthoritySha256,imageId:v.imageId,sourceManifestSha256:v.sourceManifestSha256,
    ...(v.resourceSourceManifestSha256 === undefined ? {} : {resourceSourceManifestSha256:v.resourceSourceManifestSha256}),
    profile:{name:v.profile.name,sha256:v.profile.sha256},
    config:{container:v.config.container,url:v.config.url,token:v.config.token},
    diagnostic:{container:v.diagnostic.container,url:v.diagnostic.url,token:v.diagnostic.token},
    restart:{container:v.restart.container,url:v.restart.url,token:v.restart.token},
    ...(v.uploadPreview ? {uploadPreview:{container:v.uploadPreview.container,url:v.uploadPreview.url,token:v.uploadPreview.token}} : {})})+'\n';
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
  if(expected.enabled!==false || !path.isAbsolute(filePath||''))throw fail('SYSTEM_MANAGED_STAGE_INVALID');
  const directory=path.dirname(filePath);assertPrivateDirectory(directory);
  const existing=readPublished(filePath);
  if(existing){if(encode(existing)!==bytes)throw fail('SYSTEM_MANAGED_CONFLICT');return Object.freeze({filePath,created:false,staged:true});}
  const temporary=path.join(directory,'.system-'+randomBytes(12).toString('hex')+'.pending');let fd,created=false;
  try {
    fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    try{fs.linkSync(temporary,filePath);created=true;}catch(error){if(error.code!=='EEXIST')throw error;}
  } finally {if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(temporary);}catch(error){if(error.code!=='ENOENT')throw error;}}
  const parent=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
  if(encode(readPublished(filePath))!==bytes)throw fail('SYSTEM_MANAGED_CONFLICT');
  return Object.freeze({filePath,created,staged:true});
}
module.exports={modesFor,managedPath,validate,load,capture,stage,encode,FILE,LIMIT};
