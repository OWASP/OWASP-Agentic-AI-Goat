'use strict';
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const managed=require('./secureshopSystemManagedConfiguration');
const {workspaceId}=require('../../scripts/application-data-root');
const {authorityDigest,validateAuthorityState}=require('../../scripts/local-docker-authority');
const fail=code=>Object.assign(new Error('Owned System managed activation unavailable'),{code});
function load({root=path.resolve(__dirname,'../..'),home=os.homedir(),environment=process.env}={}){
 const filePath=managed.managedPath({root,home});
 // A workspace with no System record remains dependency-free/default-disabled.
 try{fs.lstatSync(filePath);}catch(error){if(error.code==='ENOENT')return Object.freeze({});throw error;}
 const value=managed.load({filePath});if(!value?.enabled)return Object.freeze({});
 const id=workspaceId(root);if(value.workspaceId!==id)throw fail('SYSTEM_ACTIVATION_SCOPE');
 const file=path.join(path.dirname(filePath),'local-docker.json');let fd;
 try{
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const stat=fs.fstatSync(fd);
  if(!stat.isFile()||stat.uid!==process.getuid()||stat.nlink!==1||(stat.mode&0o777)!==0o600||stat.size>8192)throw fail('SYSTEM_ACTIVATION_AUTHORITY');
  const buffer=Buffer.alloc(8193),n=fs.readSync(fd,buffer,0,buffer.length,0),after=fs.fstatSync(fd),named=fs.lstatSync(file);
  if(n!==stat.size||after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs||named.ino!==stat.ino||named.dev!==stat.dev||named.isSymbolicLink())throw fail('SYSTEM_ACTIVATION_AUTHORITY');
  const authority=validateAuthorityState(JSON.parse(buffer.subarray(0,n)),{workspaceId:id});
  if(authorityDigest(authority)!==value.dockerAuthoritySha256)throw fail('SYSTEM_ACTIVATION_AUTHORITY');
 }catch{throw fail('SYSTEM_ACTIVATION_AUTHORITY');}finally{if(fd!==undefined)fs.closeSync(fd);}
 const overlay={SS_BOUND_SYSTEM_CONFIG_ENABLED:'true',SS_SYSTEM_CONFIG_BASE_URL:value.config.url,SS_SYSTEM_CONFIG_TOKEN:value.config.token,
  SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED:'true',SS_SYSTEM_DIAGNOSTIC_BASE_URL:value.diagnostic.url,SS_SYSTEM_DIAGNOSTIC_TOKEN:value.diagnostic.token,
  SS_BOUND_SYSTEM_RESTART_ENABLED:'true',SS_SYSTEM_RESTART_BASE_URL:value.restart.url,SS_SYSTEM_RESTART_TOKEN:value.restart.token,
  ...(value.uploadPreview ? {SS_BOUND_UPLOAD_PREVIEW_ENABLED:'true',SS_UPLOAD_PREVIEW_BASE_URL:value.uploadPreview.url,SS_UPLOAD_PREVIEW_TOKEN:value.uploadPreview.token} : {})};
 for(const [key,v]of Object.entries(overlay))if(environment[key]!==undefined&&environment[key]!==v)throw fail('SYSTEM_ACTIVATION_ENV_CONFLICT');
 return Object.freeze(overlay);
}
function loadWithQualified({root=path.resolve(__dirname,'../..'),home=os.homedir(),environment=process.env}={}) {
 const qualified=require('./secureshopQualifiedManagedConfiguration').load({root,home});
 return Object.freeze({...qualified,...load({root,home,environment:{...environment,...qualified}})});
}
function getUploadPreviewClient({environment=process.env}={}) {
 if(environment.SS_BOUND_UPLOAD_PREVIEW_ENABLED===undefined || environment.SS_BOUND_UPLOAD_PREVIEW_ENABLED==='false')return null;
 if(environment.SS_BOUND_UPLOAD_PREVIEW_ENABLED!=='true')throw fail('UPLOAD_PREVIEW_ACTIVATION_INVALID');
 return require('./secureshopUploadPreviewClient').createSecureShopUploadPreviewClient({baseURL:environment.SS_UPLOAD_PREVIEW_BASE_URL,token:environment.SS_UPLOAD_PREVIEW_TOKEN});
}
async function assertReady({environment=process.env}={}){
 const uploadPreview=getUploadPreviewClient({environment});if(uploadPreview)await uploadPreview.assertReady();
 if(environment.SS_BOUND_SYSTEM_CONFIG_ENABLED==='true')await require('./secureshopSystemConfigActivation').prepareSystemConfigClient({env:environment});
 if(environment.SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED==='true')await require('./secureshopSystemDiagnosticActivation').prepareSystemDiagnosticClient({env:environment});
 if(environment.SS_BOUND_SYSTEM_RESTART_ENABLED==='true')await require('./secureshopSystemRestartActivation').prepareSystemRestartClient({env:environment});
}
module.exports={load,loadWithQualified,assertReady,getUploadPreviewClient};
