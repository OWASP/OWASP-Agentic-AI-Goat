'use strict';
const fs=require('node:fs/promises'),constants=require('node:fs').constants,path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const fail=()=>Object.assign(Error('Private Analytics configuration unavailable'),{code:'ANALYTICS_MANAGED_CONFIGURATION_INVALID'});
const hash=value=>createHash('sha256').update(value).digest('hex');
const keys=['version','enabled','workspaceId','dockerAuthoritySha256','containerName','containerId','volumeName','imageId','port','password','ownerId','identity','controlSchemaSha256'];
function validate(value,{root,platform=process.platform}) {
 const workspaceId=hash((platform==='win32'?path.win32:path).resolve(root)).slice(0,12),name=`owasp-ai-goat-analytics-${workspaceId}`;
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join()!==[...keys].sort().join()
  ||value.version!==1||typeof value.enabled!=='boolean'||value.workspaceId!==workspaceId
  ||value.containerName!==name||value.volumeName!==name+'-data'
  ||!/^sha256:[a-f0-9]{64}$/.test(value.imageId)||!Number.isInteger(value.port)||value.port<1024||value.port>65535
  ||!['dockerAuthoritySha256','containerId','password','controlSchemaSha256'].every(key=>typeof value[key]==='string'&&/^[a-f0-9]{64}$/.test(value[key]))
  ||typeof value.ownerId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.ownerId))throw fail();
 const identity=value.identity;
 if(!identity||Object.getPrototypeOf(identity)!==Object.prototype||Object.keys(identity).sort().join()!=='clusterName,controlDatabase,systemIdentifier'
  ||identity.controlDatabase!==`owasp_ai_goat_analytics_control_${workspaceId}`||identity.clusterName!==`owasp-ai-goat-owned-analytics-${workspaceId}`
  ||typeof identity.systemIdentifier!=='string'||!/^[0-9]{10,24}$/.test(identity.systemIdentifier))throw fail();
 return Object.freeze({...value,identity:Object.freeze({...identity})});
}
function createManagedAnalyticsConfigurationReader({filesystemPlatform=process.platform,privateState,fileSystem=fs}={}) {
async function readManagedAnalyticsConfiguration({root,homeDirectory=os.homedir(),uid=process.getuid?.()}={}) {
 if(filesystemPlatform==='win32'){
  try{
   const native=privateState||require('../../scripts/lib/windows-private-state'),p=path.win32;
   if(typeof root!=='string'||typeof homeDirectory!=='string'||native.normalizePrivatePath(root)!==root||native.normalizePrivatePath(homeDirectory)!==homeDirectory)throw fail();
   const directory=p.join(homeDirectory,'.owasp-ai-goat',hash(p.resolve(root)).slice(0,12)),filename=p.join(directory,'analytics-managed.json');
   // Only an exact named absence observed BEFORE native admission is optional.
   // Native denial, including disappearance after this check, is never absence.
   try{await fileSystem.lstat(filename);}catch(error){if(error.code==='ENOENT')return null;throw error;}
   const location=()=>{const observed=native.inspectPrivateDirectory(directory);if(observed?.path!==directory||!Number.isInteger(observed.identity?.volumeSerial)||observed.identity.volumeSerial<0||observed.identity.volumeSerial>0xffffffff||!/^[a-f0-9]{16}$/.test(observed.identity.fileId))throw fail();return {path:observed.path,volumeSerial:observed.identity.volumeSerial,fileId:observed.identity.fileId};};
   const before=location(),bytes=native.readPrivateFile(filename);
   if(!Buffer.isBuffer(bytes)||bytes.length>32768)throw fail();
   const config=validate(JSON.parse(bytes.toString('utf8')),{root,platform:filesystemPlatform});
   if(JSON.stringify(location())!==JSON.stringify(before))throw fail();
   return {config,directory,filename,sha256:hash(bytes)};
  }catch{throw fail();}
 }
 if(typeof root!=='string'||!path.isAbsolute(root)||typeof homeDirectory!=='string'||!path.isAbsolute(homeDirectory)||!Number.isInteger(uid))throw fail();
 const directory=path.join(homeDirectory,'.owasp-ai-goat',hash(path.resolve(root)).slice(0,12)),filename=path.join(directory,'analytics-managed.json');
 let handle;
 try {
  const parent=await fs.lstat(directory);if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==uid||(parent.mode&0o077))throw fail();
  handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);
  const stat=await handle.stat();if(!stat.isFile()||stat.uid!==uid||(stat.mode&0o077)||stat.size>32768||stat.nlink!==1)throw fail();
  const bytes=await handle.readFile();if(bytes.length!==stat.size)throw fail();
  let value;try{value=JSON.parse(bytes.toString('utf8'));}catch{throw fail();}
  return {config:validate(value,{root}),directory,filename,sha256:hash(bytes)};
 }catch(error){if(error.code==='ENOENT')return null;throw fail();}finally{await handle?.close();}
}
return readManagedAnalyticsConfiguration;
}
const readManagedAnalyticsConfiguration=createManagedAnalyticsConfigurationReader();
module.exports={validate,readManagedAnalyticsConfiguration,createManagedAnalyticsConfigurationReader};
