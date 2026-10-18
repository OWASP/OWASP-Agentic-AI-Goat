'use strict';
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const managed=require('../../server/services/secureshopSystemManagedConfiguration');
const fail=code=>Object.assign(new Error('Owned System activation requires recovery'),{code});
function capture(filePath){const result=managed.capture({filePath});if(!result)throw fail('SYSTEM_ACTIVATION_MISSING');return result;}
function activate({filePath,expected}){
 const lock=filePath+'.activation-lock';fs.mkdirSync(lock,{mode:0o700});let temporary;
 try{
  const current=capture(filePath);
  if(current.dev!==expected.dev||current.ino!==expected.ino||current.sha256!==expected.sha256)throw fail('SYSTEM_ACTIVATION_CONFLICT');
  if(current.value.enabled)return{activationEnabled:true,changed:false};
  temporary=path.join(path.dirname(filePath),'.system-activate-'+crypto.randomBytes(12).toString('hex'));
  const fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,managed.encode({...current.value,enabled:true}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  const latest=capture(filePath);if(latest.dev!==expected.dev||latest.ino!==expected.ino||latest.sha256!==expected.sha256)throw fail('SYSTEM_ACTIVATION_CONFLICT');
  fs.renameSync(temporary,filePath);temporary=undefined;
  const dir=fs.openSync(path.dirname(filePath),fs.constants.O_RDONLY);try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
  return{activationEnabled:true,changed:true};
 }finally{if(temporary)fs.unlinkSync(temporary);fs.rmdirSync(lock);}
}
function assertPersistentPrerequisites({root,homeDirectory=os.homedir(),existingEnvironment={},fresh=false,architecture=process.arch}={}) {
 if(architecture!=='arm64')throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
 const qualified=require('../../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory});
 const effective={...(fresh?{SS_ENABLE:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'}:{}),...existingEnvironment,...qualified};
 if(effective.SS_ENABLE!=='true'||effective.SS_BOUND_REVIEWS_ENABLED!=='true'||effective.PLATFORM_DATABASE_ENGINE!=='postgres'||effective.WORKSHOP_DATABASE_ENGINE!=='postgres')throw fail('SYSTEM_ACTIVATION_PERSISTENT_PREREQUISITES');
 return true;
}
function listenerPorts({root,homeDirectory=os.homedir(),environment=process.env}) {
 const existing=managed.load({filePath:managed.managedPath({root,home:homeDirectory})});
 const result={};
 for(const [mode,key,fallback]of [['config','DVAIA_SYSTEM_CONFIG_PORT',8090],['diagnostic','DVAIA_SYSTEM_DIAGNOSTIC_PORT',8091],['restart','DVAIA_SYSTEM_RESTART_PORT',8092],...((existing?.uploadPreview||environment.DVAIA_UPLOAD_PREVIEW_PORT!==undefined)?[['uploadPreview','DVAIA_UPLOAD_PREVIEW_PORT',8093]]:[])]) {
  const raw=environment[key];let requested;
  if(raw!==undefined){if(typeof raw!=='string'||!/^\d{4,5}$/.test(raw)||String(Number(raw))!==raw||Number(raw)<1024||Number(raw)>65535)throw fail('SYSTEM_INSTALL_PORT_INVALID');requested=Number(raw);}
  const recorded=existing?.[mode]?Number(new URL(existing[mode].url).port):undefined;
  if(recorded!==undefined&&requested!==undefined&&recorded!==requested)throw fail('SYSTEM_INSTALL_PORT_CONFLICT');
  result[mode+'Port']=recorded??requested??fallback;
 }
 if(new Set(Object.values(result)).size!==Object.keys(result).length)throw fail('SYSTEM_INSTALL_PORT_CONFLICT');
 return Object.freeze(result);
}
async function setupOwnedSystem({enabled=false,root,homeDirectory=os.homedir(),platform=process.platform,environment=process.env,
 applicationEnvironment=environment,architecture=process.arch,provision=require('./secureshop-owned-system-provision').provision}={}){
 if(enabled!==true)return Object.freeze({requested:false,activationEnabled:false});
 if(architecture!=='arm64')throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
 // A setup flag grants only System provisioning; it does not enable the shop or
 // change storage engines on the operator's behalf.
 if(applicationEnvironment.SS_ENABLE!=='true'||applicationEnvironment.SS_BOUND_REVIEWS_ENABLED!=='true'
  ||applicationEnvironment.PLATFORM_DATABASE_ENGINE!=='postgres'||applicationEnvironment.WORKSHOP_DATABASE_ENGINE!=='postgres')throw fail('SYSTEM_ACTIVATION_PREREQUISITES');
 const filePath=managed.managedPath({root,home:homeDirectory});
 const ports=listenerPorts({root,homeDirectory,environment});
 const options={root,home:homeDirectory,platform,architecture,environment,reconcileEnabled:true,...ports};
 await provision(options);
 const expected=capture(filePath);
 // Reverify exact staged bytes across the final image/container/readiness pass.
 const result=await provision(options);
 if(result.ready!==true||result.managedPath!==filePath||result.imageId!==expected.value.imageId)throw fail('SYSTEM_ACTIVATION_READINESS');
 const publication=activate({filePath,expected});
 return Object.freeze({requested:true,activationEnabled:true,managedPath:filePath,imageId:result.imageId,changed:publication.changed});
}
module.exports={listenerPorts,setupOwnedSystem,assertPersistentPrerequisites,capture,activate};
