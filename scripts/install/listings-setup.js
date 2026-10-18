'use strict';
const os=require('node:os'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const automatic=require('./secureshop-owned-listings-qualified-candidate');
const managed=require('../../server/services/secureshopListingsManagedConfiguration');
const {verifyExisting}=require('./secureshop-owned-listings-provision');
const {assertActivationReadiness}=require('./secureshop-owned-listings-activate');
const fail=code=>Object.assign(new Error('Owned Listings requires its checked-in qualified package and verified local runtime prerequisites; application capability remains unavailable'),{code});
function configuredBuildCa(environment={}){
 const file=environment.npm_config_cafile||environment.NPM_CONFIG_CAFILE||environment.NODE_EXTRA_CA_CERTS;
 if(!file)return {};
 if(typeof file!=='string'||!path.isAbsolute(file))throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');
 let fd;
 try{
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const before=fs.fstatSync(fd);
  if(!before.isFile()||before.size<1||before.size>1048576||(before.mode&0o022)||![0,process.getuid()].includes(before.uid))throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');
  const bytes=Buffer.alloc(before.size+1),count=fs.readSync(fd,bytes,0,bytes.length,0),after=fs.fstatSync(fd),named=fs.lstatSync(file);
  if(count!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||named.dev!==before.dev||named.ino!==before.ino||named.isSymbolicLink())throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');
  return {buildCaFile:file,buildCaSha256:crypto.createHash('sha256').update(bytes.subarray(0,count)).digest('hex')};
 }catch{throw fail('LISTINGS_INSTALL_BUILD_CA_INVALID');}finally{if(fd!==undefined)fs.closeSync(fd);}
}
function preflight({root,architecture=process.arch,environment=process.env}={}){
 return Object.freeze({...automatic.qualifiedPackage({root,architecture}),...configuredBuildCa(environment)});
}
async function setupOwnedListings({requested=false,explicitActivation=false,root,homeDirectory=os.homedir(),platform=process.platform,environment=process.env,applicationEnvironment=environment,maintenanceScope,architecture=process.arch,qualification,prepare=automatic.prepare,verify=verifyExisting,readiness=assertActivationReadiness,publish=managed.activate}={}){
 if(typeof requested!=='boolean'||typeof explicitActivation!=='boolean'||(!requested&&explicitActivation))throw fail('LISTINGS_ACTIVATION_REQUEST_INVALID');
 if(!requested)return Object.freeze({requested:false,activationEnabled:false});
 const verified=preflight({root,architecture,environment});
 if(qualification&&JSON.stringify(qualification)!==JSON.stringify(verified))throw fail('LISTINGS_INSTALL_QUALIFICATION_CHANGED');
 if(explicitActivation)require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope,applicationEnvironment);
 const filePath=managed.managedPath({root,home:homeDirectory}),prior=managed.capture({filePath});
 const verifyCurrent=async configuration=>{
  // The resource/private-state check must be the last asynchronous gate:
  // schema and retained-history reads may take long enough for daemon state
  // to change before the managed enabled record is published.
  await readiness({applicationEnvironment});
  const result=await verify({root,home:homeDirectory,platform,environment,architecture,qualified:verified,configuration,startStopped:false});
  if(result.ready!==true||result.enabled!==configuration.enabled||!/^([a-f0-9]{64})$/.test(result.containerId||''))throw fail('LISTINGS_ACTIVATION_RESOURCE_UNREADY');
  return true;
 };
 if(prior?.value.enabled===true){
  await verifyCurrent(prior.value);
  return Object.freeze({requested:true,managerReady:true,ready:true,capabilityAvailable:true,activationEnabled:true,restartRequired:false,alreadyEnabled:true});
 }
 const result=await prepare({root,home:homeDirectory,platform,environment,applicationEnvironment,
  maintenanceScope,explicitActivation,...verified});
 if(result.managerReady!==true||result.ready!==false||result.capabilityAvailable!==false||result.activationEnabled!==false)throw fail('LISTINGS_INSTALL_PREPARATION_INVALID');
 if(!explicitActivation)return Object.freeze({...result,requested:true});
 const staged=managed.capture({filePath});if(!staged||staged.value.enabled!==false)throw fail('LISTINGS_ACTIVATION_CONFIGURATION_MISSING');
 await verifyCurrent(staged.value);
 require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope,applicationEnvironment);
 await publish({filePath,expected:staged,verify:async configuration=>{
  require('../lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope,applicationEnvironment);
  return verifyCurrent(configuration);
 }});
 return Object.freeze({...result,requested:true,ready:true,capabilityAvailable:true,activationEnabled:true,restartRequired:true});
}
module.exports={preflight,setupOwnedListings,configuredBuildCa};
