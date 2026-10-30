'use strict';
// Configuration location only. Never an import root or maintenance capability.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const fail=()=>Object.assign(Error('Maintenance installation unavailable'),{code:'APPLICATION_MAINTENANCE_INSTALLATION_INVALID'});
function createMaintenanceInstallationResolver({platform=process.platform,fileSystem=fs,homeDirectory:home,sourceDirectory=path.resolve(__dirname,'../..'),privateState}={}){
const fs=fileSystem,path=platform==='win32'?require('node:path').win32:require('node:path');
function resolveMaintenanceInstallation(installationRoot){
 const sourceRoot=sourceDirectory;
 if(installationRoot===undefined)installationRoot=sourceRoot;
 if(typeof installationRoot!=='string'||!path.isAbsolute(installationRoot)||path.resolve(installationRoot)!==installationRoot||fs.realpathSync(installationRoot)!==installationRoot||fs.realpathSync(sourceRoot)!==sourceRoot)throw fail();
 const separate=installationRoot!==sourceRoot,homeDirectory=separate?installationRoot:fs.realpathSync(home===undefined?os.homedir():home),id=createHash('sha256').update(installationRoot).digest('hex').slice(0,12),privateParent=path.join(homeDirectory,'.owasp-ai-goat'),directory=path.join(privateParent,id);
 const paths=[sourceRoot,installationRoot,privateParent,directory],capture=(p,i)=>{
  if(platform==='win32'){
   try{
    if(fs.realpathSync(p)!==p)throw fail();
    const native=privateState||require('./windows-private-state');
    const observed=(i>=2||i===1&&separate)?native.inspectPrivateDirectory(p):native.inspectWorkspaceDirectory(p);
    if(observed.path!==p||observed.size!==null||!Number.isInteger(observed.identity?.volumeSerial)||observed.identity.volumeSerial<0||observed.identity.volumeSerial>0xffffffff||!/^[a-f0-9]{16}$/.test(observed.identity.fileId))throw fail();
    return{path:observed.path,volumeSerial:observed.identity.volumeSerial,fileId:observed.identity.fileId};
   }catch{throw fail();}
  }
  const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||fs.realpathSync(p)!==p||s.uid!==process.getuid()||((i>=2||i===1&&separate)&&(s.mode&511)!==448))throw fail();return{dev:s.dev,ino:s.ino,uid:s.uid,mode:s.mode};
 };
 const identities=paths.map(capture),bindingSha256=createHash('sha256').update(JSON.stringify({sourceRoot,installationRoot,directory,identities})).digest('hex');
 const assertCurrent=()=>{paths.forEach((p,i)=>{if(JSON.stringify(capture(p,i))!==JSON.stringify(identities[i]))throw fail();});};
 return Object.freeze({sourceRoot,installationRoot,homeDirectory,directory,id,envPath:path.join(installationRoot,'.env'),bindingSha256,assertCurrent});
}
return Object.freeze({resolveMaintenanceInstallation});
}
module.exports={...createMaintenanceInstallationResolver(),createMaintenanceInstallationResolver};
