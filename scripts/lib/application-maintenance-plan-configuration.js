'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const fail=()=>Object.assign(Error('Maintenance plan configuration unavailable'),{code:'MAINTENANCE_PLAN_CONFIGURATION_UNAVAILABLE'});
function read(file,{workspace=false}={}){
 if(process.platform==='win32'){
  const native=require('./windows-private-state');
  const bytes=workspace?native.readPrivateWorkspaceFile(file):native.readPrivateFile(file);
  if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)throw fail();return bytes;
 }
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const a=fs.fstatSync(fd);if(!a.isFile()||a.uid!==process.getuid()||(a.mode&0o777)!==0o600||a.nlink!==1||a.size>1024*1024)throw fail();const buffer=Buffer.alloc(1048577);let length=0;while(length<buffer.length){const count=fs.readSync(fd,buffer,length,buffer.length-length,length);if(!count)break;length+=count;}if(length>1048576)throw fail();const bytes=buffer.subarray(0,length);const b=fs.fstatSync(fd),n=fs.lstatSync(file);if(bytes.length!==a.size||a.size!==b.size||a.ino!==n.ino||a.dev!==n.dev||n.isSymbolicLink()||a.mtimeMs!==b.mtimeMs||a.ctimeMs!==b.ctimeMs||a.mode!==b.mode||a.uid!==b.uid||a.nlink!==b.nlink||a.mode!==n.mode||a.uid!==n.uid||a.nlink!==n.nlink)throw fail();return bytes;}finally{fs.closeSync(fd);}
}
function optionalRead(file){
 try{return read(file);}catch(cause){
  if(process.platform!=='win32'){if(cause.code==='ENOENT')return undefined;throw cause;}
  // Native diagnostics are scrubbed. Only a fresh exact named ENOENT check
  // permits omission; ACL denial, reparse and inaccessible names remain errors.
  try{fs.lstatSync(file);}catch(observation){if(observation.code==='ENOENT')return undefined;}
  throw cause;
 }
}
function loadMaintenancePlanConfiguration({root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir(),adminUrl}={}){
 try{
 root=fs.realpathSync(root);const id=createHash('sha256').update(root).digest('hex').slice(0,12),directory=path.join(homeDirectory,'.dvaia',id);
 if(process.platform==='win32'){require('./windows-private-state').inspectPrivateDirectory(directory);if(fs.realpathSync(directory)!==directory)throw fail();}
 else{const d=fs.lstatSync(directory);if(fs.realpathSync(directory)!==directory||!d.isDirectory()||d.uid!==process.getuid()||(d.mode&0o777)!==0o700)throw fail();}
 const manifestPath=path.join(directory,'provisioning.json');JSON.parse(read(manifestPath));
 const text=read(path.join(root,'.env'),{workspace:true}).toString('utf8'),plan=require('../../db/postgres/provision-application').provisioningPlan(),keys=new Set(plan.flatMap(x=>[x.runtimeVariable,x.migrationVariable]).concat(['PG_TLS','CTF_DELIVERY_DATABASE_URL'])),seen=new Set();
 for(const line of text.split(/\r?\n/)){const m=line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:\s)/);if(m&&keys.has(m[1])){if(seen.has(m[1]))throw fail();seen.add(m[1]);}}
 const parsed=require('dotenv').parse(text),environment={};for(const k of keys)if(parsed[k]!==undefined)environment[k]=parsed[k];
 for(const row of plan)for(const k of [row.runtimeVariable,row.migrationVariable])if(!environment[k])throw fail();
 const local=path.join(directory,'local-postgres.json');let state;
 const localBytes=optionalRead(local);if(localBytes!==undefined){state=JSON.parse(localBytes);require('./setup-local-postgres-state').validateLocalPostgresState(state,{id,name:`dvaia-postgres-${id}`});}
 environment.PG_ADMIN_DATABASE_URL=adminUrl||(state&&`postgresql://postgres:${state.password}@127.0.0.1:${state.port}/postgres`);if(!environment.PG_ADMIN_DATABASE_URL)throw fail();
 const delivery=path.join(directory,'ctf-delivery.json');let deliveryManifestPath;const deliveryBytes=optionalRead(delivery);if(deliveryBytes!==undefined){JSON.parse(deliveryBytes);deliveryManifestPath=delivery;}
 if(Boolean(environment.CTF_DELIVERY_DATABASE_URL)!==Boolean(deliveryManifestPath))throw fail();
 return Object.freeze({environment:Object.freeze(environment),manifestPath,deliveryManifestPath});
 }catch{throw fail();}
}
module.exports={loadMaintenancePlanConfiguration};
